// Package transit is the OpenBao client of the token path: ES256 signing with transit keys that never
// leave OpenBao, and create-only KV v2 secrets. Only public keys enter the process.
package transit

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// KeyVersion names one version of a transit key; tokens bound to it keep working after rotation.
type KeyVersion struct {
	Name    string
	Version int
}

// Ref is the form stored in signing_key.key_ref: transit:<name>:v<version>.
func (k KeyVersion) Ref() string { return fmt.Sprintf("transit:%s:v%d", k.Name, k.Version) }

// ParseRef parses a Ref.
func ParseRef(ref string) (KeyVersion, error) {
	rest, ok := strings.CutPrefix(ref, "transit:")
	name, ver, ok2 := strings.Cut(rest, ":v")
	if !ok || !ok2 || validName(name) != nil {
		return KeyVersion{}, errors.New("transit: malformed key reference")
	}
	n, err := strconv.Atoi(ver)
	k := KeyVersion{Name: name, Version: n}
	// Round trip rejects leading zeros, signs and anything Atoi tolerates beyond the canonical form.
	if err != nil || n < 1 || k.Ref() != ref {
		return KeyVersion{}, errors.New("transit: malformed key reference")
	}
	return k, nil
}

// Signer signs with transit. Sign takes the full JWS signing input (sha2-256, prehashed=false,
// marshaling_algorithm=jws, key_version pinned), checks the returned version and returns exactly 64
// bytes R||S.
type Signer interface {
	Sign(ctx context.Context, key KeyVersion, signingInput []byte) ([]byte, error)
	PublicKey(ctx context.Context, key KeyVersion) (*ecdsa.PublicKey, error)
	// EnsureKey creates the key non-exportable as ecdsa-p256 if missing and returns its latest version.
	EnsureKey(ctx context.Context, name string) (KeyVersion, error)
}

// Secrets is KV v2 with create-only writes.
type Secrets interface {
	Create(ctx context.Context, path string, value []byte) error // cas=0; ErrExists when present
	Read(ctx context.Context, path string) ([]byte, error)       // ErrNotFound when absent
	Delete(ctx context.Context, path string) error               // all versions
	List(ctx context.Context, prefix string) ([]string, error)
	// CreatedTime is when the secret's first version was written, from its KV v2 metadata.
	CreatedTime(ctx context.Context, path string) (time.Time, error) // ErrNotFound when absent
}

// TokenSource yields the OpenBao token per call (Kubernetes auth in a cluster, a dev token in tests).
type TokenSource func(ctx context.Context) (string, error)

// Config configures a Client.
type Config struct {
	Addr         string
	TransitMount string // default "transit"
	KVMount      string // default "secret"
	Token        TokenSource
	HTTPClient   *http.Client
}

var (
	ErrExists          = errors.New("transit: secret exists")
	ErrNotFound        = errors.New("transit: not found")
	ErrVersionMismatch = errors.New("transit: signed with another key version")
)

// Client implements Signer and Secrets.
type Client struct{ cfg Config }

var (
	_ Signer  = (*Client)(nil)
	_ Secrets = (*Client)(nil)
)

// New returns a Client.
func New(cfg Config) (*Client, error) {
	u, err := url.Parse(cfg.Addr)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
		return nil, errors.New("transit: Addr must be scheme://host[:port]")
	}
	if cfg.Token == nil {
		return nil, errors.New("transit: Token is required")
	}
	cfg.Addr = u.Scheme + "://" + u.Host
	if cfg.TransitMount == "" {
		cfg.TransitMount = "transit"
	}
	if cfg.KVMount == "" {
		cfg.KVMount = "secret"
	}
	if validMount(cfg.TransitMount) != nil || validMount(cfg.KVMount) != nil {
		return nil, errors.New("transit: invalid mount")
	}
	cfg.HTTPClient = safeHTTPClient(cfg.HTTPClient)
	return &Client{cfg: cfg}, nil
}

func (c *Client) Sign(ctx context.Context, key KeyVersion, signingInput []byte) ([]byte, error) {
	if err := validKey(key); err != nil {
		return nil, err
	}
	if len(signingInput) == 0 || len(signingInput) > maxSignInput {
		return nil, errors.New("transit: sign: input size out of bounds")
	}
	body := map[string]any{
		"input":                base64.StdEncoding.EncodeToString(signingInput),
		"hash_algorithm":       "sha2-256",
		"prehashed":            false,
		"key_version":          key.Version,
		"marshaling_algorithm": "jws",
	}
	var out struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	if _, err := c.do(ctx, "sign", http.MethodPost, c.transitPath("sign", key.Name), body, &out); err != nil {
		return nil, err
	}
	prefix, sig, ok := strings.Cut(strings.TrimPrefix(out.Data.Signature, "vault:"), ":")
	if !ok || !strings.HasPrefix(out.Data.Signature, "vault:v") {
		return nil, errors.New("transit: sign: malformed signature")
	}
	if prefix != "v"+strconv.Itoa(key.Version) {
		return nil, ErrVersionMismatch
	}
	raw, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || len(raw) != 64 {
		return nil, errors.New("transit: sign: signature is not 64 bytes R||S")
	}
	return raw, nil
}

func (c *Client) PublicKey(ctx context.Context, key KeyVersion) (*ecdsa.PublicKey, error) {
	if err := validKey(key); err != nil {
		return nil, err
	}
	info, err := c.readKey(ctx, "public key", key.Name)
	if err != nil {
		return nil, err
	}
	if info.Type != keyType {
		return nil, errors.New("transit: public key: not an ecdsa-p256 key")
	}
	raw, ok := info.Keys[strconv.Itoa(key.Version)]
	if !ok {
		return nil, fmt.Errorf("transit: public key: %w", ErrNotFound)
	}
	var v struct {
		PublicKey string `json:"public_key"`
	}
	if json.Unmarshal(raw, &v) != nil {
		return nil, errors.New("transit: public key: malformed answer")
	}
	block, _ := pem.Decode([]byte(v.PublicKey))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("transit: public key: not a PEM public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	ec, ok := pub.(*ecdsa.PublicKey)
	if err != nil || !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("transit: public key: not a P-256 key")
	}
	return ec, nil
}

// LatestKey reads the latest non-exportable key version without creating or changing it.
func (c *Client) LatestKey(ctx context.Context, name string) (KeyVersion, error) {
	if err := validName(name); err != nil {
		return KeyVersion{}, err
	}
	info, err := c.readKey(ctx, "latest key", name)
	if err != nil {
		return KeyVersion{}, err
	}
	if info.Type != keyType || info.Exportable || info.AllowPlaintextBackup || info.LatestVersion < 1 {
		return KeyVersion{}, errors.New("transit: latest key: existing key is not a non-exportable ecdsa-p256 key")
	}
	return KeyVersion{Name: name, Version: info.LatestVersion}, nil
}

func (c *Client) EnsureKey(ctx context.Context, name string) (KeyVersion, error) {
	if err := validName(name); err != nil {
		return KeyVersion{}, err
	}
	info, err := c.readKey(ctx, "ensure key", name)
	if errors.Is(err, ErrNotFound) {
		body := map[string]any{"type": keyType, "exportable": false, "allow_plaintext_backup": false}
		if _, err := c.do(ctx, "ensure key", http.MethodPost, c.transitPath("keys", name), body, nil); err != nil {
			return KeyVersion{}, err
		}
		info, err = c.readKey(ctx, "ensure key", name)
	}
	if err != nil {
		return KeyVersion{}, err
	}
	// An existing key is accepted only if it is what this package would have created.
	if info.Type != keyType || info.Exportable || info.AllowPlaintextBackup || info.LatestVersion < 1 {
		return KeyVersion{}, errors.New("transit: ensure key: existing key is not a non-exportable ecdsa-p256 key")
	}
	return KeyVersion{Name: name, Version: info.LatestVersion}, nil
}

func (c *Client) Create(ctx context.Context, path string, value []byte) error {
	if err := validPath(path); err != nil {
		return err
	}
	if len(value) == 0 || len(value) > maxValue {
		return errors.New("transit: create: value size out of bounds")
	}
	body := map[string]any{
		"data":    map[string]any{"value": value}, // []byte marshals as base64
		"options": map[string]any{"cas": 0},
	}
	status, err := c.do(ctx, "create", http.MethodPost, c.kvPath("data", path), body, nil)
	if status == http.StatusBadRequest && errors.Is(err, errCAS) {
		return ErrExists
	}
	return err
}

func (c *Client) Read(ctx context.Context, path string) ([]byte, error) {
	if err := validPath(path); err != nil {
		return nil, err
	}
	var out struct {
		Data struct {
			Data struct {
				Value []byte `json:"value"`
			} `json:"data"`
		} `json:"data"`
	}
	if _, err := c.do(ctx, "read", http.MethodGet, c.kvPath("data", path), nil, &out); err != nil {
		return nil, err
	}
	if out.Data.Data.Value == nil {
		// A soft-deleted version answers 404 too; a 200 without a value is not one of ours.
		return nil, errors.New("transit: read: secret has no value")
	}
	return out.Data.Data.Value, nil
}

func (c *Client) Delete(ctx context.Context, path string) error {
	if err := validPath(path); err != nil {
		return err
	}
	_, err := c.do(ctx, "delete", http.MethodDelete, c.kvPath("metadata", path), nil, nil)
	return err
}

// List lists the entries directly under prefix; "" lists the mount's root. A trailing "/" is
// accepted. Sub-folders end with "/".
func (c *Client) List(ctx context.Context, prefix string) ([]string, error) {
	prefix = strings.TrimSuffix(prefix, "/")
	if prefix != "" {
		if err := validPath(prefix); err != nil {
			return nil, err
		}
	}
	var out struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	_, err := c.do(ctx, "list", "LIST", c.kvPath("metadata", prefix), nil, &out)
	if errors.Is(err, ErrNotFound) {
		return nil, nil // nothing under the prefix
	}
	if err != nil {
		return nil, err
	}
	return out.Data.Keys, nil
}

func (c *Client) CreatedTime(ctx context.Context, path string) (time.Time, error) {
	if err := validPath(path); err != nil {
		return time.Time{}, err
	}
	var out struct {
		Data struct {
			CreatedTime time.Time `json:"created_time"`
		} `json:"data"`
	}
	if _, err := c.do(ctx, "metadata", http.MethodGet, c.kvPath("metadata", path), nil, &out); err != nil {
		return time.Time{}, err
	}
	if out.Data.CreatedTime.IsZero() {
		return time.Time{}, errors.New("transit: metadata: no created_time")
	}
	return out.Data.CreatedTime, nil
}
