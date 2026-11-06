package transit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// keyType is the only transit key type this package creates or accepts.
const keyType = "ecdsa-p256"

// maxBody bounds what is read of any answer; key metadata and KV entries are a few KiB.
const maxBody = 1 << 20

// Request limits. A JWS signing input is a header and a claim set, far below maxSignInput; a KV value
// is an upstream access token, far below maxValue, which leaves room for base64 and the answer's
// metadata inside maxBody so that whatever this client writes it can read back.
const (
	maxSignInput = 16 << 10
	maxValue     = 256 << 10
)

// errCAS marks a KV write refused by check-and-set; Create maps it to ErrExists.
var errCAS = errors.New("check-and-set refused")

// StatusError is an answer outside 2xx: the operation and the status, nothing of the body. A 404
// also matches ErrNotFound, so callers that only care whether a thing exists keep errors.Is; a
// caller that must tell a refusal (4xx, permanent) from an outage (5xx, transient) uses errors.As.
type StatusError struct {
	Op     string
	Status int
}

func (e *StatusError) Error() string { return fmt.Sprintf("transit: %s: status %d", e.Op, e.Status) }

// Is makes a 404 match ErrNotFound.
func (e *StatusError) Is(target error) bool {
	return target == ErrNotFound && e.Status == http.StatusNotFound
}

// safeHTTPClient mirrors services/token-store/internal/openbao.NewClient, which this package cannot
// import: a 3xx is an answer, never a new destination for the token. It returns a copy of c that never follows a redirect, whatever c was configured with,
// and, when c has no transport of its own, a standard one without a proxy from the environment. A
// custom transport is the caller's: its proxy and TLS settings are used as given.
func safeHTTPClient(c *http.Client) *http.Client {
	out := &http.Client{}
	if c != nil {
		*out = *c
	}
	if out.Transport == nil {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.Proxy = nil
		out.Transport = t
	}
	out.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return out
}

// do sends one request with the per-call token and decodes a 2xx answer into out. Errors name the
// operation and the HTTP status only: never the token, the request body or the answer's text.
func (c *Client) do(ctx context.Context, op, method, path string, body, out any) (int, error) {
	token, err := c.cfg.Token(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return 0, fmt.Errorf("transit: %s: %w", op, ctx.Err())
		}
		// The token source's error is not wrapped: it may carry what an authentication returned.
		return 0, fmt.Errorf("transit: %s: %w", op, ErrTokenSource)
	}
	if token == "" {
		return 0, fmt.Errorf("transit: %s: %w: no token", op, ErrTokenSource)
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, fmt.Errorf("transit: %s: encoding request", op)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.Addr+path, rd)
	if err != nil {
		return 0, fmt.Errorf("transit: %s: building request", op)
	}
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.cfg.HTTPClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return 0, fmt.Errorf("transit: %s: %w", op, ctx.Err())
		}
		// The transport error is not wrapped: its text is not ours to vouch for.
		return 0, fmt.Errorf("transit: %s: request failed", op)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return resp.StatusCode, fmt.Errorf("transit: %s: status %d: reading answer", op, resp.StatusCode)
	}
	if len(raw) > maxBody {
		return resp.StatusCode, fmt.Errorf("transit: %s: status %d: answer too large", op, resp.StatusCode)
	}
	switch s := resp.StatusCode; {
	case s == http.StatusBadRequest && casRefused(raw):
		return s, fmt.Errorf("transit: %s: status %d: %w", op, s, errCAS)
	case s < 200 || s > 299:
		return s, &StatusError{Op: op, Status: s}
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, fmt.Errorf("transit: %s: malformed answer", op)
		}
	}
	return resp.StatusCode, nil
}

func casRefused(raw []byte) bool {
	var e struct {
		Errors []string `json:"errors"`
	}
	if json.Unmarshal(raw, &e) != nil {
		return false
	}
	for _, m := range e.Errors {
		if strings.Contains(m, "check-and-set") {
			return true
		}
	}
	return false
}

type keyInfo struct {
	Type                 string                     `json:"type"`
	Exportable           bool                       `json:"exportable"`
	AllowPlaintextBackup bool                       `json:"allow_plaintext_backup"`
	LatestVersion        int                        `json:"latest_version"`
	MinEncryptionVersion int                        `json:"min_encryption_version"`
	Keys                 map[string]json.RawMessage `json:"keys"`
}

// accept admits an existing key only if it is what this package would have created: ecdsa-p256,
// not exportable, no plaintext backup, at least one version.
func (info keyInfo) accept(op string) error {
	if info.Type != keyType || info.Exportable || info.AllowPlaintextBackup || info.LatestVersion < 1 {
		return fmt.Errorf("transit: %s: %w", op, ErrUnsupportedKey)
	}
	return nil
}

func (c *Client) readKey(ctx context.Context, op, name string) (keyInfo, error) {
	var out struct {
		Data keyInfo `json:"data"`
	}
	_, err := c.do(ctx, op, http.MethodGet, c.transitPath("keys", name), nil, &out)
	return out.Data, err
}

func (c *Client) transitPath(kind, name string) string {
	return "/v1/" + c.cfg.TransitMount + "/" + kind + "/" + name
}

// kvPath escapes each segment; validPath has already refused empty, "." and ".." segments.
func (c *Client) kvPath(kind, path string) string {
	segs := strings.Split(path, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return "/v1/" + c.cfg.KVMount + "/" + kind + "/" + strings.Join(segs, "/")
}

// validMount admits mount paths of plain segments only: no escapes, delimiters or dot segments,
// since a mount is placed in the URL path as it is.
func validMount(m string) error {
	if m == "" {
		return errors.New("transit: invalid mount")
	}
	for _, s := range strings.Split(m, "/") {
		if validName(s) != nil {
			return errors.New("transit: invalid mount")
		}
	}
	return nil
}

func validPath(p string) error {
	if p == "" {
		return errors.New("transit: empty path")
	}
	for _, s := range strings.Split(p, "/") {
		if s == "" || s == "." || s == ".." {
			return errors.New("transit: invalid path")
		}
	}
	return nil
}

// validName admits transit key names that are safe in a URL path and in a Ref.
func validName(n string) error {
	if n == "" || len(n) > 128 || n == "." || n == ".." {
		return errors.New("transit: invalid key name")
	}
	for _, r := range n {
		if !isNameRune(r) {
			return errors.New("transit: invalid key name")
		}
	}
	return nil
}

func validKey(k KeyVersion) error {
	if k.Version < 1 {
		return errors.New("transit: key version must be pinned")
	}
	return validName(k.Name)
}

func isNameRune(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.'
}
