// Package ociclient is a minimal client for the OCI distribution API: manifests by digest or tag and
// blobs by digest, with anonymous bearer or basic authentication. It reads only; it verifies every
// digest it is given and bounds every response.
//
// ponytail: a first-party client instead of go-containerregistry, whose remote package pulls in about
// thirty modules (Docker CLI, OpenTelemetry, credential helpers) for the three calls needed here.
package ociclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
)

// Media types the client asks for. An index is fetched like a manifest; deciding whether it is
// acceptable is the caller's business.
const (
	MediaTypeOCIManifest    = "application/vnd.oci.image.manifest.v1+json"
	MediaTypeOCIIndex       = "application/vnd.oci.image.index.v1+json"
	MediaTypeDockerManifest = "application/vnd.docker.distribution.manifest.v2+json"
	MediaTypeDockerList     = "application/vnd.docker.distribution.manifest.list.v2+json"
)

var acceptManifests = strings.Join([]string{MediaTypeOCIManifest, MediaTypeOCIIndex, MediaTypeDockerManifest, MediaTypeDockerList}, ", ")

var (
	// ErrNotFound: the registry answered 404.
	ErrNotFound = errors.New("ociclient: not found")
	// ErrDigestMismatch: the content does not hash to the requested digest.
	ErrDigestMismatch = errors.New("ociclient: digest mismatch")
	// ErrTooLarge: the response exceeds its bound.
	ErrTooLarge = errors.New("ociclient: response too large")
)

var (
	digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	repoPattern   = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$`)
	tagPattern    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)
	hostPattern   = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$`)
)

// ValidDigest reports whether d is a sha256 digest in canonical form.
func ValidDigest(d string) bool { return digestPattern.MatchString(d) }

// Credential is a registry user name and password (or token).
type Credential struct{ Username, Password string }

// Client reads from OCI registries. The zero value is not usable; use New.
type Client struct {
	http        *http.Client
	plainHTTP   map[string]bool
	credentials map[string]Credential

	MaxManifestBytes int64
	MaxBlobBytes     int64

	mu     sync.Mutex
	tokens map[string]string // registry + scope -> bearer token
}

// Options configures a Client.
type Options struct {
	// HTTPClient defaults to a client with no timeout of its own; callers bound requests with the context.
	HTTPClient *http.Client
	// PlainHTTP lists registry hosts spoken to over http instead of https (a local test registry).
	PlainHTTP []string
	// Credentials by registry host. Registries without an entry are accessed anonymously.
	Credentials map[string]Credential
	// Bounds; defaults 4 MiB for manifests and 32 MiB for blobs.
	MaxManifestBytes, MaxBlobBytes int64
}

// New returns a Client.
func New(o Options) *Client {
	base := o.HTTPClient
	if base == nil {
		base = &http.Client{}
	}
	plain := map[string]bool{}
	for _, h := range o.PlainHTTP {
		plain[h] = true
	}
	c := &Client{
		plainHTTP:        plain,
		credentials:      o.Credentials,
		MaxManifestBytes: 4 << 20,
		MaxBlobBytes:     32 << 20,
		tokens:           map[string]string{},
	}
	if o.MaxManifestBytes > 0 {
		c.MaxManifestBytes = o.MaxManifestBytes
	}
	if o.MaxBlobBytes > 0 {
		c.MaxBlobBytes = o.MaxBlobBytes
	}
	// A copy, so the caller's client keeps its own redirect policy.
	hc := *base
	hc.CheckRedirect = c.checkRedirect
	c.http = &hc
	return c
}

// Redirects (registries send blobs to a CDN) stay on https unless the origin registry is configured
// for plain http, and are limited in number. Credentials never leave the original host: net/http
// would keep the Authorization header on a redirect to a subdomain, so it is removed here.
//
// ponytail: any https destination is followed, since CDN hosts vary by registry; what reaches them is
// a GET without credentials whose body is digest-checked and never returned. A per-registry CDN
// allow-list is the upgrade path if the destinations must be pinned.
func (c *Client) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 3 {
		return errors.New("ociclient: too many redirects")
	}
	samePlainHost := req.URL.Scheme == "http" && c.plainHTTP[via[0].URL.Host] && req.URL.Host == via[0].URL.Host
	if req.URL.Scheme != "https" && !samePlainHost {
		return fmt.Errorf("ociclient: redirect to %s refused", req.URL.Scheme)
	}
	if req.URL.Host != via[0].URL.Host {
		req.Header.Del("Authorization")
	}
	return nil
}

// Manifest is a fetched manifest or index.
type Manifest struct {
	MediaType string
	Digest    string // sha256 of Body
	Body      []byte
}

// Descriptor is the part of an OCI descriptor the callers use.
type Descriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// ImageManifest is the part of an image manifest the callers use.
type ImageManifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Config        Descriptor   `json:"config"`
	Layers        []Descriptor `json:"layers"`
}

// ManifestByDigest fetches repository@digest and verifies the content hashes to digest.
func (c *Client) ManifestByDigest(ctx context.Context, registry, repository, digest string) (*Manifest, error) {
	if !ValidDigest(digest) {
		return nil, fmt.Errorf("ociclient: invalid digest %q", digest)
	}
	m, err := c.manifest(ctx, registry, repository, digest)
	if err != nil {
		return nil, err
	}
	if m.Digest != digest {
		return nil, ErrDigestMismatch
	}
	return m, nil
}

// ManifestByTag fetches repository:tag. The content is unverified: a tag names no digest, so the
// caller must verify what it reads (for a signature tag, by its signature).
func (c *Client) ManifestByTag(ctx context.Context, registry, repository, tag string) (*Manifest, error) {
	if !tagPattern.MatchString(tag) {
		return nil, fmt.Errorf("ociclient: invalid tag %q", tag)
	}
	return c.manifest(ctx, registry, repository, tag)
}

func (c *Client) manifest(ctx context.Context, registry, repository, ref string) (*Manifest, error) {
	body, header, err := c.get(ctx, registry, repository, "manifests/"+ref, acceptManifests, c.MaxManifestBytes)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	mediaType := header.Get("Content-Type")
	if i := strings.IndexByte(mediaType, ';'); i >= 0 {
		mediaType = mediaType[:i]
	}
	// The body's own mediaType wins over the header when present.
	var probe struct {
		MediaType string `json:"mediaType"`
	}
	if json.Unmarshal(body, &probe) == nil && probe.MediaType != "" {
		mediaType = probe.MediaType
	}
	return &Manifest{MediaType: mediaType, Digest: "sha256:" + hex.EncodeToString(sum[:]), Body: body}, nil
}

// Blob fetches repository@digest and verifies the content hashes to digest.
func (c *Client) Blob(ctx context.Context, registry, repository, digest string) ([]byte, error) {
	if !ValidDigest(digest) {
		return nil, fmt.Errorf("ociclient: invalid digest %q", digest)
	}
	body, _, err := c.get(ctx, registry, repository, "blobs/"+digest, "*/*", c.MaxBlobBytes)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	if "sha256:"+hex.EncodeToString(sum[:]) != digest {
		return nil, ErrDigestMismatch
	}
	return body, nil
}

func (c *Client) scheme(registry string) string {
	if c.plainHTTP[registry] {
		return "http"
	}
	return "https"
}

func (c *Client) get(ctx context.Context, registry, repository, path, accept string, limit int64) ([]byte, http.Header, error) {
	if !hostPattern.MatchString(registry) {
		return nil, nil, fmt.Errorf("ociclient: invalid registry %q", registry)
	}
	if !repoPattern.MatchString(repository) {
		return nil, nil, fmt.Errorf("ociclient: invalid repository %q", repository)
	}
	u := c.scheme(registry) + "://" + registry + "/v2/" + repository + "/" + path
	scope := "repository:" + repository + ":pull"

	token := "" // a token fetched by this request is used for its retry, whatever the cache holds
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("Accept", accept)
		c.authorize(req, registry, scope, token)

		resp, err := c.http.Do(req)
		if err != nil {
			return nil, nil, err
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			challenge := resp.Header.Get("WWW-Authenticate")
			drain(resp)
			if token, err = c.login(ctx, registry, scope, challenge); err != nil {
				return nil, nil, err
			}
			continue
		}
		body, err := readBounded(resp, limit)
		if err != nil {
			return nil, nil, err
		}
		return body, resp.Header, nil
	}
}

func (c *Client) authorize(req *http.Request, registry, scope, token string) {
	if token == "" {
		c.mu.Lock()
		token = c.tokens[registry+" "+scope]
		c.mu.Unlock()
	}
	switch {
	case token != "":
		req.Header.Set("Authorization", "Bearer "+token)
	case c.credentials[registry] != (Credential{}):
		cred := c.credentials[registry]
		req.SetBasicAuth(cred.Username, cred.Password)
	}
}

// login answers a Bearer challenge: fetches a token from the realm for the scope, with the
// registry's credentials only when the realm is on the registry's own host. The realm must use https
// unless it is the plain-http registry itself.
//
// ponytail: a realm on another host (Docker Hub's auth.docker.io) gets an anonymous token request;
// a per-registry trusted-realm list is the upgrade path if such a registry needs credentials.
func (c *Client) login(ctx context.Context, registry, scope, challenge string) (string, error) {
	scheme, params := parseChallenge(challenge)
	if !strings.EqualFold(scheme, "bearer") {
		return "", fmt.Errorf("ociclient: %s: unauthorized", registry)
	}
	realm, err := url.Parse(params["realm"])
	if err != nil || realm.Host == "" {
		return "", fmt.Errorf("ociclient: %s: invalid token realm", registry)
	}
	samePlainHost := realm.Scheme == "http" && c.plainHTTP[registry] && realm.Host == registry
	if realm.Scheme != "https" && !samePlainHost {
		return "", fmt.Errorf("ociclient: %s: token realm must use https", registry)
	}
	q := realm.Query()
	if s := params["service"]; s != "" {
		q.Set("service", s)
	}
	q.Set("scope", scope)
	realm.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	if err != nil {
		return "", err
	}
	if cred := c.credentials[registry]; cred != (Credential{}) && realm.Host == registry {
		req.SetBasicAuth(cred.Username, cred.Password)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	body, err := readBounded(resp, 1<<20)
	if err != nil {
		return "", fmt.Errorf("ociclient: %s: token: %w", registry, err)
	}
	var t struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &t); err != nil {
		return "", fmt.Errorf("ociclient: %s: token response: %w", registry, err)
	}
	token := t.Token
	if token == "" {
		token = t.AccessToken
	}
	if token == "" || len(token) > maxTokenBytes {
		return "", fmt.Errorf("ociclient: %s: empty or oversized token", registry)
	}
	c.mu.Lock()
	// ponytail: at maxTokens the map is emptied and tokens are fetched again; per-entry expiry is the
	// upgrade path if re-login traffic ever matters.
	if len(c.tokens) >= maxTokens {
		c.tokens = map[string]string{}
	}
	c.tokens[registry+" "+scope] = token
	c.mu.Unlock()
	return token, nil
}

// Bounds on the bearer-token cache: every distinct repository scope adds a token.
const (
	maxTokens     = 256
	maxTokenBytes = 16 << 10
)

// parseChallenge parses `Scheme k="v", k2="v2"`.
func parseChallenge(h string) (string, map[string]string) {
	scheme, rest, _ := strings.Cut(strings.TrimSpace(h), " ")
	params := map[string]string{}
	for rest != "" {
		rest = strings.TrimLeft(rest, " ,")
		key, after, ok := strings.Cut(rest, "=")
		if !ok {
			break
		}
		var value string
		if strings.HasPrefix(after, `"`) {
			end := strings.IndexByte(after[1:], '"')
			if end < 0 {
				break
			}
			value, rest = after[1:end+1], after[end+2:]
		} else {
			value, rest, _ = strings.Cut(after, ",")
		}
		params[strings.ToLower(strings.TrimSpace(key))] = value
	}
	return scheme, params
}

func readBounded(resp *http.Response, limit int64) ([]byte, error) {
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, ErrNotFound
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("ociclient: %s: status %d", resp.Request.URL.Redacted(), resp.StatusCode)
	case resp.ContentLength > limit:
		return nil, ErrTooLarge
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, ErrTooLarge
	}
	return body, nil
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
}
