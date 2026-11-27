// Package statuslist checks a credential's revocation state against an IETF Token Status List: a
// JWT of type statuslist+jwt whose status_list member carries a compressed bit array, fetched from
// the URI the credential names. Fail closed: when the list cannot be fetched, verified or read,
// the state is unknown and the caller refuses. ES256 only, standard library only.
package statuslist

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
)

// Typ is the status-list token's typ header; MediaType is what a list server answers with.
const (
	Typ       = "statuslist+jwt"
	MediaType = "application/statuslist+jwt"
)

// Status is one entry's value. The specification registers 0 (valid), 1 (invalid) and 2
// (suspended); wider entries may carry application values.
type Status uint8

const (
	Valid     Status = 0
	Invalid   Status = 1
	Suspended Status = 2
)

// Bounds on what is fetched, decompressed and kept.
const (
	MaxTokenSize   = 1 << 20
	MaxListSize    = 8 << 20
	maxCached      = 256
	defaultTimeout = 3 * time.Second
	defaultTTL     = 60 * time.Second
)

var (
	// ErrUnavailable: the list could not be fetched, verified or read; the state is unknown.
	ErrUnavailable = errors.New("statuslist: list unavailable")
	// ErrMalformed: the token is not a status list in the agreed form. It is a kind of
	// unavailable: errors.Is(err, ErrUnavailable) holds for it.
	ErrMalformed = fmt.Errorf("%w: malformed list", ErrUnavailable)
)

// Checker answers the status of entry idx of the list at uri, which must be issued by issuer: a
// Token Status List is only believed for credentials of the issuer that signed it.
type Checker interface {
	Status(ctx context.Context, issuer, uri string, idx int) (Status, error)
}

// List is a verified, decoded status list.
type List struct {
	Issuer    string
	Subject   string
	Bits      int
	entries   []byte
	IssuedAt  time.Time
	ExpiresAt time.Time     // zero when the token has no exp
	TTL       time.Duration // zero when the token names none
}

// Len is the number of entries the list holds; zero for the zero List.
func (l List) Len() int {
	if l.Bits == 0 {
		return 0
	}
	return len(l.entries) * 8 / l.Bits
}

// At reads entry idx. Entries are packed least-significant first within each byte.
func (l List) At(idx int) (Status, error) {
	if l.Bits == 0 || idx < 0 || idx >= l.Len() {
		return 0, fmt.Errorf("%w: index out of range", ErrUnavailable)
	}
	perByte := 8 / l.Bits
	b := l.entries[idx/perByte]
	shift := uint(idx%perByte) * uint(l.Bits)
	return Status(b >> shift & (1<<uint(l.Bits) - 1)), nil
}

// Parse verifies token as the status list of issuer at uri, at instant now, and decodes it. The
// header is exactly alg ES256, typ statuslist+jwt and a kid of issuer's; iss must be issuer; sub
// must equal uri; exp, when present, must be in the future.
func Parse(token string, trusted if03.Issuers, issuer, uri string, now time.Time) (List, error) {
	if issuer == "" || uri == "" {
		return List{}, fmt.Errorf("%w: issuer and uri are required", ErrUnavailable)
	}
	_, payload, err := jose.Verify(token, jose.HeaderPolicy{Typ: Typ, KidNeeded: true}, func(h jose.Header) (*ecdsa.PublicKey, error) {
		owner, key, ok := trusted.Key(h.Kid)
		if !ok || owner != issuer {
			return nil, errors.New("kid not held by the issuer")
		}
		return key, nil
	})
	if err != nil {
		return List{}, fmt.Errorf("%w: signature not verified with a key of the issuer", ErrUnavailable)
	}
	m, err := jose.ParseObject(payload)
	if err != nil {
		return List{}, fmt.Errorf("%w: payload", ErrMalformed)
	}
	l := List{Issuer: issuer}
	if iss, _, ok := jose.String(m, "iss"); !ok || iss != issuer {
		return List{}, fmt.Errorf("%w: iss is not the issuer", ErrUnavailable)
	}
	if l.Subject, _, err = stringMember(m, "sub"); err != nil {
		return List{}, err
	}
	if l.Subject != uri {
		return List{}, fmt.Errorf("%w: sub is another list", ErrUnavailable)
	}
	if l.IssuedAt, err = dateMember(m, "iat", true); err != nil {
		return List{}, err
	}
	if l.ExpiresAt, err = dateMember(m, "exp", false); err != nil {
		return List{}, err
	}
	if !l.ExpiresAt.IsZero() && !l.ExpiresAt.After(now) {
		return List{}, fmt.Errorf("%w: expired", ErrUnavailable)
	}
	if raw, present := m["ttl"]; present {
		n, ok := jose.Integer(raw)
		if !ok || n == 0 || n > maxSeconds {
			return List{}, fmt.Errorf("%w: ttl", ErrMalformed)
		}
		l.TTL = time.Duration(n) * time.Second
	}
	sl, err := jose.ParseObject(m["status_list"])
	if err != nil {
		return List{}, fmt.Errorf("%w: status_list", ErrMalformed)
	}
	for name := range sl {
		if !statusListMembers[name] {
			return List{}, fmt.Errorf("%w: status_list member not allowed", ErrMalformed)
		}
	}
	if _, present := sl["aggregation_uri"]; present {
		if v, _, ok := jose.String(sl, "aggregation_uri"); !ok || v == "" {
			return List{}, fmt.Errorf("%w: aggregation_uri", ErrMalformed)
		}
	}
	bits, ok := jose.Integer(sl["bits"])
	if !ok || (bits != 1 && bits != 2 && bits != 4 && bits != 8) {
		return List{}, fmt.Errorf("%w: bits", ErrMalformed)
	}
	l.Bits = int(bits)
	lst, _, ok := jose.String(sl, "lst")
	if !ok {
		return List{}, fmt.Errorf("%w: lst", ErrMalformed)
	}
	if l.entries, err = decompress(lst); err != nil {
		return List{}, err
	}
	return l, nil
}

// The members of status_list: bits and lst are required, aggregation_uri is the one optional
// member the specification registers.
var statusListMembers = map[string]bool{"bits": true, "lst": true, "aggregation_uri": true}

// maxSeconds bounds a ttl: a year, so that a duration never overflows.
const maxSeconds = 366 * 24 * 60 * 60

func decompress(lst string) ([]byte, error) {
	compressed, err := jose.DecodeB64(lst)
	if err != nil {
		return nil, fmt.Errorf("%w: lst encoding", ErrMalformed)
	}
	zr, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("%w: lst compression", ErrMalformed)
	}
	defer func() { _ = zr.Close() }()
	entries, err := io.ReadAll(io.LimitReader(zr, MaxListSize+1))
	if err != nil {
		return nil, fmt.Errorf("%w: lst compression", ErrMalformed)
	}
	if len(entries) > MaxListSize {
		return nil, fmt.Errorf("%w: list larger than %d bytes", ErrMalformed, MaxListSize)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("%w: empty list", ErrMalformed)
	}
	return entries, nil
}

func stringMember(m map[string]json.RawMessage, name string) (string, bool, error) {
	v, present, ok := jose.String(m, name)
	if !present || !ok || v == "" {
		return "", present, fmt.Errorf("%w: %s", ErrMalformed, name)
	}
	return v, true, nil
}

func dateMember(m map[string]json.RawMessage, name string, required bool) (time.Time, error) {
	raw, present := m[name]
	if !present {
		if required {
			return time.Time{}, fmt.Errorf("%w: %s", ErrMalformed, name)
		}
		return time.Time{}, nil
	}
	n, ok := jose.Integer(raw)
	if !ok {
		return time.Time{}, fmt.Errorf("%w: %s", ErrMalformed, name)
	}
	return time.Unix(n, 0).UTC(), nil
}

// Client fetches, verifies and caches status lists. Fetches go only to URIs under AllowedPrefixes
// (a credential names the URI, so the set of hosts a verifier will talk to is configured, never
// taken from the presentation; see ValidPrefix), never follow redirects, read at most MaxTokenSize
// bytes and give up after Timeout. A list is cached for the shorter of CacheTTL and the token's
// ttl, and never past its exp; at most maxCached lists are kept, and concurrent misses for one URI
// share one fetch. A fetch that fails after the cache entry expired is ErrUnavailable: nothing
// stale is relied on.
type Client struct {
	HTTP            *http.Client
	Trusted         if03.Issuers
	AllowedPrefixes []string
	CacheTTL        time.Duration // zero means 60 s
	Timeout         time.Duration // zero means 3 s
	Now             func() time.Time

	mu       sync.Mutex
	cache    map[string]cached
	inflight map[string]*fetching
}

type cached struct {
	list  List
	until time.Time
}

// fetching is one fetch in progress; followers wait on done and read its result.
type fetching struct {
	done chan struct{}
	list List
	err  error
}

var _ Checker = (*Client)(nil)

// ValidPrefix says whether p may be an allowed prefix: an absolute http or https URL with a host,
// no userinfo, no query or fragment, and a path ending in "/". A prefix that fails this never
// matches; a service checks its configuration with it at startup.
func ValidPrefix(p string) error {
	u, err := url.Parse(p)
	switch {
	case err != nil, u.Scheme != "https" && u.Scheme != "http", u.Host == "", u.User != nil,
		u.RawQuery != "", u.Fragment != "", u.ForceQuery, u.Opaque != "":
		return errors.New("statuslist: a prefix is an absolute http(s) URL with a host and a path ending in /")
	case !strings.HasSuffix(u.EscapedPath(), "/"), hasDotSegment(u.Path):
		return errors.New("statuslist: a prefix path ends in / and has no . or .. segment")
	}
	return nil
}

// hasDotSegment reports a "." or ".." segment in a decoded path: what a server would resolve to
// another place than the prefix names (percent-encoded forms included, since p is decoded; a
// ";parameter" suffix, which servlet containers strip before resolving, does not hide one).
func hasDotSegment(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		seg, _, _ = strings.Cut(seg, ";")
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

// Status returns the state of entry idx of issuer's list at uri.
func (c *Client) Status(ctx context.Context, issuer, uri string, idx int) (Status, error) {
	l, err := c.list(ctx, issuer, uri)
	if err != nil {
		return 0, err
	}
	return l.At(idx)
}

// list answers from the cache, joins a fetch already in flight for uri, or fetches itself. One
// flight serves every concurrent caller: its fetch runs detached from the first caller's
// cancellation (bounded by Timeout), so a caller giving up does not fail the others; a follower
// whose own ctx ends leaves with ErrUnavailable. The flight is parsed for the first caller's
// issuer, so a concurrent caller naming another issuer for the same URI gets ErrUnavailable for
// that flight and refetches next time: fail closed, never another issuer's list.
func (c *Client) list(ctx context.Context, issuer, uri string) (List, error) {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	at := now()
	c.mu.Lock()
	entry, hit := c.cache[uri]
	if hit && at.Before(entry.until) {
		c.mu.Unlock()
		if entry.list.Issuer != issuer {
			return List{}, fmt.Errorf("%w: list is another issuer's", ErrUnavailable)
		}
		return entry.list, nil
	}
	if f, running := c.inflight[uri]; running {
		c.mu.Unlock()
		select {
		case <-f.done:
			if f.err == nil && f.list.Issuer != issuer {
				return List{}, fmt.Errorf("%w: list is another issuer's", ErrUnavailable)
			}
			return f.list, f.err
		case <-ctx.Done():
			return List{}, fmt.Errorf("%w: fetch failed", ErrUnavailable)
		}
	}
	f := &fetching{done: make(chan struct{}), err: fmt.Errorf("%w: fetch did not complete", ErrUnavailable)}
	if c.inflight == nil {
		c.inflight = map[string]*fetching{}
	}
	c.inflight[uri] = f
	c.mu.Unlock()
	// Whatever happens in the fetch, a panic included, the flight is removed and its followers
	// released; f.err stays "did not complete" unless the fetch returned.
	defer func() {
		c.mu.Lock()
		delete(c.inflight, uri)
		if f.err == nil {
			c.store(uri, f.list, at)
		}
		c.mu.Unlock()
		close(f.done)
	}()
	f.list, f.err = c.fetchAndParse(context.WithoutCancel(ctx), issuer, uri, at)
	return f.list, f.err
}

func (c *Client) fetchAndParse(ctx context.Context, issuer, uri string, at time.Time) (List, error) {
	if !c.allowed(uri) {
		return List{}, fmt.Errorf("%w: uri not under an allowed prefix", ErrUnavailable)
	}
	token, err := c.fetch(ctx, uri)
	if err != nil {
		return List{}, err
	}
	return Parse(token, c.Trusted, issuer, uri, at)
}

// store caches l under uri, with c.mu held: expired entries are dropped first, and when the cache
// is still full the entry expiring soonest makes room.
func (c *Client) store(uri string, l List, at time.Time) {
	ttl := c.CacheTTL
	if ttl == 0 {
		ttl = defaultTTL
	}
	if l.TTL > 0 && l.TTL < ttl {
		ttl = l.TTL
	}
	until := at.Add(ttl)
	if !l.ExpiresAt.IsZero() && l.ExpiresAt.Before(until) {
		until = l.ExpiresAt
	}
	if c.cache == nil {
		c.cache = map[string]cached{}
	}
	for k, e := range c.cache {
		if !at.Before(e.until) {
			delete(c.cache, k)
		}
	}
	if _, present := c.cache[uri]; !present && len(c.cache) >= maxCached {
		var soonest string
		for k, e := range c.cache {
			if soonest == "" || e.until.Before(c.cache[soonest].until) {
				soonest = k
			}
		}
		delete(c.cache, soonest)
	}
	c.cache[uri] = cached{list: l, until: until}
}

// Cached is the number of lists held, for tests and readiness.
func (c *Client) Cached() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.cache)
}

// allowed compares the parsed URI with each valid prefix: same scheme and host (port included), no
// userinfo, no . or .. segment in the decoded path, and the prefix's path leading the URI's. A
// prefix that is not valid matches nothing.
func (c *Client) allowed(uri string) bool {
	u, err := url.Parse(uri)
	if err != nil || u.User != nil || u.Opaque != "" || hasDotSegment(u.Path) {
		return false
	}
	for _, p := range c.AllowedPrefixes {
		if ValidPrefix(p) != nil {
			continue
		}
		pu, _ := url.Parse(p)
		if strings.EqualFold(u.Scheme, pu.Scheme) && strings.EqualFold(u.Host, pu.Host) && strings.HasPrefix(u.EscapedPath(), pu.EscapedPath()) {
			return true
		}
	}
	return false
}

func (c *Client) fetch(ctx context.Context, uri string) (string, error) {
	timeout := c.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return "", fmt.Errorf("%w: uri", ErrUnavailable)
	}
	req.Header.Set("Accept", MediaType)
	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	noRedirect := *client
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noRedirect.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: fetch failed", ErrUnavailable)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: status %d", ErrUnavailable, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxTokenSize+1))
	if err != nil || len(body) > MaxTokenSize {
		return "", fmt.Errorf("%w: body", ErrUnavailable)
	}
	return strings.TrimSpace(string(body)), nil
}
