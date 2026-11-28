// Package trainresolve decides whether an attested peer's measurement is the one TRAIN expects of
// it (ZT-35, ZT-18, ZT-64, ZT-67). It runs behind the attested channel's peer verifier, after the
// channel has verified the peer's evidence: it never verifies evidence itself, it compares the
// measurements the channel extracted from verified evidence with the TEEM-sha256 values published
// in the peer's trust-list entry (the carrier and grammar of ADR-0011, decision 4.2).
//
// The peer is looked up by a key derived from its authenticated identity, the identity its TLS
// certificate matched (ADR-0011, decision 4.3): by default the identity itself, with the host of
// the identity URI as the trust-scheme pointer. The resolution, what TRAIN holds for the key, is
// cached for a bounded time; a verdict never is (ADR-0011, consequences).
//
// Every step fails closed: a peer without a usable identity, without a SHA-256 measurement, without
// a published value, with a value that differs, or a TRAIN that cannot be consulted or trusted is a
// refusal, each with the reason code of its family. The package never logs; the caller decides what
// a refusal means and reports it.
package trainresolve

import (
	"context"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Digest is one measurement the channel extracted from the peer's verified evidence.
type Digest struct {
	Hex     string // the digest, hex encoded
	HashAlg string // the algorithm as the evidence states it, for example "SHA-256"
}

// Peer is the attested peer as the channel hands it over: the identity its certificate matched and
// the measurements of its verified evidence.
type Peer struct {
	Identity string
	Digests  []Digest
}

// Lookup is how a peer is asked of TRAIN: the string compared with the trust-list entries'
// ServiceTypeIdentifier, and the trust-scheme pointers (zone domains) the resolver starts from.
type Lookup struct {
	Key      string
	Pointers []string
}

// KeyFunc derives a peer's Lookup from its authenticated identity. An error means the peer cannot
// be looked up at all and is refused as ErrZoneUnknown without consulting TRAIN.
type KeyFunc func(identity string) (Lookup, error)

// DefaultKey is the derivation proposed to close ADR-0011 decision 4.3: the key is the identity
// verbatim, the pointer is the host of the identity URI. For a SPIFFE identity
// "spiffe://zone-b.example/gateway" the key is that string and the pointer "zone-b.example", the
// zone's trust domain, which is the zone domain the trust-list file declares, lowercased since DNS
// names are case-insensitive. An identity that is not a URI with a host (a DNS SAN, an empty
// string) has no pointer here: use WithPointers.
func DefaultKey(identity string) (Lookup, error) {
	if !strings.Contains(identity, "://") {
		return Lookup{}, &Error{Code: CodeZoneUnknown, Kind: ErrZoneUnknown, Reason: "the identity is not a URI, so no trust-scheme pointer can be derived from it"}
	}
	u, err := url.Parse(identity)
	if err != nil || u.Hostname() == "" {
		return Lookup{}, &Error{Code: CodeZoneUnknown, Kind: ErrZoneUnknown, Reason: "the identity URI has no host to use as the trust-scheme pointer", Err: err}
	}
	// DNS names are case-insensitive; one zone, one pointer, one cache entry. The key stays verbatim.
	return Lookup{Key: identity, Pointers: []string{strings.ToLower(u.Hostname())}}, nil
}

// WithPointers derives the key as DefaultKey does, the identity verbatim, but with fixed
// trust-scheme pointers, for deployments whose identities carry no trust domain (DNS SANs).
func WithPointers(pointers ...string) KeyFunc {
	fixed := make([]string, 0, len(pointers))
	for _, p := range pointers {
		if p != "" {
			fixed = append(fixed, p)
		}
	}
	return func(identity string) (Lookup, error) {
		if identity == "" {
			return Lookup{}, &Error{Code: CodeZoneUnknown, Kind: ErrZoneUnknown, Reason: "the peer has no identity"}
		}
		if len(fixed) == 0 {
			return Lookup{}, &Error{Code: CodeZoneUnknown, Kind: ErrZoneUnknown, Reason: "no trust-scheme pointer is configured"}
		}
		return Lookup{Key: identity, Pointers: append([]string(nil), fixed...)}, nil
	}
}

// Expected is one authoritative resolution: what TRAIN holds for a key. It is what the cache keeps.
// An empty Values with a nil error is a successful resolution that found nothing to compare with:
// no entry under the key, or an entry without a TEEM-sha256 value.
type Expected struct {
	Key        string
	Pointers   []string
	EntryUUID  string    // the trust-list entry's UUID; "" when there is no entry
	Values     []string  // the published TEEM-sha256 values, lowercase hex, deduplicated, sorted
	TrustList  string    // where the list was read from, for evidence; "" when unknown
	ResolvedAt time.Time // when the source answered
}

// Source resolves a Lookup in TRAIN. "No entry" and "an entry without values" are successful
// resolutions with an empty Values. A failure is an *Error of this package (ErrZoneUnknown when the
// pointers resolve to no trust list, ErrUnreachable otherwise); any other error is treated as
// ErrUnreachable.
type Source interface {
	Resolve(ctx context.Context, l Lookup) (Expected, error)
}

// Stats counts what the verifier did, for evidence and tests.
type Stats struct {
	Hits     atomic.Int64 // verifications served from the cache
	Misses   atomic.Int64 // verifications that waited for a resolution at the source, joined one, or were refused for lack of one
	Flights  atomic.Int64 // resolutions started at the source
	Refusals atomic.Int64 // verifications that refused the peer
}

// Defaults: the trust-list staleness window of the architecture's staleness matrix, and a
// resolution budget that leaves room inside the channel's handshake deadline.
const (
	DefaultTTL            = 300 * time.Second
	DefaultResolveTimeout = 5 * time.Second
)

// Verifier compares peers with what TRAIN expects of them. It is safe for concurrent use.
type Verifier struct {
	// TTL bounds how long a resolution is served from the cache. Nothing is served after it.
	TTL time.Duration
	// ResolveTimeout bounds one resolution at the source. A resolution runs detached from the
	// caller's context so that a caller whose deadline ends first is refused now while the
	// resolution completes and warms the cache for the peer's next attempt.
	ResolveTimeout time.Duration
	Stats          Stats

	src Source
	key KeyFunc
	now func() time.Time

	mu       sync.Mutex
	cache    map[string]cached
	inflight map[string]*flight
}

// New returns a Verifier over src, deriving keys with key (DefaultKey when nil), with the default
// TTL and resolution timeout. It panics on a nil Source: a verifier without a source could only
// refuse, and that misconfiguration is better found at start than at the first handshake.
func New(src Source, key KeyFunc) *Verifier {
	if src == nil {
		panic("trainresolve: New called with a nil Source")
	}
	if key == nil {
		key = DefaultKey
	}
	return &Verifier{
		TTL:            DefaultTTL,
		ResolveTimeout: DefaultResolveTimeout,
		src:            src,
		key:            key,
		now:            time.Now,
		cache:          map[string]cached{},
		inflight:       map[string]*flight{},
	}
}

// Outcome is what a verification decided from, for evidence: the resolution (zero when TRAIN
// could not be consulted), whether it came from the cache, and the peer's digests that were
// compared (the well-formed SHA-256 ones, deduplicated and sorted).
type Outcome struct {
	Expected  Expected
	FromCache bool
	Presented []string
}

// Verify refuses or accepts the peer. In order, each step failing closed: the peer's identity
// yields a Lookup (else ErrZoneUnknown, no network); the peer presented at least one well-formed
// SHA-256 digest (else ErrMismatch, no network); TRAIN is consulted, through the cache (a failure
// is returned as the source classified it and is never cached); TRAIN holds at least one
// TEEM-sha256 value for the key (else ErrUnpublished); one of them equals one of the presented
// digests (else ErrMismatch). A nil error means the peer's measurement is the expected one.
func (v *Verifier) Verify(ctx context.Context, p Peer) error {
	_, err := v.Check(ctx, p)
	return err
}

// Check is Verify with its evidence: the same verdict, and the Outcome it was decided from.
func (v *Verifier) Check(ctx context.Context, p Peer) (Outcome, error) {
	out, err := v.check(ctx, p)
	if err != nil {
		v.Stats.Refusals.Add(1)
	}
	return out, err
}

func (v *Verifier) check(ctx context.Context, p Peer) (Outcome, error) {
	var out Outcome
	lookup, err := v.lookupFor(p.Identity)
	if err != nil {
		return out, err
	}
	presented, seen := presentedDigests(p.Digests)
	out.Presented = presented
	if len(presented) == 0 {
		return out, refuse(ErrMismatch, "the peer presented no well-formed SHA-256 measurement ("+itoa(seen)+" measurement(s) seen)", nil)
	}
	exp, fromCache, err := v.resolve(ctx, lookup)
	if err != nil {
		return out, err
	}
	out.Expected, out.FromCache = exp, fromCache
	if len(exp.Values) == 0 {
		reason := "no TEEM-sha256 value is published under the key " + quote(lookup.Key)
		if exp.EntryUUID != "" {
			reason += " (entry " + exp.EntryUUID + " carries none)"
		}
		return out, refuse(ErrUnpublished, reason, nil)
	}
	for _, d := range presented {
		if contains(exp.Values, d) {
			return out, nil
		}
	}
	return out, refuse(ErrMismatch, "the peer presented "+itoa(len(presented))+" measurement(s) "+abbreviate(presented)+", TRAIN expects "+itoa(len(exp.Values))+" value(s) "+abbreviate(exp.Values), nil)
}

// Resolve returns what TRAIN holds for the peer with this identity, and whether the answer came
// from the cache. It is Verify's resolution step on its own, for probes and evidence.
func (v *Verifier) Resolve(ctx context.Context, identity string) (Expected, bool, error) {
	lookup, err := v.lookupFor(identity)
	if err != nil {
		return Expected{}, false, err
	}
	return v.resolve(ctx, lookup)
}

func (v *Verifier) lookupFor(identity string) (Lookup, error) {
	if identity == "" {
		return Lookup{}, refuse(ErrZoneUnknown, "the peer has no identity", nil)
	}
	lookup, err := v.key(identity)
	if err != nil {
		return Lookup{}, asKeyRefusal(err)
	}
	if lookup.Key == "" || len(lookup.Pointers) == 0 {
		return Lookup{}, refuse(ErrZoneUnknown, "the key derivation returned no key or no trust-scheme pointer", nil)
	}
	return lookup, nil
}

func asKeyRefusal(err error) error {
	if e, ok := err.(*Error); ok && e.Kind == ErrZoneUnknown {
		return e
	}
	return refuse(ErrZoneUnknown, "the key derivation failed", err)
}

// presentedDigests keeps the digests that can be compared with a TEEM-sha256 value: the algorithm
// names SHA-256 under any of its spellings, and the digest is 64 lowercase hex characters, the
// grammar of ADR-0011 decision 4.2. Anything else is left out, not normalised: an uppercase or
// prefixed digest is a producer that does not follow the grammar, and hiding that would hide the
// bug until a stricter reader appears. The result is deduplicated and sorted; seen is how many
// digests were handed over.
func presentedDigests(digests []Digest) (presented []string, seen int) {
	set := map[string]bool{}
	for _, d := range digests {
		seen++
		if !isSHA256(d.HashAlg) || !IsTEEMValue(d.Hex) {
			continue
		}
		set[d.Hex] = true
	}
	for h := range set {
		presented = append(presented, h)
	}
	sort.Strings(presented)
	return presented, seen
}

// isSHA256 accepts "SHA-256", "sha256", "sha-256", "SHA_256" and their case variants.
func isSHA256(alg string) bool {
	alg = strings.ToLower(alg)
	alg = strings.ReplaceAll(alg, "-", "")
	alg = strings.ReplaceAll(alg, "_", "")
	return alg == "sha256"
}

// IsTEEMValue reports whether s follows the wire grammar of a TEEM-sha256 value: exactly 64
// lowercase hexadecimal characters, no prefix, no whitespace.
func IsTEEMValue(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func contains(sorted []string, s string) bool {
	i := sort.SearchStrings(sorted, s)
	return i < len(sorted) && sorted[i] == s
}

// abbreviate names values by their first 12 characters, enough to tell them apart in a reason
// without repeating 64 characters per value.
func abbreviate(values []string) string {
	parts := make([]string, 0, len(values))
	for _, v := range values {
		if len(v) > 12 {
			v = v[:12] + "..."
		}
		parts = append(parts, v)
	}
	return "[" + strings.Join(parts, " ") + "]"
}

func quote(s string) string { return "\"" + s + "\"" }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
