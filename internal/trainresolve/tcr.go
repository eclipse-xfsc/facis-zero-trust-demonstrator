package trainresolve

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TCRConfig configures the Source that asks TRAIN's Trust Content Resolver.
type TCRConfig struct {
	// BaseURL is the resolver's origin, scheme and host only ("https://tcr.zone.example"); the
	// resolve path is appended. A path, query or fragment is a configuration error.
	BaseURL string
	// Client is the HTTP client to use; nil means NewHTTPClient(nil), which trusts the system roots.
	Client *http.Client
	// RequireDIDVerified also requires the resolver's well-known DID configuration check to have
	// passed. Off by default: the check needs a did-configuration document at the trust framework's
	// origin, which the client's instance may not publish; when it does, turning this on binds the
	// trust list to that origin as well.
	RequireDIDVerified bool
	// MaxBody bounds what is read of an answer; a trust-list entry is a few kilobytes. Default 1 MiB.
	MaxBody int64
}

const (
	resolvePath    = "/tcr/v1/resolve"
	defaultMaxBody = 1 << 20
	// teemType is the carrier of the expected measurement in a trust-list entry (ADR-0011, 4.2).
	teemType = "TEEM-sha256"
)

// TCR is the Source over TRAIN's Trust Content Resolver, upstream's `train-trusted-content-resolver`.
// It asks `POST /tcr/v1/resolve` with the lookup key as the issuer and the pointers as the trust
// scheme pointers; the resolver walks DNS, the DIDs and the trust-list credential and answers with
// the trust-list entry whose ServiceTypeIdentifier equals the issuer, if any, and whether the
// credential verified. Only an answer the resolver marks as verified, and whose entry this package
// checks again against the key and the value grammar, becomes a resolution.
type TCR struct {
	endpoint           string
	client             *http.Client
	requireDIDVerified bool
	maxBody            int64
	now                func() time.Time
}

// NewTCR validates the configuration and returns the Source.
func NewTCR(cfg TCRConfig) (*TCR, error) {
	u, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("trainresolve: resolver URL: %w", err)
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, errors.New("trainresolve: resolver URL must be http(s)://host[:port]")
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return nil, errors.New("trainresolve: resolver URL carries a path, query, fragment or credentials; give the origin only")
	}
	t := &TCR{
		endpoint:           u.Scheme + "://" + u.Host + resolvePath,
		client:             cfg.Client,
		requireDIDVerified: cfg.RequireDIDVerified,
		maxBody:            cfg.MaxBody,
		now:                time.Now,
	}
	if t.client == nil {
		t.client = NewHTTPClient(nil)
	}
	if t.maxBody <= 0 {
		t.maxBody = defaultMaxBody
	}
	return t, nil
}

// NewHTTPClient is the client the resolver is meant to be asked with: no proxy, since the resolver
// is a management-plane service reached over its declared opening and nothing from the pod's
// environment may sit in between; no redirects, since only the configured origin is ever consulted
// and a 3xx is an answer, never a new destination; TLS 1.3 at least, with roots as the zone's
// trust anchors (nil: the system roots); a small idle pool. The request's context, not the client,
// carries the deadline.
func NewHTTPClient(roots *x509.CertPool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.MaxIdleConnsPerHost = 2
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// The resolver's request and answer, with the field names of upstream's OpenAPI document and Go
// client (`openapi/tcr_openapi.yaml`, `clients/go/tcr`, at commit e27b1ed). Only what is consumed
// is declared; `error` fields are kept raw, since their shape is not fixed and only their presence
// matters.
type resolveRequest struct {
	Issuer              string   `json:"issuer"`
	TrustSchemePointers []string `json:"trustSchemePointers"`
}

type resolveResponse struct {
	TrustSchemePointers []resolvedPointer `json:"trustSchemePointers"`
	ResolvedResults     []resolvedDID     `json:"resolvedResults"`
}

type resolvedPointer struct {
	Pointer string          `json:"pointer"`
	DIDs    []string        `json:"dids"`
	Error   json.RawMessage `json:"error"`
}

type resolvedDID struct {
	DID         string          `json:"did"`
	ResolvedDoc *resolvedDoc    `json:"resolvedDoc"`
	Error       json.RawMessage `json:"error"`
}

type resolvedDoc struct {
	Endpoints   []resolvedTrustList `json:"endpoints"`
	DIDVerified bool                `json:"didVerified"`
}

type resolvedTrustList struct {
	VCURI      string          `json:"vcUri"`
	TLURI      string          `json:"tlUri"`
	TrustList  json.RawMessage `json:"trustList"`
	VCVerified bool            `json:"vcVerified"`
}

// tspEntry is the part of a trust-list provider entry this package reads: the field the resolver
// matched the issuer on, and the carrier of the expected measurement. The key names are the trust
// list's (upstream's `train-shared` model, which the publisher of this repository writes).
type tspEntry struct {
	UUID           string `json:"UUID"`
	TSPInformation struct {
		TSPCertificationList struct {
			TSPCertification []typeValue `json:"TSPCertification"`
		} `json:"TSPCertificationList"`
	} `json:"TSPInformation"`
	TSPServices struct {
		TSPService []struct {
			ServiceTypeIdentifier string `json:"ServiceTypeIdentifier"`
		} `json:"TSPService"`
	} `json:"TSPServices"`
}

type typeValue struct {
	Type  string `json:"Type"`
	Value string `json:"Value"`
}

func present(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return s != "" && s != "null"
}

// Resolve asks the resolver and turns its answer into a resolution, or a refusal:
//
//   - anything but a 200 with a JSON body within MaxBody is ErrUnreachable: a transport failure, a
//     status (400, 500, 502 DNS error, 510 DID error, a 3xx that is not followed), an oversized or
//     unreadable body;
//   - every pointer failed or resolved no DID, and nothing was resolved: ErrZoneUnknown, the zone is
//     absent from TRAIN;
//   - a resolved DID with an error, without endpoints, with an endpoint whose credential the
//     resolver did not verify (or whose DID configuration it did not verify, when required): the
//     answer cannot be trusted, ErrUnreachable;
//   - verified endpoints without an entry: a resolution with no values, TRAIN holds nothing for the
//     key;
//   - a verified endpoint with an entry: the entry must name the key among its services, every
//     TEEM-sha256 value must follow the grammar, and all endpoints must agree on the entry; else
//     ErrUnreachable. The TEEM-sha256 values are the resolution; other pairs are ignored.
func (t *TCR) Resolve(ctx context.Context, l Lookup) (Expected, error) {
	body, err := json.Marshal(resolveRequest{Issuer: l.Key, TrustSchemePointers: l.Pointers})
	if err != nil {
		return Expected{}, refuse(ErrUnreachable, "encoding the resolve request", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.endpoint, bytes.NewReader(body))
	if err != nil {
		return Expected{}, refuse(ErrUnreachable, "building the resolve request", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := t.client.Do(req)
	if err != nil {
		return Expected{}, refuse(ErrUnreachable, "asking the resolver", err)
	}
	defer func() {
		// Drained before it is closed, whatever the status, so the connection goes back to the pool.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, t.maxBody))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return Expected{}, refuse(ErrUnreachable, fmt.Sprintf("the resolver answered %d", resp.StatusCode), nil)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, t.maxBody+1))
	if err != nil {
		return Expected{}, refuse(ErrUnreachable, "reading the resolver's answer", err)
	}
	if int64(len(raw)) > t.maxBody {
		return Expected{}, refuse(ErrUnreachable, fmt.Sprintf("the resolver's answer exceeds %d bytes", t.maxBody), nil)
	}
	var answer resolveResponse
	if err := json.Unmarshal(raw, &answer); err != nil {
		return Expected{}, refuse(ErrUnreachable, "the resolver's answer is not the resolve document", err)
	}
	return t.interpret(l, answer)
}

func (t *TCR) interpret(l Lookup, answer resolveResponse) (Expected, error) {
	if len(answer.ResolvedResults) == 0 {
		usable := 0
		var failed []string
		for _, p := range answer.TrustSchemePointers {
			if present(p.Error) || len(p.DIDs) == 0 {
				failed = append(failed, p.Pointer)
				continue
			}
			usable++
		}
		if usable == 0 {
			return Expected{}, refuse(ErrZoneUnknown, "no trust list is anchored behind the pointer(s) "+abbreviateStrings(l.Pointers)+" (failed: "+abbreviateStrings(failed)+")", nil)
		}
		return Expected{}, refuse(ErrUnreachable, "the pointers resolved to DIDs but the resolver returned no result for them", nil)
	}

	exp := Expected{Key: l.Key, Pointers: append([]string(nil), l.Pointers...), ResolvedAt: t.now()}
	var found *tspEntry
	foundValues := map[string]bool{}
	for _, r := range answer.ResolvedResults {
		if present(r.Error) {
			return Expected{}, refuse(ErrUnreachable, "the resolver reported an error for DID "+quote(r.DID), nil)
		}
		if r.ResolvedDoc == nil || len(r.ResolvedDoc.Endpoints) == 0 {
			return Expected{}, refuse(ErrUnreachable, "the resolver returned no trust-list endpoint for DID "+quote(r.DID), nil)
		}
		if t.requireDIDVerified && !r.ResolvedDoc.DIDVerified {
			return Expected{}, refuse(ErrUnreachable, "the resolver did not verify the DID configuration of "+quote(r.DID), nil)
		}
		for _, ep := range r.ResolvedDoc.Endpoints {
			if !ep.VCVerified {
				return Expected{}, refuse(ErrUnreachable, "the resolver did not verify the trust-list credential at "+quote(ep.VCURI), nil)
			}
			if exp.TrustList == "" {
				exp.TrustList = ep.TLURI
			}
			if !present(ep.TrustList) {
				continue // a verified list without an entry for the key: authoritative absence
			}
			var entry tspEntry
			if err := json.Unmarshal(ep.TrustList, &entry); err != nil {
				return Expected{}, refuse(ErrUnreachable, "the trust-list entry is not the provider document", err)
			}
			if !namesKey(entry, l.Key) {
				return Expected{}, refuse(ErrUnreachable, "the resolver returned an entry that does not name the key "+quote(l.Key)+" among its services", nil)
			}
			values, err := teemValues(entry)
			if err != nil {
				return Expected{}, err
			}
			if found != nil && (found.UUID != entry.UUID || !sameSet(foundValues, values)) {
				return Expected{}, refuse(ErrUnreachable, "the resolver returned two different entries for the key "+quote(l.Key)+" ("+found.UUID+", "+entry.UUID+")", nil)
			}
			if found == nil {
				e := entry
				found = &e
				foundValues = values
				exp.TrustList = ep.TLURI
			}
		}
	}
	if found != nil {
		exp.EntryUUID = found.UUID
		for v := range foundValues {
			exp.Values = append(exp.Values, v)
		}
	}
	return normalise(exp, l, exp.ResolvedAt), nil
}

func namesKey(entry tspEntry, key string) bool {
	for _, s := range entry.TSPServices.TSPService {
		if s.ServiceTypeIdentifier == key {
			return true
		}
	}
	return false
}

// teemValues selects the TEEM-sha256 pairs of the entry. A value that does not follow the grammar
// refuses the whole resolution: the publisher is bound to the grammar, and a reader that tolerated
// a deviation would hide it until a stricter reader appears (ADR-0011, 4.2).
func teemValues(entry tspEntry) (map[string]bool, error) {
	values := map[string]bool{}
	for _, tv := range entry.TSPInformation.TSPCertificationList.TSPCertification {
		if tv.Type != teemType {
			continue
		}
		if !IsTEEMValue(tv.Value) {
			return nil, refuse(ErrUnreachable, "entry "+entry.UUID+" carries a "+teemType+" value that does not follow the grammar (64 lowercase hex characters)", nil)
		}
		values[tv.Value] = true
	}
	return values, nil
}

func sameSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func abbreviateStrings(values []string) string {
	return "[" + strings.Join(values, " ") + "]"
}
