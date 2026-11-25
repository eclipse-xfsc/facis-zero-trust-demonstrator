package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/trustlist"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
)

// trainSite is TRAIN as the verification service meets it, over HTTPS: a TCR that resolves the
// pointer to the trust-list issuer's DID and VC location, the issuer's did:web document, the
// trust-list VC (signed here with JsonWebSignature2020 by a key generated for the test) and the
// trust list.
type trainSite struct {
	t        *testing.T
	srv      *httptest.Server
	did      string
	key      ed25519.PrivateKey
	mu       sync.Mutex
	vc       []byte
	list     []byte
	didDoc   []byte
	broken   map[string]bool // paths answered 404
	tcrDID   string          // the DID the TCR reports; "" means did
	resolves int
}

const listedIssuer = "did:web:issuer.zone-a.test"

func newTrainSite(t *testing.T) *trainSite {
	t.Helper()
	s := &trainSite{t: t, broken: map[string]bool{}}
	_, s.key, _ = ed25519.GenerateKey(rand.Reader)
	s.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.broken[r.URL.Path] {
			http.NotFound(w, r)
			return
		}
		switch r.URL.Path {
		case "/tcr/v1/resolve":
			s.resolves++
			did := s.did
			if s.tcrDID != "" {
				did = s.tcrDID
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"trustSchemePointers": []any{map[string]any{"pointer": "trust.zone-a.test", "dids": []string{did}}},
				"resolvedResults": []any{map[string]any{"did": did, "resolvedDoc": map[string]any{
					"document": map[string]any{}, "didVerified": true,
					"endpoints": []any{map[string]any{"vcUri": s.srv.URL + "/vc", "tlUri": s.srv.URL + "/list", "vcVerified": true}}}}},
			})
		case "/.well-known/did.json":
			_, _ = w.Write(s.didDoc)
		case "/vc":
			_, _ = w.Write(s.vc)
		case "/list":
			_, _ = w.Write(s.list)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.srv.Close)
	s.did = "did:web:" + strings.ReplaceAll(strings.TrimPrefix(s.srv.URL, "https://"), ":", "%3A")
	s.setDIDKey(s.key.Public().(ed25519.PublicKey))
	s.list, _ = json.Marshal(map[string]any{"TrustServiceStatusList": map[string]any{"TrustServiceProviderList": map[string]any{
		"TrustServiceProvider": []any{entry(listedIssuer, "active")}}}})
	s.publish(time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour), nil)
	return s
}

func (s *trainSite) setDIDKey(pub ed25519.PublicKey) {
	vm := s.did + "#trust-list-1"
	s.didDoc, _ = json.Marshal(map[string]any{"@context": []string{"https://www.w3.org/ns/did/v1"}, "id": s.did,
		"verificationMethod": []any{map[string]any{"id": vm, "type": "JsonWebKey2020", "controller": s.did,
			"publicKeyJwk": map[string]any{"kty": "OKP", "crv": "Ed25519", "x": jose.B64(pub)}}},
		"assertionMethod": []string{vm}})
}

// publish signs a trust-list VC for the current list, issued at from and expiring at until (zero:
// no expirationDate); edit, when set, changes the VC after it was signed.
func (s *trainSite) publish(from, until time.Time, edit func(vc map[string]any)) {
	s.t.Helper()
	vc := map[string]any{
		"@context": []any{"https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/ed25519-2020/v1",
			"https://w3id.org/security/suites/jws-2020/v1", trustlist.Terms},
		"type": []any{"VerifiableCredential"}, "id": s.did + "#issuer-lists", "issuer": s.did,
		"issuanceDate": from.UTC().Format(time.RFC3339),
		"credentialSubject": map[string]any{"id": "uuid:test", "trustlisttype": "JSON based Trust-lists",
			"trustlistURI": s.srv.URL + "/list", "hash": trustlist.MultihashSHA256(s.list)},
	}
	if !until.IsZero() {
		vc["expirationDate"] = until.UTC().Format(time.RFC3339)
	}
	proof := map[string]any{"type": "JsonWebSignature2020", "created": time.Now().UTC().Format(time.RFC3339),
		"proofPurpose": "assertionMethod", "verificationMethod": s.did + "#trust-list-1"}
	header := jose.B64([]byte(`{"b64":false,"crit":["b64"],"alg":"EdDSA"}`))
	hOpts, err := trustlist.CanonicalSHA256(map[string]any{"@context": vc["@context"], "type": proof["type"], "created": proof["created"],
		"proofPurpose": proof["proofPurpose"], "verificationMethod": proof["verificationMethod"]})
	if err != nil {
		s.t.Fatal(err)
	}
	hDoc, err := trustlist.CanonicalSHA256(vc)
	if err != nil {
		s.t.Fatal(err)
	}
	proof["jws"] = header + ".." + jose.B64(ed25519.Sign(s.key, append([]byte(header+"."), append(hOpts, hDoc...)...)))
	vc["proof"] = proof
	if edit != nil {
		edit(vc)
	}
	s.mu.Lock()
	s.vc, _ = json.Marshal(vc)
	s.mu.Unlock()
}

func (s *trainSite) lister() lister {
	return tcrList(s.srv.Client(), s.srv.URL, []string{"trust.zone-a.test"}, &trustlist.Verifier{HTTP: s.srv.Client(), Now: time.Now})
}

func TestAVerifiedCurrentTrustListListsTheIssuer(t *testing.T) {
	s := newTrainSite(t)
	if ok, _, err := s.lister()(context.Background(), listedIssuer); !ok || err != nil {
		t.Fatalf("listed %v, err %v", ok, err)
	}
	if ok, _, _ := s.lister()(context.Background(), "did:web:other.test"); ok {
		t.Error("an issuer the list does not name was listed")
	}
}

// Each of these leaves the issuer unlisted, with an error: the TCR said vcVerified true for all.
func TestTrustListVCRefusals(t *testing.T) {
	now := time.Now()
	stranger, _, _ := ed25519.GenerateKey(rand.Reader)
	for name, c := range map[string]func(s *trainSite){
		"expired":         func(s *trainSite) { s.publish(now.Add(-48*time.Hour), now.Add(-time.Hour), nil) },
		"no validity end": func(s *trainSite) { s.publish(now.Add(-time.Hour), time.Time{}, nil) },
		"not yet valid":   func(s *trainSite) { s.publish(now.Add(time.Hour), now.Add(48*time.Hour), nil) },
		"expiry moved after signing": func(s *trainSite) {
			s.publish(now.Add(-48*time.Hour), now.Add(-time.Hour), func(vc map[string]any) { vc["expirationDate"] = now.Add(time.Hour).UTC().Format(time.RFC3339) })
		},
		"bad proof": func(s *trainSite) {
			s.publish(now.Add(-time.Hour), now.Add(time.Hour), func(vc map[string]any) {
				p := vc["proof"].(map[string]any)
				j := p["jws"].(string)
				p["jws"] = j[:len(j)-4] + "AAAA"
			})
		},
		"subject pointed at another list after signing": func(s *trainSite) {
			s.publish(now.Add(-time.Hour), now.Add(time.Hour), func(vc map[string]any) {
				vc["credentialSubject"].(map[string]any)["hash"] = "QmForged"
			})
		},
		"context not pinned": func(s *trainSite) {
			s.publish(now.Add(-time.Hour), now.Add(time.Hour), func(vc map[string]any) {
				vc["@context"] = append(vc["@context"].([]any), "https://example.org/other/v1")
			})
		},
		"inline context changed": func(s *trainSite) {
			s.publish(now.Add(-time.Hour), now.Add(time.Hour), func(vc map[string]any) {
				ctx := vc["@context"].([]any)
				ctx[3] = map[string]any{"hash": "https://example.org/other#hash"}
			})
		},
		"DID document names another key":    func(s *trainSite) { s.setDIDKey(stranger) },
		"VC issuer is not the resolved DID": func(s *trainSite) { s.tcrDID = "did:web:elsewhere.test" },
		"VC fetch fails":                    func(s *trainSite) { s.broken["/vc"] = true },
		"DID document fetch fails":          func(s *trainSite) { s.broken["/.well-known/did.json"] = true },
		"trust list fetch fails":            func(s *trainSite) { s.broken["/list"] = true },
		"TCR fails":                         func(s *trainSite) { s.broken["/tcr/v1/resolve"] = true },
	} {
		t.Run(name, func(t *testing.T) {
			s := newTrainSite(t)
			c(s)
			ok, _, err := s.lister()(context.Background(), listedIssuer)
			if ok || err == nil {
				t.Errorf("listed %v, err %v", ok, err)
			}
			t.Logf("refused: %v", err)
		})
	}
}

// A verified VC is reused only while its bytes are unchanged, for at most vcCacheTTL and never past
// its expiry.
func TestAVerifiedVCIsCachedNoLongerThanItsExpiry(t *testing.T) {
	s := newTrainSite(t)
	now := time.Now()
	s.publish(now.Add(-time.Hour), now.Add(time.Minute), nil)
	clock := now
	v := &trustlist.Verifier{HTTP: s.srv.Client(), Now: func() time.Time { return clock }}
	l := tcrList(s.srv.Client(), s.srv.URL, []string{"trust.zone-a.test"}, v)
	if ok, _, err := l(context.Background(), listedIssuer); !ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
	s.broken["/.well-known/did.json"] = true // a cache hit needs no DID document
	if ok, _, err := l(context.Background(), listedIssuer); !ok || err != nil {
		t.Fatalf("cached: %v %v", ok, err)
	}
	clock = now.Add(2 * time.Minute) // past the VC's expiry, inside vcCacheTTL
	if ok, _, err := l(context.Background(), listedIssuer); ok || err == nil {
		t.Errorf("an expired VC was served from the cache: %v %v", ok, err)
	}
}

// fixtureTransport answers GETs from files: URL → file under testdata/tspa.
type fixtureTransport map[string]string

func (f fixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	file, ok := f[r.URL.String()]
	if !ok {
		return &http.Response{StatusCode: http.StatusNotFound, Body: http.NoBody, Request: r}, nil
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(raw)), Request: r}, nil
}

// TestAVCSignedByOurTSPAVerifies runs the check on a trust-list VC our patched TSPA image signed
// (scripts/verify-tspa-vc/run.sh: a fresh key, did:web:tspa.local.test, P30D), with the list and
// DID document of that run, at a time inside the VC's window and after it.
func TestAVCSignedByOurTSPAVerifies(t *testing.T) {
	raw, err := os.ReadFile("testdata/tspa/vc.json")
	if err != nil {
		t.Fatal(err)
	}
	var vc struct {
		IssuanceDate, ExpirationDate string
		CredentialSubject            struct{ TrustlistURI string }
	}
	if err := json.Unmarshal(raw, &vc); err != nil {
		t.Fatal(err)
	}
	issued, _ := time.Parse(time.RFC3339, vc.IssuanceDate)
	expires, _ := time.Parse(time.RFC3339, vc.ExpirationDate)
	files := fixtureTransport{
		"https://tspa.example/vc":                      "testdata/tspa/vc.json",
		"https://tspa.local.test/.well-known/did.json": "testdata/tspa/did.json",
		vc.CredentialSubject.TrustlistURI:              "testdata/tspa/trust-list.json",
	}
	at := func(now time.Time) error {
		v := &trustlist.Verifier{HTTP: &http.Client{Transport: files}, Now: func() time.Time { return now }}
		list, _, err := v.TrustList(context.Background(), "did:web:tspa.local.test", "https://tspa.example/vc")
		if err == nil && !trustlist.ListsActive(list, "did:web:connector-b.facis-ztd.local") {
			return errors.New("the verified list does not list the published entry")
		}
		return err
	}
	if err := at(issued.Add(time.Hour)); err != nil {
		t.Fatalf("inside its window: %v", err)
	}
	if err := at(expires.Add(time.Second)); err == nil {
		t.Error("accepted after its expirationDate")
	}
	tampered := strings.Replace(string(raw), "JSON based Trust-lists", "XML based Trust-lists", 1)
	if tampered == string(raw) {
		t.Fatal("fixture changed shape")
	}
	tmp := t.TempDir() + "/vc.json"
	_ = os.WriteFile(tmp, []byte(tampered), 0o600)
	files["https://tspa.example/vc"] = tmp
	if err := at(issued.Add(time.Hour)); err == nil {
		t.Error("a changed subject term still verified")
	}
}

// A nested @context can re-map a term after signing: the signed hash stays under its full IRI
// while "hash" becomes an @index the proof never sees, and is replaced. Only the root context is
// allowed.
func TestANestedContextCannotSubstituteTheHash(t *testing.T) {
	s := newTrainSite(t)
	forged, _ := json.Marshal(map[string]any{"TrustServiceStatusList": map[string]any{"TrustServiceProviderList": map[string]any{
		"TrustServiceProvider": []any{entry("did:web:attacker.test", "active")}}}})
	s.publish(time.Now().Add(-time.Hour), time.Now().Add(time.Hour), func(vc map[string]any) {
		cs := vc["credentialSubject"].(map[string]any)
		cs["https://tspa.facis.cloud/ns/trustlist#hash"] = cs["hash"]
		cs["@context"] = map[string]any{"hash": "@index"}
		cs["hash"] = trustlist.MultihashSHA256(forged)
	})
	s.list = forged
	ok, _, err := s.lister()(context.Background(), "did:web:attacker.test")
	if ok || err == nil {
		t.Fatalf("a nested context substituted the list: %v %v", ok, err)
	}
	t.Logf("refused: %v", err)
}

// A verified VC is cached for the DID it was verified under only.
func TestACachedVCIsNotAcceptedForAnotherDID(t *testing.T) {
	s := newTrainSite(t)
	v := &trustlist.Verifier{HTTP: s.srv.Client(), Now: time.Now}
	if _, _, err := v.TrustList(context.Background(), s.did, s.srv.URL+"/vc"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.TrustList(context.Background(), "did:web:other.test", s.srv.URL+"/vc"); err == nil {
		t.Error("bytes verified under one DID were accepted for another")
	}
}

// Trust taken from a trust-list VC ends with the VC, not at the next refresh: the deadline is kept
// with the issuer's keys and checked whenever the policy is used.
func TestAnIssuerIsWithdrawnWhenItsTrustListExpiresBetweenRefreshes(t *testing.T) {
	s := newTrainSite(t)
	now := time.Now()
	s.publish(now.Add(-time.Hour), now.Add(time.Minute), nil)
	keys := writeIssuerKeys(t, listedIssuer)
	srv := &server{log: slog.New(slog.NewJSONHandler(io.Discard, nil))}
	trustConfig{keysFile: keys, listed: s.lister(), acceptedVCT: []string{"urn:vct"}, statusPrefixes: []string{"https://status.test/"}}.refresh(context.Background(), srv)
	if p := srv.policyAt(now); p == nil || p.Trusted[listedIssuer] == nil {
		t.Fatal("not trusted while its trust list is current")
	}
	if p := srv.policyAt(now.Add(2 * time.Minute)); p != nil {
		t.Errorf("still trusted after its trust list expired: %v", p.Trusted)
	}
}

// The window is checked again after the DID document and the list were fetched.
func TestAVCThatExpiresDuringRetrievalIsRefused(t *testing.T) {
	s := newTrainSite(t)
	now := time.Now()
	s.publish(now.Add(-time.Hour), now.Add(time.Minute), nil)
	calls := 0
	v := &trustlist.Verifier{HTTP: s.srv.Client(), Now: func() time.Time {
		calls++
		if calls > 1 {
			return now.Add(2 * time.Minute) // after the fetches
		}
		return now
	}}
	if _, _, err := v.TrustList(context.Background(), s.did, s.srv.URL+"/vc"); err == nil {
		t.Error("a VC that expired while it was being checked was accepted")
	}
}

func writeIssuerKeys(t *testing.T, iss string) string {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk := jose.PublicJWK(&k.PublicKey)
	jwk.Kid = "k1"
	b, _ := json.Marshal(map[string]any{iss: map[string]any{"keys": []jose.JWK{jwk}}})
	path := t.TempDir() + "/issuer-keys.json"
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
