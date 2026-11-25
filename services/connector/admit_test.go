package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/policyhook/hook"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/trustlist"
)

// The trust-list VC, list and DID document our TSPA image signed (scripts/verify-tspa-vc/run.sh),
// the verification service's fixture: the list names did:web:connector-b.facis-ztd.local.
const (
	tspaFixture = "../verification-service/testdata/tspa/"
	fixtureDID  = "did:web:tspa.local.test"
	listedPeer  = "did:web:connector-b.facis-ztd.local"
)

// tspaFiles answers GETs from the fixture; down makes every fetch fail.
type tspaFiles struct {
	files map[string]string
	down  bool
	gets  int
}

func (f *tspaFiles) RoundTrip(r *http.Request) (*http.Response, error) {
	f.gets++
	file, ok := f.files[r.URL.String()]
	if f.down || !ok {
		return &http.Response{StatusCode: http.StatusBadGateway, Body: http.NoBody, Request: r}, nil
	}
	raw, err := os.ReadFile(tspaFixture + file)
	if err != nil {
		return nil, err
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(raw)), Request: r}, nil
}

// forwardedCert is a certificate with one URI SAN, as the proxy forwards it.
func forwardedCert(t *testing.T, san string) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u, err := url.Parse(san)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(1), URIs: []*url.URL{u}},
		&x509.Certificate{SerialNumber: big.NewInt(1)}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return url.QueryEscape(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
}

func TestPeersAreAdmittedFromTheVerifiedTrustListOnly(t *testing.T) {
	raw, err := os.ReadFile(tspaFixture + "vc.json")
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
	tspa := &tspaFiles{files: map[string]string{
		"http://tspa.test/tspa/v1/facis-ztd.local/vc/trust-list": "vc.json",
		"https://tspa.local.test/.well-known/did.json":           "did.json",
		vc.CredentialSubject.TrustlistURI:                        "trust-list.json",
	}}
	clock := issued.Add(time.Hour)
	var out bytes.Buffer
	a := &peerAdmitter{lists: &trustlist.Verifier{HTTP: &http.Client{Transport: tspa}, Now: func() time.Time { return clock }},
		did: fixtureDID, vcURL: "http://tspa.test/tspa/v1/facis-ztd.local/vc/trust-list", framework: "facis-ztd.local",
		refresh: time.Minute, events: newEventSink(&out, "b")}
	// check asks for one decision and returns it with the event it wrote.
	check := func(cert string) (hook.Outcome, if01Event) {
		t.Helper()
		out.Reset()
		got := a.Evaluate(context.Background(), hook.Request{Headers: http.Header{"X-Request-Id": {"req-1"}}, PeerCertificate: cert})
		var ev if01Event
		if err := json.Unmarshal(out.Bytes(), &ev); err != nil || strings.Count(out.String(), "\n") != 1 {
			t.Fatalf("not one event: %q", out.String())
		}
		if ev.Kind != "decision" || ev.CorrelationID != "req-1" || ev.Source != "connector-b" {
			t.Fatalf("event %+v", ev)
		}
		return got, ev
	}
	refused := func(name, cert string, status int, code string) {
		t.Helper()
		got, ev := check(cert)
		var body hook.Refusal
		_ = json.Unmarshal(got.Body, &body)
		if got.Allowed || got.Status != status || got.ReasonCode != code || body.ReasonCode != code ||
			ev.Payload.State != "denied" || ev.Payload.ReasonCode != code {
			t.Errorf("%s: outcome %+v, event %+v; want %d %s", name, got, ev.Payload, status, code)
		}
	}
	listed, unlisted := forwardedCert(t, listedPeer), forwardedCert(t, "did:web:connector-x.facis-ztd.local")

	got, ev := check(listed)
	if !got.Allowed || ev.Payload.State != "allowed" || !strings.Contains(ev.Payload.Detail, "peer="+listedPeer) ||
		!strings.Contains(ev.Payload.Detail, expires.UTC().Format(time.RFC3339)) {
		t.Fatalf("listed peer: %+v, event %+v", got, ev.Payload)
	}
	refused("unlisted peer", unlisted, http.StatusForbidden, reasonPeerNotListed)
	refused("no certificate", "", http.StatusForbidden, reasonPeerNotListed)

	// The verified list is kept for the refresh interval: no fetch, and an outage is not seen yet.
	fetched := tspa.gets
	tspa.down = true
	if got, _ := check(listed); !got.Allowed || tspa.gets != fetched {
		t.Errorf("inside the refresh interval: %+v after %d more fetches", got, tspa.gets-fetched)
	}
	// Past it the list is retrieved again; unavailable, every peer is refused.
	clock = clock.Add(2 * time.Minute)
	refused("list unavailable", listed, http.StatusServiceUnavailable, reasonTrustUnreachable)
	tspa.down = false
	if got, _ := check(listed); !got.Allowed {
		t.Errorf("list back: %+v", got)
	}
	// The kept list ends with its VC, whatever the refresh interval.
	a.refresh = 365 * 24 * time.Hour
	clock = expires.Add(-time.Second)
	if got, _ := check(listed); !got.Allowed {
		t.Fatalf("a second before the VC expires: %+v", got)
	}
	clock = expires.Add(time.Second)
	refused("VC expired", listed, http.StatusServiceUnavailable, reasonTrustUnreachable)
}

func TestAdmitPeersConfiguration(t *testing.T) {
	ok := []string{"--tspa-url", "https://tspa.test/tspa-service/tspa/v1", "--trust-framework", "facis-ztd.local",
		"--trust-list-issuer", fixtureDID, "--zone", "b"}
	if _, err := parseAdmit(ok, func(string) string { return "" }, io.Discard); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(ok); i += 2 {
		bad := append([]string{}, ok...)
		bad[i] = ""
		if _, err := parseAdmit(bad, func(string) string { return "" }, io.Discard); err == nil {
			t.Errorf("%s empty accepted", ok[i-1])
		}
	}
}
