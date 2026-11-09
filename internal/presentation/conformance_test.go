package presentation_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/presentation"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/statuslist"
)

// The committed conformance tree and the reason-code registry, relative to this package. Both are
// committed: their absence is a defect, never a reason to skip.
const (
	fixtureDir   = "../../features/fixtures/oid4vp"
	registryFile = "../../docs/contracts/reason-codes.json"
	fixtureVCT   = "https://facis.example/credentials/participant"
)

type fixtureCase struct {
	Fixture bool   `json:"fixture"`
	Case    string `json:"case"`
	Input   struct {
		VPToken  string `json:"vp_token"`
		Nonce    string `json:"nonce"`
		Audience string `json:"audience"`
		Now      string `json:"now"`
	} `json:"input"`
	StatusList string `json:"status_list"`
	Expect     struct {
		Status         string            `json:"status"`
		ReasonCode     string            `json:"reason_code"`
		Claims         map[string]string `json:"claims"`
		CredentialRefs []string          `json:"credential_refs"`
	} `json:"expect"`
}

// TestConformanceFixtures runs every committed case through the policy and compares the verdict
// with the case's expectation; every reason code expected or produced must be registered.
func TestConformanceFixtures(t *testing.T) {
	registered := registry(t)
	trustDoc, err := os.ReadFile(filepath.Join(fixtureDir, "trusted-issuers.json"))
	if err != nil {
		t.Fatalf("committed fixtures: %v", err)
	}
	trusted, err := if03.ParseIssuers(trustDoc)
	if err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(fixtureDir, "cases", "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatal("no cases")
	}
	sort.Strings(files)
	seen := map[string]bool{}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var c fixtureCase
		if err := json.Unmarshal(data, &c); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		if !c.Fixture || c.Case != strings.TrimSuffix(filepath.Base(file), ".json") {
			t.Errorf("%s: not marked as a fixture, or misnamed", file)
		}
		seen[c.Case] = true
		t.Run(c.Case, func(t *testing.T) {
			if c.Expect.ReasonCode != "" && !registered[c.Expect.ReasonCode] {
				t.Fatalf("expects %s, which is not a registered reason code", c.Expect.ReasonCode)
			}
			now, err := time.Parse(time.RFC3339, c.Input.Now)
			if err != nil {
				t.Fatal(err)
			}
			policy := presentation.Policy{Trusted: trusted, AcceptedVCT: map[string]bool{fixtureVCT: true}, Status: statusClient(t, c.StatusList, trusted, now)}
			got, err := policy.Judge(context.Background(), c.Input.VPToken, presentation.Binding{Nonce: c.Input.Nonce, Audience: c.Input.Audience, Now: now})
			if err != nil {
				t.Fatal(err)
			}
			if got.ReasonCode != "" && !registered[got.ReasonCode] {
				t.Errorf("produced %s, which is not a registered reason code", got.ReasonCode)
			}
			if got.Status != c.Expect.Status || got.ReasonCode != c.Expect.ReasonCode {
				t.Fatalf("got %s/%s, want %s/%s", got.Status, got.ReasonCode, c.Expect.Status, c.Expect.ReasonCode)
			}
			if len(got.Claims) != len(c.Expect.Claims) {
				t.Errorf("claims %v, want %v", got.Claims, c.Expect.Claims)
			}
			for k, v := range c.Expect.Claims {
				if got.Claims[k] != v {
					t.Errorf("claim %s = %q, want %q", k, got.Claims[k], v)
				}
			}
			if strings.Join(got.CredentialRefs, ",") != strings.Join(c.Expect.CredentialRefs, ",") {
				t.Errorf("refs %v, want %v", got.CredentialRefs, c.Expect.CredentialRefs)
			}
		})
	}
	for _, want := range []string{"valid", "tampered-disclosure", "untrusted-issuer", "revoked", "status-unavailable"} {
		if !seen[want] {
			t.Errorf("case %s missing", want)
		}
	}
}

// statusClient is the status-list client the verifier would run, answering from the committed
// list the case names: clear, revoked or expired serve that file; unavailable and none answer 404.
// Any other value is a defect in the case.
func statusClient(t *testing.T, which string, trusted if03.Issuers, now time.Time) *statuslist.Client {
	t.Helper()
	var body []byte
	switch which {
	case "clear", "revoked", "expired":
		tok, err := os.ReadFile(filepath.Join(fixtureDir, "status-lists", which+".jwt"))
		if err != nil {
			t.Fatalf("status list %s: %v", which, err)
		}
		body = tok
	case "unavailable", "none":
	default:
		t.Fatalf("status_list %q is not clear, revoked, expired, unavailable or none", which)
	}
	return &statuslist.Client{Trusted: trusted, AllowedPrefixes: []string{"https://status.fixture.invalid/"}, Now: func() time.Time { return now },
		HTTP: &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
			if body == nil {
				return &http.Response{StatusCode: http.StatusNotFound, Body: http.NoBody, Request: r}, nil
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(body))), Request: r}, nil
		})}}
}

// registry is the set of codes docs/contracts/reason-codes.json registers.
func registry(t *testing.T) map[string]bool {
	t.Helper()
	data, err := os.ReadFile(registryFile)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	var doc struct {
		Families map[string]struct {
			Codes map[string]json.RawMessage `json:"codes"`
		} `json:"families"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, f := range doc.Families {
		for code := range f.Codes {
			out[code] = true
		}
	}
	return out
}

// TestProducerCodesAreRegistered ties the constants the policy writes to the registry.
func TestProducerCodesAreRegistered(t *testing.T) {
	registered := registry(t)
	for _, code := range []string{if03.CodeInvalid, if03.CodeIssuerUntrusted, if03.CodeRevoked, if03.CodeStatusUnavailable} {
		if !registered[code] {
			t.Errorf("%s is not in the registry", code)
		}
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
