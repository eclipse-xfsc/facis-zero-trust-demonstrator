package sdjwt_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/sdjwt"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/sdjwt/sdjwtfixture"
)

// TestInspectAgreesWithVerifyOnTheConformanceTree: for every conformance case, a credential the
// holder-side inspection refuses is one the verifier refuses too. Inspect sees less than Verify
// (no issuer key, no key binding, no accepted types), so it may accept what Verify refuses, never
// the reverse.
func TestInspectAgreesWithVerifyOnTheConformanceTree(t *testing.T) {
	root := filepath.Join("..", "..", "features", "fixtures", "oid4vp")
	rawTrust, err := os.ReadFile(filepath.Join(root, "trusted-issuers.json"))
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := if03.ParseIssuers(rawTrust)
	if err != nil {
		t.Fatal(err)
	}
	cases, err := filepath.Glob(filepath.Join(root, "cases", "*.json"))
	if err != nil || len(cases) == 0 {
		t.Fatalf("no conformance cases: %v", err)
	}
	inspected, refused := 0, 0
	for _, path := range cases {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var c struct {
			Input struct {
				VPToken  string    `json:"vp_token"`
				Nonce    string    `json:"nonce"`
				Audience string    `json:"audience"`
				Now      time.Time `json:"now"`
			} `json:"input"`
		}
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		// The credential as the holder kept it: the presentation without its key binding.
		cut := strings.LastIndex(c.Input.VPToken, "~")
		if cut < 0 {
			continue
		}
		credential := c.Input.VPToken[:cut+1]
		_, inspectErr := sdjwt.Inspect(credential, c.Input.Now)
		inspected++
		if inspectErr == nil {
			continue
		}
		refused++
		p, err := sdjwt.Parse(c.Input.VPToken)
		if err == nil {
			_, err = sdjwt.Verify(p, trusted, map[string]bool{"https://facis.example/credentials/participant": true},
				sdjwt.Expect{Nonce: c.Input.Nonce, Audience: c.Input.Audience, Now: c.Input.Now})
		}
		if err == nil {
			t.Errorf("%s: the holder refuses a credential the verifier accepts: %v", filepath.Base(path), inspectErr)
		}
	}
	if inspected < 10 || refused == 0 {
		t.Errorf("inspected %d cases and refused %d; the tree no longer exercises both answers", inspected, refused)
	}
}

func TestBindProducesWhatVerifyAccepts(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	issuerKey, holderKey := sdjwtfixture.TestIssuerKey(), sdjwtfixture.TestHolderKey()
	issued, err := sdjwtfixture.Issue(context.Background(), sdjwtfixture.IssueOptions{
		IssuerKey: issuerKey, Kid: "k1", Issuer: "https://issuer.example", VCT: "vct:a",
		Claims: []sdjwtfixture.Claim{{Name: "role", Value: "participant"}}, Disclosable: []string{"role"},
		Holder: &holderKey.PublicKey, IssuedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	credential, _ := sdjwtfixture.Select(issued, "role")
	sign := func(_ context.Context, in []byte) ([]byte, error) { return sdjwtfixture.SignES256(holderKey, in) }

	held, err := sdjwt.Inspect(credential, now)
	if err != nil || held.VCT != "vct:a" || held.Issuer != "https://issuer.example" || held.Kid != "k1" {
		t.Fatalf("inspect: %+v, %v", held, err)
	}
	if bound, err := held.Holder.PublicKey(); err != nil || !bound.Equal(&holderKey.PublicKey) {
		t.Errorf("the inspected holder key is not the credential's: %v", err)
	}
	vp, err := sdjwt.Bind(context.Background(), credential, sign, "nonce-0123456789abcdef", "https://aud.example", now)
	if err != nil {
		t.Fatal(err)
	}
	p, err := sdjwt.Parse(vp)
	if err != nil {
		t.Fatal(err)
	}
	trusted := if03.Issuers{"https://issuer.example": {"k1": &issuerKey.PublicKey}}
	if _, err := sdjwt.Verify(p, trusted, map[string]bool{"vct:a": true}, sdjwt.Expect{Nonce: "nonce-0123456789abcdef", Audience: "https://aud.example", Now: now}); err != nil {
		t.Errorf("verify: %v", err)
	}
	if _, err := sdjwt.Inspect(vp, now); !errors.Is(err, sdjwt.ErrMalformed) {
		t.Errorf("a presentation inspected as a held credential: %v", err)
	}
	if _, err := sdjwt.Inspect(credential, time.Time{}); !errors.Is(err, sdjwt.ErrExpect) {
		t.Errorf("inspection at no instant: %v", err)
	}

	for name, bind := range map[string]func() (string, error){
		"no nonce": func() (string, error) {
			return sdjwt.Bind(context.Background(), credential, sign, "", "https://aud.example", now)
		},
		"no audience": func() (string, error) { return sdjwt.Bind(context.Background(), credential, sign, "n", "", now) },
		"no instant": func() (string, error) {
			return sdjwt.Bind(context.Background(), credential, sign, "n", "a", time.Time{})
		},
		"no signer": func() (string, error) { return sdjwt.Bind(context.Background(), credential, nil, "n", "a", now) },
		"no tilde": func() (string, error) {
			return sdjwt.Bind(context.Background(), strings.TrimSuffix(credential, "~"), sign, "n", "a", now)
		},
	} {
		if vp, err := bind(); !errors.Is(err, sdjwt.ErrExpect) || vp != "" {
			t.Errorf("%s: got %q, %v", name, vp, err)
		}
	}
}
