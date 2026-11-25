package presentation_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/presentation"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/sdjwt"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/sdjwt/sdjwtfixture"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/statuslist"
)

type fixedStatus struct {
	status statuslist.Status
	err    error
	issuer string
}

func (f *fixedStatus) Status(_ context.Context, issuer, _ string, _ int) (statuslist.Status, error) {
	f.issuer = issuer
	return f.status, f.err
}

func TestJudge(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	issuerKey, holderKey := sdjwtfixture.TestIssuerKey(), sdjwtfixture.TestHolderKey()
	trusted := if03.Issuers{"https://issuer.example": {"k1": &issuerKey.PublicKey}}
	issued, err := sdjwtfixture.Issue(context.Background(), sdjwtfixture.IssueOptions{
		IssuerKey: issuerKey, Kid: "k1", Issuer: "https://issuer.example", VCT: "vct:a",
		Claims: []sdjwtfixture.Claim{{Name: "role", Value: "participant"}}, Disclosable: []string{"role"},
		Holder: &holderKey.PublicKey, Status: &sdjwt.StatusRef{URI: "https://s.example/1", Index: 3}, IssuedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	selected, _ := sdjwtfixture.Select(issued, "role")
	vp, err := sdjwtfixture.Present(context.Background(), selected, holderKey, "nonce-0123456789abcdef", "https://aud.example", now)
	if err != nil {
		t.Fatal(err)
	}
	binding := presentation.Binding{Nonce: "nonce-0123456789abcdef", Audience: "https://aud.example", Now: now}
	checker := &fixedStatus{}
	policy := presentation.Policy{Trusted: trusted, AcceptedVCT: map[string]bool{"vct:a": true}, Status: checker}

	got, err := policy.Judge(context.Background(), vp, binding)
	if err != nil || got.Status != if03.StatusVerified || got.ReasonCode != "" || got.Claims["role"] != "participant" {
		t.Fatalf("verified: %+v, %v", got, err)
	}
	if got.CredentialRefs[0] != "https://issuer.example#vct:a" {
		t.Errorf("a credential without jti is referenced by its vct: %v", got.CredentialRefs)
	}
	if checker.issuer != "https://issuer.example" {
		t.Errorf("the status check was asked for issuer %q", checker.issuer)
	}
	checker.status = statuslist.Suspended
	if got, _ := policy.Judge(context.Background(), vp, binding); got.Status != if03.StatusRevoked || got.ReasonCode != if03.CodeRevoked || got.Claims == nil {
		t.Errorf("suspended entry: %+v", got)
	}
	checker.status, checker.err = statuslist.Valid, statuslist.ErrMalformed
	if got, _ := policy.Judge(context.Background(), vp, binding); got.Status != if03.StatusFailed || got.ReasonCode != if03.CodeStatusUnavailable || got.Claims == nil {
		t.Errorf("malformed list: %+v", got)
	}
	checker.err = nil
	if got, _ := policy.Judge(context.Background(), "not a presentation", binding); got.Status != if03.StatusFailed || got.ReasonCode != if03.CodeInvalid || got.Claims != nil {
		t.Errorf("garbage: %+v", got)
	}

	for name, bad := range map[string]func() (presentation.Policy, presentation.Binding){
		"no trust":   func() (presentation.Policy, presentation.Binding) { p := policy; p.Trusted = nil; return p, binding },
		"no checker": func() (presentation.Policy, presentation.Binding) { p := policy; p.Status = nil; return p, binding },
		"no vct": func() (presentation.Policy, presentation.Binding) {
			p := policy
			p.AcceptedVCT = nil
			return p, binding
		},
		"no accepted vct": func() (presentation.Policy, presentation.Binding) {
			p := policy
			p.AcceptedVCT = map[string]bool{"vct:a": false}
			return p, binding
		},
		"empty trust set": func() (presentation.Policy, presentation.Binding) {
			p := policy
			p.Trusted = if03.Issuers{}
			return p, binding
		},
		"no nonce":    func() (presentation.Policy, presentation.Binding) { b := binding; b.Nonce = ""; return policy, b },
		"no audience": func() (presentation.Policy, presentation.Binding) { b := binding; b.Audience = ""; return policy, b },
		"no instant": func() (presentation.Policy, presentation.Binding) {
			b := binding
			b.Now = time.Time{}
			return policy, b
		},
		"negative skew": func() (presentation.Policy, presentation.Binding) {
			p := policy
			p.Skew = -time.Second
			return p, binding
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, b := bad()
			if _, err := p.Judge(context.Background(), vp, b); !errors.Is(err, presentation.ErrPolicy) {
				t.Errorf("got %v", err)
			}
			// A misconfiguration is the caller's whatever the token looks like.
			if _, err := p.Judge(context.Background(), "not a presentation", b); !errors.Is(err, presentation.ErrPolicy) {
				t.Errorf("with an unparsable token: %v", err)
			}
		})
	}
}
