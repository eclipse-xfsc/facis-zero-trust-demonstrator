// Package presentation judges one OID4VP presentation the way the verification service does: the
// SD-JWT VC is verified against the trusted issuers, its claims are read, its Token Status List is
// consulted, and the result is mapped to the status and reason code of an IF-03 outcome. It is the
// one place that mapping lives; the conformance fixtures and the service both run it.
package presentation

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/sdjwt"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/statuslist"
)

// ErrPolicy is the caller's: the policy or the binding is incomplete. No presentation was judged.
var ErrPolicy = errors.New("presentation: policy or binding incomplete")

// Policy is what a verifier is configured with.
type Policy struct {
	Trusted     if03.Issuers
	AcceptedVCT map[string]bool
	Status      statuslist.Checker
	// Skew and KeyBindingMaxAge are sdjwt.Expect's; zero means its defaults.
	Skew             time.Duration
	KeyBindingMaxAge time.Duration
}

// Binding is what this presentation must be bound to, and when it is judged.
type Binding struct {
	Nonce    string
	Audience string
	Now      time.Time
}

// Verdict is the outcome's content: the status, the reason when not verified, and, once the
// credential was read, its role and entitlement and the reference to it.
type Verdict struct {
	Status         string
	ReasonCode     string
	Claims         map[string]string // role, and entitlement when disclosed; nil before the credential was read
	CredentialRefs []string          // "<iss>#<jti>", or "<iss>#<vct>" for a credential without jti; nil before the credential was read
}

// Judge applies the policy to vpToken, in this order: trust and signature first
// (CRED-ISSUER-UNTRUSTED, then CRED-INVALID), the credential's envelope, disclosures and key
// binding (CRED-INVALID), a non-empty role (CRED-INVALID), a status reference (CRED-INVALID), and
// only then the status list: unreadable is CRED-STATUS-UNAVAILABLE, a set entry is CRED-REVOKED,
// a clear one is verified. An error is the caller's only (ErrPolicy); every refusal of the
// presentation is a Verdict.
func (p Policy) Judge(ctx context.Context, vpToken string, b Binding) (Verdict, error) {
	if len(p.Trusted) == 0 || p.Status == nil || !acceptsAny(p.AcceptedVCT) || p.Skew < 0 || p.KeyBindingMaxAge < 0 ||
		b.Nonce == "" || b.Audience == "" || b.Now.IsZero() {
		return Verdict{}, ErrPolicy
	}
	invalid := Verdict{Status: if03.StatusFailed, ReasonCode: if03.CodeInvalid}
	parsed, err := sdjwt.Parse(vpToken)
	if err != nil {
		return invalid, nil
	}
	v, err := sdjwt.Verify(parsed, p.Trusted, p.AcceptedVCT, sdjwt.Expect{Nonce: b.Nonce, Audience: b.Audience, Now: b.Now, Skew: p.Skew, KeyBindingMaxAge: p.KeyBindingMaxAge})
	switch {
	case errors.Is(err, sdjwt.ErrExpect):
		return Verdict{}, fmt.Errorf("%w: %w", ErrPolicy, err)
	case errors.Is(err, sdjwt.ErrUntrusted):
		return Verdict{Status: if03.StatusFailed, ReasonCode: if03.CodeIssuerUntrusted}, nil
	case err != nil:
		return invalid, nil
	}
	role, _, ok := jose.String(v.Claims, "role")
	if !ok || role == "" {
		return invalid, nil
	}
	claims := map[string]string{"role": role}
	if ent, present, ok := jose.String(v.Claims, "entitlement"); present {
		if !ok || ent == "" {
			return invalid, nil
		}
		claims["entitlement"] = ent
	}
	if v.Status == nil {
		return invalid, nil
	}
	ref := v.JTI
	if ref == "" {
		ref = v.VCT
	}
	read := Verdict{Claims: claims, CredentialRefs: []string{v.Issuer + "#" + ref}}
	status, err := p.Status.Status(ctx, v.Issuer, v.Status.URI, v.Status.Index)
	switch {
	case err != nil:
		read.Status, read.ReasonCode = if03.StatusFailed, if03.CodeStatusUnavailable
	case status != statuslist.Valid:
		read.Status, read.ReasonCode = if03.StatusRevoked, if03.CodeRevoked
	default:
		read.Status = if03.StatusVerified
	}
	return read, nil
}

func acceptsAny(vct map[string]bool) bool {
	for _, ok := range vct {
		if ok {
			return true
		}
	}
	return false
}
