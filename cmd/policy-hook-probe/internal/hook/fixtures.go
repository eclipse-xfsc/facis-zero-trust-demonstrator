package hook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// The two credentials the fixtures authenticate, presented as "DPoP <value>".
const (
	FixtureTokenRead = "fx-token-read" // the token of the input fixture valid-example.json: scope read
	FixtureTokenNone = "fx-token-none" // the same token without an entitlement: scope none
)

const scopeAllowed = "read"

// Fixtures is a policy source and authenticator made of the contract fixtures
// (docs/contracts/fixtures/if05-*): two fixed tokens, each answered with the decision fixture it
// maps to, so what the verification sends through the guard is the contract's own examples.
type Fixtures struct {
	allow, deny, presentation Decision
	example, noToken          Input
}

// LoadFixtures reads the fixtures from dir, the docs/contracts/fixtures folder of the repository.
func LoadFixtures(dir string) (*Fixtures, error) {
	f := &Fixtures{}
	for _, file := range []struct {
		name string
		into any
	}{
		{"if05-policy-decision.v1/valid-allow-substitute.json", &f.allow},
		{"if05-policy-decision.v1/valid-deny.json", &f.deny},
		{"if05-policy-decision.v1/valid-presentation-required.json", &f.presentation},
		{"if05-policy-input.v1/valid-example.json", &f.example},
		{"if05-policy-input.v1/valid-no-token.json", &f.noToken},
	} {
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(file.name)))
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, file.into); err != nil {
			return nil, fmt.Errorf("%s: %w", file.name, err)
		}
	}
	for _, d := range []Decision{f.allow, f.deny, f.presentation} {
		if err := d.Validate(); err != nil {
			return nil, fmt.Errorf("decision fixture: %w", err)
		}
	}
	switch {
	case !f.allow.Allow || !f.allow.Substitutes():
		return nil, errors.New("valid-allow-substitute.json is not an allow with the substitution obligation")
	case f.deny.ReasonCode != ReasonRuleDeny || f.presentation.ReasonCode != ReasonPresentationRequired:
		return nil, errors.New("the deny fixtures do not carry the expected reason codes")
	case !f.example.Token.Present || f.example.Token.Scope != scopeAllowed || f.noToken.Token.Present:
		return nil, errors.New("the input fixtures do not carry the expected tokens")
	}
	return f, nil
}

// Authenticate implements Authenticator: "DPoP fx-token-read" is the example fixture's token,
// "DPoP fx-token-none" the same token with scope none, anything else no token.
func (f *Fixtures) Authenticate(authorization, _ string) Token {
	scheme, value, ok := strings.Cut(strings.TrimSpace(authorization), " ")
	if !ok || !strings.EqualFold(scheme, "DPoP") {
		return Token{Present: false}
	}
	switch strings.TrimSpace(value) {
	case FixtureTokenRead:
		return f.example.Token
	case FixtureTokenNone:
		t := f.example.Token
		t.Scope = "none"
		return t
	}
	return Token{Present: false}
}

// Decide implements Decider: no token asks for a presentation, the entitled scope is allowed with
// substitution, any other token is denied by rule.
func (f *Fixtures) Decide(_ context.Context, in Input) (Decision, error) {
	switch {
	case !in.Token.Present:
		return f.presentation, nil
	case in.Token.Scope == scopeAllowed:
		return f.allow, nil
	}
	return f.deny, nil
}

// Case is one request of the verification's input set with the decision it must receive.
type Case struct {
	Name          string   `json:"name"`
	Authorization string   `json:"authorization,omitempty"`
	Input         Input    `json:"input"`
	Decision      Decision `json:"decision"`
}

// Cases returns the input set: the two input fixtures, plus the entitled token without its
// entitlement. Input.CorrelationID is the fixture's; the guard assigns its own per request.
func (f *Fixtures) Cases() []Case {
	none := f.example
	none.Token.Scope = "none"
	none.CorrelationID = "fx-corr-3"
	return []Case{
		{Name: "allow-substitute", Authorization: "DPoP " + FixtureTokenRead, Input: f.example, Decision: f.allow},
		{Name: "rule-deny", Authorization: "DPoP " + FixtureTokenNone, Input: none, Decision: f.deny},
		{Name: "presentation-required", Input: f.noToken, Decision: f.presentation},
	}
}
