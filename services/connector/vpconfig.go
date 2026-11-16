package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider"
)

// maxConfigFile bounds the trusted-issuers and scope-map files.
const maxConfigFile = 1 << 20

// loadVP reads the verified-presentation configuration from its two files. Without the issuers
// file the grant stays off (zero config). Errors name the flag and a fixed reason, never anything
// the file holds.
func loadVP(issuersFile, scopeMapFile string) (oauth2provider.VerifiedPresentationConfig, error) {
	var vp oauth2provider.VerifiedPresentationConfig
	if issuersFile == "" {
		if scopeMapFile != "" {
			return vp, errors.New("--vp-scope-map-file needs --vp-trusted-issuers-file")
		}
		return vp, nil
	}
	if scopeMapFile == "" {
		return vp, errors.New("missing: set --vp-scope-map-file or CONNECTOR_VP_SCOPE_MAP_FILE with --vp-trusted-issuers-file")
	}
	var err error
	if vp.TrustedIssuers, err = loadIssuers(issuersFile); err != nil {
		return vp, fmt.Errorf("--vp-trusted-issuers-file: %w", err)
	}
	if vp.Scopes, err = loadScopeMap(scopeMapFile); err != nil {
		return vp, fmt.Errorf("--vp-scope-map-file: %w", err)
	}
	return vp, nil
}

func readConfigFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	switch {
	case err != nil:
		return nil, errors.New("cannot read the file")
	case len(b) > maxConfigFile:
		return nil, errors.New("the file is larger than 1 MiB")
	}
	return b, nil
}

// loadIssuers reads the trusted-issuers file in the trust-set format the connector and the
// verification service share (if03.ParseIssuers):
// {"<issuer URI>": {"keys": [<public P-256 JWK with kid>, ...]}}.
func loadIssuers(path string) (if03.Issuers, error) {
	b, err := readConfigFile(path)
	if err != nil {
		return nil, err
	}
	return if03.ParseIssuers(b)
}

// loadScopeMap parses [{"role": R, "entitlement": E (optional), "scopes": [S, ...]}, ...], the JSON
// form of []oauth2provider.ClaimScopes, strictly: no other or duplicate member, a role, at least one
// scope, no claim pair twice, never the registration scope.
func loadScopeMap(path string) ([]oauth2provider.ClaimScopes, error) {
	b, err := readConfigFile(path)
	if err != nil {
		return nil, err
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(b, &entries); err != nil || len(entries) == 0 {
		return nil, errors.New("not a non-empty JSON array")
	}
	allowed := map[string]bool{"role": true, "entitlement": true, "scopes": true}
	var out []oauth2provider.ClaimScopes
	for _, raw := range entries {
		m, err := jose.ParseObject(raw)
		if err != nil {
			return nil, errors.New("an entry is not a JSON object")
		}
		for name := range m {
			if !allowed[name] {
				return nil, errors.New(`an entry has a member other than "role", "entitlement" and "scopes"`)
			}
		}
		var cs oauth2provider.ClaimScopes
		var ok bool
		if cs.Role, _, ok = jose.String(m, "role"); !ok || cs.Role == "" {
			return nil, errors.New(`an entry has no "role" string`)
		}
		if _, present := m["entitlement"]; present {
			if cs.Entitlement, _, ok = jose.String(m, "entitlement"); !ok || cs.Entitlement == "" {
				return nil, errors.New(`an entry's "entitlement" is not a non-empty string`)
			}
		}
		if json.Unmarshal(m["scopes"], &cs.Scopes) != nil || len(cs.Scopes) == 0 ||
			slices.ContainsFunc(cs.Scopes, func(s string) bool {
				return s == "" || strings.ContainsAny(s, " \t\r\n") || s == oauth2provider.RegistrationScope
			}) {
			return nil, errors.New(`an entry's "scopes" is not a non-empty array of scopes, ` + oauth2provider.RegistrationScope + ` excluded`)
		}
		if slices.ContainsFunc(out, func(o oauth2provider.ClaimScopes) bool { return o.Role == cs.Role && o.Entitlement == cs.Entitlement }) {
			return nil, errors.New("a role and entitlement pair appears more than once")
		}
		out = append(out, cs)
	}
	return out, nil
}
