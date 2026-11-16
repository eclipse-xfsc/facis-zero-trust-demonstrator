package acquire

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/sdjwt/sdjwtfixture"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/verificationclient"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/verificationtest"
)

func TestLoadConfigBuildsARouteWhoseOutcomesComeFromAPresentation(t *testing.T) {
	dir := t.TempDir()
	verifierKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	verifier := verificationtest.Start(t, verificationtest.Options{Issuer: vpIssuer, Kid: vpKid, Key: verifierKey,
		Policy: verificationtest.Policy(&verificationtest.Status{})})
	pub, _ := x509.MarshalPKIXPublicKey(&verifierKey.PublicKey)
	holderKey, _ := x509.MarshalECPrivateKey(sdjwtfixture.TestHolderKey())
	otherKey, _ := x509.MarshalECPrivateKey(verifierKey)
	credentialFile := filepath.Join(dir, "holder-credential.sd-jwt")
	if err := os.WriteFile(credentialFile, []byte(verificationtest.Credential(t, vpRole, vpEntitle, time.Now())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	holderKeyFile := writePEM(t, dir, "holder-key.pem", "EC PRIVATE KEY", holderKey)
	fixtureKeyFile := writePEM(t, dir, "fixture-key.pem", "EC PRIVATE KEY", otherKey)

	path := filepath.Join(dir, "acquire.json")
	load := func(outcomes map[string]any) (Loaded, error) {
		route := map[string]any{
			"name": "zone-b-api", "peer_zone": "zone-b", "audience": audience, "connector_url": "https://connector.zone-b.test/",
			"client_id": clientID, "client_secret_file": filepath.Join(dir, "secret"),
		}
		for k, v := range outcomes {
			route[k] = v
		}
		raw, _ := json.Marshal(map[string]any{
			"signing_key":     "token-store",
			"trusted_issuers": []any{map[string]any{"issuer": vpIssuer, "kid": vpKid, "public_key_file": writePEM(t, dir, "pub.pem", "PUBLIC KEY", pub)}},
			"routes":          []any{route},
		})
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return LoadConfig(path)
	}
	holder := func() map[string]any {
		return map[string]any{"kind": "file", "credential_file": credentialFile, "key_file": holderKeyFile}
	}
	block := func(edit func(map[string]any)) map[string]any {
		b := map[string]any{"url": verifier.URL + "/", "timeout_seconds": 3, "holder": holder()}
		if edit != nil {
			edit(b)
		}
		return map[string]any{"verification_outcomes": b}
	}
	withHolder := func(edit func(map[string]any)) map[string]any {
		return block(func(b map[string]any) {
			h := holder()
			edit(h)
			b["holder"] = h
		})
	}
	// A challenge of its own for every call: one that got no presentation leaves its request open.
	var ch Challenge
	outcome := func(l Loaded) (string, error) {
		ch = Challenge{Value: "challenge-" + randHex(16), ClientID: clientID, Audience: audience, ExpiresAt: time.Now().Add(2 * time.Minute)}
		return l.Routes["zone-b-api"].Outcomes.Outcome(t.Context(), ch)
	}

	got, err := load(block(nil))
	if err != nil {
		t.Fatal(err)
	}
	jws, err := outcome(got)
	if err != nil {
		t.Fatal(err)
	}
	o, err := if03.Verify(jws, got.Trusted, if03.Expect{ClientID: clientID, Challenge: ch.Value, Audience: audience}, time.Now())
	if err != nil || o.Claims.Role != vpRole || o.Claims.Entitlement != vpEntitle {
		t.Fatalf("outcome %+v refused: %v", o, err)
	}
	client := got.Routes["zone-b-api"].Outcomes.(*verificationclient.Client)
	if client.Timeout != 3*time.Second || client.BaseURL != verifier.URL {
		t.Errorf("client built with timeout %s and url %q", client.Timeout, client.BaseURL)
	}
	for name, seconds := range map[string]any{"absent": nil, "zero": 0, "the least": 1, "the most": int(verificationclient.MaxTimeout / time.Second)} {
		l, err := load(block(func(b map[string]any) {
			if seconds == nil {
				delete(b, "timeout_seconds")
			} else {
				b["timeout_seconds"] = seconds
			}
		}))
		if err != nil {
			t.Errorf("timeout_seconds %s: %v", name, err)
			continue
		}
		if _, err := outcome(l); err != nil {
			t.Errorf("timeout_seconds %s: the route yields no outcome: %v", name, err)
		}
	}

	// The holder's files are read when it presents, not when the routes are: a command that only
	// reads the routes needs neither, and a missing file is that presentation's failure.
	absent, err := load(withHolder(func(h map[string]any) { h["credential_file"] = filepath.Join(dir, "absent") }))
	if err != nil {
		t.Fatalf("a route whose credential file is not there yet: %v", err)
	}
	if _, err := outcome(absent); !errors.Is(err, verificationclient.ErrHolder) || verificationclient.Stage(err) != "holder" {
		t.Errorf("presenting without the file: %v", err)
	}
	wrongKey, err := load(withHolder(func(h map[string]any) { h["key_file"] = fixtureKeyFile }))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := outcome(wrongKey); !errors.Is(err, verificationclient.ErrHolder) {
		t.Errorf("presenting with a key the credential does not name: %v", err)
	}

	for name, c := range map[string]struct {
		outcomes map[string]any
		reason   string
	}{
		"both outcome sources": {func() map[string]any {
			b := block(nil)
			b["fixture_outcomes"] = map[string]any{"issuer": vpIssuer, "kid": vpKid, "private_key_file": fixtureKeyFile, "role": vpRole}
			return b
		}(), "exclude each other"},
		"relative url":                {block(func(b map[string]any) { b["url"] = "verification.zone-b" }), "absolute http(s) url"},
		"url with credentials":        {block(func(b map[string]any) { b["url"] = "https://user:pass@verification.zone-b.test" }), "absolute http(s) url"},
		"url with a bare query":       {block(func(b map[string]any) { b["url"] = "https://verification.zone-b.test/?" }), "without query or fragment"},
		"url with a fragment":         {block(func(b map[string]any) { b["url"] = "https://verification.zone-b.test/#x" }), "without query or fragment"},
		"timeout past the bound":      {block(func(b map[string]any) { b["timeout_seconds"] = int(verificationclient.MaxTimeout/time.Second) + 1 }), "timeout_seconds of 1 to"},
		"negative timeout":            {block(func(b map[string]any) { b["timeout_seconds"] = -1 }), "timeout_seconds of 1 to"},
		"timeout that would wrap":     {block(func(b map[string]any) { b["timeout_seconds"] = 18446744074 }), ""},
		"timeout that wraps negative": {block(func(b map[string]any) { b["timeout_seconds"] = 9223372037 }), ""},
		"no holder":                   {block(func(b map[string]any) { delete(b, "holder") }), `holder of kind "file"`},
		"holder of another kind":      {withHolder(func(h map[string]any) { h["kind"] = "wallet" }), `holder of kind "file"`},
		"holder without a kind":       {withHolder(func(h map[string]any) { delete(h, "kind") }), `holder of kind "file"`},
		"no credential file":          {withHolder(func(h map[string]any) { delete(h, "credential_file") }), "credential_file and key_file"},
		"no key file":                 {withHolder(func(h map[string]any) { h["key_file"] = "" }), "credential_file and key_file"},
		"unknown member":              {block(func(b map[string]any) { b["wallet"] = "ocm" }), `unknown field "wallet"`},
		"unknown holder member":       {withHolder(func(h map[string]any) { h["pin"] = "1234" }), `unknown field "pin"`},
	} {
		_, err := load(c.outcomes)
		if err == nil || !strings.Contains(err.Error(), c.reason) {
			t.Errorf("%s: got %v; want a refusal naming %q", name, err, c.reason)
			continue
		}
		if strings.Contains(err.Error(), dir) || strings.Contains(err.Error(), "pass@") || strings.Contains(err.Error(), "1234") {
			t.Errorf("%s: the refusal repeats a path or a credential: %v", name, err)
		}
	}
}
