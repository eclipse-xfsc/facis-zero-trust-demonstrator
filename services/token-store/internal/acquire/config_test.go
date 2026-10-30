package acquire

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
)

func writePEM(t *testing.T, dir, name, typ string, der []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadConfigBuildsRoutesWhoseFixtureOutcomesVerify(t *testing.T) {
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	priv, _ := x509.MarshalECPrivateKey(key)
	cfg := map[string]any{
		"signing_key":     "token-store",
		"trusted_issuers": []any{map[string]any{"issuer": vpIssuer, "kid": vpKid, "public_key_file": writePEM(t, dir, "pub.pem", "PUBLIC KEY", pub)}},
		"routes": []any{map[string]any{
			"name": "zone-b-api", "peer_zone": "zone-b", "audience": audience, "connector_url": "https://connector.zone-b.test/",
			"client_id": clientID, "client_secret_file": filepath.Join(dir, "secret"),
			"fixture_outcomes": map[string]any{"issuer": vpIssuer, "kid": vpKid, "private_key_file": writePEM(t, dir, "key.pem", "EC PRIVATE KEY", priv), "role": vpRole},
		}},
	}
	raw, _ := json.Marshal(cfg)
	path := filepath.Join(dir, "acquire.json")
	_ = os.WriteFile(path, raw, 0o600)
	got, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	r, ok := got.Routes["zone-b-api"]
	if !ok || got.SigningKey != "token-store" || r.Outcomes == nil {
		t.Fatalf("loaded %+v", got)
	}
	ch := Challenge{Value: strings.Repeat("c", 43), ClientID: clientID, Audience: audience}
	seen := map[string]bool{}
	for range 2 {
		jws, err := r.Outcomes.Outcome(t.Context(), ch)
		if err != nil {
			t.Fatal(err)
		}
		o, err := if03.Verify(jws, got.Trusted, if03.Expect{ClientID: clientID, Challenge: ch.Value, Audience: audience}, time.Now())
		if err != nil {
			t.Fatalf("fixture outcome refused: %v", err)
		}
		if v := o.ExpiresAt.Sub(o.VerifiedAt); v < 60*time.Second || v > 120*time.Second {
			t.Errorf("validity %v", v)
		}
		seen[o.OutcomeID] = true
	}
	if len(seen) != 2 {
		t.Error("the fixture reused an outcome_id")
	}

	// Unknown members and missing fields are refused.
	for _, bad := range []string{`{"signing_key":"k","extra":1}`, `{"trusted_issuers":[]}`, `{"signing_key":"k"}`} {
		_ = os.WriteFile(path, []byte(bad), 0o600)
		if _, err := LoadConfig(path); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestLoadConfigBuildsTheSubstitutionRoutes(t *testing.T) {
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	issuers := []any{map[string]any{"issuer": vpIssuer, "kid": vpKid, "public_key_file": writePEM(t, dir, "pub.pem", "PUBLIC KEY", pub)}}
	route := func(name, tenant string, extra map[string]any) map[string]any {
		r := map[string]any{"name": name, "peer_zone": "zone-b", "audience": audience, "tenant": tenant,
			"connector_url": "https://connector.zone-b.test", "client_id": clientID, "client_secret_file": filepath.Join(dir, "secret")}
		for k, v := range extra {
			r[k] = v
		}
		return r
	}
	sub := map[string]any{"callers": []string{"spiffe://zone-a.test/ns/ztd-mgmt/sa/guard"}, "methods": []string{"GET"},
		"target_prefix": audience + "/v1"}
	load := func(routes ...any) (Loaded, error) {
		raw, _ := json.Marshal(map[string]any{"signing_key": "k", "trusted_issuers": issuers, "routes": routes})
		path := filepath.Join(dir, "acquire.json")
		_ = os.WriteFile(path, raw, 0o600)
		return LoadConfig(path)
	}
	got, err := load(route("a", "", sub), route("cli-only", "t1", nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Substitution) != 1 || got.Substitution[0].TargetPrefix != audience+"/v1" || got.Substitution[0].Tenant != "" {
		t.Fatalf("substitution routes %+v", got.Substitution)
	}
	if r, ok := got.For("zone-b", audience, "t1"); !ok || r.Name != "cli-only" {
		t.Errorf("For: %+v %v", r, ok)
	}
	for name, routes := range map[string][]any{
		"same route key":           {route("a", "", sub), route("b", "", nil)},
		"methods without callers":  {route("a", "", map[string]any{"methods": []string{"GET"}})},
		"caller not a SPIFFE ID":   {route("a", "", map[string]any{"callers": []string{"guard"}, "methods": []string{"GET"}, "target_prefix": audience})},
		"target prefix with dots":  {route("a", "", map[string]any{"callers": sub["callers"], "methods": []string{"GET"}, "target_prefix": audience + "/v1/../x"})},
		"callers without a method": {route("a", "", map[string]any{"callers": sub["callers"], "target_prefix": audience})},
	} {
		if _, err := load(routes...); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
