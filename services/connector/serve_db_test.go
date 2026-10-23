package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/pgtest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/replay"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/tokenverify"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/transit"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/dpoptest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/signing"
)

const scope = "resource.read"

// infra is a migrated database of the test's own, a fresh transit key on the dev OpenBao and a child
// token of its own (a canary, unlike the dev root token). The test skips without
// TOKEN_STORE_TEST_DATABASE_URL, TRANSIT_TEST_ADDR and TRANSIT_TEST_TOKEN.
type infra struct {
	dsn, openbao, baoToken, tokenFile string
	key                               transit.KeyVersion
	pool                              *pgxpool.Pool
}

func newInfra(t *testing.T) infra {
	t.Helper()
	addr, root := os.Getenv("TRANSIT_TEST_ADDR"), os.Getenv("TRANSIT_TEST_TOKEN")
	if addr == "" || root == "" {
		t.Skip("TRANSIT_TEST_ADDR and TRANSIT_TEST_TOKEN not set")
	}
	addr = strings.TrimSuffix(addr, "/")
	dsn := pgtest.MigratedURL(t, "connector")
	pool, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	// pgtest applies the files directly; record them as the token store's runner would.
	if _, err := pool.Exec(t.Context(), `CREATE TABLE schema_migrations (version integer PRIMARY KEY, name text NOT NULL,
		checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now());
		INSERT INTO schema_migrations (version, name, checksum) SELECT v, 'm', '' FROM generate_series(1, `+strconv.Itoa(schemaVersion)+`) v`); err != nil {
		t.Fatal(err)
	}

	bao := func(path, body string, out any) int {
		req, _ := http.NewRequest(http.MethodPost, addr+path, strings.NewReader(body))
		req.Header.Set("X-Vault-Token", root)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if out != nil {
			_ = json.NewDecoder(resp.Body).Decode(out)
		}
		return resp.StatusCode
	}
	if s := bao("/v1/sys/mounts/transit", `{"type":"transit"}`, nil); s != http.StatusNoContent && s != http.StatusBadRequest {
		t.Fatalf("enabling transit: status %d", s)
	}
	var created struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if s := bao("/v1/auth/token/create", `{"policies":["root"],"ttl":"10m"}`, &created); s != http.StatusOK || created.Auth.ClientToken == "" {
		t.Fatalf("creating a token: status %d", s)
	}
	client, err := transit.New(transit.Config{Addr: addr, Token: func(context.Context) (string, error) { return root, nil }})
	if err != nil {
		t.Fatal(err)
	}
	suffix := make([]byte, 6)
	_, _ = rand.Read(suffix)
	key, err := client.EnsureKey(t.Context(), "connector-at-"+hex.EncodeToString(suffix))
	if err != nil {
		t.Fatal(err)
	}
	return infra{dsn: dsn, openbao: addr, baoToken: created.Auth.ClientToken,
		tokenFile: writeFile(t, "bao-token", created.Auth.ClientToken+"\n"), key: key, pool: pool}
}

// args runs the connector on a fixed API address, so its registration endpoint is the URL a client
// actually reaches, and a restart keeps it.
func (in infra) args(t *testing.T, apiAddr string, version int) []string {
	endpoint := "http://" + apiAddr + "/oauth2/register"
	return append(baseArgs(t, in.dsn, in.openbao), "--addr", apiAddr, "--openbao-token-file", in.tokenFile,
		"--signing-key", in.key.Name, "--signing-key-version", strconv.Itoa(version),
		"--registration-endpoint", endpoint, "--registrar-audiences", endpoint+","+resourceAudience)
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().String()
}

// dpopCall sends the request build makes for a nonce (none first), and once more with the server's
// nonce when it asks for one. Every proof minted is appended to proofs.
func dpopCall(t *testing.T, proofs *[]string, build func(nonce string) (*http.Request, string)) (*http.Response, []byte) {
	t.Helper()
	nonce := ""
	for range 2 {
		req, proof := build(nonce)
		*proofs = append(*proofs, proof)
		req.Header.Set("DPoP", proof)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var body bytes.Buffer
		_, _ = body.ReadFrom(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode < 300 || resp.Header.Get("DPoP-Nonce") == "" || nonce != "" {
			return resp, body.Bytes()
		}
		nonce = resp.Header.Get("DPoP-Nonce")
	}
	panic("unreachable")
}

// token asks for a client_credentials token bound to key.
func token(t *testing.T, proofs *[]string, apiAddr, id, secret string, key *dpoptest.Key, scope, audience string) string {
	t.Helper()
	tokenURL := "http://" + apiAddr + "/oauth2/token"
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {scope}, "audience": {audience}}
	resp, body := dpopCall(t, proofs, func(nonce string) (*http.Request, string) {
		req, _ := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Request-Id", "token-call")
		req.SetBasicAuth(url.QueryEscape(id), url.QueryEscape(secret))
		return req, dpoptest.Mint(t, key, dpoptest.Proof{Method: http.MethodPost, URL: tokenURL, Nonce: nonce})
	})
	var issued struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &issued) != nil || issued.TokenType != "DPoP" || issued.AccessToken == "" {
		t.Fatalf("token for %s: status %d", id, resp.StatusCode)
	}
	return issued.AccessToken
}

// The binary end to end against PostgreSQL and OpenBao: it seeds the registrar on an empty database;
// the registrar gets a DPoP-bound token for the registration endpoint and a resource audience and
// registers a client; that client's token is accepted by tokenverify through the binary's key set.
// The connector drains on SIGTERM, a restart with the same settings is ready again, and a restart
// with another registrar secret is not. No secret, token, proof or URL reaches the records.
func TestServeBootstrapsTheRegistrarAndIssuesVerifiableTokens(t *testing.T) {
	in := newInfra(t)
	apiAddr := freeAddr(t)
	args := in.args(t, apiAddr, in.key.Version)
	r := start(t, args)
	waitFor(t, r, `"ready":true`)

	code, hdr, body := get(t, "http://"+apiAddr+"/.well-known/jwks.json")
	if code != http.StatusOK || hdr.Get("Cache-Control") != "public, max-age=300" ||
		!strings.Contains(body, `"use":"sig"`) || !strings.Contains(body, `"alg":"ES256"`) {
		t.Errorf("jwks %d %v %s", code, hdr, body)
	}

	var proofs []string
	registrarKey := dpoptest.NewKey(t)
	endpoint := "http://" + apiAddr + "/oauth2/register"
	registrarToken := token(t, &proofs, apiAddr, "registrar", canaryRegistrarSecret, registrarKey,
		oauth2provider.RegistrationScope+" "+scope, endpoint+" "+resourceAudience)

	metadata, _ := json.Marshal(map[string]any{
		"client_name": "participant backend", "grant_types": []string{"client_credentials"},
		"token_endpoint_auth_method": "client_secret_basic", "scope": scope,
		"dpop_bound_access_tokens": true, "audience": []string{resourceAudience},
	})
	resp, regBody := dpopCall(t, &proofs, func(nonce string) (*http.Request, string) {
		req, _ := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(metadata))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "DPoP "+registrarToken)
		return req, dpoptest.Mint(t, registrarKey, dpoptest.Proof{Method: http.MethodPost, URL: endpoint, AccessToken: registrarToken, Nonce: nonce})
	})
	var registered struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if resp.StatusCode != http.StatusCreated || json.Unmarshal(regBody, &registered) != nil || registered.ClientID == "" {
		t.Fatalf("registration: status %d", resp.StatusCode)
	}

	clientKey := dpoptest.NewKey(t)
	clientToken := token(t, &proofs, apiAddr, registered.ClientID, registered.ClientSecret, clientKey, scope, resourceAudience)
	verifier, err := tokenverify.New(tokenverify.Config{
		Issuer: "https://connector.example", JWKSURL: "http://" + apiAddr + "/.well-known/jwks.json",
		Audience: resourceAudience, PublicBaseURL: resourceAudience, Scopes: []string{scope}, Replay: replay.NewPostgres(in.pool),
	})
	if err != nil {
		t.Fatal(err)
	}
	resourceProof := dpoptest.Mint(t, clientKey, dpoptest.Proof{Method: http.MethodGet, URL: resourceAudience + "/data", AccessToken: clientToken})
	call, _ := http.NewRequest(http.MethodGet, resourceAudience+"/data", nil)
	call.Header.Set("Authorization", "DPoP "+clientToken)
	call.Header.Set("DPoP", resourceProof)
	if id, err := verifier.Verify(call); err != nil || id.ClientID != registered.ClientID || id.JKT != clientKey.Thumbprint() {
		t.Fatalf("tokenverify: %+v, %v", id, err)
	}

	if code := r.stop(t); code != exitOK || !r.sawDraining {
		t.Errorf("exit %d after SIGTERM, readiness drained: %v", code, r.sawDraining)
	}
	logs := r.out.String() + r.errOut.String()

	// A restart with the same settings finds the registrar as it left it.
	again := start(t, args)
	waitFor(t, again, `"ready":true`)
	if code := again.stop(t); code != exitOK {
		t.Errorf("restart: exit %d", code)
	}
	logs += again.out.String() + again.errOut.String()

	// Another registrar secret is a conflict: never overwritten, never ready.
	other := start(t, append(args, "--registrar-secret-file", writeFile(t, "other-registrar", "another-registrar-secret-0123456789abcdef")))
	waitFor(t, other, `"registrar":"conflict"`)
	if code := other.stop(t); code != exitOK {
		t.Errorf("conflicting restart: exit %d", code)
	}
	otherLogs := other.out.String() + other.errOut.String()
	if !strings.Contains(otherLogs, "registrar client exists with other settings") {
		t.Errorf("the conflict was not recorded")
	}
	logs += otherLogs

	// Columns as configured but metadata on the row: the provider would read the metadata, which can
	// say more than the columns, so this is a conflict too.
	if _, err := in.pool.Exec(t.Context(), `UPDATE oauth2_client SET metadata = '{"scope":"connector:client_registration resource.read resource.admin"}' WHERE client_id = $1`, "registrar"); err != nil {
		t.Fatal(err)
	}
	withMetadata := start(t, args)
	waitFor(t, withMetadata, `"registrar":"conflict"`)
	if code := withMetadata.stop(t); code != exitOK {
		t.Errorf("restart with metadata: exit %d", code)
	}
	logs += withMetadata.out.String() + withMetadata.errOut.String()

	canaries := map[string]string{
		"database URL": in.dsn, "postgres scheme": "postgres://", "OpenBao token": in.baoToken,
		"token secret": strings.TrimSpace(canaryTokenSecret), "registration secret": canaryRegistrationSecret,
		"registrar secret": canaryRegistrarSecret, "other registrar secret": "another-registrar-secret",
		"registrar token": registrarToken, "client secret": registered.ClientSecret, "client token": clientToken,
		"resource proof": resourceProof, "Authorization header": "Authorization",
	}
	for i, p := range proofs {
		canaries["proof "+strconv.Itoa(i)] = p
	}
	noCanary(t, logs, canaries)
	for _, want := range []string{`"msg":"signer ready"`, `"msg":"registrar ready"`, `"msg":"ready"`, `"correlation_id":"token-call"`,
		`"path":"/oauth2/register"`, `"msg":"draining"`, `"window":"2m0s"`} {
		if !strings.Contains(logs, want) {
			t.Errorf("records lack %s:\n%s", want, logs)
		}
	}
}

// A pinned key version that does not exist keeps the connector not ready and serving no token.
func TestServeIsNotReadyWithoutTheKeyVersion(t *testing.T) {
	in := newInfra(t)
	apiAddr := freeAddr(t)
	r := start(t, in.args(t, apiAddr, in.key.Version+5))
	body := waitFor(t, r, `"registrar":"ok"`)
	if !strings.Contains(body, `"signing_key":"missing"`) || !strings.Contains(body, `"postgres":"ok"`) || !strings.Contains(body, `"openbao":"ok"`) {
		t.Errorf("readyz %s", body)
	}
	if code, _, _ := get(t, "http://"+apiAddr+"/.well-known/jwks.json"); code != http.StatusServiceUnavailable {
		t.Errorf("jwks %d, want 503", code)
	}
	if code := r.stop(t); code != exitOK {
		t.Errorf("exit %d after SIGTERM", code)
	}
}

// waitFor polls /readyz until its body contains want and returns that body.
func waitFor(t *testing.T, r *running, want string) string {
	t.Helper()
	var body string
	for range 100 {
		if _, _, body = get(t, "http://"+r.opsAddr+"/readyz"); strings.Contains(body, want) {
			return body
		}
		select {
		case <-r.exit:
			t.Fatalf("serve exited:\n%s", r.out.String())
		default:
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("readyz never had %s: %s\n%s", want, body, r.out.String())
	return ""
}

// The verified-presentation grant through the binary: started with a trusted issuer and a scope map,
// the connector lets the registrar register a client for a delegated VP scope; that client gets a
// challenge, exchanges an IF-03 outcome signed for it for a DPoP-bound token that tokenverify accepts
// with the VP scope through the binary's key set, and a second use of the outcome is refused as
// consumed.
func TestServeIssuesVerifiedPresentationTokens(t *testing.T) {
	in := newInfra(t)
	apiAddr := freeAddr(t)
	issuerKey, jwk := testJWK(t, "verifier-key-1")
	args := append(in.args(t, apiAddr, in.key.Version),
		"--vp-trusted-issuers-file", writeFile(t, "issuers.json", `{"`+vpIssuer+`":{"keys":[`+jwk+`]}}`),
		"--vp-scope-map-file", writeFile(t, "scopes.json", `[{"role":"operator","scopes":["`+vpScope+`"]}]`),
		"--registrar-delegable-scopes", vpScope)
	r := start(t, args)
	waitFor(t, r, `"ready":true`)
	defer func() {
		if code := r.stop(t); code != exitOK {
			t.Errorf("exit %d after SIGTERM", code)
		}
	}()

	var proofs []string
	registrarKey := dpoptest.NewKey(t)
	endpoint := "http://" + apiAddr + "/oauth2/register"
	registrarToken := token(t, &proofs, apiAddr, "registrar", canaryRegistrarSecret, registrarKey,
		oauth2provider.RegistrationScope+" "+scope, endpoint+" "+resourceAudience)
	metadata, _ := json.Marshal(map[string]any{
		"client_name": "participant backend", "grant_types": []string{"client_credentials", oauth2provider.VerifiedPresentationGrantType},
		"token_endpoint_auth_method": "client_secret_basic", "scope": vpScope,
		"dpop_bound_access_tokens": true, "audience": []string{resourceAudience},
	})
	resp, regBody := dpopCall(t, &proofs, func(nonce string) (*http.Request, string) {
		req, _ := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(metadata))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "DPoP "+registrarToken)
		return req, dpoptest.Mint(t, registrarKey, dpoptest.Proof{Method: http.MethodPost, URL: endpoint, AccessToken: registrarToken, Nonce: nonce})
	})
	var client struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if resp.StatusCode != http.StatusCreated || json.Unmarshal(regBody, &client) != nil || client.ClientID == "" {
		t.Fatalf("registration: status %d %s", resp.StatusCode, regBody)
	}

	form := url.Values{"audience": {resourceAudience}}
	req, _ := http.NewRequest(http.MethodPost, "http://"+apiAddr+"/oauth2/challenge", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(client.ClientID), url.QueryEscape(client.ClientSecret))
	chResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var challenged struct {
		Challenge string `json:"challenge"`
		ExpiresIn int    `json:"expires_in"`
	}
	if err := json.NewDecoder(chResp.Body).Decode(&challenged); err != nil || chResp.StatusCode != http.StatusOK || challenged.Challenge == "" {
		t.Fatalf("challenge: status %d, %v", chResp.StatusCode, err)
	}
	_ = chResp.Body.Close()

	id := make([]byte, 16)
	_, _ = rand.Read(id)
	now := time.Now().UTC()
	payload, _ := json.Marshal(map[string]any{
		"iss": vpIssuer, "outcome_id": fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:]),
		"client_id": client.ClientID, "challenge": challenged.Challenge, "audience": resourceAudience,
		"claims": map[string]string{"role": "operator"}, "status": "verified",
		"verified_at": now.Add(-5 * time.Second).Format(time.RFC3339), "expires_at": now.Add(100 * time.Second).Format(time.RFC3339),
	})
	issuer, err := signing.NewLocal(issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := jose.Sign(t.Context(), jose.Header{Typ: if03.Typ, Kid: "verifier-key-1"}, payload, issuer.Sign)
	if err != nil {
		t.Fatal(err)
	}

	clientKey := dpoptest.NewKey(t)
	tokenURL := "http://" + apiAddr + "/oauth2/token"
	grant := func() (*http.Response, []byte) {
		vpForm := url.Values{"grant_type": {oauth2provider.VerifiedPresentationGrantType}, "outcome": {outcome},
			"challenge": {challenged.Challenge}, "audience": {resourceAudience}}
		return dpopCall(t, &proofs, func(nonce string) (*http.Request, string) {
			req, _ := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(vpForm.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.SetBasicAuth(url.QueryEscape(client.ClientID), url.QueryEscape(client.ClientSecret))
			return req, dpoptest.Mint(t, clientKey, dpoptest.Proof{Method: http.MethodPost, URL: tokenURL, Nonce: nonce})
		})
	}
	resp, body := grant()
	var issued struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &issued) != nil || issued.TokenType != "DPoP" || issued.Scope != vpScope {
		t.Fatalf("verified-presentation grant: status %d %s", resp.StatusCode, body)
	}

	verifier, err := tokenverify.New(tokenverify.Config{
		Issuer: "https://connector.example", JWKSURL: "http://" + apiAddr + "/.well-known/jwks.json",
		Audience: resourceAudience, PublicBaseURL: resourceAudience, Scopes: []string{vpScope}, Replay: replay.NewPostgres(in.pool),
	})
	if err != nil {
		t.Fatal(err)
	}
	call, _ := http.NewRequest(http.MethodGet, resourceAudience+"/data", nil)
	call.Header.Set("Authorization", "DPoP "+issued.AccessToken)
	call.Header.Set("DPoP", dpoptest.Mint(t, clientKey, dpoptest.Proof{Method: http.MethodGet, URL: resourceAudience + "/data", AccessToken: issued.AccessToken}))
	if got, err := verifier.Verify(call); err != nil || got.ClientID != client.ClientID || got.JKT != clientKey.Thumbprint() {
		t.Fatalf("tokenverify: %+v, %v", got, err)
	}

	resp, body = grant()
	var refused struct{ Error, Reason string }
	if resp.StatusCode != http.StatusBadRequest || json.Unmarshal(body, &refused) != nil ||
		refused.Error != "invalid_grant" || refused.Reason != if03.CodeConsumed {
		t.Errorf("second use of the outcome: status %d %s, want 400 invalid_grant %s", resp.StatusCode, body, if03.CodeConsumed)
	}
}
