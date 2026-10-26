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
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/santhosh-tekuri/jsonschema/v6"

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
		RAT          string `json:"registration_access_token"`
	}
	if resp.StatusCode != http.StatusCreated || json.Unmarshal(regBody, &registered) != nil || registered.ClientID == "" || registered.RAT == "" {
		t.Fatalf("registration: status %d", resp.StatusCode)
	}

	// The accepted registration left its audit row, naming the client, the registrar and the
	// request; then four refusals, each audited with its rule or the library's reason, none of
	// them leaving a client. The nonce handshake of each call is no decision and leaves no row.
	registrations := 1
	for name, c := range map[string]struct {
		change func(m map[string]any)
		token  string
		rule   string
		code   string
	}{
		"no DPoP binding":  {func(m map[string]any) { m["dpop_bound_access_tokens"] = false }, registrarToken, ruleDPoPBound, "TOK-REGISTRATION-REJECTED"},
		"public client":    {func(m map[string]any) { m["token_endpoint_auth_method"] = "none" }, registrarToken, ruleAuthMethod, "TOK-REGISTRATION-REJECTED"},
		"redirect_uris":    {func(m map[string]any) { m["redirect_uris"] = []string{"https://x.example/cb"} }, registrarToken, ruleMembers, "TOK-REGISTRATION-REJECTED"},
		"no authorization": {nil, "", ruleLibrary, "TOK-MISSING"},
		// A token the store does not know: the library refuses it, the policy gives no verdict.
		"forged token": {func(m map[string]any) { m["dpop_bound_access_tokens"] = false }, "connector_at_forged.unknown", ruleLibrary, "TOK-INVALID"},
	} {
		m := map[string]any{"client_name": "refused " + name, "grant_types": []string{"client_credentials"},
			"token_endpoint_auth_method": "client_secret_basic", "scope": scope,
			"dpop_bound_access_tokens": true, "audience": []string{resourceAudience}}
		if c.change != nil {
			c.change(m)
		}
		body, _ := json.Marshal(m)
		resp, answer := dpopCall(t, &proofs, func(nonce string) (*http.Request, string) {
			req, _ := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Request-Id", "refused-"+strings.ReplaceAll(name, " ", "-"))
			if c.token != "" {
				req.Header.Set("Authorization", "DPoP "+c.token)
			}
			return req, dpoptest.Mint(t, registrarKey, dpoptest.Proof{Method: http.MethodPost, URL: endpoint, AccessToken: c.token, Nonce: nonce})
		})
		var refusal struct {
			Error, Reason, Description string `json:"-"`
		}
		var raw map[string]string
		_ = json.Unmarshal(answer, &raw)
		refusal.Error, refusal.Reason, refusal.Description = raw["error"], raw["reason"], raw["error_description"]
		switch c.rule {
		case ruleLibrary:
			if resp.StatusCode != http.StatusUnauthorized || refusal.Reason != "invalid_token" {
				t.Errorf("%s: %d %s", name, resp.StatusCode, answer)
			}
		default:
			if resp.StatusCode != http.StatusBadRequest || refusal.Error != "invalid_client_metadata" || refusal.Reason != "registration_rejected" || refusal.Description != ruleText[c.rule] {
				t.Errorf("%s: %d %s", name, resp.StatusCode, answer)
			}
		}
		registrations++
	}
	type auditRow struct {
		Kind, ClientID, Reason, Correlation, Detail string
	}
	rows, err := in.pool.Query(t.Context(), `SELECT kind, coalesce(client_id, ''), coalesce(reason_code, ''), coalesce(correlation_id, ''), detail::text
		FROM audit_event WHERE kind LIKE 'registration.%' ORDER BY event_id`)
	if err != nil {
		t.Fatal(err)
	}
	var audit []auditRow
	for rows.Next() {
		var a auditRow
		if err := rows.Scan(&a.Kind, &a.ClientID, &a.Reason, &a.Correlation, &a.Detail); err != nil {
			t.Fatal(err)
		}
		audit = append(audit, a)
	}
	rows.Close()
	if len(audit) != registrations {
		t.Fatalf("%d audit rows for %d registrations: %+v", len(audit), registrations, audit)
	}
	if a := audit[0]; a.Kind != "registration.accepted" || a.ClientID != registered.ClientID || a.Reason != "" ||
		!strings.Contains(a.Detail, `"registrar": "registrar"`) || !strings.Contains(a.Detail, `"client_name": "participant backend"`) {
		t.Errorf("accepted row: %+v", a)
	}
	rules := map[string]bool{}
	for _, a := range audit[1:] {
		if a.Kind != "registration.refused" || !strings.HasPrefix(a.Correlation, "refused-") {
			t.Errorf("refused row: %+v", a)
		}
		var detail struct {
			Rule   string `json:"rule"`
			Status int    `json:"status"`
		}
		_ = json.Unmarshal([]byte(a.Detail), &detail)
		rules[detail.Rule] = true
		if detail.Rule == ruleLibrary {
			if (a.Reason != "TOK-MISSING" && a.Reason != "TOK-INVALID") || a.ClientID != "" || detail.Status != http.StatusUnauthorized {
				t.Errorf("library refusal row: %+v", a)
			}
		} else if a.Reason != "TOK-REGISTRATION-REJECTED" || a.ClientID != "registrar" || detail.Status != http.StatusBadRequest {
			t.Errorf("policy refusal row: %+v", a)
		}
	}
	for _, rule := range []string{ruleDPoPBound, ruleAuthMethod, ruleMembers, ruleLibrary} {
		if !rules[rule] {
			t.Errorf("no audit row for rule %s: %v", rule, rules)
		}
	}
	var clients int
	if err := in.pool.QueryRow(t.Context(), `SELECT count(*) FROM oauth2_client`).Scan(&clients); err != nil || clients != 2 {
		t.Errorf("%d clients (registrar and one registered), err %v", clients, err)
	}
	var detailText string
	if err := in.pool.QueryRow(t.Context(), `SELECT coalesce(string_agg(detail::text, ' '), '') FROM audit_event`).Scan(&detailText); err != nil {
		t.Fatal(err)
	}
	for _, canary := range []string{registered.ClientSecret, registered.RAT, registrarToken, canaryRegistrarSecret} {
		if strings.Contains(detailText, canary) {
			t.Errorf("a secret reached the audit detail")
		}
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
		"registration access token": registered.RAT,
		"resource proof":            resourceProof, "Authorization header": "Authorization",
	}
	for i, p := range proofs {
		canaries["proof "+strconv.Itoa(i)] = p
	}
	noCanary(t, logs, canaries)
	for _, want := range []string{`"msg":"signer ready"`, `"msg":"registrar ready"`, `"msg":"ready"`, `"correlation_id":"token-call"`,
		`"path":"/oauth2/register"`, `"msg":"draining"`, `"window":"2m0s"`, `"outcome":"accepted"`, `"outcome":"refused"`} {
		if !strings.Contains(logs, want) {
			t.Errorf("records lack %s:\n%s", want, logs)
		}
	}
	// The IF-01 events of the first run, each valid against the contract: one registered, then one
	// refused per refusal, with its correlation id, its registry code and, for the policy's own, its rule.
	schema := if01Schema(t)
	var events []if01Event
	for _, line := range strings.Split(r.out.String(), "\n") {
		if !strings.Contains(line, `"kind":"token_event"`) {
			continue
		}
		doc, err := jsonschema.UnmarshalJSON(strings.NewReader(line))
		if err != nil {
			t.Fatalf("event line: %v\n%s", err, line)
		}
		if err := schema.Validate(doc); err != nil {
			t.Errorf("event violates the IF-01 contract: %v\n%s", err, line)
		}
		var ev if01Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("event line: %v\n%s", err, line)
		}
		events = append(events, ev)
	}
	if len(events) != registrations {
		t.Fatalf("%d events for %d registrations", len(events), registrations)
	}
	for i, ev := range events {
		if ev.Seq != uint64(i) || ev.Source != "connector-b" || !strings.HasPrefix(ev.RunID, "connector-b-") || ev.CorrelationID == "" {
			t.Errorf("event %d: %+v", i, ev)
		}
	}
	if events[0].Payload.State != "registered" || events[0].Payload.Detail != "client_id="+registered.ClientID {
		t.Errorf("registered event: %+v", events[0])
	}
	want := map[string][2]string{ // correlation id: reason code, rule id
		"refused-no-DPoP-binding":  {"TOK-REGISTRATION-REJECTED", ruleDPoPBound},
		"refused-public-client":    {"TOK-REGISTRATION-REJECTED", ruleAuthMethod},
		"refused-redirect_uris":    {"TOK-REGISTRATION-REJECTED", ruleMembers},
		"refused-no-authorization": {"TOK-MISSING", ""},
		"refused-forged-token":     {"TOK-INVALID", ""},
	}
	for _, ev := range events[1:] {
		w, known := want[ev.CorrelationID]
		if !known || ev.Payload.State != "refused" || ev.Payload.ReasonCode != w[0] || ev.Payload.RuleID != w[1] {
			t.Errorf("refused event: %+v", ev)
		}
		delete(want, ev.CorrelationID)
	}
	if len(want) != 0 {
		t.Errorf("no event for %v", want)
	}
}

// `connector register` against the running binary: it obtains the registrar's token, registers,
// writes the credentials file, and those credentials obtain a token; a metadata file the policy
// refuses exits 1 and leaves no file; no secret reaches its output.
func TestRegisterCommandAgainstTheBinary(t *testing.T) {
	in := newInfra(t)
	apiAddr := freeAddr(t)
	r := start(t, in.args(t, apiAddr, in.key.Version))
	waitFor(t, r, `"ready":true`)
	defer func() {
		if code := r.stop(t); code != exitOK {
			t.Errorf("exit %d after SIGTERM", code)
		}
	}()

	out := filepath.Join(t.TempDir(), "credentials.json")
	var stdout, stderr bytes.Buffer
	code := run([]string{"register", "--connector", "http://" + apiAddr, "--registrar-id", "registrar",
		"--registrar-secret-file", writeFile(t, "registrar-secret", canaryRegistrarSecret),
		"--client-name", "cli participant", "--scope", scope, "--audience", resourceAudience, "--out", out, "--request-id", "cli-register"}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("register: exit %d\n%s%s", code, stdout.String(), stderr.String())
	}
	content, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var creds struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if json.Unmarshal(content, &creds) != nil || len(creds.ClientID) != 64 || len(creds.ClientSecret) != 32 {
		t.Fatalf("credentials file: %s", content)
	}
	var proofs []string
	if tok := token(t, &proofs, apiAddr, creds.ClientID, creds.ClientSecret, dpoptest.NewKey(t), scope, resourceAudience); tok == "" {
		t.Error("the registered credentials obtained no token")
	}
	var kind, correlation string
	if err := in.pool.QueryRow(t.Context(), `SELECT kind, coalesce(correlation_id, '') FROM audit_event WHERE client_id = $1`, creds.ClientID).Scan(&kind, &correlation); err != nil ||
		kind != "registration.accepted" || correlation != "cli-register" {
		t.Errorf("audit row of the command's registration: %s %s %v", kind, correlation, err)
	}

	refused := filepath.Join(t.TempDir(), "refused.json")
	metadata := writeFile(t, "metadata.json", `{"client_name":"cli refused","grant_types":["client_credentials"],"token_endpoint_auth_method":"client_secret_basic","scope":"`+scope+`","dpop_bound_access_tokens":false,"audience":["`+resourceAudience+`"]}`)
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"register", "--connector", "http://" + apiAddr, "--registrar-id", "registrar",
		"--registrar-secret-file", writeFile(t, "registrar-secret", canaryRegistrarSecret),
		"--metadata-file", metadata, "--out", refused}, &stdout, &stderr)
	if code != exitRefused || !strings.Contains(stderr.String(), "registration refused: registration_rejected (400): "+ruleText[ruleDPoPBound]) {
		t.Errorf("refused register: exit %d\n%s%s", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(refused); !os.IsNotExist(err) {
		t.Errorf("a refused registration left a file")
	}
	noCanary(t, stdout.String()+stderr.String(), map[string]string{"client secret": creds.ClientSecret, "registrar secret": canaryRegistrarSecret})
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

	// connector register does the same for a VP client once it knows which scopes are delegable:
	// they stay out of the registrar's token, which can never carry them. Without that it asks the
	// token for the VP scope and is refused before anything is registered.
	registerVP := func(out string, extra ...string) (int, string) {
		var stdout, stderr bytes.Buffer
		code := run(append([]string{"register", "--connector", "http://" + apiAddr, "--registrar-id", "registrar",
			"--registrar-secret-file", writeFile(t, "registrar-secret", canaryRegistrarSecret),
			"--client-name", "cli vp participant", "--scope", vpScope, "--audience", resourceAudience,
			"--grant-types", oauth2provider.VerifiedPresentationGrantType, "--out", out}, extra...), &stdout, &stderr)
		return code, stdout.String() + stderr.String()
	}
	if code, output := registerVP(filepath.Join(t.TempDir(), "vp.json"), "--delegable-scopes", vpScope); code != exitOK {
		t.Errorf("register a VP client: exit %d\n%s", code, output)
	}
	if code, output := registerVP(filepath.Join(t.TempDir(), "vp.json")); code != exitRefused || !strings.Contains(output, "registrar token refused") {
		t.Errorf("register a VP client without its delegable scope named: exit %d\n%s", code, output)
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
