package renew

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/connectortest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/dpopproof"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/pgtest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/replay"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/tokenverify"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/transit"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/verificationclient"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/verificationclient/fixtureholder"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/verificationtest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/acquire"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/acquire/acquiretest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/testsupport"
)

// The end-to-end run of the verified-presentation grant with the deployable verification service:
// the real verification-service binary (its own PostgreSQL database, its outcome key in OpenBao
// transit, the pinned FIXTURE trust list), the token store's acquisition and renewal worker with the
// presentation hook, the real connector binary as zone B, and a protected resource that validates
// the DPoP-bound token with internal/tokenverify. A credential issuer and holder are generated for
// the run. The mesh is simulated: the hook's transport adds the X-Forwarded-Client-Cert header the
// service's sidecar would set. With VP_E2E_RECORD set, the run's transcript is written to that file.

const (
	storeSPIFFE = "spiffe://zone-a.test/ns/ztd-mgmt/sa/ztd-token-store"
	vsIssuer    = "https://verification.zone-a.test"
)

// sidecar stands in for the client and server proxies of the mesh: it sets the forwarded client
// certificate of the token store's identity on every request to the verification service.
type sidecar struct{ id string }

func (s sidecar) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("X-Forwarded-Client-Cert", `By=spiffe://zone-a.test/ns/ztd-mgmt/sa/verification-service;Hash=00;Subject="";URI=`+s.id)
	return http.DefaultTransport.RoundTrip(r)
}

type transcript struct {
	mu    sync.Mutex
	t     *testing.T
	lines []string
}

func (tr *transcript) step(format string, args ...any) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	line := fmt.Sprintf(format, args...)
	tr.t.Log(line)
	tr.lines = append(tr.lines, line)
}

func (tr *transcript) save() {
	if path := os.Getenv("VP_E2E_RECORD"); path != "" {
		_ = os.WriteFile(path, []byte(strings.Join(tr.lines, "\n")+"\n"), 0o600)
	}
}

// startVerificationService builds and runs the service binary; it returns its base URL and the
// trust-set entry of its outcome key, as the binary's trust-set command prints it.
func startVerificationService(t *testing.T, kit *verificationtest.Kit, baoAddr, baoToken string) (string, string, []byte, *pgxpool.Pool) {
	t.Helper()
	_, self, _, _ := runtime.Caller(0)
	bin := filepath.Join(t.TempDir(), "verification-service")
	build := exec.Command("go", "build", "-o", bin, "./services/verification-service")
	build.Dir = filepath.Join(filepath.Dir(self), "..", "..", "..", "..")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the verification service: %s", out)
	}
	dsn := pgtest.DatabaseURL(t, "vs_e2e")
	key := "vs-e2e-" + acquiretest.RandHex(6)
	api, ops := acquiretest.FreeAddr(t), acquiretest.FreeAddr(t)
	common := []string{"--openbao-url", baoAddr, "--openbao-token-file", acquiretest.WriteFile(t, "vs-bao-token", baoToken+"\n"),
		"--signing-key", key, "--issuer", vsIssuer}
	trustSet, err := exec.Command(bin, append([]string{"trust-set"}, common...)...).Output()
	if err != nil {
		t.Fatalf("trust-set: %v", err)
	}
	cmd := exec.Command(bin, append(append([]string{"serve"}, common...), "--addr", api, "--ops-addr", ops,
		"--public-url", "http://"+api, "--database-url", dsn, "--callers", storeSPIFFE,
		"--issuer-keys-file", kit.IssuerKeysFile, "--trust-list-file", kit.TrustListFile,
		"--accepted-vct", verificationtest.CredentialVCT, "--status-prefixes", kit.StatusPrefix)...)
	logs := &testsupport.Buffer{}
	cmd.Stdout, cmd.Stderr = logs, logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Signal(syscall.SIGTERM); _ = cmd.Wait() })
	for i := 0; ; i++ {
		if resp, err := http.Get("http://" + ops + "/readyz"); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if i == 100 {
			t.Fatalf("verification service never ready:\n%s", logs.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	pool, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("verification service records:\n%s", logs.String())
		}
	})
	return "http://" + api, key, trustSet, pool
}

func TestEndToEndPresentationGrantTokenProtectedCallAndRenewal(t *testing.T) {
	addr, token := os.Getenv("TRANSIT_TEST_ADDR"), os.Getenv("TRANSIT_TEST_TOKEN")
	if addr == "" || token == "" {
		t.Skip("TRANSIT_TEST_ADDR and TRANSIT_TEST_TOKEN not set")
	}
	ctx := t.Context()
	tr := &transcript{t: t}
	defer tr.save()

	// The credential side, generated for this run.
	kit := verificationtest.Provision(t, "https://issuer.zone-a.test")
	tr.step("provisioned: credential issuer %s (fresh P-256 key), holder (fresh P-256 key), status list at %s, pinned FIXTURE trust list listing the issuer", kit.Issuer, kit.StatusPrefix)

	// The verification service, and zone B trusting its outcome key as the consumers' file says.
	vsURL, vsKey, trustSet, vsDB := startVerificationService(t, kit, addr, token)
	trusted, err := if03.ParseIssuers(trustSet)
	if err != nil {
		t.Fatalf("trust-set output: %v", err)
	}
	kid := vsKey + "-v1"
	_, outcomeKey, ok := trusted.Key(kid)
	if !ok {
		t.Fatalf("trust-set names no key %s: %s", kid, trustSet)
	}
	tr.step("verification service up: binary, PostgreSQL request store, outcome key transit:%s:v1 (kid %s), caller allowed %s", vsKey, kid, storeSPIFFE)

	dsnB := pgtest.MigratedURL(t, "vpe2e_b")
	poolB, err := pgxpool.New(ctx, dsnB)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(poolB.Close)
	b := connectortest.Start(t, dsnB, addr, token, connectortest.Options{Issuer: acquiretest.BIssuer, VPIssuer: vsIssuer, VPKid: kid, VPKey: outcomeKey,
		Audiences: []string{acquiretest.Audience}, ScopeMap: []connectortest.Scope{{Role: acquiretest.VPRole, Entitlement: acquiretest.VPEntitle, Scopes: []string{acquiretest.VPScope}}}})
	clientID, secret := b.Register(t, "zone-a token store", acquiretest.VPScope, acquiretest.Audience)
	tr.step("zone B connector up: binary, trusts %s kid %s, scope map %s/%s -> %s", vsIssuer, kid, acquiretest.VPRole, acquiretest.VPEntitle, acquiretest.VPScope)

	// Zone A's token store with the presentation hook on the route.
	poolA, err := pgxpool.New(ctx, pgtest.MigratedURL(t, "vpe2e_a"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(poolA.Close)
	kv, err := transit.New(transit.Config{Addr: addr, Token: func(context.Context) (string, error) { return token, nil }})
	if err != nil {
		t.Fatal(err)
	}
	holder, err := fixtureholder.New(kit.Credential(t, acquiretest.VPRole, acquiretest.VPEntitle, verificationtest.CredentialOptions{}), kit.HolderKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	route := acquire.Route{Name: "zone-b-api", PeerZone: "zone-b", Audience: acquiretest.Audience, ConnectorURL: b.Base, ClientID: clientID,
		ClientSecretFile: acquiretest.WriteFile(t, "secret", secret+"\n"),
		Outcomes:         &verificationclient.Client{BaseURL: vsURL, Holder: holder, HTTP: &http.Client{Transport: sidecar{storeSPIFFE}}}}
	logs := &testsupport.Buffer{}
	a := &acquire.Acquirer{DB: poolA, Signer: kv, Secrets: kv, KeyName: "vpe2e-a-" + acquiretest.RandHex(6),
		Trusted: trusted, Log: slog.New(slog.NewJSONHandler(logs, nil)), Prefix: "ztd/token-store-e2e/" + acquiretest.RandHex(6)}

	// A protected resource of zone B.
	verifier, err := tokenverify.New(tokenverify.Config{Issuer: acquiretest.BIssuer, JWKSURL: b.Base + "/.well-known/jwks.json",
		Audience: acquiretest.Audience, PublicBaseURL: acquiretest.Audience, Scopes: []string{acquiretest.VPScope}, Replay: replay.NewMemory()})
	if err != nil {
		t.Fatal(err)
	}
	resource := httptest.NewServer(verifier.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, _ := tokenverify.FromContext(r.Context())
		_, _ = fmt.Fprintf(w, "protected resource served client %s", id.ClientID)
	})))
	defer resource.Close()
	call := func(label, tokenID string) {
		t.Helper()
		var ref string
		if err := poolA.QueryRow(ctx, `SELECT token_ref FROM upstream_token WHERE token_id = $1`, tokenID).Scan(&ref); err != nil {
			t.Fatal(err)
		}
		value, err := kv.Read(ctx, ref)
		if err != nil {
			t.Fatal(err)
		}
		key, err := acquire.LoadKey(ctx, poolA, kv, a.KeyName)
		if err != nil {
			t.Fatal(err)
		}
		ath := sha256.Sum256(value)
		proof, err := dpopproof.Build(ctx, key, dpopproof.Claims{HTM: http.MethodGet, HTU: acquiretest.Audience + "/resource", ATH: base64.RawURLEncoding.EncodeToString(ath[:])})
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest(http.MethodGet, resource.URL+"/resource", nil)
		req.Header.Set("Authorization", "DPoP "+string(value))
		req.Header.Set("DPoP", proof)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: protected call answered %d %s", label, resp.StatusCode, body)
		}
		tr.step("%s: protected call GET /resource with the DPoP-bound token -> %d %q", label, resp.StatusCode, body)
	}
	outcomes := func() []string {
		rows, err := vsDB.Query(ctx, `SELECT request_id || ' ' || challenge || ' ' || coalesce(outcome_id::text,'-') || ' ' || coalesce(status,'-') || ' ' || coalesce(reason_code,'-') || ' ' || coalesce(detail,'-') FROM verification_request ORDER BY created_at`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var s string
			_ = rows.Scan(&s)
			out = append(out, s)
		}
		return out
	}
	consumedAtB := func(outcomeID string) bool {
		var n int
		_ = poolB.QueryRow(ctx, `SELECT count(*) FROM verified_outcome WHERE outcome_id::text = $1 AND consumed_at IS NOT NULL`, outcomeID).Scan(&n)
		return n == 1
	}

	// 1. Acquisition: presentation -> outcome -> grant -> token -> protected call.
	tok, err := a.Acquire(ctx, route)
	if err != nil {
		t.Fatalf("acquisition: %v\n%s", err, logs.String())
	}
	first := outcomes()
	if len(first) != 1 || !strings.Contains(first[0], " verified - -") {
		t.Fatalf("verification records after the acquisition: %v", first)
	}
	firstOutcome := strings.Fields(first[0])[2]
	tr.step("acquisition: presentation verified, outcome %s signed by %s; record [request challenge outcome status reason detail] = %s", firstOutcome, kid, first[0])
	if !consumedAtB(firstOutcome) {
		t.Fatal("zone B did not consume the outcome for the grant")
	}
	tr.step("acquisition: zone B consumed outcome %s for the verified-presentation grant and issued token %s (expires %s)", firstOutcome, tok.ID, tok.ExpiresAt.UTC().Format(time.RFC3339))
	call("acquisition", tok.ID)

	// 2. Renewal: a fresh presentation, a new outcome, a new token, a protected call with it.
	if _, err := poolA.Exec(ctx, `UPDATE upstream_token SET renew_after = now() - interval '1 second' WHERE token_id = $1`, tok.ID); err != nil {
		t.Fatal(err)
	}
	w := &Worker{DB: poolA, Acquirer: a, Routes: acquire.Loaded{SigningKey: a.KeyName, Routes: map[string]acquire.Route{route.Name: route}},
		Instance: "e2e", Backoff: 10 * time.Millisecond, StaleAfter: time.Second, Log: slog.New(slog.NewJSONHandler(logs, nil))}
	w.Cycle(ctx)
	var renewed, oldState string
	if err := poolA.QueryRow(ctx, `SELECT token_id::text FROM upstream_token WHERE state = 'active'`).Scan(&renewed); err != nil || renewed == tok.ID {
		t.Fatalf("no new active token after renewal (%v)\n%s", err, logs.String())
	}
	_ = poolA.QueryRow(ctx, `SELECT state FROM upstream_token WHERE token_id = $1`, tok.ID).Scan(&oldState)
	second := outcomes()
	if len(second) != 2 || !strings.Contains(second[1], " verified - -") {
		t.Fatalf("verification records after the renewal: %v", second)
	}
	f1, f2 := strings.Fields(second[0]), strings.Fields(second[1])
	if f1[1] == f2[1] || f1[2] == f2[2] {
		t.Fatalf("the renewal reused a challenge or an outcome: %v", second)
	}
	if !consumedAtB(f2[2]) {
		t.Fatal("zone B did not consume the renewal's outcome")
	}
	tr.step("renewal: fresh presentation for a new challenge, outcome %s (first was %s); record = %s", f2[2], f1[2], second[1])
	tr.step("renewal: zone B consumed outcome %s and issued token %s; previous token %s is %s", f2[2], renewed, tok.ID, oldState)
	call("renewal", renewed)

	// 3. The service's own refusals, against the running binary.
	post := func(rt http.RoundTripper, path, ctype, body string) (int, string) {
		resp, err := (&http.Client{Transport: rt}).Post(vsURL+path, ctype, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, strings.TrimSpace(string(raw))
	}
	code, body := post(sidecar{storeSPIFFE}, verificationclient.ResponsesPath+f2[0], "application/x-www-form-urlencoded", url.Values{"vp_token": {"x"}}.Encode())
	if code != http.StatusNotFound || !strings.Contains(body, "CRED-REQUEST-UNKNOWN") {
		t.Fatalf("replay: %d %s", code, body)
	}
	tr.step("replay of the renewal's request %s -> %d %s", f2[0], code, body)
	reqBody, _ := json.Marshal(map[string]any{"challenge": f2[1], "client_id": clientID, "audience": acquiretest.Audience,
		"expires_at": time.Now().Add(time.Minute).UTC().Format(time.RFC3339)})
	code, body = post(sidecar{storeSPIFFE}, verificationclient.RequestsPath, "application/json", string(reqBody))
	if code != http.StatusBadRequest || !strings.Contains(body, "CRED-REQUEST-INVALID") {
		t.Fatalf("challenge replay: %d %s", code, body)
	}
	tr.step("replay of the renewal's challenge at /v1/requests -> %d %s", code, body)
	code, body = post(sidecar{"spiffe://zone-a.test/ns/ztd-data/sa/participant"}, verificationclient.RequestsPath, "application/json", string(reqBody))
	if code != http.StatusForbidden {
		t.Fatalf("another caller: %d %s", code, body)
	}
	tr.step("request from another mesh identity (ztd-data/participant) -> %d %s", code, body)
	code, body = post(http.DefaultTransport, verificationclient.RequestsPath, "application/json", string(reqBody))
	if code != http.StatusForbidden {
		t.Fatalf("no identity: %d %s", code, body)
	}
	tr.step("request without a forwarded mesh identity -> %d %s", code, body)

	// 4. A revoked credential: the service signs a revoked outcome, the store refuses it, zone B issues nothing.
	kit.Revoke(true)
	// The service may rely on a fetched list for its ttl (1 s here, never more than 60 s): the bound
	// on how long a revocation takes to be seen.
	time.Sleep(1500 * time.Millisecond)
	before := len(outcomes())
	_, err = a.Acquire(ctx, route)
	if err == nil || !strings.Contains(err.Error(), if03.CodeNotVerified) {
		t.Fatalf("a revoked credential: %v; want %s", err, if03.CodeNotVerified)
	}
	after := outcomes()
	if len(after) != before+1 || !strings.Contains(after[len(after)-1], " revoked CRED-REVOKED -") {
		t.Fatalf("revoked: %v", after)
	}
	revokedOutcome := strings.Fields(after[len(after)-1])[2]
	if consumedAtB(revokedOutcome) {
		t.Fatal("zone B consumed a revoked outcome")
	}
	tr.step("revoked credential: record = %s; the store refused the outcome (%v), zone B consumed nothing", after[len(after)-1], err)
	var buf bytes.Buffer
	_ = json.Indent(&buf, trustSet, "", "  ")
	tr.step("trust-set printed by the service for the consumers:\n%s", buf.String())
}
