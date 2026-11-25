package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/meshcaller"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/pgtest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/sdjwt/sdjwtfixture"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/verificationtest"
)

// These tests run the service's handlers against a real PostgreSQL (TOKEN_STORE_TEST_DATABASE_URL;
// they skip without it), a credential issuer, holder and status list generated per test
// (verificationtest.Provision) and the pinned FIXTURE trust list. Outcomes are signed with a process
// key here; the transit signer runs in the end-to-end test.

const (
	storeID  = "spiffe://zone-a.example/ns/ztd-mgmt/sa/ztd-token-store"
	otherID  = "spiffe://zone-a.example/ns/ztd-mgmt/sa/ztd-token-store-2"
	mallory  = "spiffe://zone-a.example/ns/ztd-data/sa/participant"
	issuer   = "https://verifier.zone-a.test"
	audience = "https://api.zone-b.test"
	client   = "zone-a-token-store"
)

type harness struct {
	t      *testing.T
	kit    *verificationtest.Kit
	srv    *httptest.Server
	db     *pgxpool.Pool
	key    *ecdsa.PrivateKey
	logs   *strings.Builder
	logsMu *sync.Mutex
	// refresh rebuilds the policy, as the service's ticker does; its status-list cache starts empty.
	refresh func()
}

type lockedWriter struct {
	mu *sync.Mutex
	b  *strings.Builder
}

func (w lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dsn := pgtest.DatabaseURL(t, "vs")
	db, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	h := &harness{t: t, kit: verificationtest.Provision(t, "https://issuer.zone-a.test"), db: db, logs: &strings.Builder{}, logsMu: &sync.Mutex{}}
	h.key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	callers, _ := meshcaller.NewXFCC([]string{storeID, otherID})
	s := &server{store: store{db: db}, callers: callers, issuer: issuer, kid: "outcome-1", publicURL: "https://verification.zone-a.test",
		log: slog.New(slog.NewJSONHandler(lockedWriter{h.logsMu, h.logs}, nil)), now: time.Now,
		sign: func(_ context.Context, in []byte) ([]byte, error) { return sdjwtfixture.SignES256(h.key, in) }}
	if err := s.store.migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	tc := trustConfig{keysFile: h.kit.IssuerKeysFile, listed: pinnedList(h.kit.TrustListFile),
		acceptedVCT: []string{verificationtest.CredentialVCT}, statusPrefixes: []string{h.kit.StatusPrefix}}
	h.refresh = func() { tc.refresh(t.Context(), s) }
	h.refresh()
	if s.policyAt(time.Now()) == nil {
		t.Fatal("no policy")
	}
	h.srv = httptest.NewServer(s.routes())
	t.Cleanup(h.srv.Close)
	return h
}

func xfcc(id string) string {
	return `By=spiffe://zone-a.example/ns/ztd-mgmt/sa/verification-service;Hash=00;Subject="";URI=` + id
}

func (h *harness) post(caller, path, contentType, body string) (int, map[string]any) {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	if caller != "" {
		req.Header.Set("X-Forwarded-Client-Cert", xfcc(caller))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func challenge() string { return strings.ReplaceAll(rand.Text(), "=", "") }

func (h *harness) open(caller, ch string) (int, map[string]any) {
	body, _ := json.Marshal(map[string]any{"challenge": ch, "client_id": client, "audience": audience,
		"expires_at": time.Now().Add(100 * time.Second).UTC().Format(time.RFC3339)})
	return h.post(caller, "/v1/requests", "application/json", string(body))
}

func (h *harness) answer(caller, id, vpToken string) (int, map[string]any) {
	return h.post(caller, "/v1/responses/"+id, "application/x-www-form-urlencoded", url.Values{"vp_token": {vpToken}}.Encode())
}

// present opens a request for a new challenge and answers it with credential, key binding signed by
// holderKey; it returns the request id and the answer.
func (h *harness) present(credential string, holderKey *ecdsa.PrivateKey) (string, int, map[string]any) {
	h.t.Helper()
	ch := challenge()
	status, req := h.open(storeID, ch)
	if status != http.StatusCreated {
		h.t.Fatalf("create: %d %v", status, req)
	}
	id := req["request_id"].(string)
	vp, err := sdjwtfixture.Present(context.Background(), credential, holderKey, ch, audience, time.Now())
	if err != nil {
		h.t.Fatal(err)
	}
	code, out := h.answer(storeID, id, vp)
	return id, code, out
}

func (h *harness) row(id string) (status, reason, detail string) {
	h.t.Helper()
	var s, r, d *string
	if err := h.db.QueryRow(context.Background(), `SELECT status, reason_code, detail FROM verification_request WHERE request_id = $1`, id).Scan(&s, &r, &d); err != nil {
		h.t.Fatal(err)
	}
	deref := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	return deref(s), deref(r), deref(d)
}

// outcome is the payload of a signed outcome, read without judging it.
func (h *harness) outcome(out map[string]any) if03.Outcome {
	h.t.Helper()
	parts := strings.Split(out["outcome"].(string), ".")
	raw, err := jose.DecodeB64(parts[1])
	var o if03.Outcome
	if err != nil || json.Unmarshal(raw, &o) != nil {
		h.t.Fatalf("outcome not readable: %v", err)
	}
	return o
}

func TestAVerifiedPresentationYieldsASignedVerifiedOutcome(t *testing.T) {
	h := newHarness(t)
	id, code, out := h.present(h.kit.Credential(t, "participant-operator", "write", verificationtest.CredentialOptions{}), h.kit.HolderKey)
	if code != http.StatusOK || out["status"] != if03.StatusVerified {
		t.Fatalf("%d %v", code, out)
	}
	o, err := if03.Verify(out["outcome"].(string), if03.Issuers{issuer: {"outcome-1": &h.key.PublicKey}},
		if03.Expect{ClientID: client, Challenge: h.outcome(out).Challenge, Audience: audience}, time.Now())
	if err != nil || o.Claims.Role != "participant-operator" || o.Claims.Entitlement != "write" || o.ClientID != client {
		t.Fatalf("outcome %+v: %v", o, err)
	}
	if s, r, d := h.row(id); s != if03.StatusVerified || r != "" || d != "" {
		t.Errorf("recorded %s/%s/%s", s, r, d)
	}
}

// Every failure the review names is a distinct refusal: an IF-03 status and reason code in the
// signed outcome, and for the two that share CRED-INVALID a distinct detail in the service's record;
// for the request rules a contract refusal with its own detail.
func TestEachFailureIsADistinctRefusal(t *testing.T) {
	h := newHarness(t)
	ok := verificationtest.CredentialOptions{}
	stranger, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	type want struct{ status, reason, detail string }
	got := map[string]want{}
	for name, c := range map[string]struct {
		credential string
		holder     *ecdsa.PrivateKey
		revoke     bool
		want       want
	}{
		"untrusted issuer":   {credential: h.kit.Credential(t, "r", "e", verificationtest.CredentialOptions{FromUnlisted: true}), holder: h.kit.HolderKey, want: want{if03.StatusFailed, if03.CodeIssuerUntrusted, ""}},
		"revoked":            {credential: h.kit.Credential(t, "r", "e", ok), holder: h.kit.HolderKey, revoke: true, want: want{if03.StatusRevoked, if03.CodeRevoked, ""}},
		"wrong holder":       {credential: h.kit.Credential(t, "r", "e", ok), holder: stranger, want: want{if03.StatusFailed, if03.CodeInvalid, "holder-binding"}},
		"expired":            {credential: h.kit.Credential(t, "r", "e", verificationtest.CredentialOptions{ExpiresAt: time.Now().Add(-time.Hour)}), holder: h.kit.HolderKey, want: want{if03.StatusFailed, if03.CodeInvalid, "credential-expired"}},
		"malformed vp_token": {credential: "", want: want{"", codeRequestInvalid, "malformed-vp-token"}},
		"not a presentation": {credential: "garbage", want: want{if03.StatusFailed, if03.CodeInvalid, "malformed-presentation"}},
	} {
		t.Run(name, func(t *testing.T) {
			h.kit.Revoke(c.revoke)
			h.refresh()
			defer func() { h.kit.Revoke(false); h.refresh() }()
			ch := challenge()
			_, req := h.open(storeID, ch)
			id := req["request_id"].(string)
			vp := c.credential
			if c.holder != nil {
				var err error
				if vp, err = sdjwtfixture.Present(context.Background(), c.credential, c.holder, ch, audience, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			code, out := h.answer(storeID, id, vp)
			s, r, d := h.row(id)
			switch {
			case c.want.status == "":
				if code != http.StatusBadRequest || out["reason_code"] != c.want.reason {
					t.Fatalf("%d %v", code, out)
				}
			case code != http.StatusOK || out["status"] != c.want.status || h.outcome(out).ReasonCode != c.want.reason:
				t.Fatalf("%d %v", code, out)
			}
			if (want{s, r, d}) != c.want {
				t.Errorf("recorded %s/%s/%s; want %+v", s, r, d, c.want)
			}
			got[name] = c.want
		})
	}
	seen := map[want]string{}
	for name, w := range got {
		if prev, dup := seen[w]; dup {
			t.Errorf("%s and %s are the same refusal %+v", name, prev, w)
		}
		seen[w] = name
	}
}

func TestARequestIsAnsweredOnceAndAChallengeOpenedOnce(t *testing.T) {
	h := newHarness(t)
	credential := h.kit.Credential(t, "r", "e", verificationtest.CredentialOptions{})
	ch := challenge()
	_, req := h.open(storeID, ch)
	id := req["request_id"].(string)
	vp, _ := sdjwtfixture.Present(context.Background(), credential, h.kit.HolderKey, ch, audience, time.Now())

	// Ten concurrent answers to one request: exactly one is judged.
	var wg sync.WaitGroup
	codes := make(chan int, 10)
	for range 10 {
		wg.Add(1)
		go func() { defer wg.Done(); c, _ := h.answer(storeID, id, vp); codes <- c }()
	}
	wg.Wait()
	close(codes)
	n := map[int]int{}
	for c := range codes {
		n[c]++
	}
	if n[http.StatusOK] != 1 || n[http.StatusNotFound] != 9 {
		t.Fatalf("answers %v; want one 200 and nine 404", n)
	}
	if code, out := h.answer(storeID, id, vp); code != http.StatusNotFound || out["reason_code"] != codeRequestUnknown {
		t.Errorf("replayed request: %d %v", code, out)
	}
	if !strings.Contains(h.log(), `"detail":"replayed"`) {
		t.Error("the replay is not recorded as such")
	}
	// The challenge cannot be opened again, answered or not.
	if code, out := h.open(storeID, ch); code != http.StatusBadRequest || out["reason_code"] != codeRequestInvalid {
		t.Errorf("replayed challenge: %d %v", code, out)
	}
	if !strings.Contains(h.log(), `"detail":"challenge-replayed"`) {
		t.Error("the challenge replay is not recorded as such")
	}
	if code, out := h.answer(storeID, "0123456789abcdef0123456789abcdef", vp); code != http.StatusNotFound || out["reason_code"] != codeRequestUnknown {
		t.Errorf("unknown request: %d %v", code, out)
	}
	if code, out := h.post(storeID, "/v1/requests", "application/json", `{"challenge":"short"}`); code != http.StatusBadRequest || out["reason_code"] != codeRequestInvalid {
		t.Errorf("malformed request: %d %v", code, out)
	}
}

func (h *harness) log() string { h.logsMu.Lock(); defer h.logsMu.Unlock(); return h.logs.String() }

// Only the declared caller identity, forwarded by the service's own sidecar, may call, and a
// request is answered only by the identity that opened it.
func TestOnlyTheDeclaredCallerIsServed(t *testing.T) {
	h := newHarness(t)
	for name, caller := range map[string]string{"no mesh identity": "", "another workload": mallory} {
		if code, _ := h.open(caller, challenge()); code != http.StatusForbidden {
			t.Errorf("%s: create answered %d", name, code)
		}
	}
	ch := challenge()
	_, req := h.open(storeID, ch)
	id := req["request_id"].(string)
	if code, _ := h.answer(mallory, id, "x"); code != http.StatusForbidden {
		t.Errorf("another workload answered %d", code)
	}
	if code, out := h.answer(otherID, id, "x"); code != http.StatusNotFound || out["reason_code"] != codeRequestUnknown {
		t.Errorf("a second allowed caller answered another's request: %d %v", code, out)
	}
	if !strings.Contains(h.log(), `"detail":"other-caller"`) {
		t.Error("not recorded as another caller's request")
	}
	// The forged second XFCC element a client could add is refused.
	r, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/v1/requests", strings.NewReader("{}"))
	r.Header.Add("X-Forwarded-Client-Cert", xfcc(mallory))
	r.Header.Add("X-Forwarded-Client-Cert", xfcc(storeID))
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("two forwarded certificates answered %d", resp.StatusCode)
	}
}

// A request whose row is locked past its expiry is not judged when the lock is released: expiry is
// checked again with the clock read after the request was consumed.
func TestARequestThatExpiresWhileWaitingForItsRowIsNotJudged(t *testing.T) {
	h := newHarness(t)
	ch := challenge()
	body, _ := json.Marshal(map[string]any{"challenge": ch, "client_id": client, "audience": audience,
		"expires_at": time.Now().Add(2 * time.Second).UTC().Format(time.RFC3339Nano)})
	code, req := h.post(storeID, "/v1/requests", "application/json", string(body))
	if code != http.StatusCreated {
		t.Fatalf("create: %d %v", code, req)
	}
	id := req["request_id"].(string)
	vp, _ := sdjwtfixture.Present(context.Background(), h.kit.Credential(t, "r", "e", verificationtest.CredentialOptions{}), h.kit.HolderKey, ch, audience, time.Now())

	tx, err := h.db.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(context.Background(), `SELECT 1 FROM verification_request WHERE request_id = $1 FOR UPDATE`, id); err != nil {
		t.Fatal(err)
	}
	type result struct {
		code int
		out  map[string]any
	}
	done := make(chan result, 1)
	go func() { c, o := h.answer(storeID, id, vp); done <- result{c, o} }()
	time.Sleep(3 * time.Second) // past expires_at, the answer waiting on the row
	_ = tx.Rollback(context.Background())
	r := <-done
	if r.code != http.StatusNotFound || r.out["reason_code"] != codeRequestUnknown {
		t.Fatalf("answered %d %v after the request expired", r.code, r.out)
	}
	if _, reason, detail := h.row(id); reason != codeRequestUnknown || detail != "expired" {
		t.Errorf("recorded %s/%s", reason, detail)
	}
}
