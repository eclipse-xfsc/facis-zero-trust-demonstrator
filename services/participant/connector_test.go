package participant

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/connectorclient"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/dpopproof"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/replay"
)

type acceptAll struct{}

func (acceptAll) TryUse(context.Context, replay.Use) (bool, error) { return true, nil }

type outcomeFunc func(context.Context, connectorclient.Challenge) (string, error)

func (f outcomeFunc) Outcome(ctx context.Context, ch connectorclient.Challenge) (string, error) {
	return f(ctx, ch)
}

// fakeConnector issues unsigned tokens bound to the proof's key; the Participant reads only the payload.
type fakeConnector struct {
	t        *testing.T
	srv      *httptest.Server
	now      func() time.Time
	grants   atomic.Int32
	inflight atomic.Int32
	maxIn    atomic.Int32
	// token answers a grant whose proof has jkt; nil issues a good token.
	token     func(w http.ResponseWriter, jkt string) bool
	challenge func(w http.ResponseWriter) bool
}

func newFakeConnector(t *testing.T, now func() time.Time) *fakeConnector {
	f := &fakeConnector{t: t, now: now}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, secret, ok := r.BasicAuth(); !ok || id != "client-1" || secret != "secret-1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/oauth2/challenge":
			if f.challenge != nil && f.challenge(w) {
				return
			}
			_, _ = w.Write([]byte(`{"challenge":"` + strings.Repeat("c", 43) + `","expires_in":120}`))
		case "/oauth2/token":
			f.grants.Add(1)
			n := f.inflight.Add(1)
			defer f.inflight.Add(-1)
			for m := f.maxIn.Load(); n > m && !f.maxIn.CompareAndSwap(m, n); m = f.maxIn.Load() {
			}
			time.Sleep(20 * time.Millisecond)
			v, err := dpopproof.Verify(r.Context(), r.Header.Get("DPoP"), dpopproof.Expect{Method: http.MethodPost, URI: f.srv.URL + "/oauth2/token"},
				dpopproof.Policy{Lifespan: time.Hour, Skew: time.Hour}, time.Now(), acceptAll{})
			if err != nil || r.FormValue("outcome") != "outcome-jws" || r.FormValue("audience") != "https://api.test" {
				t.Errorf("grant request: %v %v", err, r.Form)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if f.token != nil && f.token(w, v.JKT) {
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"` + f.jwt(v.JKT, "https://api.test") + `","token_type":"DPoP"}`))
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeConnector) jwt(jkt, aud string) string {
	now := f.now()
	payload, _ := json.Marshal(map[string]any{"aud": aud, "iat": now.Unix(), "exp": now.Add(300 * time.Second).Unix(), "cnf": map[string]string{"jkt": jkt}})
	return "e30." + base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString([]byte(f.now().String()))
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Advance(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.t = c.t.Add(d) }

func credentialsFile(t *testing.T, content string) string {
	p := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const goodCredentials = `{"client_id":"client-1","client_secret":"secret-1"}`

func newBootstrap(t *testing.T, f *fakeConnector, clock *fakeClock, creds string, outcomes connectorclient.OutcomeSource) *ConnectorBootstrap {
	t.Helper()
	if outcomes == nil {
		outcomes = outcomeFunc(func(context.Context, connectorclient.Challenge) (string, error) { return "outcome-jws", nil })
	}
	b, err := NewConnectorBootstrap(f.srv.URL, credentialsFile(t, creds), "https://api.test", outcomes, nil)
	if err != nil {
		t.Fatal(err)
	}
	b.now = clock.Now
	return b
}

type reports struct {
	mu  sync.Mutex
	got []string
}

func (r *reports) report(s State, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, string(s)+"/"+reason)
}

func TestConnectorBootstrapAuthorizesAndRenewsOnce(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	f := newFakeConnector(t, clock.Now)
	b := newBootstrap(t, f, clock, goodCredentials, nil)
	r := &reports{}
	session, err := b.Run(t.Context(), r.report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(r.got, " ") != "presenting/step_started acquiring_token/step_started" {
		t.Fatalf("reports %v", r.got)
	}

	target := "https://resource.test/demo"
	auth1, proof1, err1 := session.Authorize(t.Context(), http.MethodPost, target)
	auth2, proof2, err2 := session.Authorize(t.Context(), http.MethodPost, target)
	if err1 != nil || err2 != nil || auth1 != auth2 || proof1 == proof2 || !strings.HasPrefix(auth1, "DPoP ") {
		t.Fatalf("authorize: %v %v; same token %v, same proof %v", err1, err2, auth1 == auth2, proof1 == proof2)
	}
	token := strings.TrimPrefix(auth1, "DPoP ")
	for _, p := range []string{proof1, proof2} {
		v, err := dpopproof.Verify(t.Context(), p, dpopproof.Expect{Method: http.MethodPost, URI: target, AccessToken: token, JKT: b.jkt},
			dpopproof.Policy{Lifespan: time.Minute, Skew: 30 * time.Second}, time.Now(), acceptAll{})
		if err != nil || v.Claims.ATH != connectorclient.ATH(token) {
			t.Fatalf("proof: %v", err)
		}
	}

	// Past three quarters of the lifetime, concurrent callers trigger exactly one grant.
	clock.Advance(226 * time.Second)
	var wg sync.WaitGroup
	tokens := make([]string, 8)
	for i := range tokens {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, _, err := session.Authorize(t.Context(), http.MethodPost, target)
			if err != nil {
				t.Error(err)
			}
			tokens[i] = a
		}()
	}
	wg.Wait()
	if g := f.grants.Load(); g != 2 || f.maxIn.Load() != 1 {
		t.Fatalf("%d grants, %d at once; want 2 grants, one at a time", g, f.maxIn.Load())
	}
	for _, a := range tokens {
		if a != tokens[0] || a == auth1 {
			t.Fatal("callers did not all get the renewed token")
		}
	}

	// A failed renewal keeps the current token until it expires and is not retried at once.
	f.token = func(w http.ResponseWriter, _ string) bool { w.WriteHeader(http.StatusBadGateway); return true }
	clock.Advance(226 * time.Second)
	if a, _, err := session.Authorize(t.Context(), http.MethodPost, target); err != nil || a != tokens[0] {
		t.Fatalf("failed renewal: %v", err)
	}
	if _, _, err := session.Authorize(t.Context(), http.MethodPost, target); err != nil || f.grants.Load() != 3 {
		t.Fatalf("renewal retried within renewRetry: %d grants, %v", f.grants.Load(), err)
	}
	clock.Advance(75 * time.Second)
	if _, _, err := session.Authorize(t.Context(), http.MethodPost, target); err == nil {
		t.Fatal("an expired token was used")
	}
}

func TestConnectorBootstrapFailureStates(t *testing.T) {
	refuse := func(status int, body string) func(http.ResponseWriter, string) bool {
		return func(w http.ResponseWriter, _ string) bool {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
			return true
		}
	}
	nonce := func(w http.ResponseWriter, _ string) bool {
		w.Header().Set("DPoP-Nonce", "n")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"reason":"dpop_use_nonce"}`))
		return true
	}
	for name, c := range map[string]struct {
		creds     string
		challenge func(http.ResponseWriter) bool
		outcome   error
		token     func(http.ResponseWriter, string) bool
		otherJKT  bool
		want      string
	}{
		"credentials missing":  {creds: `{"client_id":"client-1"}`, want: "failed_registration/bootstrap_error"},
		"credentials extra":    {creds: `{"client_id":"client-1","client_secret":"secret-1","x":1}`, want: "failed_registration/bootstrap_error"},
		"credentials rejected": {creds: `{"client_id":"client-1","client_secret":"wrong"}`, want: "failed_registration/registration_rejected"},
		"connector 5xx": {challenge: func(w http.ResponseWriter) bool { w.WriteHeader(http.StatusServiceUnavailable); return true },
			want: "failed_connector_unreachable/connector_unreachable"},
		"challenge malformed": {challenge: func(w http.ResponseWriter) bool { _, _ = w.Write([]byte(`{}`)); return true },
			want: "failed_presentation/upstream_error"},
		"outcome source":       {outcome: errors.New("down"), want: "failed_presentation/upstream_error"},
		"outcome refused":      {token: refuse(400, `{"reason":"CRED-OUTCOME-SIGNATURE"}`), want: "failed_presentation/presentation_rejected"},
		"nonce twice":          {token: nonce, want: "failed_token/nonce_retry_exhausted"},
		"grant refused":        {token: refuse(400, `{"reason":"invalid_request"}`), want: "failed_token/token_rejected"},
		"grant answer lost":    {token: refuse(500, ``), want: "failed_connector_unreachable/connector_unreachable"},
		"token bound to other": {otherJKT: true, want: "failed_token/token_rejected"},
	} {
		t.Run(name, func(t *testing.T) {
			clock := &fakeClock{t: time.Now()}
			f := newFakeConnector(t, clock.Now)
			f.challenge = c.challenge
			f.token = c.token
			if c.otherJKT {
				f.token = func(w http.ResponseWriter, _ string) bool {
					_, _ = w.Write([]byte(`{"access_token":"` + f.jwt("other-jkt", "https://api.test") + `","token_type":"DPoP"}`))
					return true
				}
			}
			creds := c.creds
			if creds == "" {
				creds = goodCredentials
			}
			var outcomes connectorclient.OutcomeSource
			if c.outcome != nil {
				outcomes = outcomeFunc(func(context.Context, connectorclient.Challenge) (string, error) { return "", c.outcome })
			}
			r := &reports{}
			session, err := newBootstrap(t, f, clock, creds, outcomes).Run(t.Context(), r.report)
			if err == nil || session != nil || r.got[len(r.got)-1] != c.want {
				t.Fatalf("run: %v; reports %v; want last %s", err, r.got, c.want)
			}
		})
	}
}

func TestLoadConfigTokenMode(t *testing.T) {
	key := filepath.Join(t.TempDir(), "key.pem")
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(k)
	if err := os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	set := map[string]string{
		"PARTICIPANT_ADAPTER_MODE": "token", "PARTICIPANT_RESOURCE_URL": "http://127.0.0.1:8086",
		"PARTICIPANT_CONNECTOR_URL": "http://127.0.0.1:8080", "PARTICIPANT_CREDENTIALS_FILE": "/run/secrets/participant/credentials.json",
		"PARTICIPANT_AUDIENCE": "https://api.test", "PARTICIPANT_OUTCOME_ISSUER": "https://verifier.test",
		"PARTICIPANT_OUTCOME_KID": "v1", "PARTICIPANT_OUTCOME_KEY_FILE": key, "PARTICIPANT_OUTCOME_ROLE": "report-reader",
	}
	for k, v := range set {
		t.Setenv(k, v)
	}
	cfg, err := LoadConfig()
	if err != nil || cfg.ServingMode() != ModeToken {
		t.Fatalf("LoadConfig: %v %q", err, cfg.ServingMode())
	}
	for _, name := range []string{"PARTICIPANT_RESOURCE_URL", "PARTICIPANT_CONNECTOR_URL", "PARTICIPANT_CREDENTIALS_FILE",
		"PARTICIPANT_AUDIENCE", "PARTICIPANT_OUTCOME_ISSUER", "PARTICIPANT_OUTCOME_KID", "PARTICIPANT_OUTCOME_KEY_FILE", "PARTICIPANT_OUTCOME_ROLE"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "")
			if _, err := LoadConfig(); err == nil || !strings.Contains(err.Error(), "PARTICIPANT_") {
				t.Fatalf("LoadConfig without %s: %v", name, err)
			}
		})
	}
	t.Run("bad key file", func(t *testing.T) {
		t.Setenv("PARTICIPANT_OUTCOME_KEY_FILE", credentialsFile(t, "not a key"))
		if _, err := LoadConfig(); err == nil || strings.Contains(err.Error(), "not a key") {
			t.Fatalf("LoadConfig: %v", err)
		}
	})
}

func TestReadCredentialsIsStrict(t *testing.T) {
	if id, secret, err := readCredentials(credentialsFile(t, " "+goodCredentials+"\n")); err != nil || id != "client-1" || secret != "secret-1" {
		t.Fatalf("good file: %q %v", id, err)
	}
	for name, content := range map[string]string{
		"trailing brace":      goodCredentials + "}",
		"trailing bracket":    goodCredentials + "]",
		"trailing JSON":       goodCredentials + `{"client_id":"x"}`,
		"duplicate id":        `{"client_id":"client-1","client_id":"other","client_secret":"secret-1"}`,
		"duplicate secret":    `{"client_id":"client-1","client_secret":"secret-1","client_secret":"other"}`,
		"escaped duplicate":   `{"client_id":"client-1","client_id":"other","client_secret":"secret-1"}`,
		"case variant":        `{"Client_ID":"client-1","client_secret":"secret-1"}`,
		"case variant secret": `{"client_id":"client-1","CLIENT_SECRET":"secret-1"}`,
		"null id":             `{"client_id":null,"client_secret":"secret-1"}`,
		"null secret":         `{"client_id":"client-1","client_secret":null}`,
		"empty secret":        `{"client_id":"client-1","client_secret":""}`,
		"number id":           `{"client_id":1,"client_secret":"secret-1"}`,
		"unknown member":      `{"client_id":"client-1","client_secret":"secret-1","scope":"x"}`,
		"missing secret":      `{"client_id":"client-1"}`,
		"array":               `["client-1","secret-1"]`,
		"empty":               ``,
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := readCredentials(credentialsFile(t, content))
			if err == nil {
				t.Fatal("accepted")
			}
			for _, leak := range []string{"secret-1", "client-1", "other"} {
				if strings.Contains(err.Error(), leak) {
					t.Fatalf("error repeats the file: %v", err)
				}
			}
		})
	}
}

// A renewal that fails slowly is judged by the clock after it: the old token is not returned once it
// has expired meanwhile, and the retry wait starts when the attempt ended.
func TestConnectorSessionJudgesAFailedRenewalAfterIt(t *testing.T) {
	target := "https://resource.test/demo"
	setup := func(t *testing.T, during time.Duration) (*fakeClock, *fakeConnector, TokenSession) {
		clock := &fakeClock{t: time.Now()}
		f := newFakeConnector(t, clock.Now)
		session, err := newBootstrap(t, f, clock, goodCredentials, nil).Run(t.Context(), func(State, string) {})
		if err != nil {
			t.Fatal(err)
		}
		f.token = func(w http.ResponseWriter, _ string) bool {
			clock.Advance(during)
			w.WriteHeader(http.StatusBadGateway)
			return true
		}
		clock.Advance(226 * time.Second) // due for renewal, 74 s before expiry
		return clock, f, session
	}

	t.Run("expired during the attempt", func(t *testing.T) {
		_, _, session := setup(t, 80*time.Second)
		if a, p, err := session.Authorize(t.Context(), http.MethodPost, target); err == nil || a != "" || p != "" {
			t.Fatalf("Authorize returned a token that expired during the failed renewal: %v", err)
		}
	})
	t.Run("retry wait starts after the attempt", func(t *testing.T) {
		clock, f, session := setup(t, 10*time.Second)
		if _, _, err := session.Authorize(t.Context(), http.MethodPost, target); err != nil {
			t.Fatalf("token still valid: %v", err)
		}
		clock.Advance(renewRetry - time.Second) // 4 s after the attempt ended, 14 s after it began
		if _, _, err := session.Authorize(t.Context(), http.MethodPost, target); err != nil || f.grants.Load() != 2 {
			t.Fatalf("renewal retried %d grants before renewRetry passed since the failure: %v", f.grants.Load(), err)
		}
	})
}

// /reset waits for a renewal running outside the bootstrap, or changes nothing when its context ends
// first; after it, the dropped session starts no renewal.
func TestResetWaitsForARunningRenewal(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	f := newFakeConnector(t, clock.Now)
	l := newLifecycle(newBootstrap(t, f, clock, goodCredentials, nil), 1, time.Millisecond, time.Now, slog.New(slog.DiscardHandler))
	l.start(t.Context())
	deadline := time.Now().Add(5 * time.Second)
	for l.currentSession() == nil {
		if time.Now().After(deadline) {
			t.Fatalf("not ready: %+v", l.snapshot(ModeToken))
		}
		time.Sleep(5 * time.Millisecond)
	}
	session := l.currentSession()

	entered, release := make(chan struct{}), make(chan struct{})
	var once, releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock) // a failing test must not leave the handler blocked
	f.token = func(w http.ResponseWriter, jkt string) bool {
		once.Do(func() { close(entered) })
		<-release
		return false // then a good token
	}
	clock.Advance(226 * time.Second)
	renewed := make(chan error, 1)
	go func() {
		_, _, err := session.Authorize(context.Background(), http.MethodPost, "https://resource.test/demo")
		renewed <- err
	}()
	<-entered

	before := l.snapshot(ModeToken)
	short, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if _, err := l.reset(short, ModeToken); err == nil {
		t.Fatal("reset returned while a renewal was running")
	}
	if after := l.snapshot(ModeToken); after.State != before.State || len(after.History) != len(before.History) || l.currentSession() != session {
		t.Fatalf("a timed-out reset changed the state: %+v", after)
	}

	done := make(chan StateSnapshot, 1)
	go func() {
		snap, err := l.reset(t.Context(), ModeToken)
		if err != nil {
			t.Error(err)
		}
		done <- snap
	}()
	select {
	case <-done:
		t.Fatal("reset did not wait for the renewal")
	case <-time.After(100 * time.Millisecond):
	}
	unblock()
	if err := <-renewed; err != nil {
		t.Fatalf("renewal: %v", err)
	}
	if snap := <-done; snap.State != StateIdle {
		t.Fatalf("reset: %+v", snap)
	}

	// The dropped session is retired: due again, it does not start a grant. The bootstrap the reset
	// started is let finish first, so its own grant is not counted.
	for l.currentSession() == nil || l.currentSession() == session {
		if time.Now().After(deadline.Add(5 * time.Second)) {
			t.Fatalf("no new session after reset: %+v", l.snapshot(ModeToken))
		}
		time.Sleep(5 * time.Millisecond)
	}
	grants := f.grants.Load()
	clock.Advance(226 * time.Second)
	_, _, _ = session.Authorize(t.Context(), http.MethodPost, "https://resource.test/demo")
	if f.grants.Load() != grants {
		t.Fatal("a retired session renewed")
	}
}
