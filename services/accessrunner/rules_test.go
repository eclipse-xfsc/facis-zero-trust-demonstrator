package accessrunner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
)

// kubeStub answers the revocation list and records deployment patches.
func kubeStub(t *testing.T, configMap *atomic.Value, patches *atomic.Int32) *Kube {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/configmaps/ztd-access-revocations"):
			body, _ := configMap.Load().(string)
			if body == "" {
				http.NotFound(w, r)
				return
			}
			_, _ = io.WriteString(w, body)
		case r.Method == http.MethodPatch:
			patches.Add(1)
			_, _ = io.WriteString(w, "{}")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	file := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(file, []byte("sa-token"), 0o600)
	return &Kube{API: server.URL, TokenFile: file, HTTP: server.Client(), Namespace: "ztd-access"}
}

func TestRevocationListMustBeWellFormed(t *testing.T) {
	var cm atomic.Value
	var patches atomic.Int32
	k := kubeStub(t, &cm, &patches)
	for name, tc := range map[string]struct {
		body    string
		revoked bool
		fails   bool
	}{
		"empty list":               {`{"data":{"revoked":""}}`, false, false},
		"listed":                   {`{"data":{"revoked":"g-0\ng-1\n"}}`, true, false},
		"not listed":               {`{"data":{"revoked":"g-0"}}`, false, false},
		"no revoked key":           {`{"data":{"other":"g-1"}}`, false, true},
		"no data":                  {`{"data":null}`, false, true},
		"a line that is not an id": {`{"data":{"revoked":" g-1"}}`, false, true},
		"no list at all":           {"", false, true},
	} {
		cm.Store(tc.body)
		revoked, err := k.Revoked(t.Context(), "g-1")
		if (err != nil) != tc.fails || revoked != tc.revoked {
			t.Errorf("%s: revoked=%v err=%v", name, revoked, err)
		}
	}
}

// Times outside the bounds are refused before any arithmetic on them.
func TestGrantTimesAreBounded(t *testing.T) {
	key := newTestKey(t)
	trust := Trust{Target: "t", Approvers: []Approver{{Subject: "approver", Key: jose.PublicJWK(&key.k.PublicKey)}}}
	now := time.Unix(1_800_000_000, 0)
	for name, g := range map[string]Grant{
		"before the epoch": {NotBefore: math.MinInt64, ApprovedAt: math.MinInt64, NotAfter: 1_831_536_000},
		"far future":       {NotBefore: 1_799_999_000, ApprovedAt: 1_799_999_000, NotAfter: math.MaxInt64},
	} {
		g.ID, g.Subject, g.Role, g.Operations, g.Target, g.PolicyVersion, g.Approver, g.Reason =
			"g", "caller", "user-admin", []string{OpListUsers}, "t", PolicyVersion(), "approver", "r"
		compact, _ := Sign(t.Context(), g, "approver", key.sign)
		if _, err := VerifyGrant(compact, trust, "caller", OpListUsers, now, func(string) (bool, error) { return false, nil }); !errors.Is(err, ErrGrantDuration) {
			t.Errorf("%s: %v", name, err)
		}
	}
	g := Grant{ID: "g with\nnewline", Subject: "caller", Role: "user-admin", Operations: []string{OpListUsers}, Target: "t", PolicyVersion: PolicyVersion(),
		Approver: "approver", ApprovedAt: now.Unix() - 1, NotBefore: now.Unix() - 1, NotAfter: now.Unix() + 60, Reason: "r"}
	compact, _ := Sign(t.Context(), g, "approver", key.sign)
	if _, err := VerifyGrant(compact, trust, "caller", OpListUsers, now, func(string) (bool, error) { return false, nil }); !errors.Is(err, ErrGrantMalformed) {
		t.Errorf("a grant id the revocation list cannot name: %v", err)
	}
}

// A key the realm removed stops verifying within keyRefresh plus keyThrottle, and a key set that
// cannot be fetched is not used after keyMaxStale.
func TestCallerKeysExpire(t *testing.T) {
	key := newTestKey(t)
	jwk := jose.PublicJWK(&key.k.PublicKey)
	jwk.Kid = "realm-ec"
	var served atomic.Value
	full, _ := json.Marshal(map[string]any{"keys": []any{jwk}})
	served.Store(string(full))
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		body := served.Load().(string)
		if body == "" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, body)
	}))
	defer jwks.Close()
	now := time.Unix(1_800_000_000, 0)
	c := &Callers{Issuer: "iss", JWKSURL: jwks.URL, Audience: "aud", Client: "azp", HTTP: jwks.Client(), Now: func() time.Time { return now }}
	token := func() string {
		payload, _ := json.Marshal(map[string]any{"iss": "iss", "sub": "s", "azp": "azp", "typ": "Bearer", "aud": "aud", "exp": now.Unix() + 600})
		compact, _ := jose.Sign(t.Context(), jose.Header{Typ: "JWT", Kid: "realm-ec"}, payload, key.sign)
		return "Bearer " + compact
	}
	if _, err := c.Authenticate(t.Context(), token()); err != nil {
		t.Fatalf("first use: %v", err)
	}
	// The realm removes the key: still known within the refresh interval, gone after it.
	other := newTestKey(t)
	otherJWK := jose.PublicJWK(&other.k.PublicKey)
	otherJWK.Kid = "realm-ec-2"
	removed, _ := json.Marshal(map[string]any{"keys": []any{otherJWK}})
	served.Store(string(removed))
	now = now.Add(keyRefresh)
	if _, err := c.Authenticate(t.Context(), token()); err != nil {
		t.Fatalf("within the refresh interval: %v", err)
	}
	now = now.Add(time.Second)
	if _, err := c.Authenticate(t.Context(), token()); !errors.Is(err, ErrCaller) {
		t.Fatalf("a removed key still verified: %v", err)
	}
	// The key set returns, then cannot be fetched: it is used until keyMaxStale, not after.
	served.Store(string(full))
	now = now.Add(keyThrottle)
	if _, err := c.Authenticate(t.Context(), token()); err != nil {
		t.Fatalf("after the key returned: %v", err)
	}
	served.Store("")
	now = now.Add(keyMaxStale)
	if _, err := c.Authenticate(t.Context(), token()); err != nil {
		t.Fatalf("at keyMaxStale: %v", err)
	}
	now = now.Add(time.Second)
	if _, err := c.Authenticate(t.Context(), token()); !errors.Is(err, ErrCaller) {
		t.Fatalf("a stale key set still verified: %v", err)
	}
}

// The time is checked again just before an operation starts: a grant that ends while the call is
// being checked runs nothing.
func TestGrantIsRecheckedBeforeDispatch(t *testing.T) {
	var cm atomic.Value
	cm.Store(`{"data":{"revoked":""}}`)
	var patches atomic.Int32
	kube := kubeStub(t, &cm, &patches)

	callerKey, approverKey := newTestKey(t), newTestKey(t)
	jwk := jose.PublicJWK(&callerKey.k.PublicKey)
	jwk.Kid = "realm-ec"
	keys, _ := json.Marshal(map[string]any{"keys": []any{jwk}})
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(keys) }))
	defer jwks.Close()

	start := time.Unix(1_800_000_000, 0)
	var calls atomic.Int32
	// The first reading of the clock (the grant check) is inside the grant; every later one is
	// after its end.
	clock := func() time.Time {
		if calls.Add(1) == 1 {
			return start
		}
		return start.Add(time.Hour)
	}
	trust := Trust{Target: "t", Approvers: []Approver{{Subject: "approver", Key: jose.PublicJWK(&approverKey.k.PublicKey)}}}
	logs := &bytes.Buffer{}
	s := &Server{Trust: trust, Kube: kube, Plane: []string{"ztd-data"}, Log: slog.New(slog.NewJSONHandler(logs, nil)), Now: clock,
		Callers: &Callers{Issuer: "iss", JWKSURL: jwks.URL, Audience: "aud", Client: "azp", HTTP: jwks.Client(), Now: func() time.Time { return start }}}
	payload, _ := json.Marshal(map[string]any{"iss": "iss", "sub": "caller", "azp": "azp", "typ": "Bearer", "aud": "aud", "exp": start.Unix() + 600})
	token, _ := jose.Sign(t.Context(), jose.Header{Typ: "JWT", Kid: "realm-ec"}, payload, callerKey.sign)
	grant, _ := Sign(context.Background(), Grant{ID: "g", Subject: "caller", Role: "cluster-operator", Operations: []string{OpClusterRestart}, Target: "t",
		PolicyVersion: PolicyVersion(), Approver: "approver", ApprovedAt: start.Unix() - 1, NotBefore: start.Unix() - 1, NotAfter: start.Unix() + 60, Reason: "r"}, "approver", approverKey.sign)
	body, _ := json.Marshal(map[string]any{"grant": grant, "params": map[string]any{"namespace": "ztd-data", "deployment": "app"}})
	req := httptest.NewRequest(http.MethodPost, "/v1/operations/"+OpClusterRestart, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "grant_expired") || patches.Load() != 0 {
		t.Fatalf("a grant that ended during the checks: %d %s, %d patches", rec.Code, rec.Body.String(), patches.Load())
	}
}
