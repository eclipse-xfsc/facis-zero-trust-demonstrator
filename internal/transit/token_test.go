package transit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeLogin is OpenBao's /v1/auth/<mount>/login: it accepts the JWT "good-<n>" for role "r" and
// answers with token "tok-<login count>" and the given lease; status overrides the answer.
type fakeLogin struct {
	// hold, when set, makes the first accepted login wait for it to close; arrived signals that
	// login's arrival.
	hold, arrived chan struct{}
	arrivals      atomic.Int32
	logins        atomic.Int32
	status        atomic.Int32
	lease         int
	jwts          []string
	mu            sync.Mutex
}

func (f *fakeLogin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var in struct{ Role, JWT string }
	if r.Method != http.MethodPost || r.URL.Path != "/v1/auth/kubernetes/login" ||
		json.NewDecoder(r.Body).Decode(&in) != nil || in.Role != "r" || !strings.HasPrefix(in.JWT, "good-") {
		http.Error(w, `{"errors":["permission denied canary-body"]}`, http.StatusForbidden)
		return
	}
	if s := f.status.Load(); s != 0 {
		http.Error(w, `{"errors":["canary-body"]}`, int(s))
		return
	}
	f.mu.Lock()
	f.jwts = append(f.jwts, in.JWT)
	f.mu.Unlock()
	if f.hold != nil && f.arrivals.Add(1) == 1 {
		close(f.arrived)
		<-f.hold
	}
	n := f.logins.Add(1)
	_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{
		"client_token": fmt.Sprintf("tok-%d", n), "lease_duration": f.lease}})
}

func setup(t *testing.T, lease int, jwt string) (*KubernetesAuth, *fakeLogin, string, func(time.Duration)) {
	t.Helper()
	f := &fakeLogin{lease: lease}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte(jwt+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var clock atomic.Int64
	clock.Store(time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC).UnixNano())
	now = func() time.Time { return time.Unix(0, clock.Load()) }
	t.Cleanup(func() { now = time.Now })
	return &KubernetesAuth{Addr: srv.URL, Role: "r", JWTFile: file}, f, file,
		func(d time.Duration) { clock.Add(int64(d)) }
}

// settle waits until no background login runs.
func settle(t *testing.T, k *KubernetesAuth) {
	t.Helper()
	for range 200 {
		k.mu.Lock()
		r := k.flight != nil
		k.mu.Unlock()
		if !r {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("background login did not finish")
}

func TestKubernetesAuthCachesAndRenewsAtHalfLease(t *testing.T) {
	k, f, file, advance := setup(t, 60, "good-1")
	ctx := context.Background()
	for range 3 {
		if tok, err := k.Token(ctx); err != nil || tok != "tok-1" {
			t.Fatalf("first token: %q %v", tok, err)
		}
	}
	advance(29 * time.Second)
	if tok, _ := k.Token(ctx); tok != "tok-1" || f.logins.Load() != 1 {
		t.Fatalf("logged in again before half the lease: %q, %d logins", tok, f.logins.Load())
	}
	// The kubelet rotated the projected token: the next login sends the new one.
	if err := os.WriteFile(file, []byte("good-2"), 0o600); err != nil {
		t.Fatal(err)
	}
	advance(time.Second)
	// Due for renewal: the caller still gets the valid token at once, and one background login
	// replaces it.
	if tok, err := k.Token(ctx); err != nil || tok != "tok-1" {
		t.Fatalf("a caller waited for the renewal: %q %v", tok, err)
	}
	settle(t, k)
	if tok, err := k.Token(ctx); err != nil || tok != "tok-2" {
		t.Fatalf("renewal at half the lease: %q %v", tok, err)
	}
	if f.jwts[1] != "good-2" {
		t.Fatalf("renewal did not reread the rotated JWT: %v", f.jwts)
	}
}

func TestKubernetesAuthKeepsValidTokenWhileLoginFailsThenFailsClosed(t *testing.T) {
	k, f, _, advance := setup(t, 60, "good-1")
	ctx := context.Background()
	if _, err := k.Token(ctx); err != nil {
		t.Fatal(err)
	}
	f.status.Store(http.StatusServiceUnavailable)
	advance(40 * time.Second)
	if tok, err := k.Token(ctx); err != nil || tok != "tok-1" {
		t.Fatalf("a valid token was dropped on a failed renewal: %q %v", tok, err)
	}
	settle(t, k)
	if tok, err := k.Token(ctx); err != nil || tok != "tok-1" {
		t.Fatalf("a valid token was dropped after a failed background renewal: %q %v", tok, err)
	}
	settle(t, k)
	advance(15 * time.Second) // 55s: inside the expiry margin
	tok, err := k.Token(ctx)
	if err == nil || tok != "" {
		t.Fatalf("an expiring token was handed out: %q", tok)
	}
	if strings.Contains(err.Error(), "canary") || strings.Contains(err.Error(), "good-") {
		t.Fatalf("error carries the answer or the JWT: %v", err)
	}
	// OpenBao back: the next call logs in again, without a restart.
	f.status.Store(0)
	if tok, err := k.Token(ctx); err != nil || tok != "tok-2" {
		t.Fatalf("re-login after expiry: %q %v", tok, err)
	}
}

func TestKubernetesAuthRefusals(t *testing.T) {
	ctx := context.Background()
	k, _, _, _ := setup(t, 60, "wrong")
	if _, err := k.Token(ctx); err == nil || !strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), "canary") {
		t.Fatalf("a refused JWT: %v", err)
	}
	k.JWTFile = filepath.Join(t.TempDir(), "absent")
	if _, err := k.Token(ctx); err == nil {
		t.Fatal("a missing JWT file logged in")
	}
	k, _, _, _ = setup(t, 0, "good-1")
	if _, err := k.Token(ctx); err == nil {
		t.Fatal("a token without a lease was accepted")
	}
	k, _, _, _ = setup(t, 60, "good-1")
	k.Mount = "../sys"
	if _, err := k.Token(ctx); err == nil {
		t.Fatal("an invalid mount was used")
	}
}

func TestKubernetesAuthOneLoginForConcurrentCallers(t *testing.T) {
	k, f, _, _ := setup(t, 60, "good-1")
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() { _, _ = k.Token(context.Background()) })
	}
	wg.Wait()
	if n := f.logins.Load(); n != 1 {
		t.Fatalf("%d logins for concurrent callers", n)
	}
}

// A client whose login fails answers ErrTokenSource, which the services' readiness reports as not
// ready; nothing reaches the transit path without a token.
func TestClientWithFailedLoginIsTokenSourceError(t *testing.T) {
	k, _, _, _ := setup(t, 60, "wrong")
	c, err := New(Config{Addr: k.Addr, Token: k.Token})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.LatestKey(context.Background(), "k"); !errors.Is(err, ErrTokenSource) {
		t.Fatalf("want ErrTokenSource, got %v", err)
	}
}

func TestFileToken(t *testing.T) {
	file := filepath.Join(t.TempDir(), "t")
	src := FileToken(file)
	if _, err := src(context.Background()); err == nil {
		t.Fatal("missing file read")
	}
	_ = os.WriteFile(file, []byte(" a \n"), 0o600)
	if tok, err := src(context.Background()); err != nil || tok != "a" {
		t.Fatalf("%q %v", tok, err)
	}
	_ = os.WriteFile(file, []byte("b"), 0o600)
	if tok, _ := src(context.Background()); tok != "b" {
		t.Fatalf("replaced token not reread: %q", tok)
	}
}

// A caller whose context ends stops waiting for a slow login at once; the login goes on, and the
// next caller gets its token.
func TestKubernetesAuthCallerDeadlineWhileLoginIsSlow(t *testing.T) {
	k, f, _, _ := setup(t, 60, "good-1")
	f.hold, f.arrived = make(chan struct{}), make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := k.Token(ctx); !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatalf("a caller waited past its deadline: %v after %v", err, time.Since(start))
	}
	<-f.arrived
	close(f.hold)
	if tok, err := k.Token(context.Background()); err != nil || tok != "tok-1" {
		t.Fatalf("the slow login's token: %q %v", tok, err)
	}
	if n := f.logins.Load(); n != 1 {
		t.Fatalf("%d logins: the cancelled caller's login was not shared", n)
	}
}

// A background renewal still in flight when the token expires: the caller waits for that same
// login, not a second one.
func TestKubernetesAuthExpiryJoinsBackgroundRenewal(t *testing.T) {
	k, f, _, advance := setup(t, 60, "good-1")
	ctx := context.Background()
	if _, err := k.Token(ctx); err != nil {
		t.Fatal(err)
	}
	f.hold, f.arrived = make(chan struct{}), make(chan struct{})
	advance(30 * time.Second)
	if tok, _ := k.Token(ctx); tok != "tok-1" { // starts the background renewal
		t.Fatalf("got %q", tok)
	}
	<-f.arrived
	advance(30 * time.Second) // expired meanwhile
	done := make(chan string)
	go func() { tok, _ := k.Token(ctx); done <- tok }()
	close(f.hold)
	if tok := <-done; tok != "tok-2" || f.logins.Load() != 2 {
		t.Fatalf("got %q after %d logins, want tok-2 after 2", tok, f.logins.Load())
	}
}

// Two logins that overlap and end out of order: the later one's token stays.
func TestKubernetesAuthOlderLoginNeverOverwritesNewer(t *testing.T) {
	k, f, _, _ := setup(t, 60, "good-1")
	f.hold, f.arrived = make(chan struct{}), make(chan struct{})
	k.mu.Lock()
	older := k.start()
	k.mu.Unlock()
	<-f.arrived // the older login is held at the server
	k.mu.Lock()
	newer := k.start()
	k.mu.Unlock()
	<-newer.done
	close(f.hold)
	<-older.done
	if older.token != "tok-2" || newer.token != "tok-1" {
		t.Fatalf("server order: older %q, newer %q", older.token, newer.token)
	}
	if tok, _ := k.Token(context.Background()); tok != "tok-1" {
		t.Fatalf("the older login overwrote the newer token: %q", tok)
	}
}
