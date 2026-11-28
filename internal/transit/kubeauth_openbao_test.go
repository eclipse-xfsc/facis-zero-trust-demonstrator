package transit

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestOpenBaoKubernetesAuth runs against a real OpenBao whose auth/kubernetes/ reviews tokens with
// a real API server (scripts/verify-openbao-kubernetes-auth/verify.sh sets it up) and skips
// otherwise. KUBEAUTH_TEST_ADDR is the server, KUBEAUTH_TEST_ROLE a role with a short ttl
// (KUBEAUTH_TEST_TTL) whose policy may create and read the transit key KUBEAUTH_TEST_KEY and nothing
// else, and
// KUBEAUTH_TEST_JWTS a directory of service-account tokens: good and rotated (the role's account,
// namespace and audience), wrong-sa, wrong-ns and wrong-aud.
func TestOpenBaoKubernetesAuth(t *testing.T) {
	addr, role, dir, key := os.Getenv("KUBEAUTH_TEST_ADDR"), os.Getenv("KUBEAUTH_TEST_ROLE"), os.Getenv("KUBEAUTH_TEST_JWTS"), os.Getenv("KUBEAUTH_TEST_KEY")
	ttl, _ := time.ParseDuration(os.Getenv("KUBEAUTH_TEST_TTL"))
	if addr == "" || role == "" || dir == "" || key == "" || ttl <= 0 {
		t.Skip("KUBEAUTH_TEST_ADDR, _ROLE, _JWTS, _KEY and _TTL not set")
	}
	ctx := context.Background()
	jwt := filepath.Join(t.TempDir(), "token")
	use := func(name string) {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(jwt, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	alive := func(token string) int {
		req, _ := http.NewRequest(http.MethodGet, addr+"/v1/auth/token/lookup-self", nil)
		req.Header.Set("X-Vault-Token", token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal("lookup-self: request failed")
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	use("good")
	k := &KubernetesAuth{Addr: addr, Role: role, JWTFile: jwt}
	c, err := New(Config{Addr: addr, Token: k.Token})
	if err != nil {
		t.Fatal(err)
	}
	t.Run("login and least privilege", func(t *testing.T) {
		if _, err := c.EnsureKey(ctx, key); err != nil {
			t.Fatalf("create the role's key: %v", err)
		}
		if _, err := c.LatestKey(ctx, key); err != nil {
			t.Fatalf("read the role's key: %v", err)
		}
		var status *StatusError
		if _, err := c.EnsureKey(ctx, "kubeauth-not-mine"); !errors.As(err, &status) || status.Status != http.StatusForbidden {
			t.Fatalf("a key outside the policy: %v", err)
		}
		if err := c.Create(ctx, "kubeauth/probe", []byte("x")); !errors.As(err, &status) || status.Status != http.StatusForbidden {
			t.Fatalf("KV outside the policy: %v", err)
		}
	})

	first, _ := k.Token(ctx)
	t.Run("renewal at half the lease with the rotated token", func(t *testing.T) {
		use("rotated")
		time.Sleep(ttl/2 + time.Second)
		if _, err := c.LatestKey(ctx, key); err != nil {
			t.Fatalf("after half the lease: %v", err)
		}
		second := first
		for i := 0; i < 100 && second == first; i++ { // the renewal runs in the background
			time.Sleep(50 * time.Millisecond)
			second, _ = k.Token(ctx)
		}
		if second == first {
			t.Fatal("no new login at half the lease")
		}
		if alive(first) != http.StatusOK {
			t.Fatal("the previous token died before its lease ended")
		}
	})

	t.Run("re-login after the token expired", func(t *testing.T) {
		held, _ := k.Token(ctx)
		time.Sleep(ttl + time.Second)
		if s := alive(held); s != http.StatusForbidden {
			t.Fatalf("the expired token answered %d, want 403", s)
		}
		if _, err := c.LatestKey(ctx, key); err != nil {
			t.Fatalf("after expiry: %v", err)
		}
		if now, _ := k.Token(ctx); now == held || alive(now) != http.StatusOK {
			t.Fatal("no fresh token after expiry")
		}
	})

	t.Run("a restarted client logs in fresh", func(t *testing.T) {
		fresh := &KubernetesAuth{Addr: addr, Role: role, JWTFile: jwt}
		c2, _ := New(Config{Addr: addr, Token: fresh.Token})
		if _, err := c2.LatestKey(ctx, key); err != nil {
			t.Fatalf("restarted client: %v", err)
		}
	})

	for _, wrong := range []string{"wrong-sa", "wrong-ns", "wrong-aud"} {
		t.Run("refused "+wrong, func(t *testing.T) {
			use(wrong)
			k := &KubernetesAuth{Addr: addr, Role: role, JWTFile: jwt}
			_, err := k.Token(ctx)
			if err == nil || !strings.Contains(err.Error(), "login status 403") {
				t.Fatalf("want a 403 login refusal, got %v", err)
			}
			c, _ := New(Config{Addr: addr, Token: k.Token})
			if _, err := c.LatestKey(ctx, key); !errors.Is(err, ErrTokenSource) {
				t.Fatalf("a refused login must fail the call closed: %v", err)
			}
		})
	}
}
