package ociclient

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// fakeNet serves named hosts from in-process TLS servers. Certificates are not verified: the tests
// are about the client's protocol decisions, not about TLS.
type fakeNet struct {
	addrs map[string]string // host:443 -> listener address
}

func (f *fakeNet) client() *http.Client {
	dialer := &net.Dialer{}
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if real, ok := f.addrs[addr]; ok {
				addr = real
			}
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test servers only
	}}
}

func (f *fakeNet) serve(t *testing.T, host string, h http.HandlerFunc) {
	t.Helper()
	ts := httptest.NewTLSServer(h)
	t.Cleanup(ts.Close)
	f.addrs[host+":443"] = ts.Listener.Addr().String()
}

func newNet() *fakeNet { return &fakeNet{addrs: map[string]string{}} }

func TestManifestAndBlobVerified(t *testing.T) {
	manifest := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}`)
	blob := []byte("layer content")
	n := newNet()
	n.serve(t, "registry.test", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/team/app/manifests/" + digestOf(manifest), "/v2/team/app/manifests/v1":
			w.Header().Set("Content-Type", MediaTypeOCIManifest)
			_, _ = w.Write(manifest)
		case "/v2/team/app/blobs/" + digestOf(blob):
			_, _ = w.Write(blob)
		case "/v2/team/app/blobs/" + digestOf([]byte("other")):
			_, _ = w.Write(blob) // lies about its content
		default:
			http.NotFound(w, r)
		}
	})
	c := New(Options{HTTPClient: n.client()})
	ctx := context.Background()

	m, err := c.ManifestByDigest(ctx, "registry.test", "team/app", digestOf(manifest))
	if err != nil || m.MediaType != MediaTypeOCIManifest || m.Digest != digestOf(manifest) {
		t.Fatalf("ManifestByDigest = %+v, %v", m, err)
	}
	if m, err := c.ManifestByTag(ctx, "registry.test", "team/app", "v1"); err != nil || m.Digest != digestOf(manifest) {
		t.Fatalf("ManifestByTag = %+v, %v", m, err)
	}
	if b, err := c.Blob(ctx, "registry.test", "team/app", digestOf(blob)); err != nil || string(b) != string(blob) {
		t.Fatalf("Blob = %q, %v", b, err)
	}
	if _, err := c.Blob(ctx, "registry.test", "team/app", digestOf([]byte("other"))); !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("lying blob: err = %v, want ErrDigestMismatch", err)
	}
	if _, err := c.ManifestByDigest(ctx, "registry.test", "team/app", digestOf([]byte("absent"))); !errors.Is(err, ErrNotFound) {
		t.Errorf("absent manifest: err = %v, want ErrNotFound", err)
	}
}

func TestManifestDigestMismatch(t *testing.T) {
	n := newNet()
	n.serve(t, "registry.test", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"schemaVersion":2}`)) })
	c := New(Options{HTTPClient: n.client()})
	_, err := c.ManifestByDigest(context.Background(), "registry.test", "app", digestOf([]byte("expected")))
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("err = %v, want ErrDigestMismatch", err)
	}
}

func TestBounds(t *testing.T) {
	big := strings.Repeat("x", 2048)
	n := newNet()
	n.serve(t, "registry.test", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/blobs/") {
			w.Header().Set("Content-Length", "2048")
		} else {
			w.(http.Flusher).Flush() // chunked: no Content-Length, the reader must stop by itself
		}
		_, _ = w.Write([]byte(big))
	})
	c := New(Options{HTTPClient: n.client(), MaxManifestBytes: 1024, MaxBlobBytes: 1024})
	ctx := context.Background()
	if _, err := c.ManifestByTag(ctx, "registry.test", "app", "v1"); !errors.Is(err, ErrTooLarge) {
		t.Errorf("manifest: err = %v, want ErrTooLarge", err)
	}
	if _, err := c.Blob(ctx, "registry.test", "app", digestOf([]byte(big))); !errors.Is(err, ErrTooLarge) {
		t.Errorf("blob: err = %v, want ErrTooLarge", err)
	}
}

func TestInputValidation(t *testing.T) {
	c := New(Options{})
	ctx := context.Background()
	cases := []struct{ registry, repo, ref string }{
		{"registry.test", "app", "sha256:short"},
		{"registry.test", "App/Upper", "v1"},
		{"registry.test", "../escape", "v1"},
		{"user@registry.test", "app", "v1"},
		{"registry.test/path", "app", "v1"},
		{"registry.test", "app", "bad tag"},
	}
	for _, tc := range cases {
		if _, err := c.ManifestByTag(ctx, tc.registry, tc.repo, tc.ref); err == nil {
			t.Errorf("%+v: accepted", tc)
		}
	}
	if _, err := c.ManifestByDigest(ctx, "registry.test", "app", "sha256:"+strings.Repeat("A", 64)); err == nil {
		t.Error("upper-case digest accepted")
	}
}

func TestBearerChallenge(t *testing.T) {
	var tokenQuery, tokenAuth string
	n := newNet()
	n.serve(t, "registry.test", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			tokenQuery, tokenAuth = r.URL.RawQuery, r.Header.Get("Authorization")
			_, _ = w.Write([]byte(`{"token":"t0k"}`))
			return
		}
		if r.Header.Get("Authorization") != "Bearer t0k" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="https://registry.test/token",service="registry.test",scope="repository:team/app:pull"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"schemaVersion":2}`))
	})
	c := New(Options{HTTPClient: n.client(), Credentials: map[string]Credential{"registry.test": {"user", "secret"}}})
	if _, err := c.ManifestByTag(context.Background(), "registry.test", "team/app", "v1"); err != nil {
		t.Fatalf("ManifestByTag: %v", err)
	}
	if !strings.Contains(tokenQuery, "scope=repository%3Ateam%2Fapp%3Apull") || !strings.Contains(tokenQuery, "service=registry.test") {
		t.Errorf("token query = %q", tokenQuery)
	}
	if !strings.HasPrefix(tokenAuth, "Basic ") {
		t.Errorf("token request without the registry's credentials: %q", tokenAuth)
	}
}

func TestTokenCacheBounded(t *testing.T) {
	n := newNet()
	n.serve(t, "registry.test", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			_, _ = fmt.Fprintf(w, `{"token":%q}`, r.URL.Query().Get("scope"))
			return
		}
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="https://registry.test/token"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	c := New(Options{HTTPClient: n.client()})
	for i := 0; i < maxTokens+10; i++ {
		_, _ = c.ManifestByTag(context.Background(), "registry.test", fmt.Sprintf("app%d", i), "v1")
	}
	if len(c.tokens) > maxTokens {
		t.Errorf("token cache holds %d tokens, cap %d", len(c.tokens), maxTokens)
	}
}

func TestConcurrentLoginsSurviveEviction(t *testing.T) {
	// Many scopes past the cap, logging in at once: a cache reset by one request must not take away
	// the token another request has just fetched for its retry.
	n := newNet()
	n.serve(t, "registry.test", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			_, _ = fmt.Fprintf(w, `{"token":%q}`, r.URL.Query().Get("scope"))
			return
		}
		repo := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v2/"), "/manifests/v1")
		if r.Header.Get("Authorization") != "Bearer repository:"+repo+":pull" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="https://registry.test/token"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	})
	c := New(Options{HTTPClient: n.client()})
	var wg sync.WaitGroup
	errs := make(chan error, 8*maxTokens)
	next := make(chan int)
	for w := 0; w < 32; w++ { // bounded, so the test server's accept backlog is not the failure
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				if _, err := c.ManifestByTag(context.Background(), "registry.test", fmt.Sprintf("app%d", i), "v1"); err != nil {
					errs <- err
				}
			}
		}()
	}
	for i := 0; i < 8*maxTokens; i++ {
		next <- i
	}
	close(next)
	wg.Wait()
	close(errs)
	if err, failed := <-errs; failed {
		t.Errorf("%d logins failed, first: %v", len(errs)+1, err)
	}
}

func TestOversizedTokenRefused(t *testing.T) {
	n := newNet()
	n.serve(t, "registry.test", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			_, _ = fmt.Fprintf(w, `{"token":%q}`, strings.Repeat("x", maxTokenBytes+1))
			return
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="https://registry.test/token"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	c := New(Options{HTTPClient: n.client()})
	if _, err := c.ManifestByTag(context.Background(), "registry.test", "app", "v1"); err == nil || len(c.tokens) != 0 {
		t.Errorf("oversized token: err = %v, cached %d", err, len(c.tokens))
	}
}

func TestForeignRealmGetsNoCredentials(t *testing.T) {
	var tokenAuth = "unset"
	n := newNet()
	n.serve(t, "auth.test", func(w http.ResponseWriter, r *http.Request) {
		tokenAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"token":"t0k"}`))
	})
	n.serve(t, "registry.test", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer t0k" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="https://auth.test/token"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"schemaVersion":2}`))
	})
	c := New(Options{HTTPClient: n.client(), Credentials: map[string]Credential{"registry.test": {"user", "secret"}}})
	if _, err := c.ManifestByTag(context.Background(), "registry.test", "app", "v1"); err != nil {
		t.Fatalf("ManifestByTag: %v", err)
	}
	if tokenAuth != "" {
		t.Errorf("registry credentials sent to a realm on another host: %q", tokenAuth)
	}
}

func TestPlainTextRealmRefused(t *testing.T) {
	n := newNet()
	n.serve(t, "registry.test", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="http://registry.test/token"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	c := New(Options{HTTPClient: n.client(), Credentials: map[string]Credential{"registry.test": {"user", "secret"}}})
	_, err := c.ManifestByTag(context.Background(), "registry.test", "app", "v1")
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("err = %v, want refusal of a plain-text realm", err)
	}
}

func TestRedirects(t *testing.T) {
	blob := []byte("layer")
	sub := []byte("subdomain layer")
	var cdnAuth, subAuth string
	n := newNet()
	n.serve(t, "cdn.test", func(w http.ResponseWriter, r *http.Request) {
		cdnAuth = r.Header.Get("Authorization")
		_, _ = w.Write(blob)
	})
	n.serve(t, "blobs.registry.test", func(w http.ResponseWriter, r *http.Request) {
		subAuth = r.Header.Get("Authorization")
		_, _ = w.Write(sub)
	})
	n.serve(t, "registry.test", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/app/blobs/"+digestOf(sub) {
			http.Redirect(w, r, "https://blobs.registry.test/blob", http.StatusTemporaryRedirect)
			return
		}
		if r.URL.Path == "/v2/app/blobs/"+digestOf([]byte("plain")) {
			http.Redirect(w, r, "http://cdn.test/blob", http.StatusTemporaryRedirect)
			return
		}
		http.Redirect(w, r, "https://cdn.test/blob", http.StatusTemporaryRedirect)
	})
	c := New(Options{HTTPClient: n.client(), Credentials: map[string]Credential{"registry.test": {"user", "secret"}}})
	ctx := context.Background()

	if b, err := c.Blob(ctx, "registry.test", "app", digestOf(blob)); err != nil || string(b) != "layer" {
		t.Fatalf("Blob via https redirect = %q, %v", b, err)
	}
	if cdnAuth != "" {
		t.Errorf("credentials forwarded to another host: %q", cdnAuth)
	}
	// net/http keeps Authorization on a redirect to a subdomain; the client must not.
	if _, err := c.Blob(ctx, "registry.test", "app", digestOf(sub)); err != nil {
		t.Fatalf("Blob via subdomain redirect: %v", err)
	}
	if subAuth != "" {
		t.Errorf("credentials forwarded to a subdomain: %q", subAuth)
	}
	if _, err := c.Blob(ctx, "registry.test", "app", digestOf([]byte("plain"))); err == nil || !strings.Contains(err.Error(), "redirect to http refused") {
		t.Errorf("redirect to http: err = %v", err)
	}
}

func TestPlainHTTPRegistry(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{}`)) }))
	defer ts.Close()
	host := strings.TrimPrefix(ts.URL, "http://")
	if _, err := New(Options{}).ManifestByTag(context.Background(), host, "app", "v1"); err == nil {
		t.Error("plain-http registry reached without being configured for it")
	}
	if _, err := New(Options{PlainHTTP: []string{host}}).ManifestByTag(context.Background(), host, "app", "v1"); err != nil {
		t.Errorf("configured plain-http registry: %v", err)
	}
}
