package transit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A client the caller supplies still never follows a redirect: the token must not travel to the
// redirect's destination, whatever the supplied client would do on its own.
func TestSuppliedClientNeverFollowsRedirects(t *testing.T) {
	var reached atomic.Int32
	elsewhere := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Add(1) }))
	t.Cleanup(elsewhere.Close)

	for _, status := range []int{http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		bao := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, elsewhere.URL+r.URL.Path, status)
		}))
		t.Cleanup(bao.Close)

		c, err := New(Config{Addr: bao.URL, Token: staticToken(canaryToken), HTTPClient: &http.Client{Timeout: 5 * time.Second}})
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Create(context.Background(), "a", []byte("v")); err == nil {
			t.Errorf("status %d: redirect answered as success", status)
		}
	}
	if n := reached.Load(); n != 0 {
		t.Fatalf("the redirect destination received %d requests", n)
	}
}

// What a token source returns as an error is never passed on: it may carry an authentication answer.
func TestTokenSourceErrorIsNotPassedOn(t *testing.T) {
	c, err := New(Config{Addr: "http://127.0.0.1:1", Token: func(context.Context) (string, error) {
		return "", errors.New("login refused: " + canaryToken + " " + canarySecret)
	}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Read(context.Background(), "a")
	if err == nil || strings.Contains(err.Error(), canaryToken) || strings.Contains(err.Error(), canarySecret) {
		t.Fatalf("error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cancelled, _ := New(Config{Addr: "http://127.0.0.1:1", Token: func(ctx context.Context) (string, error) { return "", ctx.Err() }})
	if _, err := cancelled.Read(ctx, "a"); !errors.Is(err, context.Canceled) {
		t.Errorf("cancellation not preserved: %v", err)
	}
}

func TestMountsAreSinglePlainSegments(t *testing.T) {
	for _, m := range []string{"secret/metadata/victim#", "secret?x=1", "secret%2fother", "a/../b", "./secret", "sec ret", "secret/"} {
		for _, cfg := range []Config{{KVMount: m}, {TransitMount: m}} {
			cfg.Addr, cfg.Token = "http://127.0.0.1:1", staticToken("t")
			if _, err := New(cfg); err == nil {
				t.Errorf("mount %q accepted", m)
			}
		}
	}
	if _, err := New(Config{Addr: "http://127.0.0.1:1", Token: staticToken("t"), KVMount: "zone-a/kv"}); err != nil {
		t.Errorf("nested plain mount refused: %v", err)
	}
}

// Oversized inputs are refused before anything is sent; the largest accepted value round-trips
// within the answer limit.
func TestRequestSizesAreBounded(t *testing.T) {
	var sent atomic.Int32
	var stored json.RawMessage // the "data" object of the last write, served back on read as KV v2 does
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		sent.Add(1)
		if r.Method == http.MethodPost {
			var req struct {
				Data json.RawMessage `json:"data"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("request: %v", err)
			}
			stored = req.Data
			return
		}
		_, _ = w.Write([]byte(`{"data":{"data":`))
		_, _ = w.Write(stored)
		_, _ = w.Write([]byte(`,"metadata":{"version":1}}}`))
	})
	ctx := context.Background()
	k := KeyVersion{Name: "k", Version: 1}

	if _, err := c.Sign(ctx, k, make([]byte, maxSignInput+1)); err == nil {
		t.Error("oversized signing input accepted")
	}
	if err := c.Create(ctx, "a", make([]byte, maxValue+1)); err == nil {
		t.Error("oversized value accepted")
	}
	if err := c.Create(ctx, "a", nil); err == nil {
		t.Error("empty value accepted")
	}
	if n := sent.Load(); n != 0 {
		t.Fatalf("%d requests sent for refused inputs", n)
	}

	big := bytes.Repeat([]byte{0xff}, maxValue)
	if err := c.Create(ctx, "a", big); err != nil {
		t.Fatal(err)
	}
	got, err := c.Read(ctx, "a")
	if err != nil || !bytes.Equal(got, big) {
		t.Fatalf("largest value did not round-trip: %d bytes, %v", len(got), err)
	}
}
