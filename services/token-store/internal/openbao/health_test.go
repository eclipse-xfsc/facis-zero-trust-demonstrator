package openbao

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestHealth(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		want    State
		wantErr bool
	}{
		{name: "initialised and unsealed", status: 200, body: `{"initialized":true,"sealed":false,"standby":false}`, want: State{Initialized: true}},
		{name: "standby", status: 200, body: `{"initialized":true,"sealed":false,"standby":true}`, want: State{Initialized: true, Standby: true}},
		{name: "sealed", status: 200, body: `{"initialized":true,"sealed":true}`, want: State{Initialized: true, Sealed: true}},
		{name: "uninitialised", status: 200, body: `{"initialized":false,"sealed":true}`, want: State{Sealed: true}},
		// With every state mapped to 200, these can only come from something in between and say
		// nothing about the server: the mesh's 503 for a pod that is gone must not read as sealed.
		{name: "a 503 is not sealed", status: 503, body: "upstream connect error", wantErr: true},
		{name: "a 501 is not uninitialised", status: 501, body: "", wantErr: true},
		{name: "a 429 is not standby", status: 429, body: "", wantErr: true},
		{name: "server error", status: 500, body: "boom", wantErr: true},
		{name: "bad gateway", status: 502, body: "", wantErr: true},
		{name: "malformed body", status: 200, body: `{"initialized":`, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/sys/health" {
					t.Errorf("path %q", r.URL.Path)
				}
				if q := r.URL.Query(); q.Get("uninitcode") != "200" || q.Get("sealedcode") != "200" || q.Get("standbycode") != "200" {
					t.Errorf("query %q lacks the status mappings", r.URL.RawQuery)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			got, err := Health(context.Background(), srv.Client(), srv.URL, nil)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("got %+v, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("state %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestHealthForwardsTheRequestHeaders(t *testing.T) {
	var seen http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		_, _ = w.Write([]byte(`{"initialized":true}`))
	}))
	defer srv.Close()
	propagate := http.Header{}
	propagate.Set("X-Request-Id", "req-1")
	propagate.Set("Traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
	propagate.Set("Tracestate", "vendor=a")
	if _, err := Health(context.Background(), srv.Client(), srv.URL, propagate); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"X-Request-Id": "req-1",
		"Traceparent":  "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
		"Tracestate":   "vendor=a",
		"Accept":       "application/json",
	} {
		if got := seen.Get(name); got != want {
			t.Errorf("%s arrived as %q, want %q", name, got, want)
		}
	}
}

// A redirect is an answer, not a new destination: the client never follows it, so neither the
// forwarded identifiers nor the question reach the host a proxy named.
func TestNewClientFollowsNoRedirect(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path == "/elsewhere" {
			_, _ = w.Write([]byte(`{"initialized":true,"sealed":false}`))
			return
		}
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	defer srv.Close()
	if _, err := Health(context.Background(), NewClient(), srv.URL, nil); err == nil {
		t.Fatal("a redirect was followed to a healthy answer")
	}
	if n := requests.Load(); n != 1 {
		t.Errorf("%d requests, want 1: the redirect was followed", n)
	}
}

func TestNewClientUsesNoProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("NO_PROXY", "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"initialized":true,"sealed":false}`))
	}))
	defer srv.Close()
	if _, err := Health(context.Background(), NewClient(), srv.URL, nil); err != nil {
		t.Fatalf("the proxy from the environment was used: %v", err)
	}
}

func TestHealthRefusedConnectionIsAnError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	if _, err := Health(context.Background(), &http.Client{}, "http://"+addr, nil); err == nil {
		t.Fatal("refused connection: want an error")
	}
}

func TestHealthHonoursTheDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(5 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := Health(ctx, srv.Client(), srv.URL, nil); err == nil {
		t.Fatal("slow server: want an error")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("took %v, the deadline was 200ms", elapsed)
	}
}
