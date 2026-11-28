package connectorgateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/atls"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/atls/atlstest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type events struct {
	mu      sync.Mutex
	entries []Event
}

func (e *events) record(v Event) { e.mu.Lock(); defer e.mu.Unlock(); e.entries = append(e.entries, v) }
func (e *events) snapshot() []Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]Event(nil), e.entries...)
}
func (e *events) wait(t *testing.T, role, decision string) Event {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		for _, v := range e.snapshot() {
			if v.Role == role && v.Decision == decision {
				return v
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("missing %s %s decision: %+v", role, decision, e.snapshot())
	return Event{}
}

func configs(t *testing.T) (atls.Config, atls.Config) {
	t.Helper()
	if dir := os.Getenv("GATEWAY_FIXTURES"); dir != "" {
		// Both zones' trust anchors in one file, as the gateway's mounted trust is.
		trust := filepath.Join(t.TempDir(), "ca.pem")
		var anchors []byte
		for _, zone := range []string{"a", "b"} {
			pem, err := os.ReadFile(filepath.Join(dir, "zone-"+zone, "ca.pem"))
			if err != nil {
				t.Fatal(err)
			}
			anchors = append(anchors, pem...)
		}
		if err := os.WriteFile(trust, anchors, 0o600); err != nil {
			t.Fatal(err)
		}
		load := func(zone, peer string) atls.Config {
			var cmcd struct {
				Addr string `json:"cmcAddr"`
			}
			b, err := os.ReadFile(filepath.Join(dir, "zone-"+zone, "cmcd.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(b, &cmcd); err != nil {
				t.Fatal(err)
			}
			// The loader the gateway binary uses on its mounted files.
			att, err := Config{Certificate: filepath.Join(dir, "zone-"+zone, "cert.pem"), Key: filepath.Join(dir, "zone-"+zone, "key.pem"), CA: trust, Cmcd: cmcd.Addr, PeerIdentity: "spiffe://" + peer + "/gateway"}.Attestation()
			if err != nil {
				t.Fatal(err)
			}
			att.HandshakeTimeout = 3 * time.Second
			return att
		}
		return load("a", "b"), load("b", "a")
	}
	pki := atlstest.NewPKI(t)
	a, b := atlstest.NewZone(t, pki, "a"), atlstest.NewZone(t, pki, "b")
	ac, bc := a.Config(t, b), b.Config(t, a)
	ac.HandshakeTimeout, bc.HandshakeTimeout = 3*time.Second, 3*time.Second
	return ac, bc
}

// tap relays the inter-connector hop and keeps every byte that crossed it, so the proof shows
// that the hop was used and that it carried TLS records only, no call information in the clear.
type tap struct {
	ln   net.Listener
	mu   sync.Mutex
	seen bytes.Buffer
}

func newTap(t *testing.T, target string) *tap {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tp := &tap{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	relay := func(dst, src net.Conn) {
		_, _ = io.Copy(io.MultiWriter(dst, tp), src)
		_ = dst.Close()
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			u, err := net.Dial("tcp", target)
			if err != nil {
				_ = c.Close()
				continue
			}
			go relay(u, c)
			go relay(c, u)
		}
	}()
	return tp
}

func (tp *tap) Write(b []byte) (int, error) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	return tp.seen.Write(b)
}

// protected fails unless the hop carried TLS records and none of the markers in the clear.
func (tp *tap) protected(t *testing.T, markers ...string) int {
	t.Helper()
	tp.mu.Lock()
	defer tp.mu.Unlock()
	wire := tp.seen.Bytes()
	if len(wire) < 3 || wire[0] != 0x16 || wire[1] != 0x03 {
		t.Fatalf("the inter-connector hop did not start with a TLS handshake record (%d bytes)", len(wire))
	}
	for _, m := range markers {
		if bytes.Contains(wire, []byte(m)) {
			t.Fatalf("call information %q crossed the inter-connector hop in the clear", m)
		}
	}
	return len(wire)
}

// pair starts the two connectors with a tap on the hop between them.
func pair(t *testing.T, target string, a, b atls.Config, e *events) (*Gateway, *tap) {
	t.Helper()
	ingress, err := Start(t.Context(), Config{Role: "ingress", Listen: "127.0.0.1:0", Target: target}, b, e.record)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ingress.Close() })
	hop := newTap(t, ingress.Addr().String())
	egress, err := Start(t.Context(), Config{Role: "egress", Listen: "127.0.0.1:0", Target: hop.ln.Addr().String()}, a, e.record)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = egress.Close() })
	return egress, hop
}

// TestGatewayProof runs with two external cmcd processes in the BDD proof.
// Default unit tests use the upstream test gRPC adapter with real CMC reports.
func TestGatewayProof(t *testing.T) {
	a, b := configs(t)
	all := &events{}
	wire := 0
	t.Run("HTTP", func(t *testing.T) {
		var calls atomic.Int64
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			body, _ := io.ReadAll(r.Body)
			if r.Method != "POST" || r.RequestURI != "/resource%2Fpart?q=a%2Bb" || r.Host != "resource.example:8443" || string(body) != "request payload" || r.Header.Get("Authorization") != "Bearer fixture-only" || r.Header.Get("Traceparent") != "trace-fixture" || !reflect.DeepEqual(r.Header.Values("X-Call"), []string{"one", "two"}) {
				t.Error("HTTP call information changed")
			}
			w.Header().Set("Trailer", "X-Result")
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, "response payload")
			w.Header().Set("X-Result", "complete")
		}))
		defer upstream.Close()
		eg, hop := pair(t, strings.TrimPrefix(upstream.URL, "http://"), a, b, all)
		preconnected, err := net.DialTimeout("tcp", eg.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = preconnected.Close() }()
		left := all.wait(t, "egress", "established")
		right := all.wait(t, "ingress", "established")
		if left.Binding == "" || left.Binding != right.Binding || left.TLSVersion != tls.VersionTLS13 || right.TLSVersion != tls.VersionTLS13 || left.Peer != a.ExpectedPeerIdentity {
			t.Fatal("channel binding or TLS version differs")
		}
		awaitForward(t, all.snapshot())
		var used atomic.Bool
		client := &http.Client{Transport: &http.Transport{Proxy: nil, DialContext: func(context.Context, string, string) (net.Conn, error) {
			if used.Swap(true) {
				return nil, errors.New("unexpected second HTTP connection")
			}
			return preconnected, nil
		}}, Timeout: 8 * time.Second}
		defer client.CloseIdleConnections()
		req, _ := http.NewRequestWithContext(t.Context(), "POST", "http://"+eg.Addr().String()+"/resource%2Fpart?q=a%2Bb", strings.NewReader("request payload"))
		req.Host = "resource.example:8443"
		req.Header.Set("Authorization", "Bearer fixture-only")
		req.Header.Set("Traceparent", "trace-fixture")
		req.Header["X-Call"] = []string{"one", "two"}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if err != nil || res.StatusCode != 201 || string(body) != "response payload" || res.Trailer.Get("X-Result") != "complete" {
			t.Fatalf("HTTP response information changed: %v", err)
		}
		wire += hop.protected(t, "request payload", "response payload", "fixture-only", "trace-fixture", "resource.example", "X-Call", "X-Result")
		// Neither a plaintext peer nor a TLS peer holding a zone certificate but speaking no
		// attestation gets a byte to the upstream; each refusal is recorded with its reason.
		for _, plainTLS := range []bool{false, true} {
			refusals := &events{}
			gate, err := Start(t.Context(), Config{Role: "ingress", Listen: "127.0.0.1:0", Target: strings.TrimPrefix(upstream.URL, "http://")}, b, refusals.record)
			if err != nil {
				t.Fatal(err)
			}
			var conn net.Conn
			if plainTLS {
				cfg := a.TLS.Clone()
				cfg.InsecureSkipVerify = true // test client: URI SAN verification is performed by atls in production
				conn, err = tls.Dial("tcp", gate.Addr().String(), cfg)
			} else {
				conn, err = net.DialTimeout("tcp", gate.Addr().String(), time.Second)
			}
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			want := atls.ErrPlainTLS
			if plainTLS {
				// TLS 1.3 with a zone certificate completes; the attestation exchange never does.
				want = atls.ErrHandshakeTimeout
			}
			_, _ = io.WriteString(conn, "GET /unprotected HTTP/1.1\r\nHost: bypass\r\n\r\n")
			_, _ = io.ReadAll(conn)
			_ = conn.Close()
			event := refusals.wait(t, "ingress", "refused")
			if event.Reason != want.Error() {
				t.Fatalf("wrong refusal: %+v", event)
			}
			all.record(event)
			_ = gate.Close()
		}
		if calls.Load() != 1 {
			t.Fatalf("unprotected path reached upstream: %d calls", calls.Load())
		}
	})
	t.Run("GRPC", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		srv := grpc.NewServer()
		grpc_health_v1.RegisterHealthServer(srv, &health{t: t})
		go func() { _ = srv.Serve(ln) }()
		defer srv.Stop()
		eg, hop := pair(t, ln.Addr().String(), a, b, all)
		cc, err := grpc.NewClient(eg.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithAuthority("resource.example"))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = cc.Close() }()
		ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
		defer cancel()
		ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer fixture-only", "traceparent", "trace-fixture", "x-call", "one", "x-call", "two", "binary-bin", string([]byte{0, 1, 255})))
		var headers, trailers metadata.MD
		res, err := grpc_health_v1.NewHealthClient(cc).Check(ctx, &grpc_health_v1.HealthCheckRequest{Service: "opaque/service"}, grpc.Header(&headers), grpc.Trailer(&trailers))
		if err != nil {
			t.Fatal(err)
		}
		if res.Status != grpc_health_v1.HealthCheckResponse_SERVING || !reflect.DeepEqual(headers.Get("x-response"), []string{"header"}) || !reflect.DeepEqual(trailers.Get("x-result"), []string{"trailer"}) {
			t.Fatal("gRPC response metadata changed")
		}
		if _, err := grpc_health_v1.NewHealthClient(cc).Check(ctx, &grpc_health_v1.HealthCheckRequest{Service: "refused/service"}); status.Code(err) != codes.PermissionDenied || status.Convert(err).Message() != "fixture refusal" {
			t.Fatalf("gRPC error status changed: %v", err)
		}
		stream, err := grpc_health_v1.NewHealthClient(cc).Watch(ctx, &grpc_health_v1.HealthCheckRequest{Service: "opaque/service"})
		if err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if _, err = stream.Recv(); err != nil {
				t.Fatal(err)
			}
		}
		if _, err = stream.Recv(); err != io.EOF {
			t.Fatalf("stream end: %v", err)
		}
		if !reflect.DeepEqual(stream.Trailer().Get("x-result"), []string{"stream-complete"}) {
			t.Fatal("stream trailer lost")
		}
		wire += hop.protected(t, "fixture-only", "trace-fixture", "resource.example", "opaque/service", "fixture refusal", "stream-complete")
	})
	t.Run("NoPlainTLSFallback", func(t *testing.T) {
		ln, err := tls.Listen("tcp", "127.0.0.1:0", b.TLS.Clone())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = ln.Close() }()
		received := make(chan []byte, 1)
		go func() {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				received <- nil
				return
			}
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
			data, _ := io.ReadAll(io.LimitReader(conn, 1<<20))
			received <- data
		}()
		ev := &events{}
		eg, err := Start(t.Context(), Config{Role: "egress", Listen: "127.0.0.1:0", Target: ln.Addr().String()}, a, ev.record)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = eg.Close() }()
		c, err := net.DialTimeout("tcp", eg.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(6 * time.Second))
		_, _ = io.WriteString(c, "GET /must-not-arrive HTTP/1.1\r\nHost: resource\r\n\r\n")
		_, _ = io.ReadAll(c)
		_ = c.Close()
		event := ev.wait(t, "egress", "refused")
		// The peer completes TLS 1.3 with its zone certificate and never attests.
		if event.Reason != atls.ErrHandshakeTimeout.Error() {
			t.Fatalf("wrong refusal: %+v", event)
		}
		if data := <-received; strings.Contains(string(data), "must-not-arrive") {
			t.Fatal("plain TLS fallback delivered application traffic")
		}
		all.record(event)
	})
	if out := os.Getenv("GATEWAY_RECORD"); out != "" && !t.Failed() {
		if os.Getenv("GATEWAY_FIXTURES") == "" {
			t.Fatal("acceptance record requires external cmcd fixtures")
		}
		record := struct {
			Passed bool    `json:"passed"`
			Proof  string  `json:"proof"`
			Events []Event `json:"events"`
			// Bytes the tap saw on the inter-connector hop: TLS records, no call information.
			WireBytes int `json:"interConnectorTLSBytes"`
		}{true, "http-grpc-two-cmcd", all.snapshot(), wire}
		data, err := json.MarshalIndent(record, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(out, append(data, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

type health struct {
	grpc_health_v1.UnimplementedHealthServer
	t *testing.T
}

func (h *health) check(ctx context.Context, req *grpc_health_v1.HealthCheckRequest) {
	h.t.Helper()
	md, _ := metadata.FromIncomingContext(ctx)
	for k, want := range map[string][]string{"authorization": {"Bearer fixture-only"}, "traceparent": {"trace-fixture"}, "x-call": {"one", "two"}, "binary-bin": {string([]byte{0, 1, 255})}, ":authority": {"resource.example"}} {
		if !reflect.DeepEqual(md.Get(k), want) {
			h.t.Errorf("gRPC %s changed", k)
		}
	}
	if req.Service != "opaque/service" {
		h.t.Error("gRPC payload changed")
	}
	if _, ok := ctx.Deadline(); !ok {
		h.t.Error("gRPC deadline lost")
	}
}
func (h *health) Check(ctx context.Context, req *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	if req.Service == "refused/service" {
		return nil, status.Error(codes.PermissionDenied, "fixture refusal")
	}
	h.check(ctx, req)
	_ = grpc.SetHeader(ctx, metadata.Pairs("x-response", "header"))
	_ = grpc.SetTrailer(ctx, metadata.Pairs("x-result", "trailer"))
	return &grpc_health_v1.HealthCheckResponse{Status: grpc_health_v1.HealthCheckResponse_SERVING}, nil
}
func (h *health) Watch(req *grpc_health_v1.HealthCheckRequest, s grpc.ServerStreamingServer[grpc_health_v1.HealthCheckResponse]) error {
	h.check(s.Context(), req)
	s.SetTrailer(metadata.Pairs("x-result", "stream-complete"))
	for range 2 {
		if err := s.Send(&grpc_health_v1.HealthCheckResponse{Status: grpc_health_v1.HealthCheckResponse_SERVING}); err != nil {
			return err
		}
	}
	return nil
}

func TestRejectConfiguration(t *testing.T) {
	a := atls.Config{}
	for _, role := range []string{"", "plain-tls"} {
		if g, err := Start(t.Context(), Config{Role: role}, a, func(Event) {}); err == nil {
			_ = g.Close()
			t.Fatal("accepted invalid role")
		}
	}
	a.Mode = atls.ModeServer
	if g, err := Start(t.Context(), Config{Role: "egress", Target: "127.0.0.1:1"}, a, func(Event) {}); err == nil {
		_ = g.Close()
		t.Fatal("accepted unilateral attestation")
	}
}

// The BDD Given waits here with a live attested channel before When releases the
// actual application request. Standalone proofs proceed immediately.
func awaitForward(t *testing.T, entries []Event) {
	t.Helper()
	dir := os.Getenv("GATEWAY_CONTROL_DIR")
	if dir == "" {
		return
	}
	data, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "ready.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.NewTimer(60 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err = os.Stat(filepath.Join(dir, "forward")); err == nil {
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("BDD did not release the request")
		case <-tick.C:
		}
	}
}

func TestChannelExpires(t *testing.T) {
	a, b := configs(t)
	a.ChannelLifetime = time.Second
	b.ChannelLifetime = 10 * time.Second
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer upstream.Close()
	ev := &events{}
	eg, _ := pair(t, strings.TrimPrefix(upstream.URL, "http://"), a, b, ev)
	conn, err := net.DialTimeout("tcp", eg.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	ev.wait(t, "egress", "established")
	if e := ev.wait(t, "egress", "refused"); e.Reason != "channel_expired" {
		t.Fatalf("wrong expiry record: %+v", e)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	_, err = conn.Read(make([]byte, 1))
	var timeout net.Error
	if err == nil || (errors.As(err, &timeout) && timeout.Timeout()) {
		t.Fatalf("expired channel stayed usable: %v", err)
	}
}
