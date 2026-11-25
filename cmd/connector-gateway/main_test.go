package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/atls"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/atls/atlstest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/atls/provision"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/connectorgateway"
)

// zoneFiles is the mounted material of one zone's gateway: certificate, key and trust anchor.
type zoneFiles struct {
	cert, key, ca, cmcd, identity string
}

// materialOf writes a test zone's certificate and key as the gateway mounts them and starts the
// zone's stand-in cmcd.
func materialOf(t *testing.T, dir string, z *atlstest.Zone, peer *atlstest.Zone) zoneFiles {
	t.Helper()
	var certPEM []byte
	for _, der := range z.Cert.Certificate {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	key, err := x509.MarshalPKCS8PrivateKey(z.Cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	f := zoneFiles{
		cert:     filepath.Join(dir, z.Name+"-cert.pem"),
		key:      filepath.Join(dir, z.Name+"-key.pem"),
		ca:       z.PKI.CAFile,
		cmcd:     z.Config(t, peer).CmcdAddr,
		identity: z.Identity,
	}
	for path, data := range map[string][]byte{f.cert: certPEM, f.key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// configFile writes a gateway configuration and returns its path.
func configFile(t *testing.T, dir, name string, cfg map[string]any) string {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name+".json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// freeAddr reserves a loopback port and releases it for the gateway to bind.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// waitListening dials addr until it accepts; a refusal recorded by an attested listener for the
// probe is expected and tolerated by the assertions.
func waitListening(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s never listened", addr)
}

// safeBuffer collects the JSON lines of several roles.
type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuffer) events(t *testing.T) []connectorgateway.Event {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []connectorgateway.Event
	for _, line := range strings.Split(strings.TrimSpace(s.b.String()), "\n") {
		if line == "" {
			continue
		}
		var e connectorgateway.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("stdout line is not one JSON decision: %q", line)
		}
		out = append(out, e)
	}
	return out
}

func find(events []connectorgateway.Event, role, decision string) (connectorgateway.Event, bool) {
	for _, e := range events {
		if e.Role == role && e.Decision == decision {
			return e, true
		}
	}
	return connectorgateway.Event{}, false
}

// Two processes of the binary, one per role, with the material each zone mounts: an HTTP call
// through the egress reaches the ingress's target over a mutually attested channel, and each
// process records the decision as one JSON line with the same channel binding.
func TestRunPairCarriesHTTPOverTheAttestedChannel(t *testing.T) {
	pki := atlstest.NewPKI(t)
	a, b := atlstest.NewZone(t, pki, "a"), atlstest.NewZone(t, pki, "b")
	dir := t.TempDir()
	ma, mb := materialOf(t, dir, a, b), materialOf(t, dir, b, a)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/resource" || r.Header.Get("X-Call") != "one" {
			t.Error("call information changed on the way")
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, "answer")
	}))
	defer upstream.Close()
	ingressAddr, egressAddr := freeAddr(t), freeAddr(t)
	ingress := configFile(t, dir, "ingress", map[string]any{
		"role": "ingress", "listen": ingressAddr, "target": strings.TrimPrefix(upstream.URL, "http://"),
		"certificate": mb.cert, "key": mb.key, "ca": mb.ca, "cmcd": mb.cmcd, "peerIdentity": ma.identity,
	})
	egress := configFile(t, dir, "egress", map[string]any{
		"role": "egress", "listen": egressAddr, "target": ingressAddr,
		"certificate": ma.cert, "key": ma.key, "ca": ma.ca, "cmcd": ma.cmcd, "peerIdentity": mb.identity,
	})
	ctx, cancel := context.WithCancel(t.Context())
	out := &safeBuffer{}
	errs := make(chan error, 2)
	for _, path := range []string{ingress, egress} {
		go func() { errs <- run(ctx, []string{"--config", path}, out, cancel) }()
	}
	// Neither listener is probed directly: a bare connect to the attested listener would be a
	// refused handshake of its own. The call is retried until both roles serve.
	var res *http.Response
	var body []byte
	deadline := time.Now().Add(15 * time.Second)
	for {
		client := &http.Client{Timeout: 10 * time.Second}
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+egressAddr+"/resource", nil)
		req.Header.Set("X-Call", "one")
		var err error
		res, err = client.Do(req)
		if err == nil {
			body, _ = io.ReadAll(res.Body)
			_ = res.Body.Close()
			client.CloseIdleConnections()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no call made it through the pair: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if res.StatusCode != http.StatusAccepted || string(body) != "answer" {
		t.Fatalf("the answer changed on the way: %d %q", res.StatusCode, body)
	}
	cancel()
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("a role did not stop cleanly: %v", err)
		}
	}
	events := out.events(t)
	left, ok1 := find(events, "egress", "established")
	right, ok2 := find(events, "ingress", "established")
	if !ok1 || !ok2 {
		t.Fatalf("both roles must record the established channel: %+v", events)
	}
	if left.Reason != "mutual_attestation" || right.Reason != "mutual_attestation" {
		t.Fatalf("the channel is mutual attestation only: %+v %+v", left, right)
	}
	if left.Binding == "" || left.Binding != right.Binding {
		t.Fatalf("the two ends must record one channel binding: %q %q", left.Binding, right.Binding)
	}
	if left.TLSVersion != tls.VersionTLS13 || right.TLSVersion != tls.VersionTLS13 {
		t.Fatalf("TLS 1.3 only: %d %d", left.TLSVersion, right.TLSVersion)
	}
	if left.Peer != mb.identity || right.Peer != ma.identity {
		t.Fatalf("each end records the identity it expected: %q %q", left.Peer, right.Peer)
	}
	for _, e := range events {
		switch e.Decision {
		case "started":
			t.Fatalf("no startup check was configured, none may be recorded: %+v", e)
		case "established":
			if e.Binding != left.Binding {
				t.Fatalf("one call, one channel: a second binding was recorded: %+v", events)
			}
		}
	}
}

// A configuration the gateway cannot honour is refused before any listener opens; every refusal
// is exit status 1.
func TestRunRefusesAConfigurationItCannotHonour(t *testing.T) {
	pki := atlstest.NewPKI(t)
	a, b := atlstest.NewZone(t, pki, "a"), atlstest.NewZone(t, pki, "b")
	dir := t.TempDir()
	m := materialOf(t, dir, a, b)
	good := map[string]any{
		"role": "ingress", "listen": freeAddr(t), "target": "127.0.0.1:1",
		"certificate": m.cert, "key": m.key, "ca": m.ca, "cmcd": m.cmcd, "peerIdentity": b.Identity,
	}
	with := func(changes map[string]any) map[string]any {
		cfg := map[string]any{}
		for k, v := range good {
			cfg[k] = v
		}
		for k, v := range changes {
			if v == nil {
				delete(cfg, k)
			} else {
				cfg[k] = v
			}
		}
		return cfg
	}
	cases := map[string]struct {
		args []string
		cfg  map[string]any
		want string
	}{
		"missing file":           {args: []string{"--config", filepath.Join(dir, "absent.json")}, want: "no such file"},
		"positional argument":    {args: []string{"--config", configFile(t, dir, "pos", good), "extra"}, want: "positional"},
		"unknown field":          {cfg: with(map[string]any{"plainTLS": true}), want: "unknown field"},
		"unknown role":           {cfg: with(map[string]any{"role": "relay"}), want: "ingress or egress"},
		"certificate missing":    {cfg: with(map[string]any{"certificate": filepath.Join(dir, "none.pem")}), want: "gateway certificate"},
		"attestation incomplete": {cfg: with(map[string]any{"attestation": map[string]any{"zone": "x.json"}}), want: "metadataCA"},
		"attestation negative":   {cfg: with(map[string]any{"attestation": map[string]any{"zone": "x.json", "metadataCA": []string{m.ca}, "timeoutSeconds": -1}}), want: "negative"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			args := c.args
			if args == nil {
				args = []string{"--config", configFile(t, dir, strings.ReplaceAll(name, " ", "-"), c.cfg)}
			}
			out := &safeBuffer{}
			err := run(t.Context(), args, out, func() {})
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("refusal %q expected, got %v", c.want, err)
			}
			if exitCode(err) != 1 {
				t.Fatalf("a configuration refusal is exit status 1, got %d", exitCode(err))
			}
			if listen, ok := c.cfg["listen"].(string); ok {
				if conn, err := net.DialTimeout("tcp", listen, 200*time.Millisecond); err == nil {
					_ = conn.Close()
					t.Fatal("a refused configuration opened a listener")
				}
			}
			if len(out.events(t)) != 0 {
				t.Fatalf("a configuration refusal records no decision: %+v", out.events(t))
			}
		})
	}
}

// The startup check decides whether the role serves at all: a rejected report or an unreachable
// attester is recorded as a refusal, exits with its own status and opens no listener; a verified
// report is recorded as the start and the role serves.
func TestStartupCheckGatesTheRole(t *testing.T) {
	pki := atlstest.NewPKI(t)
	a, b := atlstest.NewZone(t, pki, "a"), atlstest.NewZone(t, pki, "b")
	dir := t.TempDir()
	m := materialOf(t, dir, a, b)
	zoneFile := filepath.Join("..", "..", "deployment", "attestation", "zone-a.json")
	cases := map[string]struct {
		check  error
		exit   int
		reason string
		serves bool
	}{
		"report rejected":      {check: errors.New("component atls-gateway: verified aa, configured bb"), exit: 2, reason: "evidence_rejected"},
		"attester unreachable": {check: fmt.Errorf("%w: 127.0.0.1:1: refused", provision.ErrNoReport), exit: 3, reason: "attester_unavailable"},
		"evidence verified":    {exit: 0, reason: "evidence_verified", serves: true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			var got struct {
				cmcd string
				zone string
				cas  int
			}
			checkEvidence = func(ctx context.Context, cmcdAddr string, cas []*x509.Certificate, z *provision.Zone) (*provision.Evidence, error) {
				if _, ok := ctx.Deadline(); !ok {
					t.Error("the startup check must be bounded")
				}
				got.cmcd, got.zone, got.cas = cmcdAddr, z.Zone, len(cas)
				if c.check != nil {
					return nil, c.check
				}
				return &provision.Evidence{}, nil
			}
			t.Cleanup(func() { checkEvidence = provision.Check })
			listen := freeAddr(t)
			cfg := configFile(t, dir, strings.ReplaceAll(name, " ", "-"), map[string]any{
				"role": "ingress", "listen": listen, "target": "127.0.0.1:1",
				"certificate": m.cert, "key": m.key, "ca": m.ca, "cmcd": m.cmcd, "peerIdentity": b.Identity,
				"attestation": map[string]any{"zone": zoneFile, "metadataCA": []string{m.ca}, "timeoutSeconds": 5},
			})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			out := &safeBuffer{}
			done := make(chan error, 1)
			go func() { done <- run(ctx, []string{"--config", cfg}, out, cancel) }()
			var err error
			if c.serves {
				waitListening(t, listen)
				cancel()
			}
			select {
			case err = <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("run did not return")
			}
			if exitCode(err) != c.exit {
				t.Fatalf("exit %d expected, got %d (%v)", c.exit, exitCode(err), err)
			}
			if got.cmcd != m.cmcd || got.zone != "zone-a" || got.cas != 1 {
				t.Fatalf("the check must receive the zone's cmcd, configuration and metadata CA: %+v", got)
			}
			events := out.events(t)
			decision := "refused"
			if c.serves {
				decision = "started"
			}
			if len(events) == 0 || events[0].Role != "ingress" || events[0].Decision != decision || events[0].Reason != c.reason {
				t.Fatalf("the first decision must be the startup outcome %s/%s: %+v", decision, c.reason, events)
			}
			if !c.serves {
				if conn, dialErr := net.DialTimeout("tcp", listen, 200*time.Millisecond); dialErr == nil {
					_ = conn.Close()
					t.Fatal("a refused startup check opened the listener")
				}
				if len(events) != 1 {
					t.Fatalf("a refused startup records one decision only: %+v", events)
				}
			}
		})
	}
}

// The attested listener refuses a plain TLS 1.3 client with a zone certificate that never attests,
// and records why; the binary surfaces that refusal as it is.
func TestRunRecordsRefusalsOfUnattestedPeers(t *testing.T) {
	pki := atlstest.NewPKI(t)
	a, b := atlstest.NewZone(t, pki, "a"), atlstest.NewZone(t, pki, "b")
	dir := t.TempDir()
	m := materialOf(t, dir, b, a)
	listen := freeAddr(t)
	cfg := configFile(t, dir, "ingress", map[string]any{
		"role": "ingress", "listen": listen, "target": "127.0.0.1:1",
		"certificate": m.cert, "key": m.key, "ca": m.ca, "cmcd": m.cmcd, "peerIdentity": a.Identity,
	})
	ctx, cancel := context.WithCancel(t.Context())
	out := &safeBuffer{}
	done := make(chan error, 1)
	go func() { done <- run(ctx, []string{"--config", cfg}, out, cancel) }()
	waitListening(t, listen)
	tlsCfg := a.TLSConfig()
	tlsCfg.InsecureSkipVerify = true // test client only; the listener verifies the client
	conn, err := tls.Dial("tcp", listen, tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: bypass\r\n\r\n")
	_, _ = io.ReadAll(conn)
	_ = conn.Close()
	deadline := time.Now().Add(15 * time.Second)
	var refusal connectorgateway.Event
	for time.Now().Before(deadline) {
		if e, ok := func() (connectorgateway.Event, bool) {
			for _, e := range out.events(t) {
				if e.Decision == "refused" && e.Reason == atls.ErrHandshakeTimeout.Error() {
					return e, true
				}
			}
			return connectorgateway.Event{}, false
		}(); ok {
			refusal = e
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if refusal.Role != "ingress" {
		t.Fatalf("the unattested TLS peer must be refused with the handshake timeout: %+v", out.events(t))
	}
}

func TestExitCode(t *testing.T) {
	if exitCode(nil) != 0 || exitCode(errors.New("x")) != 1 || exitCode(checkFailed{errors.New("x")}) != 2 ||
		exitCode(fmt.Errorf("wrapped: %w", checkFailed{errors.New("x")})) != 2 || exitCode(fmt.Errorf("%w: y", provision.ErrNoReport)) != 3 {
		t.Fatal("exit status mapping changed")
	}
}
