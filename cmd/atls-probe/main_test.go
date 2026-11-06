package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/cmd/atls-probe/internal/record"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/atls"
)

// The probe reaches the attested channel only through internal/atls: no file of it, tests
// included, imports the CMC library or the test-only fixtures, and the relay does not import
// the wrapper either.
func TestImports(t *testing.T) {
	const (
		cmc      = "github.com/Fraunhofer-AISEC/cmc"
		wrapper  = "github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/atls"
		fixtures = wrapper + "/atlstest"
	)
	fset := token.NewFileSet()
	seen := 0
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		seen++
		relay := strings.HasPrefix(filepath.ToSlash(path), "internal/relay/")
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			switch {
			case p == cmc || strings.HasPrefix(p, cmc+"/"):
				t.Errorf("%s imports the CMC library (%s)", path, p)
			case p == fixtures:
				t.Errorf("%s imports the test-only fixtures (%s)", path, p)
			case relay && (p == wrapper || strings.HasPrefix(p, wrapper+"/")):
				t.Errorf("%s: the relay must speak plain TLS, it imports %s", path, p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen < 5 {
		t.Fatalf("only %d Go files checked", seen)
	}
}

func readRecord(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("record is not JSON: %v\n%s", err, raw)
	}
	return m
}

// Without a cmcd address the probe stops with a configuration error before it opens a socket.
func TestCmcdAddressIsRequired(t *testing.T) {
	for _, mode := range []string{"server", "client"} {
		t.Run(mode, func(t *testing.T) {
			// The address is one nothing may listen on afterwards.
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := ln.Addr().String()
			_ = ln.Close()

			rec := filepath.Join(t.TempDir(), "record.json")
			where := "--listen"
			if mode == "client" {
				where = "--connect"
			}
			var stderr bytes.Buffer
			// The certificate files do not exist: the run must end before it would read them.
			code := run([]string{mode, where, addr, "--cert", "missing.pem", "--key", "missing.pem",
				"--ca", "missing.pem", "--peer-id", "spiffe://b/gateway", "--record", rec}, &stderr)
			if code != exitConfig {
				t.Fatalf("exit status %d, want %d\n%s", code, exitConfig, stderr.String())
			}
			if !strings.Contains(stderr.String(), "--cmcd is required") {
				t.Fatalf("stderr does not name the missing cmcd address:\n%s", stderr.String())
			}
			m := readRecord(t, rec)
			if m["outcome"] != record.OutcomeConfigError || !strings.Contains(fmt.Sprint(m["config_error"]), "--cmcd") {
				t.Fatalf("record: outcome %v, config_error %v", m["outcome"], m["config_error"])
			}
			if c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
				_ = c.Close()
				t.Fatal("the probe opened a listener without a cmcd address")
			}
		})
	}
}

func TestUsageErrors(t *testing.T) {
	rec := filepath.Join(t.TempDir(), "record.json")
	cases := map[string][]string{
		"no mode":           {},
		"unknown mode":      {"proxy"},
		"unknown flag":      {"client", "--nonsense"},
		"no record":         {"client", "--connect", "127.0.0.1:1", "--cmcd", "127.0.0.1:1", "--peer-id", "x"},
		"missing material":  {"client", "--connect", "127.0.0.1:1", "--cmcd", "127.0.0.1:1", "--peer-id", "x", "--record", rec, "--cert", "missing.pem", "--key", "missing.pem", "--ca", "missing.pem"},
		"relay no upstream": {"relay", "--listen", "127.0.0.1:0", "--record", rec},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			if code := run(args, io.Discard); code != exitConfig {
				t.Fatalf("exit status %d, want %d", code, exitConfig)
			}
		})
	}
}

func TestSentinelNames(t *testing.T) {
	for _, s := range sentinels {
		if got := sentinelName(fmt.Errorf("wrapped: %w", &atls.Error{Kind: s.err, Reason: "x"})); got != s.name {
			t.Errorf("sentinelName(%v) = %q, want %q", s.err, got, s.name)
		}
		if !strings.HasPrefix(s.name, "Err") {
			t.Errorf("sentinel name %q", s.name)
		}
	}
	if got := sentinelName(io.EOF); got != "" {
		t.Errorf("io.EOF named %q", got)
	}
}

func TestTransportKind(t *testing.T) {
	cases := map[string]error{
		"eof":              io.EOF,
		"unexpected-eof":   io.ErrUnexpectedEOF,
		"connection-reset": &net.OpError{Op: "read", Err: os.NewSyscallError("read", syscall.ECONNRESET)},
		"broken-pipe":      &net.OpError{Op: "write", Err: os.NewSyscallError("write", syscall.EPIPE)},
		"closed":           net.ErrClosed,
		"other":            errors.New("something else"),
	}
	for want, err := range cases {
		if got := transportKind(err); got != want {
			t.Errorf("transportKind(%v) = %q, want %q", err, got, want)
		}
		// The wrapper reports every such error but io.EOF as a lost channel, which still matches
		// the transport error underneath.
		lost := &atls.Error{Kind: atls.ErrChannelLost, Reason: "read failed", Err: err}
		if got := transportKind(lost); got != want {
			t.Errorf("transportKind(%v) = %q, want %q", lost, got, want)
		}
		if got := sentinelName(lost); got != "ErrChannelLost" {
			t.Errorf("sentinelName(%v) = %q, want ErrChannelLost", lost, got)
		}
	}
}

// pair returns the two ends of a TCP connection on the loopback interface.
func pair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	a, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b := <-accepted
	if b == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}

func newHolder(t *testing.T, hold, interval time.Duration) (*holder, *record.File) {
	t.Helper()
	rec := record.New(filepath.Join(t.TempDir(), "record.json"), "client", "dialer", record.Environment{})
	rec.NextSession()
	return &holder{probe: &probe{stderr: io.Discard}, rec: rec, hold: hold, interval: interval}, rec
}

// Without --hold each end sends one heartbeat, waits for the peer's and closes.
func TestSingleExchange(t *testing.T) {
	a, b := pair(t)
	ha, ra := newHolder(t, 0, time.Second)
	hb, rb := newHolder(t, 0, time.Second)
	done := make(chan struct{})
	go func() { ha.run(context.Background(), 0, a); close(done) }()
	hb.run(context.Background(), 0, b)
	<-done
	for name, rec := range map[string]*record.File{"a": ra, "b": rb} {
		s := rec.Snapshot()
		if s.Ended != record.EndedExchangeComplete || s.Error != nil || s.Heartbeats.Sent != 1 || s.Heartbeats.Received != 1 {
			t.Errorf("end %s: ended %q, error %+v, heartbeats %+v", name, s.Ended, s.Error, s.Heartbeats)
		}
		if s.ApplicationBytesSent == 0 || s.ApplicationBytesReceived == 0 {
			t.Errorf("end %s: application bytes %d sent, %d received", name, s.ApplicationBytesSent, s.ApplicationBytesReceived)
		}
	}
}

// A held channel records the first failure: here the peer goes away.
func TestHoldRecordsPeerLoss(t *testing.T) {
	a, b := pair(t)
	h, rec := newHolder(t, time.Minute, 20*time.Millisecond)
	done := make(chan struct{})
	go func() { h.run(context.Background(), 0, a); close(done) }()

	// The peer sends two heartbeats, then its end of the connection disappears.
	for i := range 2 {
		if _, err := fmt.Fprintf(b, "heartbeat %d 0\n", i+1); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(100 * time.Millisecond)
	_ = b.Close()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the holder did not notice the peer leaving")
	}
	s := rec.Snapshot()
	if s.Error == nil {
		t.Fatalf("no error recorded; ended %q", s.Ended)
	}
	if s.Error.Kind != "transport" || s.Error.Sentinel != "" || s.Error.DetectedAtUnixMs == 0 {
		t.Fatalf("error %+v", s.Error)
	}
	if s.Heartbeats.Received != 2 || s.Heartbeats.Sent < 2 {
		t.Fatalf("heartbeats %+v", s.Heartbeats)
	}
	if s.Ended != record.EndedPeerClosed && s.Ended != record.EndedError {
		t.Fatalf("ended %q", s.Ended)
	}
}

// The hold time ends the session from this end, and a stop request ends it early.
func TestHoldEnds(t *testing.T) {
	t.Run("hold elapsed", func(t *testing.T) {
		a, b := pair(t)
		go func() { _, _ = io.Copy(io.Discard, b) }()
		h, rec := newHolder(t, 150*time.Millisecond, 20*time.Millisecond)
		h.run(context.Background(), 0, a)
		if s := rec.Snapshot(); s.Ended != record.EndedHoldElapsed || s.Error != nil {
			t.Fatalf("ended %q, error %+v", s.Ended, s.Error)
		}
	})
	t.Run("stopped", func(t *testing.T) {
		a, b := pair(t)
		go func() { _, _ = io.Copy(io.Discard, b) }()
		h, rec := newHolder(t, time.Minute, 20*time.Millisecond)
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(100*time.Millisecond, cancel)
		h.run(ctx, 0, a)
		if s := rec.Snapshot(); s.Ended != record.EndedSignal {
			t.Fatalf("ended %q", s.Ended)
		}
	})
}
