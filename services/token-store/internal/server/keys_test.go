package server

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/transit"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/acquire"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/acquire/acquiretest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/keys"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/testsupport"
)

// These tests need a real OpenBao and a database, as the substitution tests do (newSubEnv).

// serveUntil runs Serve on cfg and returns what it returned, waiting at most wait; the server's
// records go to logs. The context is cancelled when the test ends, so a server that keeps running
// stops cleanly.
func serveUntil(t *testing.T, cfg Config, logs *testsupport.Buffer, wait time.Duration) error {
	t.Helper()
	s, err := New(context.Background(), cfg, testLogger(logs))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	select {
	case err := <-done:
		return err
	case <-time.After(wait):
		cancel()
		<-done
		return errors.New("serve kept running")
	}
}

func recordsWith(t *testing.T, logs *testsupport.Buffer, msg string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, r := range records(t, logs) {
		if r["msg"] == msg {
			out = append(out, r)
		}
	}
	return out
}

// On a clean start the configured key is provisioned, its one active row registered with the
// thumbprint of the version's public key, and the resolution logged once.
func TestStartupRegistersTheKeyAndResolvesActiveReferences(t *testing.T) {
	e := newSubEnv(t, false)
	e.server()
	ctx := t.Context()
	var ref, jkt string
	if err := e.poolA.QueryRow(ctx, `SELECT key_ref, jkt FROM signing_key WHERE state = 'active'`).Scan(&ref, &jkt); err != nil {
		t.Fatalf("the registered row: %v", err)
	}
	kv, err := transit.ParseRef(ref)
	if err != nil || kv.Name != e.loaded.SigningKey || kv.Version != 1 {
		t.Fatalf("registered %q, %v; want version 1 of %s", ref, err, e.loaded.SigningKey)
	}
	pub, err := e.bao.PublicKey(ctx, kv)
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := keys.Thumbprint(pub); jkt != want {
		t.Fatalf("registered thumbprint %s, want %s", jkt, want)
	}
	resolved := recordsWith(t, e.logs, msgKeysResolved)
	if len(resolved) != 1 || resolved[0]["active_references"] != float64(1) || resolved[0]["key_ref"] != ref {
		t.Fatalf("resolution records: %v", resolved)
	}
	if n := len(recordsWith(t, e.logs, msgKeysUnavailable)); n != 0 {
		t.Fatalf("%d unavailable records on a clean start", n)
	}
}

// A registered thumbprint that is not the version's public key is a misconfiguration: the
// service stops with an error that names the reason and no key material.
func TestStartupStopsOnAMisconfiguredKey(t *testing.T) {
	e := newSubEnv(t, false)
	ctx := t.Context()
	kv, _, err := keys.Keys{Signer: e.bao, Name: e.loaded.SigningKey}.Ensure(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.poolA.Exec(ctx, `INSERT INTO signing_key (key_ref, jkt, alg, state) VALUES ($1, $2, 'ES256', 'active')`,
		kv.Ref(), strings.Repeat("A", 43)); err != nil {
		t.Fatal(err)
	}
	err = serveUntil(t, e.config(), e.logs, 15*time.Second)
	var m *misconfigured
	if !errors.As(err, &m) || m.reason != acquire.ReasonMismatch || !errors.Is(err, keys.ErrMismatch) {
		t.Fatalf("Serve returned %v; want a mismatch misconfiguration", err)
	}
	stopped := recordsWith(t, e.logs, msgKeysMisconfigured)
	if len(stopped) != 1 || stopped[0]["reason"] != acquire.ReasonMismatch || stopped[0]["key"] != e.loaded.SigningKey {
		t.Fatalf("stop records: %v", stopped)
	}
	if logs := e.logs.String(); strings.Contains(logs, "-----") || strings.Contains(logs, "BEGIN ") {
		t.Fatalf("key material in the records:\n%s", logs)
	}
}

// A registered version transit does not have is missing, and the service stops as well: it
// never minted with it and must not guess another version.
func TestStartupStopsWhenTheRegisteredVersionIsMissing(t *testing.T) {
	e := newSubEnv(t, false)
	ctx := t.Context()
	if _, _, err := (keys.Keys{Signer: e.bao, Name: e.loaded.SigningKey}).Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := e.poolA.Exec(ctx, `INSERT INTO signing_key (key_ref, jkt, alg, state) VALUES ($1, $2, 'ES256', 'active')`,
		transit.KeyVersion{Name: e.loaded.SigningKey, Version: 7}.Ref(), strings.Repeat("B", 43)); err != nil {
		t.Fatal(err)
	}
	err := serveUntil(t, e.config(), e.logs, 15*time.Second)
	if reasonOf(err) != acquire.ReasonMissing {
		t.Fatalf("Serve returned %v; want reason %s", err, acquire.ReasonMissing)
	}
}

// flakyBao is the key-value store while it is away: transit calls fail until it is back.
type flakyBao struct {
	OpenBao
	down atomic.Bool
}

func (f *flakyBao) fail() error {
	if f.down.Load() {
		return errors.New("request failed")
	}
	return nil
}

func (f *flakyBao) EnsureKey(ctx context.Context, name string) (transit.KeyVersion, error) {
	if err := f.fail(); err != nil {
		return transit.KeyVersion{}, err
	}
	return f.OpenBao.EnsureKey(ctx, name)
}

func (f *flakyBao) LatestKey(ctx context.Context, name string) (transit.KeyVersion, error) {
	if err := f.fail(); err != nil {
		return transit.KeyVersion{}, err
	}
	return f.OpenBao.LatestKey(ctx, name)
}

func (f *flakyBao) PublicKey(ctx context.Context, kv transit.KeyVersion) (*ecdsa.PublicKey, error) {
	if err := f.fail(); err != nil {
		return nil, err
	}
	return f.OpenBao.PublicKey(ctx, kv)
}

func (f *flakyBao) KeyStatus(ctx context.Context, name string) (transit.KeyVersion, int, error) {
	if err := f.fail(); err != nil {
		return transit.KeyVersion{}, 0, err
	}
	return f.OpenBao.KeyStatus(ctx, name)
}

// While OpenBao is away the service waits rather than stops: one warning for the outage, not one
// per attempt, and the keys resolve once it is back.
func TestStartupWaitsWhileOpenBaoIsUnreachable(t *testing.T) {
	e := newSubEnv(t, false)
	flaky := &flakyBao{OpenBao: e.bao}
	flaky.down.Store(true)
	cfg := e.config()
	cfg.OpenBao = flaky
	s, err := New(context.Background(), cfg, testLogger(e.logs))
	if err != nil {
		t.Fatal(err)
	}
	stop := startServer(t, s)
	// Attempts at 0 s and 1 s have failed by now; the next is due at 3 s.
	time.Sleep(1500 * time.Millisecond)
	select {
	case <-s.keyStarted:
		t.Fatal("the keys resolved while OpenBao was away")
	default:
	}
	if n := len(recordsWith(t, e.logs, msgKeysUnavailable)); n != 1 {
		t.Fatalf("%d unavailable records during one outage; want 1", n)
	}
	flaky.down.Store(false)
	select {
	case <-s.keyStarted:
	case <-time.After(10 * time.Second):
		t.Fatal("the keys did not resolve once OpenBao was back")
	}
	resolved := recordsWith(t, e.logs, msgKeysResolved)
	if len(resolved) != 1 || resolved[0]["attempts"].(float64) < 2 {
		t.Fatalf("resolution records: %v", resolved)
	}
	if n := len(recordsWith(t, e.logs, msgKeysMisconfigured)); n != 0 {
		t.Fatal("an outage stopped the service")
	}
	if err := stop(); err != nil {
		t.Fatalf("Serve returned %v after a clean stop", err)
	}
}

// A configured key transit does not have reads missing, not unreachable: readiness tells a
// configuration fault from an outage.
func TestReadyz_AMissingConfiguredKeyIsMissing(t *testing.T) {
	e := newSubEnv(t, false)
	s, _ := e.server()
	e.loaded.SigningKey = "absent-" + acquiretest.RandHex(6)
	if w := s.checkSigningKey(t.Context()); w != checkMissing {
		t.Fatalf("missing configured key: %q, want %q", w, checkMissing)
	}
}

// A registered version below transit's signing floor resolves to its public key but can no longer
// sign (a rotation that did not finish): startup stops with retired and names the row; the next
// keys rotate repairs it by adopting the version transit is at, and readiness follows.
func TestStartupStopsWhenTheRegisteredVersionIsBelowTheFloor(t *testing.T) {
	e := newSubEnv(t, false)
	ctx := t.Context()
	kv, jkt, err := keys.Keys{Signer: e.bao, Name: e.loaded.SigningKey}.Ensure(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.poolA.Exec(ctx, `INSERT INTO signing_key (key_ref, jkt, alg, state) VALUES ($1, $2, 'ES256', 'active')`, kv.Ref(), jkt); err != nil {
		t.Fatal(err)
	}
	if _, err := e.bao.Rotate(ctx, e.loaded.SigningKey); err != nil {
		t.Fatal(err)
	}
	if err := e.bao.SetMinSigningVersion(ctx, e.loaded.SigningKey, 2); err != nil {
		t.Fatal(err)
	}
	err = serveUntil(t, e.config(), e.logs, 15*time.Second)
	if reasonOf(err) != acquire.ReasonRetired {
		t.Fatalf("Serve returned %v; want reason %s", err, acquire.ReasonRetired)
	}
	stopped := recordsWith(t, e.logs, msgKeysMisconfigured)
	if len(stopped) != 1 || stopped[0]["key_ref"] != kv.Ref() {
		t.Fatalf("stop records: %v", stopped)
	}
	if rot, err := acquire.Rotate(ctx, e.poolA, e.bao, e.loaded.SigningKey); err != nil || !rot.Adopted || rot.Active != (transit.KeyVersion{Name: e.loaded.SigningKey, Version: 2}).Ref() {
		t.Fatalf("repair by rotate: %+v %v", rot, err)
	}
	before := len(recordsWith(t, e.logs, msgKeysResolved))
	e.server()
	if n := len(recordsWith(t, e.logs, msgKeysResolved)) - before; n != 1 {
		t.Fatalf("after the repair: %d resolution records", n)
	}
}

// Readiness tells a key the store cannot mint with from one it can: a registered version below
// the floor, or a key whose only registered version is retired, reads retired; a repaired or
// re-registered key reads ok again.
func TestReadyz_AKeyTheStoreCannotMintWithIsRetired(t *testing.T) {
	e := newSubEnv(t, true)
	s, _ := e.server()
	ctx := t.Context()
	if w := s.checkSigningKey(ctx); w != checkOK {
		t.Fatalf("after startup: %q", w)
	}
	if _, err := e.bao.Rotate(ctx, e.loaded.SigningKey); err != nil {
		t.Fatal(err)
	}
	if w := s.checkSigningKey(ctx); w != checkOK {
		t.Fatalf("transit ahead but the registered version still signs: %q", w)
	}
	if err := e.bao.SetMinSigningVersion(ctx, e.loaded.SigningKey, 2); err != nil {
		t.Fatal(err)
	}
	if w := s.checkSigningKey(ctx); w != checkRetired {
		t.Fatalf("registered version below the floor: %q, want %q", w, checkRetired)
	}
	if _, err := acquire.Rotate(ctx, e.poolA, e.bao, e.loaded.SigningKey); err != nil {
		t.Fatal(err)
	}
	if w := s.checkSigningKey(ctx); w != checkOK {
		t.Fatalf("after the repair: %q", w)
	}
	if _, err := e.poolA.Exec(ctx, `UPDATE signing_key SET state = 'retired', retired_at = now() WHERE state = 'active'`); err != nil {
		t.Fatal(err)
	}
	if w := s.checkSigningKey(ctx); w != checkRetired {
		t.Fatalf("only retired versions: %q, want %q", w, checkRetired)
	}
}

// Until startup has resolved the keys the store is not ready: readiness answers starting, so no
// traffic reaches a pod whose keys may yet prove misconfigured.
func TestReadyz_IsStartingUntilTheKeysResolve(t *testing.T) {
	e := newSubEnv(t, false)
	flaky := &flakyBao{OpenBao: e.bao}
	flaky.down.Store(true)
	cfg := e.config()
	cfg.OpenBao = flaky
	s, err := New(context.Background(), cfg, testLogger(e.logs))
	if err != nil {
		t.Fatal(err)
	}
	stop := startServer(t, s)
	if w := s.checkSigningKey(t.Context()); w != checkStarting {
		t.Fatalf("while the keys resolve: %q, want %q", w, checkStarting)
	}
	flaky.down.Store(false)
	select {
	case <-s.keyStarted:
	case <-time.After(10 * time.Second):
		t.Fatal("the keys did not resolve")
	}
	if w := s.checkSigningKey(t.Context()); w == checkStarting {
		t.Fatalf("resolved, still %q", w)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
}

// scopedBao is the key-value store seen through a token scoped to the store's own key: any other
// key answers 403.
type scopedBao struct {
	OpenBao
	own string
}

func (b *scopedBao) PublicKey(ctx context.Context, kv transit.KeyVersion) (*ecdsa.PublicKey, error) {
	if kv.Name != b.own {
		return nil, &transit.StatusError{Op: "public key", Status: 403}
	}
	return b.OpenBao.PublicKey(ctx, kv)
}

// An active row of another key (left over after a rename) that the store's scoped token cannot
// read is a warning, not this key's misconfiguration: startup resolves and readiness is not held.
func TestStartupToleratesAForeignRowItCannotRead(t *testing.T) {
	e := newSubEnv(t, true)
	ctx := t.Context()
	other := "sub-old-" + acquiretest.RandHex(6)
	kv, jkt, err := keys.Keys{Signer: e.bao, Name: other}.Ensure(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.poolA.Exec(ctx, `INSERT INTO signing_key (key_ref, jkt, alg, state) VALUES ($1, $2, 'ES256', 'active')`, kv.Ref(), jkt); err != nil {
		t.Fatal(err)
	}
	cfg := e.config()
	cfg.OpenBao = &scopedBao{OpenBao: e.bao, own: e.loaded.SigningKey}
	s, err := New(context.Background(), cfg, testLogger(e.logs))
	if err != nil {
		t.Fatal(err)
	}
	stop := startServer(t, s)
	select {
	case <-s.keyStarted:
	case <-time.After(10 * time.Second):
		t.Fatal("startup did not resolve")
	}
	if n := len(recordsWith(t, e.logs, msgKeysResolved)); n != 1 {
		t.Fatalf("%d resolution records", n)
	}
	foreign := recordsWith(t, e.logs, msgKeyForeign)
	if len(foreign) != 1 || foreign[0]["key_ref"] != kv.Ref() {
		t.Fatalf("foreign-row records: %v", foreign)
	}
	if w := s.checkSigningKey(ctx); w != checkOK {
		t.Fatalf("readiness with an unreadable foreign row: %q", w)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
}
