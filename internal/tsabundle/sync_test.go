package tsabundle

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeTSA keeps one policy per key, as the TSA does, and evaluates like the policy: the revision is
// data.bundle.revision, unless the Rego writes a literal bundle_revision (every input) or a
// "# real-revision: X" marker (every input but the probe's empty one).
type fakeTSA struct {
	mu       sync.Mutex
	policies map[string]*fakePolicy // evaluation path -> policy
	imports  int
	fail     int // evaluations still to fail, as a slow or overloaded TSA does
}

type fakePolicy struct {
	probe, real, version string
	locked               bool
}

var (
	literalRevision = regexp.MustCompile(`"bundle_revision": "([^"]+)"`)
	realRevision    = regexp.MustCompile(`# real-revision: (\S+)`)
)

func (f *fakeTSA) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.URL.Path == "/v1/policy/import":
		body, _ := io.ReadAll(r.Body)
		files, _ := unzip(body)
		parts, _ := unzip(files[0].body)
		var m metadata
		_ = json.Unmarshal(parts[0].body, &m)
		var data struct{ Bundle struct{ Revision string } }
		_ = json.Unmarshal(parts[2].body, &data)
		p := &fakePolicy{probe: data.Bundle.Revision, version: m.Policy.Version}
		if lit := literalRevision.FindSubmatch(parts[1].body); lit != nil {
			p.probe = string(lit[1])
		}
		p.real = p.probe
		if lit := realRevision.FindSubmatch(parts[1].body); lit != nil {
			p.real = string(lit[1])
		}
		f.policies[Coordinates{m.Policy.Repository, m.Policy.Group, m.Policy.Name, m.Policy.Version}.EvaluationPath()] = p
		f.imports++
	case r.URL.Path == "/v1/policies":
		var out struct {
			Policies []Coordinates `json:"policies"`
		}
		for _, p := range f.policies {
			out.Policies = append(out.Policies, coords.At(p.version))
		}
		_ = json.NewEncoder(w).Encode(out)
	case strings.HasSuffix(r.URL.Path, "/lock"):
		p, ok := f.policies[strings.TrimSuffix(r.URL.Path, "/lock")+"/evaluation"]
		if !ok {
			http.NotFound(w, r)
			return
		}
		p.locked = true
	default:
		p, ok := f.policies[r.URL.Path]
		if f.fail > 0 || !ok || p.locked {
			if f.fail > 0 {
				f.fail--
			}
			http.Error(w, "policy not found", http.StatusInternalServerError)
			return
		}
		body, _ := io.ReadAll(r.Body)
		answer := p.real
		if string(body) == "{}" {
			answer = p.probe
		}
		_, _ = io.WriteString(w, `{"decision":{"bundle_revision":"`+answer+`"}}`)
	}
}

func (f *fakeTSA) do(fn func()) { f.mu.Lock(); defer f.mu.Unlock(); fn() }

// answers is what the TSA answers the probe under a revision's key ("" when it holds none or it is locked).
func (f *fakeTSA) answers(revision string) (a string) {
	f.do(func() {
		if p := f.policies[coords.At(revision).EvaluationPath()]; p != nil && !p.locked {
			a = p.probe
		}
	})
	return a
}

func (f *fakeTSA) count() (n int) { f.do(func() { n = f.imports }); return n }

// edited is a correctly signed bundle of the guard policy with its Rego changed by edit.
func edited(t *testing.T, k *ecdsa.PrivateKey, revision string, edit func(string) string) []byte {
	t.Helper()
	dir := t.TempDir()
	rego, _ := os.ReadFile(policyDir + "/policy.rego")
	changed := edit(string(rego))
	if changed == string(rego) {
		t.Fatal("the edit changed nothing; update the test")
	}
	data, _ := os.ReadFile(policyDir + "/data.json")
	if os.WriteFile(dir+"/policy.rego", []byte(changed), 0o600) != nil || os.WriteFile(dir+"/data.json", data, 0o600) != nil {
		t.Fatal("write failed")
	}
	innerZip, err := Pack(dir, "", coords, revision, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	outer, err := Seal(innerZip, sign(t, k, innerZip), &k.PublicKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return outer
}

// lying answers the probe with claims instead of its own revision.
func lying(t *testing.T, k *ecdsa.PrivateKey, revision, claims string) []byte {
	return edited(t, k, revision, func(r string) string {
		return strings.ReplaceAll(r, `"bundle_revision": revision`, `"bundle_revision": "`+claims+`"`)
	})
}

type rig struct {
	t     *testing.T
	tsa   *fakeTSA
	srv   *httptest.Server
	store map[string][]byte
	key   *ecdsa.PrivateKey
	logs  *bytes.Buffer
}

func newRig(t *testing.T) *rig {
	ActivationWindow, RetryFailedAfter = time.Second, time.Hour
	r := &rig{t: t, tsa: &fakeTSA{policies: map[string]*fakePolicy{}}, key: newKey(t), logs: &bytes.Buffer{}}
	r.srv = httptest.NewServer(r.tsa)
	t.Cleanup(r.srv.Close)
	r.store = map[string][]byte{}
	return r
}

// syncer is a sidecar on dir: a new one on the same dir is that sidecar after a container restart.
func (r *rig) syncer(dir string) *Syncer {
	s := &Syncer{TSA: r.srv.URL, Policy: coords, Key: &r.key.PublicKey, HTTP: r.srv.Client(), Dir: dir,
		Log: slog.New(slog.NewJSONHandler(r.logs, nil)),
		Fetch: func(_ context.Context, ref string) ([]byte, error) {
			if b, ok := r.store[ref]; ok {
				return b, nil
			}
			return nil, errors.New("not found")
		}}
	if err := s.Open(context.Background()); err != nil {
		r.t.Fatal(err)
	}
	return s
}

func (r *rig) step(s *Syncer, d Desired, wantErr bool, want string) {
	r.t.Helper()
	if err := s.Reconcile(context.Background(), d); (err != nil) != wantErr {
		r.t.Fatalf("%v: error %v", d, err)
	}
	if s.Active() != want || r.tsa.answers(want) != want {
		r.t.Fatalf("%v: active %q, tsa answers %q under %q", d, s.Active(), r.tsa.answers(want), want)
	}
}

func TestSyncerActivatesVerifiedBundlesOnlyAndRollsBack(t *testing.T) {
	r := newRig(t)
	other := newKey(t)
	r.store = map[string][]byte{"v1": bundle(t, r.key, "v1"), "v1-resigned": bundle(t, r.key, "v1"), "v2": bundle(t, r.key, "v2"),
		"forged": bundle(t, other, "v3"), "lying": lying(t, r.key, "v3", "v2")}
	s := r.syncer(t.TempDir())
	r.step(s, Desired{"v1", "v1"}, false, "v1")
	r.step(s, Desired{"v1-resigned", "v1"}, true, "v1") // the same revision for another digest
	r.step(s, Desired{"v2", "v2"}, false, "v2")
	n := r.tsa.count()
	r.step(s, Desired{"forged", "v3"}, true, "v2")  // signed by another key: refused before import
	r.step(s, Desired{"v1", "v5"}, true, "v2")      // a bundle that is not the declared revision
	r.step(s, Desired{"missing", "v4"}, true, "v2") // registry failure
	if r.tsa.count() != n {
		t.Fatal("a refused bundle reached the TSA")
	}
	// Signed, data says v3, Rego answers v2: imported under its own key, never switched to.
	r.step(s, Desired{"lying", "v3"}, true, "v2")
	if r.tsa.answers("v3") != "v2" || r.tsa.count() != n+1 {
		t.Fatal("the lying candidate was not imported under its own key")
	}
	r.step(s, Desired{"v1", "v1"}, false, "v1") // rollback
	n = r.tsa.count()
	r.step(s, Desired{"v1", "v1"}, false, "v1") // already active: no import
	r.tsa.do(func() { r.tsa.fail = 1 })         // one unanswered probe: no import, still served
	s.Check(context.Background())
	r.step(s, Desired{"v1", "v1"}, false, "v1")
	if r.tsa.count() != n {
		t.Fatal("an active pair or a single failed probe caused an import")
	}
	if strings.Contains(string(JWKS(&r.key.PublicKey)), `"d"`) {
		t.Fatal("JWKS carries private material")
	}
}

func TestLedgerSurvivesASidecarRestart(t *testing.T) {
	r := newRig(t)
	r.store = map[string][]byte{"A": bundle(t, r.key, "R"), "B": edited(t, r.key, "R", func(s string) string { return s + "\n# other content\n" }),
		"lying": lying(t, r.key, "L", "R")}
	dir := t.TempDir()
	s := r.syncer(dir)
	r.step(s, Desired{"A", "R"}, false, "R")
	r.step(s, Desired{"lying", "L"}, true, "R")
	n := r.tsa.count()
	// The sidecar container restarts; the TSA keeps its policies and the ledger survives in dir.
	s = r.syncer(dir)
	s.Check(context.Background())
	if s.Active() != "R" {
		t.Fatal("the restarted sidecar does not serve the active revision")
	}
	r.step(s, Desired{"B", "R"}, true, "R")     // B at R: refused, R's key keeps A
	r.step(s, Desired{"lying", "L"}, true, "R") // still backed off after the restart
	if r.tsa.count() != n {
		t.Fatal("the restarted sidecar imported into a used key or retried a failed declaration")
	}
	// The ledger is lost too (a new state directory beside a running TSA): every key the TSA holds is
	// taken, and B at R is still refused.
	s = r.syncer(t.TempDir())
	r.step(s, Desired{"B", "R"}, true, "")
	if r.tsa.count() != n {
		t.Fatal("a key found in the TSA was given other content")
	}
}

func TestBackoffIsPerDeclaration(t *testing.T) {
	r := newRig(t)
	r.store = map[string][]byte{"ok": bundle(t, r.key, "v1"), "A": lying(t, r.key, "a", "x"), "B": lying(t, r.key, "b", "y")}
	s := r.syncer(t.TempDir())
	r.step(s, Desired{"ok", "v1"}, false, "v1")
	r.step(s, Desired{"A", "a"}, true, "v1")
	r.step(s, Desired{"B", "b"}, true, "v1")
	n := r.tsa.count()
	r.step(s, Desired{"A", "a"}, true, "v1")
	if r.tsa.count() != n {
		t.Fatal("A was imported again after B failed")
	}
}

func TestRetirementLocksOldRevisionsAndKeepsThemTaken(t *testing.T) {
	r := newRig(t)
	KeepInactive = 2
	revs := []string{"v1", "v2", "v3", "v4", "v5", "v6"}
	for _, v := range revs {
		r.store[v] = bundle(t, r.key, v)
	}
	r.store["v1-other"] = bundle(t, r.key, "v1")
	s := r.syncer(t.TempDir())
	for _, v := range revs {
		r.step(s, Desired{v, v}, false, v)
	}
	// Active v6, previous v5, kept v4 and v3; v1 and v2 locked.
	for v, want := range map[string]bool{"v1": false, "v2": false, "v3": true, "v4": true, "v5": true, "v6": true} {
		if (r.tsa.answers(v) != "") != want {
			t.Fatalf("%s evaluable: %v, want %v", v, !want, want)
		}
	}
	r.step(s, Desired{"v1-other", "v1"}, true, "v6") // a retired revision stays taken
	r.step(s, Desired{"v1", "v1"}, false, "v1")      // and can be rolled back to with its own bundle
}

func TestGateRefusesADecisionOfAnotherRevision(t *testing.T) {
	r := newRig(t)
	// Answers the probe as "split", real input as "v1".
	r.store["split"] = edited(t, r.key, "split", func(s string) string { return s + "\n# real-revision: v1\n" })
	r.store["v1"] = bundle(t, r.key, "v1")
	s := r.syncer(t.TempDir())
	ask := func() int {
		rec := httptest.NewRecorder()
		s.Gate().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"token":{"present":false}}`)))
		return rec.Code
	}
	if ask() != http.StatusServiceUnavailable {
		t.Fatal("forwarded with nothing active")
	}
	r.step(s, Desired{"v1", "v1"}, false, "v1")
	if ask() != http.StatusOK {
		t.Fatal("a matching decision was not forwarded")
	}
	r.step(s, Desired{"split", "split"}, false, "split")
	if ask() != http.StatusServiceUnavailable || !strings.Contains(r.logs.String(), "decision refused") {
		t.Fatal("a decision naming another revision was forwarded")
	}
}

func TestHealthRunsWithoutAReadableDeclaration(t *testing.T) {
	r := newRig(t)
	r.store["v1"] = bundle(t, r.key, "v1")
	s := r.syncer(t.TempDir())
	r.step(s, Desired{"v1", "v1"}, false, "v1")
	r.tsa.do(func() { r.tsa.policies = map[string]*fakePolicy{} }) // the TSA restarted empty
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx, 20*time.Millisecond, func() (Desired, error) { return Desired{}, errors.New("desired.json: invalid character") })
	for deadline := time.Now().Add(5 * time.Second); r.tsa.answers("v1") != "v1"; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the active revision was not restored while the declaration was unreadable")
		}
	}
	for deadline := time.Now().Add(2 * time.Second); s.Active() != "v1"; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("readiness did not come back")
		}
	}
}
