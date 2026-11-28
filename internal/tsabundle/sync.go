package tsabundle

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/cosignverify"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/ociclient"
)

// Desired is the bundle Git declares active: a digest reference and the revision it must carry.
type Desired struct {
	Bundle   string `json:"bundle"`
	Revision string `json:"revision"`
}

// Syncer keeps the TSA on the desired bundle.
//
// Each revision is imported under its own TSA key (Coordinates.At) and becomes active only when an
// evaluation under that key answers with that revision; activation is then the switch of the key the
// gate forwards evaluations to, an atomic step of its own. The TSA's replace-in-place is avoided on
// purpose: in v1.1.4 it drops its policy cache through a notification that is lost when the import
// request ends first, so a replaced policy can keep answering indefinitely. For the same reason a key
// is never given other content: the ledger, kept in Dir (an emptyDir that survives a restart of the
// sidecar container), records the reference every revision was imported as, for good.
type Syncer struct {
	TSA    string // TSA base URL, pod-local
	Policy Coordinates
	Key    *ecdsa.PublicKey
	// Fetch returns the outer bundle of a digest reference, after the registry-side checks.
	Fetch func(ctx context.Context, ref string) ([]byte, error)
	HTTP  *http.Client
	Log   *slog.Logger
	Dir   string // state: ledger.json and the bundles of the kept revisions

	mu     sync.Mutex
	l      ledger
	misses int
	active atomic.Value // string: the revision the gate forwards to, "" when none
}

type ledger struct {
	// Revisions holds every revision ever imported or found in the TSA, never deleted: a revision
	// names one reference for good ("unknown" for one found without a record).
	Revisions map[string]*entry `json:"revisions"`
	Active    string            `json:"active"`
	Previous  string            `json:"previous"`
	// Failed holds declarations ("<ref> <revision>") that failed after import, and when.
	Failed map[string]time.Time `json:"failed"`
}

type entry struct {
	Ref      string    `json:"ref"`
	Imported time.Time `json:"imported"`
	Locked   bool      `json:"locked"`
}

const (
	// lostAfter is how many consecutive unanswered probes count as a TSA that lost its policies (it
	// starts empty after a restart). A single slow evaluation is not.
	lostAfter = 3
	// unknownRef marks a revision found in the TSA without a ledger record.
	unknownRef = "unknown"
)

// ActivationWindow bounds the wait for an imported revision to answer.
var ActivationWindow = 30 * time.Second

// RetryFailedAfter is how long a declaration that failed after import is left alone.
var RetryFailedAfter = 5 * time.Minute

// KeepInactive is how many inactive revisions, beyond the active and the previous one, stay
// evaluable in the TSA. Older ones are locked there (the TSA has no delete; its memory is freed when
// it restarts, after which only the active revision is imported again) and stay in the ledger.
var KeepInactive = 2

// Active is the revision evaluations are forwarded to, "" when none.
func (s *Syncer) Active() string { v, _ := s.active.Load().(string); return v }

// Open loads the ledger from Dir. Without one (a new pod, or a lost state directory) it records every
// revision the TSA already holds as unknown, so none of them can be given other content.
func (s *Syncer) Open(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.l = ledger{Revisions: map[string]*entry{}, Failed: map[string]time.Time{}}
	raw, err := os.ReadFile(filepath.Join(s.Dir, "ledger.json"))
	if err == nil {
		if err := json.Unmarshal(raw, &s.l); err != nil {
			return fmt.Errorf("ledger unreadable: %w", err)
		}
		if s.l.Revisions == nil {
			s.l.Revisions = map[string]*entry{}
		}
		if s.l.Failed == nil {
			s.l.Failed = map[string]time.Time{}
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	held, err := s.held(ctx)
	if err != nil {
		return fmt.Errorf("tsa policies unreadable: %w", err)
	}
	for _, v := range held {
		s.l.Revisions[v] = &entry{Ref: unknownRef}
	}
	return s.save()
}

// held lists the versions of the policy the TSA holds.
func (s *Syncer) held(ctx context.Context) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, s.TSA+"/v1/policies?policyName="+s.Policy.Name, nil)
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		Policies []Coordinates `json:"policies"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out) != nil {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var versions []string
	for _, p := range out.Policies {
		if p.At(p.Version) == s.Policy.At(p.Version) {
			versions = append(versions, p.Version)
		}
	}
	return versions, nil
}

func (s *Syncer) save() error {
	raw, _ := json.Marshal(s.l)
	tmp := filepath.Join(s.Dir, "ledger.json.tmp")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(s.Dir, "ledger.json"))
}

func (s *Syncer) bundleFile(revision string) string {
	return filepath.Join(s.Dir, "bundle-"+revision+".zip")
}

// Probe evaluates an empty input under revision's key: the policy denies it, naming the revision it
// evaluated with. ok is false when the TSA gave no decision.
func (s *Syncer) Probe(ctx context.Context, revision string) (answered string, ok bool) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	d, err := Evaluate(ctx, s.HTTP, s.TSA+s.Policy.At(revision).EvaluationPath(), []byte("{}"))
	if err != nil {
		return "", false
	}
	return d.BundleRevision, true
}

func (s *Syncer) post(ctx context.Context, path, contentType string, body []byte) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, s.TSA+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return err
	}
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%d %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

// load imports a verified bundle under its revision's key and waits until that key answers with
// the revision.
func (s *Syncer) load(ctx context.Context, outer []byte, revision string) error {
	if err := s.post(ctx, "/v1/policy/import", "application/zip", outer); err != nil {
		return fmt.Errorf("tsa import: %w", err)
	}
	got := ""
	for deadline := time.Now().Add(ActivationWindow); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		var ok bool
		if got, ok = s.Probe(ctx, revision); ok {
			break
		}
	}
	if got != revision {
		return fmt.Errorf("imported bundle evaluates as revision %q, not %q", got, revision)
	}
	return nil
}

// Check is the health of the active revision, independent of any declaration: it must still answer
// under its key; a TSA that lost it (restarted empty) gets it again from Dir. Readiness follows.
func (s *Syncer) Check(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rev := s.l.Active
	if rev == "" {
		s.active.Store("")
		return
	}
	got, ok := s.Probe(ctx, rev)
	switch {
	case ok && got == rev:
		s.misses = 0
		s.active.Store(rev)
		return
	case !ok:
		if s.misses++; s.misses < lostAfter {
			return
		}
	}
	s.misses = 0
	s.active.Store("")
	outer, err := os.ReadFile(s.bundleFile(rev))
	if err == nil {
		err = s.load(ctx, outer, rev)
	}
	if err != nil {
		s.Log.Error("active bundle not restored", "revision", rev, "reason", err.Error())
		return
	}
	s.active.Store(rev)
	s.Log.Info("active bundle restored", "bundle", s.l.Revisions[rev].Ref, "revision", rev)
}

// Reconcile makes the declared reference and revision the active pair. The fetch and verification
// run outside the lock, so health checks continue meanwhile.
func (s *Syncer) Reconcile(ctx context.Context, d Desired) error {
	refuse := func(err error) error {
		s.Log.Error("bundle refused", "bundle", d.Bundle, "revision", d.Revision, "active_revision", s.Active(), "reason", err.Error())
		return err
	}
	if err := s.admissible(d); err != nil {
		if errors.Is(err, errActive) {
			return nil
		}
		return refuse(err)
	}
	outer, err := s.Fetch(ctx, d.Bundle)
	if err != nil {
		return refuse(err)
	}
	if err := Open(outer, Expect{Key: s.Key, Coordinates: s.Policy, Revision: d.Revision}); err != nil {
		return refuse(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.admissibleLocked(d); err != nil {
		return refuse(err)
	}
	s.l.Revisions[d.Revision] = &entry{Ref: d.Bundle, Imported: time.Now().UTC()}
	if err := os.WriteFile(s.bundleFile(d.Revision), outer, 0o600); err != nil {
		return refuse(err)
	}
	if err := s.save(); err != nil {
		return refuse(err)
	}
	if err := s.load(ctx, outer, d.Revision); err != nil {
		s.l.Failed[d.Bundle+" "+d.Revision] = time.Now().UTC()
		_ = os.Remove(s.bundleFile(d.Revision))
		_ = s.save()
		return refuse(err)
	}
	previous := s.l.Active
	if previous != d.Revision {
		s.l.Previous = previous
	}
	s.l.Active = d.Revision
	s.misses = 0
	s.active.Store(d.Revision)
	s.retire(ctx)
	_ = s.save()
	s.Log.Info("bundle activated", "bundle", d.Bundle, "revision", d.Revision, "previous_revision", previous)
	return nil
}

var errActive = errors.New("already active")

func (s *Syncer) admissible(d Desired) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.admissibleLocked(d)
}

func (s *Syncer) admissibleLocked(d Desired) error {
	if d.Bundle == "" || d.Revision == "" {
		return errors.New("desired bundle and revision are required")
	}
	if e := s.l.Revisions[d.Revision]; e != nil {
		if e.Ref != d.Bundle {
			return fmt.Errorf("revision %s is recorded as %s; a revision is never given another bundle", d.Revision, e.Ref)
		}
		if d.Revision == s.l.Active && s.Active() == d.Revision {
			return errActive
		}
	}
	if at, ok := s.l.Failed[d.Bundle+" "+d.Revision]; ok && time.Since(at) < RetryFailedAfter {
		return fmt.Errorf("failed after import at %s; not retried before %s", at.Format(time.RFC3339), at.Add(RetryFailedAfter).Format(time.RFC3339))
	}
	return nil
}

// retire locks every revision beyond the active, the previous and the KeepInactive most recent
// others, and drops its kept bundle; the ledger keeps it, so its revision stays taken.
func (s *Syncer) retire(ctx context.Context) {
	var others []string
	for rev, e := range s.l.Revisions {
		if rev != s.l.Active && rev != s.l.Previous && !e.Locked {
			others = append(others, rev)
		}
	}
	sort.Slice(others, func(i, j int) bool { return s.l.Revisions[others[i]].Imported.After(s.l.Revisions[others[j]].Imported) })
	for i, rev := range others {
		if i < KeepInactive && s.l.Revisions[rev].Ref != unknownRef {
			continue
		}
		if err := s.post(ctx, strings.TrimSuffix(s.Policy.At(rev).EvaluationPath(), "/evaluation")+"/lock", "application/json", nil); err != nil {
			s.Log.Error("revision not retired", "revision", rev, "reason", err.Error())
			continue
		}
		s.l.Revisions[rev].Locked = true
		_ = os.Remove(s.bundleFile(rev))
		s.Log.Info("revision retired", "revision", rev)
	}
}

// Run keeps the active revision healthy and follows the declaration, independently: a declaration
// that cannot be read, or a slow fetch, never stops the health checks.
func (s *Syncer) Run(ctx context.Context, poll time.Duration, desired func() (Desired, error)) {
	go func() {
		for {
			s.Check(ctx)
			select {
			case <-ctx.Done():
				return
			case <-time.After(poll):
			}
		}
	}()
	for {
		if d, err := desired(); err != nil {
			s.Log.Error("desired bundle unreadable", "reason", err.Error(), "active_revision", s.Active())
		} else {
			_ = s.Reconcile(ctx, d)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(poll):
		}
	}
}

// Gate forwards an evaluation to the active revision's key and passes the answer on only if its
// decision names that revision: a policy that answers the probe correctly but real input under
// another revision is refused, never forwarded.
func (s *Syncer) Gate() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rev := s.Active()
		if rev == "" {
			http.Error(w, "no verified policy bundle is active", http.StatusServiceUnavailable)
			return
		}
		input, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
		if err != nil {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		raw, err := EvaluateRaw(r.Context(), s.HTTP, s.TSA+s.Policy.At(rev).EvaluationPath(), input)
		var d Decision
		if err == nil && (json.Unmarshal(raw, &d) != nil || d.BundleRevision != rev) {
			s.Log.Error("decision refused", "active_revision", rev, "answered_revision", d.BundleRevision)
			err = errors.New("decision names another revision")
		}
		if err != nil {
			http.Error(w, "policy evaluation unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(append(append([]byte(`{"decision":`), raw...), '}'))
	})
}

// Decision is the part of an IF-05 decision the probe reads.
type Decision struct {
	BundleRevision string `json:"bundle_revision"`
}

// EvaluateRaw posts input to a TSA evaluation URL and returns the policy's "decision" member, raw.
func EvaluateRaw(ctx context.Context, client *http.Client, url string, input []byte) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(input))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("tsa unavailable")
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10+1))
	if err != nil || len(raw) > 64<<10 {
		return nil, errors.New("tsa response unreadable")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tsa status %d", resp.StatusCode)
	}
	var result struct {
		Decision json.RawMessage `json:"decision"`
	}
	if json.Unmarshal(raw, &result) != nil || len(result.Decision) == 0 {
		return nil, errors.New("tsa result has no decision")
	}
	return result.Decision, nil
}

// Evaluate is EvaluateRaw decoded into the revision the probe needs.
func Evaluate(ctx context.Context, client *http.Client, url string, input []byte) (Decision, error) {
	raw, err := EvaluateRaw(ctx, client, url, input)
	if err != nil {
		return Decision{}, err
	}
	var d Decision
	err = json.Unmarshal(raw, &d)
	return d, err
}

// RegistryFetch verifies a bundle's cosign signature by the trust root and returns its single layer.
func RegistryFetch(client *ociclient.Client, key *ecdsa.PublicKey, repository string) func(context.Context, string) ([]byte, error) {
	return func(ctx context.Context, image string) ([]byte, error) {
		ref, ok := cosignverify.ParseRef(image)
		if !ok {
			return nil, errors.New("bundle must be referenced as host/repository@sha256:<digest>")
		}
		name := ref.Registry + "/" + ref.Repository
		if name != repository && !strings.HasPrefix(name, strings.TrimSuffix(repository, "/")+"/") {
			return nil, errors.New("bundle repository is not the configured one")
		}
		if r := cosignverify.VerifySignature(ctx, client, ref, []*ecdsa.PublicKey{key}); !r.OK() {
			return nil, fmt.Errorf("%s: %s", r.Code, r.Detail)
		}
		m, err := client.ManifestByDigest(ctx, ref.Registry, ref.Repository, ref.Digest)
		if err != nil {
			return nil, err
		}
		var im ociclient.ImageManifest
		if json.Unmarshal(m.Body, &im) != nil || len(im.Layers) != 1 || im.Layers[0].MediaType != MediaType || im.Layers[0].Size > maxBundle {
			return nil, errors.New("artefact is not a single TSA bundle layer")
		}
		return client.Blob(ctx, ref.Registry, ref.Repository, im.Layers[0].Digest)
	}
}
