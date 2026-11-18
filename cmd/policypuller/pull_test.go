package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/ociclient"
)

// registry serves manifests by tag or digest and blobs by digest, as the verifier's tests do.
type registry struct {
	mu        sync.Mutex
	manifests map[string][]byte
	blobs     map[string][]byte
	down      atomic.Bool
}

func newRegistry(t *testing.T) (*registry, string) {
	t.Helper()
	reg := &registry{manifests: map[string][]byte{}, blobs: map[string][]byte{}}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if reg.down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		reg.mu.Lock()
		defer reg.mu.Unlock()
		parts := strings.Split(r.URL.Path, "/")
		ref := parts[len(parts)-1]
		var body []byte
		switch parts[len(parts)-2] {
		case "manifests":
			body = reg.manifests[ref]
			w.Header().Set("Content-Type", ociclient.MediaTypeOCIManifest)
		case "blobs":
			body = reg.blobs[ref]
		}
		if body == nil {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(ts.Close)
	return reg, strings.TrimPrefix(ts.URL, "http://")
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (r *registry) put(ref string, m map[string]any) string {
	b, _ := json.Marshal(m)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.manifests[ref] = b
	r.manifests[digestOf(b)] = b
	return digestOf(b)
}

func (r *registry) blob(b []byte) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.blobs[digestOf(b)] = b
	return digestOf(b)
}

// retag points the tag at a manifest already stored by digest, as `oras tag` does.
func (r *registry) retag(tag, digest string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.manifests[tag] = r.manifests[digest]
}

func (r *registry) untag(tag string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.manifests, tag)
}

// apiServer is the API server as the puller sees it: one Application, merge-patched in place, and
// the Events created on it.
type apiServer struct {
	mu      sync.Mutex
	app     map[string]any
	patches int
	events  []map[string]any
}

func newAPIServer(t *testing.T, annotations map[string]any, digest string) (*apiServer, *kubeClient) {
	t.Helper()
	api := &apiServer{app: map[string]any{
		"metadata": map[string]any{"name": "ztd-admission", "namespace": "argocd", "uid": "u1", "annotations": annotations},
		"spec": map[string]any{"source": map[string]any{"helm": map[string]any{"valuesObject": map[string]any{
			"git": map[string]any{"repoURL": "https://example.test/repo.git"}, "package": map[string]any{"digest": digest},
		}}}},
	}}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		api.mu.Lock()
		defer api.mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		switch {
		case r.URL.Path == applicationPath("argocd", "ztd-admission") && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(api.app)
		case r.URL.Path == applicationPath("argocd", "ztd-admission") && r.Method == http.MethodPatch:
			if r.Header.Get("Content-Type") != "application/merge-patch+json" {
				http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
				return
			}
			var patch map[string]any
			if err := json.Unmarshal(body, &patch); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			api.patches++
			api.app = merge(api.app, patch).(map[string]any)
			_ = json.NewEncoder(w).Encode(api.app)
		case r.URL.Path == "/api/v1/namespaces/argocd/events" && r.Method == http.MethodPost:
			var ev map[string]any
			_ = json.Unmarshal(body, &ev)
			api.events = append(api.events, ev)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write(body)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.Close)
	return api, &kubeClient{base: ts.URL, token: "token", http: ts.Client()}
}

// merge applies a JSON merge patch (RFC 7386).
func merge(target, patch any) any {
	p, ok := patch.(map[string]any)
	if !ok {
		return patch
	}
	t, ok := target.(map[string]any)
	if !ok || t == nil {
		t = map[string]any{}
	}
	for k, v := range p {
		if v == nil {
			delete(t, k)
			continue
		}
		t[k] = merge(t[k], v)
	}
	return t
}

func (a *apiServer) annotation(key string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	v, _ := a.app["metadata"].(map[string]any)["annotations"].(map[string]any)[key].(string)
	return v
}

func (a *apiServer) digest() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	src := a.app["spec"].(map[string]any)["source"].(map[string]any)
	v, _ := src["helm"].(map[string]any)["valuesObject"].(map[string]any)["package"].(map[string]any)["digest"].(string)
	return v
}

func (a *apiServer) eventReasons() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for _, ev := range a.events {
		out = append(out, ev["type"].(string)+"/"+ev["reason"].(string))
	}
	return out
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// fixture is a registry with a package publisher and a signer, and an Application to write to.
type fixture struct {
	t    *testing.T
	reg  *registry
	host string
	key  *ecdsa.PrivateKey
	api  *apiServer
	kube *kubeClient
}

const repo = "facis/policy/admission"

func newFixture(t *testing.T, annotations map[string]any, digest string) *fixture {
	t.Helper()
	reg, host := newRegistry(t)
	api, kube := newAPIServer(t, annotations, digest)
	return &fixture{t: t, reg: reg, host: host, key: newKey(t), api: api, kube: kube}
}

// publish pushes a policy package at the tag with these annotations and returns its digest.
func (f *fixture) publish(tag string, artifactType string, annotations map[string]string) string {
	content := f.reg.blob([]byte("catalogue " + annotations["org.opencontainers.image.version"] + annotations[createdAnnotation]))
	m := map[string]any{"schemaVersion": 2, "mediaType": ociclient.MediaTypeOCIManifest, "artifactType": artifactType,
		"config": map[string]any{"mediaType": "application/vnd.oci.empty.v1+json", "digest": f.reg.blob([]byte("{}")), "size": 2},
		"layers": []map[string]any{{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": content, "size": 9}},
	}
	if annotations != nil {
		m["annotations"] = annotations
	}
	return f.reg.put(tag, m)
}

func policy(created string) map[string]string {
	return map[string]string{createdAnnotation: created, "org.opencontainers.image.version": "0.0.0-test"}
}

// sign pushes a cosign signature of the digest by k, at the ".sig" tag.
func (f *fixture) sign(k *ecdsa.PrivateKey, digest string) {
	payload := []byte(`{"critical":{"identity":{"docker-reference":"` + f.host + "/" + repo + `"},"image":{"docker-manifest-digest":"` + digest + `"},"type":"cosign container image signature"},"optional":null}`)
	sum := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, k, sum[:])
	if err != nil {
		f.t.Fatal(err)
	}
	f.reg.put(strings.Replace(digest, ":", "-", 1)+".sig", map[string]any{"schemaVersion": 2, "mediaType": ociclient.MediaTypeOCIManifest,
		"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": f.reg.blob([]byte("{}")), "size": 2},
		"layers": []map[string]any{{"mediaType": "application/vnd.dev.cosign.simplesigning.v1+json", "digest": f.reg.blob(payload), "size": len(payload),
			"annotations": map[string]string{"dev.cosignproject.cosign/signature": base64.StdEncoding.EncodeToString(sig)}}},
	})
}

func (f *fixture) puller() *Puller {
	return &Puller{Registry: f.host, Repository: repo, Tag: "main", Keys: []*ecdsa.PublicKey{&f.key.PublicKey},
		Namespace: "argocd", Application: "ztd-admission",
		Client: ociclient.New(ociclient.Options{PlainHTTP: []string{f.host}}), Kube: f.kube,
		Now: func() time.Time { return time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC) }}
}

func (f *fixture) pull() (Outcome, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return f.puller().Pull(ctx)
}

func wantRefusal(t *testing.T, err error, reason string) {
	t.Helper()
	var r *Refusal
	if !errors.As(err, &r) || r.Reason != reason {
		t.Fatalf("got %v, want a refusal %q", err, reason)
	}
}

func TestAppliesAVerifiedPackage(t *testing.T) {
	f := newFixture(t, nil, "")
	d := f.publish("main", ArtifactType, policy("2026-10-20T10:00:00+01:00"))
	f.sign(f.key, d)
	out, err := f.pull()
	if err != nil || !out.Changed || out.Digest != d {
		t.Fatalf("got %+v, %v", out, err)
	}
	if f.api.digest() != d {
		t.Fatalf("Application digest %q, want %q", f.api.digest(), d)
	}
	if f.api.annotation(AnnotationDigest) != d || f.api.annotation(AnnotationCreated) != "2026-10-20T10:00:00+01:00" ||
		f.api.annotation(AnnotationVerified) != "2026-10-28T12:00:00Z" {
		t.Fatalf("annotations: %v", f.api.app["metadata"])
	}
	if got := f.api.eventReasons(); len(got) != 1 || got[0] != "Normal/"+ReasonApplied {
		t.Fatalf("events %v", got)
	}
}

func TestAPackageAlreadyFollowedIsNotWrittenAgain(t *testing.T) {
	f := newFixture(t, nil, "")
	d := f.publish("main", ArtifactType, policy("2026-10-20T10:00:00Z"))
	f.sign(f.key, d)
	if _, err := f.pull(); err != nil {
		t.Fatal(err)
	}
	out, err := f.pull()
	if err != nil || out.Changed {
		t.Fatalf("second pull: %+v, %v", out, err)
	}
	if f.api.patches != 1 {
		t.Fatalf("%d patches, want 1", f.api.patches)
	}
}

func TestRefusesASignatureByAnotherKey(t *testing.T) {
	f := newFixture(t, map[string]any{AnnotationDigest: "sha256:old"}, "sha256:old")
	d := f.publish("main", ArtifactType, policy("2026-10-20T10:00:00Z"))
	f.sign(newKey(t), d)
	_, err := f.pull()
	wantRefusal(t, err, "unsigned")
	if f.api.digest() != "sha256:old" {
		t.Fatalf("digest changed to %q", f.api.digest())
	}
	if got := f.api.eventReasons(); len(got) != 1 || got[0] != "Warning/"+ReasonRefused {
		t.Fatalf("events %v", got)
	}
	if !strings.Contains(f.api.annotation(AnnotationRefused), "unsigned") {
		t.Fatalf("refused annotation %q", f.api.annotation(AnnotationRefused))
	}
}

func TestRefusesAnUnsignedPackage(t *testing.T) {
	f := newFixture(t, nil, "")
	f.publish("main", ArtifactType, policy("2026-10-20T10:00:00Z"))
	_, err := f.pull()
	wantRefusal(t, err, "unsigned")
	if f.api.digest() != "" {
		t.Fatalf("digest written: %q", f.api.digest())
	}
}

func TestRefusesAnOlderPackageThanTheOneFollowed(t *testing.T) {
	f := newFixture(t, map[string]any{AnnotationDigest: "sha256:new", AnnotationCreated: "2026-10-25T00:00:00Z"}, "sha256:new")
	d := f.publish("main", ArtifactType, policy("2026-10-20T10:00:00Z"))
	f.sign(f.key, d)
	_, err := f.pull()
	wantRefusal(t, err, "rollback")
	if f.api.digest() != "sha256:new" {
		t.Fatalf("digest changed to %q", f.api.digest())
	}
}

func TestAppliesANewerPackage(t *testing.T) {
	f := newFixture(t, map[string]any{AnnotationDigest: "sha256:old", AnnotationCreated: "2026-10-20T10:00:00Z"}, "sha256:old")
	d := f.publish("main", ArtifactType, policy("2026-10-25T00:00:00Z"))
	f.sign(f.key, d)
	out, err := f.pull()
	if err != nil || !out.Changed || f.api.digest() != d {
		t.Fatalf("got %+v, %v, digest %q", out, err, f.api.digest())
	}
}

func TestAppliesAPackageOfTheSameTime(t *testing.T) {
	// The same commit published again under another version is another digest with the same created.
	f := newFixture(t, map[string]any{AnnotationDigest: "sha256:old", AnnotationCreated: "2026-10-20T10:00:00Z"}, "sha256:old")
	d := f.publish("main", ArtifactType, policy("2026-10-20T11:00:00+01:00"))
	f.sign(f.key, d)
	if out, err := f.pull(); err != nil || !out.Changed {
		t.Fatalf("got %+v, %v", out, err)
	}
}

func TestRefusesAPackageWithoutACreatedTime(t *testing.T) {
	f := newFixture(t, nil, "")
	d := f.publish("main", ArtifactType, map[string]string{"org.opencontainers.image.version": "0.0.0-test"})
	f.sign(f.key, d)
	_, err := f.pull()
	wantRefusal(t, err, "unordered")
}

func TestRefusesWhatIsNotAPolicyPackage(t *testing.T) {
	f := newFixture(t, nil, "")
	d := f.publish("main", "application/vnd.cncf.helm.chart.v1", policy("2026-10-20T10:00:00Z"))
	f.sign(f.key, d)
	_, err := f.pull()
	wantRefusal(t, err, "not-a-policy-package")

	f.reg.put("main", map[string]any{"schemaVersion": 2, "mediaType": ociclient.MediaTypeOCIIndex, "manifests": []any{}})
	_, err = f.pull()
	wantRefusal(t, err, "not-a-policy-package")
}

func TestRefusesWhenNothingIsAtTheTag(t *testing.T) {
	f := newFixture(t, nil, "")
	_, err := f.pull()
	wantRefusal(t, err, "no-package")
}

func TestARegistryThatCannotBeReachedChangesNothing(t *testing.T) {
	f := newFixture(t, map[string]any{AnnotationDigest: "sha256:old"}, "sha256:old")
	f.reg.down.Store(true)
	_, err := f.pull()
	var u *Unavailable
	if !errors.As(err, &u) {
		t.Fatalf("got %v, want unavailable", err)
	}
	if f.api.digest() != "sha256:old" {
		t.Fatalf("digest changed to %q", f.api.digest())
	}
	if got := f.api.eventReasons(); len(got) != 1 || got[0] != "Warning/"+ReasonUnavailable {
		t.Fatalf("events %v", got)
	}

	// The signature lookup failing is the same: unreachable is not unsigned.
	f.reg.down.Store(false)
	d := f.publish("main", ArtifactType, policy("2026-10-20T10:00:00Z"))
	f.sign(f.key, d)
	f.reg.untag(strings.Replace(d, ":", "-", 1) + ".sig")
	_, err = f.pull()
	wantRefusal(t, err, "unsigned")
}

func TestASuccessClearsTheRefusalAndARepeatedRefusalIsWrittenOnce(t *testing.T) {
	f := newFixture(t, nil, "")
	d := f.publish("main", ArtifactType, policy("2026-10-20T10:00:00Z"))
	f.sign(newKey(t), d)
	for range 2 {
		_, err := f.pull()
		wantRefusal(t, err, "unsigned")
	}
	if f.api.patches != 1 {
		t.Fatalf("%d patches for a repeated refusal, want 1", f.api.patches)
	}
	f.sign(f.key, d)
	if _, err := f.pull(); err != nil {
		t.Fatal(err)
	}
	if f.api.annotation(AnnotationRefused) != "" {
		t.Fatalf("refused annotation still %q", f.api.annotation(AnnotationRefused))
	}
}

func TestATagMovedAwayAndBackClearsTheRefusal(t *testing.T) {
	f := newFixture(t, nil, "")
	d := f.publish("main", ArtifactType, policy("2026-10-20T10:00:00Z"))
	f.sign(f.key, d)
	if _, err := f.pull(); err != nil {
		t.Fatal(err)
	}
	// The tag moved to a package nobody trusted signed, then back to the one followed.
	other := f.publish("main", ArtifactType, policy("2026-10-21T10:00:00Z"))
	f.sign(newKey(t), other)
	_, err := f.pull()
	wantRefusal(t, err, "unsigned")
	if f.api.annotation(AnnotationRefused) == "" {
		t.Fatal("no refusal recorded")
	}
	f.reg.retag("main", d)
	out, err := f.pull()
	if err != nil || out.Changed || out.Digest != d {
		t.Fatalf("got %+v, %v", out, err)
	}
	if f.api.annotation(AnnotationRefused) != "" {
		t.Fatalf("refused annotation still %q after the tag came back to the followed digest", f.api.annotation(AnnotationRefused))
	}
	if f.api.digest() != d || f.api.annotation(AnnotationDigest) != d {
		t.Fatalf("the Application moved from %s: %v", d, f.api.app)
	}
}
