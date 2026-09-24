package cosignverify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/ociclient"
)

// registry is an in-memory OCI registry for one repository.
type registry struct {
	mu        sync.Mutex
	manifests map[string][]byte // tag or digest -> body
	blobs     map[string][]byte
	requests  atomic.Int64
	down      atomic.Bool
	delay     atomic.Int64 // per request, nanoseconds
}

func newRegistry(t *testing.T) (*registry, string) {
	t.Helper()
	reg := &registry{manifests: map[string][]byte{}, blobs: map[string][]byte{}}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reg.requests.Add(1)
		time.Sleep(time.Duration(reg.delay.Load()))
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

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (r *registry) blob(b []byte) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	d := digest(b)
	r.blobs[d] = b
	return d
}

func (r *registry) manifest(ref string, m any) string {
	b, _ := json.Marshal(m)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.manifests[ref] = b
	r.manifests[digest(b)] = b
	return digest(b)
}

type layer struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int               `json:"size"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

func imageManifest(layers ...layer) map[string]any {
	return map[string]any{"schemaVersion": 2, "mediaType": ociclient.MediaTypeOCIManifest,
		"config": layer{MediaType: "application/vnd.oci.image.config.v1+json", Digest: digest([]byte("{}")), Size: 2},
		"layers": layers}
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func sign(t *testing.T, k *ecdsa.PrivateKey, message []byte) string {
	sum := sha256.Sum256(message)
	sig, err := ecdsa.SignASN1(rand.Reader, k, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

// fixture pushes an image and, by default, a valid signature and both attestations.
type fixture struct {
	t      *testing.T
	reg    *registry
	host   string
	key    *ecdsa.PrivateKey
	repo   string
	digest string
	sigs   []layer
	atts   []layer
}

func newFixture(t *testing.T) *fixture {
	reg, host := newRegistry(t)
	f := &fixture{t: t, reg: reg, host: host, key: newKey(t), repo: "team/app"}
	f.platform(`{"architecture":"amd64","os":"linux"}`)
	return f
}

// platform (re)pushes the image with this configuration; call it before signing.
func (f *fixture) platform(config string) {
	f.digest = f.reg.manifest("v1", map[string]any{"schemaVersion": 2, "mediaType": ociclient.MediaTypeOCIManifest,
		"config": layer{MediaType: "application/vnd.oci.image.config.v1+json", Digest: f.reg.blob([]byte(config)), Size: len(config)},
		"layers": []layer{{MediaType: "application/vnd.oci.image.layer.v1.tar", Digest: f.reg.blob([]byte("rootfs")), Size: 6}}})
}

// sbom is a valid CycloneDX SBOM of this image, as Syft writes it for an image scanned by digest.
func (f *fixture) sbom() string {
	return fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"component":{"type":"container","name":%q,"version":%q}},"components":[{"type":"library","name":"musl","version":"1.2.5"}]}`,
		f.host+"/"+f.repo, f.digest)
}

// mock is a valid mock-attestation predicate (the sw sample).
func (f *fixture) mock() string {
	b, err := os.ReadFile("../../docs/attestation/samples/sw.mock.json")
	if err != nil {
		f.t.Fatal(err)
	}
	return string(b)
}

func (f *fixture) image() string { return f.host + "/" + f.repo + "@" + f.digest }

func (f *fixture) signaturePayload(digest, reference string) []byte {
	return []byte(fmt.Sprintf(`{"critical":{"identity":{"docker-reference":%q},"image":{"docker-manifest-digest":%q},"type":"cosign container image signature"},"optional":null}`, reference, digest))
}

func (f *fixture) addSignature(k *ecdsa.PrivateKey, payload []byte) {
	f.sigs = append(f.sigs, layer{MediaType: simpleSigningType, Digest: f.reg.blob(payload), Size: len(payload),
		Annotations: map[string]string{signatureAnnot: sign(f.t, k, payload)}})
}

func (f *fixture) statement(predicateType, subjectDigest, typ string, predicate string) []byte {
	return []byte(fmt.Sprintf(`{"_type":%q,"predicateType":%q,"subject":[{"name":%q,"digest":{"sha256":%q}}],"predicate":%s}`,
		typ, predicateType, f.host+"/"+f.repo, strings.TrimPrefix(subjectDigest, "sha256:"), predicate))
}

func (f *fixture) addAttestation(k *ecdsa.PrivateKey, predicateType string, stmt []byte) {
	env := map[string]any{"payloadType": inTotoPayloadType, "payload": base64.StdEncoding.EncodeToString(stmt),
		"signatures": []map[string]string{{"keyid": "", "sig": sign(f.t, k, pae(inTotoPayloadType, stmt))}}}
	f.addEnvelope(predicateType, env)
}

func (f *fixture) addEnvelope(predicateType string, env map[string]any) {
	b, _ := json.Marshal(env)
	f.atts = append(f.atts, layer{MediaType: dsseEnvelopeType, Digest: f.reg.blob(b), Size: len(b),
		Annotations: map[string]string{"predicateType": predicateType}})
}

func (f *fixture) valid() *fixture {
	f.addSignature(f.key, f.signaturePayload(f.digest, f.host+"/"+f.repo))
	f.addAttestation(f.key, PredicateSBOM, f.statement(PredicateSBOM, f.digest, statementType, f.sbom()))
	f.addAttestation(f.key, PredicateMock, f.statement(PredicateMock, f.digest, statementType, f.mock()))
	return f
}

func (f *fixture) publish() {
	tag := strings.Replace(f.digest, ":", "-", 1)
	if f.sigs != nil {
		f.reg.manifest(tag+".sig", imageManifest(f.sigs...))
	}
	if f.atts != nil {
		f.reg.manifest(tag+".att", imageManifest(f.atts...))
	}
}

func (f *fixture) verifier(keys ...*ecdsa.PublicKey) *Verifier {
	if keys == nil {
		keys = []*ecdsa.PublicKey{&f.key.PublicKey}
	}
	f.publish()
	client := ociclient.New(ociclient.Options{PlainHTTP: []string{f.host}})
	return New(client, &Policy{Repositories: []string{f.host + "/team"}, Keys: keys, Revision: "r1"}, 4)
}

func TestValidImage(t *testing.T) {
	f := newFixture(t).valid()
	r := f.verifier().VerifyImage(context.Background(), f.image())
	if !r.OK() {
		t.Fatalf("valid image refused: %+v", r)
	}
	if string(r.Predicates[PredicateSBOM]) != f.sbom() || !json.Valid(r.Predicates[PredicateMock]) {
		t.Errorf("predicates = %s", r.Predicates)
	}
}

func TestRefusals(t *testing.T) {
	other := "sha256:" + strings.Repeat("ab", 32)
	cases := []struct {
		name  string
		setup func(f *fixture)
		keys  func(f *fixture) []*ecdsa.PublicKey
		want  string
	}{
		{"unsigned", func(f *fixture) {
			f.addAttestation(f.key, PredicateSBOM, f.statement(PredicateSBOM, f.digest, statementType, `{}`))
			f.addAttestation(f.key, PredicateMock, f.statement(PredicateMock, f.digest, statementType, `{}`))
		}, nil, CodeUnsigned},
		{"signed by another key", func(f *fixture) { f.valid() },
			func(f *fixture) []*ecdsa.PublicKey { return []*ecdsa.PublicKey{&newKey(f.t).PublicKey} }, CodeUnsigned},
		{"signature for another digest", func(f *fixture) {
			f.addSignature(f.key, f.signaturePayload(other, f.host+"/"+f.repo))
		}, nil, CodeUnsigned},
		{"signature for another repository", func(f *fixture) {
			f.addSignature(f.key, f.signaturePayload(f.digest, f.host+"/team/other"))
		}, nil, CodeUnsigned},
		{"tampered signature payload", func(f *fixture) {
			f.valid()
			payload := f.signaturePayload(f.digest, f.host+"/"+f.repo)
			f.sigs[0].Annotations[signatureAnnot] = sign(f.t, f.key, append(payload, ' '))
		}, nil, CodeUnsigned},
		{"SBOM attestation missing", func(f *fixture) {
			f.addSignature(f.key, f.signaturePayload(f.digest, f.host+"/"+f.repo))
			f.addAttestation(f.key, PredicateMock, f.statement(PredicateMock, f.digest, statementType, f.mock()))
		}, nil, CodeSBOMMissing},
		{"mock attestation missing", func(f *fixture) {
			f.addSignature(f.key, f.signaturePayload(f.digest, f.host+"/"+f.repo))
			f.addAttestation(f.key, PredicateSBOM, f.statement(PredicateSBOM, f.digest, statementType, f.sbom()))
		}, nil, CodeNoAttestation},
		{"SBOM with one invalid component", func(f *fixture) {
			f.withSBOM(strings.Replace(f.sbom(), `"type":"library"`, `"type":"not-a-type"`, 1))
		}, nil, CodeSBOMInvalid},
		{"SBOM of an unaccepted CycloneDX version", func(f *fixture) {
			f.withSBOM(strings.Replace(f.sbom(), `"specVersion":"1.6"`, `"specVersion":"1.4"`, 1))
		}, nil, CodeSBOMInvalid},
		{"SBOM naming another image", func(f *fixture) {
			f.withSBOM(strings.Replace(f.sbom(), f.digest, other, 1))
		}, nil, CodeSBOMInvalid},
		{"SBOM of a non-container component", func(f *fixture) {
			f.withSBOM(strings.Replace(f.sbom(), `"type":"container"`, `"type":"application"`, 1))
		}, nil, CodeSBOMInvalid},
		{"SBOM without components", func(f *fixture) {
			f.withSBOM(strings.Replace(f.sbom(), `,"components":[{"type":"library","name":"musl","version":"1.2.5"}]`, "", 1))
		}, nil, CodeSBOMInvalid},
		{"mock predicate with an extra property", func(f *fixture) {
			f.addSignature(f.key, f.signaturePayload(f.digest, f.host+"/"+f.repo))
			f.addAttestation(f.key, PredicateSBOM, f.statement(PredicateSBOM, f.digest, statementType, f.sbom()))
			mock := strings.Replace(f.mock(), "{", `{"image":"x",`, 1)
			f.addAttestation(f.key, PredicateMock, f.statement(PredicateMock, f.digest, statementType, mock))
		}, nil, CodeAttestationInvalid},
		{"non-Linux image", func(f *fixture) {
			f.platform(`{"architecture":"amd64","os":"windows"}`)
			f.valid()
		}, nil, CodeNotLinux},
		{"image without an os", func(f *fixture) {
			f.platform(`{"architecture":"amd64"}`)
			f.valid()
		}, nil, CodeNotLinux},
		{"arm64 image", func(f *fixture) {
			f.platform(`{"architecture":"arm64","os":"linux"}`)
			f.valid()
		}, nil, CodeArchUnsupported},
		{"image index", func(f *fixture) {
			f.digest = f.reg.manifest("idx", map[string]any{"schemaVersion": 2, "mediaType": ociclient.MediaTypeOCIIndex,
				"manifests": []any{map[string]any{"mediaType": ociclient.MediaTypeOCIManifest, "digest": f.digest, "size": 1,
					"platform": map[string]string{"os": "linux", "architecture": "amd64"}}}})
			f.valid()
		}, nil, CodeIndexUnsupported},
		{"wrong predicate type only", func(f *fixture) {
			f.addSignature(f.key, f.signaturePayload(f.digest, f.host+"/"+f.repo))
			f.addAttestation(f.key, "https://slsa.dev/provenance/v1", f.statement("https://slsa.dev/provenance/v1", f.digest, statementType, `{}`))
		}, nil, CodeSBOMMissing},
		{"attestation copied from another image", func(f *fixture) {
			f.addSignature(f.key, f.signaturePayload(f.digest, f.host+"/"+f.repo))
			f.addAttestation(f.key, PredicateSBOM, f.statement(PredicateSBOM, other, statementType, `{}`))
		}, nil, CodeAttestationInvalid},
		{"attestation signed by another key", func(f *fixture) {
			f.addSignature(f.key, f.signaturePayload(f.digest, f.host+"/"+f.repo))
			f.addAttestation(newKey(f.t), PredicateSBOM, f.statement(PredicateSBOM, f.digest, statementType, `{}`))
		}, nil, CodeAttestationInvalid},
		{"unsigned envelope", func(f *fixture) {
			f.addSignature(f.key, f.signaturePayload(f.digest, f.host+"/"+f.repo))
			stmt := f.statement(PredicateSBOM, f.digest, statementType, `{}`)
			f.addEnvelope(PredicateSBOM, map[string]any{"payloadType": inTotoPayloadType, "payload": base64.StdEncoding.EncodeToString(stmt), "signatures": []any{}})
		}, nil, CodeAttestationInvalid},
		{"tampered envelope", func(f *fixture) {
			f.addSignature(f.key, f.signaturePayload(f.digest, f.host+"/"+f.repo))
			stmt := f.statement(PredicateSBOM, f.digest, statementType, `{}`)
			tampered := f.statement(PredicateSBOM, f.digest, statementType, `{"extra":1}`)
			f.addEnvelope(PredicateSBOM, map[string]any{"payloadType": inTotoPayloadType, "payload": base64.StdEncoding.EncodeToString(tampered),
				"signatures": []map[string]string{{"sig": sign(f.t, f.key, pae(inTotoPayloadType, stmt))}}})
		}, nil, CodeAttestationInvalid},
		{"Statement v1 is out of profile", func(f *fixture) {
			f.addSignature(f.key, f.signaturePayload(f.digest, f.host+"/"+f.repo))
			f.addAttestation(f.key, PredicateSBOM, f.statement(PredicateSBOM, f.digest, "https://in-toto.io/Statement/v1", `{}`))
		}, nil, CodeAttestationInvalid},
		{"SBOM predicate a string", func(f *fixture) { f.withSBOM(`"not an object"`) }, nil, CodeSBOMInvalid},
		{"SBOM predicate null", func(f *fixture) { f.withSBOM(`null`) }, nil, CodeSBOMInvalid},
		{"SBOM predicate an array", func(f *fixture) { f.withSBOM(`[]`) }, nil, CodeSBOMInvalid},
		{"SBOM with a second, empty metadata", func(f *fixture) {
			// encoding/json would keep the first metadata; the schema sees the last. One reading only.
			f.withSBOM(strings.Replace(f.sbom(), `,"components":`, `,"metadata":{},"components":`, 1))
		}, nil, CodeSBOMInvalid},
		{"mock predicate a string", func(f *fixture) {
			f.addSignature(f.key, f.signaturePayload(f.digest, f.host+"/"+f.repo))
			f.addAttestation(f.key, PredicateSBOM, f.statement(PredicateSBOM, f.digest, statementType, f.sbom()))
			f.addAttestation(f.key, PredicateMock, f.statement(PredicateMock, f.digest, statementType, `"x"`))
		}, nil, CodeAttestationInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			tc.setup(f)
			var keys []*ecdsa.PublicKey
			if tc.keys != nil {
				keys = tc.keys(f)
			}
			if r := f.verifier(keys...).VerifyImage(context.Background(), f.image()); r.Code != tc.want {
				t.Errorf("code = %q (%s), want %q", r.Code, r.Detail, tc.want)
			}
		})
	}
}

// withSBOM signs the image and attests the given SBOM and a valid mock predicate.
func (f *fixture) withSBOM(sbom string) {
	f.addSignature(f.key, f.signaturePayload(f.digest, f.host+"/"+f.repo))
	f.addAttestation(f.key, PredicateSBOM, f.statement(PredicateSBOM, f.digest, statementType, sbom))
	f.addAttestation(f.key, PredicateMock, f.statement(PredicateMock, f.digest, statementType, f.mock()))
}

func TestPlatformDetailBounded(t *testing.T) {
	for _, config := range []string{
		`{"architecture":"amd64","os":"` + strings.Repeat("w", 1<<20) + `"}`,
		`{"architecture":"` + strings.Repeat("a", 1<<20) + `","os":"linux"}`,
	} {
		f := newFixture(t)
		f.platform(config)
		f.valid()
		if r := f.verifier().VerifyImage(context.Background(), f.image()); r.OK() || len(r.Detail) > 512 {
			t.Errorf("code %s, detail length %d", r.Code, len(r.Detail))
		}
	}
}

func TestReattestedImagePasses(t *testing.T) {
	// An earlier, invalid SBOM attestation next to a valid one: the valid one is enough.
	f := newFixture(t)
	f.addAttestation(f.key, PredicateSBOM, f.statement(PredicateSBOM, f.digest, statementType, `{"bomFormat":"CycloneDX","specVersion":"1.4"}`))
	f.valid()
	if r := f.verifier().VerifyImage(context.Background(), f.image()); !r.OK() {
		t.Fatalf("re-attested image refused: %+v", r)
	}
}

func TestSchemas(t *testing.T) {
	if _, err := schemas(); err != nil {
		t.Fatalf("vendored schemas: %v", err)
	}
	vendored, _ := schemaFS.ReadFile("schemas/mock-attestation.schema.json")
	published, err := os.ReadFile("../../docs/attestation/mock-attestation.schema.json")
	if err != nil || string(vendored) != string(published) {
		t.Errorf("schemas/mock-attestation.schema.json differs from docs/attestation (%v)", err)
	}
	// Every published mock sample validates.
	s, _ := schemas()
	samples, _ := filepath.Glob("../../docs/attestation/samples/*.json")
	for _, name := range samples {
		b, _ := os.ReadFile(name)
		if err := validateWith(s.mock, b); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(samples) == 0 {
		t.Error("no mock samples found")
	}
}

func TestReferenceAndAllowListCheckedBeforeNetwork(t *testing.T) {
	f := newFixture(t).valid()
	v := f.verifier()
	for image, want := range map[string]string{
		f.host + "/team/app:v1":                                CodeNotDigest,
		"team/app@" + f.digest:                                 CodeNotDigest,
		f.host + "/team/app:v1@" + f.digest:                    CodeNotDigest,
		f.host + "/elsewhere/app@" + f.digest:                  CodeRegistryDenied,
		f.host + "/teamster/app@" + f.digest:                   CodeRegistryDenied,
		"evil.example/team/app@" + f.digest:                    CodeRegistryDenied,
		"evil.example/" + f.host + "/team/app@" + f.digest:     CodeNotDigest,
		f.host + "/team/app@sha256:" + strings.Repeat("A", 64): CodeNotDigest,
	} {
		if r := v.VerifyImage(context.Background(), image); r.Code != want {
			t.Errorf("%s: code %q, want %q", image, r.Code, want)
		}
	}
	if n := f.reg.requests.Load(); n != 0 {
		t.Errorf("%d registry requests for refused references, want 0", n)
	}
}

func TestCache(t *testing.T) {
	f := newFixture(t).valid()
	v := f.verifier()
	now := time.Now()
	v.now = func() time.Time { return now }
	ctx := context.Background()

	if !v.VerifyImage(ctx, f.image()).OK() {
		t.Fatal("first verification failed")
	}
	before := f.reg.requests.Load()
	if !v.VerifyImage(ctx, f.image()).OK() || f.reg.requests.Load() != before || v.Stats.Hits.Load() != 1 {
		t.Fatalf("second verification not served from cache: requests %d -> %d, hits %d", before, f.reg.requests.Load(), v.Stats.Hits.Load())
	}

	// A new trust policy (the key removed) is never answered from the old cache.
	v.SetPolicy(&Policy{Repositories: []string{f.host + "/team"}, Keys: []*ecdsa.PublicKey{&newKey(t).PublicKey}, Revision: "r2"})
	if r := v.VerifyImage(ctx, f.image()); r.Code != CodeUnsigned {
		t.Errorf("after key removal: %+v, want %s", r, CodeUnsigned)
	}

	// Positive entries expire.
	v.SetPolicy(&Policy{Repositories: []string{f.host + "/team"}, Keys: []*ecdsa.PublicKey{&f.key.PublicKey}, Revision: "r3"})
	v.VerifyImage(ctx, f.image())
	now = now.Add(v.PositiveTTL + time.Second)
	before = f.reg.requests.Load()
	v.VerifyImage(ctx, f.image())
	if f.reg.requests.Load() == before {
		t.Error("expired entry served from cache")
	}
}

func TestCacheBounded(t *testing.T) {
	f := newFixture(t)
	v := f.verifier()
	policy := v.policy.Load()
	for i := 0; i < maxCacheEntries+10; i++ {
		v.store(fmt.Sprintf("k%d", i), policy, Result{Code: CodeUnsigned})
	}
	if n := len(v.cache); n > maxCacheEntries {
		t.Errorf("cache holds %d entries, cap %d", n, maxCacheEntries)
	}
}

func TestSignaturesPerEnvelopeCapped(t *testing.T) {
	// A valid signature placed after the cap is not reached, so padding an envelope with
	// signatures cannot buy extra verification work.
	f := newFixture(t)
	f.addSignature(f.key, f.signaturePayload(f.digest, f.host+"/"+f.repo))
	stmt := f.statement(PredicateSBOM, f.digest, statementType, `{}`)
	sigs := []map[string]string{}
	for i := 0; i < 4; i++ {
		sigs = append(sigs, map[string]string{"sig": "AA=="})
	}
	sigs = append(sigs, map[string]string{"sig": sign(t, f.key, pae(inTotoPayloadType, stmt))})
	f.addEnvelope(PredicateSBOM, map[string]any{"payloadType": inTotoPayloadType,
		"payload": base64.StdEncoding.EncodeToString(stmt), "signatures": sigs})
	if r := f.verifier().VerifyImage(context.Background(), f.image()); r.Code != CodeAttestationInvalid {
		t.Errorf("valid signature past the cap: %+v, want %s", r, CodeAttestationInvalid)
	}
}

func TestSlowVerificationCompletesDetached(t *testing.T) {
	// A cold verification slower than the request deadline: the request fails closed, but the
	// verification finishes and a retry is answered from the cache.
	f := newFixture(t).valid()
	v := f.verifier()
	f.reg.delay.Store(int64(20 * time.Millisecond))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	r := v.VerifyImage(ctx, f.image())
	cancel()
	if r.Code != CodeProviderDown {
		t.Fatalf("first request: %+v, want %s", r, CodeProviderDown)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		r = v.VerifyImage(ctx, f.image())
		cancel()
		if r.OK() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("never admitted: %+v", r)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestConcurrentRequestsShareOneVerification(t *testing.T) {
	// The registry requests of one verification, measured on a separate fixture.
	one := newFixture(t).valid()
	if !one.verifier().VerifyImage(context.Background(), one.image()).OK() {
		t.Fatal("baseline verification failed")
	}
	perVerification := one.reg.requests.Load()

	f := newFixture(t).valid()
	v := f.verifier()
	f.reg.delay.Store(int64(10 * time.Millisecond))
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r := v.VerifyImage(context.Background(), f.image()); !r.OK() {
				t.Errorf("concurrent request: %+v", r)
			}
		}()
	}
	wg.Wait()
	if n := f.reg.requests.Load(); n != perVerification {
		t.Errorf("%d registry requests for 10 concurrent requests, want %d (one verification)", n, perVerification)
	}
}

func TestVerdictCachedBetweenLookupAndStart(t *testing.T) {
	// The interleaving where a flight stores its verdict and finishes after a request missed the
	// cache but before it chose a flight: the request must take the cached verdict, not start again.
	f := newFixture(t).valid()
	v := f.verifier()
	ref, _ := ParseRef(f.image())
	policy := v.policy.Load()
	key := ref.String() + " " + policy.Revision
	v.store(key, policy, Result{})
	fl, r, cached := v.start(key, ref, policy)
	if !cached || fl != nil || !r.OK() || f.reg.requests.Load() != 0 {
		t.Errorf("start after a verdict was cached: flight %v, cached %v, result %+v, %d registry requests", fl, cached, r, f.reg.requests.Load())
	}
}

func TestInflightBounded(t *testing.T) {
	f := newFixture(t).valid()
	v := f.verifier()
	v.mu.Lock()
	for i := range maxInflight {
		v.inflight[fmt.Sprintf("busy %d", i)] = &flight{done: make(chan struct{})}
	}
	v.mu.Unlock()
	if r := v.VerifyImage(context.Background(), f.image()); r.Code != CodeProviderDown || f.reg.requests.Load() != 0 {
		t.Errorf("at the in-flight bound: %+v, %d registry requests", r, f.reg.requests.Load())
	}
}

func TestRegistryDownFailsClosedAndIsNotCached(t *testing.T) {
	f := newFixture(t).valid()
	v := f.verifier()
	f.reg.down.Store(true)
	if r := v.VerifyImage(context.Background(), f.image()); r.Code != CodeProviderDown {
		t.Fatalf("registry down: %+v, want %s", r, CodeProviderDown)
	}
	f.reg.down.Store(false)
	if r := v.VerifyImage(context.Background(), f.image()); !r.OK() {
		t.Fatalf("after recovery: %+v", r)
	}
}

func TestParsePublicKeys(t *testing.T) {
	k := newKey(t)
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	good := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if keys, err := ParsePublicKeys(good); err != nil || len(keys) != 1 {
		t.Fatalf("P-256 key: %v", err)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der384, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	if _, err := ParsePublicKeys(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der384})); err == nil {
		t.Error("P-384 key accepted")
	}
	if _, err := ParsePublicKeys([]byte("no pem")); err == nil {
		t.Error("empty input accepted")
	}
}
