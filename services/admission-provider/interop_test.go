package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/cosignverify"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/ociclient"
)

// TestInterop signs and attests real images with the pinned cosign through the release script, in a
// plain-http registry:2, and has the provider verify them through ProviderRequests. It runs when
// FACIS_INTEROP_REGISTRY (host:port) and COSIGN (the pinned binary) are set, as in the CI interop job.
func TestInterop(t *testing.T) {
	registry, cosign := os.Getenv("FACIS_INTEROP_REGISTRY"), os.Getenv("COSIGN")
	if registry == "" || cosign == "" {
		t.Skip("FACIS_INTEROP_REGISTRY and COSIGN not set")
	}
	dir := t.TempDir()
	ctx := context.Background()

	run := func(env []string, name string, args ...string) string {
		t.Helper()
		cmd := exec.Command(name, args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), env...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
		}
		return string(out)
	}
	keyEnv := []string{"COSIGN_PASSWORD="}
	run(keyEnv, cosign, "generate-key-pair")
	pub, err := os.ReadFile(filepath.Join(dir, "cosign.pub"))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := cosignverify.ParsePublicKeys(pub)
	if err != nil {
		t.Fatal(err)
	}

	mock, err := os.ReadFile(filepath.Join("..", "..", "docs", "attestation", "samples", "sw.mock.json"))
	if err != nil {
		t.Fatal(err)
	}
	script, _ := filepath.Abs(filepath.Join("..", "..", "scripts", "supplychain", "sign-attest.sh"))
	signEnv := []string{"COSIGN_PASSWORD=", "COSIGN_KEY=" + filepath.Join(dir, "cosign.key"), "COSIGN=" + cosign}

	signed := push(t, registry, "interop/signed")
	// The SBOM names the image as Syft does for an image scanned by digest.
	name, dgst, _ := strings.Cut(signed, "@")
	sbom := fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"component":{"type":"container","name":%q,"version":%q}},"components":[]}`, name, dgst)
	for file, content := range map[string][]byte{"mock.json": mock, "sbom.json": []byte(sbom)} {
		if err := os.WriteFile(filepath.Join(dir, file), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	run(signEnv, "bash", script, signed, "sbom.json", "mock.json")
	unsigned := push(t, registry, "interop/unsigned")
	copied := push(t, registry, "interop/copied")
	run(signEnv, cosign, "sign", "--yes", "--key", filepath.Join(dir, "cosign.key"), "--tlog-upload=false", "--new-bundle-format=false", copied)
	copyAttestations(t, registry, signed, copied)

	// The CLI cross-check the release uses.
	run(nil, cosign, "verify", "--key", "cosign.pub", "--insecure-ignore-tlog=true", signed)
	run(nil, cosign, "verify-attestation", "--key", "cosign.pub", "--insecure-ignore-tlog=true", "--type", cosignverify.PredicateMock, signed)

	client := ociclient.New(ociclient.Options{PlainHTTP: []string{registry}})
	v := cosignverify.New(client, &cosignverify.Policy{Repositories: []string{registry + "/interop"}, Keys: keys, Revision: "interop"}, 4)
	if r := v.VerifyImage(ctx, signed); !json.Valid(r.Predicates[cosignverify.PredicateMock]) || !bytes.Contains(r.Predicates[cosignverify.PredicateSBOM], []byte("CycloneDX")) {
		t.Errorf("predicates = %+v", r)
	}
	h := &handler{verifier: v, trust: &trust{}, timeout: time.Second, metrics: newMetrics(&v.Stats)}
	tag := registry + "/interop/signed:latest"
	_, resp := post(t, h, request(signed, unsigned, copied, tag, "evil.example/interop/x@"+strings.SplitN(signed, "@", 2)[1]))
	want := []string{"", cosignverify.CodeUnsigned, cosignverify.CodeAttestationInvalid, cosignverify.CodeNotDigest, cosignverify.CodeRegistryDenied}
	for i, it := range resp.Response.Items {
		if code, _, _ := strings.Cut(it.Error, ":"); code != want[i] || (want[i] == "" && it.Value != verifiedValue) {
			t.Errorf("%s: %+v, want code %q", it.Key, it, want[i])
		}
	}

	// Warm-cache latency of a full ProviderRequest, the in-process counterpart of the cluster p99.
	var durations []time.Duration
	for range 200 {
		start := time.Now()
		if _, resp := post(t, h, request(signed)); resp.Response.Items[0].Value != verifiedValue {
			t.Fatalf("warm request: %+v", resp.Response)
		}
		durations = append(durations, time.Since(start))
	}
	slices.Sort(durations)
	p99 := durations[len(durations)*99/100]
	t.Logf("in-process p99 over %d warm requests: %s", len(durations), p99)
	if p99 > 100*time.Millisecond {
		t.Errorf("in-process p99 %s", p99)
	}

	strangerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	stranger := cosignverify.New(client, &cosignverify.Policy{Repositories: []string{registry + "/interop"}, Keys: []*ecdsa.PublicKey{&strangerKey.PublicKey}, Revision: "x"}, 1)
	if r := stranger.VerifyImage(ctx, signed); r.Code != cosignverify.CodeUnsigned {
		t.Errorf("wrong trusted key: %+v, want %s", r, cosignverify.CodeUnsigned)
	}
}

// push uploads a single-platform linux/amd64 image with a random layer and returns its digest reference.
func push(t *testing.T, registry, repo string) string {
	t.Helper()
	layer := make([]byte, 64)
	_, _ = rand.Read(layer)
	config := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`)
	upload(t, registry, repo, layer)
	upload(t, registry, repo, config)
	manifest, _ := json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": ociclient.MediaTypeOCIManifest,
		"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": digest(config), "size": len(config)},
		"layers": []any{map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": digest(layer), "size": len(layer)}},
	})
	req, _ := http.NewRequest(http.MethodPut, fmt.Sprintf("http://%s/v2/%s/manifests/%s", registry, repo, digest(manifest)), bytes.NewReader(manifest))
	req.Header.Set("Content-Type", ociclient.MediaTypeOCIManifest)
	do(t, req, http.StatusCreated)
	return fmt.Sprintf("%s/%s@%s", registry, repo, digest(manifest))
}

func upload(t *testing.T, registry, repo string, blob []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("http://%s/v2/%s/blobs/uploads/", registry, repo), nil)
	resp := do(t, req, http.StatusAccepted)
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "http") {
		loc = "http://" + registry + loc
	}
	sep := "?"
	if strings.Contains(loc, "?") {
		sep = "&"
	}
	req, _ = http.NewRequest(http.MethodPut, loc+sep+"digest="+digest(blob), bytes.NewReader(blob))
	req.Header.Set("Content-Type", "application/octet-stream")
	do(t, req, http.StatusCreated)
}

// copyAttestations copies the .att manifest (and its blobs) of one image to another image's tag -
// what an attacker reusing a genuine attestation would do.
func copyAttestations(t *testing.T, registry, from, to string) {
	t.Helper()
	src, _ := cosignverify.ParseRef(from)
	dst, _ := cosignverify.ParseRef(to)
	client := ociclient.New(ociclient.Options{PlainHTTP: []string{registry}})
	m, err := client.ManifestByTag(context.Background(), registry, src.Repository, cosignTag(src.Digest))
	if err != nil {
		t.Fatal(err)
	}
	var im ociclient.ImageManifest
	_ = json.Unmarshal(m.Body, &im)
	for _, d := range append(im.Layers, im.Config) {
		b, err := client.Blob(context.Background(), registry, src.Repository, d.Digest)
		if err != nil {
			t.Fatal(err)
		}
		upload(t, registry, dst.Repository, b)
	}
	req, _ := http.NewRequest(http.MethodPut, fmt.Sprintf("http://%s/v2/%s/manifests/%s", registry, dst.Repository, cosignTag(dst.Digest)), bytes.NewReader(m.Body))
	req.Header.Set("Content-Type", m.MediaType)
	do(t, req, http.StatusCreated)
}

func do(t *testing.T, req *http.Request, want int) *http.Response {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != want {
		t.Fatalf("%s %s: status %d, want %d: %s", req.Method, req.URL, resp.StatusCode, want, body)
	}
	return resp
}

// cosignTag is the classic cosign attestation tag of a digest.
func cosignTag(digest string) string { return strings.Replace(digest, ":", "-", 1) + ".att" }

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
