// Package cosignverify verifies container images against the demonstrator's one signing profile:
// cosign v2 classic layout (".sig" and ".att" tags), key-based ECDSA P-256, no transparency log,
// attestations as DSSE envelopes of in-toto Statement v0.1. Anything outside that profile is refused.
// The image itself must be a single-platform linux/amd64 manifest; the SBOM (CycloneDX 1.5, 1.6 or
// 1.7 JSON) and the mock attestation must validate against their schemas.
//
// A result names the admission reason code of the first check that failed, from the contracts'
// reason-code registry.
package cosignverify

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/ociclient"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Reason codes (docs/contracts/reason-codes.json).
const (
	CodeNotDigest          = "ADM-NOT-DIGEST"
	CodeRegistryDenied     = "ADM-REGISTRY-DENIED"
	CodeUnsigned           = "ADM-UNSIGNED"
	CodeSBOMMissing        = "ADM-SBOM-MISSING"
	CodeSBOMInvalid        = "ADM-SBOM-INVALID"
	CodeNoAttestation      = "ADM-NO-ATTESTATION"
	CodeAttestationInvalid = "ADM-ATTESTATION-INVALID"
	CodeProviderDown       = "ADM-PROVIDER-DOWN"
	CodeNotLinux           = "ADM-NOT-LINUX"
	CodeArchUnsupported    = "ADM-ARCH-UNSUPPORTED"
	CodeIndexUnsupported   = "ADM-INDEX-UNSUPPORTED"
)

// Predicate types of the two required attestations.
const (
	PredicateSBOM = "https://cyclonedx.org/bom"
	PredicateMock = "https://facis.eu/ztd/mock-attestation/v1"
)

const (
	statementType      = "https://in-toto.io/Statement/v0.1"
	inTotoPayloadType  = "application/vnd.in-toto+json"
	simpleSigningType  = "application/vnd.dev.cosign.simplesigning.v1+json"
	dsseEnvelopeType   = "application/vnd.dsse.envelope.v1+json"
	signatureAnnot     = "dev.cosignproject.cosign/signature"
	cosignSignatureTyp = "cosign container image signature"
)

// Policy is the trust configuration. Revision identifies it in the cache: a new policy never sees a
// result computed under an old one.
type Policy struct {
	// Repositories lists allowed repository prefixes, "host/path" (e.g. "ghcr.io/org"); an image is
	// allowed when "host/repository" equals an entry or continues it with "/".
	Repositories []string
	Keys         []*ecdsa.PublicKey
	Revision     string
}

// ParsePublicKeys reads PEM "PUBLIC KEY" blocks (cosign.pub) and accepts only ECDSA P-256 keys.
func ParsePublicKeys(pemData []byte) ([]*ecdsa.PublicKey, error) {
	var keys []*ecdsa.PublicKey
	for {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)
		if block == nil {
			break
		}
		if block.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("cosignverify: unexpected PEM block %q", block.Type)
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("cosignverify: %w", err)
		}
		key, ok := pub.(*ecdsa.PublicKey)
		if !ok || key.Curve != elliptic.P256() {
			return nil, errors.New("cosignverify: only ECDSA P-256 keys are in the profile")
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, errors.New("cosignverify: no public key found")
	}
	return keys, nil
}

// Result of a verification. Code is empty when the image passed.
type Result struct {
	Code   string
	Detail string
	// Predicates holds the verified predicate of each required attestation, by predicate type.
	Predicates map[string]json.RawMessage
}

// OK reports whether the image passed.
func (r Result) OK() bool { return r.Code == "" }

// Stats counts cache use.
type Stats struct{ Hits, Misses atomic.Int64 }

// Verifier verifies images. Safe for concurrent use.
type Verifier struct {
	client *ociclient.Client
	policy atomic.Pointer[Policy]
	sem    chan struct{}
	now    func() time.Time

	PositiveTTL, NegativeTTL time.Duration
	// VerifyTimeout bounds one verification, which runs detached from the request that started it.
	VerifyTimeout time.Duration
	Stats         Stats

	mu       sync.Mutex
	cache    map[string]cached
	inflight map[string]*flight
}

// flight is one verification in progress; every request for the same image and policy waits on it.
type flight struct {
	done   chan struct{}
	result Result
}

// maxInflight bounds the verifications running at once across distinct images (beyond the registry
// concurrency, which bounds the ones talking to the registry).
const maxInflight = 256

type cached struct {
	result  Result
	expires time.Time
}

// New returns a Verifier that makes at most concurrency registry verifications at once.
func New(client *ociclient.Client, policy *Policy, concurrency int) *Verifier {
	if concurrency < 1 {
		concurrency = 1
	}
	v := &Verifier{
		client:        client,
		sem:           make(chan struct{}, concurrency),
		now:           time.Now,
		PositiveTTL:   5 * time.Minute,
		NegativeTTL:   30 * time.Second,
		VerifyTimeout: 30 * time.Second,
		cache:         map[string]cached{},
		inflight:      map[string]*flight{},
	}
	v.SetPolicy(policy)
	return v
}

// SetPolicy replaces the trust policy and empties the cache.
func (v *Verifier) SetPolicy(p *Policy) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.policy.Store(p)
	v.cache = map[string]cached{}
}

// Ref is a parsed digest reference.
type Ref struct{ Registry, Repository, Digest string }

func (r Ref) String() string { return r.Registry + "/" + r.Repository + "@" + r.Digest }

// ParseRef accepts only "host/repository@sha256:<hex>" with an explicit registry host.
func ParseRef(image string) (Ref, bool) {
	name, digest, ok := strings.Cut(image, "@")
	if !ok || !ociclient.ValidDigest(digest) {
		return Ref{}, false
	}
	host, repo, ok := strings.Cut(name, "/")
	explicitHost := strings.ContainsAny(host, ".:") || host == "localhost" // never an implied Docker Hub
	if !ok || repo == "" || strings.Contains(repo, ":") || !explicitHost {
		return Ref{}, false
	}
	return Ref{Registry: host, Repository: repo, Digest: digest}, true
}

func (p *Policy) allows(r Ref) bool {
	name := r.Registry + "/" + r.Repository
	for _, prefix := range p.Repositories {
		if name == prefix || strings.HasPrefix(name, strings.TrimSuffix(prefix, "/")+"/") {
			return true
		}
	}
	return false
}

// VerifyImage runs the profile's checks in order and returns the first failure: digest reference,
// allowed repository (both before any network call), signature, image platform, SBOM attestation,
// mock attestation.
//
// A verification that has to reach the registry runs detached from ctx, bounded by VerifyTimeout,
// and is shared by every concurrent request for the same image under the same policy. A request whose
// ctx ends first is answered ADM-PROVIDER-DOWN (fail closed), but the verification completes and its
// verdict is cached, so a retry is answered from the cache: a cold verification slower than the
// admission deadline cannot deny an image forever.
func (v *Verifier) VerifyImage(ctx context.Context, image string) Result {
	ref, ok := ParseRef(image)
	if !ok {
		return Result{Code: CodeNotDigest, Detail: "image must be referenced as host/repository@sha256:<digest>"}
	}
	policy := v.policy.Load()
	if !policy.allows(ref) {
		return Result{Code: CodeRegistryDenied, Detail: ref.Registry + "/" + ref.Repository}
	}
	key := ref.String() + " " + policy.Revision
	if r, ok := v.lookup(key); ok {
		return r
	}
	f, cached, ok := v.start(key, ref, policy)
	if ok {
		return cached
	}
	if f == nil {
		return Result{Code: CodeProviderDown, Detail: "too many verifications in progress"}
	}
	select {
	case <-f.done:
		return f.result
	case <-ctx.Done():
		return Result{Code: CodeProviderDown, Detail: "verification still in progress; retry"}
	}
}

// start returns the cached verdict for key if one appeared since the lookup (a flight can finish in
// between), else joins the verification in progress, else starts one; the flight is nil when too
// many are running. Cache and flights are read under one lock, so a finished flight is never missed.
func (v *Verifier) start(key string, ref Ref, policy *Policy) (*flight, Result, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if c, ok := v.cache[key]; ok && !v.now().After(c.expires) {
		return nil, c.result, true
	}
	if f, ok := v.inflight[key]; ok {
		return f, Result{}, false
	}
	if len(v.inflight) >= maxInflight {
		return nil, Result{}, false
	}
	f := &flight{done: make(chan struct{})}
	v.inflight[key] = f
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), v.VerifyTimeout)
		defer cancel()
		select {
		case v.sem <- struct{}{}:
			f.result = v.verify(ctx, ref, policy)
			<-v.sem
		case <-ctx.Done():
			f.result = Result{Code: CodeProviderDown, Detail: "verification capacity exhausted"}
		}
		v.store(key, policy, f.result)
		v.mu.Lock()
		delete(v.inflight, key)
		v.mu.Unlock()
		close(f.done)
	}()
	return f, Result{}, false
}

func (v *Verifier) lookup(key string) (Result, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	c, ok := v.cache[key]
	if !ok || v.now().After(c.expires) {
		v.Stats.Misses.Add(1)
		return Result{}, false
	}
	v.Stats.Hits.Add(1)
	return c.result, true
}

const maxCacheEntries = 4096

// store caches verdicts; an infrastructure failure is not a verdict and is not cached.
//
// ponytail: at maxCacheEntries the expired entries are swept and, if that frees nothing, the cache is
// emptied; an LRU is the upgrade path if distinct-digest churn ever costs hit rate.
func (v *Verifier) store(key string, policy *Policy, r Result) {
	if r.Code == CodeProviderDown {
		return
	}
	ttl := v.PositiveTTL
	if !r.OK() {
		ttl = v.NegativeTTL
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.policy.Load() != policy {
		return // the policy changed while verifying
	}
	if len(v.cache) >= maxCacheEntries {
		now := v.now()
		for k, c := range v.cache {
			if now.After(c.expires) {
				delete(v.cache, k)
			}
		}
		if len(v.cache) >= maxCacheEntries {
			v.cache = map[string]cached{}
		}
	}
	v.cache[key] = cached{result: r, expires: v.now().Add(ttl)}
}

func (v *Verifier) verify(ctx context.Context, ref Ref, policy *Policy) Result {
	if r := v.verifySignature(ctx, ref, policy); !r.OK() {
		return r
	}
	if r := v.verifyPlatform(ctx, ref); !r.OK() {
		return r
	}
	s, err := schemas()
	if err != nil {
		return Result{Code: CodeProviderDown, Detail: "predicate schemas: " + err.Error()}
	}
	predicates := map[string]json.RawMessage{}
	for _, want := range []struct {
		predicate, missing, invalid string
		validate                    func(json.RawMessage) error
	}{
		{PredicateSBOM, CodeSBOMMissing, CodeSBOMInvalid, func(p json.RawMessage) error { return validateSBOM(s, ref, p) }},
		{PredicateMock, CodeNoAttestation, CodeAttestationInvalid, func(p json.RawMessage) error { return validateWith(s.mock, p) }},
	} {
		p, r := v.verifyAttestation(ctx, ref, policy, want.predicate, want.missing, want.invalid, want.validate)
		if !r.OK() {
			return r
		}
		predicates[want.predicate] = p
	}
	return Result{Predicates: predicates}
}

func tagFor(digest, suffix string) string { return strings.Replace(digest, ":", "-", 1) + "." + suffix }

// layers fetches the manifest at the cosign tag; a missing tag is "no layers", not an error.
func (v *Verifier) layers(ctx context.Context, ref Ref, suffix string) ([]ociclient.Descriptor, error) {
	m, err := v.client.ManifestByTag(ctx, ref.Registry, ref.Repository, tagFor(ref.Digest, suffix))
	if errors.Is(err, ociclient.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var im ociclient.ImageManifest
	if err := json.Unmarshal(m.Body, &im); err != nil {
		return nil, fmt.Errorf("cosign %s manifest: %w", suffix, err)
	}
	const maxLayers = 16
	if len(im.Layers) > maxLayers {
		im.Layers = im.Layers[:maxLayers]
	}
	return im.Layers, nil
}

func down(err error) Result {
	return Result{Code: CodeProviderDown, Detail: "registry: " + err.Error()}
}

type simpleSigning struct {
	Critical struct {
		Identity struct {
			DockerReference string `json:"docker-reference"`
		} `json:"identity"`
		Image struct {
			DockerManifestDigest string `json:"docker-manifest-digest"`
		} `json:"image"`
		Type string `json:"type"`
	} `json:"critical"`
}

func verifySig(keys []*ecdsa.PublicKey, digest [32]byte, sig []byte) bool {
	for _, k := range keys {
		if ecdsa.VerifyASN1(k, digest[:], sig) {
			return true
		}
	}
	return false
}

func (v *Verifier) verifySignature(ctx context.Context, ref Ref, policy *Policy) Result {
	layers, err := v.layers(ctx, ref, "sig")
	if err != nil {
		return down(err)
	}
	for _, l := range layers {
		if ctx.Err() != nil {
			return down(ctx.Err())
		}
		if l.MediaType != simpleSigningType {
			continue
		}
		sig, err := base64.StdEncoding.DecodeString(l.Annotations[signatureAnnot])
		if err != nil || len(sig) == 0 {
			continue
		}
		payload, err := v.client.Blob(ctx, ref.Registry, ref.Repository, l.Digest)
		if err != nil {
			if errors.Is(err, ociclient.ErrNotFound) || errors.Is(err, ociclient.ErrDigestMismatch) || errors.Is(err, ociclient.ErrTooLarge) {
				continue
			}
			return down(err)
		}
		if !verifySig(policy.Keys, sha256.Sum256(payload), sig) {
			continue
		}
		var ss simpleSigning
		if json.Unmarshal(payload, &ss) != nil {
			continue
		}
		if ss.Critical.Type == cosignSignatureTyp &&
			ss.Critical.Image.DockerManifestDigest == ref.Digest &&
			ss.Critical.Identity.DockerReference == ref.Registry+"/"+ref.Repository {
			return Result{}
		}
	}
	return Result{Code: CodeUnsigned, Detail: "no valid signature by a trusted key for " + ref.String()}
}

type envelope struct {
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"`
	Signatures  []struct {
		Sig string `json:"sig"`
	} `json:"signatures"`
}

type statement struct {
	Type          string `json:"_type"`
	PredicateType string `json:"predicateType"`
	Subject       []struct {
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	Predicate json.RawMessage `json:"predicate"`
}

// pae is the DSSE pre-authentication encoding.
func pae(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload))
}

// verifyAttestation finds an attestation of the wanted predicate type that is signed by a trusted
// key, bound to this digest and whose predicate validates. A layer that claims the type but is not
// signed or bound is reported as ADM-ATTESTATION-INVALID, so a copied or tampered attestation is
// distinguishable from a missing one; a signed and bound one whose predicate fails validation is
// reported with the invalid code. Any one layer that passes is enough (a re-attested image carries
// its earlier attestations too).
func (v *Verifier) verifyAttestation(ctx context.Context, ref Ref, policy *Policy, want, missing, invalid string, validate func(json.RawMessage) error) (json.RawMessage, Result) {
	layers, err := v.layers(ctx, ref, "att")
	if err != nil {
		return nil, down(err)
	}
	wantHex := strings.TrimPrefix(ref.Digest, "sha256:")
	claimed := false
	var predicateErr error
	for _, l := range layers {
		if ctx.Err() != nil {
			return nil, down(ctx.Err())
		}
		if l.MediaType != dsseEnvelopeType {
			continue
		}
		if l.Annotations["predicateType"] == want {
			claimed = true
		}
		raw, err := v.client.Blob(ctx, ref.Registry, ref.Repository, l.Digest)
		if err != nil {
			if errors.Is(err, ociclient.ErrNotFound) || errors.Is(err, ociclient.ErrDigestMismatch) || errors.Is(err, ociclient.ErrTooLarge) {
				continue
			}
			return nil, down(err)
		}
		var env envelope
		if json.Unmarshal(raw, &env) != nil {
			continue
		}
		payload, err := base64.StdEncoding.DecodeString(env.Payload)
		if err != nil {
			continue
		}
		var st statement
		if json.Unmarshal(payload, &st) != nil || st.PredicateType != want {
			continue
		}
		claimed = true
		if env.PayloadType != inTotoPayloadType || st.Type != statementType {
			continue
		}
		// The PAE is hashed once, and only the first few signatures are tried, so an envelope padded
		// with signatures costs no more than a short one.
		const maxSignatures = 4
		sigs := env.Signatures
		if len(sigs) > maxSignatures {
			sigs = sigs[:maxSignatures]
		}
		digest := sha256.Sum256(pae(env.PayloadType, payload))
		signed := false
		for _, s := range sigs {
			if sig, err := base64.StdEncoding.DecodeString(s.Sig); err == nil && verifySig(policy.Keys, digest, sig) {
				signed = true
				break
			}
		}
		if !signed {
			continue
		}
		bound := false
		for _, s := range st.Subject {
			if h := s.Digest["sha256"]; len(h) == 64 && strings.EqualFold(h, wantHex) {
				bound = true
			}
		}
		if !bound {
			continue
		}
		if err := validate(st.Predicate); err != nil {
			predicateErr = err
			continue
		}
		return st.Predicate, Result{}
	}
	if predicateErr != nil {
		return nil, Result{Code: invalid, Detail: want + " predicate for " + ref.String() + ": " + truncate(predicateErr.Error(), 300)}
	}
	if claimed {
		return nil, Result{Code: CodeAttestationInvalid, Detail: want + " attestation does not verify for " + ref.String()}
	}
	return nil, Result{Code: missing, Detail: "no " + want + " attestation for " + ref.String()}
}

// verifyPlatform admits only a single-platform linux/amd64 image manifest: an index is refused, so
// the signature, the attestations and the platform all bind the one digest that runs.
func (v *Verifier) verifyPlatform(ctx context.Context, ref Ref) Result {
	m, err := v.client.ManifestByDigest(ctx, ref.Registry, ref.Repository, ref.Digest)
	if err != nil {
		return down(fmt.Errorf("image manifest: %w", err))
	}
	switch m.MediaType {
	case ociclient.MediaTypeOCIManifest, ociclient.MediaTypeDockerManifest:
	case ociclient.MediaTypeOCIIndex, ociclient.MediaTypeDockerList:
		return Result{Code: CodeIndexUnsupported, Detail: ref.String() + " is an image index; reference the linux/amd64 manifest digest"}
	default:
		return Result{Code: CodeIndexUnsupported, Detail: fmt.Sprintf("%s: manifest media type %q is not a single-platform image manifest", ref, truncate(m.MediaType, 64))}
	}
	var im ociclient.ImageManifest
	if err := json.Unmarshal(m.Body, &im); err != nil || !ociclient.ValidDigest(im.Config.Digest) {
		return Result{Code: CodeIndexUnsupported, Detail: ref.String() + ": not a valid image manifest"}
	}
	raw, err := v.client.Blob(ctx, ref.Registry, ref.Repository, im.Config.Digest)
	if err != nil {
		return down(fmt.Errorf("image config: %w", err))
	}
	var config struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
	}
	if err := json.Unmarshal(raw, &config); err != nil {
		return Result{Code: CodeNotLinux, Detail: ref.String() + ": image configuration is not valid JSON"}
	}
	if config.OS != "linux" {
		return Result{Code: CodeNotLinux, Detail: fmt.Sprintf("%s: image configuration declares os %q", ref, truncate(config.OS, 64))}
	}
	if config.Architecture != "amd64" {
		return Result{Code: CodeArchUnsupported, Detail: fmt.Sprintf("%s: image configuration declares architecture %q", ref, truncate(config.Architecture, 64))}
	}
	return Result{}
}

func validateWith(s *jsonschema.Schema, predicate json.RawMessage) error {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(predicate))
	if err != nil {
		return err
	}
	return s.Validate(doc)
}

// validateSBOM checks the SBOM against the CycloneDX schema of its specVersion, then binds it to the
// image: its metadata.component is the container "registry/repository" at this digest, as Syft writes
// it for an image scanned by digest, and it lists components. The schema and the binding read the
// same decoded document (exact key names, one value per key), so no second reading of the JSON can
// see a different SBOM.
func validateSBOM(s *compiledSchemas, ref Ref, predicate json.RawMessage) error {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(predicate))
	if err != nil {
		return err
	}
	sbom, ok := doc.(map[string]any)
	if !ok {
		return errors.New("not a JSON object")
	}
	format, _ := sbom["bomFormat"].(string)
	version, _ := sbom["specVersion"].(string)
	schema, ok := s.sbom[version]
	if format != "CycloneDX" || !ok {
		return fmt.Errorf("not CycloneDX 1.5, 1.6 or 1.7 JSON (bomFormat %q, specVersion %q)", truncate(format, 32), truncate(version, 32))
	}
	if err := schema.Validate(doc); err != nil {
		return err
	}
	metadata, _ := sbom["metadata"].(map[string]any)
	component, _ := metadata["component"].(map[string]any)
	typ, _ := component["type"].(string)
	name, _ := component["name"].(string)
	digest, _ := component["version"].(string)
	if typ != "container" || name != ref.Registry+"/"+ref.Repository || digest != ref.Digest {
		return fmt.Errorf("metadata.component (%s %q %q) does not name this image", truncate(typ, 32), truncate(name, 128), truncate(digest, 80))
	}
	if _, ok := sbom["components"].([]any); !ok {
		return errors.New("no components array")
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
