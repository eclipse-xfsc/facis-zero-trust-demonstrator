package atlstest

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/cmc"
	"github.com/Fraunhofer-AISEC/cmc/prover"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/atls"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/atls/internal/testhook"
)

// proverMu serialises report generation. CMC's drivers are process-global singletons and the sw
// driver writes its state on every report, so concurrent generation is a data race inside CMC.
var proverMu sync.Mutex

// Zone is one zone's attester material: its TLS certificate and identity, signed metadata, and
// an in-process CMC configured with the sw driver (mock evidence, no TEE).
type Zone struct {
	Name string
	// Identity is the zone's certificate identity, "spiffe://<name>/gateway".
	Identity string
	Cert     tls.Certificate
	PKI      *PKI
	// EvidenceNotAfter is the validity end written into the zone's signed metadata.
	EvidenceNotAfter time.Time

	lib *cmc.Config
	c   *cmc.Cmc
	// tb is the test that created the zone; the stand-in cmcd lives as long as it does.
	tb testing.TB

	cmcdOnce sync.Once
	cmcdAddr string
}

// ZoneOption adjusts a zone.
type ZoneOption func(*zoneOptions)

type zoneOptions struct {
	notBefore, notAfter time.Time
}

// WithEvidenceValidity sets the validity window of the zone's signed metadata, and so of its
// evidence. The default is one minute ago to one hour from now.
func WithEvidenceValidity(notBefore, notAfter time.Time) ZoneOption {
	return func(o *zoneOptions) { o.notBefore, o.notAfter = notBefore, notAfter }
}

// NewZone creates the material for zone name under pki.
func NewZone(t testing.TB, pki *PKI, name string, opts ...ZoneOption) *Zone {
	mustTest()
	t.Helper()
	o := zoneOptions{notBefore: time.Now().Add(-time.Minute), notAfter: time.Now().Add(time.Hour)}
	for _, opt := range opts {
		opt(&o)
	}
	dir := t.TempDir()
	z := &Zone{
		Name:             name,
		Identity:         "spiffe://" + name + "/gateway",
		PKI:              pki,
		EvidenceNotAfter: o.notAfter,
		tb:               t,
	}
	z.Cert = pki.Issue(t, z.Identity)
	metadata := writeMetadata(t, filepath.Join(dir, "metadata"), pki, name, o.notBefore, o.notAfter)
	// All zones of a PKI share one sw driver storage, and so one sw attestation key. CMC's
	// drivers are process-global and libapi re-initialises them from the calling zone's storage
	// on every call; with a key per zone, a report could carry one zone's key in its collateral
	// and be signed with the other's when both ends run in this process (finding N4).
	storage := pki.swStorage
	if err := os.MkdirAll(storage, 0o700); err != nil {
		t.Fatalf("atlstest: storage: %v", err)
	}
	z.lib = swConfig("libapi", storage, dir, []string{pki.CAFile}, metadata)
	// Create the CMC once: provisions the sw attestation key on disk and serves the stand-in.
	proverMu.Lock()
	c, err := cmc.NewCmc(z.lib)
	proverMu.Unlock()
	if err != nil {
		t.Fatalf("atlstest: CMC for zone %s: %v", name, err)
	}
	z.c = c
	return z
}

// swConfig is the CMC configuration of a zone attesting with the sw driver (mock evidence, no
// TEE): signed metadata read from the directory metadata, trust anchors rootCas, the sw
// attestation key kept in storage, caches under dir. api selects how the CMC is reached:
// "libapi" in process, "grpc" for a cmcd.
func swConfig(api, storage, dir string, rootCas []string, metadata string) *cmc.Config {
	return &cmc.Config{
		Drivers:          []string{"sw"},
		Ctr:              true,
		CtrDriver:        "sw",
		HashAlg:          "SHA-256",
		Api:              api,
		Storage:          storage,
		Cache:            filepath.Join(dir, "cache"),
		RootCas:          rootCas,
		MetadataLocation: []string{"file://" + metadata},
		// NewCmc requires an endorser and an enroller. The sw driver uses neither; "direct"
		// contacts vendors only for TDX/SNP, and the enrollment address is never reached
		// because TLS keys come from tls.Config.
		EndorsementMode: "direct",
		VendorCache:     filepath.Join(dir, "vendor-cache"),
		EnrollmentMode:  "est",
		EnrollmentAddr:  "https://127.0.0.1:1/never-contacted",
	}
}

// LibAPIConfig returns the zone's in-process CMC configuration, for tests that drive CMC's
// attestedtls package directly to pin its behaviour.
func (z *Zone) LibAPIConfig() *cmc.Config {
	mustTest()
	return z.lib
}

// TLSConfig returns a tls.Config with the zone's certificate and the PKI as trust anchor.
func (z *Zone) TLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{z.Cert},
		RootCAs:      z.PKI.Pool,
		ClientCAs:    z.PKI.Pool,
	}
}

// Config returns an atls.Config for this zone expecting peer, attesting through the zone's
// stand-in cmcd over gRPC — the production attester path.
func (z *Zone) Config(t testing.TB, peer *Zone) atls.Config {
	mustTest()
	t.Helper()
	return atls.Config{
		TLS:                  z.TLSConfig(),
		CmcdAddr:             z.StartCmcd(t),
		ExpectedPeerIdentity: peer.Identity,
	}
}

// InProcessConfig returns an atls.Config for this zone expecting peer, attesting through the
// in-process CMC (libapi backend).
func (z *Zone) InProcessConfig(peer *Zone) atls.Config {
	mustTest()
	return InProcess(atls.Config{
		TLS:                  z.TLSConfig(),
		ExpectedPeerIdentity: peer.Identity,
	}, z)
}

// InProcess returns cfg attesting through zone's in-process CMC (libapi backend) instead of a
// cmcd. CMC's libapi re-initialises its process-global drivers on every call, so handshakes
// through it must not run concurrently with other CMC use in the process (see the package
// documentation of atls).
func InProcess(cfg atls.Config, zone *Zone) atls.Config {
	mustTest()
	return testhook.InProcess(cfg, zone.lib).(atls.Config)
}

// ForceVerdict makes CMC see every attestation result of cfg's end with the given status
// ("success", "warn" or "fail"), as if its verifier had produced it.
func ForceVerdict(cfg atls.Config, status string) atls.Config {
	mustTest()
	return testhook.RewriteResult(cfg, func(r *ar.AttestationResult) bool {
		r.Summary.Status = ar.Status(status)
		return true
	}).(atls.Config)
}

// DropResult hides every attestation result of cfg's end from the wrapper, as if CMC had
// produced none.
func DropResult(cfg atls.Config) atls.Config {
	mustTest()
	return testhook.RewriteResult(cfg, func(*ar.AttestationResult) bool { return false }).(atls.Config)
}

// OnResult calls fn with the status of every attestation result of cfg's end, in CMC's result
// callback, before CMC acts on the result.
func OnResult(cfg atls.Config, fn func(status string)) atls.Config {
	mustTest()
	return testhook.RewriteResult(cfg, func(r *ar.AttestationResult) bool {
		fn(string(r.Summary.Status))
		return true
	}).(atls.Config)
}

// Report returns an attestation report of the zone whose nonce is nonce, JSON serialized.
func (z *Zone) Report(t testing.TB, nonce []byte) []byte {
	mustTest()
	t.Helper()
	ser, err := ar.NewJsonSerializer()
	if err != nil {
		t.Fatalf("atlstest: serializer: %v", err)
	}
	proverMu.Lock()
	defer proverMu.Unlock()
	report, err := prover.Generate(nonce, nil, z.c.GetMetadata(), z.c.Drivers, ser, z.c.HashAlg)
	if err != nil {
		t.Fatalf("atlstest: report: %v", err)
	}
	return report
}

// writeMetadata writes the minimum signed metadata CMC's verifier accepts: an image description
// listing one root manifest. Both are JWS-signed by a certificate of the zone PKI.
func writeMetadata(t testing.TB, dir string, pki *PKI, zone string, notBefore, notAfter time.Time) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("atlstest: metadata dir: %v", err)
	}
	cert, key := pki.signer(t, "metadata-signer."+zone)
	validity := &ar.Validity{
		NotBefore: notBefore.UTC().Format(time.RFC3339),
		NotAfter:  notAfter.UTC().Format(time.RFC3339),
	}
	// CMC requires metadata versions to be RFC 3339 timestamps.
	version := time.Now().UTC().Format(time.RFC3339)
	manifest := zone + "-root"
	items := map[string]ar.Metadata{
		"manifest.json": {
			MetaInfo: ar.MetaInfo{Type: ar.TYPE_MANIFEST, Name: manifest, Version: version, Validity: validity},
			Manifest: ar.Manifest{BaseLayers: []string{manifest}},
		},
		"image-description.json": {
			MetaInfo: ar.MetaInfo{Type: ar.TYPE_IMAGE_DESCRIPTION, Name: zone + "-image", Version: version, Validity: validity},
			ImageDescription: ar.ImageDescription{Descriptions: []ar.ManifestDescription{
				{Type: ar.TYPE_MANIFEST_DESCRIPTION, Name: manifest, Manifest: manifest},
			}},
		},
	}
	for file, m := range items {
		payload, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("atlstest: marshal %s: %v", file, err)
		}
		signed := signJWS(t, payload, key, cert, pki.CA)
		if err := os.WriteFile(filepath.Join(dir, file), signed, 0o600); err != nil {
			t.Fatalf("atlstest: write %s: %v", file, err)
		}
	}
	return dir
}

// signJWS signs payload as CMC does for JSON metadata: a JWS in full serialization with the
// signer's chain in the x5c header.
func signJWS(t testing.TB, payload []byte, key *ecdsa.PrivateKey, chain ...*x509.Certificate) []byte {
	t.Helper()
	x5c := make([]string, len(chain))
	for i, c := range chain {
		x5c[i] = base64.StdEncoding.EncodeToString(c.Raw)
	}
	opts := (&jose.SignerOptions{}).WithHeader("x5c", x5c)
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, opts)
	if err != nil {
		t.Fatalf("atlstest: signer: %v", err)
	}
	obj, err := s.Sign(payload)
	if err != nil {
		t.Fatalf("atlstest: sign: %v", err)
	}
	return []byte(obj.FullSerialize())
}
