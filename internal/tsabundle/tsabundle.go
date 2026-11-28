// Package tsabundle builds, verifies and activates Rego policy bundles for the XFSC TSA policy
// service (eclipse-xfsc/custom-policy-agent). The bundle is the TSA's own import format, an outer
// zip holding policy_bundle.zip and signature.raw, so the TSA can import it unchanged; this package
// adds what the TSA does not do: verification against a pinned trust root before anything is loaded.
//
// The TSA's own import check fetches the verification key from the URL the bundle names, so on its
// own it proves nothing about origin. A bundle is accepted here only if it is signed by the trust
// root, names the pod-local trust-root URL (KeyURL), targets the configured policy and carries the
// revision Git declared.
package tsabundle

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/cosignverify"
)

const (
	// MediaType is the OCI layer type of a published bundle.
	MediaType = "application/vnd.facis.tsa.bundle.v1+zip"
	// KeyURL is where the bundle sidecar serves the trust root inside the TSA pod. It is part of the
	// signed metadata, so the TSA can fetch no other key for a bundle this package accepted.
	KeyURL = "http://127.0.0.1:8080/trust-root.json"

	maxBundle = 1 << 20
	inner     = "policy_bundle.zip" // names the TSA's import requires, in this order
	signature = "signature.raw"
)

// Coordinates name a policy in the TSA: /policy/{repository}/{group}/{name}/{version}/evaluation.
// The Rego package must be "{group}.{name}". A bundle's version is its revision (At); the configured
// version only names the path the sidecar serves to the IF-05 adapters.
type Coordinates struct {
	Repository string `json:"repository"`
	Group      string `json:"group"`
	Name       string `json:"name"`
	Version    string `json:"version"`
}

var segment = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Validate refuses coordinates that cannot be a URL path segment or a Rego package name.
func (c Coordinates) Validate() error {
	for _, s := range []string{c.Repository, c.Group, c.Name, c.Version} {
		if !segment.MatchString(s) || s == "." || s == ".." {
			return errors.New("policy coordinates must be plain path segments")
		}
	}
	return nil
}

// At is the policy as one bundle revision is stored in the TSA: the revision is its version. Each
// revision therefore has its own TSA key and cache entry, and switching revisions never depends on
// the TSA dropping a cached policy (which it does unreliably, see Syncer).
func (c Coordinates) At(revision string) Coordinates {
	c.Version = revision
	return c
}

// EvaluationPath is the TSA path that evaluates the policy.
func (c Coordinates) EvaluationPath() string {
	return "/policy/" + c.Repository + "/" + c.Group + "/" + c.Name + "/" + c.Version + "/evaluation"
}

type metadata struct {
	Policy struct {
		Name       string    `json:"name"`
		Group      string    `json:"group"`
		Version    string    `json:"version"`
		Repository string    `json:"repository"`
		Locked     bool      `json:"locked"`
		LastUpdate time.Time `json:"lastUpdate"`
	} `json:"policy"`
	PublicKeyURL string `json:"publicKeyURL"`
}

// Pack builds the inner policy_bundle.zip from a policy directory holding policy.rego and data.json:
// metadata.json first (the TSA requires it, with the revision as the policy version), then the
// policy, then the data with data.bundle.revision set to revision. dataFile, when not empty, replaces the directory's data.json
// (a zone's own configuration).
func Pack(dir, dataFile string, c Coordinates, revision string, now time.Time) ([]byte, error) {
	c = c.At(revision)
	if err := c.Validate(); err != nil {
		return nil, errors.New("coordinates or revision invalid: revisions are [A-Za-z0-9._-], at most 64")
	}
	rego, err := os.ReadFile(filepath.Join(dir, "policy.rego"))
	if err != nil {
		return nil, err
	}
	if dataFile == "" {
		dataFile = filepath.Join(dir, "data.json")
	}
	raw, err := os.ReadFile(dataFile)
	if err != nil {
		return nil, err
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil || data == nil {
		return nil, errors.New("data.json must be a JSON object")
	}
	if _, ok := data["bundle"]; ok {
		return nil, errors.New("data.json must not set bundle: the revision is the publisher's")
	}
	data["bundle"] = map[string]string{"revision": revision}
	var m metadata
	m.Policy.Repository, m.Policy.Group, m.Policy.Name, m.Policy.Version = c.Repository, c.Group, c.Name, c.Version
	m.Policy.LastUpdate = now.UTC()
	m.PublicKeyURL = KeyURL
	meta, _ := json.Marshal(m)
	dataJSON, _ := json.Marshal(data)
	return zipOf([][2]string{{"metadata.json", string(meta)}, {"policy.rego", string(rego)}, {"data.json", string(dataJSON)}}, now)
}

// SigningInput is what the signer signs: the TSA verifies an ECDSA/SHA-256 signature over the
// SHA-256 of policy_bundle.zip, so `cosign sign-blob` is given this digest, not the zip.
func SigningInput(innerZip []byte) []byte {
	d := sha256.Sum256(innerZip)
	return d[:]
}

// Seal checks sig against key and builds the outer bundle the TSA imports.
func Seal(innerZip, sig []byte, key *ecdsa.PublicKey, now time.Time) ([]byte, error) {
	if !verify(innerZip, sig, key) {
		return nil, errors.New("signature does not verify with the given key")
	}
	return zipOf([][2]string{{inner, string(innerZip)}, {signature, string(sig)}}, now)
}

func verify(innerZip, sig []byte, key *ecdsa.PublicKey) bool {
	d := sha256.Sum256(SigningInput(innerZip))
	return ecdsa.VerifyASN1(key, d[:], sig)
}

// Expect is what an acceptable bundle must match.
type Expect struct {
	Key         *ecdsa.PublicKey
	Coordinates Coordinates
	Revision    string
}

// Open verifies an outer bundle before anything loads it: exactly the two entries the TSA imports,
// a signature by the trust root, metadata naming KeyURL and the expected policy, only policy.rego and
// data.json beside it (no data-config.json: the TSA would fetch data from wherever it names), and
// data.bundle.revision equal to the expected revision.
func Open(outer []byte, e Expect) error {
	files, err := unzip(outer)
	if err != nil {
		return err
	}
	if len(files) != 2 || files[0].name != inner || files[1].name != signature {
		return errors.New("bundle must hold policy_bundle.zip then signature.raw")
	}
	if !verify(files[0].body, files[1].body, e.Key) {
		return errors.New("bundle signature does not verify with the trust root")
	}
	parts, err := unzip(files[0].body)
	if err != nil {
		return err
	}
	if len(parts) == 0 || parts[0].name != "metadata.json" {
		return errors.New("policy bundle must start with metadata.json")
	}
	seen := map[string][]byte{}
	for _, p := range parts {
		if _, dup := seen[p.name]; dup {
			return fmt.Errorf("duplicate %s", p.name)
		}
		switch p.name {
		case "metadata.json", "policy.rego", "data.json":
			seen[p.name] = p.body
		default:
			return fmt.Errorf("policy bundle must not contain %q", p.name)
		}
	}
	var m metadata
	if err := json.Unmarshal(seen["metadata.json"], &m); err != nil {
		return errors.New("metadata.json invalid")
	}
	got := Coordinates{m.Policy.Repository, m.Policy.Group, m.Policy.Name, m.Policy.Version}
	switch {
	case m.PublicKeyURL != KeyURL:
		return errors.New("bundle names a key URL other than the pod-local trust root")
	case got != e.Coordinates.At(e.Revision):
		return errors.New("bundle targets another policy")
	case m.Policy.Locked:
		return errors.New("bundle is locked")
	case len(seen["policy.rego"]) == 0:
		return errors.New("bundle has no policy.rego")
	}
	var data struct {
		Bundle struct {
			Revision string `json:"revision"`
		} `json:"bundle"`
	}
	if json.Unmarshal(seen["data.json"], &data) != nil || data.Bundle.Revision == "" {
		return errors.New("bundle data names no revision")
	}
	if data.Bundle.Revision != e.Revision {
		return fmt.Errorf("bundle revision %q is not the declared %q", data.Bundle.Revision, e.Revision)
	}
	return nil
}

// JWKS is the trust root as the JWK set the TSA fetches from KeyURL; the TSA uses its first key.
func JWKS(key *ecdsa.PublicKey) []byte {
	enc := base64.RawURLEncoding.EncodeToString
	// Uncompressed SEC 1 point: 0x04 || X || Y, each coordinate 32 bytes for P-256.
	point, err := key.Bytes()
	if err != nil || len(point) != 65 {
		return nil
	}
	out, _ := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256",
		"x": enc(point[1:33]), "y": enc(point[33:]),
	}}})
	return out
}

// TrustRoot is the single P-256 key of a PEM file (cosign.pub). One key, because the TSA verifies
// with the first key it is served; rotation is a new trust root and a re-signed bundle.
func TrustRoot(pemData []byte) (*ecdsa.PublicKey, error) {
	keys, err := cosignverify.ParsePublicKeys(pemData)
	if err != nil {
		return nil, err
	}
	if len(keys) != 1 {
		return nil, errors.New("trust root must be exactly one P-256 key")
	}
	return keys[0], nil
}

type file struct {
	name string
	body []byte
}

func zipOf(entries [][2]string, now time.Time) ([]byte, error) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, e := range entries {
		f, err := w.CreateHeader(&zip.FileHeader{Name: e[0], Method: zip.Deflate, Modified: now.UTC()})
		if err != nil {
			return nil, err
		}
		if _, err := io.WriteString(f, e[1]); err != nil {
			return nil, err
		}
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func unzip(b []byte) ([]file, error) {
	if len(b) > maxBundle {
		return nil, errors.New("bundle too large")
	}
	r, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return nil, errors.New("bundle is not a zip archive")
	}
	if len(r.File) > 8 {
		return nil, errors.New("bundle has too many entries")
	}
	var out []file
	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(io.LimitReader(rc, maxBundle+1))
		_ = rc.Close()
		if err != nil || len(body) > maxBundle {
			return nil, errors.New("bundle entry unreadable or too large")
		}
		out = append(out, file{f.Name, body})
	}
	return out, nil
}
