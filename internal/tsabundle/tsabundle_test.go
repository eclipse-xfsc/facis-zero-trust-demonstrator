package tsabundle

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"os"
	"testing"
	"time"
)

const policyDir = "../../policies/tsa/facis/guard/1.0"

var coords = Coordinates{Repository: "policies", Group: "facis", Name: "guard", Version: "1.0"}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// sign signs as `cosign sign-blob` does: ECDSA over the SHA-256 of the signing input.
func sign(t *testing.T, k *ecdsa.PrivateKey, innerZip []byte) []byte {
	t.Helper()
	d := sha256.Sum256(SigningInput(innerZip))
	sig, err := ecdsa.SignASN1(rand.Reader, k, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func bundle(t *testing.T, k *ecdsa.PrivateKey, revision string) []byte {
	t.Helper()
	innerZip, err := Pack(policyDir, "", coords, revision, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	outer, err := Seal(innerZip, sign(t, k, innerZip), &k.PublicKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return outer
}

// rebuild re-packs a bundle's inner zip through edit, keeping the original signature.
func rebuild(t *testing.T, outer []byte, edit func([]file) []file) []byte {
	t.Helper()
	files, err := unzip(outer)
	if err != nil {
		t.Fatal(err)
	}
	parts, err := unzip(files[0].body)
	if err != nil {
		t.Fatal(err)
	}
	var entries [][2]string
	for _, p := range edit(parts) {
		entries = append(entries, [2]string{p.name, string(p.body)})
	}
	innerZip, _ := zipOf(entries, time.Now())
	out, _ := zipOf([][2]string{{inner, string(innerZip)}, {signature, string(files[1].body)}}, time.Now())
	return out
}

func TestOpenAcceptsOnlyWhatTheTrustRootSigned(t *testing.T) {
	trusted, other := newKey(t), newKey(t)
	good := bundle(t, trusted, "v1")
	expect := Expect{Key: &trusted.PublicKey, Coordinates: coords, Revision: "v1"}
	if err := Open(good, expect); err != nil {
		t.Fatalf("signed bundle refused: %v", err)
	}
	resign := func(b []byte) []byte { // a validly signed bundle with altered content
		files, _ := unzip(b)
		out, _ := Seal(files[0].body, sign(t, trusted, files[0].body), &trusted.PublicKey, time.Now())
		return out
	}
	withMeta := func(edit func(*metadata)) []byte {
		return resign(rebuild(t, good, func(ps []file) []file {
			var m metadata
			_ = json.Unmarshal(ps[0].body, &m)
			edit(&m)
			ps[0].body, _ = json.Marshal(m)
			return ps
		}))
	}
	for name, c := range map[string]struct {
		outer  []byte
		expect Expect
	}{
		"other key":         {bundle(t, other, "v1"), expect},
		"declared revision": {good, Expect{Key: &trusted.PublicKey, Coordinates: coords, Revision: "v2"}},
		"other policy":      {good, Expect{Key: &trusted.PublicKey, Coordinates: Coordinates{"policies", "facis", "other", "1.0"}, Revision: "v1"}},
		"tampered policy": {rebuild(t, good, func(ps []file) []file {
			ps[1].body = []byte("package facis.guard\ndecision := {\"allow\": true}\n")
			return ps
		}), expect},
		"foreign key URL": {withMeta(func(m *metadata) { m.PublicKeyURL = "https://attacker.invalid/key.json" }), expect},
		"locked":          {withMeta(func(m *metadata) { m.Policy.Locked = true }), expect},
		"external data": {resign(rebuild(t, good, func(ps []file) []file {
			return append(ps, file{"data-config.json", []byte(`{"url":"https://attacker.invalid"}`)})
		})), expect},
		"metadata not first": {resign(rebuild(t, good, func(ps []file) []file { return []file{ps[1], ps[0], ps[2]} })), expect},
		"unsigned": {func() []byte {
			f, _ := unzip(good)
			o, _ := zipOf([][2]string{{inner, string(f[0].body)}}, time.Now())
			return o
		}(), expect},
		"not a zip": {[]byte("PK\x03\x04 nonsense"), expect},
	} {
		t.Run(name, func(t *testing.T) {
			if err := Open(c.outer, c.expect); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestPackRefusesAPresetRevision(t *testing.T) {
	dir := t.TempDir()
	data := dir + "/data.json"
	if err := os.WriteFile(data, []byte(`{"bundle":{"revision":"forged"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Pack(policyDir, data, coords, "v1", time.Now()); err == nil {
		t.Fatal("publisher revision overridable from data")
	}
}
