package atlstest

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Fraunhofer-AISEC/cmc/cmc"
)

// Environment variables of the fixture writer.
const (
	// fixtureDirEnv names the directory TestWriteFixtures writes to. Unset: the test does nothing.
	fixtureDirEnv = "ATLS_FIXTURE_DIR"
	// fixtureCmcdEnv + "A" / "B" set the address each zone's cmcd listens on.
	fixtureCmcdEnv = "ATLS_FIXTURE_CMCD_"
)

// fixtureZones are the zones the writer produces, with the default address of each zone's cmcd.
var fixtureZones = []struct{ name, cmcdAddr string }{
	{"a", "127.0.0.1:9955"},
	{"b", "127.0.0.1:9956"},
}

// cmcdConfig is the JSON configuration file of CMC's cmcd v0.9.15 (cmcd/config.go): the CMC
// configuration plus logging.
type cmcdConfig struct {
	LogLevel string `json:"logLevel,omitempty"`
	cmc.Config
}

// fixtureIndex is written as fixtures.json: what the directory holds, without any secret.
type fixtureIndex struct {
	GeneratedAt string                 `json:"generatedAt"`
	ValidUntil  string                 `json:"validUntil"`
	Zones       map[string]fixtureZone `json:"zones"`
	Relay       map[string]fixtureCert `json:"relay"`
}

type fixtureZone struct {
	Identity string `json:"identity"`
	CA       string `json:"ca"`
	Cert     string `json:"cert"`
	Key      string `json:"key"`
	Metadata string `json:"metadata"`
	Cmcd     string `json:"cmcdConfig"`
	CmcdAddr string `json:"cmcdAddr"`
}

type fixtureCert struct {
	Identity string `json:"identity"`
	Cert     string `json:"cert"`
	Key      string `json:"key"`
}

// TestWriteFixtures writes, when ATLS_FIXTURE_DIR names an absolute directory, the material two
// zones need to run the attested channel against real cmcd processes:
//
//	zone-<z>/ca.pem       the zone's CA certificate (each zone has its own CA)
//	zone-<z>/cert.pem     the zone's mTLS certificate, identity spiffe://<z>/gateway
//	zone-<z>/key.pem      its private key
//	zone-<z>/metadata/    metadata signed by a signer the zone's CA issued
//	zone-<z>/cmcd.json    the zone's cmcd configuration (sw driver, no enrolment server)
//	relay/as-zone-<z>.*   a second certificate and key carrying zone <z>'s identity, for the
//	                      man-in-the-middle relay of the tampered-binding proof
//	fixtures.json         index of the above
//
// Both CAs are trust anchors of both zones. Everything is valid for one hour. The CA and
// metadata-signer keys are never written; the zone and relay keys are written only below the
// output directory. Without the variable the test does nothing.
func TestWriteFixtures(t *testing.T) {
	dir := os.Getenv(fixtureDirEnv)
	if dir == "" {
		return
	}
	if !filepath.IsAbs(dir) {
		t.Fatalf("%s must be an absolute path, got %q", fixtureDirEnv, dir)
	}
	addrs := map[string]string{}
	for _, z := range fixtureZones {
		addrs[z.name] = z.cmcdAddr
		if v := os.Getenv(fixtureCmcdEnv + strings.ToUpper(z.name)); v != "" {
			addrs[z.name] = v
		}
	}
	idx := writeFixtures(t, dir, addrs)
	t.Logf("wrote fixtures for zones a and b to %s (valid until %s)", dir, idx.ValidUntil)
}

// TestFixturesAreUsable writes the fixtures into the test's temporary directory and checks what
// the proofs rely on: distinct CAs that are both trust anchors of both zones, certificates
// carrying the zone identities, and a cmcd configuration CMC accepts and loads metadata from.
func TestFixturesAreUsable(t *testing.T) {
	dir := t.TempDir()
	idx := writeFixtures(t, dir, map[string]string{"a": "127.0.0.1:9955", "b": "127.0.0.1:9956"})

	cas := map[string]*x509.Certificate{}
	for name, z := range idx.Zones {
		cas[name] = readCert(t, z.CA)
	}
	if cas["a"].Equal(cas["b"]) || cas["a"].Subject.CommonName == cas["b"].Subject.CommonName {
		t.Fatal("zones a and b share a CA")
	}

	for name, z := range idx.Zones {
		leaf := readCert(t, z.Cert)
		if len(leaf.URIs) != 1 || leaf.URIs[0].String() != "spiffe://"+name+"/gateway" {
			t.Fatalf("zone %s certificate carries %v", name, leaf.URIs)
		}
		if err := leaf.CheckSignatureFrom(cas[name]); err != nil {
			t.Fatalf("zone %s certificate is not issued by its CA: %v", name, err)
		}
		relay := readCert(t, idx.Relay[name].Cert)
		if relay.URIs[0].String() != z.Identity || relay.Equal(leaf) {
			t.Fatalf("relay certificate for zone %s: identity %v", name, relay.URIs)
		}
		if err := relay.CheckSignatureFrom(cas[name]); err != nil {
			t.Fatalf("relay certificate for zone %s is not issued by its CA: %v", name, err)
		}

		raw, err := os.ReadFile(z.Cmcd)
		if err != nil {
			t.Fatal(err)
		}
		var cfg cmcdConfig
		if err := json.Unmarshal(raw, &cfg); err != nil {
			t.Fatalf("zone %s cmcd.json: %v", name, err)
		}
		if !slices.Equal(cfg.RootCas, []string{idx.Zones["a"].CA, idx.Zones["b"].CA}) {
			t.Fatalf("zone %s trust anchors are %v, want both CAs", name, cfg.RootCas)
		}
		if cfg.Api != "grpc" || cfg.CmcAddr != z.CmcdAddr || !slices.Equal(cfg.Drivers, []string{"sw"}) {
			t.Fatalf("zone %s cmcd.json: api %q, address %q, drivers %v", name, cfg.Api, cfg.CmcAddr, cfg.Drivers)
		}
		// The same code path cmcd runs at start: read the anchors, load and check the metadata,
		// provision the sw attestation key in the zone's own storage.
		proverMu.Lock()
		c, err := cmc.NewCmc(&cfg.Config)
		proverMu.Unlock()
		if err != nil {
			t.Fatalf("zone %s: CMC refuses the generated configuration: %v", name, err)
		}
		if n := len(c.GetMetadata()); n != 2 {
			t.Fatalf("zone %s: CMC loaded %d metadata items, want 2", name, n)
		}
	}

	// Private keys exist only where the index says.
	var keys []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(raw), "PRIVATE KEY") {
			keys = append(keys, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{idx.Relay["a"].Key, idx.Relay["b"].Key, idx.Zones["a"].Key, idx.Zones["b"].Key}
	slices.Sort(keys)
	slices.Sort(want)
	if !slices.Equal(keys, want) {
		t.Fatalf("PEM private keys at %v, want only %v", keys, want)
	}
}

// writeFixtures writes the two zones' material below dir and returns its index.
func writeFixtures(t *testing.T, dir string, cmcdAddrs map[string]string) fixtureIndex {
	t.Helper()
	now := time.Now()
	notBefore, notAfter := now.Add(-time.Minute), now.Add(time.Hour)
	idx := fixtureIndex{
		GeneratedAt: now.UTC().Format(time.RFC3339),
		ValidUntil:  notAfter.UTC().Format(time.RFC3339),
		Zones:       map[string]fixtureZone{},
		Relay:       map[string]fixtureCert{},
	}

	// One CA per zone; every zone trusts both.
	pkis := map[string]*PKI{}
	var rootCas []string
	for _, z := range fixtureZones {
		pkis[z.name] = newPKI(t, "atlstest zone "+z.name+" CA")
		zdir := filepath.Join(dir, "zone-"+z.name)
		mkdir(t, zdir)
		ca := filepath.Join(zdir, "ca.pem")
		writeFile(t, ca, certPEM(pkis[z.name].CA.Raw))
		rootCas = append(rootCas, ca)
	}

	mkdir(t, filepath.Join(dir, "relay"))
	for _, z := range fixtureZones {
		pki := pkis[z.name]
		zdir := filepath.Join(dir, "zone-"+z.name)
		identity := "spiffe://" + z.name + "/gateway"

		fz := fixtureZone{
			Identity: identity,
			CA:       filepath.Join(zdir, "ca.pem"),
			Cert:     filepath.Join(zdir, "cert.pem"),
			Key:      filepath.Join(zdir, "key.pem"),
			Metadata: filepath.Join(zdir, "metadata"),
			Cmcd:     filepath.Join(zdir, "cmcd.json"),
			CmcdAddr: cmcdAddrs[z.name],
		}
		writeCertAndKey(t, pki, identity, fz.Cert, fz.Key)
		writeMetadata(t, fz.Metadata, pki, z.name, notBefore, notAfter)

		// Unlike the in-process zones of NewZone, each cmcd is its own process with its own sw
		// attestation key, so every zone gets its own storage.
		cfg := cmcdConfig{
			LogLevel: "info",
			Config:   *swConfig("grpc", filepath.Join(zdir, "storage"), zdir, rootCas, fz.Metadata),
		}
		cfg.CmcAddr = fz.CmcdAddr
		raw, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			t.Fatalf("atlstest: marshal cmcd config: %v", err)
		}
		writeFile(t, fz.Cmcd, append(raw, '\n'))
		idx.Zones[z.name] = fz

		// The relay's certificates: issued by the same CA, same identity, another key.
		fc := fixtureCert{
			Identity: identity,
			Cert:     filepath.Join(dir, "relay", "as-zone-"+z.name+".cert.pem"),
			Key:      filepath.Join(dir, "relay", "as-zone-"+z.name+".key.pem"),
		}
		writeCertAndKey(t, pki, identity, fc.Cert, fc.Key)
		idx.Relay[z.name] = fc
	}

	raw, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		t.Fatalf("atlstest: marshal fixture index: %v", err)
	}
	writeFile(t, filepath.Join(dir, "fixtures.json"), append(raw, '\n'))
	return idx
}

func writeCertAndKey(t *testing.T, pki *PKI, identity, certFile, keyFile string) {
	t.Helper()
	c := pki.Issue(t, identity)
	key, err := keyPEM(c.PrivateKey)
	if err != nil {
		t.Fatalf("atlstest: marshal key: %v", err)
	}
	writeFile(t, certFile, certPEM(c.Certificate[0]))
	writeFile(t, keyFile, key)
}

func mkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("atlstest: %v", err)
	}
}

func writeFile(t *testing.T, file string, data []byte) {
	t.Helper()
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatalf("atlstest: %v", err)
	}
}

func readCert(t *testing.T, file string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatalf("%s holds no PEM block", file)
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	return c
}
