package provision

import (
	"bytes"
	"crypto"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/verifier"
)

const goodZone = `{"zone":"zone-x","validity_days":30,"components":[{"name":"gw","rootfs_sha256":"` +
	"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" +
	`","oci_config":{"ociVersion":"1.2.0","process":{"user":{"uid":1,"gid":1},"args":["/gw"],"cwd":"/"},"root":{"path":"rootfs"}}}]}`

func TestParseRefuses(t *testing.T) {
	if _, err := Parse([]byte(goodZone)); err != nil {
		t.Fatalf("the reference configuration: %v", err)
	}
	for name, edit := range map[string]func(string) string{
		"unknown field":     func(s string) string { return strings.Replace(s, `"zone":`, `"extra":1,"zone":`, 1) },
		"zone not a label":  func(s string) string { return strings.Replace(s, `"zone-x"`, `"Zone X"`, 1) },
		"validity zero":     func(s string) string { return strings.Replace(s, `"validity_days":30`, `"validity_days":0`, 1) },
		"validity too long": func(s string) string { return strings.Replace(s, `"validity_days":30`, `"validity_days":400`, 1) },
		"digest upper case": func(s string) string { return strings.Replace(s, "0123456789abcdef0", "0123456789ABCDEF0", 1) },
		"digest short":      func(s string) string { return strings.Replace(s, "0123456789abcdef\",", "\",", 1) },
		"no args":           func(s string) string { return strings.Replace(s, `"args":["/gw"],`, ``, 1) },
		"unknown oci field": func(s string) string { return strings.Replace(s, `"cwd":"/"`, `"cwd":"/","shell":true`, 1) },
		"no components":     func(s string) string { return s[:strings.Index(s, `"components"`)] + `"components":[]}` },
		"repeated component": func(s string) string {
			i := strings.Index(s, `{"name"`)
			c := s[i : len(s)-2]
			return s[:len(s)-2] + "," + c + "]}"
		},
		"identical measurement": func(s string) string {
			i := strings.Index(s, `{"name"`)
			c := strings.Replace(s[i:len(s)-2], `"name":"gw"`, `"name":"gw2"`, 1)
			return s[:len(s)-2] + "," + c + "]}"
		},
		"trailing data": func(s string) string { return s + "{}" },
	} {
		if _, err := Parse([]byte(edit(goodZone))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The measurement log and the reference values agree the way CMC's verifier checks them: the
// template hash it recomputes from a reference value equals the logged event's, and the aggregate
// is the extension of the logged template hashes.
func TestRenderAgreesWithCMC(t *testing.T) {
	z, err := Parse([]byte(goodZone))
	if err != nil {
		t.Fatal(err)
	}
	md, err := z.Metadata(time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	var manifest ar.Metadata
	if err := json.Unmarshal(md["manifest.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Validity.NotBefore != "2026-11-18T12:00:00Z" || manifest.Validity.NotAfter != "2026-12-18T12:00:00Z" {
		t.Errorf("validity %+v", manifest.Validity)
	}
	raw, err := z.MeasurementLog()
	if err != nil {
		t.Fatal(err)
	}
	var log ar.Artifact
	if err := json.Unmarshal(raw, &log); err != nil {
		t.Fatal(err)
	}
	ser, _ := ar.NewJsonSerializer()
	ref := manifest.Sbom.Components[0]
	if ta, _ := ref.GetTrustAnchor(); ta != ar.TRUST_ANCHOR_SW {
		t.Fatalf("trust anchor %q", ta)
	}
	event := log.Events[0]
	template, ok, err := verifier.ValidateTemplateHash(ser, &ref, event.CtrData)
	if err != nil || !ok || !bytes.Equal(template, event.GetHash(crypto.SHA256)) {
		t.Fatalf("CMC recomputes %x (ok %v, %v), the log holds %x", template, ok, err, event.GetHash(crypto.SHA256))
	}
	ms, _ := z.Measurements()
	extended := make([]byte, 32)
	h := crypto.SHA256.New()
	h.Write(extended)
	h.Write(template)
	if !bytes.Equal(Aggregate(ms), h.Sum(nil)) {
		t.Fatal("the aggregate is not the extension of the template hash")
	}
}

// A change of any measured value changes the aggregate the evidence signs.
func TestMeasuredChangeChangesAggregate(t *testing.T) {
	base, _ := Parse([]byte(goodZone))
	ms, _ := base.Measurements()
	for name, edit := range map[string]func(string) string{
		"rootfs":   func(s string) string { return strings.Replace(s, "0123456789abcdef0", "1123456789abcdef0", 1) },
		"oci args": func(s string) string { return strings.Replace(s, `"/gw"`, `"/gw2"`, 1) },
		"oci user": func(s string) string { return strings.Replace(s, `"uid":1`, `"uid":2`, 1) },
	} {
		z, err := Parse([]byte(edit(goodZone)))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		other, _ := z.Measurements()
		if bytes.Equal(Aggregate(ms), Aggregate(other)) {
			t.Errorf("%s: the aggregate did not change", name)
		}
	}
}

// The zone files in Git load.
func TestZoneFilesInGit(t *testing.T) {
	files, _ := filepath.Glob("../../../deployment/attestation/*.json")
	if len(files) == 0 {
		t.Fatal("no zone files")
	}
	for _, f := range files {
		z, err := Load(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSuffix(filepath.Base(f), ".json") != z.Zone {
			t.Errorf("%s names zone %s", f, z.Zone)
		}
	}
}
