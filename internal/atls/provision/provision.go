// Package provision turns a zone's attestation configuration, versioned in Git, into what CMC
// consumes: the unsigned manifest and image description that the pipeline signs and the zone's
// estserver serves (the reference values), and the container measurement log that cmcd's
// software driver signs into its evidence (the measured values). Both come from the same
// configuration, so a reviewed change to it is the only way the evidence or the reference values
// change (ADR-0011, class 3).
//
// It lives under internal/atls because it uses CMC's own types and hashing, which only
// internal/atls may import.
package provision

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/verifier"
	oci "github.com/opencontainers/runtime-spec/specs-go"
)

// Zone is one zone's attestation configuration as it is kept in Git.
type Zone struct {
	// Zone names the zone; it names the manifest and the image description.
	Zone string `json:"zone"`
	// ValidityDays is how long signed metadata stays valid from the moment it is signed.
	ValidityDays int `json:"validity_days"`
	// Components are the measured containers of the zone.
	Components []Component `json:"components"`
}

// Component is one measured container: what a container runtime would measure at launch.
type Component struct {
	Name string `json:"name"`
	// RootfsSha256 is the digest of the container's root filesystem, hex.
	RootfsSha256 string `json:"rootfs_sha256"`
	// OCIConfig is the container's OCI runtime configuration.
	OCIConfig json.RawMessage `json:"oci_config"`
}

var (
	dnsLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	hex256   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// maxValidityDays bounds the validity of signed metadata.
const maxValidityDays = 365

// Load reads and checks a zone configuration. Unknown fields are refused.
func Load(path string) (*Zone, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	z, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return z, nil
}

// Parse checks a zone configuration. Unknown fields are refused.
func Parse(raw []byte) (*Zone, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var z Zone
	if err := dec.Decode(&z); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("trailing data")
	}
	if err := z.check(); err != nil {
		return nil, err
	}
	return &z, nil
}

func (z *Zone) check() error {
	if !dnsLabel.MatchString(z.Zone) {
		return fmt.Errorf("zone %q is not a DNS label", z.Zone)
	}
	if z.ValidityDays < 1 || z.ValidityDays > maxValidityDays {
		return fmt.Errorf("validity_days %d is outside 1..%d", z.ValidityDays, maxValidityDays)
	}
	if len(z.Components) == 0 {
		return errors.New("no components")
	}
	seen := map[string]bool{}
	for _, c := range z.Components {
		if !dnsLabel.MatchString(c.Name) || seen[c.Name] {
			return fmt.Errorf("component name %q is not a DNS label or is repeated", c.Name)
		}
		seen[c.Name] = true
		if !hex256.MatchString(c.RootfsSha256) {
			return fmt.Errorf("component %s: rootfs_sha256 is not 64 lower-case hex digits", c.Name)
		}
		if _, err := c.spec(); err != nil {
			return fmt.Errorf("component %s: %w", c.Name, err)
		}
	}
	// CMC matches events to reference values by measurement and names each verified event after
	// the first reference that matches; two components with one measurement cannot be told apart.
	ms, err := z.Measurements()
	if err != nil {
		return err
	}
	byHash := map[string]string{}
	for _, m := range ms {
		if other, ok := byHash[string(m.TemplateHash)]; ok {
			return fmt.Errorf("components %s and %s have the same measurement", other, m.Name)
		}
		byHash[string(m.TemplateHash)] = m.Name
	}
	return nil
}

func (c Component) spec() (*oci.Spec, error) {
	dec := json.NewDecoder(bytes.NewReader(c.OCIConfig))
	dec.DisallowUnknownFields()
	var s oci.Spec
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("oci_config: %w", err)
	}
	if s.Version == "" || s.Process == nil || len(s.Process.Args) == 0 {
		return nil, errors.New("oci_config needs ociVersion and process.args")
	}
	return &s, nil
}

// Measurement is a component's measured values, as CMC computes them.
type Measurement struct {
	Name string
	// ConfigSha256 is CMC's hash of the canonical OCI configuration.
	ConfigSha256 []byte
	// RootfsSha256 is the root filesystem digest.
	RootfsSha256 []byte
	// TemplateHash is sha256(ConfigSha256 ‖ RootfsSha256): the value extended into the sw
	// driver's aggregate and the one ADR-0011 § 4.1 publishes into TRAIN.
	TemplateHash []byte
}

// Measurements computes each component's measured values, in configuration order.
func (z *Zone) Measurements() ([]Measurement, error) {
	out := make([]Measurement, 0, len(z.Components))
	for _, c := range z.Components {
		spec, err := c.spec()
		if err != nil {
			return nil, err
		}
		config, err := verifier.CalculateSpecHash(spec)
		if err != nil {
			return nil, fmt.Errorf("component %s: %w", c.Name, err)
		}
		rootfs, _ := hex.DecodeString(c.RootfsSha256)
		h := sha256.Sum256(append(append([]byte{}, config...), rootfs...))
		out = append(out, Measurement{Name: c.Name, ConfigSha256: config, RootfsSha256: rootfs, TemplateHash: h[:]})
	}
	return out, nil
}

// Aggregate is the value the sw driver signs into its evidence: every template hash extended, in
// order, into 32 zero bytes.
func Aggregate(ms []Measurement) []byte {
	agg := make([]byte, 32)
	for _, m := range ms {
		h := sha256.Sum256(append(agg, m.TemplateHash...))
		agg = h[:]
	}
	return agg
}

// Metadata renders the zone's unsigned metadata, by file name: the manifest, whose reference
// values are the components, and the image description listing it. Both carry signedAt as their
// version and are valid from then for ValidityDays.
func (z *Zone) Metadata(signedAt time.Time) (map[string][]byte, error) {
	signedAt = signedAt.UTC().Truncate(time.Second)
	validity := &ar.Validity{
		NotBefore: signedAt.Format(time.RFC3339),
		NotAfter:  signedAt.AddDate(0, 0, z.ValidityDays).Format(time.RFC3339),
	}
	// CMC requires metadata versions to be RFC 3339 timestamps and keeps the newest of two.
	version := signedAt.Format(time.RFC3339)
	manifest := z.Zone + "-manifest"
	refs := make([]ar.Component, 0, len(z.Components))
	for _, c := range z.Components {
		spec, err := c.spec()
		if err != nil {
			return nil, err
		}
		rootfs, _ := hex.DecodeString(c.RootfsSha256)
		ref := ar.Component{
			Type:    ar.TYPE_APP,
			Name:    c.Name,
			Hashes:  []ar.ReferenceHash{{Alg: crypto.SHA256.String(), Content: rootfs}},
			CtrData: &ar.CtrData{RootfsSha256: rootfs, OciSpec: spec},
		}
		ref.SetTrustAnchor(ar.TRUST_ANCHOR_SW)
		refs = append(refs, ref)
	}
	items := map[string]ar.Metadata{
		"manifest.json": {
			MetaInfo: ar.MetaInfo{Type: ar.TYPE_MANIFEST, Name: manifest, Version: version, Validity: validity},
			Manifest: ar.Manifest{
				BaseLayers: []string{manifest},
				Sbom:       &ar.Sbom{BomFormat: "CycloneDX", SpecVersion: "1.7", Components: refs},
			},
		},
		"image-description.json": {
			MetaInfo: ar.MetaInfo{Type: ar.TYPE_IMAGE_DESCRIPTION, Name: z.Zone + "-image", Version: version, Validity: validity},
			ImageDescription: ar.ImageDescription{Descriptions: []ar.ManifestDescription{
				{Type: ar.TYPE_MANIFEST_DESCRIPTION, Name: manifest, Manifest: manifest},
			}},
		},
	}
	out := map[string][]byte{}
	for file, m := range items {
		data, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			return nil, err
		}
		out[file] = data
	}
	return out, nil
}

// MeasurementLog renders the container measurement log cmcd's sw driver reads (its ctrLog): one
// event per component, as a container runtime records it at launch.
func (z *Zone) MeasurementLog() ([]byte, error) {
	ms, err := z.Measurements()
	if err != nil {
		return nil, err
	}
	log := ar.Artifact{Type: ar.TYPE_SW_EVENTLOG, Events: []ar.Component{}}
	for i, m := range ms {
		spec, _ := z.Components[i].spec()
		event := ar.Component{
			Type:    ar.TYPE_APP,
			Name:    m.Name,
			Hashes:  []ar.ReferenceHash{{Alg: crypto.SHA256.String(), Content: m.TemplateHash}},
			CtrData: &ar.CtrData{ConfigSha256: m.ConfigSha256, RootfsSha256: m.RootfsSha256, OciSpec: spec},
		}
		event.SetIndex(0)
		log.Events = append(log.Events, event)
	}
	return json.MarshalIndent(log, "", "  ")
}
