package cosignverify

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// The predicate schemas, vendored and pinned by SHA256SUMS: CycloneDX 1.5, 1.6 and 1.7 with the
// schemas they reference (CycloneDX/specification tag 1.7.2), and the mock-attestation schema (a
// copy of docs/attestation/mock-attestation.schema.json, kept identical by a test).
//
//go:embed schemas/*.json schemas/SHA256SUMS
var schemaFS embed.FS

const (
	cycloneDXBase = "http://cyclonedx.org/schema/"
	mockSchemaURL = "https://facis.eu/ztd/mock-attestation.schema.json"
)

// sbomVersions maps an accepted CycloneDX specVersion to its schema.
var sbomVersions = map[string]string{"1.5": "bom-1.5.schema.json", "1.6": "bom-1.6.schema.json", "1.7": "bom-1.7.schema.json"}

type compiledSchemas struct {
	sbom map[string]*jsonschema.Schema
	mock *jsonschema.Schema
}

// schemas compiles the vendored schemas once. A checksum mismatch or a compile error is a build
// defect, reported by every verification that needs them (and by the tests).
var schemas = sync.OnceValues(func() (*compiledSchemas, error) {
	sums, err := schemaFS.ReadFile("schemas/SHA256SUMS")
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	// No loader for http(s): every reference must resolve to a vendored resource, never a download.
	c.UseLoader(jsonschema.SchemeURLLoader{})
	for _, line := range strings.Split(strings.TrimSpace(string(sums)), "\n") {
		want, name, ok := strings.Cut(line, "  ")
		if !ok {
			return nil, fmt.Errorf("schemas/SHA256SUMS: malformed line %q", line)
		}
		b, err := schemaFS.ReadFile("schemas/" + name)
		if err != nil {
			return nil, err
		}
		if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != want {
			return nil, fmt.Errorf("schemas/%s: checksum mismatch", name)
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err != nil {
			return nil, fmt.Errorf("schemas/%s: %w", name, err)
		}
		url := cycloneDXBase + name
		if name == "mock-attestation.schema.json" {
			url = mockSchemaURL
		}
		if err := c.AddResource(url, doc); err != nil {
			return nil, err
		}
	}
	out := &compiledSchemas{sbom: map[string]*jsonschema.Schema{}}
	for version, name := range sbomVersions {
		if out.sbom[version], err = c.Compile(cycloneDXBase + name); err != nil {
			return nil, err
		}
	}
	if out.mock, err = c.Compile(mockSchemaURL); err != nil {
		return nil, err
	}
	return out, nil
})

// ValidateMockPredicate checks a mock-attestation predicate against the schema the verifier enforces,
// so a producer can refuse to attest what admission would refuse.
func ValidateMockPredicate(predicate []byte) error {
	s, err := schemas()
	if err != nil {
		return err
	}
	return validateWith(s.mock, predicate)
}
