// Command mockattest writes the mock-attestation predicate of one TEE profile (ZT-71): the published
// sample for that profile (docs/attestation/samples), after checking it against the schema admission
// enforces. cosign wraps it in an in-toto Statement bound to the image digest.
//
//	go run ./cmd/mockattest -profile sw > mock.json
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/cosignverify"
)

var profilePattern = regexp.MustCompile(`^[a-z][a-z-]*$`)

func main() {
	profile := flag.String("profile", "sw", "TEE profile: sw, tpm, snp, sgx, tdx, azure-tpm, azure-snp or azure-tdx")
	samples := flag.String("samples", "docs/attestation/samples", "directory of the published mock samples")
	flag.Parse()
	b, err := predicate(*samples, *profile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mockattest:", err)
		os.Exit(1)
	}
	_, _ = os.Stdout.Write(b)
}

func predicate(dir, profile string) ([]byte, error) {
	if !profilePattern.MatchString(profile) {
		return nil, fmt.Errorf("invalid profile %q", profile)
	}
	b, err := os.ReadFile(filepath.Join(dir, profile+".mock.json"))
	if err != nil {
		return nil, fmt.Errorf("no sample for profile %q: %w", profile, err)
	}
	if err := cosignverify.ValidateMockPredicate(b); err != nil {
		return nil, fmt.Errorf("sample %s does not validate: %w", profile, err)
	}
	return b, nil
}
