//go:build ignore

// measure prints the container measurement of an OCI bundle as the attestation
// component computes it, and nothing else: no nonce, no signature, no driver.
// Those change on every run, so a determinism check that compared whole evidence
// would fail for reasons that have nothing to do with the source.
//
//	measure -bundle DIR
//
// It is excluded from this repository's module by the build tag above, because it
// imports the attestation component, which is not a dependency of the delivery
// module. measure-with-cmc.sh compiles it inside a checkout of that component at
// the pinned commit, which is also what makes the measurement comparable: the
// hash is a property of that code at that revision.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Fraunhofer-AISEC/cmc/measure"
)

// containerID only feeds measure.Normalize, which replaces a runtime's container
// ID with a placeholder. The fixture has no runtime, so any constant will do --
// but it has to be the same constant everywhere, or the config hash moves.
const containerID = "measurement-determinism-fixture"

type result struct {
	ConfigSha256 string `json:"configSha256"`
	RootfsSha256 string `json:"rootfsSha256"`
	TemplateHash string `json:"templateHash"`
}

func main() {
	bundle := flag.String("bundle", "", "OCI bundle directory (config.json + rootfs/)")
	flag.Parse()
	if *bundle == "" {
		fail("-bundle is required")
	}

	configRaw, err := os.ReadFile(filepath.Join(*bundle, "config.json"))
	check(err, "read config.json")

	configHash, _, err := measure.GetSpecMeasurement(containerID, configRaw)
	check(err, "measure the configuration")

	rootfsHash, err := measure.GetRootfsMeasurement(filepath.Join(*bundle, "rootfs"))
	check(err, "measure the rootfs")

	template := sha256.Sum256(append(append([]byte{}, configHash...), rootfsHash...))

	out, err := json.MarshalIndent(result{
		ConfigSha256: hex.EncodeToString(configHash),
		RootfsSha256: hex.EncodeToString(rootfsHash),
		TemplateHash: hex.EncodeToString(template[:]),
	}, "", "  ")
	check(err, "encode the result")
	fmt.Println(string(out))
}

func check(err error, what string) {
	if err != nil {
		fail("failed to %s: %v", what, err)
	}
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "measure: "+format+"\n", a...)
	os.Exit(1)
}
