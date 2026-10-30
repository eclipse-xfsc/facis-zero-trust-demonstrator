package authelia

import (
	"os/exec"
	"strings"
	"testing"
)

// verifiedLibraryVersion is the library release the conformance tests in
// this package were run against. Changing the pinned version means running
// them again, then updating this constant, docs/dependencies.md and the
// architecture decision that records the library.
const verifiedLibraryVersion = "v0.3.2"

func TestLibraryVersionIsTheOneVerified(t *testing.T) {
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Version}}", "authelia.com/provider/oauth2").Output()
	if err != nil {
		t.Fatalf("read the pinned library version: %v", err)
	}

	if pinned := strings.TrimSpace(string(out)); pinned != verifiedLibraryVersion {
		t.Fatalf("go.mod pins authelia.com/provider/oauth2 %s but the conformance suite was verified against %s; "+
			"run the suite on the new version and update verifiedLibraryVersion, docs/dependencies.md and the architecture decision",
			pinned, verifiedLibraryVersion)
	}
}
