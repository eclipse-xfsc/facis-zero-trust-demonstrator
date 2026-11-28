package trainresolve

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

// TestDependsOnTheStandardLibraryOnly keeps the package free of the attested-channel package and of
// the CMC library: it is meant to be plugged behind the channel's peer verifier, so it must not
// depend on the channel, and it must build on main before the channel does.
func TestDependsOnTheStandardLibraryOnly(t *testing.T) {
	list := exec.Command("go", "list", "-json=ImportPath,Deps", ".")
	out, err := list.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	var p struct {
		ImportPath string
		Deps       []string
	}
	if err := json.NewDecoder(bytes.NewReader(out)).Decode(&p); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(p.ImportPath, "/internal/trainresolve") || len(p.Deps) == 0 {
		t.Fatalf("unexpected listing: %+v", p)
	}
	for _, dep := range p.Deps {
		first, _, _ := strings.Cut(dep, "/")
		if strings.Contains(first, ".") {
			t.Errorf("%s depends on %s; only the standard library is allowed", p.ImportPath, dep)
		}
	}
}
