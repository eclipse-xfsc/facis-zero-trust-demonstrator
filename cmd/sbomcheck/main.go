// Command sbomcheck checks a repository SBOM before it is signed and attached to a release: it must be
// valid CycloneDX (the vendored schemas admission uses), and every module the go.mod of -dir requires
// must be in it at the version the build selects, replacements resolved.
//
// The requirement list is a complete inventory only for a tidy go.mod with module graph pruning (go
// directive 1.17 or later): then it lists every module that supplies a package to any build or test of
// the module, on any platform and under any build tag, and the module graph's other entries supply no
// package. Both conditions are checked, and each requirement is compared with the version Go selects,
// so the check cannot be passed by removing a module from go.mod and the SBOM together.
//
//	go run ./cmd/sbomcheck -sbom sbom.json -dir <checkout of the release tag>
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/cosignverify"
)

type module struct{ Path, Version string }

type goMod struct {
	Go      string
	Require []module
	Replace []struct{ Old, New module }
}

func main() {
	sbomPath := flag.String("sbom", "", "CycloneDX JSON SBOM to check")
	dir := flag.String("dir", ".", "directory of the Go module the SBOM describes")
	flag.Parse()
	if *sbomPath == "" {
		fmt.Fprintln(os.Stderr, "usage: sbomcheck -sbom <sbom.json> [-dir <module dir>]")
		os.Exit(2)
	}
	b, err := os.ReadFile(*sbomPath)
	if err != nil {
		fail(err)
	}
	if out, err := run(*dir, "go", "mod", "tidy", "-diff"); err != nil {
		fail(fmt.Errorf("go.mod is not tidy, so its requirements are not the build inventory:\n%s", out))
	}
	out, err := run(*dir, "go", "mod", "edit", "-json")
	if err != nil {
		fail(fmt.Errorf("go mod edit: %w", err))
	}
	var gm goMod
	if err := json.Unmarshal(out, &gm); err != nil {
		fail(fmt.Errorf("go.mod: %w", err))
	}
	if !pruned(gm.Go) {
		fail(fmt.Errorf("go directive %q predates module graph pruning (1.17): the requirements are not the build inventory", gm.Go))
	}
	selected, err := run(*dir, "go", "list", "-m", "-json", "all")
	if err != nil {
		fail(fmt.Errorf("go list -m: %w", err))
	}
	diffs, err := versionMismatches(gm.Require, selected)
	if err != nil {
		fail(err)
	}
	for _, d := range diffs {
		fmt.Fprintln(os.Stderr, "sbomcheck:", d)
	}
	if len(diffs) > 0 {
		os.Exit(1)
	}
	mods, local := resolve(gm)
	// A module replaced by a local directory has no version an SBOM can carry; it is reported, not
	// silently passed.
	for _, path := range local {
		fmt.Fprintf(os.Stderr, "sbomcheck: %s is replaced by a local directory and cannot be checked\n", path)
	}
	if len(local) > 0 {
		os.Exit(1)
	}
	missing, err := check(b, mods)
	if err != nil {
		fail(err)
	}
	for _, m := range missing {
		fmt.Fprintf(os.Stderr, "sbomcheck: %s %s is required but not in the SBOM\n", m.Path, m.Version)
	}
	if len(missing) > 0 {
		os.Exit(1)
	}
	fmt.Printf("sbomcheck: valid CycloneDX, all %d required modules present at their selected versions\n", len(mods))
}

func run(dir, name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	var stderr bytes.Buffer
	cmd.Dir, cmd.Stderr = dir, &stderr
	out, err := cmd.Output()
	if err != nil {
		return append(out, stderr.Bytes()...), err
	}
	return out, nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "sbomcheck:", err)
	os.Exit(1)
}

// pruned reports whether a go directive enables module graph pruning (go 1.17 or later).
func pruned(goVersion string) bool {
	major, minor, _ := strings.Cut(goVersion, ".")
	minor, _, _ = strings.Cut(minor, ".")
	ma, err1 := strconv.Atoi(major)
	mi, err2 := strconv.Atoi(minor)
	return err1 == nil && err2 == nil && (ma > 1 || (ma == 1 && mi >= 17))
}

// check validates the SBOM and returns the modules it lacks, sorted by path. Only Go components count.
func check(sbom []byte, mods []module) ([]module, error) {
	if err := cosignverify.ValidateCycloneDX(sbom); err != nil {
		return nil, err
	}
	var doc struct {
		Components []struct{ Name, Version, Purl string } `json:"components"`
	}
	if err := json.Unmarshal(sbom, &doc); err != nil {
		return nil, err
	}
	have := map[module]bool{}
	for _, c := range doc.Components {
		if strings.HasPrefix(c.Purl, "pkg:golang/") {
			have[module{c.Name, c.Version}] = true
		}
	}
	var missing []module
	for _, m := range mods {
		if !have[m] {
			missing = append(missing, m)
		}
	}
	sort.Slice(missing, func(i, j int) bool { return missing[i].Path < missing[j].Path })
	return missing, nil
}

// versionMismatches compares each requirement with the version Go selects for it (the go list -m -json
// all stream): in a tidy go.mod they are the same, so any difference means the requirement list is not
// the inventory of the build.
func versionMismatches(required []module, selectedJSON []byte) ([]string, error) {
	selected := map[string]string{}
	dec := json.NewDecoder(bytes.NewReader(selectedJSON))
	for {
		var m struct {
			Path, Version string
			Main          bool
		}
		if err := dec.Decode(&m); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("go list -m: %w", err)
		}
		if !m.Main {
			selected[m.Path] = m.Version
		}
	}
	var diffs []string
	for _, r := range required {
		switch v, ok := selected[r.Path]; {
		case !ok:
			diffs = append(diffs, fmt.Sprintf("%s: go.mod requires %s, the build does not select it", r.Path, r.Version))
		case v != r.Version:
			diffs = append(diffs, fmt.Sprintf("%s: go.mod requires %s, the build selects %s", r.Path, r.Version, v))
		}
	}
	return diffs, nil
}

// resolve returns the modules go.mod requires, each as the build uses it: replaced by the replacement
// for its exact version if there is one, else by the replacement for all its versions, as Go applies
// them, whatever the declaration order. Modules whose winning replacement is a local directory are
// returned separately, by their required path.
func resolve(gm goMod) (mods []module, local []string) {
	for _, r := range gm.Require {
		var exact, wildcard *module
		for i := range gm.Replace {
			rp := gm.Replace[i]
			switch {
			case rp.Old.Path != r.Path:
			case rp.Old.Version == r.Version:
				exact = &gm.Replace[i].New
			case rp.Old.Version == "":
				wildcard = &gm.Replace[i].New
			}
		}
		winner := exact
		if winner == nil {
			winner = wildcard
		}
		switch {
		case winner == nil:
			mods = append(mods, r)
		case winner.Version == "":
			local = append(local, r.Path)
		default:
			mods = append(mods, *winner)
		}
	}
	return mods, local
}

// modulesFromGoMod parses go mod edit -json output and resolves its requirements.
func modulesFromGoMod(goModJSON []byte) ([]module, []string, error) {
	var gm goMod
	if err := json.Unmarshal(goModJSON, &gm); err != nil {
		return nil, nil, fmt.Errorf("go.mod: %w", err)
	}
	mods, local := resolve(gm)
	return mods, local, nil
}
