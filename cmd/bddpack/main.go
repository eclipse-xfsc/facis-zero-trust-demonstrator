// Command bddpack renders the acceptance pack from the committed Annex A source
// (features/annex/annex-a.json) and holds every feature file to it.
//
//	go run ./cmd/bddpack          # regenerate the pack
//	go run ./cmd/bddpack -check   # fail if a generated file is stale or a scenario is not verbatim
//	go run ./cmd/bddpack -evidence bundles/bdd/evidence -catalogue bundles/bdd/bdd-catalogue.md
//	                              # a run's catalogue, with the evidence basis read from the run
//
// Run it from the repository root. Generated: the feature files of every family except the
// hand-written ones, the pending step registrations of both runners, the row list and the
// catalogue page.
package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func main() {
	check := flag.Bool("check", false, "fail if a generated file differs instead of writing it")
	evidence := flag.String("evidence", "", "a run's evidence directory; with -catalogue, render that run's catalogue")
	catalogue := flag.String("catalogue", "", "where to write the run's catalogue (with -evidence)")
	flag.Parse()
	if (*evidence == "") != (*catalogue == "") {
		fmt.Fprintln(os.Stderr, "bddpack: -evidence and -catalogue go together")
		os.Exit(2)
	}
	if *evidence != "" {
		if err := runCatalogue(".", *evidence, *catalogue); err != nil {
			fmt.Fprintln(os.Stderr, "bddpack:", err)
			os.Exit(1)
		}
		return
	}
	if err := run(".", *check); err != nil {
		fmt.Fprintln(os.Stderr, "bddpack:", err)
		os.Exit(1)
	}
}

func run(root string, check bool) error {
	annex, err := loadAnnex(filepath.Join(root, annexPath))
	if err != nil {
		return err
	}
	files := render(annex)

	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	var stale []string
	for _, path := range paths {
		full := filepath.Join(root, path)
		current, err := os.ReadFile(full)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if string(current) == files[path] {
			continue
		}
		if check {
			stale = append(stale, path)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(full, []byte(files[path]), 0o644); err != nil {
			return err
		}
	}
	if len(stale) > 0 {
		return fmt.Errorf("generated files are stale, run go run ./cmd/bddpack:\n  %s", strings.Join(stale, "\n  "))
	}

	// Generated feature files the Annex no longer produces would still run and claim rows.
	features, err := readFeatures(root)
	if err != nil {
		return err
	}
	for path, content := range features {
		if strings.HasPrefix(content, "# "+generated) && files[path] == "" {
			return fmt.Errorf("%s is generated but the Annex no longer produces it; delete it", path)
		}
	}
	return verify(annex, features)
}

func runCatalogue(root, evidence, out string) error {
	annex, err := loadAnnex(filepath.Join(root, annexPath))
	if err != nil {
		return err
	}
	basis, err := evidenceBasis(evidence)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return err
	}
	return os.WriteFile(out, []byte(renderCatalogue(annex, basis)), 0o644)
}

// readFeatures reads every feature file of both runners, keyed by its path from the root.
func readFeatures(root string) (map[string]string, error) {
	features := map[string]string{}
	for _, dir := range []string{"features/go", "features/js"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || filepath.Ext(path) != ".feature" {
				return err
			}
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			features[filepath.ToSlash(rel)] = string(content)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return features, nil
}
