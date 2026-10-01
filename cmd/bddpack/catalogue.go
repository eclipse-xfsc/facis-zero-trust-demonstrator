package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// testData names the committed inputs of the implemented families.
var testData = map[string][]string{
	"lifecycle": {
		"`features/fixtures/charts/lifecycle-fixture/` — the release under test (fixture)",
		"`features/fixtures/charts/lifecycle-fixture/ci/values.yaml` — its valid baseline values",
		"`INVALID` in `features/js/steps/lifecycle.steps.mjs` — the invalid-parameter examples",
	},
	"orce-qa": {
		"`features/fixtures/charts/lifecycle-fixture/` — the release the controlled error targets",
		"the `chart value rejected` example of `INVALID` in `features/js/steps/lifecycle.steps.mjs`",
	},
}

// evidenceBasis reads every scenario.json a run left under dir and says, per row, what the evidence
// was produced with. The basis comes from the run itself, never from a scenario name. A run that
// crashed may have left no evidence directory, or a truncated file: the catalogue is still written,
// and such a row reads "no evidence in this run" (the sheet, not the catalogue, fails the run).
func evidenceBasis(dir string) (map[string]string, error) {
	seen := map[string]map[string]bool{}
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return map[string]string{}, nil
	}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != "scenario.json" {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var s struct {
			Row, Target, Run, Chart string
			Fixture                 bool
		}
		if err := json.Unmarshal(content, &s); err != nil || s.Row == "" {
			fmt.Fprintf(os.Stderr, "bddpack: %s is not a complete scenario record; ignored\n", path)
			return nil
		}
		release := "release " + s.Chart
		if s.Fixture {
			release = "fixture release"
		}
		if seen[s.Row] == nil {
			seen[s.Row] = map[string]bool{}
		}
		seen[s.Row][fmt.Sprintf("%s on %s (run %s)", release, s.Target, s.Run)] = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	basis := map[string]string{}
	for row, set := range seen {
		var list []string
		for entry := range set {
			list = append(list, entry)
		}
		sort.Strings(list)
		basis[row] = strings.Join(list, "; ")
	}
	return basis, nil
}

func cell(s string) string { return strings.ReplaceAll(s, "|", `\|`) }

// renderCatalogue is the M2 catalogue page. With basis nil (the committed page) the evidence basis
// of an implemented row points to the runs; a run renders its own copy with -evidence.
func renderCatalogue(annex Annex, basis map[string]string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "<!-- %s -->\n\n# BDD catalogue\n\n", generated)
	fmt.Fprintf(&b, "Every Annex A row with its acceptance criterion and its executable scenario, worded exactly as in\n`%s` (SHA-256 `%s`). How rows are run and\nreported is described in [BDD acceptance](bdd.md).\n\n", annex.Source, annex.SHA256)
	b.WriteString("- **implemented**: the scenario has real steps and decides the row.\n")
	b.WriteString("- **pending**: the scenario is the Annex wording with pending steps; it runs, is reported as\n  *not run*, and proves nothing yet.\n")
	b.WriteString("- **Evidence basis**: what a run's evidence was produced with, read from the run itself.\n")
	if basis == nil {
		b.WriteString("  This page is built from the repository, not from a run: each cluster run publishes its own\n  copy of the catalogue with the basis filled in.\n")
	}

	implementedCount := 0
	for _, r := range annex.Rows {
		if r.Status == implemented {
			implementedCount++
		}
	}
	fmt.Fprintf(&b, "\n%d rows: %d implemented, %d pending.\n\n", len(annex.Rows), implementedCount, len(annex.Rows)-implementedCount)

	b.WriteString("| Row | Requirement | Gate | Status | Runner |\n|---|---|---|---|---|\n")
	for _, r := range annex.Rows {
		fmt.Fprintf(&b, "| [%s](#%s) | %s | %s | %s | %s |\n", r.ID, strings.ToLower(r.ID), cell(r.Requirement),
			cell(strings.SplitN(r.Gate, " - ", 2)[0]), r.Status, runnerName[r.Runner])
	}

	for _, r := range annex.Rows {
		fmt.Fprintf(&b, "\n<a id=\"%s\"></a>\n\n## %s — %s\n\n", strings.ToLower(r.ID), r.ID, r.Requirement)
		status := r.Status
		if r.Cluster {
			status += ", runs on a cluster"
		}
		evidence := "`" + r.EvidencePath + "`"
		if len(r.SharedExecution) > 0 {
			evidence += " — one shared execution for " + strings.Join(r.SharedExecution, " and ")
		}
		fields := [][2]string{
			{"Test ID", r.TestID},
			{"Acceptance criterion", r.AcceptanceCriterion},
			{"Test type", r.TestType},
			{"Gate", r.Gate},
			{"Evidence", evidence},
			{"Automation status", status},
			{"Evidence basis", basisOf(r, basis)},
			{"Runner", runnerName[r.Runner]},
			{"Scenario file", "`" + featurePath(r) + "`"},
		}
		if data := testData[r.Family]; r.Status == implemented && len(data) > 0 {
			fields = append(fields, [2]string{"Test data", strings.Join(data, "; ")})
		}
		b.WriteString("| | |\n|---|---|\n")
		for _, f := range fields {
			fmt.Fprintf(&b, "| %s | %s |\n", f[0], cell(f[1]))
		}
		fmt.Fprintf(&b, "\n```gherkin\nGiven %s\nWhen %s\nThen %s\n```\n", r.Given, r.When, r.Then)
	}
	return b.String()
}

func basisOf(r Row, basis map[string]string) string {
	switch {
	case r.Status == pending:
		return "none (pending)"
	case basis == nil:
		return "recorded per run"
	case basis[r.ID] == "":
		return "no evidence in this run"
	}
	return basis[r.ID]
}
