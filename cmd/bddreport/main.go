// Command bddreport merges the cucumber-JSON emitted by each BDD runner and
// generates the requirement-to-test traceability sheet from the scenario tags
// and results.
//
//	bddreport --rows features/annex-rows.txt --out bundles/bdd report1.json report2.json
//	bddreport --require-complete ...   # also fail on an uncovered or failed row
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/bddreport"
)

func main() {
	rowsPath := flag.String("rows", "features/annex-rows.txt", "file listing the Annex A row ids, one per line")
	outDir := flag.String("out", "bundles/bdd", "directory the merged report and the sheet are written to")
	requireComplete := flag.Bool("require-complete", false, "fail on an uncovered or failed row, after writing the sheets")
	flag.Parse()

	if err := run(*rowsPath, *outDir, flag.Args(), *requireComplete); err != nil {
		fmt.Fprintln(os.Stderr, "bddreport:", err)
		os.Exit(1)
	}
}

func run(rowsPath, outDir string, reports []string, requireComplete bool) error {
	if len(reports) == 0 {
		return fmt.Errorf("no cucumber-JSON report given")
	}

	rows, err := readRows(rowsPath)
	if err != nil {
		return err
	}

	inputs := make([][]byte, 0, len(reports))
	for _, path := range reports {
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading report: %w", err)
		}
		inputs = append(inputs, content)
	}

	features, err := bddreport.Merge(inputs)
	if err != nil {
		return err
	}
	report := bddreport.Coverage(features, rows)

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("creating the output directory: %w", err)
	}
	sheets := []struct{ name, content string }{
		{"traceability.md", report.Markdown()},
		{"traceability.csv", report.CSV()},
	}
	for _, sheet := range sheets {
		if err := os.WriteFile(filepath.Join(outDir, sheet.name), []byte(sheet.content), 0o644); err != nil {
			return fmt.Errorf("writing %s: %w", sheet.name, err)
		}
	}

	failed := 0
	for _, row := range report.Rows {
		if row.Result == bddreport.Failed {
			failed++
		}
	}
	fmt.Printf("%d rows, %d covered, %d proven, %d failed, %d uncovered\n",
		len(report.Rows), len(report.Rows)-report.Uncovered(), report.Proven(), failed, report.Uncovered())

	// A tag shaped like a row id that matches no row is a typo: the scenario runs,
	// passes, and proves nothing. Fail rather than report false coverage.
	if len(report.UnknownTags) > 0 {
		return fmt.Errorf("tags match no Annex row: %s", strings.Join(report.UnknownTags, ", "))
	}
	// A missing report leaves its rows uncovered; with the flag that cannot pass silently.
	if requireComplete {
		if err := report.Complete(); err != nil {
			return fmt.Errorf("the sheet is not complete: %w", err)
		}
	}
	return nil
}

func readRows(path string) ([]string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading the rows file: %w", err)
	}
	var rows []string
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rows = append(rows, line)
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("%s lists no rows", path)
	}
	return rows, nil
}
