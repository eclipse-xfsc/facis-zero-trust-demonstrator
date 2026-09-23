// Package bddreport merges the cucumber-JSON produced by each BDD runner and
// derives the requirement-to-test traceability sheet from the scenario tags and
// their results.
//
// The sheet is generated, never maintained: a requirement row is covered when a
// scenario carries its tag, and a row nobody tagged shows up as a gap. Covered is
// not proven: a row is proven only when every execution of every scenario that
// covers it passed.
package bddreport

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// rowTag matches the Annex A row identifiers and nothing else. Tags like
// @BDD-ZT-013 (the test identifier) or @platform are not row references and are
// ignored rather than reported as unknown.
var rowTag = regexp.MustCompile(`^(ZT-\d+|TDR-BDD-\d+|M7-\d+)$`)

type Tag struct {
	Name string `json:"name"`
}

type Result struct {
	Status string `json:"status"`
}

type Step struct {
	Result Result `json:"result"`
}

// Element is one executed scenario. Hooks are reported beside the steps, and a
// failing After hook (evidence capture, cleanup) fails the scenario too.
type Element struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	Tags   []Tag  `json:"tags"`
	Before []Step `json:"before"`
	Steps  []Step `json:"steps"`
	After  []Step `json:"after"`
}

// Row results. A row with no covering scenario has no result.
const (
	Passed = "passed"
	Failed = "failed"
	NotRun = "not run"
)

// status reduces an execution to one result. Anything that is not an outright
// pass or failure - skipped, or no steps at all - is "not run": it proves nothing.
func (e Element) status() string {
	steps := append(append(append([]Step{}, e.Before...), e.Steps...), e.After...)
	if len(e.Steps) == 0 {
		return NotRun
	}
	result := Passed
	for _, step := range steps {
		switch step.Result.Status {
		case "passed":
		case "failed", "undefined", "pending", "ambiguous":
			return Failed
		default:
			result = NotRun
		}
	}
	return result
}

type Feature struct {
	URI      string    `json:"uri"`
	Name     string    `json:"name"`
	Tags     []Tag     `json:"tags"`
	Elements []Element `json:"elements"`
}

// Merge concatenates cucumber-JSON documents in the order they were given. Both
// runners emit the same legacy shape - an array of features - so merging them is
// concatenation, and a malformed document is an error rather than a silent gap.
func Merge(inputs [][]byte) ([]Feature, error) {
	var merged []Feature
	for i, input := range inputs {
		var features []Feature
		if err := json.Unmarshal(input, &features); err != nil {
			return nil, fmt.Errorf("report %d: %w", i+1, err)
		}
		merged = append(merged, features...)
	}
	return merged, nil
}

type Row struct {
	ID        string
	Scenarios []string
	// Result is Passed only when every covering execution passed, across every
	// report merged - each target of a matrix run and each Outline example.
	Result string
}

type Report struct {
	Rows        []Row
	UnknownTags []string
}

// Coverage maps every requirement row to the scenarios that claim it. Rows keep
// the order of the rows file so the sheet reads the same way every time.
func Coverage(features []Feature, rows []string) Report {
	known := make(map[string]int, len(rows))
	report := Report{Rows: make([]Row, len(rows))}
	for i, id := range rows {
		known[id] = i
		report.Rows[i] = Row{ID: id}
	}

	unknown := map[string]struct{}{}
	for _, feature := range features {
		for _, element := range feature.Elements {
			// Both runners inline the feature's tags into each scenario before
			// writing the report, and a scenario may repeat a tag, so the ids are
			// deduplicated: a scenario covers a row once or not at all.
			for _, id := range distinct(rowIDs(tagNames(element.Tags))) {
				if i, ok := known[id]; ok {
					row := &report.Rows[i]
					row.Scenarios = distinct(append(row.Scenarios, element.Name))
					row.Result = worst(row.Result, element.status())
					continue
				}
				unknown[id] = struct{}{}
			}
		}
	}

	for id := range unknown {
		report.UnknownTags = append(report.UnknownTags, id)
	}
	sort.Strings(report.UnknownTags)
	return report
}

// worst keeps the weakest result seen for a row: one failed execution fails it,
// and one execution that did not run keeps it from passing.
func worst(current, next string) string {
	rank := map[string]int{"": 0, Passed: 1, NotRun: 2, Failed: 3}
	if rank[next] > rank[current] {
		return next
	}
	return current
}

func tagNames(tags []Tag) []string {
	names := make([]string, 0, len(tags))
	for _, tag := range tags {
		names = append(names, tag.Name)
	}
	return names
}

func distinct(ids []string) []string {
	seen := make(map[string]struct{}, len(ids))
	unique := make([]string, 0, len(ids))
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		unique = append(unique, id)
	}
	return unique
}

func rowIDs(names []string) []string {
	ids := make([]string, 0, len(names))
	for _, name := range names {
		id := strings.TrimPrefix(name, "@")
		if rowTag.MatchString(id) {
			ids = append(ids, id)
		}
	}
	return ids
}

// Proven counts the rows whose every covering execution passed.
func (r Report) Proven() int {
	proven := 0
	for _, row := range r.Rows {
		if row.Result == Passed {
			proven++
		}
	}
	return proven
}

// Uncovered counts the rows no scenario claims.
func (r Report) Uncovered() int {
	uncovered := 0
	for _, row := range r.Rows {
		if len(row.Scenarios) == 0 {
			uncovered++
		}
	}
	return uncovered
}

func (r Report) Markdown() string {
	var b strings.Builder
	b.WriteString("| Row | Covered | Result | Scenarios |\n|---|---|---|---|\n")
	for _, row := range r.Rows {
		covered, result, scenarios := "no", "—", "—"
		if len(row.Scenarios) > 0 {
			// A scenario name is free text; an unescaped pipe would split the row
			// into extra columns and corrupt the table.
			covered, result = "yes", row.Result
			scenarios = strings.ReplaceAll(strings.Join(row.Scenarios, "; "), "|", `\|`)
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", row.ID, covered, result, scenarios)
	}
	return b.String()
}

// neutralise stops a scenario name from arriving as a live formula when the
// sheet is opened in a spreadsheet. The sheet ships as acceptance evidence and
// its names are author-controlled text.
func neutralise(cell string) string {
	if cell == "" {
		return cell
	}
	if strings.ContainsRune("=+-@\t\r", rune(cell[0])) {
		return "'" + cell
	}
	return cell
}

func (r Report) CSV() string {
	var b strings.Builder
	w := csv.NewWriter(&b)
	_ = w.Write([]string{"row", "covered", "result", "scenarios"})
	for _, row := range r.Rows {
		covered := "no"
		if len(row.Scenarios) > 0 {
			covered = "yes"
		}
		_ = w.Write([]string{row.ID, covered, row.Result, neutralise(strings.Join(row.Scenarios, "; "))})
	}
	w.Flush()
	return b.String()
}
