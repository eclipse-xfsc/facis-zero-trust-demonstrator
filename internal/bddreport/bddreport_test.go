package bddreport

import (
	"strings"
	"testing"
)

const goReport = `[
  {"uri":"features/platform.feature","name":"Platform baseline","tags":[{"name":"@platform"}],
   "elements":[
     {"type":"scenario","name":"Every release image is Linux","tags":[{"name":"@ZT-13"},{"name":"@BDD-ZT-013"}]}
   ]}
]`

const jsReport = `[
  {"uri":"features/ui/journey.feature","name":"Demonstrator journey","tags":[],
   "elements":[
     {"type":"scenario","name":"A refusal is shown in the UI","tags":[{"name":"@ZT-05"}]}
   ]}
]`

func TestMergeKeepsEveryFeature(t *testing.T) {
	features, err := Merge([][]byte{[]byte(goReport), []byte(jsReport)})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if len(features) != 2 {
		t.Fatalf("merged %d features, want 2", len(features))
	}
	if features[0].URI != "features/platform.feature" || features[1].URI != "features/ui/journey.feature" {
		t.Fatalf("merge did not preserve input order: %+v", features)
	}
}

func TestMergeRejectsMalformedInput(t *testing.T) {
	if _, err := Merge([][]byte{[]byte("{not json")}); err == nil {
		t.Fatal("Merge accepted malformed JSON, want an error")
	}
}

func TestCoverageMarksTaggedRowsCovered(t *testing.T) {
	features, err := Merge([][]byte{[]byte(goReport), []byte(jsReport)})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	report := Coverage(features, []string{"ZT-05", "ZT-13", "ZT-16"})

	covered := map[string][]string{}
	for _, row := range report.Rows {
		covered[row.ID] = row.Scenarios
	}
	if got := covered["ZT-13"]; len(got) != 1 || got[0] != "Every release image is Linux" {
		t.Errorf("ZT-13 scenarios = %v, want the Go scenario", got)
	}
	if got := covered["ZT-05"]; len(got) != 1 {
		t.Errorf("ZT-05 scenarios = %v, want the JavaScript scenario", got)
	}
	if got := covered["ZT-16"]; len(got) != 0 {
		t.Errorf("ZT-16 scenarios = %v, want none - no scenario carries that tag", got)
	}
	if report.Uncovered() != 1 {
		t.Errorf("Uncovered() = %d, want 1", report.Uncovered())
	}
}

// Both runners inline the feature's tags into each scenario's own tag list
// before writing the report - this is the shape they actually emit. Counting the
// feature tags a second time would report one scenario as two, which is the
// false coverage this tool exists to prevent.
func TestCoverageCountsAFeatureLevelTagOnce(t *testing.T) {
	const asRunnersEmitIt = `[
      {"uri":"f.feature","name":"F","tags":[{"name":"@ZT-13"}],
       "elements":[{"type":"scenario","name":"inherits","tags":[{"name":"@ZT-13"}]}]}
    ]`
	features, err := Merge([][]byte{[]byte(asRunnersEmitIt)})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	report := Coverage(features, []string{"ZT-13"})
	if got := report.Rows[0].Scenarios; len(got) != 1 {
		t.Fatalf("Scenarios = %v, want the scenario counted once", got)
	}
}

func TestCoverageCountsARepeatedTagOnce(t *testing.T) {
	const repeated = `[
      {"uri":"f.feature","name":"F","tags":[],
       "elements":[{"type":"scenario","name":"repeated","tags":[{"name":"@ZT-13"},{"name":"@ZT-13"}]}]}
    ]`
	features, err := Merge([][]byte{[]byte(repeated)})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	report := Coverage(features, []string{"ZT-13"})
	if got := report.Rows[0].Scenarios; len(got) != 1 {
		t.Fatalf("Scenarios = %v, want the scenario counted once", got)
	}
}

// Scenario names are free text and the sheet is a pipe table, so an unescaped
// pipe would split the row into extra columns.
func TestMarkdownEscapesPipesInScenarioNames(t *testing.T) {
	const piped = `[
      {"uri":"f.feature","name":"F","tags":[],
       "elements":[{"type":"scenario","name":"allow | deny","tags":[{"name":"@ZT-13"}]}]}
    ]`
	features, err := Merge([][]byte{[]byte(piped)})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	row := strings.Split(Coverage(features, []string{"ZT-13"}).Markdown(), "\n")[2]
	if !strings.Contains(row, `allow \| deny`) {
		t.Errorf("the pipe in the scenario name was not escaped:\n%s", row)
	}
	// Only the five column separators may be live pipes; the escaped one is text.
	if separators := strings.Count(strings.ReplaceAll(row, `\|`, ""), "|"); separators != 5 {
		t.Errorf("row has %d column separators, want 5:\n%s", separators, row)
	}
}

// A typo in a tag is the failure mode that silently costs coverage: the scenario
// runs, passes, and proves nothing about the row it was meant to cover.
func TestCoverageReportsTagsThatMatchNoRow(t *testing.T) {
	const typo = `[
      {"uri":"f.feature","name":"F","tags":[],
       "elements":[{"type":"scenario","name":"typo","tags":[{"name":"@ZT-999"}]}]}
    ]`
	features, err := Merge([][]byte{[]byte(typo)})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	report := Coverage(features, []string{"ZT-13"})
	if len(report.UnknownTags) != 1 || report.UnknownTags[0] != "ZT-999" {
		t.Fatalf("UnknownTags = %v, want [ZT-999]", report.UnknownTags)
	}
}

func TestSheetListsEveryRowInOrder(t *testing.T) {
	features, err := Merge([][]byte{[]byte(goReport)})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	sheet := Coverage(features, []string{"ZT-13", "ZT-16"}).Markdown()

	if !strings.Contains(sheet, "| ZT-13 | yes | not run | Every release image is Linux |") {
		t.Errorf("sheet is missing the covered row:\n%s", sheet)
	}
	if !strings.Contains(sheet, "| ZT-16 | no | — | — |") {
		t.Errorf("sheet is missing the uncovered row:\n%s", sheet)
	}
	if strings.Index(sheet, "ZT-13") > strings.Index(sheet, "ZT-16") {
		t.Error("sheet rows are not in the order of the rows file")
	}
}

// The sheet is delivered as acceptance evidence and gets opened in a spreadsheet.
// A scenario name is author-controlled text, so a name starting with a formula
// character must not arrive as a live formula (CWE-1236).
func TestCSVNeutralisesFormulaCharacters(t *testing.T) {
	const crafted = `[
      {"uri":"f.feature","name":"F","tags":[],
       "elements":[{"type":"scenario","name":"=HYPERLINK(\"http://example.invalid\")","tags":[{"name":"@ZT-13"}]}]}
    ]`
	features, err := Merge([][]byte{[]byte(crafted)})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	csv := Coverage(features, []string{"ZT-13"}).CSV()

	if strings.Contains(csv, ",=HYPERLINK") {
		t.Errorf("a formula reached the sheet unescaped:\n%s", csv)
	}
	if !strings.Contains(csv, "'=HYPERLINK") {
		t.Errorf("the formula character was not neutralised:\n%s", csv)
	}
}

func TestCSVIsGeneratedFromTheSameReport(t *testing.T) {
	features, _ := Merge([][]byte{[]byte(goReport)})
	csv := Coverage(features, []string{"ZT-13", "ZT-16"}).CSV()

	want := "row,covered,result,scenarios\nZT-13,yes,not run,Every release image is Linux\nZT-16,no,,\n"
	if csv != want {
		t.Errorf("CSV =\n%q\nwant\n%q", csv, want)
	}
}

// The G7 rows added in Annex A v1.7 are row references like any other; a
// pattern that only knew ZT and TDR-BDD would drop their tags and leave the
// final-validation rows permanently uncovered.
func TestCoverageRecognisesTheG7Rows(t *testing.T) {
	const report = `[
      {"uri":"f.feature","name":"F","tags":[],
       "elements":[{"type":"scenario","name":"final validation","tags":[{"name":"@M7-01"}]}]}
    ]`
	features, err := Merge([][]byte{[]byte(report)})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	got := Coverage(features, []string{"M7-01", "M7-02"})
	if len(got.Rows[0].Scenarios) != 1 || got.Uncovered() != 1 || len(got.UnknownTags) != 0 {
		t.Fatalf("M7-01 not recognised as a row tag: %+v", got)
	}
}

func scenario(name, row string, statuses ...string) string {
	steps := make([]string, 0, len(statuses))
	for _, status := range statuses {
		steps = append(steps, `{"result":{"status":"`+status+`"}}`)
	}
	return `{"type":"scenario","name":"` + name + `","tags":[{"name":"@` + row + `"}],"steps":[` + strings.Join(steps, ",") + `]}`
}

func resultOf(t *testing.T, reports ...string) string {
	t.Helper()
	inputs := make([][]byte, 0, len(reports))
	for _, elements := range reports {
		inputs = append(inputs, []byte(`[{"uri":"f.feature","name":"F","tags":[],"elements":[`+elements+`]}]`))
	}
	features, err := Merge(inputs)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	return Coverage(features, []string{"TDR-BDD-01"}).Rows[0].Result
}

// Tag coverage is not proof: a scenario that ran and failed covers the row but
// must not prove it.
func TestAFailedStepFailsTheRow(t *testing.T) {
	if got := resultOf(t, scenario("deploy", "TDR-BDD-01", "passed", "failed", "skipped")); got != Failed {
		t.Fatalf("result = %q, want %q", got, Failed)
	}
}

func TestEveryStepPassedProvesTheRow(t *testing.T) {
	if got := resultOf(t, scenario("deploy", "TDR-BDD-01", "passed", "passed")); got != Passed {
		t.Fatalf("result = %q, want %q", got, Passed)
	}
}

// A row runs once per target and once per Outline example; one failure among
// them fails it, whichever report it came from.
func TestOneFailedExecutionAmongManyFailsTheRow(t *testing.T) {
	ionos := scenario("deploy", "TDR-BDD-01", "passed")
	osc := scenario("deploy", "TDR-BDD-01", "passed", "failed")
	if got := resultOf(t, ionos, osc); got != Failed {
		t.Fatalf("result = %q, want %q", got, Failed)
	}
}

func TestASkippedScenarioIsNotRun(t *testing.T) {
	if got := resultOf(t, scenario("deploy", "TDR-BDD-01", "skipped", "skipped")); got != NotRun {
		t.Fatalf("result = %q, want %q", got, NotRun)
	}
}

func TestAnUndefinedStepFailsTheRow(t *testing.T) {
	if got := resultOf(t, scenario("deploy", "TDR-BDD-01", "passed", "undefined")); got != Failed {
		t.Fatalf("result = %q, want %q", got, Failed)
	}
}

// Evidence capture and cleanup run in an After hook. If they fail, the
// scenario's evidence is incomplete and the row must not be proven.
func TestAFailedAfterHookFailsTheRow(t *testing.T) {
	element := `{"type":"scenario","name":"deploy","tags":[{"name":"@TDR-BDD-01"}],` +
		`"steps":[{"result":{"status":"passed"}}],"after":[{"result":{"status":"failed"}}]}`
	if got := resultOf(t, element); got != Failed {
		t.Fatalf("result = %q, want %q", got, Failed)
	}
}

// The same scenario run on several targets is one scenario in the sheet.
func TestTheSameScenarioOnSeveralTargetsIsListedOnce(t *testing.T) {
	a := scenario("deploy", "TDR-BDD-01", "passed")
	features, _ := Merge([][]byte{
		[]byte(`[{"uri":"f","name":"F","tags":[],"elements":[` + a + `]}]`),
		[]byte(`[{"uri":"f","name":"F","tags":[],"elements":[` + a + `]}]`),
	})
	if got := Coverage(features, []string{"TDR-BDD-01"}).Rows[0].Scenarios; len(got) != 1 {
		t.Fatalf("Scenarios = %v, want one entry", got)
	}
}
