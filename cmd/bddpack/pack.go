package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Annex is the committed single source: Annex A exported once from the client's workbook.
type Annex struct {
	Source string `json:"source"`
	SHA256 string `json:"sha256"`
	Rows   []Row  `json:"rows"`
}

type Row struct {
	ID                  string `json:"id"`
	TestID              string `json:"testId"`
	Requirement         string `json:"requirement"`
	AcceptanceCriterion string `json:"acceptanceCriterion"`
	TestType            string `json:"testType"`
	Gate                string `json:"gate"`
	EvidencePath        string `json:"evidencePath"`
	// SharedExecution lists the test ids of a row the Annex marks "SHARED EXECUTION": executed
	// once, one evidence bundle, traced to every row listed.
	SharedExecution []string `json:"sharedExecution"`
	Statement       string   `json:"statement"`
	Given           string   `json:"given"`
	When            string   `json:"when"`
	Then            string   `json:"then"`
	Family          string   `json:"family"`
	Runner          string   `json:"runner"`
	Status          string   `json:"status"`
	Cluster         bool     `json:"cluster"`
}

const (
	implemented = "implemented"
	pending     = "pending"
	annexPath   = "features/annex/annex-a.json"
)

// handWritten families keep their own feature file (an Outline, a description); the verbatim
// test still holds them to the Annex text.
var handWritten = map[string]string{"lifecycle": "features/js/lifecycle.feature"}

var familyTitles = map[string]string{
	"workload-identity":    "Workload identity",
	"mesh":                 "Mesh enrolment and segmentation",
	"plane-separation":     "Management and data plane separation",
	"admission":            "Admission control",
	"supply-chain":         "Supply chain",
	"attested-channel":     "Attested channel",
	"trust-lists":          "Expected measurements and trust lists",
	"authorization":        "Authorization surface",
	"credential-lifecycle": "Credential lifecycle",
	"policy":               "Policy decision",
	"fail-secure":          "Fail-secure behaviour",
	"security-baseline":    "Security baseline",
	"environments":         "Target environments",
	"release-quality":      "Release quality",
	"visualization":        "Visualization and journey",
	"documentation":        "Documentation and reproduction",
	"lifecycle":            "Deployment lifecycle",
	"orce-qa":              "ORCE automation QA",
	"final-acceptance":     "Final acceptance",
}

func loadAnnex(path string) (Annex, error) {
	var annex Annex
	content, err := os.ReadFile(path)
	if err != nil {
		return annex, err
	}
	if err := json.Unmarshal(content, &annex); err != nil {
		return annex, fmt.Errorf("%s: %w", path, err)
	}
	return annex, validate(annex)
}

// A scenario is one Annex execution: rows the Annex marks as a shared execution are one scenario
// carrying every row's tags.
type scenario struct {
	Rows []Row
}

func (s scenario) first() Row { return s.Rows[0] }

func (s scenario) name() string {
	var names []string
	for _, r := range s.Rows {
		if !contains(names, r.Requirement) {
			names = append(names, r.Requirement)
		}
	}
	return strings.Join(names, " / ")
}

func (s scenario) tags() []string {
	var tags []string
	for _, r := range s.Rows {
		tags = append(tags, "@"+r.ID, "@"+r.TestID)
	}
	if s.first().Status == pending {
		tags = append(tags, "@pending")
	}
	if s.first().Cluster {
		tags = append(tags, "@cluster")
	}
	return tags
}

func scenarios(rows []Row) []scenario {
	var out []scenario
	shared := map[string]int{}
	for _, r := range rows {
		if len(r.SharedExecution) == 0 {
			out = append(out, scenario{Rows: []Row{r}})
			continue
		}
		key := strings.Join(r.SharedExecution, " ")
		if i, ok := shared[key]; ok {
			out[i].Rows = append(out[i].Rows, r)
			continue
		}
		shared[key] = len(out)
		out = append(out, scenario{Rows: []Row{r}})
	}
	return out
}

var (
	rowID     = regexp.MustCompile(`^(ZT-\d{2}|TDR-BDD-\d{2}|M7-\d{2})$`)
	testID    = regexp.MustCompile(`^BDD-(ZT|TDR|M7)-\d{3}$`)
	evidenceP = regexp.MustCompile(`^evidence/(bdd-[a-z0-9]+-\d{3}|shared/bdd-[a-z0-9]+-\d{3}-\d{3})/$`)
)

func validate(annex Annex) error {
	var errs []string
	fail := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }
	if annex.Source == "" || len(annex.SHA256) != 64 {
		fail("the source name and its SHA-256 are required")
	}
	if len(annex.Rows) == 0 {
		fail("no rows")
	}
	seen := map[string]bool{}
	for _, r := range annex.Rows {
		if !rowID.MatchString(r.ID) || seen[r.ID] {
			fail("%q: invalid or duplicate row id", r.ID)
		}
		seen[r.ID] = true
		if !testID.MatchString(r.TestID) {
			fail("%s: invalid test id %q", r.ID, r.TestID)
		}
		if "GIVEN "+r.Given+" WHEN "+r.When+" THEN "+r.Then != r.Statement {
			fail("%s: the clauses do not rebuild the statement", r.ID)
		}
		for _, clause := range []string{r.Given, r.When, r.Then} {
			// U+2028/U+2029 end a JavaScript regular expression literal as a newline would.
			if clause == "" || clause != strings.TrimSpace(clause) || strings.ContainsAny(clause, "\n\r\u2028\u2029") {
				fail("%s: a clause is empty, padded or spans lines", r.ID)
			}
		}
		if _, ok := familyTitles[r.Family]; !ok {
			fail("%s: unknown family %q", r.ID, r.Family)
		}
		if r.Runner != "go" && r.Runner != "js" {
			fail("%s: runner must be go or js", r.ID)
		}
		if r.Status != implemented && r.Status != pending {
			fail("%s: status must be implemented or pending", r.ID)
		}
		if r.Cluster && r.Status == pending {
			fail("%s: a pending row never carries @cluster", r.ID)
		}
		if !evidenceP.MatchString(r.EvidencePath) {
			fail("%s: evidence path %q", r.ID, r.EvidencePath)
		}
		if (len(r.SharedExecution) > 0) != strings.HasPrefix(r.EvidencePath, "evidence/shared/") {
			fail("%s: a shared evidence path goes with a shared execution, and only with one", r.ID)
		}
	}

	runners := map[string]string{}
	for _, r := range annex.Rows {
		if other, ok := runners[r.Family]; ok && other != r.Runner {
			fail("family %s spans both runners", r.Family)
		}
		runners[r.Family] = r.Runner
	}

	for _, s := range scenarios(annex.Rows) {
		var ids []string
		for _, r := range s.Rows {
			ids = append(ids, r.TestID)
		}
		if len(s.first().SharedExecution) > 0 && strings.Join(ids, " ") != strings.Join(s.first().SharedExecution, " ") {
			fail("shared execution %v is traced to %v", s.first().SharedExecution, ids)
		}
		for _, r := range s.Rows[1:] {
			if r.Statement != s.first().Statement || r.EvidencePath != s.first().EvidencePath || r.Family != s.first().Family ||
				r.Status != s.first().Status || r.Cluster != s.first().Cluster {
				fail("%s and %s are one shared execution but differ in statement, evidence, family, status or cluster", s.first().ID, r.ID)
			}
		}
	}

	// A clause shared between rows stays pending until every row using it is implemented;
	// otherwise the pending registration would shadow, or collide with, the real step.
	statuses := map[string]map[string]string{}
	for _, r := range annex.Rows {
		for _, clause := range []string{r.Given, r.When, r.Then} {
			if statuses[clause] == nil {
				statuses[clause] = map[string]string{}
			}
			statuses[clause][r.ID] = r.Status
		}
	}
	for clause, byRow := range statuses {
		var impl, pend []string
		for id, status := range byRow {
			if status == implemented {
				impl = append(impl, id)
			} else {
				pend = append(pend, id)
			}
		}
		if len(impl) > 0 && len(pend) > 0 {
			sort.Strings(impl)
			sort.Strings(pend)
			fail("clause %q is shared by implemented %v and pending %v rows; implement them together", clause, impl, pend)
		}
	}

	if len(errs) > 0 {
		sort.Strings(errs)
		return fmt.Errorf("%s:\n  %s", annexPath, strings.Join(errs, "\n  "))
	}
	return nil
}

// pendingTexts lists every distinct clause of a pending row for one runner, in Annex order.
func pendingTexts(rows []Row, runner string) []string {
	var texts []string
	seen := map[string]bool{}
	for _, r := range rows {
		if r.Runner != runner || r.Status != pending {
			continue
		}
		for _, clause := range []string{r.Given, r.When, r.Then} {
			if !seen[clause] {
				seen[clause] = true
				texts = append(texts, clause)
			}
		}
	}
	return texts
}

// goPattern matches exactly the text under godog, which compiles step patterns with Go regexp.
func goPattern(text string) string { return "^" + regexp.QuoteMeta(text) + "$" }

// jsPattern is a JavaScript RegExp literal matching exactly the text. Cucumber expressions would
// read "/" as alternation and "( )" as optional text, so plain regular expressions are used.
func jsPattern(text string) string {
	var b strings.Builder
	b.WriteString("/^")
	for _, r := range text {
		if strings.ContainsRune(`\^$.|?*+()[]{}/`, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	b.WriteString("$/")
	return b.String()
}

const generated = "Code generated by cmd/bddpack from " + annexPath + ". DO NOT EDIT."

// render returns every generated file, keyed by its path relative to the repository root.
func render(annex Annex) map[string]string {
	files := map[string]string{}

	byFamily := map[string][]scenario{}
	var families []string
	for _, s := range scenarios(annex.Rows) {
		f := s.first().Family
		if _, ok := byFamily[f]; !ok {
			families = append(families, f)
		}
		byFamily[f] = append(byFamily[f], s)
	}
	for _, f := range families {
		if _, ok := handWritten[f]; ok {
			continue
		}
		files[featurePath(byFamily[f][0].first())] = renderFeature(f, byFamily[f])
	}

	files["internal/bdd/pending_gen_test.go"] = renderGoPending(pendingTexts(annex.Rows, "go"))
	files["features/js/steps/pending.gen.mjs"] = renderJSPending(pendingTexts(annex.Rows, "js"))
	files["features/annex-rows.txt"] = renderRows(annex)
	files["docs/bdd-catalogue.md"] = renderCatalogue(annex, nil)
	return files
}

func featurePath(r Row) string {
	if path, ok := handWritten[r.Family]; ok {
		return path
	}
	return fmt.Sprintf("features/%s/%s.feature", r.Runner, r.Family)
}

func renderFeature(family string, list []scenario) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\nFeature: %s\n", generated, familyTitles[family])
	fmt.Fprintf(&b, "  Annex A rows for %s, worded exactly as in the Annex.\n", familyTitles[family])
	for _, s := range list {
		r := s.first()
		fmt.Fprintf(&b, "\n  %s\n  Scenario: %s\n", strings.Join(s.tags(), " "), s.name())
		fmt.Fprintf(&b, "    Given %s\n    When %s\n    Then %s\n", r.Given, r.When, r.Then)
	}
	return b.String()
}

func renderGoPending(texts []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "// %s\n\npackage bdd\n\nimport \"github.com/cucumber/godog\"\n\n", generated)
	b.WriteString("// pendingSteps are the clauses of the Annex rows not implemented yet. They run as pending,\n")
	b.WriteString("// never as undefined, so a pending row is reported as not run rather than as a failure.\n")
	b.WriteString("var pendingSteps = []string{\n")
	for _, t := range texts {
		fmt.Fprintf(&b, "\t%s,\n", strconv.Quote(goPattern(t)))
	}
	b.WriteString("}\n\nfunc registerPending(ctx *godog.ScenarioContext) {\n")
	b.WriteString("\tfor _, pattern := range pendingSteps {\n\t\tctx.Step(pattern, func() error { return godog.ErrPending })\n\t}\n}\n")
	return b.String()
}

func renderJSPending(texts []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "// %s\n//\n", generated)
	b.WriteString("// The clauses of the Annex rows not implemented yet. They run as pending, never as undefined,\n")
	b.WriteString("// so a pending row is reported as not run rather than as a failure.\n")
	b.WriteString("import { Given } from '@cucumber/cucumber'\n\nconst pending = () => 'pending'\n\n")
	for _, t := range texts {
		fmt.Fprintf(&b, "Given(%s, pending)\n", jsPattern(t))
	}
	return b.String()
}

func renderRows(annex Annex) string {
	var b strings.Builder
	b.WriteString("# Annex A requirement rows - the denominator of the traceability sheet.\n")
	b.WriteString("# One row id per line, in Annex A order. A row with no tagged scenario is a gap.\n")
	fmt.Fprintf(&b, "# %s\n# Source: %s (sha256 %s).\n", generated, annex.Source, annex.SHA256)
	for _, r := range annex.Rows {
		b.WriteString(r.ID + "\n")
	}
	return b.String()
}

var runnerName = map[string]string{"go": "godog", "js": "Cucumber.js"}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
