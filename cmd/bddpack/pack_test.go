package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func row(id, test, family, runner, status, given, when, then string) Row {
	n := strings.ToLower(strings.TrimPrefix(test, "BDD-"))
	return Row{
		ID: id, TestID: test, Requirement: "Requirement " + id, AcceptanceCriterion: "Criterion " + id,
		TestType: "BDD / integration", Gate: "G2 - baseline", EvidencePath: "evidence/bdd-" + n + "/",
		Statement: "GIVEN " + given + " WHEN " + when + " THEN " + then,
		Given:     given, When: when, Then: then, Family: family, Runner: runner, Status: status,
		Cluster: status == implemented && family == "lifecycle",
	}
}

// sample covers the shapes of the real Annex: a "/" and a "( )" in a clause, a clause shared by
// two rows, a shared execution (two rows, one scenario) and a hand-written cluster family.
func sample() Annex {
	shared1 := row("ZT-42", "BDD-ZT-042", "documentation", "js", pending, "the concept is written", "the client reviews it", "it is approved.")
	shared2 := row("ZT-79", "BDD-ZT-079", "documentation", "js", pending, "the concept is written", "the client reviews it", "it is approved.")
	shared1.EvidencePath = "evidence/shared/bdd-zt-042-079/"
	shared2.EvidencePath = "evidence/shared/bdd-zt-042-079/"
	shared1.SharedExecution = []string{"BDD-ZT-042", "BDD-ZT-079"}
	shared2.SharedExecution = []string{"BDD-ZT-042", "BDD-ZT-079"}
	return Annex{
		Source: "annex.xlsx", SHA256: strings.Repeat("a", 64),
		Rows: []Row{
			row("ZT-01", "BDD-ZT-001", "mesh", "go", pending, "the mesh (with mTLS) is deployed", "two services talk via HTTP/2", "the call is carried AND logged."),
			row("ZT-02", "BDD-ZT-002", "mesh", "go", pending, "the mesh (with mTLS) is deployed", "a pod starts", "it is admitted [signed] only $ok^."),
			shared1,
			row("ZT-16", "BDD-ZT-016", "documentation", "js", pending, "the guide exists", "a reader follows it", "the setup/usage is reproduced."),
			shared2,
			row("TDR-BDD-01", "BDD-TDR-001", "lifecycle", "js", implemented, "an approved release", "the workflow runs", "it is Ready."),
		},
	}
}

const lifecycle = `@cluster
Feature: Deployment lifecycle
  Hand-written.

  @TDR-BDD-01 @BDD-TDR-001
  Scenario: Successful deployment
    A description is allowed.

    Given an approved release
    When the workflow runs
    Then it is Ready.

  Scenario: an untagged regression check
    Given anything at all
`

// pack is the rendered feature files plus the hand-written lifecycle file.
func pack(t *testing.T, annex Annex) map[string]string {
	t.Helper()
	if err := validate(annex); err != nil {
		t.Fatal(err)
	}
	features := map[string]string{"features/js/lifecycle.feature": lifecycle}
	for path, content := range render(annex) {
		if strings.HasSuffix(path, ".feature") {
			features[path] = content
		}
	}
	return features
}

func with(features map[string]string, path, content string) map[string]string {
	out := map[string]string{path: content}
	for p, c := range features {
		if p != path {
			out[p] = c
		}
	}
	return out
}

func wantError(t *testing.T, err error, fragment string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), fragment) {
		t.Fatalf("want an error containing %q, got %v", fragment, err)
	}
}

func TestRenderedPackIsVerbatimAndComplete(t *testing.T) {
	annex := sample()
	if err := verify(annex, pack(t, annex)); err != nil {
		t.Fatal(err)
	}
}

func TestRenderIsDeterministic(t *testing.T) {
	a, b := render(sample()), render(sample())
	for path := range a {
		if a[path] != b[path] {
			t.Fatalf("%s differs between two renders", path)
		}
	}
}

func TestSharedExecutionIsOneScenarioWithBothRows(t *testing.T) {
	doc := render(sample())["features/js/documentation.feature"]
	if n := strings.Count(doc, "Scenario:"); n != 2 {
		t.Fatalf("%d scenarios, want 2 (ZT-16, and ZT-42/ZT-79 together):\n%s", n, doc)
	}
	if !strings.Contains(doc, "@ZT-42 @BDD-ZT-042 @ZT-79 @BDD-ZT-079 @pending\n") {
		t.Fatalf("the shared scenario does not carry both rows:\n%s", doc)
	}
}

func TestSharedExecutionMustMatchItsRows(t *testing.T) {
	annex := sample()
	annex.Rows[4].SharedExecution = nil
	wantError(t, validate(annex), "ZT-79: a shared evidence path goes with a shared execution")

	annex = sample()
	annex.Rows[2].SharedExecution = []string{"BDD-ZT-042", "BDD-ZT-080"}
	annex.Rows[4].SharedExecution = []string{"BDD-ZT-042", "BDD-ZT-080"}
	wantError(t, validate(annex), "shared execution [BDD-ZT-042 BDD-ZT-080] is traced to [BDD-ZT-042 BDD-ZT-079]")
}

func TestStatementMustRoundTrip(t *testing.T) {
	annex := sample()
	annex.Rows[0].Then = "the call is carried."
	wantError(t, validate(annex), "ZT-01: the clauses do not rebuild the statement")
}

func TestOneCharacterChangeFailsVerbatim(t *testing.T) {
	annex := sample()
	features := pack(t, annex)
	for path, content := range features {
		// Drop the period that ends the file's first Then step.
		then := strings.Index(content, "    Then ")
		i := then + strings.Index(content[then:], ".\n")
		wantError(t, verify(annex, with(features, path, content[:i]+content[i+1:])), "step differs from the Annex")
	}
}

func TestCompleteness(t *testing.T) {
	annex := sample()
	features := pack(t, annex)

	missing := with(features, "features/js/lifecycle.feature", "")
	wantError(t, verify(annex, missing), "TDR-BDD-01: no scenario")

	duplicate := with(features, "features/js/copy.feature", lifecycle)
	wantError(t, verify(annex, duplicate), "TDR-BDD-01: 2 scenarios")

	unknown := with(features, "features/go/extra.feature", "Feature: x\n\n  @ZT-99\n  Scenario: y\n    Given z\n")
	wantError(t, verify(annex, unknown), "@ZT-99 is not an Annex row")
}

func TestTagsBelongOnTheScenario(t *testing.T) {
	annex := sample()
	for name, tc := range map[string]struct{ from, to, err string }{
		"row tag on the feature":        {"@cluster\nFeature:", "@cluster @TDR-BDD-01\nFeature:", "@TDR-BDD-01 on a feature"},
		"pending on the feature":        {"@cluster\nFeature:", "@cluster @pending\nFeature:", "@pending on a feature"},
		"pending on an implemented row": {"@TDR-BDD-01 @BDD-TDR-001\n", "@TDR-BDD-01 @BDD-TDR-001 @pending\n", "@pending must be present exactly"},
		"wrong test id":                 {"@TDR-BDD-01 @BDD-TDR-001\n", "@TDR-BDD-01 @BDD-TDR-002\n", "test-id tags"},
		"cluster row without @cluster":  {"@cluster\nFeature:", "Feature:", "@cluster must be present exactly"},
	} {
		t.Run(name, func(t *testing.T) {
			features := with(pack(t, annex), "features/js/lifecycle.feature", strings.Replace(lifecycle, tc.from, tc.to, 1))
			wantError(t, verify(annex, features), tc.err)
		})
	}

	features := pack(t, annex)
	mesh := strings.Replace(features["features/go/mesh.feature"], " @pending\n", "\n", 1)
	wantError(t, verify(annex, with(features, "features/go/mesh.feature", mesh)), "@pending must be present exactly")
}

func TestClusterTagOnExamplesIsRejected(t *testing.T) {
	annex := sample()
	outline := strings.Replace(lifecycle, "  Scenario: Successful deployment\n", "  Scenario Outline: Successful deployment - <case>\n", 1)
	outline = strings.Replace(outline, "    Then it is Ready.\n", "    Then it is Ready.\n\n    @cluster\n    Examples:\n      | case |\n      | a    |\n", 1)
	wantError(t, verify(annex, with(pack(t, annex), "features/js/lifecycle.feature", outline)), "@cluster on an examples block")
}

// A Background inside one Rule does not reach the scenarios of another Rule.
func TestBackgroundIsScopedToItsRule(t *testing.T) {
	annex := sample()
	scoped := strings.Replace(lifecycle, "  @TDR-BDD-01 @BDD-TDR-001\n",
		"  Rule: other\n    Background:\n      Given something\n\n    Scenario: x\n      Given y\n\n  Rule: lifecycle\n  @TDR-BDD-01 @BDD-TDR-001\n", 1)
	scoped = strings.Replace(scoped, "  Scenario: an untagged regression check\n    Given anything at all\n", "", 1)
	if err := verify(annex, with(pack(t, annex), "features/js/lifecycle.feature", scoped)); err != nil {
		t.Fatal(err)
	}
	withBackground := strings.Replace(lifecycle, "  @TDR-BDD-01 @BDD-TDR-001\n", "  Background:\n    Given something\n\n  @TDR-BDD-01 @BDD-TDR-001\n", 1)
	wantError(t, verify(annex, with(pack(t, annex), "features/js/lifecycle.feature", withBackground)), "must not follow a Background")
}

func TestALineSeparatorInAClauseIsRejected(t *testing.T) {
	annex := sample()
	annex.Rows[0].Given = "the mesh\u2028is deployed"
	annex.Rows[0].Statement = "GIVEN " + annex.Rows[0].Given + " WHEN " + annex.Rows[0].When + " THEN " + annex.Rows[0].Then
	wantError(t, validate(annex), "ZT-01: a clause is empty, padded or spans lines")
}

func TestPendingStepsAreEscapedAndDeduplicated(t *testing.T) {
	annex := sample()
	goTexts := pendingTexts(annex.Rows, "go")
	if len(goTexts) != 5 { // the Given shared by ZT-01 and ZT-02 is registered once
		t.Fatalf("go pending texts = %d, want 5: %q", len(goTexts), goTexts)
	}
	jsTexts := pendingTexts(annex.Rows, "js")
	if len(jsTexts) != 6 { // ZT-42 and ZT-79 share all three clauses
		t.Fatalf("js pending texts = %d, want 6: %q", len(jsTexts), jsTexts)
	}
	for _, text := range append(goTexts, jsTexts...) {
		body := strings.TrimSuffix(strings.TrimPrefix(jsPattern(text), "/"), "/")
		if regexp.MustCompile(`(^|[^\\])/`).MatchString(body) {
			t.Errorf("unescaped / ends the JavaScript literal early: %s", jsPattern(text))
		}
		// Every escape the JavaScript literal uses means the same in Go regexp.
		for name, pattern := range map[string]string{"go": goPattern(text), "js": body} {
			re := regexp.MustCompile(pattern)
			if !re.MatchString(text) {
				t.Errorf("%s pattern %s does not match %q", name, pattern, text)
			}
			if re.MatchString(text + " ") {
				t.Errorf("%s pattern %s is not anchored", name, pattern)
			}
			if strings.Contains(text, ".") && re.MatchString(strings.Replace(text, ".", "x", 1)) {
				t.Errorf("%s pattern %s reads . as a wildcard", name, pattern)
			}
		}
	}
	js := render(annex)["features/js/steps/pending.gen.mjs"]
	if !strings.Contains(js, `Given(/^the setup\/usage is reproduced\.$/, pending)`) {
		t.Fatalf("js pending steps:\n%s", js)
	}
}

func TestSharedClauseMustShareStatus(t *testing.T) {
	annex := sample()
	annex.Rows[1] = row("ZT-02", "BDD-ZT-002", "lifecycle", "js", implemented, "the mesh (with mTLS) is deployed", "a pod starts", "it is admitted.")
	wantError(t, validate(annex), "is shared by implemented [ZT-02] and pending [ZT-01] rows")
}

func TestPendingRowNeverCarriesCluster(t *testing.T) {
	annex := sample()
	annex.Rows[0].Cluster = true
	wantError(t, validate(annex), "ZT-01: a pending row never carries @cluster")
}

func TestCheckFailsOnAStaleGeneratedFile(t *testing.T) {
	root := t.TempDir()
	write := func(path, content string) {
		t.Helper()
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	source, err := json.Marshal(sample())
	if err != nil {
		t.Fatal(err)
	}
	write(annexPath, string(source))
	write("features/js/lifecycle.feature", lifecycle)

	wantError(t, run(root, true), "generated files are stale")
	if err := run(root, false); err != nil {
		t.Fatal(err)
	}
	if err := run(root, true); err != nil {
		t.Fatal(err)
	}

	write("docs/bdd-catalogue.md", "edited by hand\n")
	wantError(t, run(root, true), "docs/bdd-catalogue.md")
	if err := run(root, false); err != nil {
		t.Fatal(err)
	}

	write("features/go/retired.feature", "# "+generated+"\nFeature: retired\n")
	wantError(t, run(root, true), "features/go/retired.feature is generated but the Annex no longer produces it")
}

func TestCatalogueEvidenceBasisComesFromTheRun(t *testing.T) {
	dir := t.TempDir()
	for path, content := range map[string]string{
		"bdd-tdr-001/ionos/main/scenario.json":  `{"row":"TDR-BDD-01","target":"ionos","run":"ci-1","chart":"/opt/ztd/charts/lifecycle-fixture","fixture":true}`,
		"bdd-tdr-001/osc/main/scenario.json":    `{"row":"TDR-BDD-01","target":"osc","run":"ci-1","chart":"/opt/ztd/charts/umbrella","fixture":false}`,
		"bdd-tdr-001/ionos/other/scenario.json": `{"row":"TDR-BDD-01","target":"ionos","run":"ci-1","chart":"/opt/ztd/charts/lifecycle-fixture","fixture":true}`,
	} {
		full := filepath.Join(dir, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	basis, err := evidenceBasis(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := "fixture release on ionos (run ci-1); release /opt/ztd/charts/umbrella on osc (run ci-1)"
	if basis["TDR-BDD-01"] != want {
		t.Fatalf("basis = %q, want %q", basis["TDR-BDD-01"], want)
	}

	page := renderCatalogue(sample(), basis)
	for _, fragment := range []string{
		"| Evidence basis | " + want + " |",
		"| Evidence basis | none (pending) |",
		"| Test data | `features/fixtures/charts/lifecycle-fixture/`",
		"one shared execution for BDD-ZT-042 and BDD-ZT-079",
		"Then the setup/usage is reproduced.\n```",
	} {
		if !strings.Contains(page, fragment) {
			t.Errorf("the catalogue lacks %q", fragment)
		}
	}
	if !strings.Contains(renderCatalogue(sample(), nil), "| Evidence basis | recorded per run |") {
		t.Error("the committed catalogue claims a basis without a run")
	}
}

// A crashed run leaves no evidence, or a truncated record: the catalogue is still rendered.
func TestCatalogueSurvivesACrashedRun(t *testing.T) {
	basis, err := evidenceBasis(filepath.Join(t.TempDir(), "missing"))
	if err != nil || len(basis) != 0 {
		t.Fatalf("missing evidence dir: basis %v, err %v", basis, err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "scenario.json"), []byte(`{"row":"TDR-BDD-01","tar`), 0o644); err != nil {
		t.Fatal(err)
	}
	basis, err = evidenceBasis(dir)
	if err != nil || len(basis) != 0 {
		t.Fatalf("truncated record: basis %v, err %v", basis, err)
	}
	if !strings.Contains(renderCatalogue(sample(), basis), "| Evidence basis | no evidence in this run |") {
		t.Fatal("a row without evidence is not marked")
	}
}

// Every field check of the source has its own failing case.
func TestValidateRejectsMalformedFields(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*Row)
		err    string
	}{
		"row id":        {func(r *Row) { r.ID = "ZT-1" }, `"ZT-1": invalid or duplicate row id`},
		"test id":       {func(r *Row) { r.TestID = "BDD-ZT-1" }, `invalid test id "BDD-ZT-1"`},
		"family":        {func(r *Row) { r.Family = "nowhere" }, `unknown family "nowhere"`},
		"runner":        {func(r *Row) { r.Runner = "py" }, "runner must be go or js"},
		"status":        {func(r *Row) { r.Status = "done" }, "status must be implemented or pending"},
		"evidence path": {func(r *Row) { r.EvidencePath = "evidence/zt-001/" }, `evidence path "evidence/zt-001/"`},
		"padded clause": {func(r *Row) { r.Given = " x"; r.Statement = "GIVEN  x WHEN " + r.When + " THEN " + r.Then }, "a clause is empty, padded or spans lines"},
	} {
		t.Run(name, func(t *testing.T) {
			annex := sample()
			tc.mutate(&annex.Rows[0])
			wantError(t, validate(annex), tc.err)
		})
	}
	annex := sample()
	annex.Rows[1].ID = annex.Rows[0].ID
	wantError(t, validate(annex), `"ZT-01": invalid or duplicate row id`)
}
