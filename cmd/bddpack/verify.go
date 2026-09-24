package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	gherkin "github.com/cucumber/gherkin/go/v42"
	messages "github.com/cucumber/messages/go/v34"
)

// verify holds every feature file, hand-written or generated, to the Annex: each row has exactly
// one row-tagged scenario, its Given/When/Then are the Annex clauses byte for byte, and row,
// test-id and @pending tags sit on the scenario only. Scenarios without a row tag are regression
// checks and are ignored.
func verify(annex Annex, files map[string]string) error {
	byID := map[string]Row{}
	for _, r := range annex.Rows {
		byID[r.ID] = r
	}
	var errs []string
	fail := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }
	found := map[string][]string{}

	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		doc, err := gherkin.ParseGherkinDocument(strings.NewReader(files[path]), (&messages.Incrementing{}).NewId)
		if err != nil {
			fail("%s: %v", path, err)
			continue
		}
		if doc.Feature == nil {
			continue
		}
		feature := doc.Feature
		checkOuterTags(path, "feature", feature.Tags, fail)
		// A Background applies to the scenarios of its Feature, or of its Rule only.
		featureBackground := false
		for _, child := range feature.Children {
			featureBackground = featureBackground || child.Background != nil
		}
		var all []*messages.Scenario
		inherited := map[*messages.Scenario][]*messages.Tag{}
		background := map[*messages.Scenario]bool{}
		for _, child := range feature.Children {
			switch {
			case child.Scenario != nil:
				all = append(all, child.Scenario)
				inherited[child.Scenario] = feature.Tags
				background[child.Scenario] = featureBackground
			case child.Rule != nil:
				checkOuterTags(path, "rule", child.Rule.Tags, fail)
				ruleBackground := featureBackground
				for _, rc := range child.Rule.Children {
					ruleBackground = ruleBackground || rc.Background != nil
				}
				for _, rc := range child.Rule.Children {
					if rc.Scenario != nil {
						all = append(all, rc.Scenario)
						inherited[rc.Scenario] = append(append([]*messages.Tag{}, feature.Tags...), child.Rule.Tags...)
						background[rc.Scenario] = ruleBackground
					}
				}
			}
		}

		for _, sc := range all {
			where := fmt.Sprintf("%s:%d", path, sc.Location.Line)
			for _, ex := range sc.Examples {
				checkOuterTags(where, "examples", ex.Tags, fail)
				// Examples tags reach every pickle of the Outline, so a cluster tag there would move
				// examples in or out of the cluster runs; it belongs on the scenario or above.
				if contains(names(ex.Tags), "cluster") {
					fail("%s: @cluster on an examples block; it belongs on the scenario or above", where)
				}
			}
			tags := names(sc.Tags)
			var rows []Row
			for _, t := range tags {
				if rowTagLike.MatchString(t) {
					r, ok := byID[t]
					if !ok {
						fail("%s: @%s is not an Annex row", where, t)
						continue
					}
					rows = append(rows, r)
					found[t] = append(found[t], where)
				}
			}
			if len(rows) == 0 {
				continue // a regression scenario
			}
			if background[sc] {
				fail("%s: a row-tagged scenario must not follow a Background", where)
			}

			var wantTestIDs, gotTestIDs []string
			for _, r := range rows {
				wantTestIDs = append(wantTestIDs, r.TestID)
			}
			for _, t := range tags {
				if testIDLike.MatchString(t) {
					gotTestIDs = append(gotTestIDs, t)
				}
			}
			sort.Strings(wantTestIDs)
			sort.Strings(gotTestIDs)
			if strings.Join(wantTestIDs, " ") != strings.Join(gotTestIDs, " ") {
				fail("%s: test-id tags %v, want %v", where, gotTestIDs, wantTestIDs)
			}

			first := rows[0]
			for _, r := range rows[1:] {
				if r.Statement != first.Statement || r.Status != first.Status || r.Cluster != first.Cluster {
					fail("%s: rows %s and %s share a scenario but not a statement, status or cluster flag", where, first.ID, r.ID)
				}
			}
			if contains(tags, "pending") != (first.Status == pending) {
				fail("%s: @pending must be present exactly when the row is pending", where)
			}
			effective := append(names(inherited[sc]), tags...)
			if contains(effective, "cluster") != first.Cluster {
				fail("%s: @cluster must be present exactly when the row is a cluster row", where)
			}
			if want := featurePath(first); want != path {
				fail("%s: %s belongs in %s", where, first.ID, want)
			}

			keywords := []string{"Given", "When", "Then"}
			want := []string{first.Given, first.When, first.Then}
			if len(sc.Steps) != 3 {
				fail("%s: %d steps, want exactly Given, When, Then", where, len(sc.Steps))
				continue
			}
			var got []string
			for i, st := range sc.Steps {
				if strings.TrimSpace(st.Keyword) != keywords[i] || st.DocString != nil || st.DataTable != nil {
					fail("%s: step %d must be a plain %s", where, i+1, keywords[i])
				}
				if st.Text != want[i] {
					fail("%s: %s step differs from the Annex:\n      got  %q\n      want %q", where, keywords[i], st.Text, want[i])
				}
				got = append(got, st.Text)
			}
			if "GIVEN "+got[0]+" WHEN "+got[1]+" THEN "+got[2] != first.Statement {
				fail("%s: the steps do not rebuild the Annex statement of %s", where, first.ID)
			}
		}
	}

	for _, r := range annex.Rows {
		switch n := len(found[r.ID]); {
		case n == 0:
			fail("%s: no scenario", r.ID)
		case n > 1:
			fail("%s: %d scenarios (%s), want one", r.ID, n, strings.Join(found[r.ID], ", "))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("the pack does not match the Annex:\n  %s", strings.Join(errs, "\n  "))
	}
	return nil
}

// Row, test-id and @pending tags are per scenario; above it they would silently apply to every
// scenario in the file.
func checkOuterTags(where, level string, tags []*messages.Tag, fail func(string, ...any)) {
	for _, t := range names(tags) {
		if rowTagLike.MatchString(t) || testIDLike.MatchString(t) || t == "pending" {
			fail("%s: @%s on a %s; row, test-id and @pending tags belong on the scenario", where, t, level)
		}
	}
}

// Anything shaped like a row or test id counts, so a typo is reported rather than read as an
// untagged regression scenario.
var (
	rowTagLike = regexp.MustCompile(`^(ZT|TDR-BDD|M7)-\d+$`)
	testIDLike = regexp.MustCompile(`^BDD-(ZT|TDR|M7)-\d+$`)
)

func names(tags []*messages.Tag) []string {
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		out = append(out, strings.TrimPrefix(t.Name, "@"))
	}
	return out
}
