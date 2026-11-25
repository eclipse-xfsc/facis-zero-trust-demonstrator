package bdd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDecidePlaneMatrix holds the ZT-55 scenario's decision to the rule of the verifier's README: a row is
// green when every probe passed or was not applicable, declared when one is the declared opening and none
// failed, failed when one failed; an empty matrix or a foreign header decides nothing, and a matrix that
// lacks either direction between the planes is not held.
func TestDecidePlaneMatrix(t *testing.T) {
	header := strings.Join(planeMatrixColumns, ",")
	line := func(row, verdict string) string {
		return row + `,role,ztd-data,probe,caller,dest,8080,expected,"outcome, with a comma",network,evidence,real,` + verdict
	}
	cases := []struct {
		name    string
		matrix  string
		want    []string
		wantErr string
	}{
		{"green", header + "\n" + line("pdp-adapter-to-tsa", "pass") + "\n" + line("spire-server", "pass") + "\n" + line("spire-server", "n/a") + "\n" + line(reverseRow, "pass"),
			[]string{"pdp-adapter-to-tsa green", "spire-server green", "management-to-data green"}, ""},
		{"declared", header + "\n" + line("catch-all", "pass") + "\n" + line("catch-all", "declared") + "\n" + line(reverseRow, "pass"),
			[]string{"catch-all declared", "management-to-data green"}, ""},
		{"a failed row", header + "\n" + line("tspa", "pass") + "\n" + line("tspa", "fail") + "\n" + line("catch-all", "declared") + "\n" + line(reverseRow, "pass"),
			[]string{"tspa failed", "catch-all declared", "management-to-data green"}, "rows not held: tspa"},
		{"an unknown verdict", header + "\n" + line("tspa", "maybe") + "\n" + line(reverseRow, "pass"), []string{"tspa failed", "management-to-data green"}, "rows not held: tspa"},
		{"the management plane -> data plane direction failed", header + "\n" + line("tspa", "pass") + "\n" + line(reverseRow, "fail"),
			[]string{"tspa green", "management-to-data failed"}, "rows not held: management-to-data"},
		{"no management plane -> data plane line", header + "\n" + line("tspa", "pass"),
			[]string{"tspa green"}, "the management plane -> data plane direction was not probed"},
		{"no data plane -> management plane row", header + "\n" + line(reverseRow, "pass"),
			[]string{"management-to-data green"}, "no row of the data plane -> management plane direction"},
		{"an empty file", "", nil, "the header is not the verifier's"},
		{"a header only", header + "\n", nil, "holds no probe"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := decidePlaneMatrix(strings.NewReader(c.matrix))
			if strings.Join(got, ";") != strings.Join(c.want, ";") {
				t.Errorf("rows %q, want %q", got, c.want)
			}
			switch {
			case c.wantErr == "" && err != nil:
				t.Errorf("unexpected error %v", err)
			case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
				t.Errorf("error %v, want one containing %q", err, c.wantErr)
			}
		})
	}
}

// TestDecidePlaneMatrixSharedCases holds the decision to the cases in testdata/plane-matrix, which the
// verifier's own decider (plan_decide in scripts/verify-plane-separation/plan.sh) is held to as well by
// scripts/verify-plane-separation/verify_test.sh, so that the record and the Annex row cannot drift apart.
// Each <case>.want lists the rows' verdicts in order, then "held" or "not held".
func TestDecidePlaneMatrixSharedCases(t *testing.T) {
	csvs, err := filepath.Glob(filepath.Join("testdata", "plane-matrix", "*.csv"))
	if err != nil || len(csvs) == 0 {
		t.Fatalf("no shared cases in testdata/plane-matrix (%v)", err)
	}
	for _, path := range csvs {
		name := strings.TrimSuffix(filepath.Base(path), ".csv")
		t.Run(name, func(t *testing.T) {
			want, err := os.ReadFile(strings.TrimSuffix(path, ".csv") + ".want")
			if err != nil {
				t.Fatal(err)
			}
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.Close() }()
			rows, err := decidePlaneMatrix(f)
			held := "held"
			if err != nil {
				held = "not held"
			}
			got := strings.Join(append(rows, held), "\n")
			if got != strings.TrimRight(string(want), "\n") {
				t.Errorf("decided\n%s\nwant\n%s", got, want)
			}
		})
	}
}
