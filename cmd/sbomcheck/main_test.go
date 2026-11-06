package main

import "testing"

const sbom = `{"bomFormat":"CycloneDX","specVersion":"1.7","version":1,"components":[
 {"type":"library","name":"golang.org/x/text","version":"v0.42.0","purl":"pkg:golang/golang.org/x/text@v0.42.0"},
 {"type":"library","name":"github.com/cucumber/godog","version":"v0.16.0","purl":"pkg:golang/github.com/cucumber/godog@v0.16.0"},
 {"type":"library","name":"left-pad","version":"1.3.0","purl":"pkg:npm/left-pad@1.3.0"}]}`

func TestComplete(t *testing.T) {
	mods := []module{{"golang.org/x/text", "v0.42.0"}, {"github.com/cucumber/godog", "v0.16.0"}}
	if missing, err := check([]byte(sbom), mods); err != nil || len(missing) != 0 {
		t.Fatalf("complete SBOM: missing %v, err %v", missing, err)
	}
}

func TestMissingModuleOrVersion(t *testing.T) {
	mods := []module{{"golang.org/x/text", "v0.41.0"}, {"golang.org/x/net", "v0.59.0"}, {"github.com/cucumber/godog", "v0.16.0"}}
	missing, err := check([]byte(sbom), mods)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 2 || missing[0].Path != "golang.org/x/net" || missing[1].Path != "golang.org/x/text" {
		t.Fatalf("want x/net and x/text@v0.41.0 missing, got %v", missing)
	}
}

func TestNotCycloneDX(t *testing.T) {
	if _, err := check([]byte(`{"bomFormat":"SPDX"}`), nil); err == nil {
		t.Fatal("non-CycloneDX accepted")
	}
}

func TestModulesFromGoMod(t *testing.T) {
	goMod := `{"Require":[{"Path":"golang.org/x/text","Version":"v0.42.0","Indirect":true},
	 {"Path":"example.com/forked","Version":"v1.0.0"},{"Path":"example.com/local","Version":"v0.1.0"}],
	 "Replace":[{"Old":{"Path":"example.com/forked"},"New":{"Path":"example.com/fork","Version":"v1.0.1"}},
	 {"Old":{"Path":"example.com/local"},"New":{"Path":"../local"}}]}`
	mods, local, err := modulesFromGoMod([]byte(goMod))
	if err != nil {
		t.Fatal(err)
	}
	want := []module{{"golang.org/x/text", "v0.42.0"}, {"example.com/fork", "v1.0.1"}}
	if len(mods) != len(want) || mods[0] != want[0] || mods[1] != want[1] {
		t.Fatalf("modules: got %v, want %v", mods, want)
	}
	if len(local) != 1 || local[0] != "example.com/local" {
		t.Fatalf("local replacements: got %v", local)
	}
	if _, _, err := modulesFromGoMod([]byte(`{`)); err == nil {
		t.Fatal("malformed go.mod JSON accepted")
	}
}

func TestReplacementPrecedence(t *testing.T) {
	// Go applies an exact-version replacement before a wildcard one, whatever the declaration order.
	for _, order := range []string{
		`{"Old":{"Path":"a","Version":"v1.0.0"},"New":{"Path":"specific","Version":"v1.1.0"}},{"Old":{"Path":"a"},"New":{"Path":"fallback","Version":"v1.2.0"}}`,
		`{"Old":{"Path":"a"},"New":{"Path":"fallback","Version":"v1.2.0"}},{"Old":{"Path":"a","Version":"v1.0.0"},"New":{"Path":"specific","Version":"v1.1.0"}}`,
		`{"Old":{"Path":"a"},"New":{"Path":"../local"}},{"Old":{"Path":"a","Version":"v1.0.0"},"New":{"Path":"specific","Version":"v1.1.0"}}`,
	} {
		mods, local, err := modulesFromGoMod([]byte(`{"Require":[{"Path":"a","Version":"v1.0.0"}],"Replace":[` + order + `]}`))
		if err != nil || len(local) != 0 || len(mods) != 1 || mods[0] != (module{"specific", "v1.1.0"}) {
			t.Errorf("order %s: got %v local %v err %v", order, mods, local, err)
		}
	}
}

func TestSelectedVersionsMatch(t *testing.T) {
	required := []module{{"golang.org/x/text", "v0.42.0"}, {"golang.org/x/net", "v0.59.0"}}
	selected := `{"Path":"example.com/main","Main":true}
{"Path":"golang.org/x/text","Version":"v0.43.0"}
{"Path":"golang.org/x/net","Version":"v0.59.0"}`
	diffs, err := versionMismatches(required, []byte(selected))
	if err != nil || len(diffs) != 1 || diffs[0] != "golang.org/x/text: go.mod requires v0.42.0, the build selects v0.43.0" {
		t.Fatalf("got %v, %v", diffs, err)
	}
}
