package atls_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const cmcModule = "github.com/Fraunhofer-AISEC/cmc"

// TestExportedAPIHasNoCMCType lists the exported identifiers of package atls and checks that none
// of their signatures references a CMC type.
func TestExportedAPIHasNoCMCType(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		cmcAliases := map[string]string{}
		for _, imp := range f.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			if !strings.HasPrefix(path, cmcModule) {
				continue
			}
			alias := filepath.Base(path)
			if imp.Name != nil {
				alias = imp.Name.Name
			}
			cmcAliases[alias] = path
		}
		report := func(where string, n ast.Node) {
			checked++
			ast.Inspect(n, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok {
					if id, ok := sel.X.(*ast.Ident); ok {
						if path, ok := cmcAliases[id.Name]; ok {
							t.Errorf("%s: exported %s references %s.%s", fset.Position(sel.Pos()), where, path, sel.Sel.Name)
						}
					}
				}
				return true
			})
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if !d.Name.IsExported() {
					continue
				}
				if d.Recv != nil && !exportedRecv(d.Recv) {
					continue
				}
				report("func "+d.Name.Name, d.Type)
				if d.Recv != nil {
					report("method "+d.Name.Name, d.Recv)
				}
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.TypeSpec:
						if !s.Name.IsExported() {
							continue
						}
						if st, ok := s.Type.(*ast.StructType); ok {
							for _, field := range st.Fields.List {
								if exportedField(field) {
									report("field of "+s.Name.Name, field.Type)
								}
							}
							continue
						}
						if it, ok := s.Type.(*ast.InterfaceType); ok {
							report("interface "+s.Name.Name, it)
							continue
						}
						report("type "+s.Name.Name, s.Type)
					case *ast.ValueSpec:
						for _, n := range s.Names {
							if n.IsExported() {
								if s.Type != nil {
									report("value "+n.Name, s.Type)
								}
								for _, v := range s.Values {
									report("value "+n.Name, v)
								}
							}
						}
					}
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no exported declarations inspected")
	}
}

func exportedRecv(fl *ast.FieldList) bool {
	typ := fl.List[0].Type
	if star, ok := typ.(*ast.StarExpr); ok {
		typ = star.X
	}
	id, ok := typ.(*ast.Ident)
	return ok && id.IsExported()
}

func exportedField(f *ast.Field) bool {
	if len(f.Names) == 0 { // embedded
		typ := f.Type
		if star, ok := typ.(*ast.StarExpr); ok {
			typ = star.X
		}
		switch x := typ.(type) {
		case *ast.Ident:
			return x.IsExported()
		case *ast.SelectorExpr:
			return x.Sel.IsExported()
		}
		return false
	}
	for _, n := range f.Names {
		if n.IsExported() {
			return true
		}
	}
	return false
}

// apiGolden lists the exported API of package atls as frozen at v1: one line per exported
// identifier with its signature.
const apiGolden = "api_v1.txt"

// apiUpdateEnv, set to 1, makes TestExportedAPIFrozen rewrite the listing instead of comparing.
const apiUpdateEnv = "ATLS_API_UPDATE"

const apiHeader = `# Exported API of internal/atls, frozen at v1: one line per exported identifier.
# TestExportedAPIFrozen (api_test.go) regenerates this listing from the package and fails when
# the two differ. A change to the API is deliberate: update docs/attested-channel.md with it
# (its Stability section states which changes need agreement), then regenerate this file with
#   ATLS_API_UPDATE=1 go test -run TestExportedAPIFrozen ./internal/atls
`

// TestExportedAPIFrozen regenerates the listing of the exported API from the non-test files of
// the package and compares it with the committed one. It fails, naming each difference, when an
// exported function, method, type, field, constant or sentinel was added, removed or changed.
func TestExportedAPIFrozen(t *testing.T) {
	got := exportedAPI(t)
	if os.Getenv(apiUpdateEnv) == "1" {
		if err := os.WriteFile(apiGolden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s rewritten; update docs/attested-channel.md with the change", apiGolden)
		return
	}
	data, err := os.ReadFile(apiGolden)
	if err != nil {
		t.Fatalf("the v1 listing of the exported API is missing: %v", err)
	}
	want := string(data)
	if got == want {
		return
	}
	wantLines, gotLines := strings.Split(want, "\n"), strings.Split(got, "\n")
	differences := 0
	for _, l := range wantLines {
		if !slices.Contains(gotLines, l) {
			t.Errorf("only in %s:   %s", apiGolden, l)
			differences++
		}
	}
	for _, l := range gotLines {
		if !slices.Contains(wantLines, l) {
			t.Errorf("only in the package: %s", l)
			differences++
		}
	}
	if differences == 0 {
		t.Errorf("%s holds the right lines in another order or form", apiGolden)
	}
	t.Fatalf("the exported API of internal/atls differs from its v1 freeze (%s). If the change is "+
		"intended, update docs/attested-channel.md and regenerate the listing with %s=1; a removal "+
		"or a changed signature needs agreement first", apiGolden, apiUpdateEnv)
}

// exportedAPI type-checks the non-test files of the package in the working directory and returns
// the listing of its exported API: the header, then one sorted line per identifier.
func exportedAPI(t *testing.T) string {
	t.Helper()
	bp, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, name := range bp.GoFiles {
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	exports := exportFiles(t)
	imp := importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		file, ok := exports[path]
		if !ok {
			return nil, fmt.Errorf("no export data for %s", path)
		}
		return os.Open(file)
	})
	pkg, err := (&types.Config{Importer: imp}).Check(modulePath+"/internal/atls", fset, files, nil)
	if err != nil {
		t.Fatalf("type-check the package: %v", err)
	}

	// Types of this package are named bare, all others by their full import path.
	qual := func(p *types.Package) string {
		if p == pkg {
			return ""
		}
		return p.Path()
	}
	var typ func(types.Type) string
	// signature renders parameters and results by type only: a parameter name is not API.
	signature := func(sig *types.Signature) string {
		tuple := func(tu *types.Tuple, variadic bool) []string {
			out := make([]string, tu.Len())
			for i := range tu.Len() {
				pt := tu.At(i).Type()
				if variadic && i == tu.Len()-1 {
					out[i] = "..." + typ(pt.(*types.Slice).Elem())
					continue
				}
				out[i] = typ(pt)
			}
			return out
		}
		s := "(" + strings.Join(tuple(sig.Params(), sig.Variadic()), ", ") + ")"
		switch res := tuple(sig.Results(), false); len(res) {
		case 0:
		case 1:
			s += " " + res[0]
		default:
			s += " (" + strings.Join(res, ", ") + ")"
		}
		return s
	}
	typ = func(t types.Type) string {
		if sig, ok := t.(*types.Signature); ok {
			return "func" + signature(sig)
		}
		return types.TypeString(t, qual)
	}

	var lines []string
	add := func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }
	scope := pkg.Scope()
	for _, name := range scope.Names() {
		obj := scope.Lookup(name)
		if !obj.Exported() {
			continue
		}
		switch o := obj.(type) {
		case *types.Const:
			add("const %s %s = %s", name, typ(o.Type()), o.Val().ExactString())
		case *types.Var:
			add("var %s %s", name, typ(o.Type()))
		case *types.Func:
			add("func %s%s", name, signature(o.Type().(*types.Signature)))
		case *types.TypeName:
			if o.IsAlias() {
				add("type %s = %s", name, typ(types.Unalias(o.Type())))
				continue
			}
			named := o.Type().(*types.Named)
			switch u := named.Underlying().(type) {
			case *types.Struct:
				add("type %s struct", name)
				for i := range u.NumFields() {
					switch f := u.Field(i); {
					case !f.Exported():
					case f.Embedded():
						add("type %s struct, embedded %s", name, typ(f.Type()))
					default:
						add("type %s struct, %s %s", name, f.Name(), typ(f.Type()))
					}
				}
			case *types.Interface:
				add("type %s interface", name)
				for i := range u.NumMethods() {
					m := u.Method(i)
					if !m.Exported() {
						add("type %s interface, unexported methods", name)
						continue
					}
					add("type %s interface, %s%s", name, m.Name(), signature(m.Type().(*types.Signature)))
				}
			default:
				add("type %s %s", name, typ(u))
			}
			for i := range named.NumMethods() {
				m := named.Method(i)
				if !m.Exported() {
					continue
				}
				sig := m.Type().(*types.Signature)
				recv := name
				if _, ptr := sig.Recv().Type().(*types.Pointer); ptr {
					recv = "*" + name
				}
				add("method (%s) %s%s", recv, m.Name(), signature(sig))
			}
		}
	}
	if len(lines) == 0 {
		t.Fatal("no exported identifier found")
	}
	slices.Sort(lines)
	return apiHeader + strings.Join(slices.Compact(lines), "\n") + "\n"
}

// exportFiles maps every package the atls package depends on to the file holding its compiled
// export data, which the type checker reads instead of the sources of the dependencies.
func exportFiles(t *testing.T) map[string]string {
	t.Helper()
	out, err := exec.Command("go", "list", "-export", "-deps", "-f", "{{if .Export}}{{.ImportPath}}={{.Export}}{{end}}", ".").Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			t.Fatalf("go list -export: %v\n%s", err, ee.Stderr)
		}
		t.Fatalf("go list -export: %v", err)
	}
	files := map[string]string{}
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		if path, file, ok := strings.Cut(line, "="); ok {
			files[path] = file
		}
	}
	return files
}

// TestPinnedVersion: go.mod requires CMC v0.9.15 and does not replace it.
func TestPinnedVersion(t *testing.T) {
	out, err := exec.Command("go", "mod", "edit", "-json", filepath.Join(moduleRoot(t), "go.mod")).Output()
	if err != nil {
		t.Fatal(err)
	}
	var mod struct {
		Require []struct{ Path, Version string }
		Replace []struct{ Old struct{ Path string } }
	}
	if err := json.Unmarshal(out, &mod); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range mod.Require {
		if r.Path == cmcModule {
			found = r.Version == "v0.9.15"
			if !found {
				t.Fatalf("go.mod requires %s %s, want v0.9.15", cmcModule, r.Version)
			}
		}
	}
	if !found {
		t.Fatalf("go.mod does not require %s", cmcModule)
	}
	for _, r := range mod.Replace {
		if strings.HasPrefix(r.Old.Path, cmcModule) {
			t.Fatalf("go.mod replaces %s", r.Old.Path)
		}
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}").Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

// probe compiles (or runs) a throwaway package outside internal/atls, added through a build
// overlay so the source tree is not touched, and returns the go command's output.
func probe(t *testing.T, verb, src string) (string, error) {
	t.Helper()
	root := moduleRoot(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "probe.go")
	if err := os.WriteFile(file, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	virtual := filepath.Join(root, "internal", "zzatlsprobe", "probe.go")
	overlay, _ := json.Marshal(map[string]map[string]string{"Replace": {virtual: file}})
	overlayFile := filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(overlayFile, overlay, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{verb, "-overlay", overlayFile}
	if verb == "build" {
		args = append(args, "-o", os.DevNull)
	}
	cmd := exec.Command("go", append(args, "./internal/zzatlsprobe")...)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	return string(out), err
}

const modulePath = "github.com/eclipse-xfsc/facis-zero-trust-demonstrator"

// 5.12 A non-test package cannot select the in-process backend: the hook package is internal to
// internal/atls, the Config field is unexported, and atlstest refuses to run outside tests.
func TestInProcessBackendUnreachableFromProduction(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles probe packages")
	}
	t.Run("hook package", func(t *testing.T) {
		out, err := probe(t, "build", `package probe

import _ "`+modulePath+`/internal/atls/internal/testhook"
`)
		if err == nil || !strings.Contains(out, "use of internal package") {
			t.Fatalf("importing the hook package from outside internal/atls compiled: %v\n%s", err, out)
		}
	})
	t.Run("config field", func(t *testing.T) {
		out, err := probe(t, "build", `package probe

import "`+modulePath+`/internal/atls"

var _ = atls.Config{inProcess: nil}
`)
		if err == nil || !strings.Contains(out, "inProcess") {
			t.Fatalf("setting the in-process field from outside internal/atls compiled: %v\n%s", err, out)
		}
	})
	t.Run("atlstest outside tests", func(t *testing.T) {
		out, err := probe(t, "run", `package main

import (
	"`+modulePath+`/internal/atls"
	"`+modulePath+`/internal/atls/atlstest"
)

func main() { _ = atlstest.ForceVerdict(atls.Config{}, "success") }
`)
		if err == nil || !strings.Contains(out, "test-only package used outside a test binary") {
			t.Fatalf("atlstest ran outside a test binary: %v\n%s", err, out)
		}
	})
}
