package oauth2provider_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const (
	libraryPath = "authelia.com/provider/oauth2"
	adapterPath = "github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider/authelia"
)

// TestOAuth2LibraryIsImportedOnlyByItsAdapter keeps the third-party OAuth 2.0
// library behind the adapter. It looks at the imports each package declares
// itself, test files included - not at transitive dependencies, which every
// consumer of the adapter legitimately has.
func TestOAuth2LibraryIsImportedOnlyByItsAdapter(t *testing.T) {
	root, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}").Output()
	if err != nil {
		t.Fatalf("locate module root: %v", err)
	}

	list := exec.Command("go", "list", "-json=ImportPath,Imports,TestImports,XTestImports", "./...")
	list.Dir = strings.TrimSpace(string(root))

	var stderr bytes.Buffer
	list.Stderr = &stderr

	out, err := list.Output()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, stderr.String())
	}

	type pkg struct {
		ImportPath   string
		Imports      []string
		TestImports  []string
		XTestImports []string
	}

	var checked int

	for decoder := json.NewDecoder(bytes.NewReader(out)); ; {
		var p pkg

		if err = decoder.Decode(&p); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatalf("decode go list output: %v", err)
		}

		checked++

		if p.ImportPath == adapterPath {
			continue
		}

		for _, imported := range append(append(p.Imports, p.TestImports...), p.XTestImports...) {
			if isLibraryPackage(imported) {
				t.Errorf("%s imports %s; only %s may", p.ImportPath, imported, adapterPath)
			}
		}
	}

	if checked == 0 {
		t.Fatal("go list reported no packages, so nothing was checked")
	}
}

// TestAdapterExposesNoLibraryTypes keeps the library out of the adapter's own
// API. The import test above cannot see a library type handed to callers
// through the adapter's exported API: the caller would receive it without
// importing the library. This test type-checks the adapter and follows every
// type a caller can reach from an exported identifier - through aliases,
// pointers, containers, type arguments, and the exported fields and methods
// of the unexported types in between - and fails when any of them is
// declared by the library.
func TestAdapterExposesNoLibraryTypes(t *testing.T) {
	pkg := adapterPackage(t)

	var exported int

	for _, name := range pkg.Scope().Names() {
		if pkg.Scope().Lookup(name).Exported() {
			exported++
		}
	}

	if exported == 0 {
		t.Fatal("the adapter exports nothing, so nothing was checked")
	}

	for _, exposure := range libraryExposures(pkg) {
		t.Error(exposure)
	}
}

// TestLibraryExposureCheck runs the check behind TestAdapterExposesNoLibraryTypes
// over packages written to hand a library type to callers without naming it
// in an exported signature, and over packages that use the library without
// exposing it. A package of the library's import path stands in for it.
func TestLibraryExposureCheck(t *testing.T) {
	const library = `package oauth2

type Client struct{ ID string }

type Provider interface{ Issue() Client }
`

	exposing := []struct{ name, source, through string }{
		{"exported alias", `type Leak = oauth2.Client`, "Leak"},
		{"unexported alias in an exported result", `type hidden = oauth2.Client

func Leak() hidden { return hidden{} }`, "Leak"},
		{"unexported alias in an exported variable", `type hidden = oauth2.Client

var Leak map[string][]*hidden`, "Leak"},
		{"exported field of an unexported type", `type hidden struct{ Client oauth2.Client }

func Leak() hidden { return hidden{} }`, "Leak"},
		{"library type embedded in an unexported type", `type hidden struct{ oauth2.Client }

func Leak() *hidden { return nil }`, "Leak"},
		{"exported method of an unexported type", `type hidden struct{}

func (hidden) Client() *oauth2.Client { return nil }

func Leak() hidden { return hidden{} }`, "Leak"},
		{"exported method promoted from an unexported type", `type inner struct{}

func (inner) Client() oauth2.Client { return oauth2.Client{} }

type outer struct{ inner }

func Leak() outer { return outer{} }`, "Leak"},
		{"unexported interface in an exported result", `type hidden interface{ Provider() oauth2.Provider }

func Leak() hidden { return nil }`, "Leak"},
		{"library type in an exported method's parameter", `type Public struct{}

func (*Public) Use(oauth2.Provider) {}`, "Public"},
		{"library type as a type argument", `type box[T any] struct{ value T }

func Leak() box[oauth2.Client] { return box[oauth2.Client]{} }`, "Leak"},
		{"library interface as a type constraint", `func Leak[T oauth2.Provider](T) {}`, "Leak"},
	}

	for _, tc := range exposing {
		t.Run("found: "+tc.name, func(t *testing.T) {
			exposures := fixtureExposures(t, library, tc.source)

			if !slices.ContainsFunc(exposures, func(e string) bool { return strings.HasPrefix(e, tc.through+",") }) {
				t.Errorf("the exposure through %s was not found; reported: %q", tc.through, exposures)
			}
		})
	}

	hidden := []struct{ name, source string }{
		{"unexported function", `func use(oauth2.Client) {}`},
		{"unexported field of an exported type", `type Public struct{ client oauth2.Client }`},
		{"unexported method of an exported type", `type Public struct{}

func (Public) client() oauth2.Client { return oauth2.Client{} }`},
		{"unexported type no exported identifier reaches", `type hidden struct{ Client oauth2.Client }

func (hidden) Provider() oauth2.Provider { return nil }

func Public() int { return 0 }`},
	}

	for _, tc := range hidden {
		t.Run("none: "+tc.name, func(t *testing.T) {
			if exposures := fixtureExposures(t, library, tc.source); len(exposures) != 0 {
				t.Errorf("nothing is exposed, yet the check reported %q", exposures)
			}
		})
	}
}

func isLibraryPackage(path string) bool {
	return path == libraryPath || strings.HasPrefix(path, libraryPath+"/")
}

// adapterPackage type-checks the adapter's non-test files. Its dependencies
// are resolved from the export data go list builds for them, so the library
// itself is never type-checked from source here.
func adapterPackage(t *testing.T) *types.Package {
	t.Helper()

	list := exec.Command("go", "list", "-export", "-deps", "-json=ImportPath,Export,Dir,GoFiles", adapterPath)

	var stderr bytes.Buffer
	list.Stderr = &stderr

	out, err := list.Output()
	if err != nil {
		t.Fatalf("go list -export: %v\n%s", err, stderr.String())
	}

	type pkg struct {
		ImportPath string
		Export     string
		Dir        string
		GoFiles    []string
	}

	var (
		exports = map[string]string{}
		adapter pkg
	)

	for decoder := json.NewDecoder(bytes.NewReader(out)); ; {
		var p pkg

		if err = decoder.Decode(&p); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatalf("decode go list output: %v", err)
		}

		exports[p.ImportPath] = p.Export

		if p.ImportPath == adapterPath {
			adapter = p
		}
	}

	if adapter.Dir == "" {
		t.Fatalf("go list did not report %s", adapterPath)
	}

	fset := token.NewFileSet()

	var files []*ast.File

	for _, name := range adapter.GoFiles {
		file, err := parser.ParseFile(fset, filepath.Join(adapter.Dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}

		files = append(files, file)
	}

	lookup := func(path string) (io.ReadCloser, error) {
		export, ok := exports[path]
		if !ok || export == "" {
			return nil, fmt.Errorf("go list built no export data for %s", path)
		}

		return os.Open(export)
	}

	config := types.Config{Importer: importer.ForCompiler(fset, "gc", lookup)}

	checked, err := config.Check(adapterPath, fset, files, nil)
	if err != nil {
		t.Fatalf("type-check the adapter: %v", err)
	}

	return checked
}

// libraryExposures reports each way a caller of pkg reaches a type of the
// library from an exported identifier, as one message per path. From the
// type of an exported identifier a caller reaches, with aliases resolved,
// the element types of pointers, containers and channels, the parameters and
// results of functions, type arguments and constraints, and the exported
// fields and exported methods of any type pkg declares, exported or not.
// Types other packages declare are not followed: the import test keeps the
// library out of the rest of the module, and the standard library has no
// knowledge of it.
func libraryExposures(pkg *types.Package) []string {
	var found []string

	for _, name := range pkg.Scope().Names() {
		object := pkg.Scope().Lookup(name)
		if !object.Exported() {
			continue
		}

		walker := exposureWalker{
			pkg:  pkg,
			seen: map[types.Type]bool{},
			report: func(path []string, typ types.Type) {
				found = append(found, fmt.Sprintf("%s exposes %s, a type of %s", strings.Join(path, ", "), typ, libraryPath))
			},
		}

		walker.visit([]string{name}, object.Type())
	}

	return found
}

type exposureWalker struct {
	pkg    *types.Package
	seen   map[types.Type]bool
	report func(path []string, typ types.Type)
}

func (w *exposureWalker) visit(path []string, typ types.Type) {
	if w.seen[typ] {
		return
	}

	w.seen[typ] = true

	switch t := typ.(type) {
	case *types.Alias:
		w.visit(extend(path, "alias "+t.Obj().Name()), types.Unalias(t))
	case *types.Named:
		w.visitNamed(path, t)
	case *types.Pointer:
		w.visit(path, t.Elem())
	case *types.Slice:
		w.visit(path, t.Elem())
	case *types.Array:
		w.visit(path, t.Elem())
	case *types.Chan:
		w.visit(path, t.Elem())
	case *types.Map:
		w.visit(extend(path, "key"), t.Key())
		w.visit(path, t.Elem())
	case *types.Signature:
		for i := range t.TypeParams().Len() {
			w.visit(extend(path, "constraint of "+t.TypeParams().At(i).Obj().Name()), t.TypeParams().At(i).Constraint())
		}

		w.visitTuple(extend(path, "parameter"), t.Params())
		w.visitTuple(extend(path, "result"), t.Results())
	case *types.Struct:
		for i := range t.NumFields() {
			if field := t.Field(i); field.Exported() {
				w.visit(extend(path, "field "+field.Name()), field.Type())
			}
		}
	case *types.Interface:
		for i := range t.NumMethods() {
			if method := t.Method(i); method.Exported() {
				w.visit(extend(path, "method "+method.Name()), method.Type())
			}
		}
	case *types.TypeParam:
		w.visit(path, t.Constraint())
	case *types.Union:
		for i := range t.Len() {
			w.visit(path, t.Term(i).Type())
		}
	}
}

func (w *exposureWalker) visitTuple(path []string, tuple *types.Tuple) {
	for i := range tuple.Len() {
		w.visit(path, tuple.At(i).Type())
	}
}

func (w *exposureWalker) visitNamed(path []string, named *types.Named) {
	from := named.Obj().Pkg()

	switch {
	case from == nil: // A type of the universe, such as error.
		return
	case isLibraryPackage(from.Path()):
		w.report(path, named)

		return
	}

	for i := range named.TypeArgs().Len() {
		w.visit(extend(path, "type argument"), named.TypeArgs().At(i))
	}

	if from != w.pkg {
		return
	}

	if path[len(path)-1] != named.Obj().Name() {
		path = extend(path, named.Obj().Name())
	}

	w.visit(path, named.Underlying())

	// The method set of the pointer type holds every method a caller can
	// call, promoted ones included; an interface's methods are its own.
	receiver := types.Type(types.NewPointer(named))
	if types.IsInterface(named) {
		receiver = named
	}

	methods := types.NewMethodSet(receiver)

	for i := range methods.Len() {
		if method := methods.At(i).Obj(); method.Exported() {
			w.visit(extend(path, "method "+method.Name()), method.Type())
		}
	}
}

func extend(path []string, step string) []string {
	return append(slices.Clone(path), step)
}

// fixtureExposures type-checks source as a package importing a stand-in for
// the library, declared by library, and returns what the check reports.
func fixtureExposures(t *testing.T, library, source string) []string {
	t.Helper()

	fset := token.NewFileSet()
	lib := typeCheck(t, fset, libraryPath, library, nil)

	source = "package fixture\n\nimport \"" + libraryPath + "\"\n\n" + source

	pkg := typeCheck(t, fset, "example.com/fixture", source, importerFunc(func(path string) (*types.Package, error) {
		if path == libraryPath {
			return lib, nil
		}

		return nil, fmt.Errorf("the fixture imports %s, which is not provided", path)
	}))

	return libraryExposures(pkg)
}

// typeCheck parses and type-checks source as the single file of a package
// with the given import path, resolving its imports through imp.
func typeCheck(t *testing.T, fset *token.FileSet, path, source string, imp types.Importer) *types.Package {
	t.Helper()

	file, err := parser.ParseFile(fset, filepath.Base(path)+".go", source, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	config := types.Config{Importer: imp}

	pkg, err := config.Check(path, fset, []*ast.File{file}, nil)
	if err != nil {
		t.Fatalf("type-check %s: %v", path, err)
	}

	return pkg
}

type importerFunc func(path string) (*types.Package, error)

func (f importerFunc) Import(path string) (*types.Package, error) { return f(path) }
