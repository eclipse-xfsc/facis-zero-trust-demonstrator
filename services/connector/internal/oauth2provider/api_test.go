package oauth2provider_test

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

const (
	contractPath = "github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider"

	// apiListing holds the exported API of the contract as frozen at version
	// 1: one line per exported identifier, with its signature.
	apiListing = "api_v1.txt"

	// apiUpdateEnv, set to 1, makes TestContractAPIIsFrozen rewrite the
	// listing instead of comparing against it.
	apiUpdateEnv = "OAUTH2PROVIDER_API_UPDATE"

	// connectorContract is the published definition of the connector's
	// authorization surface, relative to the module root.
	connectorContract = "docs/contracts/if02-connector.v1.openapi.yaml"
)

const apiHeader = `# Exported API of the oauth2provider contract, frozen at version 1: one line per exported
# identifier. A struct field's line carries its position, since a caller may build the struct
# positionally. TestContractAPIIsFrozen (api_test.go) regenerates this listing from the package and
# fails when the two differ. A change to the contract is deliberate: an addition is an ordinary
# change, a removal, a changed signature or a reordered field is a breaking one and is reviewed as
# such. Describe
# the change in docs/oauth2-provider.md, then regenerate this file with
#   OAUTH2PROVIDER_API_UPDATE=1 go test -run TestContractAPIIsFrozen ./services/connector/internal/oauth2provider
`

// TestContractAPIIsFrozen regenerates the listing of the contract's exported
// API and compares it with the committed one. It fails, naming each
// difference, when an exported function, method, type, field or constant
// was added, removed or changed, or when a struct's fields were reordered.
func TestContractAPIIsFrozen(t *testing.T) {
	got := apiHeader + strings.Join(exportedAPI(t, contractPackage(t)), "\n") + "\n"

	if os.Getenv(apiUpdateEnv) == "1" {
		if err := os.WriteFile(apiListing, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}

		t.Logf("%s rewritten; describe the change in docs/oauth2-provider.md", apiListing)

		return
	}

	data, err := os.ReadFile(apiListing)
	if err != nil {
		t.Fatalf("the version 1 listing of the contract is missing: %v", err)
	}

	want := string(data)
	if got == want {
		return
	}

	wantLines, gotLines := strings.Split(want, "\n"), strings.Split(got, "\n")

	for _, line := range wantLines {
		if !slices.Contains(gotLines, line) {
			t.Errorf("only in %s:      %s", apiListing, line)
		}
	}

	for _, line := range gotLines {
		if !slices.Contains(wantLines, line) {
			t.Errorf("only in the package: %s", line)
		}
	}

	t.Fatalf("the contract's exported API differs from its version 1 listing (%s). If the change is intended, "+
		"describe it in docs/oauth2-provider.md and regenerate the listing with %s=1; a removal or a changed "+
		"signature is a breaking change", apiListing, apiUpdateEnv)
}

// TestReasonCodesMatchTheConnectorContract keeps the contract's reason codes
// and the published definition of the connector's error responses in step:
// the codes are part of an interface other components are built against, so
// neither side may gain, lose or rename one alone.
func TestReasonCodesMatchTheConnectorContract(t *testing.T) {
	pkg := contractPackage(t)

	var declared []string

	for _, name := range pkg.Scope().Names() {
		constant, ok := pkg.Scope().Lookup(name).(*types.Const)
		if !ok || !constant.Exported() || types.TypeString(constant.Type(), nil) != contractPath+".Code" {
			continue
		}

		declared = append(declared, strings.Trim(constant.Val().ExactString(), `"`))
	}

	published := publishedReasons(t)

	if len(declared) == 0 || len(published) == 0 {
		t.Fatalf("nothing to compare: %d codes declared, %d published", len(declared), len(published))
	}

	for _, code := range declared {
		if !slices.Contains(published, code) {
			t.Errorf("reason %q is declared by the contract but absent from %s", code, connectorContract)
		}
	}

	for _, code := range published {
		if !slices.Contains(declared, code) {
			t.Errorf("reason %q is published in %s but not declared by the contract", code, connectorContract)
		}
	}
}

// publishedReasons reads the values the published definition allows for the
// reason member of an error response. The file is OpenAPI in YAML; only the
// one list is needed, so it is read by its shape rather than through a YAML
// parser the module would otherwise not depend on.
func publishedReasons(t *testing.T) []string {
	t.Helper()

	root, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}").Output()
	if err != nil {
		t.Fatalf("locate module root: %v", err)
	}

	file, err := os.Open(filepath.Join(strings.TrimSpace(string(root)), filepath.FromSlash(connectorContract)))
	if err != nil {
		t.Fatalf("open the connector contract: %v", err)
	}

	defer func() { _ = file.Close() }()

	var (
		reasons []string
		state   int // 0: before "reason:", 1: expecting "enum:", 2: in the list
	)

	for scanner := bufio.NewScanner(file); scanner.Scan(); {
		line := strings.TrimSpace(scanner.Text())

		switch {
		case state == 0 && line == "reason:":
			state = 1
		case state == 1 && line == "enum:":
			state = 2
		case state == 1:
			state = 0
		case state == 2 && strings.HasPrefix(line, "- "):
			reasons = append(reasons, strings.TrimSpace(strings.TrimPrefix(line, "- ")))
		case state == 2:
			return reasons
		}
	}

	return reasons
}

// contractPackage type-checks the non-test files of the contract package,
// which is the working directory of this test. The result is shared by the
// tests that read it.
func contractPackage(t *testing.T) *types.Package {
	t.Helper()

	pkg, err := loadContractPackage()
	if err != nil {
		t.Fatalf("type-check the contract: %v", err)
	}

	return pkg
}

var loadContractPackage = sync.OnceValues(func() (*types.Package, error) {
	dir, err := build.ImportDir(".", 0)
	if err != nil {
		return nil, err
	}

	fset := token.NewFileSet()

	var files []*ast.File

	for _, name := range dir.GoFiles {
		file, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}

		files = append(files, file)
	}

	// The contract imports the standard library only, which the source
	// importer resolves without build artefacts.
	config := types.Config{Importer: importer.ForCompiler(fset, "source", nil)}

	return config.Check(contractPath, fset, files, nil)
})

// exportedAPI lists the exported API of pkg, one line per identifier, in
// name order. Types of the package itself are named bare, all others by
// import path, and parameters by type only: a parameter name is not part of
// the API. A struct's fields are listed in declaration order and each line
// carries the field's position, so that reordering two fields of one type,
// which a positional literal would not notice, changes the listing.
func exportedAPI(t *testing.T, pkg *types.Package) []string {
	t.Helper()

	qualifier := func(other *types.Package) string {
		if other == pkg {
			return ""
		}

		return other.Path()
	}

	var typeString func(types.Type) string

	signature := func(sig *types.Signature) string {
		tuple := func(tuple *types.Tuple, variadic bool) []string {
			out := make([]string, tuple.Len())

			for i := range tuple.Len() {
				if variadic && i == tuple.Len()-1 {
					out[i] = "..." + typeString(tuple.At(i).Type().(*types.Slice).Elem())

					continue
				}

				out[i] = typeString(tuple.At(i).Type())
			}

			return out
		}

		rendered := "(" + strings.Join(tuple(sig.Params(), sig.Variadic()), ", ") + ")"

		switch results := tuple(sig.Results(), false); len(results) {
		case 0:
		case 1:
			rendered += " " + results[0]
		default:
			rendered += " (" + strings.Join(results, ", ") + ")"
		}

		return rendered
	}

	typeString = func(typ types.Type) string {
		if sig, ok := typ.(*types.Signature); ok {
			return "func" + signature(sig)
		}

		return types.TypeString(typ, qualifier)
	}

	var lines []string

	add := func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }

	for _, name := range pkg.Scope().Names() {
		object := pkg.Scope().Lookup(name)
		if !object.Exported() {
			continue
		}

		switch object := object.(type) {
		case *types.Const:
			add("const %s %s = %s", name, typeString(object.Type()), object.Val().ExactString())
		case *types.Var:
			add("var %s %s", name, typeString(object.Type()))
		case *types.Func:
			add("func %s%s", name, signature(object.Type().(*types.Signature)))
		case *types.TypeName:
			if object.IsAlias() {
				add("type %s = %s", name, typeString(types.Unalias(object.Type())))

				continue
			}

			named := object.Type().(*types.Named)

			switch underlying := named.Underlying().(type) {
			case *types.Struct:
				add("type %s struct", name)

				for i := range underlying.NumFields() {
					switch field := underlying.Field(i); {
					case !field.Exported():
					case field.Embedded():
						add("type %s struct, field %d embedded %s", name, i, typeString(field.Type()))
					default:
						add("type %s struct, field %d %s %s", name, i, field.Name(), typeString(field.Type()))
					}
				}
			case *types.Interface:
				add("type %s interface", name)

				for i := range underlying.NumMethods() {
					method := underlying.Method(i)
					add("type %s interface, %s%s", name, method.Name(), signature(method.Type().(*types.Signature)))
				}
			default:
				add("type %s %s", name, typeString(underlying))
			}

			var methods []string

			for i := range named.NumMethods() {
				method := named.Method(i)
				if !method.Exported() {
					continue
				}

				sig := method.Type().(*types.Signature)

				receiver := name
				if _, pointer := sig.Recv().Type().(*types.Pointer); pointer {
					receiver = "*" + name
				}

				methods = append(methods, fmt.Sprintf("method (%s) %s%s", receiver, method.Name(), signature(sig)))
			}

			slices.Sort(methods)
			lines = append(lines, methods...)
		}
	}

	return lines
}

// TestAPIListingRecordsFieldOrder checks that the listing tells apart two
// declarations of a struct that differ only in the order of two fields of
// one type. A caller building the struct positionally would otherwise get
// the two swapped without the listing changing.
func TestAPIListingRecordsFieldOrder(t *testing.T) {
	const (
		declared = "package p\n\ntype Config struct {\n\tEnforce       bool\n\tNonceRequired bool\n}\n"
		swapped  = "package p\n\ntype Config struct {\n\tNonceRequired bool\n\tEnforce       bool\n}\n"
	)

	fset := token.NewFileSet()
	before := exportedAPI(t, typeCheck(t, fset, "example.com/p", declared, nil))
	after := exportedAPI(t, typeCheck(t, fset, "example.com/p", swapped, nil))

	if slices.Equal(before, after) {
		t.Fatalf("swapping two fields of the same type leaves the listing unchanged:\n%s", strings.Join(before, "\n"))
	}

	for _, field := range []string{"Enforce", "NonceRequired"} {
		index := slices.IndexFunc(before, func(line string) bool { return strings.Contains(line, " "+field+" ") })
		if index < 0 || slices.Contains(after, before[index]) {
			t.Errorf("the line for %s does not change when it moves: %q", field, before)
		}
	}
}
