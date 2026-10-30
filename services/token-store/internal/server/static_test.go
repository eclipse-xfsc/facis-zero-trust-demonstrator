package server

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every record this package writes must carry its request's identifiers, which only a call that
// takes the context can do. This test refuses the calls that cannot: the package-level slog
// functions, which write to the default logger rather than the injected one, and the Logger
// methods that take no context. The key-value store package never logs at all.
func TestEveryLogCallCarriesAContext(t *testing.T) {
	packageLevel := map[string]bool{
		"Debug": true, "Info": true, "Warn": true, "Error": true, "Log": true, "LogAttrs": true,
		"DebugContext": true, "InfoContext": true, "WarnContext": true, "ErrorContext": true,
		"Default": true, "SetDefault": true,
	}
	withoutContext := map[string]bool{"Debug": true, "Info": true, "Warn": true, "Error": true}

	fset := token.NewFileSet()
	scanned := 0
	for _, name := range sourceFiles(t, ".") {
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		scanned++
		imports := map[string]string{}
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			local := path[strings.LastIndex(path, "/")+1:]
			if imp.Name != nil {
				local = imp.Name.Name
			}
			imports[local] = path
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok {
				if path, isImport := imports[id.Name]; isImport {
					if path == "log/slog" && packageLevel[sel.Sel.Name] {
						t.Errorf("%s: slog.%s writes to the default logger; log through the injected one with a context", fset.Position(call.Pos()), sel.Sel.Name)
					}
					return true
				}
			}
			if withoutContext[sel.Sel.Name] && len(call.Args) > 0 {
				t.Errorf("%s: %s takes no context, so its record would carry no correlation id; use %sContext", fset.Position(call.Pos()), sel.Sel.Name, sel.Sel.Name)
			}
			return true
		})
	}
	if scanned == 0 {
		t.Fatal("no source file scanned")
	}

	for _, name := range sourceFiles(t, filepath.Join("..", "openbao")) {
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			if strings.Trim(imp.Path.Value, `"`) == "log/slog" {
				t.Errorf("%s imports log/slog; the key-value store client never logs, its caller does", name)
			}
		}
	}
}

func sourceFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		out = append(out, filepath.Join(dir, name))
	}
	return out
}
