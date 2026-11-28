package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
)

// newFileHandler serves one file at one path, from a spec "<url path>=<file>": the proof's static
// server of a fixture. The file is read once, at start.
func newFileHandler(spec string) (http.Handler, error) {
	path, file, ok := strings.Cut(spec, "=")
	if !ok || !strings.HasPrefix(path, "/") || file == "" {
		return nil, fmt.Errorf("SERVE_FILE %q: want <url path>=<file>", spec)
	}
	body, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}), nil
}
