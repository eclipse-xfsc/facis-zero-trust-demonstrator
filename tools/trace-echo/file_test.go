package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestFileHandlerServesOnePath(t *testing.T) {
	file := filepath.Join(t.TempDir(), "list.json")
	if err := os.WriteFile(file, []byte(`{"id":"list"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	h, err := newFileHandler("/status/1=" + file)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/status/1", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != `{"id":"list"}` {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/other", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("another path answered %d", rec.Code)
	}
	if _, err := newFileHandler("status/1"); err == nil {
		t.Fatal("a spec without <path>=<file> was accepted")
	}
}
