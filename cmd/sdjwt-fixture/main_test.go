package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/statuslist"
)

const committed = "../../features/fixtures/oid4vp"

// TestCommittedTreeIsCurrent regenerates the fixtures into a temporary directory and compares
// everything but signature bytes with the committed tree: the trust set, the status lists, the
// cases with their expectations, claims and digests, and the README's case table. A generator
// change without a regeneration fails here. The tree is committed, so its absence is a defect.
func TestCommittedTreeIsCurrent(t *testing.T) {
	now, _ := time.Parse(time.RFC3339, DefaultNow)
	dir := t.TempDir()
	n, err := Generate(context.Background(), dir, Params{StatusURI: DefaultURI, Audience: DefaultAud, Nonce: DefaultNonce, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	a, b := readFile(t, filepath.Join(committed, "trusted-issuers.json")), readFile(t, filepath.Join(dir, "trusted-issuers.json"))
	if !bytes.Equal(a, b) {
		t.Errorf("trusted-issuers.json differs from the committed one:\n committed %s\n generated %s", a, b)
	}
	for _, name := range statusLists {
		path := filepath.Join("status-lists", name+".jwt")
		a, b := payloadOf(t, strings.TrimSpace(string(readFile(t, filepath.Join(committed, path))))), payloadOf(t, strings.TrimSpace(string(readFile(t, filepath.Join(dir, path)))))
		if a != b {
			t.Errorf("%s differs from the committed one (apart from the signature):\n committed %s\n generated %s", path, a, b)
		}
	}
	want := names(t, filepath.Join(committed, "cases"))
	got := names(t, filepath.Join(dir, "cases"))
	if strings.Join(want, ",") != strings.Join(got, ",") {
		t.Fatalf("cases differ:\n committed %v\n generated %v", want, got)
	}
	if len(got) != n {
		t.Errorf("Generate reported %d cases, wrote %d", n, len(got))
	}
	readme := string(readFile(t, filepath.Join(committed, "README.md")))
	for _, name := range want {
		var a, b Case
		read(t, filepath.Join(committed, "cases", name), &a)
		read(t, filepath.Join(dir, "cases", name), &b)
		a.Input.VPToken, b.Input.VPToken = stripSignatures(a.Input.VPToken), stripSignatures(b.Input.VPToken)
		ja, _ := json.MarshalIndent(a, "", " ")
		jb, _ := json.MarshalIndent(b, "", " ")
		if !bytes.Equal(ja, jb) {
			t.Errorf("%s differs from the committed one (apart from signatures):\n committed %s\n generated %s", name, ja, jb)
		}
		if row := "| `" + strings.TrimSuffix(name, ".json") + "` |"; !strings.Contains(readme, row) {
			t.Errorf("README.md has no row for case %s", name)
		}
	}
}

func TestRun_Usage(t *testing.T) {
	var stderr bytes.Buffer
	for name, args := range map[string][]string{
		"no args":                {},
		"missing --out":          {"regenerate"},
		"unknown mode":           {"other"},
		"empty nonce":            {"regenerate", "--out", t.TempDir(), "--nonce", ""},
		"whitespace nonce":       {"regenerate", "--out", t.TempDir(), "--nonce", "  "},
		"empty listen":           {"serve-status", "--dir", t.TempDir(), "--listen", ""},
		"relative status uri":    {"regenerate", "--out", t.TempDir(), "--status-uri", "lists/1.jwt"},
		"audience without host":  {"regenerate", "--out", t.TempDir(), "--audience", "https:///x"},
		"bad now":                {"regenerate", "--out", t.TempDir(), "--now", "yesterday"},
		"missing --dir":          {"serve-status"},
		"--dir not a directory":  {"serve-status", "--dir", filepath.Join(t.TempDir(), "absent")},
		"unknown regenerate arg": {"regenerate", "--nope"},
	} {
		stderr.Reset()
		if code := run(args, &stderr); code != 2 {
			t.Errorf("%s: exit %d, stderr %q", name, code, stderr.String())
		}
	}
	for _, args := range [][]string{{"-h"}, {"regenerate", "-h"}, {"serve-status", "--help"}} {
		if code := run(args, &stderr); code != 0 {
			t.Errorf("%v: exit %d", args, code)
		}
	}
	stderr.Reset()
	out := t.TempDir()
	if code := run([]string{"regenerate", "--out", out}, &stderr); code != 0 || !strings.Contains(stderr.String(), "wrote the trust set") {
		t.Errorf("regenerate: exit %d, stderr %q", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(out, "cases", "valid.json")); err != nil {
		t.Error(err)
	}
}

func TestStatusHandler(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "clear.jwt"), []byte("a.b.c\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	h := statusHandler(dir, &stderr)
	get := func(method, path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		return rec
	}
	if rec := get(http.MethodGet, "/clear.jwt"); rec.Code != http.StatusOK || rec.Body.String() != "a.b.c\n" ||
		rec.Header().Get("Content-Type") != statuslist.MediaType || rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("clear.jwt: %d %q %v", rec.Code, rec.Body.String(), rec.Header())
	}
	for _, path := range []string{"/missing.jwt", "/clear.txt", "/clear.jwt/", "/../clear.jwt", "/a/clear.jwt", "/", "/..%2fclear.jwt"} {
		if rec := get(http.MethodGet, path); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s: %d", path, rec.Code)
		}
	}
	if rec := get(http.MethodPost, "/clear.jwt"); rec.Code != http.StatusNotFound {
		t.Errorf("POST: %d", rec.Code)
	}
	// One line per request, the path quoted so a crafted path cannot forge a line.
	stderr.Reset()
	get(http.MethodGet, "/x%0aforged.jwt")
	if lines := strings.Count(stderr.String(), "\n"); lines != 1 || !strings.Contains(stderr.String(), `"/x\nforged.jwt" 404`) {
		t.Errorf("log: %q", stderr.String())
	}
}

// TestServe_StartsAndStops: the server loop binds, reports, and leaves on a cancelled context.
func TestServe_StartsAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var stderr bytes.Buffer
	done := make(chan int, 1)
	go func() { done <- serve(ctx, t.TempDir(), "127.0.0.1:0", &stderr) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	if code := <-done; code != 0 || !strings.Contains(stderr.String(), "serving") || !strings.Contains(stderr.String(), "stopped") {
		t.Errorf("serve: exit %d, stderr %q", code, stderr.String())
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return data
}

// payloadOf is a JWT's decoded payload: what is compared when only the signature may differ.
func payloadOf(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", token)
	}
	payload, err := jose.DecodeB64(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}

func names(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

func read(t *testing.T, path string, v any) {
	t.Helper()
	if err := json.Unmarshal(readFile(t, path), v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

// stripSignatures blanks what legitimately changes between regenerations: the signature of every
// JWT in the presentation, and the key binding's sd_hash, which covers the issuer signature.
func stripSignatures(vp string) string {
	parts := strings.Split(vp, "~")
	for i, part := range parts {
		dots := strings.Split(part, ".")
		if len(dots) != 3 {
			continue
		}
		dots[2] = ""
		if i == len(parts)-1 { // the key binding
			payload, err := jose.DecodeB64(dots[1])
			if err == nil {
				var m map[string]json.RawMessage
				if json.Unmarshal(payload, &m) == nil {
					delete(m, "sd_hash")
					canon, _ := json.Marshal(m)
					dots[1] = jose.B64(canon)
				}
			}
		}
		parts[i] = strings.Join(dots, ".")
	}
	return strings.Join(parts, "~")
}
