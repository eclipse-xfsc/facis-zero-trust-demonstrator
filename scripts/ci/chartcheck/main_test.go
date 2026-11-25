package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The TSA gate passes on the chart and fails once the pod template reads the bundle declaration,
// whether through its reference or its revision.
func TestTSAGateRefusesABundleBoundPod(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed")
	}
	root, _ := filepath.Abs("../../..")
	chart := filepath.Join(root, "deployment/helm/tsa-policy")
	if err := checkTSA(root, chart); err != nil {
		t.Fatalf("chart refused: %v", err)
	}
	for name, annotation := range map[string]string{
		"revision": "bundle-revision: {{ .Values.bundle.revision | quote }}",
		"ref":      "bundle-ref: {{ .Values.bundle.ref | quote }}",
	} {
		t.Run(name, func(t *testing.T) {
			copied := filepath.Join(t.TempDir(), "tsa-policy")
			if out, err := exec.Command("cp", "-R", chart, copied).CombinedOutput(); err != nil {
				t.Fatalf("%v: %s", err, out)
			}
			path := filepath.Join(copied, "templates/workload.yaml")
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			anchor := "        checksum/config:"
			if !strings.Contains(string(b), anchor) {
				t.Fatal("annotation anchor missing")
			}
			b = []byte(strings.Replace(string(b), anchor, "        "+annotation+"\n"+anchor, 1))
			if err := os.WriteFile(path, b, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := checkTSA(root, copied); err == nil {
				t.Fatal("a pod annotation bound to the bundle declaration passed the gate")
			}
		})
	}
}

// The denial log check passes on the chart's Telemetry and fails once a refusal is no longer logged or
// something else is.
func TestDenialLogFilter(t *testing.T) {
	telemetry := func(expression string) []object {
		return []object{{"kind": "Telemetry", "metadata": object{"name": "mesh-default"},
			"spec": object{"accessLogging": []any{object{"filter": object{"expression": expression}}}}}}
	}
	if _, err := exec.LookPath("helm"); err == nil {
		root, _ := filepath.Abs("../../..")
		mesh, err := render(filepath.Join(root, "deployment/helm/zone-policy"), "")
		if err != nil {
			t.Fatal(err)
		}
		if err := checkDenialLog(mesh); err != nil {
			t.Fatalf("chart refused: %v", err)
		}
	}
	rbac := `response.code_details.startsWith("rbac_access_denied") || connection.termination_details.startsWith("rbac_access_denied")`
	plain := ` || response.code_details == "filter_chain_not_found"`
	if err := checkDenialLog(telemetry(rbac + plain)); err != nil {
		t.Fatalf("the full filter refused: %v", err)
	}
	for name, mesh := range map[string][]object{
		"no plaintext clause": telemetry(rbac),
		"an extra clause":     telemetry(rbac + plain + ` || response.code == 403`),
		"no Telemetry":        nil,
	} {
		if err := checkDenialLog(mesh); err == nil {
			t.Errorf("%s passed the gate", name)
		}
	}
}
