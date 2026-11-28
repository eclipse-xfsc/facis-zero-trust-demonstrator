package bdd

import (
	"strings"
	"testing"
)

// TestDecideMesh holds the mesh rows' decision to the verifier's line shapes: each required class of probe
// must be present, passed, on its layer and with its evidence; a row without an impostor is outside ZT-62.
func TestDecideMesh(t *testing.T) {
	header := strings.Join(planeMatrixColumns, ",")
	line := func(row, probe, layer, evidence, verdict string) string {
		return strings.Join([]string{row, "role", "ztd-data", `"` + probe + `"`, "c", "d", "8080", "e", "o", layer, `"` + strings.ReplaceAll(evidence, `"`, `""`) + `"`, "stand-in", verdict}, ",")
	}
	legit := line("tsa", "legitimate caller", "control channel", "the caller's proxy counted 1 request(s) to destination_principal spiffe://td/ns/ztd-mgmt/sa/tsa (istio_requests_total, reporter source)", "pass")
	impostor := line("tsa", "impostor (row labels, service account tsa-impostor)", "mesh", `{"destination":"spiffe://td/ns/ztd-mgmt/sa/tsa","detail":"rbac_access_denied_matched_policy[none]","source":"spiffe://td/ns/ztd-data/sa/tsa-impostor"}`, "pass")
	unlabelled := line("tsa", "unlabelled (service account pdp, no row labels)", "network", "Hubble drop: ... Policy denied DROPPED (TCP Flags: SYN); no new denial line", "pass")
	exportNA := line("otel", "impostor", "mesh", "the row admits every identity", "n/a")
	exportLegit := line("otel", "legitimate caller", "control channel", "the caller's proxy counted 1 request(s) to destination_principal spiffe://td/ns/ztd-mgmt/sa/otel", "pass")
	reset := line("catch-all", "plain text, no identity, behind a probe-scoped opening", "mesh", "the network let the request through (Hubble: ... FORWARDED ...) and the destination's proxy reset it; mutual TLS mode in force: STRICT; opening removed: yes", "pass")
	decide := func(t *testing.T, keep func([]planeLine) map[string]bool, lines []string, checks ...meshCheck) error {
		t.Helper()
		parsed, err := readPlaneLines(strings.NewReader(header + "\n" + strings.Join(lines, "\n")))
		if err != nil {
			t.Fatal(err)
		}
		_, err = decideMesh(keepRows(parsed, keep), checks...)
		return err
	}
	cases := []struct {
		name    string
		keep    func([]planeLine) map[string]bool
		lines   []string
		checks  []meshCheck
		wantErr string
	}{
		{"ZT-62 held", impostorRows, []string{legit, impostor, exportNA, exportLegit}, []meshCheck{legitimateCaller, impostorRefused}, ""},
		{"ZT-62 without an impostor row", impostorRows, []string{exportNA, exportLegit}, []meshCheck{legitimateCaller, impostorRefused}, "no line"},
		{"ZT-62 impostor served", impostorRows, []string{legit, strings.Replace(impostor, ",pass", ",fail", 1)}, []meshCheck{legitimateCaller, impostorRefused}, "tsa from ztd-data, impostor"},
		{"impostor without a denial line", nil, []string{legit, line("tsa", "impostor (x)", "mesh", "no denial line naming the impostor", "pass")}, []meshCheck{impostorRefused}, "impostor (x)"},
		{"legitimate caller not counted", nil, []string{line("tsa", "legitimate caller", "control channel", "the caller's proxy counted 0 request(s) to destination_principal spiffe://td", "pass")}, []meshCheck{legitimateCaller}, "legitimate caller"},
		{"ZT-61 held", nil, []string{legit, impostor, unlabelled, exportNA}, []meshCheck{legitimateCaller, impostorRefused, unlabelledDropped}, ""},
		{"unlabelled dropped without Hubble", nil, []string{line("tsa", "unlabelled (x)", "network", "denied(28)", "pass")}, []meshCheck{unlabelledDropped}, "unlabelled (x)"},
		{"ZT-23 held", nil, []string{legit, reset}, []meshCheck{legitimateCaller, plainTextReset}, ""},
		{"ZT-23 reset under PERMISSIVE", nil, []string{legit, strings.Replace(reset, "STRICT", "PERMISSIVE", 1)}, []meshCheck{legitimateCaller, plainTextReset}, "plain text"},
		{"ZT-23 no bypass probed", nil, []string{legit}, []meshCheck{legitimateCaller, plainTextReset}, "no line"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := decide(t, c.keep, c.lines, c.checks...)
			switch {
			case c.wantErr == "" && err != nil:
				t.Errorf("unexpected error %v", err)
			case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
				t.Errorf("error %v, want one containing %q", err, c.wantErr)
			}
		})
	}
}

// TestDecideRouting holds ZT-26's decision: the role's section, the direct paths and both exemptions, no
// failed check, and a record whose result is 0 failed checks.
func TestDecideRouting(t *testing.T) {
	record := "## egress-route\n\n- PASS: the gateway is available\n\n## direct-path\n\n- PASS: dropped\n  Hubble: Policy denied DROPPED\n\n" +
		"## exemptions\n\n- PASS: DNS (declared bypass, name resolution): ok\n- PASS: observability export (declared bypass, ZT-26): ok\n\nResult: 0 failed check(s).\n"
	cases := []struct{ name, record, role, wantErr string }{
		{"egress held", record, "egress", ""},
		{"wrong role's section", record, "ingress", "no check in section entry"},
		{"a failed check", strings.Replace(record, "- PASS: dropped", "- **FAIL**: dropped", 1), "egress", "direct-path: dropped"},
		{"no export exemption", strings.Replace(record, "- PASS: observability export", "- PASS: other", 1), "egress", "no PASS: observability export"},
		{"a failed result", strings.Replace(record, "Result: 0", "Result: 2", 1), "egress", "the record's result"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := decideRouting(c.record, c.role)
			switch {
			case c.wantErr == "" && err != nil:
				t.Errorf("unexpected error %v", err)
			case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
				t.Errorf("error %v, want one containing %q", err, c.wantErr)
			}
		})
	}
}
