package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEveryProfile(t *testing.T) {
	for _, p := range []string{"sw", "tpm", "snp", "sgx", "tdx", "azure-tpm", "azure-snp", "azure-tdx"} {
		if _, err := predicate("../../docs/attestation/samples", p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
}

func TestRefusals(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sw.mock.json"), []byte(`{"mock":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, profile := range map[string]string{"invalid sample": "sw", "unknown profile": "quantum", "path traversal": "../sw"} {
		if _, err := predicate(dir, profile); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
