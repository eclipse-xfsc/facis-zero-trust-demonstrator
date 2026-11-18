package protectedresource

import (
	"strings"
	"testing"
)

func TestLoadConfigTokenMode(t *testing.T) {
	for k, v := range map[string]string{
		"PROTECTED_RESOURCE_MODE": "token", "PROTECTED_RESOURCE_TOKEN_ISSUER": "https://connector.test",
		"PROTECTED_RESOURCE_JWKS_URL": "http://127.0.0.1:8080/.well-known/jwks.json", "PROTECTED_RESOURCE_AUDIENCE": "https://resource.test",
		"PROTECTED_RESOURCE_PUBLIC_BASE_URL": "https://resource.test",
	} {
		t.Setenv(k, v)
	}
	cfg, err := LoadConfig()
	if err != nil || cfg.ServingMode() != ModeToken || cfg.Verifier == nil {
		t.Fatalf("LoadConfig: %v %q", err, cfg.ServingMode())
	}
	for _, name := range []string{"PROTECTED_RESOURCE_TOKEN_ISSUER", "PROTECTED_RESOURCE_JWKS_URL",
		"PROTECTED_RESOURCE_AUDIENCE", "PROTECTED_RESOURCE_PUBLIC_BASE_URL"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "")
			if _, err := LoadConfig(); err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("LoadConfig without %s: %v", name, err)
			}
		})
	}
	t.Run("relative JWKS URL", func(t *testing.T) {
		t.Setenv("PROTECTED_RESOURCE_JWKS_URL", "/jwks.json")
		if _, err := LoadConfig(); err == nil {
			t.Fatal("LoadConfig accepted a relative JWKS URL")
		}
	})
	t.Run("sample mode has no verifier", func(t *testing.T) {
		t.Setenv("PROTECTED_RESOURCE_MODE", "sample")
		if cfg, err := LoadConfig(); err != nil || cfg.Verifier != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
	})
}
