package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/ociclient"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRegistryCredentials(t *testing.T) {
	// "auth" is base64("robot$read:s3cret").
	path := writeConfig(t, `{"auths": {
		"https://harbor.example.org/v1/": {"auth": "cm9ib3QkcmVhZDpzM2NyZXQ="},
		"registry.example.org:5443": {"username": "reader", "password": "pw"}}}`)
	got, err := registryCredentials(path)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]ociclient.Credential{
		"harbor.example.org":        {Username: "robot$read", Password: "s3cret"},
		"registry.example.org:5443": {Username: "reader", Password: "pw"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestRegistryCredentialsRefused(t *testing.T) {
	for name, content := range map[string]string{
		"not JSON":              `auths`,
		"no registry":           `{"auths": {}}`,
		"auth not base64":       `{"auths": {"harbor.example.org": {"auth": "%%%"}}}`,
		"auth without a colon":  `{"auths": {"harbor.example.org": {"auth": "cm9ib3Q="}}}`,
		"no password":           `{"auths": {"harbor.example.org": {"username": "reader"}}}`,
		"credential store only": `{"credsStore": "desktop"}`,
	} {
		if _, err := registryCredentials(writeConfig(t, content)); err == nil {
			t.Errorf("%s: accepted, want an error", name)
		}
	}
	if _, err := registryCredentials(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("a missing file: accepted, want an error")
	}
}
