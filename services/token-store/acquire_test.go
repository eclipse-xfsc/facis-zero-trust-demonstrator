package main

import (
	"io"
	"strings"
	"testing"
)

func TestParseAcquire(t *testing.T) {
	env := map[string]string{
		"TOKEN_STORE_DATABASE_URL":       "postgres://u:hunter2@db/x",
		"TOKEN_STORE_OPENBAO_URL":        "http://bao:8200",
		"TOKEN_STORE_OPENBAO_TOKEN_FILE": "/run/bao-token",
		"TOKEN_STORE_ACQUIRE_CONFIG":     "/etc/acquire.json",
	}
	get := func(k string) string { return env[k] }
	o, err := parseAcquire("acquire", false, []string{"--route", "zone-b-api"}, get, io.Discard)
	if err != nil || o.route != "zone-b-api" || o.openBaoTokenFile != "/run/bao-token" || o.databaseURL == "" {
		t.Fatalf("%+v %v", o, err)
	}
	if _, err := parseAcquire("acquire", false, nil, get, io.Discard); err == nil {
		t.Error("acquire without --route accepted")
	}
	if _, err := parseAcquire("sweep-orphans", true, nil, get, io.Discard); err != nil {
		t.Errorf("sweep-orphans: %v", err)
	}
	var usage strings.Builder
	_, err = parseAcquire("acquire", false, []string{"--bogus"}, get, &usage)
	if err == nil || strings.Contains(usage.String(), "hunter2") {
		t.Errorf("bad flag: %v; usage leaks the URL: %v", err, strings.Contains(usage.String(), "hunter2"))
	}
	if _, err := parseAcquire("acquire", false, []string{"--route", "r"}, func(string) string { return "" }, io.Discard); err == nil {
		t.Error("missing database accepted")
	}
}
