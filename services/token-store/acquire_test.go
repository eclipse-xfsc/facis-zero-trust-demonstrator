package main

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"strings"
	"testing"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/acquire"
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

// A failed acquisition prints its route and reason code, and the cause when the store refused a
// signed outcome that gives one; with no cause there is no such member.
func TestAFailedAcquisitionPrintsItsReasonAndItsCause(t *testing.T) {
	for name, c := range map[string]struct {
		err  error
		want map[string]string
	}{
		"refused outcome with a cause": {&acquire.Error{Code: if03.CodeNotVerified, Cause: if03.CodeRevoked, Err: errors.New("x")},
			map[string]string{"route": "zone-b-api", "reason_code": if03.CodeNotVerified, "cause": if03.CodeRevoked}},
		"wrapped": {fmt.Errorf("acquire: %w", &acquire.Error{Code: if03.CodeNotVerified, Cause: if03.CodeStatusUnavailable, Err: errors.New("x")}),
			map[string]string{"route": "zone-b-api", "reason_code": if03.CodeNotVerified, "cause": if03.CodeStatusUnavailable}},
		"failure without a cause": {&acquire.Error{Code: acquire.CodeOutcomeSource, Err: errors.New("x")},
			map[string]string{"route": "zone-b-api", "reason_code": acquire.CodeOutcomeSource}},
		"not an acquisition's error": {errors.New("x"), map[string]string{"route": "zone-b-api", "reason_code": ""}},
	} {
		if got := acquisitionFailure("zone-b-api", c.err); !maps.Equal(got, c.want) {
			t.Errorf("%s: %v; want %v", name, got, c.want)
		}
	}
}
