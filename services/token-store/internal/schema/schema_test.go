package schema

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// These tests need no database: they check the embedded files themselves.

func TestMigrationsAreContiguousWithUpAndDown(t *testing.T) {
	ms, err := Migrations()
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) == 0 {
		t.Fatal("no migrations embedded")
	}
	for i, m := range ms {
		if m.Version != i+1 {
			t.Errorf("migration %d has version %d", i, m.Version)
		}
		if strings.TrimSpace(m.Up) == "" || strings.TrimSpace(m.Down) == "" {
			t.Errorf("migration %04d_%s is missing its up or down SQL", m.Version, m.Name)
		}
	}
	latest, err := Latest()
	if err != nil || latest != ms[len(ms)-1].Version {
		t.Errorf("Latest() = %d, %v; want %d", latest, err, ms[len(ms)-1].Version)
	}
}

var (
	createTable = regexp.MustCompile(`(?m)^CREATE (?:UNLOGGED )?TABLE (?:IF NOT EXISTS )?(\w+)`)
	dropTable   = regexp.MustCompile(`(?m)^DROP TABLE (?:IF EXISTS )?(\w+)`)
)

// Every table an up file creates, its down file drops, and nothing else: a down that forgets a
// table would leave the schema non-empty after a full revert.
func TestDownDropsExactlyTheTablesUpCreates(t *testing.T) {
	ms, err := Migrations()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ms {
		created := names(createTable, m.Up)
		dropped := names(dropTable, m.Down)
		if strings.Join(created, ",") != strings.Join(dropped, ",") {
			t.Errorf("migration %04d_%s creates %v but drops %v", m.Version, m.Name, created, dropped)
		}
		if strings.Contains(m.Down, "IF EXISTS") {
			t.Errorf("migration %04d_%s: a down file drops what its up created, without IF EXISTS", m.Version, m.Name)
		}
	}
}

func names(re *regexp.Regexp, sql string) []string {
	var out []string
	for _, m := range re.FindAllStringSubmatch(sql, -1) {
		out = append(out, m[1])
	}
	sort.Strings(out)
	return out
}

func TestChecksumIsTheSHA256OfTheUpFile(t *testing.T) {
	ms, err := Migrations()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ms {
		sum := sha256.Sum256([]byte(m.Up))
		if want := hex.EncodeToString(sum[:]); m.Checksum != want {
			t.Errorf("migration %04d checksum %s, want %s", m.Version, m.Checksum, want)
		}
	}
}

// The first migration is the one this schema started with; its checksum is pinned so an edit to
// it fails here, before any database sees the drift.
func TestInitialMigrationIsUnchanged(t *testing.T) {
	ms, err := Migrations()
	if err != nil {
		t.Fatal(err)
	}
	if ms[0].Name != "initial" {
		t.Fatalf("first migration is %q, want initial", ms[0].Name)
	}
	const pinned = "d1dd05ad2a7cad5be6e7b50e8bf2f3f448ac98c6eef7b18c1c3b0f330f54cc86"
	if ms[0].Checksum != pinned {
		t.Errorf("0001_initial changed: checksum %s, pinned %s. A schema change is a new migration, never an edit.", ms[0].Checksum, pinned)
	}
}
