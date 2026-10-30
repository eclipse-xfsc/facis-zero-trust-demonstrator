// Package schema holds the authorization database's schema as versioned migrations and applies
// them: forward to a version, back to a version, or a report of where a database stands. The
// migrations are embedded, so the schema a deployment applies is the one its image was built from.
//
// A migration is a pair of files under migrations/, NNNN_name.up.sql and NNNN_name.down.sql,
// numbered from 0001 without gaps. Each applies in its own transaction and is recorded in
// schema_migrations with the SHA-256 of its up file; a later run that finds a recorded checksum
// differing from the embedded file refuses to continue, so an edited migration is a visible error
// rather than a silent divergence.
package schema

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
)

//go:embed migrations/*.sql
var files embed.FS

// Migration is one versioned step: the SQL that applies it and the SQL that reverts it.
type Migration struct {
	Version int
	Name    string
	Up      string
	Down    string
	// Checksum is the hex SHA-256 of Up, recorded when the migration is applied.
	Checksum string
}

var fileName = regexp.MustCompile(`^(\d{4})_([a-z0-9_]+)\.(up|down)\.sql$`)

// Migrations returns the embedded migrations in version order. Versions start at 1 and are
// contiguous, and every version has both an up and a down file; anything else is an error.
func Migrations() ([]Migration, error) {
	entries, err := fs.ReadDir(files, "migrations")
	if err != nil {
		return nil, err
	}
	byVersion := map[int]*Migration{}
	for _, e := range entries {
		m := fileName.FindStringSubmatch(e.Name())
		if m == nil {
			return nil, fmt.Errorf("migration file %q does not match NNNN_name.up.sql / .down.sql", e.Name())
		}
		version, _ := strconv.Atoi(m[1])
		body, err := fs.ReadFile(files, "migrations/"+e.Name())
		if err != nil {
			return nil, err
		}
		mig := byVersion[version]
		if mig == nil {
			mig = &Migration{Version: version, Name: m[2]}
			byVersion[version] = mig
		}
		if mig.Name != m[2] {
			return nil, fmt.Errorf("version %04d has two names, %q and %q", version, mig.Name, m[2])
		}
		switch m[3] {
		case "up":
			mig.Up = string(body)
		case "down":
			mig.Down = string(body)
		}
	}
	out := make([]Migration, 0, len(byVersion))
	for _, mig := range byVersion {
		out = append(out, *mig)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	for i := range out {
		if out[i].Version != i+1 {
			return nil, fmt.Errorf("migration versions must be contiguous from 0001; found %04d at position %d", out[i].Version, i+1)
		}
		if out[i].Up == "" || out[i].Down == "" {
			return nil, fmt.Errorf("migration %04d_%s needs both an up and a down file", out[i].Version, out[i].Name)
		}
		out[i].Checksum = checksum(out[i].Up)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no migrations are embedded")
	}
	return out, nil
}

// Latest is the version the embedded migrations reach.
func Latest() (int, error) {
	ms, err := Migrations()
	if err != nil {
		return 0, err
	}
	return ms[len(ms)-1].Version, nil
}

func checksum(sql string) string {
	sum := sha256.Sum256([]byte(sql))
	return hex.EncodeToString(sum[:])
}
