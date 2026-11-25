package schema

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestUpOnAnEmptyDatabaseAppliesEveryMigration(t *testing.T) {
	db := newTestDatabase(t)
	c := db.conn()
	if got := publicTables(t, c); len(got) != 0 {
		t.Fatalf("the test database is not empty: %v", got)
	}
	r, err := NewRunner(c)
	if err != nil {
		t.Fatal(err)
	}
	applied, err := r.Up(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	ms, _ := Migrations()
	if len(applied) != len(ms) {
		t.Fatalf("applied %d migrations, want %d", len(applied), len(ms))
	}
	status, err := r.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !status.IsCurrent() || status.Current != ms[len(ms)-1].Version {
		t.Errorf("status after up: %+v", status)
	}
	tables := publicTables(t, c)
	var created []string
	for _, m := range ms {
		created = append(created, names(createTable, m.Up)...)
	}
	created = append(created, migrationsTable)
	want := map[string]bool{}
	for _, n := range created {
		want[n] = true
	}
	for _, n := range tables {
		if !want[n] {
			t.Errorf("unexpected table %s", n)
		}
		delete(want, n)
	}
	for n := range want {
		t.Errorf("table %s was not created", n)
	}
}

func TestUpTwiceIsANoOp(t *testing.T) {
	db := newTestDatabase(t)
	c := db.migrated()
	r, _ := NewRunner(c)
	before, err := r.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	applied, err := r.Up(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 0 {
		t.Errorf("second up applied %d migrations, want none", len(applied))
	}
	after, _ := r.Status(context.Background())
	if !reflect.DeepEqual(before, after) {
		t.Errorf("second up changed the record:\nbefore %+v\nafter  %+v", before, after)
	}
}

func TestDownToZeroLeavesAnEmptySchema(t *testing.T) {
	db := newTestDatabase(t)
	c := db.migrated()
	r, _ := NewRunner(c)
	reverted, err := r.Down(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	ms, _ := Migrations()
	if len(reverted) != len(ms) {
		t.Errorf("reverted %d migrations, want %d", len(reverted), len(ms))
	}
	if got := publicTables(t, c); len(got) != 0 {
		t.Errorf("tables left after down to 0: %v", got)
	}
	status, err := r.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.Current != 0 || len(status.Applied) != 0 {
		t.Errorf("status after down to 0: %+v", status)
	}
	// Down on an empty schema is a no-op, not an error.
	if reverted, err := r.Down(context.Background(), 0); err != nil || len(reverted) != 0 {
		t.Errorf("down on an empty schema: %v, %v", reverted, err)
	}
	// And the schema comes back.
	if applied, err := r.Up(context.Background(), 0); err != nil || len(applied) != len(ms) {
		t.Errorf("up after down: %d applied, %v", len(applied), err)
	}
}

func TestAnEditedMigrationIsRefused(t *testing.T) {
	db := newTestDatabase(t)
	c := db.migrated()
	if _, err := c.Exec(context.Background(),
		`UPDATE `+migrationsTable+` SET checksum = repeat('0', 64) WHERE version = 1`); err != nil {
		t.Fatal(err)
	}
	r, _ := NewRunner(c)
	status, err := r.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.IsCurrent() || !reflect.DeepEqual(status.Drift, []int{1}) {
		t.Errorf("drift not reported: %+v", status)
	}
	if _, err := r.Up(context.Background(), 0); !errors.Is(err, ErrDrift) {
		t.Errorf("up with drift: %v, want ErrDrift", err)
	}
	if _, err := r.Down(context.Background(), 0); !errors.Is(err, ErrDrift) {
		t.Errorf("down with drift: %v, want ErrDrift", err)
	}
}

func TestUpRefusesAVersionBeyondTheEmbeddedOnes(t *testing.T) {
	db := newTestDatabase(t)
	r, _ := NewRunner(db.conn())
	_, err := r.Up(context.Background(), 99)
	if err == nil || !strings.Contains(err.Error(), "beyond") {
		t.Errorf("up to 99: %v", err)
	}
	if got := publicTables(t, db.conn()); len(got) != 0 {
		t.Errorf("a refused up left tables: %v", got)
	}
}

func TestDownNeedsATargetOfZeroOrMore(t *testing.T) {
	db := newTestDatabase(t)
	r, _ := NewRunner(db.conn())
	if _, err := r.Down(context.Background(), -1); err == nil {
		t.Error("down to -1 was accepted")
	}
}

// Two runners started together on one database take the lock in turn: both finish, one applies
// the migrations and the other finds them applied, and the schema ends at the latest version once.
func TestConcurrentRunnersSerialise(t *testing.T) {
	db := newTestDatabase(t)
	const runners = 4
	results := make([][]Migration, runners)
	errs := make([]error, runners)
	var wg sync.WaitGroup
	for i := range runners {
		c := db.conn()
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := NewRunner(c)
			if err != nil {
				errs[i] = err
				return
			}
			results[i], errs[i] = r.Up(context.Background(), 0)
		}()
	}
	wg.Wait()
	appliedBy := 0
	for i := range runners {
		if errs[i] != nil {
			t.Errorf("runner %d: %v", i, errs[i])
		}
		if len(results[i]) > 0 {
			appliedBy++
		}
	}
	if appliedBy != 1 {
		t.Errorf("%d runners applied migrations, want exactly 1", appliedBy)
	}
	r, _ := NewRunner(db.conn())
	status, err := r.Status(context.Background())
	if err != nil || !status.IsCurrent() {
		t.Errorf("status after concurrent runs: %+v, %v", status, err)
	}
	ms, _ := Migrations()
	if len(status.Applied) != len(ms) {
		t.Errorf("%d rows in %s, want %d", len(status.Applied), migrationsTable, len(ms))
	}
}

// The runner follows the connection's search_path, as every statement it runs does: a role that
// owns a schema of its own gets the migrations there, and status and down find them there too.
func TestRunnerFollowsTheSearchPath(t *testing.T) {
	db := newTestDatabase(t)
	c := db.conn()
	ctx := context.Background()
	if _, err := c.Exec(ctx, `CREATE SCHEMA app`); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(ctx, `SET search_path TO app`); err != nil {
		t.Fatal(err)
	}
	r, _ := NewRunner(c)
	ms, _ := Migrations()
	if applied, err := r.Up(ctx, 0); err != nil || len(applied) != len(ms) {
		t.Fatalf("up: %d applied, %v", len(applied), err)
	}
	if got := publicTables(t, c); len(got) != 0 {
		t.Errorf("tables landed in public: %v", got)
	}
	if got := tablesIn(t, c, "app"); len(got) < 2 {
		t.Errorf("tables in app after up: %v", got)
	}
	status, err := r.Status(ctx)
	if err != nil || !status.IsCurrent() {
		t.Errorf("status with a non-public search_path: %+v, %v", status, err)
	}
	if reverted, err := r.Down(ctx, 0); err != nil || len(reverted) != len(ms) {
		t.Errorf("down: %d reverted, %v", len(reverted), err)
	}
	if got := tablesIn(t, c, "app"); len(got) != 0 {
		t.Errorf("tables left in app after down to 0: %v", got)
	}
}

// A database migrated by a newer build is ahead of this one. Up applies nothing and status reports
// it current, since migrations only add; down is refused, since only the build that applied a
// migration knows how to revert it.
func TestADatabaseAheadOfTheBuild(t *testing.T) {
	db := newTestDatabase(t)
	c := db.migrated()
	ctx := context.Background()
	latest, _ := Latest()
	if _, err := c.Exec(ctx, `INSERT INTO `+migrationsTable+` (version, name, checksum) VALUES ($1, 'future', repeat('f', 64))`, latest+1); err != nil {
		t.Fatal(err)
	}
	r, _ := NewRunner(c)
	status, err := r.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !status.IsCurrent() || status.Current != latest+1 || len(status.Drift) != 0 {
		t.Errorf("status ahead of the build: %+v", status)
	}
	if applied, err := r.Up(ctx, 0); err != nil || len(applied) != 0 {
		t.Errorf("up on a database ahead: %d applied, %v; want nothing and no error", len(applied), err)
	}
	if _, err := r.Down(ctx, 0); err == nil || !strings.Contains(err.Error(), "newer build") {
		t.Errorf("down on a database ahead: %v; want a refusal", err)
	}
	if got := publicTables(t, c); len(got) < 2 {
		t.Errorf("a refused down removed tables: %v", got)
	}
	if _, err := r.Down(ctx, latest+1); err == nil || !strings.Contains(err.Error(), "beyond") {
		t.Errorf("down beyond the embedded migrations: %v; want a refusal", err)
	}
}

// Migration 5 meets a database the earlier store wrote: two active versions of one key (transit
// was rotated and the store followed its latest version without retiring the previous row). Only
// the highest version stays active; a malformed legacy reference and another key are left alone.
func TestMigrationFiveKeepsOnlyTheHighestActiveVersion(t *testing.T) {
	db := newTestDatabase(t)
	c := db.conn()
	ctx := context.Background()
	r, err := NewRunner(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Up(ctx, 4); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(ctx, `INSERT INTO signing_key (key_ref, jkt, alg, state) VALUES
		('transit:k:v1', 'j1', 'ES256', 'active'), ('transit:k:v2', 'j2', 'ES256', 'active'), ('transit:k:v10', 'j10', 'ES256', 'active'),
		('transit:other:v1', 'jo', 'ES256', 'active'), ('transit/legacy', 'jl', 'ES256', 'active')`); err != nil {
		t.Fatal(err)
	}
	// Live tokens bound to the versions the migration retires go with them; one bound to the
	// version that stays active stays live.
	if _, err := c.Exec(ctx, `INSERT INTO verified_outcome (outcome_id, issuer, client_id, challenge, audience, status, claims, verified_at, expires_at) VALUES
		('11111111-1111-4111-8111-111111111111', 'i', 'c', 'ch1', 'a', 'verified', '{}', now(), now() + interval '1 hour'),
		('22222222-2222-4222-8222-222222222222', 'i', 'c', 'ch2', 'b', 'verified', '{}', now(), now() + interval '1 hour');
		INSERT INTO upstream_token (token_id, peer_zone, audience, tenant, outcome_id, token_ref, key_ref, state, issued_at, expires_at, renew_after) VALUES
		('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'zb', 'a', '', '11111111-1111-4111-8111-111111111111', 'kv/a', 'transit:k:v1', 'active', now(), now() + interval '1 hour', now()),
		('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'zb', 'b', '', '22222222-2222-4222-8222-222222222222', 'kv/b', 'transit:k:v10', 'active', now(), now() + interval '1 hour', now())`); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Up(ctx, 0); err != nil {
		t.Fatalf("migration 5 on a database with two active versions: %v", err)
	}
	var tokenStates string
	if err := c.QueryRow(ctx, `SELECT string_agg(key_ref || '=' || state, ',' ORDER BY key_ref) FROM upstream_token`).Scan(&tokenStates); err != nil || tokenStates != "transit:k:v1=retired,transit:k:v10=active" {
		t.Fatalf("tokens after migration 5: %q %v", tokenStates, err)
	}
	rows, err := c.Query(ctx, `SELECT key_ref, state, retired_at IS NOT NULL FROM signing_key ORDER BY key_ref`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]string{}
	for rows.Next() {
		var ref, state string
		var retiredAt bool
		if err := rows.Scan(&ref, &state, &retiredAt); err != nil {
			t.Fatal(err)
		}
		if (state == "retired") != retiredAt {
			t.Errorf("%s: state %s with retired_at set %v", ref, state, retiredAt)
		}
		got[ref] = state
	}
	want := map[string]string{"transit:k:v1": "retired", "transit:k:v2": "retired", "transit:k:v10": "active",
		"transit:other:v1": "active", "transit/legacy": "active"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("after migration 5: %v, want %v", got, want)
	}
}
