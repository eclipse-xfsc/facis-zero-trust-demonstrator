package schema

import (
	"slices"
	"testing"
)

// NewRunnerWith takes migrations a caller loaded once. It refuses what the runner cannot index by
// version: nothing at all, a slice with a gap or out of order, one not starting at 1; and
// otherwise builds the same runner NewRunner does.
func TestNewRunnerWithRefusesWhatItCannotIndex(t *testing.T) {
	ms, err := Migrations()
	if err != nil {
		t.Fatal(err)
	}
	second := Migration{Version: 2, Name: "second", Up: "SELECT 2", Down: "SELECT 2", Checksum: "2"}
	third := Migration{Version: 3, Name: "third", Up: "SELECT 3", Down: "SELECT 3", Checksum: "3"}
	cases := []struct {
		name string
		in   []Migration
	}{
		{"none", nil},
		{"not from 1", []Migration{second}},
		{"a gap", []Migration{ms[0], third}},
		{"out of order", []Migration{second, ms[0]}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewRunnerWith(nil, tc.in); err == nil {
				t.Fatal("want an error")
			}
		})
	}

	with, err := NewRunnerWith(nil, ms)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := NewRunner(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(with.migrations) != len(plain.migrations) || with.migrations[0].Checksum != plain.migrations[0].Checksum {
		t.Errorf("NewRunnerWith and NewRunner disagree: %d and %d migrations", len(with.migrations), len(plain.migrations))
	}
	if _, err := NewRunnerWith(nil, slices.Concat(ms, []Migration{second, third})); err != nil {
		t.Errorf("a longer contiguous slice is refused: %v", err)
	}
}
