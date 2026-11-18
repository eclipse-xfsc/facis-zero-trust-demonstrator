package protectedresource

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
)

// seedV1 is the versioned demo data. A new data set is a new file (seed/v2.json) with its own version,
// so /health always names the data a response came from.
//
//go:embed seed/v1.json
var seedV1 []byte

type seedReport struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Content string `json:"content"`
}

type seedSummary struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Summary string `json:"summary"`
}

type Seed struct {
	Version           string      `json:"version"`
	Report            seedReport  `json:"report"`
	AlternativeReport seedReport  `json:"alternativeReport"`
	Summary           seedSummary `json:"summary"`
}

var demoSeed = mustLoadSeed(seedV1)

func loadSeed(raw []byte) (Seed, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var seed Seed
	if err := decoder.Decode(&seed); err != nil {
		return Seed{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Seed{}, errors.New("seed must contain one JSON object")
	}
	for _, value := range []string{
		seed.Version, seed.Report.ID, seed.Report.Title, seed.Report.Content,
		seed.AlternativeReport.ID, seed.AlternativeReport.Title, seed.AlternativeReport.Content,
		seed.Summary.ID, seed.Summary.Title, seed.Summary.Summary,
	} {
		if value == "" {
			return Seed{}, errors.New("seed has an empty field")
		}
	}
	return seed, nil
}

func mustLoadSeed(raw []byte) Seed {
	seed, err := loadSeed(raw)
	if err != nil {
		panic("protectedresource: embedded seed invalid: " + err.Error())
	}
	return seed
}

func (r seedReport) safeData() map[string]any {
	return map[string]any{
		"resource": "sample-report", "action": "read",
		"report": map[string]any{"id": r.ID, "title": r.Title, "content": r.Content},
	}
}

func (s seedSummary) safeData() map[string]any {
	return map[string]any{
		"resource": "sample-report", "action": "read",
		"summary": map[string]any{"id": s.ID, "title": s.Title, "summary": s.Summary},
	}
}
