package participant

import (
	"context"
	"errors"
	"testing"
)

func TestSampleAdapterScenarios(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		scenario   string
		outcome    Outcome
		reasonCode string
		wantError  error
	}{
		{name: "defaults to success", outcome: OutcomeSuccess, reasonCode: ReasonSampleGranted},
		{name: "denied", scenario: "denied", outcome: OutcomeDenied, reasonCode: ReasonSampleDenied},
		{name: "unavailable", scenario: "unavailable", outcome: OutcomeUnavailable, reasonCode: ReasonSampleUnavailable},
		{name: "upstream error", scenario: "error", wantError: ErrSampleAdapter},
		{name: "unsupported", scenario: "unknown", outcome: OutcomeError, reasonCode: ReasonUnsupportedScenario},
	}

	adapter := NewSampleAdapter()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := adapter.Request(context.Background(), AdapterRequest{
				RequestID: "req-adapter", CorrelationID: "corr-adapter",
				Resource: "sample-resource", Action: "read", Scenario: test.scenario,
			})
			if test.wantError != nil {
				if !errors.Is(err, test.wantError) {
					t.Fatalf("Request() error = %v, want %v", err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("Request() unexpected error: %v", err)
			}
			if result.Outcome != test.outcome || result.ReasonCode != test.reasonCode {
				t.Fatalf("Request() = (%q, %q), want (%q, %q)", result.Outcome, result.ReasonCode, test.outcome, test.reasonCode)
			}
		})
	}
}

func TestSampleAdapterHonorsCancelledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := NewSampleAdapter().Request(ctx, AdapterRequest{})
	if result != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("Request() = (%v, %v), want (nil, context.Canceled)", result, err)
	}
}

func TestLoadConfigSelectsParticipantAdapterMode(t *testing.T) {
	t.Run("sample is the default", func(t *testing.T) {
		t.Setenv("PARTICIPANT_ADAPTER_MODE", "")
		t.Setenv("PARTICIPANT_RESOURCE_URL", "")
		config, err := LoadConfig()
		if err != nil {
			t.Fatalf("LoadConfig() error = %v", err)
		}
		if config.AdapterMode != "sample" || config.ResourceURL != "" {
			t.Fatalf("LoadConfig() = %+v", config)
		}
	})

	t.Run("http sample accepts server destination", func(t *testing.T) {
		t.Setenv("PARTICIPANT_ADAPTER_MODE", "http-sample")
		t.Setenv("PARTICIPANT_RESOURCE_URL", "http://127.0.0.1:8086")
		config, err := LoadConfig()
		if err != nil {
			t.Fatalf("LoadConfig() error = %v", err)
		}
		if config.AdapterMode != "http-sample" || config.ResourceURL != "http://127.0.0.1:8086" {
			t.Fatalf("LoadConfig() = %+v", config)
		}
	})

	for _, test := range []struct {
		name string
		mode string
		url  string
	}{
		{name: "missing destination", mode: "http-sample"},
		{name: "relative destination", mode: "http-sample", url: "/protected-resource"},
		{name: "destination credentials", mode: "http-sample", url: "http://user:secret@127.0.0.1:8086"},
		{name: "live mode", mode: "live", url: "http://127.0.0.1:8086"},
		{name: "unknown mode", mode: "other"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("PARTICIPANT_ADAPTER_MODE", test.mode)
			t.Setenv("PARTICIPANT_RESOURCE_URL", test.url)
			if _, err := LoadConfig(); err == nil {
				t.Fatal("LoadConfig() accepted invalid adapter configuration")
			}
		})
	}
}
