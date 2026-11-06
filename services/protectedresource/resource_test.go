package protectedresource

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSampleAdapterScenarios(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		scenario   string
		outcome    Outcome
		reasonCode string
	}{
		{name: "success", scenario: "success", outcome: OutcomeSuccess, reasonCode: ReasonSuccess},
		{name: "denied", scenario: "denied", outcome: OutcomeDenied, reasonCode: ReasonDenied},
		{name: "unavailable", scenario: "unavailable", outcome: OutcomeUnavailable, reasonCode: ReasonUnavailable},
		{name: "error", scenario: "error", outcome: OutcomeError, reasonCode: ReasonError},
		{name: "slow", scenario: "slow", outcome: OutcomeSuccess, reasonCode: ReasonSlowSuccess},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result, err := NewSampleAdapter(time.Millisecond).Request(context.Background(), ResourceRequest{
				Resource: "sample-report", Action: "read", Scenario: test.scenario,
			})
			if err != nil {
				t.Fatalf("Request() error = %v", err)
			}
			if result.Outcome != test.outcome || result.ReasonCode != test.reasonCode || result.Explanation == "" || result.SafeData == nil {
				t.Fatalf("Request() result = %+v", result)
			}
			if test.outcome == OutcomeSuccess && result.SafeData["resource"] != "sample-report" {
				t.Fatalf("success safeData = %#v", result.SafeData)
			}
		})
	}
}

func TestSampleAdapterRejectsUncataloguedResource(t *testing.T) {
	t.Parallel()

	_, err := NewSampleAdapter(time.Millisecond).Request(context.Background(), ResourceRequest{
		Resource: "live-report", Action: "read", Scenario: "success",
	})
	if !errors.Is(err, ErrResourceNotFound) {
		t.Fatalf("Request() error = %v, want ErrResourceNotFound", err)
	}
}

func TestSampleAdapterSlowScenarioHonorsCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewSampleAdapter(time.Hour).Request(ctx, ResourceRequest{
		Resource: "sample-report", Action: "read", Scenario: "slow",
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Request() error = %v, want context.Canceled", err)
	}
}

func TestAlternativeAdapterPreservesSampleContract(t *testing.T) {
	t.Parallel()

	adapter := NewAlternativeAdapter(time.Millisecond)
	for _, test := range []struct {
		scenario string
		outcome  Outcome
	}{
		{scenario: "success", outcome: OutcomeSuccess},
		{scenario: "denied", outcome: OutcomeDenied},
		{scenario: "unavailable", outcome: OutcomeUnavailable},
		{scenario: "error", outcome: OutcomeError},
		{scenario: "slow", outcome: OutcomeSuccess},
	} {
		result, err := adapter.Request(context.Background(), ResourceRequest{
			Resource: "sample-report", Action: "read", Scenario: test.scenario,
		})
		if err != nil {
			t.Fatalf("Request(%q) error = %v", test.scenario, err)
		}
		if result.Outcome != test.outcome || result.ReasonCode == "" || result.Explanation == "" || result.SafeData == nil {
			t.Fatalf("Request(%q) result = %+v", test.scenario, result)
		}
	}

	result, err := adapter.Request(context.Background(), ResourceRequest{
		Resource: "sample-report", Action: "read", Scenario: "success",
	})
	if err != nil {
		t.Fatalf("Request(success) error = %v", err)
	}
	report, ok := result.SafeData["report"].(map[string]any)
	if !ok || report["id"] != "FACIS-SAMPLE-REPORT-ALT-001" || result.ReasonCode != ReasonAlternativeSuccess {
		t.Fatalf("alternative success = %+v", result)
	}
}

func TestLoadConfigSelectsProtectedResourceAdapter(t *testing.T) {
	t.Run("sample is the default", func(t *testing.T) {
		t.Setenv("PROTECTED_RESOURCE_ADAPTER_MODE", "")
		config, err := LoadConfig()
		if err != nil {
			t.Fatalf("LoadConfig() error = %v", err)
		}
		if config.AdapterMode != "sample" {
			t.Fatalf("AdapterMode = %q", config.AdapterMode)
		}
		if _, ok := NewResourceAdapter(config).(*SampleAdapter); !ok {
			t.Fatalf("default adapter = %T", NewResourceAdapter(config))
		}
	})

	t.Run("alternative is selectable", func(t *testing.T) {
		t.Setenv("PROTECTED_RESOURCE_ADAPTER_MODE", "sample-alternative")
		config, err := LoadConfig()
		if err != nil {
			t.Fatalf("LoadConfig() error = %v", err)
		}
		if _, ok := NewResourceAdapter(config).(*AlternativeAdapter); !ok {
			t.Fatalf("selected adapter = %T", NewResourceAdapter(config))
		}
	})

	for _, mode := range []string{"live", "unknown"} {
		t.Run("rejects "+mode, func(t *testing.T) {
			t.Setenv("PROTECTED_RESOURCE_ADAPTER_MODE", mode)
			if _, err := LoadConfig(); err == nil {
				t.Fatalf("LoadConfig() accepted %q", mode)
			}
		})
	}
}

func TestLoadConfigRejectsLiveModeAndUnboundedDelay(t *testing.T) {
	t.Run("live mode", func(t *testing.T) {
		t.Setenv("PROTECTED_RESOURCE_MODE", "live")
		if _, err := LoadConfig(); err == nil {
			t.Fatal("LoadConfig() accepted live mode")
		}
	})

	t.Run("slow delay exceeds request timeout", func(t *testing.T) {
		t.Setenv("PROTECTED_RESOURCE_MODE", "sample")
		t.Setenv("PROTECTED_RESOURCE_REQUEST_TIMEOUT", "10ms")
		t.Setenv("PROTECTED_RESOURCE_SLOW_DELAY", "11ms")
		if _, err := LoadConfig(); err == nil {
			t.Fatal("LoadConfig() accepted a slow delay greater than the request timeout")
		}
	})
}
