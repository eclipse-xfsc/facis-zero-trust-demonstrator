package protectedresource

import (
	"context"
	"errors"
	"time"
)

type Outcome string

const (
	OutcomeSuccess     Outcome = "success"
	OutcomeDenied      Outcome = "denied"
	OutcomeUnavailable Outcome = "unavailable"
	OutcomeError       Outcome = "error"
)

const (
	ReasonSuccess            = "SAMPLE_RESOURCE_RETURNED"
	ReasonDenied             = "SAMPLE_ACCESS_DENIED"
	ReasonUnavailable        = "SAMPLE_RESOURCE_UNAVAILABLE"
	ReasonError              = "SAMPLE_RESOURCE_ERROR"
	ReasonSlowSuccess        = "SAMPLE_SLOW_RESOURCE_RETURNED"
	ReasonRequestTimeout     = "SAMPLE_REQUEST_TIMEOUT"
	ReasonCancelled          = "SAMPLE_REQUEST_CANCELLED"
	ReasonInvalidRequest     = "SAMPLE_INVALID_REQUEST"
	ReasonMethodNotAllowed   = "SAMPLE_METHOD_NOT_ALLOWED"
	ReasonUnknownScenario    = "SAMPLE_UNKNOWN_SCENARIO"
	ReasonResourceNotFound   = "SAMPLE_RESOURCE_NOT_FOUND"
	ReasonRequestTooLarge    = "SAMPLE_REQUEST_TOO_LARGE"
	ReasonAdapterFailure     = "SAMPLE_ADAPTER_FAILURE"
	ReasonAlternativeSuccess = "SAMPLE_ALTERNATIVE_RESOURCE_RETURNED"
	ReasonAlternativeSlow    = "SAMPLE_ALTERNATIVE_SLOW_RESOURCE_RETURNED"
)

var ErrResourceNotFound = errors.New("sample resource not found")

type ResourceRequest struct {
	RequestID     string
	CorrelationID string
	Resource      string
	Action        string
	Scenario      string
}

type ResourceResult struct {
	Outcome     Outcome
	ReasonCode  string
	Explanation string
	SafeData    map[string]any
}

type ResourceAdapter interface {
	Request(context.Context, ResourceRequest) (ResourceResult, error)
}

type SampleAdapter struct {
	slowDelay time.Duration
}

type AlternativeAdapter struct {
	sample *SampleAdapter
}

func NewSampleAdapter(slowDelay time.Duration) *SampleAdapter {
	return &SampleAdapter{slowDelay: slowDelay}
}

func NewAlternativeAdapter(slowDelay time.Duration) *AlternativeAdapter {
	return &AlternativeAdapter{sample: NewSampleAdapter(slowDelay)}
}

func NewResourceAdapter(config Config) ResourceAdapter {
	if config.AdapterMode == "sample-alternative" {
		return NewAlternativeAdapter(config.SlowDelay)
	}
	return NewSampleAdapter(config.SlowDelay)
}

func (a *SampleAdapter) Request(ctx context.Context, request ResourceRequest) (ResourceResult, error) {
	if request.Resource != "sample-report" || request.Action != "read" {
		return ResourceResult{}, ErrResourceNotFound
	}

	switch request.Scenario {
	case "success":
		return sampleSuccess(ReasonSuccess, "The deterministic sample report was returned; no authorization or credential verification was performed."), nil
	case "denied":
		return ResourceResult{
			Outcome: OutcomeDenied, ReasonCode: ReasonDenied,
			Explanation: "Access was refused by the selected sample scenario only; this is not a real authorization decision.",
			SafeData:    emptySafeData(),
		}, nil
	case "unavailable":
		return ResourceResult{
			Outcome: OutcomeUnavailable, ReasonCode: ReasonUnavailable,
			Explanation: "The sample resource is unavailable in this deterministic scenario.",
			SafeData:    emptySafeData(),
		}, nil
	case "error":
		return ResourceResult{
			Outcome: OutcomeError, ReasonCode: ReasonError,
			Explanation: "The sample resource returned a deterministic internal error.",
			SafeData:    emptySafeData(),
		}, nil
	case "slow":
		timer := time.NewTimer(a.slowDelay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ResourceResult{}, ctx.Err()
		case <-timer.C:
			return sampleSuccess(ReasonSlowSuccess, "The deterministic sample report was returned after the configured test delay; no authorization or credential verification was performed."), nil
		}
	default:
		return ResourceResult{}, errors.New("unsupported sample scenario")
	}
}

func (a *AlternativeAdapter) Request(ctx context.Context, request ResourceRequest) (ResourceResult, error) {
	result, err := a.sample.Request(ctx, request)
	if err != nil || result.Outcome != OutcomeSuccess {
		return result, err
	}
	if request.Scenario == "slow" {
		result.ReasonCode = ReasonAlternativeSlow
	} else {
		result.ReasonCode = ReasonAlternativeSuccess
	}
	result.Explanation = "The deterministic alternative sample report was returned; no authorization or credential verification was performed."
	result.SafeData = map[string]any{
		"resource": "sample-report",
		"action":   "read",
		"report": map[string]any{
			"id":      "FACIS-SAMPLE-REPORT-ALT-001",
			"title":   "FACIS alternative deterministic sample report",
			"content": "Alternative local sample data for F09 / WP09 / ZT-77 adapter testing only.",
		},
	}
	return result, nil
}

func sampleSuccess(reasonCode, explanation string) ResourceResult {
	return ResourceResult{
		Outcome: OutcomeSuccess, ReasonCode: reasonCode, Explanation: explanation,
		SafeData: map[string]any{
			"resource": "sample-report",
			"action":   "read",
			"report": map[string]any{
				"id":      "FACIS-SAMPLE-REPORT-001",
				"title":   "FACIS deterministic sample report",
				"content": "Local sample data for F04 / WP09 / ZT-75 testing only.",
			},
		},
	}
}

func emptySafeData() map[string]any {
	return map[string]any{}
}
