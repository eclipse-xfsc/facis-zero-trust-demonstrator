package participant

import (
	"context"
	"errors"
	"strings"
)

var ErrSampleAdapter = errors.New("sample adapter error")

type RequestAdapter interface {
	Request(context.Context, AdapterRequest) (*AdapterResult, error)
}

type SampleAdapter struct{}

func NewSampleAdapter() *SampleAdapter {
	return &SampleAdapter{}
}

func (a *SampleAdapter) Request(ctx context.Context, request AdapterRequest) (*AdapterResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	scenario := strings.ToLower(strings.TrimSpace(request.Scenario))
	if scenario == "" {
		scenario = "success"
	}

	switch scenario {
	case "success":
		return &AdapterResult{
			Outcome:     OutcomeSuccess,
			ReasonCode:  ReasonSampleGranted,
			Explanation: "The sample adapter completed the protected-resource request.",
			SafeData: map[string]any{
				"resource": request.Resource,
				"action":   request.Action,
				"status":   "sample response received",
			},
		}, nil
	case "denied":
		return &AdapterResult{
			Outcome:     OutcomeDenied,
			ReasonCode:  ReasonSampleDenied,
			Explanation: "The sample adapter refused the protected-resource request.",
			SafeData: map[string]any{
				"resource": request.Resource,
				"action":   request.Action,
				"status":   "sample access refused",
			},
		}, nil
	case "unavailable":
		return &AdapterResult{
			Outcome:     OutcomeUnavailable,
			ReasonCode:  ReasonSampleUnavailable,
			Explanation: "The sample dependency did not provide a response.",
			SafeData: map[string]any{
				"status": "sample dependency unavailable",
			},
		}, nil
	case "error":
		return nil, ErrSampleAdapter
	default:
		return &AdapterResult{
			Outcome:     OutcomeError,
			ReasonCode:  ReasonUnsupportedScenario,
			Explanation: "The requested sample scenario is not supported.",
			SafeData: map[string]any{
				"supportedScenarios": []string{"success", "denied", "unavailable", "error"},
			},
		}, nil
	}
}
