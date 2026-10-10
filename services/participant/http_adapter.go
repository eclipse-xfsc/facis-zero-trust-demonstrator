package participant

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const maxUpstreamResponseBytes = 64 * 1024

var ErrInvalidUpstreamResponse = errors.New("invalid protected resource response")

type HTTPSampleAdapter struct {
	endpoint string
	client   *http.Client
}

type protectedResourceResponse struct {
	RequestID     string         `json:"requestId"`
	CorrelationID string         `json:"correlationId"`
	Source        string         `json:"source"`
	Mode          string         `json:"mode"`
	Outcome       Outcome        `json:"outcome"`
	ReasonCode    string         `json:"reasonCode"`
	Explanation   string         `json:"explanation"`
	Timestamp     time.Time      `json:"timestamp"`
	SafeData      map[string]any `json:"safeData"`
}

func NewRequestAdapter(config Config) RequestAdapter {
	if config.AdapterMode == "http-sample" {
		return NewHTTPSampleAdapter(config.ResourceURL, nil)
	}
	return NewSampleAdapter()
}

func NewHTTPSampleAdapter(resourceURL string, client *http.Client) *HTTPSampleAdapter {
	if client == nil {
		client = &http.Client{}
	}
	transport := *client
	transport.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &HTTPSampleAdapter{
		endpoint: strings.TrimRight(resourceURL, "/") + "/demo",
		client:   &transport,
	}
}

func (a *HTTPSampleAdapter) Request(ctx context.Context, request AdapterRequest) (*AdapterResult, error) {
	body, err := json.Marshal(DemoRequest(request))
	if err != nil {
		return nil, fmt.Errorf("encode protected resource request: %w", err)
	}
	outbound, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build protected resource request: %w", err)
	}
	outbound.Header.Set("Content-Type", "application/json")
	outbound.Header.Set("Accept", "application/json")

	response, err := a.client.Do(outbound)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode >= 300 && response.StatusCode < 400 {
		return nil, ErrInvalidUpstreamResponse
	}
	limited := io.LimitReader(response.Body, maxUpstreamResponseBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, ErrInvalidUpstreamResponse
	}
	if len(raw) == 0 || len(raw) > maxUpstreamResponseBytes {
		return nil, ErrInvalidUpstreamResponse
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var upstream protectedResourceResponse
	if err := decoder.Decode(&upstream); err != nil {
		return nil, ErrInvalidUpstreamResponse
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidUpstreamResponse
	}
	if !validProtectedResourceResponse(response.StatusCode, request, upstream) {
		return nil, ErrInvalidUpstreamResponse
	}

	safeData, ok := sanitizeSafeData(upstream.Outcome, upstream.SafeData)
	if !ok {
		return nil, ErrInvalidUpstreamResponse
	}

	return &AdapterResult{
		Outcome: upstream.Outcome, ReasonCode: upstream.ReasonCode,
		Explanation: upstream.Explanation, SafeData: safeData,
	}, nil
}

const (
	maxUpstreamExplanationBytes = 512
	maxUpstreamSafeTextBytes    = 512
)

// sanitizeSafeData rebuilds safeData from the documented shape only.
// success: {resource:"sample-report", action:"read", report:{id,title,content}}
// every other outcome: {} (empty object).
func sanitizeSafeData(outcome Outcome, data map[string]any) (map[string]any, bool) {
	if outcome != OutcomeSuccess {
		if len(data) != 0 {
			return nil, false
		}
		return map[string]any{}, true
	}
	if len(data) != 3 || data["resource"] != "sample-report" || data["action"] != "read" {
		return nil, false
	}
	report, ok := data["report"].(map[string]any)
	if !ok || len(report) != 3 {
		return nil, false
	}
	clean := make(map[string]any, 3)
	for _, key := range []string{"id", "title", "content"} {
		value, ok := report[key].(string)
		if !ok || !safeText(value, maxUpstreamSafeTextBytes) {
			return nil, false
		}
		clean[key] = value
	}
	return map[string]any{"resource": "sample-report", "action": "read", "report": clean}, true
}

func safeText(value string, maxBytes int) bool {
	if value == "" || len(value) > maxBytes {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func validProtectedResourceResponse(status int, request AdapterRequest, response protectedResourceResponse) bool {
	if response.RequestID != request.RequestID || response.CorrelationID != request.CorrelationID ||
		response.Source != "sample" || response.Mode != "sample" ||
		!safeText(response.Explanation, maxUpstreamExplanationBytes) ||
		response.Timestamp.IsZero() || response.SafeData == nil {
		return false
	}
	if !statusMatchesUpstreamOutcome(status, response.Outcome) {
		return false
	}
	return validProtectedResourceReason(response.Outcome, status, response.ReasonCode)
}

func statusMatchesUpstreamOutcome(status int, outcome Outcome) bool {
	switch outcome {
	case OutcomeSuccess:
		return status == http.StatusOK
	case OutcomeDenied:
		return status == http.StatusForbidden
	case OutcomeUnavailable:
		return status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout
	case OutcomeError:
		return status == http.StatusBadRequest || status == http.StatusNotFound || status >= http.StatusInternalServerError
	default:
		return false
	}
}

func validProtectedResourceReason(outcome Outcome, status int, reason string) bool {
	if outcome == OutcomeError {
		if status != http.StatusBadRequest && status != http.StatusNotFound && status < http.StatusInternalServerError {
			return false
		}
	}
	allowed := map[string]Outcome{
		"SAMPLE_RESOURCE_RETURNED":                  OutcomeSuccess,
		"SAMPLE_SLOW_RESOURCE_RETURNED":             OutcomeSuccess,
		"SAMPLE_ALTERNATIVE_RESOURCE_RETURNED":      OutcomeSuccess,
		"SAMPLE_ALTERNATIVE_SLOW_RESOURCE_RETURNED": OutcomeSuccess,
		"SAMPLE_ACCESS_DENIED":                      OutcomeDenied,
		"SAMPLE_RESOURCE_UNAVAILABLE":               OutcomeUnavailable,
		"SAMPLE_REQUEST_TIMEOUT":                    OutcomeUnavailable,
		"SAMPLE_REQUEST_CANCELLED":                  OutcomeUnavailable,
		"SAMPLE_RESOURCE_ERROR":                     OutcomeError,
		"SAMPLE_INVALID_REQUEST":                    OutcomeError,
		"SAMPLE_UNKNOWN_SCENARIO":                   OutcomeError,
		"SAMPLE_RESOURCE_NOT_FOUND":                 OutcomeError,
		"SAMPLE_REQUEST_TOO_LARGE":                  OutcomeError,
		"SAMPLE_ADAPTER_FAILURE":                    OutcomeError,
	}
	return allowed[reason] == outcome
}
