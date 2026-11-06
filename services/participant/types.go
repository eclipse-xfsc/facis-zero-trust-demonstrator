package participant

import "time"

type Outcome string

const (
	OutcomeSuccess     Outcome = "success"
	OutcomeDenied      Outcome = "denied"
	OutcomeUnavailable Outcome = "unavailable"
	OutcomeError       Outcome = "error"
)

const (
	ReasonSampleGranted       = "SAMPLE_ACCESS_GRANTED"
	ReasonSampleDenied        = "SAMPLE_ACCESS_DENIED"
	ReasonSampleUnavailable   = "SAMPLE_DEPENDENCY_UNAVAILABLE"
	ReasonInvalidRequest      = "SAMPLE_INVALID_REQUEST"
	ReasonMethodNotAllowed    = "SAMPLE_METHOD_NOT_ALLOWED"
	ReasonRequestTimeout      = "SAMPLE_REQUEST_TIMEOUT"
	ReasonConnectionFailure   = "SAMPLE_CONNECTION_FAILURE"
	ReasonAdapterError        = "SAMPLE_ADAPTER_ERROR"
	ReasonAdapterNoResponse   = "SAMPLE_ADAPTER_NO_RESPONSE"
	ReasonUnsupportedScenario = "SAMPLE_UNSUPPORTED_SCENARIO"
)

type DemoRequest struct {
	RequestID     string `json:"requestId,omitempty"`
	CorrelationID string `json:"correlationId,omitempty"`
	Resource      string `json:"resource"`
	Action        string `json:"action"`
	Scenario      string `json:"scenario,omitempty"`
}

type AdapterRequest struct {
	RequestID     string
	CorrelationID string
	Resource      string
	Action        string
	Scenario      string
}

type AdapterResult struct {
	Outcome     Outcome
	ReasonCode  string
	Explanation string
	SafeData    map[string]any
}

type DemoResponse struct {
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
