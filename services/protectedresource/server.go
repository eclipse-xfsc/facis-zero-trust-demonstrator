package protectedresource

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

const maxDemoRequestBytes = 64 * 1024

type Server struct {
	config  Config
	logger  *slog.Logger
	adapter ResourceAdapter
	mux     *http.ServeMux
	now     func() time.Time
}

type healthResponse struct {
	Status    string    `json:"status"`
	Mode      string    `json:"mode"`
	LiveMode  string    `json:"liveMode"`
	Timestamp time.Time `json:"timestamp"`
}

type demoRequest struct {
	Resource      string `json:"resource"`
	Action        string `json:"action"`
	Scenario      string `json:"scenario,omitempty"`
	RequestID     string `json:"requestId,omitempty"`
	CorrelationID string `json:"correlationId,omitempty"`
}

type demoResponse struct {
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

func NewServer(config Config, logger *slog.Logger) *Server {
	return NewServerWithAdapter(config, logger, NewResourceAdapter(config))
}

func NewServerWithAdapter(config Config, logger *slog.Logger, adapter ResourceAdapter) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	server := &Server{
		config: config, logger: logger, adapter: adapter,
		mux: http.NewServeMux(), now: func() time.Time { return time.Now().UTC() },
	}
	server.mux.HandleFunc("/health", server.handleHealth)
	server.mux.HandleFunc("/demo", server.handleDemo)
	return server
}

func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) HTTPServer() *http.Server {
	return &http.Server{
		Addr:              s.config.Address,
		Handler:           s.Handler(),
		ReadTimeout:       s.config.ServerReadTimeout(),
		ReadHeaderTimeout: s.config.RequestTimeout,
		WriteTimeout:      s.config.ServerWriteTimeout(),
		IdleTimeout:       30 * time.Second,
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{
			"status": "error", "mode": "sample", "liveMode": "unavailable",
		})
		return
	}
	writeJSON(w, http.StatusOK, healthResponse{
		Status: "ok", Mode: "sample", LiveMode: "unavailable", Timestamp: s.now(),
	})
}

func (s *Server) handleDemo(w http.ResponseWriter, r *http.Request) {
	requestID := cleanIdentifier(r.Header.Get("X-Request-ID"))
	if requestID == "" {
		requestID = newIdentifier()
	}
	headerCorrelationID := cleanIdentifier(r.Header.Get("X-Correlation-ID"))
	correlationID := headerCorrelationID
	if correlationID == "" {
		correlationID = requestID
	}

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		s.writeDemoResult(w, http.StatusMethodNotAllowed, requestID, correlationID, ResourceResult{
			Outcome: OutcomeError, ReasonCode: ReasonMethodNotAllowed,
			Explanation: "The local demo endpoint accepts POST requests only.", SafeData: emptySafeData(),
		})
		return
	}

	var input demoRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxDemoRequestBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		var sizeError *http.MaxBytesError
		if errors.As(err, &sizeError) {
			s.writeDemoResult(w, http.StatusRequestEntityTooLarge, requestID, correlationID, ResourceResult{
				Outcome: OutcomeError, ReasonCode: ReasonRequestTooLarge,
				Explanation: "The request body exceeds the 64 KiB limit.", SafeData: emptySafeData(),
			})
			return
		}
		s.writeInvalidRequest(w, requestID, correlationID, "The request body must be one valid JSON object with documented fields only.")
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		s.writeInvalidRequest(w, requestID, correlationID, "The request body must contain one JSON object only.")
		return
	}

	if value := cleanIdentifier(input.RequestID); value != "" {
		requestID = value
	}
	if value := cleanIdentifier(input.CorrelationID); value != "" {
		correlationID = value
	} else if headerCorrelationID != "" {
		correlationID = headerCorrelationID
	} else {
		correlationID = requestID
	}

	resource := strings.TrimSpace(input.Resource)
	action := strings.TrimSpace(input.Action)
	if resource == "" || action == "" {
		s.writeInvalidRequest(w, requestID, correlationID, "resource and action are required.")
		return
	}
	scenario := strings.ToLower(strings.TrimSpace(input.Scenario))
	if scenario == "" {
		scenario = "success"
	}
	if !knownScenario(scenario) {
		s.writeDemoResult(w, http.StatusBadRequest, requestID, correlationID, ResourceResult{
			Outcome: OutcomeError, ReasonCode: ReasonUnknownScenario,
			Explanation: "scenario must be success, denied, unavailable, error, or slow.", SafeData: emptySafeData(),
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.config.RequestTimeout)
	defer cancel()
	result, err := s.adapter.Request(ctx, ResourceRequest{
		RequestID: requestID, CorrelationID: correlationID,
		Resource: resource, Action: action, Scenario: scenario,
	})
	if ctxErr := ctx.Err(); ctxErr != nil {
		if errors.Is(ctxErr, context.DeadlineExceeded) {
			s.writeDemoResult(w, http.StatusGatewayTimeout, requestID, correlationID, ResourceResult{
				Outcome: OutcomeUnavailable, ReasonCode: ReasonRequestTimeout,
				Explanation: "The sample resource request exceeded its configured deadline.", SafeData: emptySafeData(),
			})
			return
		}
		s.writeDemoResult(w, http.StatusServiceUnavailable, requestID, correlationID, ResourceResult{
			Outcome: OutcomeUnavailable, ReasonCode: ReasonCancelled,
			Explanation: "The sample resource request stopped because its context was cancelled.", SafeData: emptySafeData(),
		})
		return
	}
	if err != nil {
		s.writeAdapterError(w, requestID, correlationID, err)
		return
	}
	s.writeDemoResult(w, statusForOutcome(result.Outcome), requestID, correlationID, result)
}

func (s *Server) writeAdapterError(w http.ResponseWriter, requestID, correlationID string, err error) {
	switch {
	case errors.Is(err, ErrResourceNotFound):
		s.writeDemoResult(w, http.StatusNotFound, requestID, correlationID, ResourceResult{
			Outcome: OutcomeError, ReasonCode: ReasonResourceNotFound,
			Explanation: "The requested resource and action are not in the fixed sample catalogue.", SafeData: emptySafeData(),
		})
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		s.writeDemoResult(w, http.StatusServiceUnavailable, requestID, correlationID, ResourceResult{
			Outcome: OutcomeUnavailable, ReasonCode: ReasonCancelled,
			Explanation: "The slow sample request stopped because its context was cancelled or expired.", SafeData: emptySafeData(),
		})
	default:
		s.writeDemoResult(w, http.StatusInternalServerError, requestID, correlationID, ResourceResult{
			Outcome: OutcomeError, ReasonCode: ReasonAdapterFailure,
			Explanation: "The sample resource adapter could not complete the request.", SafeData: emptySafeData(),
		})
	}
}

func (s *Server) writeInvalidRequest(w http.ResponseWriter, requestID, correlationID, explanation string) {
	s.writeDemoResult(w, http.StatusBadRequest, requestID, correlationID, ResourceResult{
		Outcome: OutcomeError, ReasonCode: ReasonInvalidRequest,
		Explanation: explanation, SafeData: emptySafeData(),
	})
}

func (s *Server) writeDemoResult(w http.ResponseWriter, status int, requestID, correlationID string, result ResourceResult) {
	if result.SafeData == nil {
		result.SafeData = emptySafeData()
	}
	s.logger.LogAttrs(context.Background(), logLevelForOutcome(result.Outcome), "protected resource request completed",
		slog.String("requestId", requestID), slog.String("correlationId", correlationID),
		slog.String("outcome", string(result.Outcome)), slog.String("reasonCode", result.ReasonCode),
	)
	writeJSON(w, status, demoResponse{
		RequestID: requestID, CorrelationID: correlationID,
		Source: "sample", Mode: "sample", Outcome: result.Outcome,
		ReasonCode: result.ReasonCode, Explanation: result.Explanation,
		Timestamp: s.now(), SafeData: result.SafeData,
	})
}

func knownScenario(scenario string) bool {
	switch scenario {
	case "success", "denied", "unavailable", "error", "slow":
		return true
	default:
		return false
	}
}

func statusForOutcome(outcome Outcome) int {
	switch outcome {
	case OutcomeSuccess:
		return http.StatusOK
	case OutcomeDenied:
		return http.StatusForbidden
	case OutcomeUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

func logLevelForOutcome(outcome Outcome) slog.Level {
	switch outcome {
	case OutcomeSuccess:
		return slog.LevelInfo
	case OutcomeDenied:
		return slog.LevelWarn
	default:
		return slog.LevelError
	}
}

func cleanIdentifier(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 128 {
		return ""
	}
	for _, character := range value {
		if character < 33 || character > 126 {
			return ""
		}
	}
	return value
}

func newIdentifier() string {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return hex.EncodeToString([]byte(time.Now().UTC().Format(time.RFC3339Nano)))
	}
	return hex.EncodeToString(buffer)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
