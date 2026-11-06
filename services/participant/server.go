package participant

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

const maxDemoRequestBytes = 64 * 1024

type Server struct {
	config  Config
	logger  *slog.Logger
	adapter RequestAdapter
	router  *http.ServeMux
	now     func() time.Time
}

type healthResponse struct {
	Status         string `json:"status"`
	Service        string `json:"service"`
	Mode           string `json:"mode"`
	LiveMode       string `json:"liveMode"`
	RequestTimeout string `json:"requestTimeout"`
}

func NewServer(config Config, logger *slog.Logger) *Server {
	return NewServerWithAdapter(config, logger, NewRequestAdapter(config))
}

func NewServerWithAdapter(config Config, logger *slog.Logger, adapter RequestAdapter) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	server := &Server{
		config:  config,
		logger:  logger,
		adapter: adapter,
		router:  http.NewServeMux(),
		now:     func() time.Time { return time.Now().UTC() },
	}
	server.router.HandleFunc("/health", server.handleHealth)
	server.router.HandleFunc("/demo", server.handleDemo)
	return server
}

func (s *Server) Handler() http.Handler {
	return s.router
}

func (s *Server) HTTPServer() *http.Server {
	return &http.Server{
		Addr:              s.config.Address,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       s.config.ServerReadTimeout(),
		WriteTimeout:      s.config.ServerWriteTimeout(),
		IdleTimeout:       30 * time.Second,
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"status": "error", "reason": "method_not_allowed"})
		return
	}
	writeJSON(w, http.StatusOK, healthResponse{
		Status:         "ok",
		Service:        "facis-participant",
		Mode:           "sample",
		LiveMode:       "unavailable",
		RequestTimeout: s.config.RequestTimeout.String(),
	})
}

func (s *Server) handleDemo(w http.ResponseWriter, r *http.Request) {
	headerRequestID := cleanIdentifier(r.Header.Get("X-Request-ID"))
	headerCorrelationID := cleanIdentifier(r.Header.Get("X-Correlation-ID"))
	requestID := headerRequestID
	if requestID == "" {
		requestID = newIdentifier()
	}
	correlationID := headerCorrelationID
	if correlationID == "" {
		correlationID = requestID
	}

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		s.writeDemoResult(w, http.StatusMethodNotAllowed, requestID, correlationID, AdapterResult{
			Outcome: OutcomeError, ReasonCode: ReasonMethodNotAllowed,
			Explanation: "The demo endpoint accepts POST requests only.",
			SafeData:    emptySafeData(),
		})
		return
	}

	var input DemoRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxDemoRequestBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		s.writeDemoResult(w, http.StatusBadRequest, requestID, correlationID, invalidRequestResult("The request body must be one valid JSON object."))
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		s.writeDemoResult(w, http.StatusBadRequest, requestID, correlationID, invalidRequestResult("The request body must contain one JSON object only."))
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
	if strings.TrimSpace(input.Resource) == "" || strings.TrimSpace(input.Action) == "" {
		s.writeDemoResult(w, http.StatusBadRequest, requestID, correlationID, invalidRequestResult("resource and action are required."))
		return
	}

	adapterRequest := AdapterRequest{
		RequestID: requestID, CorrelationID: correlationID,
		Resource: strings.TrimSpace(input.Resource), Action: strings.TrimSpace(input.Action),
		Scenario: strings.TrimSpace(input.Scenario),
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.config.RequestTimeout)
	defer cancel()

	result, err := s.adapter.Request(ctx, adapterRequest)
	if ctxErr := ctx.Err(); ctxErr != nil {
		if errors.Is(ctxErr, context.DeadlineExceeded) {
			s.writeDemoResult(w, http.StatusGatewayTimeout, requestID, correlationID, AdapterResult{
				Outcome: OutcomeUnavailable, ReasonCode: ReasonRequestTimeout,
				Explanation: "The sample dependency did not respond before the request timeout.",
				SafeData:    emptySafeData(),
			})
			return
		}
		s.writeDemoResult(w, http.StatusServiceUnavailable, requestID, correlationID, AdapterResult{
			Outcome: OutcomeUnavailable, ReasonCode: ReasonConnectionFailure,
			Explanation: "The sample dependency request was cancelled.", SafeData: emptySafeData(),
		})
		return
	}
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			s.writeDemoResult(w, http.StatusGatewayTimeout, requestID, correlationID, AdapterResult{
				Outcome: OutcomeUnavailable, ReasonCode: ReasonRequestTimeout,
				Explanation: "The sample dependency did not respond before the request timeout.",
				SafeData:    emptySafeData(),
			})
			return
		}
		var networkError net.Error
		if errors.As(err, &networkError) {
			s.writeDemoResult(w, http.StatusServiceUnavailable, requestID, correlationID, AdapterResult{
				Outcome: OutcomeUnavailable, ReasonCode: ReasonConnectionFailure,
				Explanation: "The sample dependency connection was unavailable.",
				SafeData:    emptySafeData(),
			})
			return
		}
		s.writeDemoResult(w, http.StatusBadGateway, requestID, correlationID, AdapterResult{
			Outcome: OutcomeError, ReasonCode: ReasonAdapterError,
			Explanation: "The sample adapter could not complete the request.",
			SafeData:    emptySafeData(),
		})
		return
	}
	if result == nil {
		s.writeDemoResult(w, http.StatusServiceUnavailable, requestID, correlationID, AdapterResult{
			Outcome: OutcomeUnavailable, ReasonCode: ReasonAdapterNoResponse,
			Explanation: "The sample adapter returned no response.",
			SafeData:    emptySafeData(),
		})
		return
	}

	s.writeDemoResult(w, statusForOutcome(result.Outcome), requestID, correlationID, *result)
}

func (s *Server) writeDemoResult(w http.ResponseWriter, status int, requestID, correlationID string, result AdapterResult) {
	if result.SafeData == nil {
		result.SafeData = emptySafeData()
	}
	response := DemoResponse{
		RequestID: requestID, CorrelationID: correlationID,
		Source: "sample", Mode: "sample", Outcome: result.Outcome,
		ReasonCode: result.ReasonCode, Explanation: result.Explanation,
		Timestamp: s.now(), SafeData: result.SafeData,
	}
	s.logger.LogAttrs(context.Background(), logLevelForOutcome(result.Outcome), "participant demo request completed",
		slog.String("requestId", requestID), slog.String("correlationId", correlationID),
		slog.String("source", "sample"), slog.String("outcome", string(result.Outcome)),
		slog.String("reasonCode", result.ReasonCode),
	)
	writeJSON(w, status, response)
}

func invalidRequestResult(explanation string) AdapterResult {
	return AdapterResult{Outcome: OutcomeError, ReasonCode: ReasonInvalidRequest, Explanation: explanation, SafeData: emptySafeData()}
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
		return http.StatusBadGateway
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

func emptySafeData() map[string]any {
	return map[string]any{}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
