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

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/tokenverify"
)

const maxDemoRequestBytes = 64 * 1024

type Server struct {
	config  Config
	logger  *slog.Logger
	adapter ResourceAdapter
	mux     *http.ServeMux
	// now and newID are test-only hooks for deterministic output; no configuration reaches them.
	now   func() time.Time
	newID func() string
}

type healthResponse struct {
	Status      string    `json:"status"`
	Mode        string    `json:"mode"`
	LiveMode    string    `json:"liveMode"`
	SeedVersion string    `json:"seedVersion"`
	Timestamp   time.Time `json:"timestamp"`
}

type resetResponse struct {
	Status      string    `json:"status"`
	Mode        string    `json:"mode"`
	SeedVersion string    `json:"seedVersion"`
	Timestamp   time.Time `json:"timestamp"`
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
		newID: newIdentifier,
	}
	server.mux.HandleFunc("/health", server.handleHealth)
	server.mux.HandleFunc("/reset", server.handleReset)
	if config.Verifier != nil {
		server.mux.Handle("/demo", server.accessLog(config.Verifier.Middleware(http.HandlerFunc(server.handleDemo))))
	} else {
		server.mux.HandleFunc("/demo", server.handleDemo)
	}
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
			"status": "error", "mode": s.config.ServingMode(), "liveMode": "unavailable",
		})
		return
	}
	writeJSON(w, http.StatusOK, healthResponse{
		Status: "ok", Mode: s.config.ServingMode(), LiveMode: "unavailable",
		SeedVersion: demoSeed.Version, Timestamp: s.now(),
	})
}

// handleReset restores the demo data. The data is the read-only embedded seed, so there is nothing to
// rebuild; the endpoint exists so one call resets every service. It has no access to token, replay or
// key state.
func (s *Server) handleReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"status": "error", "reason": "method_not_allowed"})
		return
	}
	s.logger.Info("protected resource reset", slog.String("seedVersion", demoSeed.Version))
	writeJSON(w, http.StatusOK, resetResponse{
		Status: "reset", Mode: s.config.ServingMode(), SeedVersion: demoSeed.Version, Timestamp: s.now(),
	})
}

type accessKey struct{}

type accessMark struct{ reached bool }

// accessLog logs requests the verifier refused before they reached handleDemo, which logs its own.
// It records the status only: never a header, token or proof.
func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mark := &accessMark{}
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r.WithContext(context.WithValue(r.Context(), accessKey{}, mark)))
		if mark.reached {
			return
		}
		s.logger.LogAttrs(r.Context(), slog.LevelWarn, "protected resource request refused",
			slog.String("requestId", cleanIdentifier(r.Header.Get("X-Request-ID"))),
			slog.String("correlationId", cleanIdentifier(r.Header.Get("X-Correlation-ID"))),
			slog.Int("status", recorder.status),
		)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (s *Server) handleDemo(w http.ResponseWriter, r *http.Request) {
	if mark, ok := r.Context().Value(accessKey{}).(*accessMark); ok {
		mark.reached = true
	}
	ctx := r.Context()
	requestID := cleanIdentifier(r.Header.Get("X-Request-ID"))
	if requestID == "" {
		requestID = s.newID()
	}
	headerCorrelationID := cleanIdentifier(r.Header.Get("X-Correlation-ID"))
	correlationID := headerCorrelationID
	if correlationID == "" {
		correlationID = requestID
	}

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		s.writeDemoResult(ctx, w, http.StatusMethodNotAllowed, requestID, correlationID, ResourceResult{
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
			s.writeDemoResult(ctx, w, http.StatusRequestEntityTooLarge, requestID, correlationID, ResourceResult{
				Outcome: OutcomeError, ReasonCode: ReasonRequestTooLarge,
				Explanation: "The request body exceeds the 64 KiB limit.", SafeData: emptySafeData(),
			})
			return
		}
		s.writeInvalidRequest(ctx, w, requestID, correlationID, "The request body must be one valid JSON object with documented fields only.")
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		s.writeInvalidRequest(ctx, w, requestID, correlationID, "The request body must contain one JSON object only.")
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
		s.writeInvalidRequest(ctx, w, requestID, correlationID, "resource and action are required.")
		return
	}
	scenario := strings.ToLower(strings.TrimSpace(input.Scenario))
	if s.config.Verifier != nil {
		s.writeScoped(ctx, w, requestID, correlationID, resource, action, scenario)
		return
	}
	if scenario == "" {
		scenario = "success"
	}
	if !knownScenario(scenario) {
		s.writeDemoResult(ctx, w, http.StatusBadRequest, requestID, correlationID, ResourceResult{
			Outcome: OutcomeError, ReasonCode: ReasonUnknownScenario,
			Explanation: "scenario must be success, denied, unavailable, error, or slow.", SafeData: emptySafeData(),
		})
		return
	}

	adapterCtx, cancel := context.WithTimeout(ctx, s.config.RequestTimeout)
	defer cancel()
	result, err := s.adapter.Request(adapterCtx, ResourceRequest{
		RequestID: requestID, CorrelationID: correlationID,
		Resource: resource, Action: action, Scenario: scenario,
	})
	if ctxErr := adapterCtx.Err(); ctxErr != nil {
		if errors.Is(ctxErr, context.DeadlineExceeded) {
			s.writeDemoResult(ctx, w, http.StatusGatewayTimeout, requestID, correlationID, ResourceResult{
				Outcome: OutcomeUnavailable, ReasonCode: ReasonRequestTimeout,
				Explanation: "The sample resource request exceeded its configured deadline.", SafeData: emptySafeData(),
			})
			return
		}
		s.writeDemoResult(ctx, w, http.StatusServiceUnavailable, requestID, correlationID, ResourceResult{
			Outcome: OutcomeUnavailable, ReasonCode: ReasonCancelled,
			Explanation: "The sample resource request stopped because its context was cancelled.", SafeData: emptySafeData(),
		})
		return
	}
	if err != nil {
		s.writeAdapterError(ctx, w, requestID, correlationID, err)
		return
	}
	s.writeDemoResult(ctx, w, statusForOutcome(result.Outcome), requestID, correlationID, result)
}

// writeScoped answers a request that passed the verifier, from the scope table in scopedResult.
// Sample scenarios do not apply in token mode.
func (s *Server) writeScoped(ctx context.Context, w http.ResponseWriter, requestID, correlationID, resource, action, scenario string) {
	if scenario != "" {
		s.writeDemoResult(ctx, w, http.StatusBadRequest, requestID, correlationID, ResourceResult{
			Outcome: OutcomeError, ReasonCode: ReasonScenarioNotAllowed,
			Explanation: "scenario is accepted in sample mode only.", SafeData: emptySafeData(),
		})
		return
	}
	if resource != "sample-report" || action != "read" {
		s.writeAdapterError(ctx, w, requestID, correlationID, ErrResourceNotFound)
		return
	}
	identity, ok := tokenverify.FromContext(ctx)
	if !ok {
		s.writeDemoResult(ctx, w, http.StatusInternalServerError, requestID, correlationID, ResourceResult{
			Outcome: OutcomeError, ReasonCode: ReasonIdentityMissing,
			Explanation: "The verified caller identity was not available.", SafeData: emptySafeData(),
		})
		return
	}
	result := scopedResult(identity.Scopes)
	s.writeDemoResult(ctx, w, statusForOutcome(result.Outcome), requestID, correlationID, result)
}

func (s *Server) writeAdapterError(ctx context.Context, w http.ResponseWriter, requestID, correlationID string, err error) {
	switch {
	case errors.Is(err, ErrResourceNotFound):
		s.writeDemoResult(ctx, w, http.StatusNotFound, requestID, correlationID, ResourceResult{
			Outcome: OutcomeError, ReasonCode: ReasonResourceNotFound,
			Explanation: "The requested resource and action are not in the fixed sample catalogue.", SafeData: emptySafeData(),
		})
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		s.writeDemoResult(ctx, w, http.StatusServiceUnavailable, requestID, correlationID, ResourceResult{
			Outcome: OutcomeUnavailable, ReasonCode: ReasonCancelled,
			Explanation: "The slow sample request stopped because its context was cancelled or expired.", SafeData: emptySafeData(),
		})
	default:
		s.writeDemoResult(ctx, w, http.StatusInternalServerError, requestID, correlationID, ResourceResult{
			Outcome: OutcomeError, ReasonCode: ReasonAdapterFailure,
			Explanation: "The sample resource adapter could not complete the request.", SafeData: emptySafeData(),
		})
	}
}

func (s *Server) writeInvalidRequest(ctx context.Context, w http.ResponseWriter, requestID, correlationID, explanation string) {
	s.writeDemoResult(ctx, w, http.StatusBadRequest, requestID, correlationID, ResourceResult{
		Outcome: OutcomeError, ReasonCode: ReasonInvalidRequest,
		Explanation: explanation, SafeData: emptySafeData(),
	})
}

func (s *Server) writeDemoResult(ctx context.Context, w http.ResponseWriter, status int, requestID, correlationID string, result ResourceResult) {
	if result.SafeData == nil {
		result.SafeData = emptySafeData()
	}
	attrs := append([]slog.Attr{
		slog.String("requestId", requestID), slog.String("correlationId", correlationID),
		slog.String("outcome", string(result.Outcome)), slog.String("reasonCode", result.ReasonCode),
	}, identityAttrs(ctx)...)
	s.logger.LogAttrs(context.Background(), logLevelForOutcome(result.Outcome), "protected resource request completed", attrs...)
	writeJSON(w, status, demoResponse{
		RequestID: requestID, CorrelationID: correlationID,
		Source: "sample", Mode: s.config.ServingMode(), Outcome: result.Outcome,
		ReasonCode: result.ReasonCode, Explanation: result.Explanation,
		Timestamp: s.now(), SafeData: result.SafeData,
	})
}

// identityAttrs names the verified caller. Only identifiers are logged, never the token or the proof.
func identityAttrs(ctx context.Context) []slog.Attr {
	identity, ok := tokenverify.FromContext(ctx)
	if !ok {
		return nil
	}
	return []slog.Attr{
		slog.String("client_id", identity.ClientID), slog.String("sub", identity.Subject), slog.String("jkt", identity.JKT),
	}
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
