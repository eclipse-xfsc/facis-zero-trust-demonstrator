package protectedresource

import (
	"log/slog"
	"net/http"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// GRPCMethod is the Resource's one gRPC method: the standard health service's unary Check, whose
// client ships with every gRPC library. It stands for a protected gRPC API as /demo does for REST.
const GRPCMethod = "/grpc.health.v1.Health/Check"

// GRPCServer serves GRPCMethod on Config.GRPCAddress over cleartext HTTP/2, behind the same token
// and proof verification as /demo: the proof names the published base URL and the method path. It
// is nil unless the address and a Verifier are configured. A refused call is answered as HTTP 401
// or 403, which a gRPC client reads as UNAUTHENTICATED or PERMISSION_DENIED.
func (s *Server) GRPCServer() *http.Server {
	if s.config.GRPCAddress == "" || s.config.Verifier == nil {
		return nil
	}
	server := grpc.NewServer()
	healthpb.RegisterHealthServer(server, health.NewServer())
	mux := http.NewServeMux()
	mux.Handle(GRPCMethod, s.accessLog(s.config.Verifier.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mark, ok := r.Context().Value(accessKey{}).(*accessMark); ok {
			mark.reached = true
		}
		id := cleanIdentifier(r.Header.Get("X-Request-ID"))
		attrs := append([]slog.Attr{slog.String("requestId", id), slog.String("correlationId", id),
			slog.String("outcome", string(OutcomeSuccess)), slog.String("grpcMethod", GRPCMethod)}, identityAttrs(r.Context())...)
		s.logger.LogAttrs(r.Context(), slog.LevelInfo, "protected resource request completed", attrs...)
		server.ServeHTTP(w, r)
	}))))
	out := &http.Server{Addr: s.config.GRPCAddress, Handler: mux, ReadHeaderTimeout: s.config.RequestTimeout, IdleTimeout: 30 * time.Second, Protocols: new(http.Protocols)}
	out.Protocols.SetUnencryptedHTTP2(true)
	return out
}
