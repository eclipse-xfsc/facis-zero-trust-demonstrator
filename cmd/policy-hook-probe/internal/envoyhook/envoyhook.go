// Package envoyhook serves the guard's outcome to Envoy: through the ext_authz filter
// (envoy.service.auth.v3.Authorization, one Check per request) and through the ext_proc filter
// (envoy.service.ext_proc.v3.ExternalProcessor, the request-headers phase decided, every other
// phase passed through). Both translate the same hook.Outcome, so a decision does not depend on
// the filter that carries it. It is the only package that may import the Envoy API.
package envoyhook

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/cmd/policy-hook-probe/internal/hook"
)

// Register adds both services, deciding with g, to a gRPC server.
func Register(r grpc.ServiceRegistrar, g *hook.Guard) {
	authv3.RegisterAuthorizationServer(r, &AuthzServer{guard: g})
	extprocv3.RegisterExternalProcessorServer(r, &ProcServer{guard: g})
}

// AuthzServer implements the Authorization service over a guard.
type AuthzServer struct {
	authv3.UnimplementedAuthorizationServer
	guard *hook.Guard
}

// NewAuthzServer returns the ext_authz service deciding with g.
func NewAuthzServer(g *hook.Guard) *AuthzServer { return &AuthzServer{guard: g} }

// Check implements the Authorization service.
func (s *AuthzServer) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	return AuthzResponse(s.guard.Evaluate(ctx, AuthzRequest(req))), nil
}

// AuthzRequest is the guard's view of a CheckRequest.
func AuthzRequest(req *authv3.CheckRequest) hook.Request {
	attrs := req.GetAttributes()
	h := attrs.GetRequest().GetHttp()
	out := hook.Request{Method: h.GetMethod(), Scheme: h.GetScheme(), Host: h.GetHost(), Path: h.GetPath(),
		Headers: http.Header{}, PeerID: attrs.GetSource().GetPrincipal()}
	for k, v := range h.GetHeaders() {
		if !strings.HasPrefix(k, ":") {
			out.Headers.Add(k, v)
		}
	}
	return out
}

// AuthzResponse is the CheckResponse for an outcome: OK with header mutations for a forwarded
// request, a denied response with status, headers and body otherwise.
func AuthzResponse(out hook.Outcome) *authv3.CheckResponse {
	if out.Allowed {
		return &authv3.CheckResponse{
			Status: &status.Status{Code: int32(codes.OK)},
			HttpResponse: &authv3.CheckResponse_OkResponse{OkResponse: &authv3.OkHttpResponse{
				Headers: headerOptions(out.SetHeaders, false), HeadersToRemove: out.RemoveHeaders}},
		}
	}
	return &authv3.CheckResponse{
		Status: &status.Status{Code: int32(grpcCode(out.Status))},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{DeniedResponse: &authv3.DeniedHttpResponse{
			Status: &typev3.HttpStatus{Code: typev3.StatusCode(out.Status)}, Headers: headerOptions(out.SetHeaders, false), Body: string(out.Body)}},
	}
}

// grpcCode is the status the filter's gRPC answer carries; Envoy denies on anything but OK and
// takes the HTTP status from the denied response.
func grpcCode(httpStatus int) codes.Code {
	switch httpStatus {
	case http.StatusUnauthorized:
		return codes.Unauthenticated
	case http.StatusServiceUnavailable:
		return codes.Unavailable
	default:
		return codes.PermissionDenied
	}
}

// ProcServer implements the ExternalProcessor service over a guard.
type ProcServer struct {
	extprocv3.UnimplementedExternalProcessorServer
	guard *hook.Guard
}

// NewProcServer returns the ext_proc service deciding with g.
func NewProcServer(g *hook.Guard) *ProcServer { return &ProcServer{guard: g} }

// Process implements the ExternalProcessor service: one stream per request, one message per
// phase Envoy is configured to send.
func (s *ProcServer) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		var resp *extprocv3.ProcessingResponse
		switch m := req.GetRequest().(type) {
		case *extprocv3.ProcessingRequest_RequestHeaders:
			resp = ProcResponse(s.guard.Evaluate(stream.Context(), ProcRequest(m.RequestHeaders)))
		case *extprocv3.ProcessingRequest_ResponseHeaders:
			resp = &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseHeaders{
				ResponseHeaders: &extprocv3.HeadersResponse{Response: &extprocv3.CommonResponse{}}}}
		case *extprocv3.ProcessingRequest_RequestBody:
			resp = &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestBody{
				RequestBody: &extprocv3.BodyResponse{Response: &extprocv3.CommonResponse{}}}}
		case *extprocv3.ProcessingRequest_ResponseBody:
			resp = &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseBody{
				ResponseBody: &extprocv3.BodyResponse{Response: &extprocv3.CommonResponse{}}}}
		case *extprocv3.ProcessingRequest_RequestTrailers:
			resp = &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestTrailers{
				RequestTrailers: &extprocv3.TrailersResponse{}}}
		default:
			resp = &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseTrailers{
				ResponseTrailers: &extprocv3.TrailersResponse{}}}
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}
}

// ProcRequest is the guard's view of the request headers Envoy sent; the pseudo-headers carry
// the method, scheme, authority and path.
func ProcRequest(h *extprocv3.HttpHeaders) hook.Request {
	out := hook.Request{Headers: http.Header{}}
	for _, hv := range h.GetHeaders().GetHeaders() {
		value := hv.GetValue()
		if value == "" && len(hv.GetRawValue()) > 0 {
			value = string(hv.GetRawValue())
		}
		switch hv.GetKey() {
		case ":method":
			out.Method = value
		case ":scheme":
			out.Scheme = value
		case ":authority":
			out.Host = value
		case ":path":
			out.Path = value
		default:
			if !strings.HasPrefix(hv.GetKey(), ":") {
				out.Headers.Add(hv.GetKey(), value)
			}
		}
	}
	return out
}

// ProcResponse is the headers-phase answer for an outcome: a header mutation and CONTINUE for a
// forwarded request, an immediate response with status, headers and body otherwise.
func ProcResponse(out hook.Outcome) *extprocv3.ProcessingResponse {
	if out.Allowed {
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestHeaders{
			RequestHeaders: &extprocv3.HeadersResponse{Response: &extprocv3.CommonResponse{
				Status:         extprocv3.CommonResponse_CONTINUE,
				HeaderMutation: &extprocv3.HeaderMutation{SetHeaders: headerOptions(out.SetHeaders, true), RemoveHeaders: out.RemoveHeaders},
			}},
		}}
	}
	return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ImmediateResponse{
		ImmediateResponse: &extprocv3.ImmediateResponse{
			Status:  &typev3.HttpStatus{Code: typev3.StatusCode(out.Status)},
			Headers: &extprocv3.HeaderMutation{SetHeaders: headerOptions(out.SetHeaders, true)},
			Body:    out.Body,
			Details: out.ReasonCode,
		},
	}}
}

// headerOptions builds the header mutations. ext_authz reads a header's value member; ext_proc
// reads raw_value, so each filter is given the one it honours.
func headerOptions(h []hook.Header, raw bool) []*corev3.HeaderValueOption {
	opts := make([]*corev3.HeaderValueOption, 0, len(h))
	for _, x := range h {
		hv := &corev3.HeaderValue{Key: x.Name}
		if raw {
			hv.RawValue = []byte(x.Value)
		} else {
			hv.Value = x.Value
		}
		opts = append(opts, &corev3.HeaderValueOption{Header: hv, AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD})
	}
	return opts
}
