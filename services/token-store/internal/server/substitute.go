package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/meshcaller"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/substitute"
)

const (
	maxSubstituteBody = 8 << 10
	// substituteTimeout is the deadline of one substitution, an on-demand acquisition included.
	substituteTimeout = 10 * time.Second
)

var substituteMethods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}

type substituteRequest struct {
	PeerZone      string  `json:"peer_zone"`
	Audience      string  `json:"audience"`
	Tenant        *string `json:"tenant"`
	Method        string  `json:"method"`
	TargetURI     string  `json:"target_uri"`
	CorrelationID string  `json:"correlation_id"`
	UpstreamNonce *string `json:"upstream_nonce"`
}

// handleSubstitute is POST /internal/substitute. In order: the caller is authenticated and must be
// listed by some route before the body is read; the body is parsed strictly; the request is
// authorized against the routes from configuration alone; only then is anything read from the
// database or the key-value store, or signed. A body that does not parse matches no route
// (TOK-ROUTE-DENIED): the contract has no other refusal for it.
func (s *Server) handleSubstitute(w http.ResponseWriter, r *http.Request) {
	c, err := s.callers.Authenticate(r)
	if err != nil || !s.routes.Admits(c) {
		s.refuse(w, r, http.StatusForbidden, "TOK-CALLER-DENIED")
		return
	}
	var req substituteRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSubstituteBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.Decode(&struct{}{}) != io.EOF ||
		req.PeerZone == "" || req.Audience == "" || !slices.Contains(substituteMethods, req.Method) || req.TargetURI == "" ||
		len(req.CorrelationID) < 1 || len(req.CorrelationID) > 128 ||
		(req.UpstreamNonce != nil && (len(*req.UpstreamNonce) < 1 || len(*req.UpstreamNonce) > 256 || !visibleASCII(*req.UpstreamNonce))) {
		s.refuse(w, r, http.StatusForbidden, "TOK-ROUTE-DENIED")
		return
	}
	creq := meshcaller.Request{PeerZone: req.PeerZone, Audience: req.Audience, Method: req.Method, TargetURI: req.TargetURI}
	if req.Tenant != nil {
		creq.Tenant = *req.Tenant
	}
	if _, err := s.routes.Authorize(c, creq); err != nil {
		code := "TOK-ROUTE-DENIED"
		if errors.Is(err, meshcaller.ErrCallerDenied) {
			code = "TOK-CALLER-DENIED"
		}
		s.refuse(w, r, http.StatusForbidden, code)
		return
	}
	if s.substitute == nil { // routes without an acquisition config cannot exist; fail closed all the same
		s.refuse(w, r, http.StatusServiceUnavailable, "TOK-STORE-UNAVAILABLE")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.subTimeout)
	defer cancel()
	sreq := substitute.Request{PeerZone: creq.PeerZone, Audience: creq.Audience, Tenant: creq.Tenant,
		Method: creq.Method, TargetURI: creq.TargetURI}
	if req.UpstreamNonce != nil {
		sreq.Nonce = *req.UpstreamNonce
	}
	res, err := s.substitute.Substitute(ctx, sreq)
	switch {
	case errors.Is(err, substitute.ErrNoUpstream):
		s.refuse(w, r, http.StatusConflict, "TOK-NO-UPSTREAM")
	case errors.Is(err, meshcaller.ErrRouteDenied):
		s.refuse(w, r, http.StatusForbidden, "TOK-ROUTE-DENIED")
	case err != nil:
		s.refuse(w, r, http.StatusServiceUnavailable, "TOK-STORE-UNAVAILABLE")
	default:
		writeJSON(w, http.StatusOK, map[string]string{"authorization": res.Authorization, "dpop": res.DPoP,
			"expires_at": res.ExpiresAt.UTC().Format(time.RFC3339)})
	}
}
