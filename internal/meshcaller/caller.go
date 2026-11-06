// Package meshcaller authenticates the store's internal callers and authorizes their routes.
package meshcaller

import (
	"errors"
	"net/http"
)

// Caller is an authenticated mesh identity.
type Caller struct {
	SPIFFEID string
}

// Authenticator establishes who called. The store trusts only what an Authenticator returns.
type Authenticator interface {
	Authenticate(r *http.Request) (Caller, error)
}

// Route is one configured substitution route.
type Route struct {
	Callers      []string // SPIFFE IDs allowed to use it
	PeerZone     string
	Audience     string
	Tenant       string
	Methods      []string
	TargetPrefix string
}

// Request is what a substitution asks for.
type Request struct {
	PeerZone  string
	Audience  string
	Tenant    string
	Method    string
	TargetURI string
}

// Router authorizes a caller's request against the configured routes.
type Router interface {
	Authorize(c Caller, req Request) (Route, error)
}

var (
	ErrCallerDenied = errors.New("TOK-CALLER-DENIED")
	ErrRouteDenied  = errors.New("TOK-ROUTE-DENIED")
)
