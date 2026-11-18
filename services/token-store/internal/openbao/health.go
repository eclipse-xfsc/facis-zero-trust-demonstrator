// Package openbao reaches the zone's key-value store. This build asks it one thing: whether it is
// there, initialised and unsealed, which the store's readiness requires before any key reference
// could resolve. It never logs; the caller decides what a failure means.
package openbao

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// State is what the server reports about itself.
type State struct {
	Initialized bool `json:"initialized"`
	Sealed      bool `json:"sealed"`
	Standby     bool `json:"standby"`
}

// healthPath asks the server to answer 200 whatever its state, so the body says what it is. Any
// other status is therefore not the server speaking of itself but something in between, a proxy
// or the mesh, and says nothing about the server's state.
const healthPath = "/v1/sys/health?uninitcode=200&sealedcode=200&standbycode=200"

// maxBody bounds what Health reads of an answer; the health document is a few hundred bytes.
const maxBody = 64 << 10

// NewClient is the client Health is meant to be called with: no proxy, since the key-value store
// is reached inside the cluster and a proxy from the pod's environment must not sit in between;
// no redirects, since only the configured address is ever consulted and a 3xx from anything in
// between is an answer, never a new destination for the forwarded identifiers; a small idle pool
// for the probes' pace. The request's context, not the client, carries the deadline.
func NewClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.MaxIdleConnsPerHost = 2
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Health reads the server's health. base is the server's URL, scheme and host only; propagate
// carries the request headers to forward unchanged (x-request-id, traceparent, tracestate). The
// deadline is the context's. Only a 200 with a health document is the server's own word and
// becomes the State; a transport failure, any other status or an unreadable body is an error.
func Health(ctx context.Context, client *http.Client, base string, propagate http.Header) (State, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+healthPath, nil)
	if err != nil {
		return State{}, err
	}
	req.Header.Set("Accept", "application/json")
	for name, values := range propagate {
		for _, v := range values {
			req.Header.Add(name, v)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return State{}, err
	}
	defer func() {
		// Drained before it is closed, whatever the status, so the connection goes back to the
		// pool instead of being torn down on every probe during an outage.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return State{}, fmt.Errorf("openbao: health answered %d", resp.StatusCode)
	}
	var s State
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&s); err != nil {
		return State{}, fmt.Errorf("openbao: reading the health answer: %w", err)
	}
	return s, nil
}
