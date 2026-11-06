package authelia

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"authelia.com/provider/oauth2"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider"
)

// outcome collects facts about a request that the library's error value does
// not carry. The library reports a replayed proof as an invalid proof; the
// store adapter, which made that determination, notes it here.
type outcome struct {
	replayed bool
}

type outcomeKey struct{}

func withOutcome(ctx context.Context) (context.Context, *outcome) {
	o := &outcome{}

	return context.WithValue(ctx, outcomeKey{}, o), o
}

func noteReplay(ctx context.Context) {
	if o, ok := ctx.Value(outcomeKey{}).(*outcome); ok {
		o.replayed = true
	}
}

// classify maps a library error to a reason code by its OAuth 2.0 error
// name, never by its message text.
func classify(err error, o *outcome) oauth2provider.Code {
	field := oauth2.ErrorToRFC6749Error(err).ErrorField

	// A refused verification outcome carries its IF-03 code as the error's cause.
	var cred *credError
	if field == "invalid_grant" && errors.As(err, &cred) {
		return cred.code
	}

	switch field {
	case "use_dpop_nonce":
		return oauth2provider.CodeDPoPUseNonce
	case "invalid_dpop_proof":
		if o != nil && o.replayed {
			return oauth2provider.CodeDPoPReplayed
		}

		return oauth2provider.CodeDPoPInvalidProof
	case "invalid_client":
		return oauth2provider.CodeInvalidClient
	case "invalid_token", "request_unauthorized":
		return oauth2provider.CodeInvalidToken
	case "insufficient_scope":
		return oauth2provider.CodeInsufficientScope
	case "invalid_client_metadata", "invalid_redirect_uri", "invalid_software_statement", "unapproved_software_statement":
		return oauth2provider.CodeRegistrationRejected
	case "server_error", "misconfiguration", "temporarily_unavailable":
		return oauth2provider.CodeServerError
	default:
		return oauth2provider.CodeInvalidRequest
	}
}

// writeWithReason lets the library render its specification-defined error
// response, then adds the reason code as one more member of the JSON body.
func writeWithReason(w http.ResponseWriter, code oauth2provider.Code, render func(http.ResponseWriter)) {
	buffer := &bufferedResponse{header: http.Header{}, status: http.StatusOK}

	render(buffer)

	body := buffer.body.Bytes()

	var members map[string]any
	if json.Unmarshal(body, &members) == nil && members != nil {
		members[oauth2provider.ReasonField] = code

		if encoded, err := json.Marshal(members); err == nil {
			body = encoded
		}
	}

	for name, values := range buffer.header {
		if name == "Content-Length" {
			continue
		}

		w.Header()[name] = values
	}

	w.WriteHeader(buffer.status)
	_, _ = w.Write(body)
}

type bufferedResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (b *bufferedResponse) Header() http.Header         { return b.header }
func (b *bufferedResponse) WriteHeader(status int)      { b.status = status }
func (b *bufferedResponse) Write(p []byte) (int, error) { return b.body.Write(p) }
