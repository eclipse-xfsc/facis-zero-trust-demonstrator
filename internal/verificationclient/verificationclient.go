// Package verificationclient is the presentation hook: an OutcomeSource that, for one connector
// challenge, asks the verification service for an OID4VP request, has a Holder present a credential
// for it, posts the presentation and returns the signed IF-03 outcome the service answers with. It
// runs without a person, once per acquisition and once per renewal. Standard library only.
package verificationclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/connectorclient"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/oid4vp"
)

// The verification contract's paths, below the service's base URL.
const (
	RequestsPath  = "/v1/requests"
	ResponsesPath = "/v1/responses/"
)

// Timeouts for one Outcome call, request to outcome. The hook is one step of an acquisition, and
// the shortest budget an acquisition runs under is the 10 s of an on-demand substitution, so the
// hook never takes longer than that; a value near the maximum leaves that path no time for the
// grant.
const (
	DefaultTimeout = 5 * time.Second
	MaxTimeout     = 10 * time.Second
)

const maxBody = 64 << 10

// Fixed-text errors: nothing the service or the holder said is repeated in them. All of them mean
// "no outcome": the caller starts again with a fresh challenge. When the call's context ended, the
// error also wraps the context's error, so a cancellation is told from a failure.
var (
	// ErrConfig: the client has no base URL or no holder, or the challenge is incomplete.
	ErrConfig = errors.New("verificationclient: client not configured")
	// ErrRequest: the service created no usable request for the challenge.
	ErrRequest = errors.New("verificationclient: no verification request")
	// ErrHolder: the holder presented nothing.
	ErrHolder = errors.New("verificationclient: holder presented nothing")
	// ErrResponse: the service answered the presentation with no outcome.
	ErrResponse = errors.New("verificationclient: no outcome")
)

// Stage names the step an Outcome error came from, as a fixed word for a log record: "config",
// "request", "holder" or "response"; empty for any other error.
func Stage(err error) string {
	switch {
	case errors.Is(err, ErrConfig):
		return "config"
	case errors.Is(err, ErrRequest):
		return "request"
	case errors.Is(err, ErrHolder):
		return "holder"
	case errors.Is(err, ErrResponse):
		return "response"
	}
	return ""
}

// Holder is the wallet side of the hook: it answers one OID4VP request with one presentation,
// without a person. The presentation is an SD-JWT VC (dc+sd-jwt) whose key-binding JWT is signed
// with the credential's holder key (cnf) and carries req.Nonce as nonce and req.ClientID as aud.
// The holder only builds the presentation; the client posts it, to req.ResponseURI, which is
// always the client's own address for the request and never one the service named. An error means
// nothing was presented, and its text is never passed on.
type Holder interface {
	Present(ctx context.Context, req oid4vp.Request) (vpToken string, err error)
}

// Client is an OutcomeSource backed by a verification service and a Holder. Safe for concurrent
// use when its Holder is.
type Client struct {
	BaseURL string        // the verification service's base URL (see connectorclient.BaseURL)
	Holder  Holder        // presents the credential
	HTTP    *http.Client  // nil: http.Client's defaults; redirects are never followed
	Timeout time.Duration // the whole call; zero means DefaultTimeout, at most MaxTimeout
}

var _ connectorclient.OutcomeSource = (*Client)(nil)

// The shapes the verification contract gives a request id and a compact JWS.
var (
	requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
	compactPattern   = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)
)

// Outcome returns a fresh signed IF-03 outcome for ch. The outcome is returned as the service
// signed it and is not judged here: an outcome that says failed or revoked is still an outcome, and
// refusing it is the consumer's (if03.Verify answers CRED-OUTCOME-NOT-VERIFIED). All the hook asks of
// it is the shape of a compact JWS. The presentation is posted to this client's own base URL, never
// to an address the answer names.
func (c *Client) Outcome(ctx context.Context, ch connectorclient.Challenge) (string, error) {
	base, err := connectorclient.BaseURL(c.BaseURL)
	if err != nil || c.Holder == nil || c.Timeout < 0 || c.Timeout > MaxTimeout ||
		ch.Value == "" || ch.ClientID == "" || ch.Audience == "" || ch.ExpiresAt.IsZero() {
		return "", ErrConfig
	}
	timeout := c.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := c.request(ctx, base, ch)
	if err != nil {
		return "", ended(ctx, err)
	}
	vp, err := c.Holder.Present(ctx, req)
	if err != nil || vp == "" || len(vp) > oid4vp.MaxVPToken {
		return "", ended(ctx, ErrHolder)
	}
	jws, err := c.respond(ctx, req.ResponseURI, vp)
	if err != nil {
		return "", ended(ctx, err)
	}
	return jws, nil
}

// ended adds the context's error to err when the call's context is over.
func ended(ctx context.Context, err error) error {
	if cause := ctx.Err(); cause != nil {
		return fmt.Errorf("%w: %w", err, cause)
	}
	return err
}

// request creates the verification request for ch and checks that it is bound to it. The request
// it returns carries this client's own address for the response, base + /v1/responses/{id}: the
// response_uri of the answer is the service's view of its address and is not used.
func (c *Client) request(ctx context.Context, base string, ch connectorclient.Challenge) (oid4vp.Request, error) {
	body, err := json.Marshal(map[string]string{
		"challenge": ch.Value, "client_id": ch.ClientID, "audience": ch.Audience,
		"expires_at": ch.ExpiresAt.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return oid4vp.Request{}, ErrRequest
	}
	status, answer, ok := c.post(ctx, base+RequestsPath, "application/json", body)
	if !ok || status != http.StatusCreated {
		return oid4vp.Request{}, ErrRequest
	}
	var out struct {
		RequestID    string          `json:"request_id"`
		Nonce        string          `json:"nonce"`
		ClientID     string          `json:"client_id"`
		ResponseMode string          `json:"response_mode"`
		DCQL         json.RawMessage `json:"dcql_query"`
	}
	if json.Unmarshal(answer, &out) != nil || !requestIDPattern.MatchString(out.RequestID) ||
		out.Nonce != ch.Value || out.ClientID != ch.Audience || out.ResponseMode != oid4vp.ResponseModeDirectPost ||
		!isObject(out.DCQL) {
		return oid4vp.Request{}, ErrRequest
	}
	return oid4vp.Request{ClientID: out.ClientID, Nonce: out.Nonce, ResponseURI: base + ResponsesPath + out.RequestID, DCQL: out.DCQL}, nil
}

// respond posts the presentation as an OID4VP direct_post form and reads the outcome.
func (c *Client) respond(ctx context.Context, target, vpToken string) (string, error) {
	form := url.Values{"vp_token": {vpToken}}
	status, answer, ok := c.post(ctx, target, "application/x-www-form-urlencoded", []byte(form.Encode()))
	if !ok || status != http.StatusOK {
		return "", ErrResponse
	}
	var out struct {
		Outcome string `json:"outcome"`
	}
	if json.Unmarshal(answer, &out) != nil || !compactPattern.MatchString(out.Outcome) {
		return "", ErrResponse
	}
	return out.Outcome, nil
}

// post sends one bounded request and reads one bounded answer. It reports no cause: the transport's
// text is not ours to vouch for, and the callers answer with their own fixed errors.
func (c *Client) post(ctx context.Context, target, contentType string, body []byte) (status int, answer []byte, ok bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return 0, nil, false
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")
	h := http.Client{}
	if c.HTTP != nil {
		h = *c.HTTP
	}
	h.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := h.Do(req)
	if err != nil {
		return 0, nil, false
	}
	defer func() { _ = resp.Body.Close() }()
	answer, err = io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil || len(answer) > maxBody {
		return 0, nil, false
	}
	return resp.StatusCode, answer, true
}

func isObject(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 1 && trimmed[0] == '{' && json.Valid(trimmed)
}
