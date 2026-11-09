// Package connectorclient is the client side of the Connector's verified-presentation grant (IF-02
// v1.1, design D5 and D10): the challenge request, the grant request with a DPoP proof and one nonce
// retry, and the checks on the issued token. The token store's acquisition and the Participant use it.
// It holds no state and keeps nothing it sends or receives.
package connectorclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/dpopproof"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
)

// VPGrantType is the Connector's verified-presentation grant (IF-02 v1.1).
const VPGrantType = "urn:facis:params:oauth:grant-type:verified-presentation"

const maxBody = 64 << 10

// Challenge is what the Connector issued for one grant.
type Challenge struct {
	Value     string
	ClientID  string
	Audience  string
	ExpiresAt time.Time
}

// OutcomeSource yields a fresh signed IF-03 outcome for a challenge: the verifier in a deployment, a
// fixture signer in tests and the demo. Each call returns a new outcome_id.
type OutcomeSource interface {
	Outcome(ctx context.Context, ch Challenge) (compactJWS string, err error)
}

// Kind is what step failed.
type Kind int

const (
	KindChallenge    Kind = iota + 1 // no usable challenge
	KindProof                        // the proof could not be signed; nothing was sent
	KindLost                         // no readable answer to the grant: terminal for the outcome
	KindRefused                      // the Connector refused the grant
	KindTokenInvalid                 // the issued token failed a response check
)

// Error is a failed call. It carries fixed text and classified fields only, never anything the
// Connector sent beyond a known reason code.
type Error struct {
	Kind Kind
	// Unreachable: the Connector was not reached or answered 5xx (KindChallenge; KindLost always is).
	Unreachable bool
	// Status is the HTTP status of a refusal, 0 when there was none.
	Status int
	// Reason is the Connector's reason for a KindRefused, set only when it is an IF-03 CRED-OUTCOME-*
	// code or dpop_use_nonce (a nonce demanded again after the one retry).
	Reason string
	// Check names the failed response check of a KindTokenInvalid: token_type, format, cnf.jkt, aud or exp.
	Check string
	text  string
}

func (e *Error) Error() string { return "connectorclient: " + e.text }

// ReasonUseNonce is the Connector's refusal asking for a (new) DPoP nonce.
const ReasonUseNonce = "dpop_use_nonce"

var credCodes = []string{if03.CodeSignature, if03.CodeNotVerified, if03.CodeMismatch, if03.CodeExpired, if03.CodeConsumed}

// Client calls one Connector as one client. Safe for concurrent use.
type Client struct {
	BaseURL      string // the Connector's base URL; /oauth2/challenge and /oauth2/token below it
	ClientID     string
	ClientSecret string       // client_secret_basic; never logged or returned
	HTTP         *http.Client // nil: 10 s timeout; redirects are never followed
	Now          func() time.Time
}

// BaseURL validates a Connector base URL: absolute http(s), no credentials, query or fragment. The
// result has no trailing slash.
func BaseURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", errors.New("bad URL")
	}
	return strings.TrimRight(u.String(), "/"), nil
}

var challengePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,256}$`)

// Challenge asks the Connector for a challenge for audience.
func (c *Client) Challenge(ctx context.Context, audience string) (Challenge, error) {
	status, _, body, err := c.post(ctx, c.base()+"/oauth2/challenge", url.Values{"audience": {audience}}, "")
	if err != nil || status != http.StatusOK {
		return Challenge{}, &Error{Kind: KindChallenge, Unreachable: err != nil || status >= 500, Status: status,
			text: "peer issued no challenge"}
	}
	var out struct {
		Challenge string `json:"challenge"`
		ExpiresIn int    `json:"expires_in"`
	}
	if json.Unmarshal(body, &out) != nil || !challengePattern.MatchString(out.Challenge) || out.ExpiresIn <= 0 {
		return Challenge{}, &Error{Kind: KindChallenge, text: "peer challenge malformed"}
	}
	return Challenge{Value: out.Challenge, ClientID: c.ClientID, Audience: audience,
		ExpiresAt: c.now().Add(time.Duration(out.ExpiresIn) * time.Second)}, nil
}

// TokenResponse is the part of the token answer the callers use.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

// Grant sends the verified-presentation grant with a fresh proof signed by key, retrying once with
// the server's nonce when challenged for one (a refusal before any write, so the outcome is still
// unused). Any answer that is not a readable 200 or a refusal is KindLost: the outcome may have been
// consumed, so the next attempt needs a fresh challenge and outcome.
func (c *Client) Grant(ctx context.Context, key dpopproof.Key, outcome, challenge, audience string) (TokenResponse, error) {
	tokenURL := c.base() + "/oauth2/token"
	form := url.Values{"grant_type": {VPGrantType}, "outcome": {outcome}, "challenge": {challenge}, "audience": {audience}}
	nonce := ""
	for try := 0; ; try++ {
		proof, err := dpopproof.Build(ctx, key, dpopproof.Claims{HTM: http.MethodPost, HTU: tokenURL, Nonce: nonce})
		if err != nil {
			return TokenResponse{}, &Error{Kind: KindProof, text: "proof not signed"}
		}
		status, header, body, err := c.post(ctx, tokenURL, form, proof)
		if err != nil || status >= 500 {
			return TokenResponse{}, &Error{Kind: KindLost, Unreachable: true, Status: status, text: "no readable answer from the peer"}
		}
		if status == http.StatusOK {
			var out TokenResponse
			if json.Unmarshal(body, &out) != nil || out.AccessToken == "" {
				return TokenResponse{}, &Error{Kind: KindLost, Unreachable: true, Status: status, text: "no readable answer from the peer"}
			}
			return out, nil
		}
		var refusal struct {
			Reason string `json:"reason"`
		}
		_ = json.Unmarshal(body, &refusal)
		if refusal.Reason == ReasonUseNonce && try == 0 && header.Get("DPoP-Nonce") != "" {
			nonce = header.Get("DPoP-Nonce")
			continue
		}
		e := &Error{Kind: KindRefused, Status: status, text: "grant refused by the peer"}
		if slices.Contains(credCodes, refusal.Reason) {
			e.Reason, e.text = refusal.Reason, "outcome refused by the peer"
		} else if refusal.Reason == ReasonUseNonce {
			e.Reason = ReasonUseNonce
		}
		return TokenResponse{}, e
	}
}

// Issued is what the checks read from an accepted token.
type Issued struct {
	IssuedAt, ExpiresAt time.Time
}

// Check accepts the issued token only if it is DPoP-bound to jkt, for audience and not expired. Only
// the payload is read; the signature is the Connector's and its resources'. An iat that is missing,
// after exp or more than a minute ahead reads as now.
func (c *Client) Check(t TokenResponse, jkt, audience string) (Issued, error) {
	bad := func(what string) (Issued, error) {
		return Issued{}, &Error{Kind: KindTokenInvalid, Check: what, text: "issued token failed the " + what + " check"}
	}
	if !strings.EqualFold(t.TokenType, "DPoP") {
		return bad("token_type")
	}
	parts := strings.Split(t.AccessToken, ".")
	if len(parts) != 3 {
		return bad("format")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return bad("format")
	}
	m, err := jose.ParseObject(raw)
	if err != nil {
		return bad("format")
	}
	cnf, err := jose.ParseObject(m["cnf"])
	if err != nil {
		return bad("cnf.jkt")
	}
	if got, _, ok := jose.String(cnf, "jkt"); !ok || got != jkt {
		return bad("cnf.jkt")
	}
	var auds []string
	if one, present, ok := jose.String(m, "aud"); present && ok {
		auds = []string{one}
	} else if json.Unmarshal(m["aud"], &auds) != nil {
		auds = nil
	}
	if !slices.Contains(auds, audience) {
		return bad("aud")
	}
	exp, ok := numericDate(m["exp"])
	now := c.now()
	if !ok || !exp.After(now) {
		return bad("exp")
	}
	iat, ok := numericDate(m["iat"])
	if !ok || iat.After(exp) || iat.After(now.Add(time.Minute)) {
		iat = now
	}
	return Issued{IssuedAt: iat, ExpiresAt: exp}, nil
}

// ATH is the proof's ath for an access token: base64url SHA-256 of its value (RFC 9449 section 4.2).
func ATH(accessToken string) string {
	d := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(d[:])
}

func numericDate(raw json.RawMessage) (time.Time, bool) {
	n, err := strconv.ParseInt(string(bytes.TrimSpace(raw)), 10, 64)
	if err != nil || n <= 0 {
		return time.Time{}, false
	}
	return time.Unix(n, 0), true
}

// post sends a form with client_secret_basic (RFC 6749 2.3.1) and, when given, a DPoP proof.
func (c *Client) post(ctx context.Context, target string, form url.Values, proof string) (int, http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(url.QueryEscape(c.ClientID), url.QueryEscape(c.ClientSecret))
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return 0, nil, nil, errors.New("request failed") // the transport's text is not ours to vouch for
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		return 0, nil, nil, errors.New("answer unreadable")
	}
	return resp.StatusCode, resp.Header, body, nil
}

func (c *Client) base() string { return strings.TrimRight(c.BaseURL, "/") }

func (c *Client) httpClient() *http.Client {
	h := http.Client{Timeout: 10 * time.Second}
	if c.HTTP != nil {
		h = *c.HTTP
	}
	h.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &h
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}
