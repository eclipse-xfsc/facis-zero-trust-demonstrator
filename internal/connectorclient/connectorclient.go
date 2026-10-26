// Package connectorclient is the client side of the Connector's authorization surface (IF-02): the
// challenge request and the verified-presentation grant with a DPoP proof and one nonce retry (design
// D5 and D10), the checks on the issued token, and dynamic client registration through a registrar.
// The token store's acquisition, the Participant and the registration command use it. It holds no
// state and keeps nothing it sends or receives.
package connectorclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/dpopproof"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
)

// VPGrantType is the Connector's verified-presentation grant (IF-02 v1.1).
const VPGrantType = "urn:facis:params:oauth:grant-type:verified-presentation"

// RegistrationScope is the scope a registrar's token carries to register clients (IF-02).
const RegistrationScope = "connector:client_registration"

// ReasonRegistrationRejected is the Connector's reason for client metadata it refused.
const ReasonRegistrationRejected = "registration_rejected"

const maxBody = 64 << 10

// maxDescription bounds the error_description a refusal is allowed to carry back to a caller.
const maxDescription = 256

// registrationReasons are the reasons IF-02 defines; a refusal carrying any other is reported
// without one.
var registrationReasons = []string{"invalid_request", "invalid_client", "invalid_token", "insufficient_scope",
	ReasonRegistrationRejected, "server_error", "dpop_invalid_proof", "dpop_replayed", ReasonUseNonce,
	"dpop_jkt_mismatch", "dpop_invalid_ath"}

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
	KindLost                         // no readable answer, or one no IF-02 call gives: terminal for the outcome
	KindRefused                      // the Connector refused the call
	KindTokenInvalid                 // the issued token failed a response check
	KindUnread                       // the Connector registered the client but its credentials could not be read
)

// Error is a failed call. It carries fixed text and classified fields only, never anything the
// Connector sent beyond a known reason code.
type Error struct {
	Kind Kind
	// Unreachable: the Connector was not reached or answered 5xx (KindChallenge; KindLost always is).
	Unreachable bool
	// Status is the HTTP status of a refusal, 0 when there was none.
	Status int
	// Reason is the Connector's reason for a KindRefused. From Grant, set only when it is an IF-03
	// CRED-OUTCOME-* code or dpop_use_nonce (a nonce demanded again after the one retry); from
	// ClientCredentialsToken and Register, any reason IF-02 defines, and every refusal carries one.
	Reason string
	// Check names the failed response check of a KindTokenInvalid: token_type, format, cnf.jkt, aud or exp.
	Check string
	// Description is the Connector's error_description of a refusal from ClientCredentialsToken or
	// Register, bounded to 256 printable characters; empty otherwise.
	Description string
	text        string
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
	// RequestID, when set, is sent as X-Request-Id on every call: the correlation id the
	// Connector's records and audit rows carry.
	RequestID string
}

// Credentials are what a registration returns and a client keeps.
type Credentials struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// Registration is the client metadata to register (IF-02 clientMetadata). Metadata, when set, is
// sent as the whole document instead of the fields.
type Registration struct {
	ClientName string
	GrantTypes []string // default client_credentials
	Scope      string   // space-separated
	Audience   []string
	Metadata   []byte
}

// ClientCredentialsToken obtains a client_credentials token for scope and audience, DPoP-bound to
// key, retrying once with the server's nonce. A registrar uses it for the token that authorises a
// registration: scope RegistrationScope plus the client's scopes, audience the registration endpoint
// plus the resource audiences the registered client may name.
func (c *Client) ClientCredentialsToken(ctx context.Context, key dpopproof.Key, scope string, audience []string) (TokenResponse, error) {
	tokenURL := c.base() + "/oauth2/token"
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {scope}, "audience": {strings.Join(audience, " ")}}
	status, body, err := c.withNonce(ctx, key, tokenURL, "", func(proof string) (int, http.Header, []byte, error) {
		return c.post(ctx, tokenURL, form, proof)
	})
	if err == nil {
		err = if02Answer(status, http.StatusOK, body)
	}
	if err != nil {
		return TokenResponse{}, err
	}
	if status == http.StatusOK {
		var out TokenResponse
		if json.Unmarshal(body, &out) != nil || out.AccessToken == "" {
			return TokenResponse{}, &Error{Kind: KindLost, Status: status, text: "token answer unreadable"}
		}
		return out, nil
	}
	return TokenResponse{}, refusal(status, body, "token refused by the peer")
}

// Register registers a client through the registration endpoint, authorised by accessToken (a
// registrar's, DPoP-bound to key), retrying once with the server's nonce. Only client_id and
// client_secret are read from the 201; the rest of the answer, the registration access token
// among it, is dropped unread. A 201 whose credentials cannot be read is KindUnread: the client
// exists without them.
func (c *Client) Register(ctx context.Context, key dpopproof.Key, endpoint, accessToken string, reg Registration) (Credentials, error) {
	body := reg.Metadata
	if body == nil {
		grants := reg.GrantTypes
		if len(grants) == 0 {
			grants = []string{"client_credentials"}
		}
		body, _ = json.Marshal(map[string]any{
			"client_name": reg.ClientName, "grant_types": grants, "token_endpoint_auth_method": "client_secret_basic",
			"scope": reg.Scope, "dpop_bound_access_tokens": true, "audience": reg.Audience,
		})
	}
	status, answer, err := c.withNonce(ctx, key, endpoint, ATH(accessToken), func(proof string) (int, http.Header, []byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return 0, nil, nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "DPoP "+accessToken)
		req.Header.Set("DPoP", proof)
		if c.RequestID != "" {
			req.Header.Set("X-Request-Id", c.RequestID)
		}
		return c.do(req)
	})
	if err == nil {
		err = if02Answer(status, http.StatusCreated, answer)
	}
	if err != nil {
		return Credentials{}, err
	}
	if status == http.StatusCreated {
		members, err := jose.ParseObject(answer)
		id, _, okID := jose.String(members, "client_id")
		secret, _, okSecret := jose.String(members, "client_secret")
		if err != nil || !okID || !okSecret || id == "" || secret == "" {
			return Credentials{}, &Error{Kind: KindUnread, Status: status, text: "registered, but the credentials in the answer could not be read"}
		}
		return Credentials{ClientID: id, ClientSecret: secret}, nil
	}
	return Credentials{}, refusal(status, answer, "registration refused by the peer")
}

// withNonce sends one DPoP-proofed call, and once more with the server's nonce when the answer
// asks for one. It returns the final answer's status and body; the error is the proof not signed
// (KindProof), or no readable answer or a 5xx (KindLost, Unreachable).
func (c *Client) withNonce(ctx context.Context, key dpopproof.Key, htu, ath string, send func(proof string) (int, http.Header, []byte, error)) (int, []byte, error) {
	nonce := ""
	for try := 0; ; try++ {
		proof, err := dpopproof.Build(ctx, key, dpopproof.Claims{HTM: http.MethodPost, HTU: htu, Nonce: nonce, ATH: ath})
		if err != nil {
			return 0, nil, &Error{Kind: KindProof, text: "proof not signed"}
		}
		status, header, body, err := send(proof)
		if err != nil {
			return 0, nil, &Error{Kind: KindLost, Unreachable: true, text: "no readable answer from the peer"}
		}
		if status >= 500 {
			return 0, nil, &Error{Kind: KindLost, Unreachable: true, Status: status, text: "server error from the peer (" + strconv.Itoa(status) + ")"}
		}
		var answer struct {
			Reason string `json:"reason"`
		}
		_ = json.Unmarshal(body, &answer)
		if answer.Reason == ReasonUseNonce && try == 0 && header.Get("DPoP-Nonce") != "" {
			nonce = header.Get("DPoP-Nonce")
			continue
		}
		return status, body, nil
	}
}

// if02Answer accepts the answer of an IF-02 call: the expected success, or a refusal, a 4xx naming
// a reason IF-02 defines. Anything else (a redirect, another success, a 404 from something in front
// of the Connector) is an answer no IF-02 call gives: KindLost, not a refusal.
func if02Answer(status, success int, body []byte) error {
	if status == success || (status >= 400 && status < 500 && reasonIn(body) != "") {
		return nil
	}
	return &Error{Kind: KindLost, Status: status, text: "unexpected answer from the peer (" + strconv.Itoa(status) + ")"}
}

// reasonIn is the reason of an IF-02 refusal, empty when the body is none.
func reasonIn(body []byte) string {
	var answer struct {
		Reason string `json:"reason"`
	}
	if json.Unmarshal(body, &answer) != nil || !slices.Contains(registrationReasons, answer.Reason) {
		return ""
	}
	return answer.Reason
}

// refusal reads an IF-02 refusal: its reason, and its description's printable part, bounded. The
// Connector's descriptions are its own fixed texts; the bound and the filter keep anything else in
// check.
func refusal(status int, body []byte, text string) *Error {
	var answer struct {
		Description string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &answer)
	return &Error{Kind: KindRefused, Status: status, Reason: reasonIn(body), Description: printable(answer.Description, maxDescription), text: text}
}

// printable keeps the printable runes of s, up to limit of them.
func printable(s string, limit int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == limit {
			break
		}
		if unicode.IsPrint(r) {
			b.WriteRune(r)
			n++
		}
	}
	return b.String()
}

// CredentialsFile is a credentials file being written: a hidden temporary file beside the target,
// created at once (so a directory that cannot take the file is known before anything is
// registered) and linked to the target only when the credentials are in it. The target is never
// overwritten, and a process killed in between leaves only the temporary file, never an empty
// target that would block the next run.
type CredentialsFile struct {
	path string
	tmp  *os.File
}

// ReserveCredentials prepares writing path, which must not exist.
func ReserveCredentials(path string) (*CredentialsFile, error) {
	if _, err := os.Lstat(path); err == nil {
		return nil, fmt.Errorf("credentials file: %s: %w", path, fs.ErrExist)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("credentials file: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp") // 0600
	if err != nil {
		return nil, fmt.Errorf("credentials file: %w", err)
	}
	f := &CredentialsFile{path: path, tmp: tmp}
	// The directory must take the hard link Write ends with; a filesystem without them is refused
	// now, before anything is registered, not after.
	if err := os.Link(tmp.Name(), f.probe()); err != nil {
		f.Abandon()
		return nil, fmt.Errorf("credentials file: cannot hard-link in %s: %w", filepath.Dir(path), err)
	}
	_ = os.Remove(f.probe())
	return f, nil
}

// Write writes the credentials file a Participant reads (PARTICIPANT_CREDENTIALS_FILE): one JSON
// object with exactly client_id and client_secret, 0600, flushed to disk, then linked into place;
// refused when the target appeared meanwhile.
func (f *CredentialsFile) Write(c Credentials) error {
	defer f.Abandon()
	doc, _ := json.Marshal(c)
	_, werr := f.tmp.Write(append(doc, '\n'))
	serr := f.tmp.Sync()
	cerr := f.tmp.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		return fmt.Errorf("credentials file: %w", err)
	}
	if err := os.Link(f.tmp.Name(), f.path); err != nil {
		return fmt.Errorf("credentials file: %w", err)
	}
	return nil
}

// Abandon removes the temporary file and the link probe; the target, if written, stays. Safe to
// call more than once.
func (f *CredentialsFile) Abandon() {
	_ = f.tmp.Close()
	_ = os.Remove(f.tmp.Name())
	_ = os.Remove(f.probe())
}

// probe is the name ReserveCredentials links the temporary file to, to learn the directory takes
// hard links.
func (f *CredentialsFile) probe() string { return f.tmp.Name() + ".link" }

// WriteCredentials writes the credentials file at path, which must not exist (CredentialsFile).
func WriteCredentials(path string, c Credentials) error {
	f, err := ReserveCredentials(path)
	if err != nil {
		return err
	}
	return f.Write(c)
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
	status, body, err := c.withNonce(ctx, key, tokenURL, "", func(proof string) (int, http.Header, []byte, error) {
		return c.post(ctx, tokenURL, form, proof)
	})
	if err != nil {
		return TokenResponse{}, err
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
	e := &Error{Kind: KindRefused, Status: status, text: "grant refused by the peer"}
	if slices.Contains(credCodes, refusal.Reason) {
		e.Reason, e.text = refusal.Reason, "outcome refused by the peer"
	} else if refusal.Reason == ReasonUseNonce {
		e.Reason = ReasonUseNonce
	}
	return TokenResponse{}, e
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
	if c.RequestID != "" {
		req.Header.Set("X-Request-Id", c.RequestID)
	}
	return c.do(req)
}

// do sends a prepared request and reads a bounded answer.
func (c *Client) do(req *http.Request) (int, http.Header, []byte, error) {
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
