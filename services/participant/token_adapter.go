package participant

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Token mode reasons. 401, 403 and 503 from the Resource each have their own name; the body of those
// answers is not trusted or forwarded.
const (
	ReasonTokenSessionNotReady     = "TOKEN_SESSION_NOT_READY"
	ReasonTokenAuthorizeFailed     = "TOKEN_AUTHORIZE_FAILED"
	ReasonTokenRejected            = "TOKEN_REJECTED"
	ReasonTokenForbidden           = "TOKEN_FORBIDDEN"
	ReasonTokenResourceUnavailable = "TOKEN_RESOURCE_UNAVAILABLE"
	ReasonTokenCredentialEchoed    = "TOKEN_CREDENTIAL_ECHOED"
	ReasonTokenDuplicateMember     = "TOKEN_RESOURCE_DUPLICATE_MEMBER"
	ReasonTokenResourceInvalid     = "TOKEN_RESOURCE_INVALID"
)

// tokenExplanations replaces every Resource explanation in token mode: upstream text is never forwarded.
var tokenExplanations = map[string]string{
	"RESOURCE_REPORT_RETURNED":      "The Resource returned the report for the token's scopes.",
	"RESOURCE_SUMMARY_RETURNED":     "The Resource returned the report summary for the token's scopes.",
	"RESOURCE_SCENARIO_NOT_ALLOWED": "The Resource refused a sample scenario in token mode.",
	"RESOURCE_IDENTITY_MISSING":     "The Resource could not read the verified caller identity.",
}

const tokenFallbackExplanation = "The Resource answered with the documented result named by reasonCode."

// TokenAdapter calls the Resource with credentials from the lifecycle's TokenSession. It asks the
// session for a fresh Authorization and DPoP pair on every call and keeps neither.
type TokenAdapter struct {
	endpoint string
	client   *http.Client
	session  func() TokenSession
}

func NewTokenAdapter(resourceURL string, client *http.Client, session func() TokenSession) *TokenAdapter {
	base := NewHTTPSampleAdapter(resourceURL, client)
	return &TokenAdapter{endpoint: base.endpoint, client: base.client, session: session}
}

func (a *TokenAdapter) Request(ctx context.Context, request AdapterRequest) (*AdapterResult, error) {
	session := a.session()
	if session == nil {
		return tokenResult(OutcomeUnavailable, ReasonTokenSessionNotReady, "The Participant has no token session yet; see GET /state."), nil
	}
	request.Scenario = "" // scenarios are sample-mode only
	body, err := json.Marshal(DemoRequest(request))
	if err != nil {
		return nil, fmt.Errorf("encode protected resource request: %w", err)
	}
	authorization, proof, err := session.Authorize(ctx, http.MethodPost, a.endpoint)
	if err != nil {
		// The error text may carry upstream detail; only the fixed reason leaves this function.
		return tokenResult(OutcomeError, ReasonTokenAuthorizeFailed, "The token session could not authorize the request."), nil
	}
	outbound, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build protected resource request: %w", err)
	}
	outbound.Header.Set("Content-Type", "application/json")
	outbound.Header.Set("Accept", "application/json")
	outbound.Header.Set("Authorization", authorization)
	outbound.Header.Set("DPoP", proof)

	response, err := a.client.Do(outbound)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()

	switch response.StatusCode {
	case http.StatusUnauthorized:
		return tokenResult(OutcomeDenied, ReasonTokenRejected, "The Resource rejected the token or its proof."), nil
	case http.StatusForbidden:
		return tokenResult(OutcomeDenied, ReasonTokenForbidden, "The Resource refused the request for the token's scopes."), nil
	case http.StatusServiceUnavailable:
		return tokenResult(OutcomeUnavailable, ReasonTokenResourceUnavailable, "The Resource could not verify tokens or was unavailable."), nil
	}
	raw, err := readResourceBody(response)
	if err != nil {
		return refusedAnswer(ReasonTokenResourceInvalid), nil
	}
	// Duplicate members make different decoders see different values, so no later check could be
	// trusted; refuse them before decoding anything.
	if duplicate, err := hasDuplicateMembers(raw); err != nil {
		return refusedAnswer(ReasonTokenResourceInvalid), nil
	} else if duplicate {
		return refusedAnswer(ReasonTokenDuplicateMember), nil
	}
	secrets := credentialForms(authorization, proof)
	if echoesCredential(raw, secrets) {
		return refusedAnswer(ReasonTokenCredentialEchoed), nil
	}
	result, err := decodeResourceBody(response.StatusCode, raw, request, ModeToken)
	if err != nil || !strictTokenSafeData(result) {
		return refusedAnswer(ReasonTokenResourceInvalid), nil
	}
	result.Explanation = tokenFallbackExplanation
	if text, ok := tokenExplanations[result.ReasonCode]; ok {
		result.Explanation = text
	}
	// Final check on exactly what will be emitted.
	emitted, err := json.Marshal(result)
	if err != nil || echoesCredential(emitted, secrets) {
		return refusedAnswer(ReasonTokenCredentialEchoed), nil
	}
	return result, nil
}

var refusedExplanations = map[string]string{
	ReasonTokenResourceInvalid:  "The Resource answer did not match the documented token-mode contract and was discarded.",
	ReasonTokenDuplicateMember:  "The Resource answer repeated a JSON member and was discarded.",
	ReasonTokenCredentialEchoed: "The Resource answer contained this request's credentials and was discarded.",
}

func refusedAnswer(reason string) *AdapterResult {
	return tokenResult(OutcomeError, reason, refusedExplanations[reason])
}

// credentialForms lists what must never come back: the Authorization value, the bare token, the proof,
// and the standard and URL-safe base64 encodings (padded and raw) of each.
// ponytail: catches whole-credential encodings only; arbitrary fragments are bounded by
// strictTokenSafeData's word-length cap, not detected.
func credentialForms(authorization, proof string) []string {
	plain := []string{authorization, proof}
	if _, token, ok := strings.Cut(authorization, " "); ok {
		plain = append(plain, token)
	}
	var forms []string
	for _, value := range plain {
		if value == "" {
			continue
		}
		forms = append(forms, value)
		for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
			forms = append(forms, encoding.EncodeToString([]byte(value)))
		}
	}
	return forms
}

// echoesCredential reports whether raw, or any JSON string or member name in it after unescaping,
// contains one of secrets. raw must be free of duplicate members for the decoded view to be complete.
func echoesCredential(raw []byte, secrets []string) bool {
	texts := []string{string(raw)}
	var decoded any
	if json.Unmarshal(raw, &decoded) == nil {
		texts = appendStrings(texts, decoded)
	}
	for _, secret := range secrets {
		for _, text := range texts {
			if strings.Contains(text, secret) {
				return true
			}
		}
	}
	return false
}

func appendStrings(out []string, value any) []string {
	switch v := value.(type) {
	case string:
		out = append(out, v)
	case []any:
		for _, item := range v {
			out = appendStrings(out, item)
		}
	case map[string]any:
		for key, item := range v {
			out = appendStrings(append(out, key), item)
		}
	}
	return out
}

// hasDuplicateMembers walks the JSON tokens and reports a member name repeated within one object, at
// any depth. Names are compared after unescaping, so "a" and "\u0061" collide.
func hasDuplicateMembers(raw []byte) (bool, error) {
	type frame struct {
		object    bool
		expectKey bool
		keys      map[string]bool
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var stack []*frame
	valueDone := func() {
		if len(stack) > 0 && stack[len(stack)-1].object {
			stack[len(stack)-1].expectKey = true
		}
	}
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			if len(stack) != 0 {
				return false, io.ErrUnexpectedEOF
			}
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{':
				stack = append(stack, &frame{object: true, expectKey: true, keys: map[string]bool{}})
			case '[':
				stack = append(stack, &frame{})
			default:
				stack = stack[:len(stack)-1]
				valueDone()
			}
			continue
		}
		if top := len(stack) - 1; top >= 0 && stack[top].object && stack[top].expectKey {
			name, _ := token.(string)
			if stack[top].keys[name] {
				return true, nil
			}
			stack[top].keys[name] = true
			stack[top].expectKey = false
			continue
		}
		valueDone()
	}
}

const (
	maxTokenIDBytes    = 64
	maxTokenTitleBytes = 128
	maxTokenTextBytes  = 512
	maxTokenWordBytes  = 32
)

// strictTokenSafeData narrows token-mode success data, already reduced to the documented keys by
// sanitizeSafeData, to the seed's form: an id of A-Z, 0-9 and '-', bounded title and text, and no word
// longer than maxTokenWordBytes, so an encoded credential cannot ride in a free-form field.
func strictTokenSafeData(result *AdapterResult) bool {
	if result.Outcome != OutcomeSuccess {
		return len(result.SafeData) == 0
	}
	kind, textKey := "report", "content"
	if _, ok := result.SafeData["summary"]; ok {
		kind, textKey = "summary", "summary"
	}
	fields, ok := result.SafeData[kind].(map[string]any)
	if !ok {
		return false
	}
	id, _ := fields["id"].(string)
	title, _ := fields["title"].(string)
	text, _ := fields[textKey].(string)
	if len(id) > maxTokenIDBytes || len(title) > maxTokenTitleBytes || len(text) > maxTokenTextBytes {
		return false
	}
	for _, r := range id {
		if (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	for _, word := range strings.Fields(title + " " + text) {
		if len(word) > maxTokenWordBytes {
			return false
		}
	}
	return true
}

func tokenResult(outcome Outcome, reason, explanation string) *AdapterResult {
	return &AdapterResult{Outcome: outcome, ReasonCode: reason, Explanation: explanation, SafeData: emptySafeData()}
}
