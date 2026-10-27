// Package guard implements the deployable guard with real token, policy and store clients.
package guard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/policyhook/hook"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/replay"
)

// Clients use configured mesh destinations only; no caller header selects a service.
type Clients struct {
	PolicyURL string
	StoreURL  string
	HTTP      *http.Client
}

func NewClients(policyURL, storeURL string) *Clients {
	return &Clients{PolicyURL: policyURL, StoreURL: storeURL, HTTP: &http.Client{
		Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (c *Clients) post(ctx context.Context, target string, input, output any) (int, error) {
	body, err := json.Marshal(input)
	if err != nil {
		return 0, errors.New("request encoding failed")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return 0, errors.New("invalid configured endpoint")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, errors.New("dependency unavailable")
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32*1024+1))
	if err != nil || len(raw) > 32*1024 {
		return resp.StatusCode, errors.New("invalid dependency response")
	}
	if resp.StatusCode != http.StatusOK {
		var refusal struct {
			ReasonCode string `json:"reason_code"`
		}
		if json.Unmarshal(raw, &refusal) == nil {
			switch refusal.ReasonCode {
			case hook.ReasonTokenNoUpstream, hook.ReasonTokenStoreUnavailable, hook.ReasonTokenCallerDenied, hook.ReasonTokenRouteDenied:
				return resp.StatusCode, &hook.RefusalError{ReasonCode: refusal.ReasonCode}
			}
		}
		return resp.StatusCode, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(output) != nil || dec.Decode(&struct{}{}) != io.EOF {
		return resp.StatusCode, errors.New("invalid dependency response")
	}
	return resp.StatusCode, nil
}

// Decide implements the existing IF-05 policy interface over a real HTTP evaluator.
func (c *Clients) Decide(ctx context.Context, in hook.Input) (hook.Decision, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	var out hook.Decision
	status, err := c.post(ctx, c.PolicyURL+"/decision", in, &out)
	if err != nil || status != http.StatusOK || out.Validate() != nil {
		return hook.Decision{}, errors.New("policy unavailable or invalid")
	}
	// Every allowed M3 request must carry the upstream substitution obligation.
	if out.Allow && !out.Substitutes() {
		return hook.Decision{}, errors.New("policy omitted required substitution")
	}
	return out, nil
}

// TryUse implements replay.Store against the token store's durable proof ledger.
func (c *Clients) TryUse(ctx context.Context, use replay.Use) (bool, error) {
	input := struct {
		JKT      string `json:"jkt"`
		HTM      string `json:"htm"`
		HTU      string `json:"htu"`
		JTI      string `json:"jti"`
		IAT      int64  `json:"iat"`
		NotAfter int64  `json:"not_after"`
	}{use.JKT, use.Method, use.URI, use.JTI, use.NotAfter.Add(-(proofLifespan + proofSkew)).Unix(), use.NotAfter.Unix()}
	var out struct {
		Fresh bool `json:"fresh"`
	}
	status, err := c.post(ctx, c.StoreURL+"/internal/replay-check", input, &out)
	if err != nil {
		return false, err
	}
	if status == http.StatusConflict {
		return false, nil
	}
	if status != http.StatusOK || !out.Fresh {
		return false, errors.New("replay store unavailable")
	}
	return true, nil
}

// Substitute retrieves the upstream token and a newly signed proof; neither is logged.
func (c *Clients) Substitute(ctx context.Context, req hook.SubstituteRequest) (hook.Substitution, error) {
	var out struct {
		Authorization string `json:"authorization"`
		DPoP          string `json:"dpop"`
		Expires       string `json:"expires_at"`
	}
	status, err := c.post(ctx, c.StoreURL+"/internal/substitute", req, &out)
	if err != nil || status != http.StatusOK {
		var refusal *hook.RefusalError
		if errors.As(err, &refusal) {
			return hook.Substitution{}, refusal
		}
		return hook.Substitution{}, errors.New("token store unavailable")
	}
	exp, err := time.Parse(time.RFC3339, out.Expires)
	if err != nil || !exp.After(time.Now()) || !strings.HasPrefix(out.Authorization, "DPoP ") || len(out.Authorization) <= 5 || len(out.Authorization) > 8192 || out.DPoP == "" || len(out.DPoP) > 8192 || strings.ContainsAny(out.Authorization+out.DPoP, "\r\n") {
		return hook.Substitution{}, errors.New("token store response invalid")
	}
	return hook.Substitution{Authorization: out.Authorization, DPoP: out.DPoP}, nil
}
