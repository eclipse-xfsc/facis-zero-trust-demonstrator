// Package oid4vp holds the small part of OpenID for Verifiable Presentations the demonstrator uses:
// a verification request bound to a connector challenge, and the direct_post response that carries
// one SD-JWT VC presentation. Standard library only.
package oid4vp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
)

// ResponseModeDirectPost is the only response mode this profile uses.
const ResponseModeDirectPost = "direct_post"

// MaxVPToken bounds a vp_token member.
const MaxVPToken = 64 << 10

var ErrResponse = errors.New("oid4vp: response not accepted")

// Request is what a holder receives: the verifier's client_id (this profile sets it to the
// audience the presentation is for, so a conformant wallet's key binding carries that audience),
// the nonce (the connector's challenge value), where to post the response, and a DCQL query
// naming the credential wanted.
type Request struct {
	ClientID    string          `json:"client_id"`
	Nonce       string          `json:"nonce"`
	ResponseURI string          `json:"response_uri"`
	State       string          `json:"state,omitempty"`
	DCQL        json.RawMessage `json:"dcql_query,omitempty"`
}

// Form renders the request as the authorization request parameters a wallet reads.
func (r Request) Form() url.Values {
	v := url.Values{}
	v.Set("client_id", r.ClientID)
	v.Set("nonce", r.Nonce)
	v.Set("response_uri", r.ResponseURI)
	v.Set("response_mode", ResponseModeDirectPost)
	v.Set("response_type", "vp_token")
	if r.State != "" {
		v.Set("state", r.State)
	}
	if len(r.DCQL) > 0 {
		v.Set("dcql_query", string(r.DCQL))
	}
	return v
}

// DCQLQuery is the query for one SD-JWT VC of the given types.
func DCQLQuery(id string, vct ...string) json.RawMessage {
	raw, _ := json.Marshal(map[string]any{"credentials": []map[string]any{{
		"id": id, "format": "dc+sd-jwt", "meta": map[string]any{"vct_values": vct},
	}}})
	return raw
}

// ParseDirectPost reads the vp_token of a direct_post response form: exactly one vp_token member,
// carrying one presentation as a string, as a one-element array of strings, or as a DCQL result
// object with one credential query id mapping to one string or one-element array. Anything else is
// refused: this profile presents exactly one credential.
func ParseDirectPost(form url.Values) (string, error) {
	values, present := form["vp_token"]
	if !present || len(values) != 1 {
		return "", fmt.Errorf("%w: vp_token must appear exactly once", ErrResponse)
	}
	raw := values[0]
	if len(raw) > MaxVPToken {
		return "", fmt.Errorf("%w: vp_token too large", ErrResponse)
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("%w: vp_token empty", ErrResponse)
	}
	switch trimmed[0] {
	case '[':
		return oneOfArray(trimmed)
	case '{':
		members, err := jose.ParseObject([]byte(trimmed))
		if err != nil || len(members) != 1 {
			return "", fmt.Errorf("%w: vp_token object must hold one credential query", ErrResponse)
		}
		var value json.RawMessage
		for _, v := range members {
			value = v // the single member
		}
		inner := strings.TrimSpace(string(value))
		if strings.HasPrefix(inner, "[") {
			return oneOfArray(inner)
		}
		var s string
		if json.Unmarshal(value, &s) != nil || s == "" {
			return "", fmt.Errorf("%w: vp_token value", ErrResponse)
		}
		return s, nil
	case '"':
		var s string
		if json.Unmarshal([]byte(trimmed), &s) != nil || s == "" {
			return "", fmt.Errorf("%w: vp_token string", ErrResponse)
		}
		return s, nil
	}
	return trimmed, nil
}

func oneOfArray(raw string) (string, error) {
	var items []string
	if json.Unmarshal([]byte(raw), &items) != nil || len(items) != 1 || items[0] == "" {
		return "", fmt.Errorf("%w: vp_token array must hold exactly one presentation", ErrResponse)
	}
	return items[0], nil
}
