package sdjwt

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
)

// disclosure is one decoded "[salt, name, value]".
type disclosure struct {
	name  string
	value json.RawMessage
	used  bool
}

// disclose resolves the _sd digests of payload, at any depth, against the presented disclosures
// and returns the claim set with the disclosed members in place and the SD-JWT bookkeeping and
// registered members left out. Refused: a disclosure that is not a three-element array of salt,
// name and value; a digest that resolves twice; a disclosure referenced by no digest; a disclosed
// name that already exists, is reserved (_sd, ..., _sd_alg) or is a registered claim at the top
// level; an array element disclosure ({"...": digest}), which this profile does not use; an _sd
// member that is not an array of strings. Decoy digests (no matching disclosure) are allowed, as
// the specification intends.
func disclose(payload map[string]json.RawMessage, presented []string) (map[string]json.RawMessage, error) {
	byDigest := make(map[string]*disclosure, len(presented))
	for _, encoded := range presented {
		raw, err := jose.DecodeB64(encoded)
		if err != nil {
			return nil, fmt.Errorf("%w: encoding", ErrDisclosure)
		}
		var parts []json.RawMessage // Unmarshal validates every element, the value included
		if err := json.Unmarshal(raw, &parts); err != nil || len(parts) != 3 {
			return nil, fmt.Errorf("%w: not a salt, name and value", ErrDisclosure)
		}
		var salt, name string
		if json.Unmarshal(parts[0], &salt) != nil || json.Unmarshal(parts[1], &name) != nil || name == "" {
			return nil, fmt.Errorf("%w: salt or name", ErrDisclosure)
		}
		digest := sha256.Sum256([]byte(encoded))
		key := jose.B64(digest[:])
		if _, dup := byDigest[key]; dup {
			return nil, fmt.Errorf("%w: presented twice", ErrDisclosure)
		}
		byDigest[key] = &disclosure{name: name, value: parts[2]}
	}

	// The envelope (iss, cnf, status, ...) is read by Verify and is never a claim: it is not
	// descended into, so a disclosure can only be referenced from the claim set.
	claimMembers := make(map[string]json.RawMessage, len(payload))
	for name, raw := range payload {
		if !registeredClaims[name] {
			claimMembers[name] = raw
		}
	}
	out, err := discloseObject(claimMembers, byDigest, 0)
	if err != nil {
		return nil, err
	}
	for _, d := range byDigest {
		if !d.used {
			return nil, fmt.Errorf("%w: not referenced by the credential", ErrDisclosure)
		}
	}
	return out, nil
}

var reservedNames = map[string]bool{"_sd": true, "...": true, "_sd_alg": true}

func discloseObject(members map[string]json.RawMessage, byDigest map[string]*disclosure, depth int) (map[string]json.RawMessage, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("%w: nested too deeply", ErrDisclosure)
	}
	out := make(map[string]json.RawMessage, len(members))
	for name, raw := range members {
		if name == "_sd" || name == "_sd_alg" {
			continue
		}
		if name == "..." {
			return nil, fmt.Errorf("%w: array element disclosure in an object", ErrDisclosure)
		}
		resolved, err := discloseValue(raw, byDigest, depth+1)
		if err != nil {
			return nil, err
		}
		out[name] = resolved
	}
	if rawSD, present := members["_sd"]; present {
		var digests []json.RawMessage
		if trimmed := bytes.TrimSpace(rawSD); len(trimmed) == 0 || trimmed[0] != '[' || json.Unmarshal(rawSD, &digests) != nil {
			return nil, fmt.Errorf("%w: _sd is not an array", ErrDisclosure)
		}
		for _, rawDigest := range digests {
			var digest string
			if json.Unmarshal(rawDigest, &digest) != nil || digest == "" {
				return nil, fmt.Errorf("%w: _sd digest is not a string", ErrDisclosure)
			}
			d, matched := byDigest[digest]
			if !matched {
				continue // a decoy
			}
			if d.used {
				return nil, fmt.Errorf("%w: digest referenced twice", ErrDisclosure)
			}
			d.used = true
			if reservedNames[d.name] {
				return nil, fmt.Errorf("%w: reserved name", ErrDisclosure)
			}
			if depth == 0 && registeredClaims[d.name] {
				return nil, fmt.Errorf("%w: registered claim disclosed", ErrDisclosure)
			}
			if _, exists := out[d.name]; exists {
				return nil, fmt.Errorf("%w: name already present", ErrDisclosure)
			}
			resolved, err := discloseValue(d.value, byDigest, depth+1)
			if err != nil {
				return nil, err
			}
			out[d.name] = resolved
		}
	}
	return out, nil
}

// discloseValue resolves nested objects and arrays; scalars pass through.
func discloseValue(raw json.RawMessage, byDigest map[string]*disclosure, depth int) (json.RawMessage, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("%w: nested too deeply", ErrDisclosure)
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("%w: empty value", ErrDisclosure)
	}
	switch trimmed[0] {
	case '{':
		members, err := jose.ParseObject(trimmed)
		if err != nil {
			return nil, fmt.Errorf("%w: object", ErrDisclosure)
		}
		resolved, err := discloseObject(members, byDigest, depth)
		if err != nil {
			return nil, err
		}
		return json.Marshal(resolved)
	case '[':
		var items []json.RawMessage
		if err := json.Unmarshal(trimmed, &items); err != nil {
			return nil, fmt.Errorf("%w: array", ErrDisclosure)
		}
		for i, item := range items {
			if m, err := jose.ParseObject(bytes.TrimSpace(item)); err == nil && len(m) == 1 && m["..."] != nil {
				return nil, fmt.Errorf("%w: array element disclosure", ErrDisclosure)
			}
			resolved, err := discloseValue(item, byDigest, depth+1)
			if err != nil {
				return nil, err
			}
			items[i] = resolved
		}
		return json.Marshal(items)
	}
	return trimmed, nil
}
