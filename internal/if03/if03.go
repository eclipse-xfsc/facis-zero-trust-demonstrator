// Package if03 verifies IF-03 verification outcomes: a compact JWS with header exactly alg, kid, typ
// (docs/api-docs.md, IF-03; docs/contracts/if03-*.schema.json).
package if03

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
)

// Typ is the outcome's typ header.
const Typ = "facis-verification-outcome+jws"

// Reason codes, as IF-03 names them.
const (
	CodeSignature   = "CRED-OUTCOME-SIGNATURE"
	CodeNotVerified = "CRED-OUTCOME-NOT-VERIFIED"
	CodeMismatch    = "CRED-OUTCOME-MISMATCH"
	CodeExpired     = "CRED-OUTCOME-EXPIRED"
	CodeConsumed    = "CRED-OUTCOME-CONSUMED"
)

// Claims is the outcome's role and optional entitlement.
type Claims struct {
	Role        string `json:"role"`
	Entitlement string `json:"entitlement,omitempty"`
}

// Outcome is a parsed, signature-checked outcome.
type Outcome struct {
	Issuer         string    `json:"iss"`
	OutcomeID      string    `json:"outcome_id"`
	ClientID       string    `json:"client_id"`
	Challenge      string    `json:"challenge"`
	Audience       string    `json:"audience"`
	Claims         Claims    `json:"claims"`
	VerifiedAt     time.Time `json:"verified_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	Status         string    `json:"status"`
	CredentialRefs []string  `json:"credential_refs,omitempty"`
	ReasonCode     string    `json:"reason_code,omitempty"`
	Raw            []byte    `json:"-"` // the payload as signed
}

// Issuers is the configured trust: issuer → kid → key. A kid belongs to exactly one issuer.
type Issuers map[string]map[string]*ecdsa.PublicKey

// Expect is the grant request the outcome must match.
type Expect struct {
	ClientID  string
	Challenge string
	Audience  string
}

// Error carries the IF-03 reason code.
type Error struct {
	Code string
	Err  error
}

func (e *Error) Error() string { return e.Code + ": " + e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

// The interval rules of IF-03: an outcome is valid for at most maxValidity after verified_at, and
// verified_at may lie at most skew in the future.
const (
	maxValidity = 120 * time.Second
	skew        = 30 * time.Second
)

// Verify checks signature (CodeSignature), payload schema, status (CodeNotVerified), the match with
// want (CodeMismatch) and the validity interval at now with 30 s skew and a 120 s maximum
// (CodeExpired). Consumption (CodeConsumed) is the caller's, inside its transaction. A payload that
// or header that does not follow the IF-03 schemas is refused with CodeSignature, the code of the
// format rule: whoever signed it, it is not an outcome in the agreed form, so nothing in it is used. Errors carry the code and fixed text only.
func Verify(compact string, trusted Issuers, want Expect, now time.Time) (Outcome, error) {
	var owner string
	_, payload, err := jose.Verify(compact, jose.HeaderPolicy{Typ: Typ, KidNeeded: true}, func(h jose.Header) (*ecdsa.PublicKey, error) {
		for iss, keys := range trusted {
			if k, ok := keys[h.Kid]; ok && k != nil {
				if owner != "" {
					return nil, errors.New("kid held by more than one issuer")
				}
				owner = iss
			}
		}
		if owner == "" {
			return nil, errors.New("unknown kid")
		}
		if utf8.RuneCountInString(h.Kid) > 128 {
			return nil, errors.New("kid too long")
		}
		return trusted[owner][h.Kid], nil
	})
	if err != nil {
		return Outcome{}, refuse(CodeSignature, "signature not verified with a trusted key")
	}
	o, ok := parsePayload(payload)
	if !ok {
		return Outcome{}, refuse(CodeSignature, "payload is not an IF-03 outcome")
	}
	if o.Issuer != owner {
		return Outcome{}, refuse(CodeSignature, "issuer does not own the signing key")
	}
	if o.Status != "verified" {
		return Outcome{}, refuse(CodeNotVerified, "outcome is not verified")
	}
	if o.ClientID != want.ClientID || o.Challenge != want.Challenge || o.Audience != want.Audience {
		return Outcome{}, refuse(CodeMismatch, "outcome is for another client, challenge or audience")
	}
	if !o.VerifiedAt.Before(o.ExpiresAt) || o.ExpiresAt.Sub(o.VerifiedAt) > maxValidity ||
		o.VerifiedAt.After(now.Add(skew)) || !now.Before(o.ExpiresAt) {
		return Outcome{}, refuse(CodeExpired, "outcome is outside its validity interval")
	}
	return o, nil
}

func refuse(code, text string) *Error { return &Error{Code: code, Err: errors.New(text)} }

var (
	uuidPattern     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	reasonPattern   = regexp.MustCompile(`^CRED(-[A-Z0-9]+)+$`)
	schemePattern   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*:`)
	dateTimePattern = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d+)?([Zz]|[+-](\d{2}):(\d{2}))$`)
)

// The members the schema names, and the ones it requires.
var (
	outcomeMembers = map[string]bool{"iss": true, "outcome_id": true, "client_id": true, "challenge": true, "audience": true,
		"claims": true, "credential_refs": true, "verified_at": true, "expires_at": true, "status": true, "reason_code": true}
	outcomeRequired = []string{"iss", "outcome_id", "client_id", "challenge", "audience", "claims", "verified_at", "expires_at", "status"}
)

// parsePayload applies if03-verification-outcome.v1.schema.json to the members exactly as written:
// a strict JSON object (no duplicates, compared by exact name, never case-folded), no member the
// schema does not name, every required member present and of its type (null is never a string,
// object or array), string bounds in characters, uuid, uri and date-time formats, and reason_code
// present exactly when the status is not verified.
func parsePayload(payload []byte) (Outcome, bool) {
	m, err := jose.ParseObject(payload)
	if err != nil || !onlyMembers(m, outcomeMembers) {
		return Outcome{}, false
	}
	for _, name := range outcomeRequired {
		if _, ok := m[name]; !ok {
			return Outcome{}, false
		}
	}
	var o Outcome
	var ok bool
	str := func(name string, min, max int) string {
		v, _, isStr := jose.String(m, name)
		if n := utf8.RuneCountInString(v); !isStr || n < min || (max > 0 && n > max) {
			ok = false
		}
		return v
	}
	ok = true
	o.Issuer = str("iss", 1, 0)
	o.OutcomeID = str("outcome_id", 1, 0)
	o.ClientID = str("client_id", 1, 256)
	o.Challenge = str("challenge", 16, 256)
	o.Audience = str("audience", 1, 0)
	o.Status = str("status", 1, 0)
	verifiedAt, expiresAt := str("verified_at", 1, 0), str("expires_at", 1, 0)
	if !ok || !isURI(o.Issuer) || !isURI(o.Audience) || !uuidPattern.MatchString(o.OutcomeID) {
		return Outcome{}, false
	}
	if o.VerifiedAt, ok = parseDateTime(verifiedAt); !ok {
		return Outcome{}, false
	}
	if o.ExpiresAt, ok = parseDateTime(expiresAt); !ok {
		return Outcome{}, false
	}

	claims, err := jose.ParseObject(m["claims"])
	if err != nil || !onlyMembers(claims, map[string]bool{"role": true, "entitlement": true}) {
		return Outcome{}, false
	}
	role, _, isStr := jose.String(claims, "role")
	if !isStr || role == "" {
		return Outcome{}, false
	}
	o.Claims.Role = role
	if _, present := claims["entitlement"]; present {
		ent, _, isStr := jose.String(claims, "entitlement")
		if !isStr || ent == "" {
			return Outcome{}, false
		}
		o.Claims.Entitlement = ent
	}

	if raw, present := m["credential_refs"]; present {
		var items []json.RawMessage
		if trimmed := bytes.TrimSpace(raw); len(trimmed) == 0 || trimmed[0] != '[' || json.Unmarshal(raw, &items) != nil {
			return Outcome{}, false
		}
		for _, item := range items {
			var ref string
			if t := bytes.TrimSpace(item); len(t) == 0 || t[0] != '"' || json.Unmarshal(item, &ref) != nil || ref == "" {
				return Outcome{}, false
			}
			o.CredentialRefs = append(o.CredentialRefs, ref)
		}
	}

	_, hasReason := m["reason_code"]
	switch o.Status {
	case "verified":
		if hasReason {
			return Outcome{}, false
		}
	case "failed", "revoked":
		reason, _, isStr := jose.String(m, "reason_code")
		if !hasReason || !isStr || !reasonPattern.MatchString(reason) {
			return Outcome{}, false
		}
		o.ReasonCode = reason
	default:
		return Outcome{}, false
	}
	o.Raw = payload
	return o, true
}

func onlyMembers(m map[string]json.RawMessage, allowed map[string]bool) bool {
	for name := range m {
		if !allowed[name] {
			return false
		}
	}
	return true
}

// isURI accepts an absolute URI as RFC 3986 writes it (JSON Schema's "uri" format):
// scheme ":" hier-part [ "?" query ] [ "#" fragment ], each part checked against its own grammar.
func isURI(s string) bool {
	if !schemePattern.MatchString(s) {
		return false
	}
	rest := s[strings.IndexByte(s, ':')+1:]
	rest, fragment, hasFragment := strings.Cut(rest, "#")
	if hasFragment && !isPart(fragment, "/?") {
		return false
	}
	rest, query, hasQuery := strings.Cut(rest, "?")
	if hasQuery && !isPart(query, "/?") {
		return false
	}
	if after, ok := strings.CutPrefix(rest, "//"); ok {
		authority, path := after, ""
		if k := strings.IndexByte(after, '/'); k >= 0 {
			authority, path = after[:k], after[k:]
		}
		return isAuthority(authority) && isPart(path, "/")
	}
	return isPart(rest, "/")
}

// isPart checks a path, query or fragment: pchar (unreserved, pct-encoded, sub-delims, ':', '@') and
// the extra characters the part allows.
func isPart(s, extra string) bool {
	return validChars(s, ":@"+extra)
}

func isAuthority(a string) bool {
	if at := strings.LastIndexByte(a, '@'); at >= 0 {
		if !validChars(a[:at], ":") {
			return false
		}
		a = a[at+1:]
	}
	host, port := a, ""
	if strings.HasPrefix(a, "[") {
		end := strings.IndexByte(a, ']')
		if end < 0 {
			return false
		}
		host, port = a[:end+1], a[end+1:]
		if !isIPLiteral(host[1 : len(host)-1]) {
			return false
		}
	} else if k := strings.LastIndexByte(a, ':'); k >= 0 {
		host, port = a[:k], a[k:]
		if !validChars(host, "") {
			return false
		}
	} else if !validChars(host, "") {
		return false
	}
	if port != "" {
		if port[0] != ':' {
			return false
		}
		for _, c := range port[1:] {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

// isIPLiteral is the inside of "[...]": an IPv6 address without a zone, or IPvFuture.
func isIPLiteral(s string) bool {
	if strings.HasPrefix(s, "v") || strings.HasPrefix(s, "V") {
		ver, rest, ok := strings.Cut(s[1:], ".")
		if !ok || ver == "" || rest == "" {
			return false
		}
		for i := 0; i < len(ver); i++ {
			if !isHex(ver[i]) {
				return false
			}
		}
		return validChars(rest, ":") && !strings.Contains(rest, "%")
	}
	addr, err := netip.ParseAddr(s)
	return err == nil && addr.Is6() && addr.Zone() == ""
}

// validChars admits unreserved and sub-delims characters, well-formed percent escapes, and extra.
func validChars(s, extra string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '%':
			if i+2 >= len(s) || !isHex(s[i+1]) || !isHex(s[i+2]) {
				return false
			}
			i += 2
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			strings.IndexByte("-._~!$&'()*+,;=", c) >= 0, strings.IndexByte(extra, c) >= 0:
		default:
			return false
		}
	}
	return true
}

func isHex(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }

// leapSecondDays are the UTC days that ended with an inserted leap second (IERS Bulletin C; none
// since 2016, none announced). A new one would be added here when announced.
var leapSecondDays = map[string]bool{
	"1972-06-30": true, "1972-12-31": true, "1973-12-31": true, "1974-12-31": true, "1975-12-31": true,
	"1976-12-31": true, "1977-12-31": true, "1978-12-31": true, "1979-12-31": true, "1981-06-30": true,
	"1982-06-30": true, "1983-06-30": true, "1985-06-30": true, "1987-12-31": true, "1989-12-31": true,
	"1990-12-31": true, "1992-06-30": true, "1993-06-30": true, "1994-06-30": true, "1995-12-31": true,
	"1997-06-30": true, "1998-12-31": true, "2005-12-31": true, "2008-12-31": true, "2012-06-30": true,
	"2015-06-30": true, "2016-12-31": true,
}

// parseDateTime accepts RFC 3339 date-time (JSON Schema's "date-time"): 'T' and 'Z' in either case, a
// real calendar date, hours 00-23, minutes 00-59, seconds 00-59, an offset of at most 23:59, and
// second 60 only where a leap second was inserted (23:59:60 UTC on a day in leapSecondDays), read as
// the first instant of the next minute.
func parseDateTime(s string) (time.Time, bool) {
	p := dateTimePattern.FindStringSubmatch(s)
	if p == nil {
		return time.Time{}, false
	}
	num := func(i int) int { n, _ := strconv.Atoi(p[i]); return n }
	year, month, day, hour, minute, second := num(1), num(2), num(3), num(4), num(5), num(6)
	if month < 1 || month > 12 || day < 1 || day > time.Date(year, time.Month(month)+1, 0, 0, 0, 0, 0, time.UTC).Day() ||
		hour > 23 || minute > 59 || second > 60 {
		return time.Time{}, false
	}
	offset := 0
	if p[9] != "" {
		oh, om := num(9), num(10)
		if oh > 23 || om > 59 {
			return time.Time{}, false
		}
		offset = (oh*60 + om) * 60
		if p[8][0] == '-' {
			offset = -offset
		}
	}
	var nanos int
	if p[7] != "" {
		frac := (p[7][1:] + "000000000")[:9]
		nanos, _ = strconv.Atoi(frac)
	}
	leap := second == 60
	if leap {
		second = 59
	}
	t := time.Date(year, time.Month(month), day, hour, minute, second, nanos, time.FixedZone("", offset)).UTC()
	if leap {
		// A leap second is 23:59:60 UTC on a day one was inserted.
		if t.Hour() != 23 || t.Minute() != 59 || !leapSecondDays[t.Format(time.DateOnly)] {
			return time.Time{}, false
		}
		t = t.Add(time.Second)
	}
	return t, true
}
