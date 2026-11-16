package caller

import (
	"errors"
	"net/http"
	"slices"
	"strings"
)

// headerXFCC is the header the store's sidecar sets from the client certificate it verified.
const headerXFCC = "X-Forwarded-Client-Cert"

// XFCC authenticates the caller by the client certificate the store's own sidecar verified and
// forwarded. It is sound only where that sidecar replaces any X-Forwarded-Client-Cert the client sent
// (SANITIZE_SET, set on the store's pod) and the API port is reachable only through it; the
// deployment owes both. As a second line it accepts exactly one element across every header field:
// a client-supplied value next to the sidecar's, what APPEND_FORWARD would produce, is refused.
type XFCC struct {
	allowed []string
}

var _ Authenticator = (*XFCC)(nil)

// NewXFCC returns an authenticator admitting the given SPIFFE IDs. With none, every call is denied.
func NewXFCC(allowed []string) (*XFCC, error) {
	for _, id := range allowed {
		if !isSPIFFEID(id) {
			return nil, errors.New("caller: allow-list entries must be spiffe:// IDs")
		}
	}
	return &XFCC{allowed: slices.Clone(allowed)}, nil
}

// Authenticate returns the caller named by the single forwarded certificate, if it is allowed.
func (a *XFCC) Authenticate(r *http.Request) (Caller, error) {
	var elements []map[string][]string
	for _, field := range r.Header.Values(headerXFCC) {
		parsed, err := ParseXFCC(field)
		if err != nil {
			return Caller{}, ErrCallerDenied
		}
		elements = append(elements, parsed...)
	}
	if len(elements) != 1 {
		return Caller{}, ErrCallerDenied
	}
	uris := elements[0]["uri"]
	if len(uris) != 1 || !isSPIFFEID(uris[0]) || !slices.Contains(a.allowed, uris[0]) {
		return Caller{}, ErrCallerDenied
	}
	return Caller{SPIFFEID: uris[0]}, nil
}

// ParseXFCC splits one X-Forwarded-Client-Cert field into its elements (comma-separated), each a set
// of key=value pairs (semicolon-separated) with keys lower-cased. Values may be double-quoted, with
// backslash escapes, and then contain commas, semicolons and equals signs. Anything else malformed
// is an error rather than a best guess.
func ParseXFCC(field string) ([]map[string][]string, error) {
	var (
		elements []map[string][]string
		current  = map[string][]string{}
		key      strings.Builder
		value    strings.Builder
		inValue  bool
		quoted   bool
		closed   bool // a quoted value ended; only a separator may follow
	)
	errMalformed := errors.New("caller: malformed X-Forwarded-Client-Cert")
	flushPair := func() error {
		k := strings.ToLower(strings.TrimSpace(key.String()))
		if k == "" || !inValue {
			return errMalformed
		}
		v := value.String()
		if !closed {
			v = strings.TrimSpace(v)
		}
		current[k] = append(current[k], v)
		key.Reset()
		value.Reset()
		inValue, closed = false, false
		return nil
	}
	for i := 0; i < len(field); i++ {
		c := field[i]
		if c < 0x20 || c == 0x7f {
			return nil, errMalformed
		}
		switch {
		case quoted:
			switch c {
			case '\\':
				if i+1 >= len(field) || field[i+1] < 0x20 || field[i+1] == 0x7f {
					return nil, errMalformed
				}
				i++
				value.WriteByte(field[i])
			case '"':
				quoted, closed = false, true
			default:
				value.WriteByte(c)
			}
		case c == ';' || c == ',':
			if err := flushPair(); err != nil {
				return nil, err
			}
			if c == ',' {
				elements = append(elements, current)
				current = map[string][]string{}
			}
		case closed:
			if c != ' ' {
				return nil, errMalformed
			}
		case !inValue && c == '=':
			inValue = true
		case !inValue:
			if !isKeyByte(c) {
				return nil, errMalformed
			}
			key.WriteByte(c)
		case c == '"' && strings.TrimSpace(value.String()) == "":
			value.Reset()
			quoted = true
		case c == '"' || c == '=':
			return nil, errMalformed
		default:
			value.WriteByte(c)
		}
	}
	if quoted {
		return nil, errMalformed
	}
	if err := flushPair(); err != nil {
		return nil, err
	}
	return append(elements, current), nil
}

// isKeyByte admits what Envoy's keys are made of (By, Hash, Cert, Chain, Subject, URI, DNS), and
// the spaces around them.
func isKeyByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == ' '
}

func isSPIFFEID(s string) bool {
	rest, ok := strings.CutPrefix(s, "spiffe://")
	if !ok || rest == "" || strings.ContainsAny(s, " \t\r\n\"\\,;?#") {
		return false
	}
	domain, path, _ := strings.Cut(rest, "/")
	return domain != "" && path != ""
}
