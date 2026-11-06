package caller

import (
	"errors"
	"net/url"
	"slices"
	"strings"
)

// Routes is the configured Router: a request is authorized when one route lists the caller and
// matches its peer zone, audience, tenant, method and target. It reads nothing but its own
// configuration, so it can run before any database read or signing.
type Routes []Route

var _ Router = Routes(nil)

// Methods a route may allow: the contract's enum.
var methods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}

// NewRoutes validates rs: every route has callers (SPIFFE IDs), a peer zone, an audience, methods
// from the contract's set and a target prefix in the canonical form Target accepts.
func NewRoutes(rs []Route) (Routes, error) {
	for _, r := range rs {
		if len(r.Callers) == 0 || r.PeerZone == "" || r.Audience == "" || len(r.Methods) == 0 {
			return nil, errors.New("caller: a route needs callers, peer_zone, audience and methods")
		}
		for _, id := range r.Callers {
			if !isSPIFFEID(id) {
				return nil, errors.New("caller: route callers must be spiffe:// IDs")
			}
		}
		for _, m := range r.Methods {
			if !slices.Contains(methods, m) {
				return nil, errors.New("caller: route methods must be GET, HEAD, POST, PUT, PATCH or DELETE")
			}
		}
		if _, _, err := Target(r.TargetPrefix); err != nil || strings.ContainsAny(r.TargetPrefix, "?") {
			return nil, errors.New("caller: target_prefix must be a canonical absolute http(s) URI without query")
		}
	}
	return slices.Clone(Routes(rs)), nil
}

// Callers is every SPIFFE ID some route admits.
func (rs Routes) Callers() []string {
	var out []string
	for _, r := range rs {
		for _, id := range r.Callers {
			if !slices.Contains(out, id) {
				out = append(out, id)
			}
		}
	}
	return out
}

// Admits reports whether some route lists c: a caller no route lists is refused before its body is
// read.
func (rs Routes) Admits(c Caller) bool {
	return c.SPIFFEID != "" && slices.Contains(rs.Callers(), c.SPIFFEID)
}

// Authorize returns the first route that lists c and matches req. ErrCallerDenied when no route
// lists c, ErrRouteDenied when none that lists c matches.
func (rs Routes) Authorize(c Caller, req Request) (Route, error) {
	if !rs.Admits(c) {
		return Route{}, ErrCallerDenied
	}
	origin, path, err := Target(req.TargetURI)
	if err != nil {
		return Route{}, ErrRouteDenied
	}
	for _, r := range rs {
		if !slices.Contains(r.Callers, c.SPIFFEID) || r.PeerZone != req.PeerZone || r.Audience != req.Audience ||
			r.Tenant != req.Tenant || !slices.Contains(r.Methods, req.Method) {
			continue
		}
		pOrigin, pPath, _ := Target(r.TargetPrefix)
		if origin == pOrigin && underPrefix(path, pPath) {
			return r, nil
		}
	}
	return Route{}, ErrRouteDenied
}

// underPrefix is a match on whole path segments: /v1 covers /v1 and /v1/x, never /v10; /v1/
// covers /v1/ and below.
func underPrefix(path, prefix string) bool {
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	return len(path) == len(prefix) || strings.HasSuffix(prefix, "/") || path[len(prefix)] == '/'
}

// Target checks that raw is an absolute http(s) URI already in the one form the store compares and
// signs, and returns its origin (scheme://host[:port]) and escaped path. It refuses rather than
// normalises: a lowercase scheme and host, no userinfo or fragment, no default port, a path that is
// empty or starts with "/", no path segment that is or could be read as a dot segment (".", "..",
// their percent-encoded forms, with or without ";" parameters), no encoded "/" or "\", no "\", and
// nothing that a parse and re-serialisation would change. What is left can only name a resource
// under a prefix it textually starts with. A query is allowed and is not part of the comparison (nor
// of a DPoP proof's htu).
func Target(raw string) (origin, path string, err error) {
	bad := errors.New("caller: target is not a canonical absolute http(s) URI")
	u, perr := url.Parse(raw)
	if perr != nil || (u.Scheme != "http" && u.Scheme != "https") || !strings.HasPrefix(raw, u.Scheme+"://") ||
		u.User != nil || u.Opaque != "" || u.Host == "" || u.Host != strings.ToLower(u.Host) ||
		strings.ContainsAny(raw, "#\\") || u.Hostname() == "" || u.String() != raw {
		return "", "", bad
	}
	if p := u.Port(); (u.Scheme == "http" && p == "80") || (u.Scheme == "https" && p == "443") || strings.HasSuffix(u.Host, ":") {
		return "", "", bad
	}
	path = u.EscapedPath()
	if path != "" && path[0] != '/' {
		return "", "", bad
	}
	lower := strings.ToLower(path)
	if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") {
		return "", "", bad
	}
	for _, seg := range strings.Split(lower, "/") {
		seg, _, _ = strings.Cut(seg, ";")
		seg = strings.ReplaceAll(seg, "%2e", ".")
		if seg == "." || seg == ".." {
			return "", "", bad
		}
	}
	if path == "" {
		path = "/"
	}
	return u.Scheme + "://" + u.Host, path, nil
}
