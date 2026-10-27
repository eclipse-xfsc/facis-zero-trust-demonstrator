package server

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/meshcaller"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/transit"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/acquire"
)

// Config is the service's configuration surface. The command line and the environment fill it;
// Validate decides whether the service can run with it.
type Config struct {
	// Addr is the API listener, the address the store's callers reach it at.
	Addr string
	// OpsAddr is the plain-HTTP listener the kubelet probes: /healthz and /readyz.
	OpsAddr string
	// DatabaseURL is the PostgreSQL connection URL. It is a credential and is never logged.
	DatabaseURL string
	// OpenBaoURL is the key-value store's URL, scheme and host only.
	OpenBaoURL string
	// ReadinessTimeout is the budget of one /readyz evaluation; a dependency that does not answer
	// within it is not reachable.
	ReadinessTimeout time.Duration
	// DrainDelay is how long a stopping service keeps its listeners open while /readyz already
	// answers 503: the time the endpoints controller needs to stop routing to the pod.
	DrainDelay time.Duration
	// ShutdownTimeout is how long a stopping service then drains its listeners before it exits.
	ShutdownTimeout time.Duration
	// ReplayCallers are the SPIFFE IDs allowed to call /internal/replay-check (the connector and
	// the guard). With none, every call to it is refused.
	ReplayCallers []string
	// Callers authenticates the store's internal callers. Nil means the forwarded client certificate
	// (meshcaller.XFCC) checked against the allow-lists above and the substitution routes' callers;
	// tests inject their own.
	Callers meshcaller.Authenticator
	// Acquisition is the routes file (--acquire-config): the routes /internal/substitute authorizes
	// and acquires tokens for. Nil refuses every substitution meshcaller.
	Acquisition *acquire.Loaded
	// OpenBao signs the store's proofs and holds the upstream token values; required with
	// Acquisition.
	OpenBao OpenBao
	// Instance names this replica in renewal claims (the pod's name); empty means a random name.
	Instance string
}

// OpenBao is the key-value store as the store uses it: transit signing and KV v2.
type OpenBao interface {
	transit.Signer
	LatestKey(context.Context, string) (transit.KeyVersion, error)
	transit.Secrets
}

// Validate reports the first thing the service cannot run with.
func (c Config) Validate() error {
	if c.Addr == "" {
		return errors.New("the API listener needs an address")
	}
	if c.OpsAddr == "" {
		return errors.New("the ops listener needs an address")
	}
	if c.DatabaseURL == "" {
		return errors.New("no database connection URL")
	}
	if err := validateBaseURL(c.OpenBaoURL); err != nil {
		return err
	}
	if c.ReadinessTimeout <= 0 {
		return errors.New("the readiness timeout must be longer than 0")
	}
	if c.DrainDelay < 0 {
		return errors.New("the drain delay cannot be negative")
	}
	if c.ShutdownTimeout <= 0 {
		return errors.New("the shutdown timeout must be longer than 0")
	}
	if _, err := meshcaller.NewXFCC(c.ReplayCallers); err != nil {
		return errors.New("the replay-check callers must be spiffe:// IDs")
	}
	if c.Acquisition != nil && c.OpenBao == nil {
		return errors.New("substitution needs the key-value store's token")
	}
	return nil
}

// validateBaseURL accepts http(s)://host[:port], with at most a trailing slash: the key-value
// store's address is a base the store appends its paths to, never a path, a query or a user.
func validateBaseURL(raw string) error {
	const want = "the key-value store URL must be http(s)://host[:port], nothing more"
	if raw == "" {
		return errors.New("no key-value store URL")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New(want)
	}
	// A bare "?" or "#" parses to an empty query or fragment and would still corrupt the paths
	// appended to the base, so the characters themselves are refused.
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
		strings.Trim(u.Path, "/") != "" || u.Opaque != "" || strings.ContainsAny(raw, "?#") {
		return errors.New(want)
	}
	return nil
}
