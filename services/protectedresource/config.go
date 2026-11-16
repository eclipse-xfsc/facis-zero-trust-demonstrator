package protectedresource

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/replay"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/tokenverify"
)

const (
	defaultAddress        = ":8086"
	defaultRequestTimeout = 5 * time.Second
	serverTimeoutMargin   = 5 * time.Second

	// ModeSample serves the scenario-driven sample without authentication; ModeToken serves /demo behind
	// the injected RequestVerifier and picks the response by token scope.
	ModeSample = "sample"
	ModeToken  = "token"
)

type Config struct {
	Address        string
	RequestTimeout time.Duration
	SlowDelay      time.Duration
	Mode           string
	AdapterMode    string
	LogLevel       string
	// Verifier, when set, selects token mode. LoadConfig sets it, to a tokenverify.Verifier, only for
	// PROTECTED_RESOURCE_MODE=token.
	Verifier tokenverify.RequestVerifier
}

// ServingMode is ModeToken when a Verifier is configured and ModeSample otherwise.
func (c Config) ServingMode() string {
	if c.Verifier != nil {
		return ModeToken
	}
	return ModeSample
}

func (c Config) ServerReadTimeout() time.Duration {
	return c.RequestTimeout + serverTimeoutMargin
}

func (c Config) ServerWriteTimeout() time.Duration {
	return c.RequestTimeout + serverTimeoutMargin
}

func LoadConfig() (Config, error) {
	cfg := Config{
		Address:        envOrDefault("PROTECTED_RESOURCE_ADDRESS", defaultAddress),
		RequestTimeout: defaultRequestTimeout,
		SlowDelay:      2 * time.Second,
		Mode:           strings.ToLower(envOrDefault("PROTECTED_RESOURCE_MODE", "sample")),
		AdapterMode:    strings.ToLower(envOrDefault("PROTECTED_RESOURCE_ADAPTER_MODE", "sample")),
		LogLevel:       strings.ToLower(envOrDefault("PROTECTED_RESOURCE_LOG_LEVEL", "info")),
	}

	var err error
	if cfg.RequestTimeout, err = durationFromEnv("PROTECTED_RESOURCE_REQUEST_TIMEOUT", cfg.RequestTimeout); err != nil {
		return Config{}, err
	}
	if cfg.SlowDelay, err = durationFromEnv("PROTECTED_RESOURCE_SLOW_DELAY", cfg.SlowDelay); err != nil {
		return Config{}, err
	}
	if cfg.SlowDelay >= cfg.RequestTimeout {
		return Config{}, fmt.Errorf("PROTECTED_RESOURCE_SLOW_DELAY must be shorter than PROTECTED_RESOURCE_REQUEST_TIMEOUT")
	}
	switch cfg.Mode {
	case ModeSample:
	case ModeToken:
		if cfg.Verifier, err = verifierFromEnv(); err != nil {
			return Config{}, err
		}
	default:
		return Config{}, fmt.Errorf("PROTECTED_RESOURCE_MODE %q is unavailable; supported modes are sample and token", cfg.Mode)
	}
	switch cfg.AdapterMode {
	case "sample", "sample-alternative":
	default:
		return Config{}, fmt.Errorf("PROTECTED_RESOURCE_ADAPTER_MODE %q is unavailable; supported modes are sample and sample-alternative", cfg.AdapterMode)
	}
	switch cfg.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return Config{}, fmt.Errorf("PROTECTED_RESOURCE_LOG_LEVEL must be debug, info, warn, or error")
	}
	return cfg, nil
}

func durationFromEnv(name string, fallback time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%s must be a positive Go duration", name)
	}
	return value, nil
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

// verifierFromEnv builds the token verifier of PROTECTED_RESOURCE_MODE=token. It requires no scope
// itself: the scope table picks the answer, and refuses a token with neither scope (403).
//
// The replay record is the Resource's own, in memory (replay.Memory), not the zone's shared proof_jti
// table: a proof names this Resource in htu, so only this Resource can be presented with it, and the
// Resource needs no database. A restart loses the record, which re-opens at most one proof window
// (120 s) for proofs presented before it; run one replica, since replicas do not share the record.
func verifierFromEnv() (*tokenverify.Verifier, error) {
	get := func(name string) string { return strings.TrimSpace(os.Getenv(name)) }
	for _, name := range []string{"PROTECTED_RESOURCE_TOKEN_ISSUER", "PROTECTED_RESOURCE_JWKS_URL",
		"PROTECTED_RESOURCE_AUDIENCE", "PROTECTED_RESOURCE_PUBLIC_BASE_URL"} {
		if get(name) == "" {
			return nil, fmt.Errorf("%s is required for token mode", name)
		}
	}
	v, err := tokenverify.New(tokenverify.Config{
		Issuer: get("PROTECTED_RESOURCE_TOKEN_ISSUER"), JWKSURL: get("PROTECTED_RESOURCE_JWKS_URL"),
		Audience: get("PROTECTED_RESOURCE_AUDIENCE"), PublicBaseURL: get("PROTECTED_RESOURCE_PUBLIC_BASE_URL"),
		Replay: replay.NewMemory(),
	})
	if err != nil {
		return nil, fmt.Errorf("token mode configuration rejected: %w", err)
	}
	return v, nil
}
