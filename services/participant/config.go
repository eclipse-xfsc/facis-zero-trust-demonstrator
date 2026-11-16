package participant

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03/if03fixture"
)

const (
	defaultAddress        = ":8085"
	defaultRequestTimeout = 5 * time.Second
	// serverTimeoutMargin keeps the inbound server deadlines strictly longer
	// than the outbound request deadline, so a timed-out upstream call can
	// still be reported to the caller as an "unavailable" result.
	serverTimeoutMargin = 5 * time.Second

	// ModeSample keeps the scenario-driven sample adapters; ModeToken runs the injected Bootstrapper and
	// calls the Resource with the TokenSession's Authorization and DPoP headers.
	ModeSample = "sample"
	ModeToken  = "token"
)

// ServerReadTimeout bounds reading an inbound demo request.
func (c Config) ServerReadTimeout() time.Duration {
	return c.RequestTimeout + serverTimeoutMargin
}

// ServerWriteTimeout covers the full outbound request deadline plus time to
// write the JSON result.
func (c Config) ServerWriteTimeout() time.Duration {
	return c.RequestTimeout + serverTimeoutMargin
}

type Config struct {
	Address        string
	RequestTimeout time.Duration
	AdapterMode    string
	ResourceURL    string
	LogLevel       string

	// Bootstrapper, when set, selects token mode (ResourceURL is then the Resource base URL). LoadConfig
	// sets it, to a ConnectorBootstrap, only for PARTICIPANT_ADAPTER_MODE=token.
	Bootstrapper Bootstrapper
	// BootstrapAttempts bounds retries of a connector-unreachable bootstrap (default 3);
	// BootstrapBackoff is the first wait, doubled per retry (default 500ms).
	BootstrapAttempts int
	BootstrapBackoff  time.Duration
}

// ServingMode is ModeToken when a Bootstrapper is configured and ModeSample otherwise.
func (c Config) ServingMode() string {
	if c.Bootstrapper != nil {
		return ModeToken
	}
	return ModeSample
}

func LoadConfig() (Config, error) {
	cfg := Config{
		Address:        envOrDefault("PARTICIPANT_ADDRESS", defaultAddress),
		RequestTimeout: defaultRequestTimeout,
		AdapterMode:    strings.ToLower(envOrDefault("PARTICIPANT_ADAPTER_MODE", "sample")),
		ResourceURL:    strings.TrimSpace(os.Getenv("PARTICIPANT_RESOURCE_URL")),
		LogLevel:       strings.ToLower(envOrDefault("PARTICIPANT_LOG_LEVEL", "info")),
	}

	if raw := strings.TrimSpace(os.Getenv("PARTICIPANT_REQUEST_TIMEOUT")); raw != "" {
		timeout, err := time.ParseDuration(raw)
		if err != nil || timeout <= 0 {
			return Config{}, fmt.Errorf("PARTICIPANT_REQUEST_TIMEOUT must be a positive Go duration")
		}
		cfg.RequestTimeout = timeout
	}

	switch cfg.AdapterMode {
	case "sample":
	case "http-sample", ModeToken:
		if err := validateResourceURL(cfg.ResourceURL); err != nil {
			return Config{}, err
		}
	default:
		return Config{}, fmt.Errorf("PARTICIPANT_ADAPTER_MODE %q is unavailable; supported modes are sample, http-sample and token", cfg.AdapterMode)
	}
	if cfg.AdapterMode == ModeToken {
		boot, err := tokenBootstrapFromEnv()
		if err != nil {
			return Config{}, err
		}
		cfg.Bootstrapper = boot
	}

	switch cfg.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return Config{}, fmt.Errorf("PARTICIPANT_LOG_LEVEL must be debug, info, warn, or error")
	}

	return cfg, nil
}

func validateResourceURL(raw string) error {
	if raw == "" {
		return fmt.Errorf("PARTICIPANT_RESOURCE_URL is required for http-sample and token mode")
	}
	destination, err := url.Parse(raw)
	if err != nil || destination.Host == "" || (destination.Scheme != "http" && destination.Scheme != "https") {
		return fmt.Errorf("PARTICIPANT_RESOURCE_URL must be an absolute HTTP or HTTPS URL")
	}
	if destination.User != nil || destination.RawQuery != "" || destination.Fragment != "" {
		return fmt.Errorf("PARTICIPANT_RESOURCE_URL must not contain credentials, a query, or a fragment")
	}
	return nil
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

// tokenBootstrapFromEnv builds the ConnectorBootstrap of PARTICIPANT_ADAPTER_MODE=token. Every setting
// is required except the entitlement; the outcome signer's key file is read now, the credentials file
// on every bootstrap run. Errors name the variable, never a file's content.
func tokenBootstrapFromEnv() (*ConnectorBootstrap, error) {
	get := func(name string) string { return strings.TrimSpace(os.Getenv(name)) }
	for _, name := range []string{"PARTICIPANT_CONNECTOR_URL", "PARTICIPANT_CREDENTIALS_FILE", "PARTICIPANT_AUDIENCE",
		"PARTICIPANT_OUTCOME_ISSUER", "PARTICIPANT_OUTCOME_KID", "PARTICIPANT_OUTCOME_KEY_FILE", "PARTICIPANT_OUTCOME_ROLE"} {
		if get(name) == "" {
			return nil, fmt.Errorf("%s is required for token mode", name)
		}
	}
	key, err := if03fixture.ReadPrivateKey(get("PARTICIPANT_OUTCOME_KEY_FILE"))
	if err != nil {
		return nil, fmt.Errorf("PARTICIPANT_OUTCOME_KEY_FILE must name a PEM P-256 private key")
	}
	outcomes := if03fixture.Fixture{Issuer: get("PARTICIPANT_OUTCOME_ISSUER"), Kid: get("PARTICIPANT_OUTCOME_KID"), Key: key,
		Claims: if03.Claims{Role: get("PARTICIPANT_OUTCOME_ROLE"), Entitlement: get("PARTICIPANT_OUTCOME_ENTITLEMENT")}}
	boot, err := NewConnectorBootstrap(get("PARTICIPANT_CONNECTOR_URL"), get("PARTICIPANT_CREDENTIALS_FILE"), get("PARTICIPANT_AUDIENCE"), outcomes, nil)
	if err != nil {
		return nil, fmt.Errorf("PARTICIPANT_CONNECTOR_URL: %w", err)
	}
	return boot, nil
}
