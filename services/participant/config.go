package participant

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	defaultAddress        = ":8085"
	defaultRequestTimeout = 5 * time.Second
	// serverTimeoutMargin keeps the inbound server deadlines strictly longer
	// than the outbound request deadline, so a timed-out upstream call can
	// still be reported to the caller as an "unavailable" result.
	serverTimeoutMargin = 5 * time.Second
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
	case "http-sample":
		if err := validateResourceURL(cfg.ResourceURL); err != nil {
			return Config{}, err
		}
	default:
		return Config{}, fmt.Errorf("PARTICIPANT_ADAPTER_MODE %q is unavailable; supported modes are sample and http-sample", cfg.AdapterMode)
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
		return fmt.Errorf("PARTICIPANT_RESOURCE_URL is required for http-sample mode")
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
