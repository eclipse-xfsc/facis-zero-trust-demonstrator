package protectedresource

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const (
	cloudMode = "cloud-api"
	// The provider's documented base URL and its read-only list operation (GET /datacenters).
	defaultCloudAPIURL = "https://api.ionos.com/cloudapi/v6"
	cloudListPath      = "/datacenters?depth=0&limit=100"

	// ReasonInterfaceRejected is the configuration-time refusal of an API that does not answer as the
	// documented interface; the log record carries the request-time reason as its cause.
	ReasonInterfaceRejected = "CLOUD_INTERFACE_REJECTED"
)

// CloudAdapter answers the Resource's read contract from a bounded, read-only cloud inventory page.
// Its one upstream call is fixed; only the API's base URL is configuration.
type CloudAdapter struct {
	tokenFile string
	endpoint  string
	success   string
	client    *http.Client
}

func newCloudAdapter(c Config) *CloudAdapter {
	success := ReasonSuccess
	if c.Verifier != nil {
		success = ReasonReportReturned
	}
	return &CloudAdapter{tokenFile: c.CloudTokenFile, endpoint: c.CloudAPIURL + cloudListPath, success: success, client: &http.Client{
		Timeout:       c.RequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{RootCAs: c.CloudRootCAs, MinVersion: tls.VersionTLS12}},
	}}
}

// cloudSettingsFromEnv reads the cloud adapter's settings: the mounted token file, the API base URL
// (HTTPS only) and, for an API behind a private CA, its certificate bundle.
func cloudSettingsFromEnv(cfg *Config) error {
	cfg.CloudTokenFile = strings.TrimSpace(os.Getenv("PROTECTED_RESOURCE_CLOUD_TOKEN_FILE"))
	if _, err := readCloudToken(cfg.CloudTokenFile); err != nil {
		return err
	}
	cfg.CloudAPIURL = strings.TrimRight(envOrDefault("PROTECTED_RESOURCE_CLOUD_API_URL", defaultCloudAPIURL), "/")
	base, err := url.Parse(cfg.CloudAPIURL)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return errors.New("PROTECTED_RESOURCE_CLOUD_API_URL must be an absolute HTTPS URL without credentials, query or fragment")
	}
	if path := strings.TrimSpace(os.Getenv("PROTECTED_RESOURCE_CLOUD_CA_FILE")); path != "" {
		pem, err := os.ReadFile(path)
		cfg.CloudRootCAs = x509.NewCertPool()
		if err != nil || !cfg.CloudRootCAs.AppendCertsFromPEM(pem) {
			return errors.New("PROTECTED_RESOURCE_CLOUD_CA_FILE must name a PEM certificate bundle")
		}
	}
	return nil
}

func readCloudToken(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", errors.New("CLOUD_CREDENTIAL_INVALID")
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 16384 {
		return "", errors.New("CLOUD_CREDENTIAL_INVALID")
	}
	b, err := io.ReadAll(io.LimitReader(f, 16385))
	token := strings.TrimSpace(string(b))
	if err != nil || len(b) > 16384 || token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", errors.New("CLOUD_CREDENTIAL_INVALID")
	}
	for _, c := range token {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', strings.ContainsRune("-._~+/=", c):
		default:
			return "", errors.New("CLOUD_CREDENTIAL_INVALID")
		}
	}
	return token, nil
}

func cloudFailure(outcome Outcome, reason string) ResourceResult {
	return ResourceResult{Outcome: outcome, ReasonCode: reason, Explanation: "Cloud inventory request did not succeed.", SafeData: emptySafeData()}
}

// list reads the first inventory page and counts its data centers. A failure is a fixed outcome and
// reason; nothing the provider sent leaves this function.
func (a *CloudAdapter) list(ctx context.Context) (int, Outcome, string) {
	token, err := readCloudToken(a.tokenFile)
	if err != nil {
		return 0, OutcomeUnavailable, "CLOUD_CREDENTIAL_INVALID"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.endpoint, nil)
	if err != nil {
		return 0, OutcomeUnavailable, "CLOUD_REQUEST_FAILED"
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return 0, OutcomeUnavailable, "CLOUD_REQUEST_FAILED"
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return 0, OutcomeDenied, "CLOUD_ACCESS_DENIED"
	}
	if resp.StatusCode != http.StatusOK {
		return 0, OutcomeUnavailable, "CLOUD_UPSTREAM_UNAVAILABLE"
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1048577))
	var collection struct {
		Type  string `json:"type"`
		Items []struct {
			Type string `json:"type"`
		} `json:"items"`
	}
	if err != nil || len(body) > 1048576 || json.Unmarshal(body, &collection) != nil || collection.Type != "collection" || collection.Items == nil {
		return 0, OutcomeUnavailable, "CLOUD_RESPONSE_INVALID"
	}
	for _, item := range collection.Items {
		if item.Type != "datacenter" {
			return 0, OutcomeUnavailable, "CLOUD_RESPONSE_INVALID"
		}
	}
	return len(collection.Items), OutcomeSuccess, ""
}

func (a *CloudAdapter) Request(ctx context.Context, input ResourceRequest) (ResourceResult, error) {
	if input.Resource != "sample-report" || input.Action != "read" {
		return ResourceResult{}, ErrResourceNotFound
	}
	if input.Scenario != "" && input.Scenario != "success" {
		return cloudFailure(OutcomeDenied, "CLOUD_SCENARIO_REFUSED"), nil
	}
	count, outcome, reason := a.list(ctx)
	if outcome != OutcomeSuccess {
		return cloudFailure(outcome, reason), nil
	}
	// The documented success shape, so the caller's contract check is unchanged. Only the count is the
	// provider's: no provider-controlled string, identifier or metadata leaves this boundary.
	return ResourceResult{Outcome: OutcomeSuccess, ReasonCode: a.success,
		Explanation: "Read-only cloud inventory page returned (maximum 100 data centers).",
		SafeData: map[string]any{"resource": "sample-report", "action": "read", "report": map[string]any{
			"id": "CLOUD-DATACENTERS", "title": "Cloud data centers",
			"content": fmt.Sprintf("%d data centers on the first inventory page of at most 100.", count),
		}}}, nil
}

// CheckInterface is the configuration-time check of a docked API, run before the Resource serves: the
// cloud adapter makes its one read-only call and the Resource refuses to start unless the answer is
// the documented interface. The refusal is logged with ReasonInterfaceRejected and its cause. The
// sample adapters have no remote interface and pass.
func CheckInterface(ctx context.Context, config Config, adapter ResourceAdapter, logger *slog.Logger) error {
	cloud, ok := adapter.(*CloudAdapter)
	if !ok {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, config.RequestTimeout)
	defer cancel()
	if _, _, cause := cloud.list(ctx); cause != "" {
		logger.LogAttrs(ctx, slog.LevelError, "protected resource configuration rejected",
			slog.String("adapter", cloudMode), slog.String("reasonCode", ReasonInterfaceRejected), slog.String("cause", cause))
		return fmt.Errorf("%s: %s", ReasonInterfaceRejected, cause)
	}
	return nil
}

var _ ResourceAdapter = (*CloudAdapter)(nil)
