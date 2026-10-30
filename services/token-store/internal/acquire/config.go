package acquire

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/connectorclient"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03/if03fixture"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/caller"
)

// Config is the acquisition configuration file (JSON). It holds file paths, never secrets.
type Config struct {
	// SigningKey is the store's transit key name (D9).
	SigningKey string `json:"signing_key"`
	// TrustedIssuers are the IF-03 issuers whose outcomes the store accepts: the peer's verifier keys.
	TrustedIssuers []struct {
		Issuer        string `json:"issuer"`
		Kid           string `json:"kid"`
		PublicKeyFile string `json:"public_key_file"` // PEM "PUBLIC KEY", P-256
	} `json:"trusted_issuers"`
	Routes []struct {
		Name             string `json:"name"`
		PeerZone         string `json:"peer_zone"`
		Audience         string `json:"audience"`
		Tenant           string `json:"tenant"`
		ConnectorURL     string `json:"connector_url"`
		ClientID         string `json:"client_id"`
		ClientSecretFile string `json:"client_secret_file"`
		// Callers, Methods and TargetPrefix make the route substitutable (D7): the SPIFFE IDs
		// allowed to call /internal/substitute for it, the methods and the target URIs under the
		// prefix. A route without callers is acquired by the command line only.
		Callers      []string `json:"callers"`
		Methods      []string `json:"methods"`
		TargetPrefix string   `json:"target_prefix"`
		// FixtureOutcomes makes the route's outcomes come from a fixture signer (tests, demo).
		FixtureOutcomes *struct {
			Issuer          string `json:"issuer"`
			Kid             string `json:"kid"`
			PrivateKeyFile  string `json:"private_key_file"` // PEM "EC PRIVATE KEY" or "PRIVATE KEY", P-256
			Role            string `json:"role"`
			Entitlement     string `json:"entitlement"`
			ValiditySeconds int    `json:"validity_seconds"`
		} `json:"fixture_outcomes"`
	} `json:"routes"`
}

// Loaded is a validated Config with its keys read.
type Loaded struct {
	SigningKey string
	Trusted    if03.Issuers
	Routes     map[string]Route
	// Substitution authorizes /internal/substitute: one caller.Route per route with callers.
	Substitution caller.Routes
}

// For is the route of (peer zone, audience, tenant); a route key names at most one route.
func (l Loaded) For(peerZone, audience, tenant string) (Route, bool) {
	for _, r := range l.Routes {
		if r.PeerZone == peerZone && r.Audience == audience && r.Tenant == tenant {
			return r, true
		}
	}
	return Route{}, false
}

// LoadConfig reads and validates the configuration file. Errors name the field, never a file's
// content.
func LoadConfig(path string) (Loaded, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Loaded{}, fmt.Errorf("acquisition config: %w", err)
	}
	var c Config
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Loaded{}, fmt.Errorf("acquisition config: %w", err)
	}
	if c.SigningKey == "" {
		return Loaded{}, errors.New("acquisition config: signing_key is required")
	}
	out := Loaded{SigningKey: c.SigningKey, Trusted: if03.Issuers{}, Routes: map[string]Route{}}
	for _, ti := range c.TrustedIssuers {
		pub, err := readPublicKey(ti.PublicKeyFile)
		if ti.Issuer == "" || ti.Kid == "" || err != nil {
			return Loaded{}, fmt.Errorf("acquisition config: trusted issuer %q: issuer, kid and a P-256 public_key_file are required", ti.Issuer)
		}
		if out.Trusted[ti.Issuer] == nil {
			out.Trusted[ti.Issuer] = map[string]*ecdsa.PublicKey{}
		}
		out.Trusted[ti.Issuer][ti.Kid] = pub
	}
	if len(out.Trusted) == 0 {
		return Loaded{}, errors.New("acquisition config: at least one trusted issuer is required")
	}
	for _, r := range c.Routes {
		if r.Name == "" || r.PeerZone == "" || r.Audience == "" || r.ClientID == "" || r.ClientSecretFile == "" {
			return Loaded{}, fmt.Errorf("acquisition config: route %q: name, peer_zone, audience, client_id and client_secret_file are required", r.Name)
		}
		if _, err := connectorclient.BaseURL(r.ConnectorURL); err != nil {
			return Loaded{}, fmt.Errorf("acquisition config: route %q: connector_url must be an absolute http(s) URL", r.Name)
		}
		if _, dup := out.Routes[r.Name]; dup {
			return Loaded{}, fmt.Errorf("acquisition config: route %q defined twice", r.Name)
		}
		if _, dup := out.For(r.PeerZone, r.Audience, r.Tenant); dup {
			return Loaded{}, fmt.Errorf("acquisition config: route %q: another route has the same peer_zone, audience and tenant", r.Name)
		}
		if len(r.Callers) > 0 {
			out.Substitution = append(out.Substitution, caller.Route{Callers: r.Callers, PeerZone: r.PeerZone,
				Audience: r.Audience, Tenant: r.Tenant, Methods: r.Methods, TargetPrefix: r.TargetPrefix})
			if _, err := caller.NewRoutes(out.Substitution[len(out.Substitution)-1:]); err != nil {
				return Loaded{}, fmt.Errorf("acquisition config: route %q: %w", r.Name, err)
			}
		} else if len(r.Methods) > 0 || r.TargetPrefix != "" {
			return Loaded{}, fmt.Errorf("acquisition config: route %q: methods and target_prefix need callers", r.Name)
		}
		route := Route{Name: r.Name, PeerZone: r.PeerZone, Audience: r.Audience, Tenant: r.Tenant,
			ConnectorURL: r.ConnectorURL, ClientID: r.ClientID, ClientSecretFile: r.ClientSecretFile}
		if f := r.FixtureOutcomes; f != nil {
			key, err := if03fixture.ReadPrivateKey(f.PrivateKeyFile)
			if err != nil || f.Issuer == "" || f.Kid == "" || f.Role == "" {
				return Loaded{}, fmt.Errorf("acquisition config: route %q: fixture_outcomes needs issuer, kid, role and a P-256 private_key_file", r.Name)
			}
			v := time.Duration(f.ValiditySeconds) * time.Second
			if v != 0 && (v < 60*time.Second || v > 120*time.Second) {
				return Loaded{}, fmt.Errorf("acquisition config: route %q: validity_seconds must be 60 to 120", r.Name)
			}
			route.Outcomes = if03fixture.Fixture{Issuer: f.Issuer, Kid: f.Kid, Key: key, Validity: v,
				Claims: if03.Claims{Role: f.Role, Entitlement: f.Entitlement}}
		}
		out.Routes[r.Name] = route
	}
	return out, nil
}

func pemBlock(path, want1, want2 string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(raw)
	if b == nil || (b.Type != want1 && b.Type != want2) {
		return nil, errors.New("not a PEM block of the expected type")
	}
	return b.Bytes, nil
}

func readPublicKey(path string) (*ecdsa.PublicKey, error) {
	der, err := pemBlock(path, "PUBLIC KEY", "PUBLIC KEY")
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKIXPublicKey(der)
	pub, ok := k.(*ecdsa.PublicKey)
	if err != nil || !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("not a P-256 public key")
	}
	return pub, nil
}
