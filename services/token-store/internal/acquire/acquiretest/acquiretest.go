// Package acquiretest runs zone B for the token store's integration tests: the real connector binary,
// through internal/connectortest, configured for the store's route, with the store's client
// registered through the registrar's DCR with the delegated verified-presentation scope, as a
// deployment registers it. A test binary that uses it calls Cleanup from its TestMain.
package acquiretest

import (
	"crypto/ecdsa"
	"testing"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/connectortest"
)

// What zone B is configured with.
const (
	VPIssuer  = "https://verifier.zone-b.test"
	VPKid     = "verifier-1"
	BIssuer   = "https://connector.zone-b.test"
	Audience  = "https://api.zone-b.test"
	VPRole    = "participant-operator"
	VPEntitle = "write"
	VPScope   = "resource.write"
)

// Cleanup removes the built connector binary.
func Cleanup() { connectortest.Cleanup() }

// ZoneB is a running connector and the store's client registered at it.
type ZoneB struct {
	Base, ClientID, ClientSecret string
	SigningKey                   string
	// Stop stops the connector (SIGTERM, then wait); later calls do nothing.
	Stop func()
}

// FreeAddr is a loopback address nothing listens on at the moment.
func FreeAddr(t *testing.T) string { return connectortest.FreeAddr(t) }

// WriteFile writes content to a file of the test's own and returns its path.
func WriteFile(t *testing.T, name, content string) string {
	return connectortest.WriteFile(t, name, content)
}

// RandHex is n random bytes, hex-encoded.
func RandHex(n int) string { return connectortest.RandHex(n) }

// StartConnector runs the connector on dsn (migrated by pgtest) and registers the store's client.
// The connector trusts issuer as the IF-03 verifier key VPKid of VPIssuer.
func StartConnector(t *testing.T, dsn, baoAddr, baoToken string, issuer *ecdsa.PublicKey) ZoneB {
	t.Helper()
	c := connectortest.Start(t, dsn, baoAddr, baoToken, connectortest.Options{
		Issuer: BIssuer, VPIssuer: VPIssuer, VPKid: VPKid, VPKey: issuer, Audiences: []string{Audience},
		ScopeMap: []connectortest.Scope{{Role: VPRole, Entitlement: VPEntitle, Scopes: []string{VPScope}}},
	})
	id, secret := c.Register(t, "zone-a token store", VPScope, Audience)
	return ZoneB{Base: c.Base, SigningKey: c.SigningKey, ClientID: id, ClientSecret: secret, Stop: c.Stop}
}
