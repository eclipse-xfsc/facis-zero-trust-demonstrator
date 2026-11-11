package acquire

import (
	"crypto/ecdsa"
	"os"
	"testing"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/acquire/acquiretest"
)

// Zone B is the real connector binary, run by acquiretest.

func TestMain(m *testing.M) {
	code := m.Run()
	acquiretest.Cleanup()
	os.Exit(code)
}

type zoneB struct {
	base, clientID, clientSecret string
}

func startConnector(t *testing.T, dsn, baoAddr, baoToken string, issuer *ecdsa.PublicKey) zoneB {
	t.Helper()
	b := acquiretest.StartConnector(t, dsn, baoAddr, baoToken, issuer)
	return zoneB{base: b.Base, clientID: b.ClientID, clientSecret: b.ClientSecret}
}
