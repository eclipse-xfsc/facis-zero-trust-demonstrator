package acquire

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/connectorclient"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03/if03fixture"
)

// The client side of the grant lives in internal/connectorclient and the fixture signer in
// internal/if03/if03fixture, shared with the Participant; these names keep acquire's API.
type (
	// Challenge is what the peer Connector issued for one grant.
	Challenge = connectorclient.Challenge
	// OutcomeSource yields a fresh signed IF-03 outcome for a challenge.
	OutcomeSource = connectorclient.OutcomeSource
	// Fixture is an OutcomeSource for tests and the demo; see if03fixture.
	Fixture = if03fixture.Fixture

	tokenResponse = connectorclient.TokenResponse
)

// VPGrantType is the peer Connector's verified-presentation grant (IF-02 v1.1).
const VPGrantType = connectorclient.VPGrantType

// newUUID is a random (version 4) UUID.
func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
