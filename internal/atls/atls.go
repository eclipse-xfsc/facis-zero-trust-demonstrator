// Package atls establishes attested TLS 1.3 channels between zones: mutually attested by
// default, or attesting only the server or only the client (Config.Mode, ZT-29).
//
// It is the only package allowed to import the CMC attested-TLS library
// (github.com/Fraunhofer-AISEC/cmc, pinned at v0.9.15); a depguard rule fails the build when any
// other package does. Its exported API uses only its own types.
//
// A channel is returned by Dial or Listener.Accept only when all of the following hold (fail
// closed):
//
//   - TLS 1.3 with mutual certificate authentication, whatever the caller's tls.Config allows;
//   - the peer's certificate chains to the zone trust anchors, carries ExpectedPeerIdentity and
//     uses a key algorithm of the crypto baseline;
//   - CMC completed the attestation of the configured mode without error;
//   - on an end that attests its peer: exactly one result exists for this connection, its verdict
//     is success (warn is a refusal), the peer's evidence is still within its validity, and the
//     PeerVerifier, if configured, accepted the peer. On an end that does not, no result exists
//     and the peer carries VerdictNotAttested.
//
// Every refusal closes the connection and returns an *Error matching exactly one sentinel.
//
// On a returned channel, Read and Write return io.EOF and timeout errors as the connection
// returns them, and every other error as an *Error matching ErrChannelLost that wraps the cause.
//
// The exported API is frozen at v1. api_v1.txt lists it and a test fails when the two differ;
// docs/attested-channel.md is the contract and states how the API may change.
//
// The attester is the zone's cmcd, reached over gRPC at Config.CmcdAddr. The in-process CMC is
// available to tests only, through package atlstest.
package atls

import (
	"sync"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/cmc"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/atls/internal/testhook"
)

func init() {
	testhook.InProcess = func(cfg any, lib *cmc.Config) any {
		c := cfg.(Config)
		c.inProcess = lib
		return c
	}
	testhook.RewriteResult = func(cfg any, fn func(*ar.AttestationResult) bool) any {
		c := cfg.(Config)
		c.rewrite = fn
		return c
	}
}

var (
	jsonOnce sync.Once
	jsonSer  ar.Serializer
	jsonErr  error
)

// jsonSerializer returns the serializer for the attested-TLS handshake messages. JSON keeps the
// messages machine- and human-readable.
func jsonSerializer() (ar.Serializer, error) {
	jsonOnce.Do(func() { jsonSer, jsonErr = ar.NewJsonSerializer() })
	return jsonSer, jsonErr
}
