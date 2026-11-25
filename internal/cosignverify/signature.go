package cosignverify

import (
	"context"
	"crypto/ecdsa"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/ociclient"
)

// VerifySignature checks only the cosign signature of ref by one of keys, in the same profile as
// images. It is for signed artefacts that are not runnable images (a TSA policy bundle), so there is
// no platform or attestation check.
func VerifySignature(ctx context.Context, client *ociclient.Client, ref Ref, keys []*ecdsa.PublicKey) Result {
	return (&Verifier{client: client}).verifySignature(ctx, ref, &Policy{Keys: keys})
}
