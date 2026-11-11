// Package replay is the one-time-use record of DPoP proofs (table proof_jti), shared by the Connector,
// the token store and the resource-side verifier.
package replay

import (
	"context"
	"time"
)

// Use identifies one presentation of a proof. Two uses are the same proof when JKT, Method, URI and
// JTI are equal.
type Use struct {
	JKT      string
	Method   string
	URI      string
	JTI      string
	NotAfter time.Time // the record is kept at least until then
}

// Store records proof uses. TryUse inserts the use and reports fresh=true only for the first caller;
// of any number of concurrent callers with the same use exactly one sees fresh=true. An error means
// the check could not be made and the caller fails closed.
type Store interface {
	TryUse(ctx context.Context, use Use) (fresh bool, err error)
}

// Window is how long a proof stays acceptable from the verifier's present: a proof is good from
// iat-skew to iat+lifespan+skew and iat may lie up to skew in the future.
func Window(lifespan, skew time.Duration) time.Duration { return lifespan + 2*skew }
