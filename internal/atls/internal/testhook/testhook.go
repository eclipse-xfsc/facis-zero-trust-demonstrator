// Package testhook connects package atls to its test-only helper package atlstest.
//
// Go's internal-package rule lets only packages rooted at internal/atls import this package, so
// code outside the wrapper cannot reach the hooks below: the compiler rejects the import. Package
// atls installs the hooks in its init function; atlstest calls them.
package testhook

import (
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/cmc"
)

// InProcess returns a copy of cfg, which must be an atls.Config, that attests through the
// in-process CMC (the libapi backend) configured by lib instead of a cmcd.
var InProcess func(cfg any, lib *cmc.Config) any

// RewriteResult returns a copy of cfg, which must be an atls.Config, whose attestation-result
// callback first passes every result to fn. fn may change the result in place; CMC then decides
// on the changed result. When fn returns false the wrapper does not record the result, as if CMC
// had produced none.
var RewriteResult func(cfg any, fn func(*ar.AttestationResult) bool) any
