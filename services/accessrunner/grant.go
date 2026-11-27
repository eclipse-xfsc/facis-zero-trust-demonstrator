package accessrunner

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
)

// GrantType is the typ of a grant's JWS header.
const GrantType = "ztd-access-grant+jwt"

// Grant is an approval: the approver lets the subject run the listed operations of the role on the
// target between NotBefore and NotAfter. All identities are Keycloak subject ids, never names.
type Grant struct {
	ID            string   `json:"grant_id"`
	Subject       string   `json:"subject_sub"`
	Role          string   `json:"role"`
	Operations    []string `json:"operations"`
	Target        string   `json:"target"`
	PolicyVersion string   `json:"policy_version"`
	Approver      string   `json:"approver_sub"`
	ApprovedAt    int64    `json:"approved_at"`
	NotBefore     int64    `json:"not_before"`
	NotAfter      int64    `json:"not_after"`
	Reason        string   `json:"reason"`
}

// Approver is a person whose approvals the runner accepts, with the key they sign with.
type Approver struct {
	Subject string   `json:"sub"`
	Key     jose.JWK `json:"key"`
}

// Trust is the runner's own configuration of approvals: never supplied by a caller.
type Trust struct {
	Target    string     `json:"target"`
	Approvers []Approver `json:"approvers"`
}

// Grant refusals, each a reason code of the runner's answer and audit record.
var (
	ErrGrantMalformed  = errors.New("grant_malformed")
	ErrGrantSignature  = errors.New("grant_signature_invalid")
	ErrGrantSelf       = errors.New("grant_self_approved")
	ErrGrantSubject    = errors.New("grant_subject_mismatch")
	ErrGrantTarget     = errors.New("grant_target_mismatch")
	ErrGrantPolicy     = errors.New("grant_policy_mismatch")
	ErrGrantNotYet     = errors.New("grant_not_yet_valid")
	ErrGrantExpired    = errors.New("grant_expired")
	ErrGrantDuration   = errors.New("grant_duration_invalid")
	ErrGrantOperation  = errors.New("grant_operation_not_granted")
	ErrGrantRevoked    = errors.New("grant_revoked")
	ErrRevocationState = errors.New("revocation_state_unavailable")
)

// GrantID is the form of a grant id: one line, so the revocation list can name it.
var GrantID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// maxTime bounds every time of a grant (the year 5138), so no difference between two of them
// overflows.
const maxTime = 100_000_000_000

// Sign signs g as the approver whose key signs with sign; kid names that key.
func Sign(ctx context.Context, g Grant, kid string, sign jose.SignFunc) (string, error) {
	payload, err := json.Marshal(g)
	if err != nil {
		return "", err
	}
	return jose.Sign(ctx, jose.Header{Typ: GrantType, Kid: kid}, payload, sign)
}

// VerifyGrant checks a grant for one call: the signature is the named approver's, the approver is
// not the subject, the subject is the caller, the target and policy are the runner's, the time is
// within the grant's bounds, the operation is both granted and in the role, and the grant is not
// revoked. revoked reads the current revocation state; an error there refuses the call.
func VerifyGrant(compact string, trust Trust, caller, operation string, now time.Time, revoked func(id string) (bool, error)) (Grant, error) {
	var named *Approver
	_, payload, err := jose.Verify(compact, jose.HeaderPolicy{Typ: GrantType, KidNeeded: true}, func(h jose.Header) (*ecdsa.PublicKey, error) {
		for i := range trust.Approvers {
			if trust.Approvers[i].Subject == h.Kid {
				named = &trust.Approvers[i]
				return named.Key.PublicKey()
			}
		}
		return nil, errors.New("unknown approver")
	})
	if err != nil {
		return Grant{}, ErrGrantSignature
	}
	var g Grant
	members, err := jose.ParseObject(payload)
	if err != nil || json.Unmarshal(payload, &g) != nil || len(members) != 11 || !GrantID.MatchString(g.ID) || g.Subject == "" || g.Approver == "" {
		return Grant{}, ErrGrantMalformed
	}
	for _, at := range []int64{g.ApprovedAt, g.NotBefore, g.NotAfter} {
		if at <= 0 || at >= maxTime {
			return Grant{}, ErrGrantDuration
		}
	}
	// The key that signed is the approver the grant names.
	if named == nil || named.Subject != g.Approver {
		return Grant{}, ErrGrantSignature
	}
	switch {
	case g.Approver == g.Subject:
		return Grant{}, ErrGrantSelf
	case g.Subject != caller:
		return Grant{}, ErrGrantSubject
	case g.Target != trust.Target:
		return Grant{}, ErrGrantTarget
	case g.PolicyVersion != PolicyVersion():
		return Grant{}, ErrGrantPolicy
	case g.NotAfter <= g.NotBefore || g.NotAfter-g.NotBefore > MaxGrantSeconds || g.ApprovedAt > g.NotBefore:
		return Grant{}, ErrGrantDuration
	case now.Unix() < g.NotBefore:
		return Grant{}, ErrGrantNotYet
	case now.Unix() >= g.NotAfter:
		return Grant{}, ErrGrantExpired
	case !slices.Contains(g.Operations, operation) || !slices.Contains(Roles[g.Role], operation):
		return Grant{}, ErrGrantOperation
	}
	isRevoked, err := revoked(g.ID)
	if err != nil {
		return Grant{}, ErrRevocationState
	}
	if isRevoked {
		return Grant{}, ErrGrantRevoked
	}
	return g, nil
}
