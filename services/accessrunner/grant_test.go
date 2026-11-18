package accessrunner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
)

type testKey struct{ k *ecdsa.PrivateKey }

func newTestKey(t *testing.T) testKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{k}
}

func (k testKey) sign(_ context.Context, in []byte) ([]byte, error) {
	sum := sha256.Sum256(in)
	r, s, err := ecdsa.Sign(rand.Reader, k.k, sum[:])
	if err != nil {
		return nil, err
	}
	return append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...), nil
}

func TestVerifyGrant(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	approverKey, otherKey := newTestKey(t), newTestKey(t)
	trust := Trust{Target: "zone-b/facis-ztd", Approvers: []Approver{
		{Subject: "approver-sub", Key: jose.PublicJWK(&approverKey.k.PublicKey)},
		{Subject: "second-approver", Key: jose.PublicJWK(&otherKey.k.PublicKey)},
	}}
	valid := Grant{ID: "g-1", Subject: "caller-sub", Role: "user-admin", Operations: []string{OpListUsers, OpDisableUser},
		Target: trust.Target, PolicyVersion: PolicyVersion(), Approver: "approver-sub", ApprovedAt: now.Unix() - 60,
		NotBefore: now.Unix() - 60, NotAfter: now.Unix() + 3600, Reason: "test"}
	notRevoked := func(string) (bool, error) { return false, nil }
	sign := func(g Grant, kid string, key testKey) string {
		compact, err := Sign(t.Context(), g, kid, key.sign)
		if err != nil {
			t.Fatal(err)
		}
		return compact
	}
	if _, err := VerifyGrant(sign(valid, "approver-sub", approverKey), trust, "caller-sub", OpDisableUser, now, notRevoked); err != nil {
		t.Fatalf("a valid grant was refused: %v", err)
	}
	change := func(f func(*Grant)) Grant {
		g := valid
		g.Operations = append([]string(nil), valid.Operations...)
		f(&g)
		return g
	}
	tampered := sign(valid, "approver-sub", approverKey)
	parts := strings.Split(tampered, ".")
	forged, _ := Sign(t.Context(), change(func(g *Grant) { g.Role = "cluster-operator" }), "approver-sub", approverKey.sign)
	tampered = parts[0] + "." + strings.Split(forged, ".")[1] + "." + parts[2]

	for name, tc := range map[string]struct {
		compact   string
		caller    string
		operation string
		at        time.Time
		revoked   func(string) (bool, error)
		want      error
	}{
		"tampered payload":                {tampered, "caller-sub", OpDisableUser, now, notRevoked, ErrGrantSignature},
		"signed by an unknown key":        {sign(valid, "approver-sub", newTestKey(t)), "caller-sub", OpDisableUser, now, notRevoked, ErrGrantSignature},
		"signed by another approver":      {sign(valid, "second-approver", otherKey), "caller-sub", OpDisableUser, now, notRevoked, ErrGrantSignature},
		"approved by the subject":         {sign(change(func(g *Grant) { g.Subject = "approver-sub" }), "approver-sub", approverKey), "approver-sub", OpDisableUser, now, notRevoked, ErrGrantSelf},
		"used by another caller":          {sign(valid, "approver-sub", approverKey), "someone-else", OpDisableUser, now, notRevoked, ErrGrantSubject},
		"for another target":              {sign(change(func(g *Grant) { g.Target = "zone-a/facis-ztd" }), "approver-sub", approverKey), "caller-sub", OpDisableUser, now, notRevoked, ErrGrantTarget},
		"under another policy":            {sign(change(func(g *Grant) { g.PolicyVersion = "sha256:old" }), "approver-sub", approverKey), "caller-sub", OpDisableUser, now, notRevoked, ErrGrantPolicy},
		"longer than eight hours":         {sign(change(func(g *Grant) { g.NotAfter = g.NotBefore + MaxGrantSeconds + 1 }), "approver-sub", approverKey), "caller-sub", OpDisableUser, now, notRevoked, ErrGrantDuration},
		"of no duration":                  {sign(change(func(g *Grant) { g.NotAfter = g.NotBefore }), "approver-sub", approverKey), "caller-sub", OpDisableUser, now, notRevoked, ErrGrantDuration},
		"approved after it begins":        {sign(change(func(g *Grant) { g.ApprovedAt = g.NotBefore + 1 }), "approver-sub", approverKey), "caller-sub", OpDisableUser, now, notRevoked, ErrGrantDuration},
		"not yet valid":                   {sign(valid, "approver-sub", approverKey), "caller-sub", OpDisableUser, now.Add(-2 * time.Minute), notRevoked, ErrGrantNotYet},
		"at its end":                      {sign(valid, "approver-sub", approverKey), "caller-sub", OpDisableUser, time.Unix(valid.NotAfter, 0), notRevoked, ErrGrantExpired},
		"operation the approver left out": {sign(valid, "approver-sub", approverKey), "caller-sub", OpEnableUser, now, notRevoked, ErrGrantOperation},
		"operation outside the role":      {sign(change(func(g *Grant) { g.Operations = append(g.Operations, OpClusterRestart) }), "approver-sub", approverKey), "caller-sub", OpClusterRestart, now, notRevoked, ErrGrantOperation},
		"revoked":                         {sign(valid, "approver-sub", approverKey), "caller-sub", OpDisableUser, now, func(string) (bool, error) { return true, nil }, ErrGrantRevoked},
		"revocation state unavailable":    {sign(valid, "approver-sub", approverKey), "caller-sub", OpDisableUser, now, func(string) (bool, error) { return false, errors.New("down") }, ErrRevocationState},
		"not a JWS":                       {"not.a.jws", "caller-sub", OpDisableUser, now, notRevoked, ErrGrantSignature},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyGrant(tc.compact, trust, tc.caller, tc.operation, tc.at, tc.revoked); !errors.Is(err, tc.want) {
				t.Errorf("got %v, want %v", err, tc.want)
			}
		})
	}

	// A grant with a member it does not define is refused, whoever signed it.
	extra, _ := jose.Sign(t.Context(), jose.Header{Typ: GrantType, Kid: "approver-sub"}, []byte(`{"grant_id":"g","subject_sub":"caller-sub","role":"user-admin","operations":["keycloak-list-users"],"target":"zone-b/facis-ztd","policy_version":"`+PolicyVersion()+`","approver_sub":"approver-sub","approved_at":1,"not_before":1,"not_after":2,"reason":"r","extra":true}`), approverKey.sign)
	if _, err := VerifyGrant(extra, trust, "caller-sub", OpListUsers, time.Unix(1, 0), notRevoked); !errors.Is(err, ErrGrantMalformed) {
		t.Errorf("a grant with an extra member: %v", err)
	}
}

// The policy version changes with the roles.
func TestPolicyVersionFollowsTheRoles(t *testing.T) {
	before := PolicyVersion()
	Roles["user-admin"] = append(Roles["user-admin"], "keycloak-delete-user")
	defer func() { Roles["user-admin"] = Roles["user-admin"][:len(Roles["user-admin"])-1] }()
	if PolicyVersion() == before {
		t.Fatal("the policy version did not change with the roles")
	}
}
