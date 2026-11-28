package verificationtest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03/if03fixture"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/sdjwt"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/sdjwt/sdjwtfixture"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/statuslist"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/statuslist/statuslistfixture"
)

// Kit is the credential side of one test run, generated fresh by Provision: an issuer signing key
// and a holder key nobody else has, the issuer keys file and the pinned trust list a deployed
// verification service reads, and a status list the issuer signs at every fetch. A second issuer,
// Unlisted, has keys in the keys file but no entry in the trust list.
type Kit struct {
	Issuer, Unlisted string
	IssuerKey        *ecdsa.PrivateKey
	UnlistedKey      *ecdsa.PrivateKey
	HolderKey        *ecdsa.PrivateKey
	// IssuerKeysFile is {"<issuer>": {"keys": [JWK]}} for both issuers (if03.ParseIssuers).
	IssuerKeysFile string
	// TrustListFile is a FIXTURE: a trust list shaped as TSPA serves it, listing Issuer only.
	TrustListFile string
	// StatusPrefix is where the status list is served; StatusIndex is every credential's entry.
	StatusPrefix string
	StatusIndex  int

	mu      sync.Mutex
	revoked bool
}

// The kid of each generated issuer key; kids are unique across a trust set.
const kitKid = "issuer-1"

func kidOf(k *Kit, iss string) string {
	if iss == k.Unlisted {
		return "unlisted-1"
	}
	return kitKid
}

// Provision generates a Kit for issuer under the test's temporary directory.
func Provision(t testing.TB, issuer string) *Kit {
	t.Helper()
	k := &Kit{Issuer: issuer, Unlisted: issuer + "/unlisted", IssuerKey: newKey(t), UnlistedKey: newKey(t), HolderKey: newKey(t), StatusIndex: 7}
	dir := t.TempDir()
	keys := map[string]any{}
	for iss, key := range map[string]*ecdsa.PrivateKey{k.Issuer: k.IssuerKey, k.Unlisted: k.UnlistedKey} {
		jwk := jose.PublicJWK(&key.PublicKey)
		jwk.Kid = kidOf(k, iss)
		keys[iss] = map[string]any{"keys": []jose.JWK{jwk}}
	}
	k.IssuerKeysFile = writeJSON(t, dir, "issuer-keys.json", keys)
	k.TrustListFile = writeJSON(t, dir, "trust-list.fixture.json", map[string]any{"TrustServiceStatusList": map[string]any{
		"FrameworkInformation": map[string]any{"FrameworkName": map[string]any{"Name": "FIXTURE pinned trust list, generated per test run"}},
		"TrustServiceProviderList": map[string]any{"TrustServiceProvider": []any{map[string]any{
			"UUID": if03fixture.NewUUID(), "TSPName": "fixture credential issuer",
			"TSPServices": map[string]any{"TSPService": []any{map[string]any{
				"ServiceName": "credential-issuer", "ServiceTypeIdentifier": k.Issuer, "ServiceCurrentStatus": "active",
			}}},
		}}},
	}})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		k.mu.Lock()
		set := map[int]statuslist.Status{}
		if k.revoked {
			set[k.StatusIndex] = statuslist.Invalid
		}
		k.mu.Unlock()
		now := time.Now()
		list, err := statuslistfixture.Sign(r.Context(), statuslistfixture.Options{Key: k.IssuerKey, Kid: kitKid, Issuer: k.Issuer,
			Subject: k.StatusPrefix + "participant.jwt", Bits: 1, Size: 64, Set: set, IssuedAt: now, ExpiresAt: now.Add(time.Hour), TTL: time.Second})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", statuslist.MediaType)
		_, _ = w.Write([]byte(list))
	}))
	t.Cleanup(srv.Close)
	k.StatusPrefix = srv.URL + "/lists/"
	return k
}

// Revoke sets (or clears) the status entry of every credential the Kit issues.
func (k *Kit) Revoke(revoked bool) { k.mu.Lock(); k.revoked = revoked; k.mu.Unlock() }

// CredentialOptions change what Credential issues; the zero value is a valid credential of Issuer.
type CredentialOptions struct {
	FromUnlisted bool             // signed by the Unlisted issuer
	Holder       *ecdsa.PublicKey // the cnf key; nil is HolderKey's
	ExpiresAt    time.Time        // zero: no exp
}

// Credential issues an SD-JWT VC of CredentialVCT with role and entitlement disclosed, as a holder
// keeps it ("<issuer JWT>~<disclosure>~<disclosure>~").
func (k *Kit) Credential(t testing.TB, role, entitlement string, o CredentialOptions) string {
	t.Helper()
	iss, key := k.Issuer, k.IssuerKey
	if o.FromUnlisted {
		iss, key = k.Unlisted, k.UnlistedKey
	}
	holder := o.Holder
	if holder == nil {
		holder = &k.HolderKey.PublicKey
	}
	issuedAt := time.Now().Add(-time.Minute)
	if !o.ExpiresAt.IsZero() && !o.ExpiresAt.After(issuedAt) {
		issuedAt = o.ExpiresAt.Add(-time.Hour)
	}
	issued, err := sdjwtfixture.Issue(context.Background(), sdjwtfixture.IssueOptions{
		IssuerKey: key, Kid: kidOf(k, iss), Issuer: iss, VCT: CredentialVCT, JTI: "urn:uuid:" + if03fixture.NewUUID(),
		Claims: []sdjwtfixture.Claim{{Name: "role", Value: role}, {Name: "entitlement", Value: entitlement}}, Disclosable: []string{"role", "entitlement"},
		Holder: holder, IssuedAt: issuedAt, ExpiresAt: o.ExpiresAt,
		Status: &sdjwt.StatusRef{URI: k.StatusPrefix + "participant.jwt", Index: k.StatusIndex},
	})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := sdjwtfixture.Select(issued, "role", "entitlement")
	if err != nil {
		t.Fatal(err)
	}
	return credential
}

func newKey(t testing.TB) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func writeJSON(t testing.TB, dir, name string, v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
