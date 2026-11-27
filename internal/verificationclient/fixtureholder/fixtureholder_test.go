package fixtureholder_test

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/oid4vp"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/presentation"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/sdjwt"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/sdjwt/sdjwtfixture"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/verificationclient/fixtureholder"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/verificationtest"
)

const (
	nonce    = "challenge-0123456789abcdef"
	audience = "https://api.zone-b.test"
)

func request(vct ...string) oid4vp.Request {
	return oid4vp.Request{ClientID: audience, Nonce: nonce, ResponseURI: "https://verifier.zone-b.test/v1/responses/x",
		DCQL: oid4vp.DCQLQuery("credential", vct...)}
}

func judge(t *testing.T, vp string, b presentation.Binding) presentation.Verdict {
	t.Helper()
	got, err := verificationtest.Policy(&verificationtest.Status{}).Judge(t.Context(), vp, b)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestThePresentationIsAcceptedForItsRequestOnly(t *testing.T) {
	now := time.Now()
	h, err := fixtureholder.New(verificationtest.Credential(t, "participant-operator", "write", now), sdjwtfixture.TestHolderKey(), now)
	if err != nil {
		t.Fatal(err)
	}
	vp, err := h.Present(t.Context(), request(verificationtest.CredentialVCT))
	if err != nil {
		t.Fatal(err)
	}
	got := judge(t, vp, presentation.Binding{Nonce: nonce, Audience: audience, Now: now})
	if got.Status != if03.StatusVerified || got.Claims["role"] != "participant-operator" || got.Claims["entitlement"] != "write" {
		t.Fatalf("verdict %+v", got)
	}
	for name, b := range map[string]presentation.Binding{
		"another nonce":    {Nonce: "challenge-of-someone-else1", Audience: audience, Now: now},
		"another audience": {Nonce: nonce, Audience: "https://other.zone-b.test", Now: now},
		"too old":          {Nonce: nonce, Audience: audience, Now: now.Add(10 * time.Minute)},
	} {
		if got := judge(t, vp, b); got.Status != if03.StatusFailed || got.ReasonCode != if03.CodeInvalid {
			t.Errorf("%s: verdict %+v", name, got)
		}
	}
	again, err := h.Present(t.Context(), request(verificationtest.CredentialVCT))
	if err != nil {
		t.Fatal(err)
	}
	if again == vp {
		t.Error("a second presentation carries the first one's key binding")
	}

	// The key binding is dated by the holder's clock.
	later := now.Add(time.Hour)
	h.Now = func() time.Time { return later }
	dated, err := h.Present(t.Context(), request(verificationtest.CredentialVCT))
	if err != nil {
		t.Fatal(err)
	}
	if got := judge(t, dated, presentation.Binding{Nonce: nonce, Audience: audience, Now: later}); got.Status != if03.StatusVerified {
		t.Errorf("a presentation dated by the holder's clock: %+v", got)
	}
	if got := judge(t, dated, presentation.Binding{Nonce: nonce, Audience: audience, Now: now}); got.Status != if03.StatusFailed {
		t.Errorf("a key binding from an hour ahead was accepted: %+v", got)
	}
}

func TestTheHolderPresentsOnlyWhatItIsAskedFor(t *testing.T) {
	now := time.Now()
	h, err := fixtureholder.New(verificationtest.Credential(t, "participant-operator", "write", now), sdjwtfixture.TestHolderKey(), now)
	if err != nil {
		t.Fatal(err)
	}
	asked := request("https://facis.example/credentials/visitor", verificationtest.CredentialVCT)
	if _, err := h.Present(t.Context(), asked); err != nil {
		t.Errorf("a query naming the held type among others: %v", err)
	}
	query := func(format string, n int) json.RawMessage {
		var credentials []map[string]any
		for range n {
			credentials = append(credentials, map[string]any{"id": "c", "format": format, "meta": map[string]any{"vct_values": []string{verificationtest.CredentialVCT}}})
		}
		raw, _ := json.Marshal(map[string]any{"credentials": credentials})
		return raw
	}
	if _, err := h.Present(t.Context(), oid4vp.Request{ClientID: audience, Nonce: nonce, DCQL: query(sdjwt.TypIssuer, 1)}); err != nil {
		t.Fatalf("the query the refusals below are variations of: %v", err)
	}
	for name, req := range map[string]oid4vp.Request{
		"another type":   request("https://facis.example/credentials/visitor"),
		"no type":        request(),
		"no query":       {ClientID: audience, Nonce: nonce},
		"no credentials": {ClientID: audience, Nonce: nonce, DCQL: query(sdjwt.TypIssuer, 0)},
		"two queries":    {ClientID: audience, Nonce: nonce, DCQL: query(sdjwt.TypIssuer, 2)},
		"another format": {ClientID: audience, Nonce: nonce, DCQL: query("mso_mdoc", 1)},
		"no nonce":       {ClientID: audience, DCQL: query(sdjwt.TypIssuer, 1)},
		"no audience":    {Nonce: nonce, DCQL: query(sdjwt.TypIssuer, 1)},
	} {
		if vp, err := h.Present(t.Context(), req); !errors.Is(err, fixtureholder.ErrNotAsked) || vp != "" {
			t.Errorf("%s: got %q, %v", name, vp, err)
		}
	}
	if _, err := (fixtureholder.Holder{}).Present(t.Context(), request(verificationtest.CredentialVCT)); !errors.Is(err, fixtureholder.ErrNotAsked) {
		t.Errorf("the zero holder presented: %v", err)
	}
}

// rewrite replaces the header or the payload of a credential's issuer JWT. The signature no
// longer matches, which a holder cannot see: it has no issuer key.
func rewrite(t *testing.T, credential string, segment int, edit func(map[string]any)) string {
	t.Helper()
	jwt, rest, _ := strings.Cut(credential, "~")
	parts := strings.Split(jwt, ".")
	raw, err := jose.DecodeB64(parts[segment])
	if err != nil {
		t.Fatal(err)
	}
	var members map[string]any
	if err := json.Unmarshal(raw, &members); err != nil {
		t.Fatal(err)
	}
	edit(members)
	if raw, err = json.Marshal(members); err != nil {
		t.Fatal(err)
	}
	parts[segment] = jose.B64(raw)
	return strings.Join(parts, ".") + "~" + rest
}

func issue(t *testing.T, o sdjwtfixture.IssueOptions, reveal ...string) string {
	t.Helper()
	o.IssuerKey, o.Kid, o.Issuer = sdjwtfixture.TestIssuerKey(), verificationtest.CredentialKid, verificationtest.CredentialIssuer
	if o.VCT == "" {
		o.VCT = verificationtest.CredentialVCT
	}
	o.Holder = &sdjwtfixture.TestHolderKey().PublicKey
	o.Status = &sdjwt.StatusRef{URI: "https://status.fixture.invalid/lists/participant.jwt", Index: 42}
	issued, err := sdjwtfixture.Issue(t.Context(), o)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := sdjwtfixture.Select(issued, reveal...)
	if err != nil {
		t.Fatal(err)
	}
	return credential
}

// TestMaterialAVerifierWouldRefuseIsRefusedByTheHolder: each credential here is one the
// presentation policy answers CRED-INVALID for whatever the request, so the holder refuses it
// itself and the failure is named as the holder's, not as a verification result.
func TestMaterialAVerifierWouldRefuseIsRefusedByTheHolder(t *testing.T) {
	now := time.Now()
	key := sdjwtfixture.TestHolderKey()
	credential := verificationtest.Credential(t, "participant-operator", "write", now)
	if _, err := fixtureholder.New(credential+"\n", key, now); err != nil {
		t.Fatalf("a trailing newline, as a mounted file has: %v", err)
	}
	presented, err := sdjwtfixture.Present(t.Context(), credential, key, nonce, audience, now)
	if err != nil {
		t.Fatal(err)
	}
	jwt, disclosures, _ := strings.Cut(credential, "~")
	segments := strings.Split(jwt, ".")
	role := []sdjwtfixture.Claim{{Name: "role", Value: "participant-operator"}}
	// A credential that fits the size a verifier reads but leaves no room for the key binding. The
	// note sits in the payload, so it grows the credential by four bytes for every three.
	withNote := func(n int) string {
		return issue(t, sdjwtfixture.IssueOptions{IssuedAt: now, Disclosable: []string{"role"},
			Claims: append([]sdjwtfixture.Claim{{Name: "note", Value: strings.Repeat("n", n)}}, role...)}, "role")
	}
	large := withNote((sdjwt.MaxLength - 120 - len(withNote(0))) * 3 / 4)
	if len(large) >= sdjwt.MaxLength || len(large) < sdjwt.MaxLength-250 {
		t.Fatalf("the large credential is %d bytes; it must be just under %d", len(large), sdjwt.MaxLength)
	}
	if _, err := fixtureholder.New(withNote(1000), key, now); err != nil {
		t.Fatalf("a credential with a note of ordinary size: %v", err)
	}

	for name, c := range map[string]struct {
		credential string
		key        *ecdsa.PrivateKey
		at         time.Time
	}{
		"empty":                           {credential: ""},
		"not a credential":                {credential: "a.b.c~"},
		"a presentation":                  {credential: presented},
		"no trailing tilde":               {credential: strings.TrimSuffix(credential, "~")},
		"byte order mark in front":        {credential: string(rune(0xFEFF)) + credential},
		"header that is not base64url":    {credential: "!!!." + segments[1] + "." + segments[2] + "~" + disclosures},
		"signature that is not base64url": {credential: segments[0] + "." + segments[1] + ".$$$~" + disclosures},
		"signature of another length":     {credential: segments[0] + "." + segments[1] + "." + segments[2][:40] + "~" + disclosures},
		"another typ":                     {credential: rewrite(t, credential, 0, func(h map[string]any) { h["typ"] = "vc+sd-jwt" })},
		"no kid":                          {credential: rewrite(t, credential, 0, func(h map[string]any) { delete(h, "kid") })},
		"no vct":                          {credential: rewrite(t, credential, 1, func(p map[string]any) { delete(p, "vct") })},
		"no cnf":                          {credential: rewrite(t, credential, 1, func(p map[string]any) { delete(p, "cnf") })},
		"cnf with a member besides jwk": {credential: rewrite(t, credential, 1, func(p map[string]any) {
			p["cnf"].(map[string]any)["kid"] = "x"
		})},
		"an unreferenced disclosure":  {credential: credential + jose.B64([]byte(`["c2FsdHNhbHRzYWx0c2FsdA","extra","value"]`)) + "~"},
		"expired":                     {credential: issue(t, sdjwtfixture.IssueOptions{IssuedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour), Claims: role, Disclosable: []string{"role"}}, "role")},
		"not yet valid":               {credential: issue(t, sdjwtfixture.IssueOptions{IssuedAt: now, NotBefore: now.Add(time.Hour), Claims: role, Disclosable: []string{"role"}}, "role")},
		"no room for the key binding": {credential: large},
		"a key the cnf does not name": {credential: credential, key: sdjwtfixture.TestOtherIssuerKey()},
		"no instant":                  {credential: credential, at: time.Time{}},
	} {
		k, at := key, now
		if c.key != nil {
			k = c.key
		}
		if name == "no instant" {
			at = c.at
		}
		if _, err := fixtureholder.New(c.credential, k, at); !errors.Is(err, fixtureholder.ErrMaterial) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	if _, err := fixtureholder.New(credential, nil, now); !errors.Is(err, fixtureholder.ErrMaterial) {
		t.Errorf("no key: got %v", err)
	}
	// What the holder cannot see is left to the verifier: a credential whose issuer signature
	// does not verify is held, and refused where the issuer's key is known.
	forged := rewrite(t, credential, 1, func(p map[string]any) { p["jti"] = "urn:uuid:00000000-0000-4000-8000-000000000001" })
	h, err := fixtureholder.New(forged, key, now)
	if err != nil {
		t.Fatalf("a credential with a foreign signature: %v", err)
	}
	vp, err := h.Present(t.Context(), request(verificationtest.CredentialVCT))
	if err != nil {
		t.Fatal(err)
	}
	if got := judge(t, vp, presentation.Binding{Nonce: nonce, Audience: audience, Now: now}); got.Status != if03.StatusFailed || got.ReasonCode != if03.CodeInvalid {
		t.Errorf("the verifier's verdict on it: %+v", got)
	}
}

type files struct{ dir, credential, key string }

func writeFiles(t *testing.T, credential string) files {
	t.Helper()
	dir := t.TempDir()
	der, err := x509.MarshalECPrivateKey(sdjwtfixture.TestHolderKey())
	if err != nil {
		t.Fatal(err)
	}
	f := files{dir: dir, credential: filepath.Join(dir, "holder-credential.sd-jwt"), key: filepath.Join(dir, "holder-key.pem")}
	if err := os.WriteFile(f.credential, []byte(credential+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestLoadReadsTheCredentialAndTheKeyFromFiles(t *testing.T) {
	now := time.Now()
	f := writeFiles(t, verificationtest.Credential(t, "participant-operator", "write", now))
	h, err := fixtureholder.Load(f.credential, f.key, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Present(t.Context(), request(verificationtest.CredentialVCT)); err != nil {
		t.Errorf("present: %v", err)
	}
	oversized := filepath.Join(f.dir, "oversized")
	if err := os.WriteFile(oversized, []byte(strings.Repeat("a", sdjwt.MaxLength+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, paths := range map[string][2]string{
		"no credential file":    {filepath.Join(f.dir, "absent"), f.key},
		"no key file":           {f.credential, filepath.Join(f.dir, "absent")},
		"files swapped":         {f.key, f.credential},
		"a directory":           {f.dir, f.key},
		"no paths":              {"", ""},
		"a file past the bound": {oversized, f.key},
	} {
		_, err := fixtureholder.Load(paths[0], paths[1], now)
		if !errors.Is(err, fixtureholder.ErrMaterial) || strings.Contains(err.Error(), f.dir) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestFilesReadsTheMaterialAtEveryPresentation(t *testing.T) {
	now := time.Now()
	f := writeFiles(t, verificationtest.Credential(t, "participant-operator", "write", now))
	holder := fixtureholder.Files{CredentialFile: f.credential, KeyFile: f.key, Now: func() time.Time { return now }}
	role := func() string {
		t.Helper()
		vp, err := holder.Present(t.Context(), request(verificationtest.CredentialVCT))
		if err != nil {
			t.Fatal(err)
		}
		got := judge(t, vp, presentation.Binding{Nonce: nonce, Audience: audience, Now: now})
		if got.Status != if03.StatusVerified {
			t.Fatalf("verdict %+v", got)
		}
		return got.Claims["role"]
	}
	if got := role(); got != "participant-operator" {
		t.Fatalf("role %q", got)
	}
	// The credential is issued again: the next presentation carries the new one, with no restart.
	if err := os.WriteFile(f.credential, []byte(verificationtest.Credential(t, "participant-auditor", "read", now)), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := role(); got != "participant-auditor" {
		t.Errorf("after the credential was replaced the holder presented role %q", got)
	}
	// The key binding is dated by the holder's clock, not the wall clock.
	now = now.Add(time.Hour)
	if got := role(); got != "participant-auditor" {
		t.Errorf("an hour on by the holder's clock: role %q", got)
	}
	if err := os.Remove(f.credential); err != nil {
		t.Fatal(err)
	}
	if vp, err := holder.Present(t.Context(), request(verificationtest.CredentialVCT)); !errors.Is(err, fixtureholder.ErrMaterial) || vp != "" {
		t.Errorf("without the credential file: %q, %v", vp, err)
	}
	if _, err := (fixtureholder.Files{}).Present(t.Context(), request(verificationtest.CredentialVCT)); !errors.Is(err, fixtureholder.ErrMaterial) {
		t.Errorf("no files named: %v", err)
	}
}
