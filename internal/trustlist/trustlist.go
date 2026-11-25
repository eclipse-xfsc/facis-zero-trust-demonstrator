// Package trustlist retrieves and verifies TRAIN trust lists: the trust-list VC a TSPA signs
// (JsonWebSignature2020, a validity window) and the list it vouches for. The verification service
// uses it for the credential issuers, the Connector's entry for the counter-connectors (ZT-18).
package trustlist

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/piprate/json-gold/ld"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
)

// The trust-list VC is verified here, not believed from the TCR: the documented TCR's vcVerified
// never checks the VC's validity window (docs/tspa-publish-api.md, section 1). For one VC the
// service checks, in this order, failing closed at every step:
//
//  1. its @context is exactly the pinned documents embedded below and the trust-list terms (nothing
//     is loaded from the network, and JSON-LD runs in safe mode, so no term is silently dropped
//     from what the proof covers);
//  2. its issuer is the DID the TCR resolved from the trust framework pointer, a did:web;
//  3. the JsonWebSignature2020 proof (EdDSA, detached unencoded JWS over the SHA-256 of the
//     URDNA2015 canonical proof options and document) verifies with the key the issuer's DID
//     document names as the proof's verificationMethod and lists under assertionMethod;
//  4. its validity window: expirationDate or validUntil required, issuanceDate or validFrom not
//     in the future;
//  5. the trust list at credentialSubject.trustlistURI has the multihash credentialSubject.hash.
//
// Only that list is then searched for the issuer. A verified result is cached by the SHA-256 of
// the VC's bytes for at most vcCacheTTL and never past the VC's expiry.

//go:embed contexts/*.jsonld
var contextFiles embed.FS

// The @context documents a trust-list VC may name, pinned: fetched once on 2026-11-21 and embedded
// (contexts/), never loaded from the network.
var pinnedContexts = map[string]string{
	"https://www.w3.org/2018/credentials/v1":           "contexts/credentials-v1.jsonld",
	"https://w3id.org/security/suites/ed25519-2020/v1": "contexts/ed25519-2020-v1.jsonld",
	"https://w3id.org/security/suites/jws-2020/v1":     "contexts/jws-2020-v1.jsonld",
}

// Terms is the inline context our TSPA's VC template carries (deployment/docker/tspa,
// patch 0003) so that the proof covers the subject: without it JSON-LD drops trustlistURI and
// hash from the signed data and anyone could point a valid VC at another list.
var Terms = map[string]any{
	"trustlisttype": "https://tspa.facis.cloud/ns/trustlist#trustlisttype",
	"trustlistURI":  map[string]any{"@id": "https://tspa.facis.cloud/ns/trustlist#trustlistURI", "@type": "@id"},
	"hash":          "https://tspa.facis.cloud/ns/trustlist#hash",
}

const vcCacheTTL = 5 * time.Minute

// MaxDoc bounds every document read: the VC, the DID document and the trust list.
const MaxDoc = 1 << 20

type pinnedLoader struct{}

func (pinnedLoader) LoadDocument(u string) (*ld.RemoteDocument, error) {
	file, ok := pinnedContexts[u]
	if !ok {
		return nil, fmt.Errorf("context %q is not pinned", u)
	}
	raw, err := contextFiles.ReadFile(file)
	if err != nil {
		return nil, err
	}
	doc, err := ld.DocumentFromReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	return &ld.RemoteDocument{DocumentURL: u, Document: doc}, nil
}

// Verifier verifies trust-list VCs. Safe for concurrent use.
type Verifier struct {
	HTTP *http.Client
	Now  func() time.Time

	mu    sync.Mutex
	cache map[cacheKey]verifiedList
}

// cacheKey is a VC's bytes and the DID it was verified under: the same bytes are not trusted for
// another DID.
type cacheKey struct {
	sum [32]byte
	did string
}

type verifiedList struct {
	list    any
	until   time.Time // of the cache entry
	expires time.Time // of the VC
}

// TrustList returns the trust list the VC at vcURI vouches for, after the checks above, and the
// VC's expiry, the deadline of any trust taken from it; did is the DID the TCR resolved from the
// pointer.
func (v *Verifier) TrustList(ctx context.Context, did, vcURI string) (any, time.Time, error) {
	raw, err := v.get(ctx, vcURI)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("trust-list VC: %w", err)
	}
	now := v.Now()
	key := cacheKey{sha256.Sum256(raw), did}
	v.mu.Lock()
	if c, ok := v.cache[key]; ok && now.Before(c.until) {
		v.mu.Unlock()
		return c.list, c.expires, nil
	}
	v.mu.Unlock()

	var vc map[string]any
	if err := json.Unmarshal(raw, &vc); err != nil {
		return nil, time.Time{}, errors.New("trust-list VC: not a JSON object")
	}
	if err := checkContexts(vc["@context"]); err != nil {
		return nil, time.Time{}, err
	}
	if nestedContext(vc, true) {
		return nil, time.Time{}, errors.New("trust-list VC: @context below the root")
	}
	if iss, _ := vc["issuer"].(string); iss == "" || iss != did || !strings.HasPrefix(iss, "did:web:") {
		return nil, time.Time{}, errors.New("trust-list VC: issuer is not the DID the TCR resolved")
	}
	until, err := vcWindow(vc, now)
	if err != nil {
		return nil, time.Time{}, err
	}
	if err := v.verifyProof(ctx, vc, did); err != nil {
		return nil, time.Time{}, err
	}
	subject, _ := vc["credentialSubject"].(map[string]any)
	listURI, _ := subject["trustlistURI"].(string)
	wantHash, _ := subject["hash"].(string)
	if listURI == "" || wantHash == "" {
		return nil, time.Time{}, errors.New("trust-list VC: no trustlistURI or hash")
	}
	listRaw, err := v.get(ctx, listURI)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("trust list: %w", err)
	}
	if MultihashSHA256(listRaw) != wantHash {
		return nil, time.Time{}, errors.New("trust list: hash does not match the VC")
	}
	// The fetches above took time: the window is checked again before the list is used.
	if !v.Now().Before(until) {
		return nil, time.Time{}, errors.New("trust-list VC: expired")
	}
	var list any
	if err := json.Unmarshal(listRaw, &list); err != nil {
		return nil, time.Time{}, errors.New("trust list: not JSON")
	}
	v.mu.Lock()
	if v.cache == nil || len(v.cache) > 64 {
		v.cache = map[cacheKey]verifiedList{} // ponytail: dropped wholesale; a handful of frameworks
	}
	v.cache[key] = verifiedList{list: list, until: minTime(now.Add(vcCacheTTL), until), expires: until}
	v.mu.Unlock()
	return list, until, nil
}

func checkContexts(c any) error {
	list, ok := c.([]any)
	if !ok || len(list) == 0 {
		return errors.New("trust-list VC: @context is not an array")
	}
	for _, e := range list {
		switch e := e.(type) {
		case string:
			if _, ok := pinnedContexts[e]; !ok {
				return errors.New("trust-list VC: @context names a document that is not pinned")
			}
		case map[string]any:
			if !reflect.DeepEqual(e, Terms) {
				return errors.New("trust-list VC: inline @context is not the trust-list terms")
			}
		default:
			return errors.New("trust-list VC: @context entry malformed")
		}
	}
	return nil
}

// nestedContext says whether an @context appears anywhere but at the root. An embedded context
// can re-map a term after signing (say "hash" to @index, the signed value kept under its full
// IRI), so that the value read is not the value signed; only the pinned root context is allowed.
func nestedContext(v any, root bool) bool {
	switch v := v.(type) {
	case map[string]any:
		for k, child := range v {
			if k == "@context" && !root {
				return true
			}
			if k != "@context" && nestedContext(child, false) {
				return true
			}
		}
	case []any:
		for _, child := range v {
			if nestedContext(child, false) {
				return true
			}
		}
	}
	return false
}

// vcWindow checks the VC's window at now and returns its end.
func vcWindow(vc map[string]any, now time.Time) (time.Time, error) {
	str := func(names ...string) string {
		for _, n := range names {
			if s, ok := vc[n].(string); ok && s != "" {
				return s
			}
		}
		return ""
	}
	endS := str("expirationDate", "validUntil")
	if endS == "" {
		return time.Time{}, errors.New("trust-list VC: no expirationDate or validUntil")
	}
	end, err := time.Parse(time.RFC3339, endS)
	if err != nil {
		return time.Time{}, errors.New("trust-list VC: validity end unreadable")
	}
	if !now.Before(end) {
		return time.Time{}, errors.New("trust-list VC: expired")
	}
	if startS := str("validFrom", "issuanceDate"); startS != "" {
		start, err := time.Parse(time.RFC3339, startS)
		if err != nil || now.Before(start) {
			return time.Time{}, errors.New("trust-list VC: not yet valid")
		}
	}
	return end, nil
}

func (v *Verifier) verifyProof(ctx context.Context, vc map[string]any, did string) error {
	proof, _ := vc["proof"].(map[string]any)
	if proof == nil || proof["type"] != "JsonWebSignature2020" || proof["proofPurpose"] != "assertionMethod" {
		return errors.New("trust-list VC: no JsonWebSignature2020 assertion proof")
	}
	vm, _ := proof["verificationMethod"].(string)
	jws, _ := proof["jws"].(string)
	if !strings.HasPrefix(vm, did+"#") || strings.Count(jws, ".") != 2 {
		return errors.New("trust-list VC: proof's verificationMethod or jws malformed")
	}
	parts := strings.Split(jws, ".")
	if parts[1] != "" {
		return errors.New("trust-list VC: jws is not detached")
	}
	headerRaw, err := jose.DecodeB64(parts[0])
	if err != nil {
		return errors.New("trust-list VC: jws header unreadable")
	}
	var h struct {
		Alg  string   `json:"alg"`
		B64  *bool    `json:"b64"`
		Crit []string `json:"crit"`
	}
	if json.Unmarshal(headerRaw, &h) != nil || h.Alg != "EdDSA" || h.B64 == nil || *h.B64 || len(h.Crit) != 1 || h.Crit[0] != "b64" {
		return errors.New("trust-list VC: jws header is not EdDSA with an unencoded payload")
	}
	sig, err := jose.DecodeB64(parts[2])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("trust-list VC: jws signature malformed")
	}
	key, err := v.didKey(ctx, did, vm)
	if err != nil {
		return err
	}
	options := map[string]any{"@context": vc["@context"]}
	for k, val := range proof {
		if k != "jws" && k != "proofValue" {
			options[k] = val
		}
	}
	document := map[string]any{}
	for k, val := range vc {
		if k != "proof" {
			document[k] = val
		}
	}
	hOpts, err := CanonicalSHA256(options)
	if err != nil {
		return err
	}
	hDoc, err := CanonicalSHA256(document)
	if err != nil {
		return err
	}
	input := append([]byte(parts[0]+"."), append(hOpts, hDoc...)...)
	if !ed25519.Verify(key, input, sig) {
		return errors.New("trust-list VC: proof does not verify")
	}
	return nil
}

// CanonicalSHA256 is the SHA-256 of doc's URDNA2015 canonical form under the pinned contexts: one
// half of what a JsonWebSignature2020 proof signs.
func CanonicalSHA256(doc map[string]any) ([]byte, error) {
	opts := ld.NewJsonLdOptions("")
	opts.Algorithm = ld.AlgorithmURDNA2015
	opts.Format = "application/n-quads"
	opts.DocumentLoader = pinnedLoader{}
	opts.SafeMode = true
	out, err := ld.NewJsonLdProcessor().Normalize(doc, opts)
	if err != nil {
		return nil, errors.New("trust-list VC: canonicalisation refused")
	}
	s, _ := out.(string)
	if s == "" {
		return nil, errors.New("trust-list VC: canonical form empty")
	}
	sum := sha256.Sum256([]byte(s))
	return sum[:], nil
}

// didKey resolves did (did:web) and returns the Ed25519 key of verification method vm, which the
// document must list under assertionMethod.
func (v *Verifier) didKey(ctx context.Context, did, vm string) (ed25519.PublicKey, error) {
	docURL, err := didWebURL(did)
	if err != nil {
		return nil, err
	}
	raw, err := v.get(ctx, docURL)
	if err != nil {
		return nil, fmt.Errorf("DID document: %w", err)
	}
	var doc struct {
		ID                 string `json:"id"`
		VerificationMethod []struct {
			ID           string          `json:"id"`
			Controller   string          `json:"controller"`
			PublicKeyJwk json.RawMessage `json:"publicKeyJwk"`
		} `json:"verificationMethod"`
		AssertionMethod []json.RawMessage `json:"assertionMethod"`
	}
	if json.Unmarshal(raw, &doc) != nil || doc.ID != did {
		return nil, errors.New("DID document: not the issuer's")
	}
	asserts := false
	for _, a := range doc.AssertionMethod {
		var id string
		if json.Unmarshal(a, &id) == nil && (id == vm || did+id == vm) {
			asserts = true
		}
	}
	if !asserts {
		return nil, errors.New("DID document: the proof's key is not an assertion method")
	}
	for _, m := range doc.VerificationMethod {
		if m.ID != vm && did+m.ID != vm {
			continue
		}
		var jwk struct {
			Kty, Crv, X string
			D           *string `json:"d"`
		}
		if json.Unmarshal(m.PublicKeyJwk, &jwk) != nil || jwk.Kty != "OKP" || jwk.Crv != "Ed25519" || jwk.D != nil {
			return nil, errors.New("DID document: the proof's key is not a public Ed25519 JWK")
		}
		x, err := jose.DecodeB64(jwk.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, errors.New("DID document: key malformed")
		}
		return ed25519.PublicKey(x), nil
	}
	return nil, errors.New("DID document: no such verification method")
}

// didWebURL is the did:web method's document location: did:web:host[%3Aport][:path...].
func didWebURL(did string) (string, error) {
	rest, ok := strings.CutPrefix(did, "did:web:")
	if !ok || rest == "" {
		return "", errors.New("not a did:web")
	}
	segs := strings.Split(rest, ":")
	host, err := url.PathUnescape(segs[0])
	if err != nil || host == "" || strings.ContainsAny(host, "/?#@") {
		return "", errors.New("did:web host malformed")
	}
	path := "/.well-known"
	if len(segs) > 1 {
		path = "/" + strings.Join(segs[1:], "/")
	}
	return "https://" + host + path + "/did.json", nil
}

func (v *Verifier) get(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, errors.New("bad URL")
	}
	resp, err := v.HTTP.Do(req)
	if err != nil {
		return nil, errors.New("unreachable")
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxDoc+1))
	if err != nil || len(raw) > MaxDoc || resp.StatusCode != http.StatusOK {
		return nil, errors.New("not answered")
	}
	return raw, nil
}

// MultihashSHA256 is IPFS's form of the trust list's hash, as TSPA writes it: base58btc of
// 0x12 0x20 || SHA-256.
func MultihashSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return base58(append([]byte{0x12, 0x20}, sum[:]...))
}

func base58(b []byte) string {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	n := new(big.Int).SetBytes(b)
	var out []byte
	for mod, base := new(big.Int), big.NewInt(58); n.Sign() > 0; {
		n.DivMod(n, base, mod)
		out = append(out, alphabet[mod.Int64()])
	}
	for _, c := range b {
		if c != 0 {
			break
		}
		out = append(out, '1')
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// ListsActive finds, anywhere in a trust list, a service object whose ServiceTypeIdentifier is
// id (the TCR's lookup key) and whose ServiceCurrentStatus is "active". The search does not
// depend on the wrapper members around the entries, which differ between TSPA's raw list and the
// TCR's answer.
func ListsActive(doc any, id string) bool {
	switch v := doc.(type) {
	case map[string]any:
		if v["ServiceTypeIdentifier"] == id && v["ServiceCurrentStatus"] == "active" {
			return true
		}
		for _, child := range v {
			if ListsActive(child, id) {
				return true
			}
		}
	case []any:
		for _, child := range v {
			if ListsActive(child, id) {
				return true
			}
		}
	}
	return false
}
