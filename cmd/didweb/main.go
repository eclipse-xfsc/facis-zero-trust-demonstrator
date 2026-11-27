// Command didweb writes the did:web document that anchors the release signing key (ZT-11): one
// JsonWebKey2020 verification method per public key, its fragment the key's RFC 7638 thumbprint, each
// listed as an assertion method. The same keys give the same bytes, in any order. The document is
// served at the URL it prints to stderr; TRAIN links the DID (docs/ci-cd.md, Trust anchor).
//
//	go run ./cmd/didweb -did <host[:port][/path]> -key docs/contracts/keys/<source>-cosign.pub [-key ...] > did.json
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"regexp"
	"sort"
	"strings"
)

type keyFiles []string

func (k *keyFiles) String() string     { return strings.Join(*k, ",") }
func (k *keyFiles) Set(v string) error { *k = append(*k, v); return nil }

func main() {
	var keys keyFiles
	location := flag.String("did", "", "where the document is served: host[:port][/path], no scheme")
	flag.Var(&keys, "key", "a PEM public key file; repeat for more than one key")
	flag.Parse()
	var pems [][]byte
	for _, k := range keys {
		b, err := os.ReadFile(k)
		if err != nil {
			fail(err)
		}
		pems = append(pems, b)
	}
	doc, url, err := document(*location, pems)
	if err != nil {
		fail(err)
	}
	_, _ = os.Stdout.Write(doc)
	fmt.Fprintln(os.Stderr, "didweb: serve this document at", url)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "didweb:", err)
	os.Exit(1)
}

var (
	hostPattern    = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]+)?$`)
	segmentPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

// didWeb maps host[:port][/path] to its DID and the HTTPS URL a did:web resolver reads (W3C did:web).
func didWeb(location string) (did, url string, err error) {
	host, path, _ := strings.Cut(location, "/")
	if !hostPattern.MatchString(host) {
		return "", "", fmt.Errorf("%q is not a host[:port] (lower case, no scheme)", host)
	}
	did = "did:web:" + strings.ReplaceAll(host, ":", "%3A")
	if path == "" {
		return did, "https://" + host + "/.well-known/did.json", nil
	}
	for _, seg := range strings.Split(path, "/") {
		if !segmentPattern.MatchString(seg) {
			return "", "", fmt.Errorf("path segment %q is not allowed", seg)
		}
		did += ":" + seg
	}
	return did, "https://" + host + "/" + path + "/did.json", nil
}

// jwk holds the public members in a fixed order, so the document's bytes depend only on the key.
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

var b64 = base64.RawURLEncoding

func toJWK(pub crypto.PublicKey) (jwk, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		e, err := k.ECDH()
		if err != nil {
			return jwk{}, err
		}
		point := e.Bytes()[1:] // uncompressed: 0x04 || X || Y, each the curve's size
		size := len(point) / 2
		return jwk{Kty: "EC", Crv: k.Curve.Params().Name, X: b64.EncodeToString(point[:size]), Y: b64.EncodeToString(point[size:])}, nil
	case ed25519.PublicKey:
		return jwk{Kty: "OKP", Crv: "Ed25519", X: b64.EncodeToString(k)}, nil
	case *rsa.PublicKey:
		return jwk{Kty: "RSA", N: b64.EncodeToString(k.N.Bytes()), E: b64.EncodeToString(big.NewInt(int64(k.E)).Bytes())}, nil
	}
	return jwk{}, fmt.Errorf("unsupported public key type %T", pub)
}

// thumbprint is the RFC 7638 JWK thumbprint: SHA-256 over the required members, sorted, no spaces.
func thumbprint(k jwk) string {
	var canonical string
	switch k.Kty {
	case "EC":
		canonical = fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, k.Crv, k.X, k.Y)
	case "OKP":
		canonical = fmt.Sprintf(`{"crv":%q,"kty":"OKP","x":%q}`, k.Crv, k.X)
	case "RSA":
		canonical = fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, k.E, k.N)
	}
	sum := sha256.Sum256([]byte(canonical))
	return b64.EncodeToString(sum[:])
}

type method struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	Controller   string `json:"controller"`
	PublicKeyJwk jwk    `json:"publicKeyJwk"`
}

type didDocument struct {
	Context            []string `json:"@context"`
	ID                 string   `json:"id"`
	VerificationMethod []method `json:"verificationMethod"`
	AssertionMethod    []string `json:"assertionMethod"`
}

// document builds the DID document for the PEM public keys; it refuses a private key, a key given twice
// and an empty key list.
func document(location string, pems [][]byte) ([]byte, string, error) {
	did, url, err := didWeb(location)
	if err != nil {
		return nil, "", err
	}
	if len(pems) == 0 {
		return nil, "", errors.New("no public key")
	}
	doc := didDocument{
		Context: []string{"https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"},
		ID:      did,
	}
	seen := map[string]bool{}
	for _, p := range pems {
		block, _ := pem.Decode(p)
		if block == nil || block.Type != "PUBLIC KEY" {
			return nil, "", errors.New("a key is not a PEM PUBLIC KEY block")
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, "", err
		}
		k, err := toJWK(pub)
		if err != nil {
			return nil, "", err
		}
		kid := thumbprint(k)
		if seen[kid] {
			return nil, "", fmt.Errorf("key %s is given twice", kid)
		}
		seen[kid] = true
		doc.VerificationMethod = append(doc.VerificationMethod, method{ID: did + "#" + kid, Type: "JsonWebKey2020", Controller: did, PublicKeyJwk: k})
	}
	sort.Slice(doc.VerificationMethod, func(i, j int) bool { return doc.VerificationMethod[i].ID < doc.VerificationMethod[j].ID })
	for _, m := range doc.VerificationMethod {
		doc.AssertionMethod = append(doc.AssertionMethod, m.ID)
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, "", err
	}
	return append(out, '\n'), url, nil
}
