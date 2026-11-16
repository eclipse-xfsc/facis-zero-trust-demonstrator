// Package fixtureholder is a stand-in wallet for the presentation hook: it holds one SD-JWT VC and
// its holder key and presents the credential to a verification request that asks for a credential
// of its type. It is not a wallet of record: it asks no one, keeps no history and holds its key in
// the process. An organisational wallet takes its place behind the same verificationclient.Holder.
package fixtureholder

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03/if03fixture"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/oid4vp"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/sdjwt"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/verificationclient"
)

// Fixed-text errors; neither repeats the credential, the key, a path or the request.
var (
	// ErrMaterial: the credential or the key is unreadable or unusable, or the key is not the
	// credential's.
	ErrMaterial = errors.New("fixtureholder: credential or holder key not usable")
	// ErrNotAsked: the request asks for no credential this holder has.
	ErrNotAsked = errors.New("fixtureholder: request does not ask for the held credential")
)

// Holder presents one credential it holds in memory. Build it with New or Load; the zero value
// presents nothing.
type Holder struct {
	credential string // "<issuer JWT>~<disclosure>~...~": the disclosures are the ones revealed
	vct        string
	key        *ecdsa.PrivateKey
	// Now is the instant the key binding is dated; nil means time.Now.
	Now func() time.Time
}

var _ verificationclient.Holder = Holder{}

// New refuses material a verifier would refuse whatever the request: credential must be an SD-JWT
// VC as a holder keeps it (sdjwt.Inspect at now: well formed, within its validity, every
// disclosure its own, a trailing tilde and no key binding), key must be the key its cnf names, and
// the presentation built from them must fit the size a verifier reads. The issuer's signature and
// the credential's revocation are the verifier's to judge.
func New(credential string, key *ecdsa.PrivateKey, now time.Time) (Holder, error) {
	credential = strings.TrimSpace(credential)
	if key == nil {
		return Holder{}, ErrMaterial
	}
	held, err := sdjwt.Inspect(credential, now)
	if err != nil {
		return Holder{}, ErrMaterial
	}
	bound, err := held.Holder.PublicKey()
	if err != nil || !bound.Equal(&key.PublicKey) {
		return Holder{}, ErrMaterial
	}
	h := Holder{credential: credential, vct: held.VCT, key: key}
	// One presentation for nothing, to learn now whether one can be built at all.
	if _, err := sdjwt.Bind(context.Background(), credential, h.sign, "fixtureholder-self-check", "urn:fixtureholder:self-check", now); err != nil {
		return Holder{}, ErrMaterial
	}
	return h, nil
}

// Load reads the credential and a P-256 PEM key from files and builds the holder with New.
func Load(credentialFile, keyFile string, now time.Time) (Holder, error) {
	f, err := os.Open(credentialFile)
	if err != nil {
		return Holder{}, ErrMaterial
	}
	raw, err := io.ReadAll(io.LimitReader(f, sdjwt.MaxLength+1))
	_ = f.Close()
	if err != nil || len(raw) > sdjwt.MaxLength {
		return Holder{}, ErrMaterial
	}
	key, err := if03fixture.ReadPrivateKey(keyFile)
	if err != nil {
		return Holder{}, ErrMaterial
	}
	return New(string(raw), key, now)
}

// Present answers req with the held credential and a key-binding JWT for req.Nonce and
// req.ClientID. It presents only when the request's one credential query asks for an SD-JWT VC of
// the held type: a holder does not hand its credential to a request for something else.
func (h Holder) Present(ctx context.Context, req oid4vp.Request) (string, error) {
	if h.key == nil || req.Nonce == "" || req.ClientID == "" {
		return "", ErrNotAsked
	}
	var query struct {
		Credentials []struct {
			Format string `json:"format"`
			Meta   struct {
				VCT []string `json:"vct_values"`
			} `json:"meta"`
		} `json:"credentials"`
	}
	if json.Unmarshal(req.DCQL, &query) != nil || len(query.Credentials) != 1 ||
		query.Credentials[0].Format != sdjwt.TypIssuer || !slices.Contains(query.Credentials[0].Meta.VCT, h.vct) {
		return "", ErrNotAsked
	}
	now := time.Now
	if h.Now != nil {
		now = h.Now
	}
	return sdjwt.Bind(ctx, h.credential, h.sign, req.Nonce, req.ClientID, now())
}

func (h Holder) sign(_ context.Context, in []byte) ([]byte, error) {
	return if03fixture.SignES256(h.key, in)
}

// Files is a Holder that reads its credential and key from files at every presentation, as the
// token store reads its other credentials: a credential issued again is presented from the next
// acquisition on, and nothing but a presentation needs the files to be there. Unusable files are
// ErrMaterial at that presentation.
type Files struct {
	CredentialFile string // the SD-JWT VC, with exactly the disclosures to reveal and a trailing tilde
	KeyFile        string // PEM, P-256: the key the credential's cnf names
	// Now is the instant the credential is checked at and the key binding is dated; nil means time.Now.
	Now func() time.Time
}

var _ verificationclient.Holder = Files{}

// Present loads the holder from the files and presents with it.
func (f Files) Present(ctx context.Context, req oid4vp.Request) (string, error) {
	now := time.Now
	if f.Now != nil {
		now = f.Now
	}
	h, err := Load(f.CredentialFile, f.KeyFile, now())
	if err != nil {
		return "", err
	}
	h.Now = now
	return h.Present(ctx, req)
}
