// Command sdjwt-fixture generates the OID4VP conformance fixtures and serves status lists for
// proofs. It is a test tool: nothing it signs is a credential of record.
//
//	sdjwt-fixture regenerate --out DIR [--status-uri URI] [--audience URI] [--nonce N] [--now RFC3339]
//	sdjwt-fixture serve-status --dir DIR --listen ADDR
//
// regenerate writes, under DIR, the trusted-issuers document of the fixture issuer, the status
// lists (clear, revoked, expired) signed for --status-uri, and one case file per presentation
// with the outcome a verifier must produce for it. Keys come from fixed scalars, salts from a
// fixed seed and instants from --now, so a regenerated tree differs from the committed one only in
// signature bytes.
//
// serve-status answers GET /<name>.jwt from DIR with the status-list media type, for a proof that
// needs a list server it can point a credential at and take down. It logs one line per request
// and stops on SIGINT or SIGTERM.
//
// Exit status: 0 done, 1 failed, 2 usage.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/sdjwt"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/sdjwt/sdjwtfixture"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/statuslist"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/statuslist/statuslistfixture"
)

const usage = `usage:
  sdjwt-fixture regenerate --out DIR [--status-uri URI] [--audience URI] [--nonce N] [--now RFC3339]
  sdjwt-fixture serve-status --dir DIR --listen ADDR
`

// The fixture issuer and credential profile.
const (
	Issuer       = "https://issuer.fixture.invalid"
	IssuerKid    = "fixture-issuer-1"
	OtherIssuer  = "https://untrusted.fixture.invalid"
	OtherKid     = "untrusted-1"
	VCT          = "https://facis.example/credentials/participant"
	JTI          = "urn:uuid:00000000-0000-4000-8000-0000000000aa"
	StatusIndex  = 42
	StatusSize   = 1024
	DefaultNonce = "fx-challenge-0123456789abcdef"
	DefaultAud   = "https://zone-b.example/resource"
	DefaultURI   = "https://status.fixture.invalid/lists/participant.jwt"
	DefaultNow   = "2026-09-09T12:00:00Z"
)

// Case is one conformance fixture: the presentation a holder posts, the binding it must satisfy,
// which status list the verifier will find, and the outcome it must produce.
type Case struct {
	Fixture    bool   `json:"fixture"`
	Case       string `json:"case"`
	What       string `json:"what"`
	Input      Input  `json:"input"`
	StatusList string `json:"status_list"` // clear | revoked | expired | unavailable | none
	Expect     Expect `json:"expect"`
}

// Input is what the verifier receives.
type Input struct {
	VPToken  string `json:"vp_token"`
	Nonce    string `json:"nonce"`
	Audience string `json:"audience"`
	Now      string `json:"now"`
}

// Expect is the outcome: its status, its reason code when not verified, and, when the credential
// was read, the claims and references it carries.
type Expect struct {
	Status         string            `json:"status"`
	ReasonCode     string            `json:"reason_code,omitempty"`
	Claims         map[string]string `json:"claims,omitempty"`
	CredentialRefs []string          `json:"credential_refs,omitempty"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "regenerate":
		return regenerate(args[1:], stderr)
	case "serve-status":
		return serveStatus(args[1:], stderr)
	case "-h", "--help", "help":
		_, _ = fmt.Fprint(stderr, usage)
		return 0
	}
	_, _ = fmt.Fprintf(stderr, "sdjwt-fixture: unknown mode %q\n%s", args[0], usage)
	return 2
}

func regenerate(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("regenerate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "directory to write (required)")
	statusURI := fs.String("status-uri", DefaultURI, "URI the credentials name for their status list")
	audience := fs.String("audience", DefaultAud, "audience the key bindings are for")
	nonce := fs.String("nonce", DefaultNonce, "nonce (the connector challenge) the key bindings carry")
	nowText := fs.String("now", DefaultNow, "the instant the cases are evaluated at")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *out == "" {
		_, _ = fmt.Fprintln(stderr, "regenerate: --out is required")
		return 2
	}
	now, err := time.Parse(time.RFC3339, *nowText)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "regenerate: --now is not RFC 3339")
		return 2
	}
	if strings.TrimSpace(*nonce) != *nonce || *nonce == "" {
		_, _ = fmt.Fprintln(stderr, "regenerate: --nonce must not be empty or carry surrounding whitespace")
		return 2
	}
	for _, f := range []struct{ name, value string }{{"--status-uri", *statusURI}, {"--audience", *audience}} {
		if u, err := url.Parse(f.value); err != nil || u.Scheme == "" || u.Host == "" {
			_, _ = fmt.Fprintf(stderr, "regenerate: %s must be an absolute URI with a host\n", f.name)
			return 2
		}
	}
	n, err := Generate(context.Background(), *out, Params{StatusURI: *statusURI, Audience: *audience, Nonce: *nonce, Now: now.UTC()})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "regenerate:", err)
		return 1
	}
	_, _ = fmt.Fprintf(stderr, "regenerate: wrote the trust set, %d status lists and %d cases under %s\n", len(statusLists), n, *out)
	return 0
}

// Params parameterises a fixture tree.
type Params struct {
	StatusURI string
	Audience  string
	Nonce     string
	Now       time.Time
}

// statusLists are the lists written under status-lists/, by name.
var statusLists = []string{"clear", "revoked", "expired"}

// Generate writes the fixture tree for p under dir and returns the number of cases written.
func Generate(ctx context.Context, dir string, p Params) (int, error) {
	issuerKey, holderKey, otherKey := sdjwtfixture.TestIssuerKey(), sdjwtfixture.TestHolderKey(), sdjwtfixture.TestOtherIssuerKey()
	for _, d := range []string{dir, filepath.Join(dir, "status-lists"), filepath.Join(dir, "cases")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return 0, err
		}
	}
	write := func(name string, data []byte) error {
		return os.WriteFile(filepath.Join(dir, name), data, 0o644)
	}

	// The trust set: the fixture issuer, one key.
	issuerJWK := jose.PublicJWK(&issuerKey.PublicKey)
	issuerJWK.Kid = IssuerKid
	trust, _ := json.MarshalIndent(map[string]any{Issuer: map[string]any{"keys": []jose.JWK{issuerJWK}}}, "", "  ")
	if err := write("trusted-issuers.json", append(trust, '\n')); err != nil {
		return 0, err
	}

	// Status lists for the credential's URI.
	lists := map[string]statuslistfixture.Options{
		"clear":   {Set: nil, ExpiresAt: p.Now.Add(365 * 24 * time.Hour)},
		"revoked": {Set: map[int]statuslist.Status{StatusIndex: statuslist.Invalid}, ExpiresAt: p.Now.Add(365 * 24 * time.Hour)},
		"expired": {Set: nil, ExpiresAt: p.Now.Add(-time.Hour)},
	}
	for _, name := range statusLists {
		o := lists[name]
		o.Key, o.Kid, o.Issuer, o.Subject, o.Bits, o.Size, o.IssuedAt = issuerKey, IssuerKid, Issuer, p.StatusURI, 1, StatusSize, p.Now.Add(-2*time.Hour)
		tok, err := statuslistfixture.Sign(ctx, o)
		if err != nil {
			return 0, err
		}
		if err := write(filepath.Join("status-lists", name+".jwt"), []byte(tok+"\n")); err != nil {
			return 0, err
		}
	}

	// The credentials.
	base := func() sdjwtfixture.IssueOptions {
		return sdjwtfixture.IssueOptions{
			IssuerKey: issuerKey, Kid: IssuerKid, Issuer: Issuer, VCT: VCT, JTI: JTI,
			Claims:      []sdjwtfixture.Claim{{Name: "role", Value: "participant"}, {Name: "entitlement", Value: "read"}, {Name: "organisation", Value: "Zone A GmbH"}},
			Disclosable: []string{"role", "entitlement", "organisation"},
			Holder:      &holderKey.PublicKey, Status: &sdjwt.StatusRef{URI: p.StatusURI, Index: StatusIndex},
			IssuedAt: p.Now.Add(-24 * time.Hour), NotBefore: p.Now.Add(-24 * time.Hour), ExpiresAt: time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC),
			Rand: seeded("facis-oid4vp-fixtures"),
		}
	}
	credential, err := sdjwtfixture.Issue(ctx, base())
	if err != nil {
		return 0, err
	}
	kbAt := p.Now.Add(-5 * time.Second)
	present := func(issued sdjwtfixture.Issued, key *ecdsa.PrivateKey, nonce, aud string, names ...string) (string, error) {
		selected, err := sdjwtfixture.Select(issued, names...)
		if err != nil {
			return "", err
		}
		return sdjwtfixture.Present(ctx, selected, key, nonce, aud, kbAt)
	}
	verified := Expect{Status: if03.StatusVerified, Claims: map[string]string{"role": "participant", "entitlement": "read"}, CredentialRefs: []string{Issuer + "#" + JTI}}
	withClaims := func(status, reason string) Expect {
		return Expect{Status: status, ReasonCode: reason, Claims: verified.Claims, CredentialRefs: verified.CredentialRefs}
	}
	invalid := Expect{Status: if03.StatusFailed, ReasonCode: if03.CodeInvalid}
	untrusted := Expect{Status: if03.StatusFailed, ReasonCode: if03.CodeIssuerUntrusted}

	type maker struct {
		name, what, list string
		expect           Expect
		token            func() (string, error)
	}
	makers := []maker{
		{"valid", "role and entitlement disclosed, key bound to the nonce and audience, status clear", "clear", verified,
			func() (string, error) {
				return present(credential, holderKey, p.Nonce, p.Audience, "role", "entitlement")
			}},
		{"valid-no-entitlement", "only the role disclosed", "clear", Expect{Status: if03.StatusVerified, Claims: map[string]string{"role": "participant"}, CredentialRefs: verified.CredentialRefs},
			func() (string, error) { return present(credential, holderKey, p.Nonce, p.Audience, "role") }},
		{"tampered-disclosure", "the role disclosure's value was changed after issuance; its digest is not in the credential", "clear", invalid,
			func() (string, error) {
				altered, err := sdjwtfixture.EncodeDisclosure("tampered", "role", "admin")
				if err != nil {
					return "", err
				}
				jwt, _, _ := strings.Cut(credential.SDJWT, "~")
				return sdjwtfixture.Present(ctx, jwt+"~"+altered+"~"+credential.Disclosures["entitlement"]+"~", holderKey, p.Nonce, p.Audience, kbAt)
			}},
		{"tampered-issuer-signature", "the issuer JWT payload was altered after signing", "clear", invalid,
			func() (string, error) {
				jwt, _, _ := strings.Cut(credential.SDJWT, "~")
				parts := strings.Split(jwt, ".")
				payload, err := jose.DecodeB64(parts[1])
				if err != nil {
					return "", err
				}
				altered := strings.Replace(string(payload), `"jti":"`+JTI+`"`, `"jti":"urn:uuid:00000000-0000-4000-8000-0000000000ab"`, 1)
				if altered == string(payload) {
					return "", errors.New("jti not found in the payload")
				}
				parts[1] = jose.B64([]byte(altered))
				tampered := sdjwtfixture.Issued{SDJWT: strings.Join(parts, ".") + "~", Disclosures: credential.Disclosures}
				return present(tampered, holderKey, p.Nonce, p.Audience, "role", "entitlement")
			}},
		{"tampered-kb-nonce", "the key binding names another nonce", "clear", invalid,
			func() (string, error) {
				return present(credential, holderKey, "fx-other-nonce-0123456789", p.Audience, "role", "entitlement")
			}},
		{"tampered-kb-audience", "the key binding names another audience", "clear", invalid,
			func() (string, error) {
				return present(credential, holderKey, p.Nonce, "https://zone-c.example/resource", "role", "entitlement")
			}},
		{"tampered-sd-hash", "a disclosure was removed after the key binding was computed", "clear", invalid,
			func() (string, error) {
				full, err := present(credential, holderKey, p.Nonce, p.Audience, "role", "entitlement")
				if err != nil {
					return "", err
				}
				parts := strings.Split(full, "~")
				return strings.Join(append(parts[:2], parts[3]), "~"), nil
			}},
		{"missing-key-binding", "no key-binding JWT", "clear", invalid,
			func() (string, error) { return sdjwtfixture.Select(credential, "role", "entitlement") }},
		{"kb-wrong-holder-key", "the key binding is signed by a key other than the credential's cnf", "clear", invalid,
			func() (string, error) {
				return present(credential, otherKey, p.Nonce, p.Audience, "role", "entitlement")
			}},
		{"untrusted-issuer", "issued by an issuer the trust set does not list", "clear", untrusted,
			func() (string, error) {
				o := base()
				o.IssuerKey, o.Kid, o.Issuer = otherKey, OtherKid, OtherIssuer
				issued, err := sdjwtfixture.Issue(ctx, o)
				if err != nil {
					return "", err
				}
				return present(issued, holderKey, p.Nonce, p.Audience, "role", "entitlement")
			}},
		{"untrusted-kid", "issued under the trusted issuer's name with a kid it does not list", "clear", untrusted,
			func() (string, error) {
				o := base()
				o.Kid = "fixture-issuer-2"
				issued, err := sdjwtfixture.Issue(ctx, o)
				if err != nil {
					return "", err
				}
				return present(issued, holderKey, p.Nonce, p.Audience, "role", "entitlement")
			}},
		{"revoked", "a valid presentation whose status-list entry is set", "revoked", withClaims(if03.StatusRevoked, if03.CodeRevoked),
			func() (string, error) {
				return present(credential, holderKey, p.Nonce, p.Audience, "role", "entitlement")
			}},
		{"status-unavailable", "a valid presentation whose status list cannot be fetched", "unavailable", withClaims(if03.StatusFailed, if03.CodeStatusUnavailable),
			func() (string, error) {
				return present(credential, holderKey, p.Nonce, p.Audience, "role", "entitlement")
			}},
		{"status-expired-list", "a valid presentation whose status list is past its exp", "expired", withClaims(if03.StatusFailed, if03.CodeStatusUnavailable),
			func() (string, error) {
				return present(credential, holderKey, p.Nonce, p.Audience, "role", "entitlement")
			}},
		{"expired-credential", "the credential's exp is in the past", "clear", invalid,
			func() (string, error) {
				o := base()
				o.ExpiresAt = p.Now.Add(-time.Hour)
				issued, err := sdjwtfixture.Issue(ctx, o)
				if err != nil {
					return "", err
				}
				return present(issued, holderKey, p.Nonce, p.Audience, "role", "entitlement")
			}},
		{"unaccepted-vct", "a credential type the verifier does not accept", "clear", invalid,
			func() (string, error) {
				o := base()
				o.VCT = "https://facis.example/credentials/visitor"
				issued, err := sdjwtfixture.Issue(ctx, o)
				if err != nil {
					return "", err
				}
				return present(issued, holderKey, p.Nonce, p.Audience, "role", "entitlement")
			}},
		{"no-status", "a credential without a status-list reference: revocation cannot be checked", "none", invalid,
			func() (string, error) {
				o := base()
				o.Status = nil
				issued, err := sdjwtfixture.Issue(ctx, o)
				if err != nil {
					return "", err
				}
				return present(issued, holderKey, p.Nonce, p.Audience, "role", "entitlement")
			}},
		{"role-missing", "a valid presentation that discloses no role", "clear", invalid,
			func() (string, error) { return present(credential, holderKey, p.Nonce, p.Audience, "entitlement") }},
	}
	for _, m := range makers {
		tok, err := m.token()
		if err != nil {
			return 0, fmt.Errorf("%s: %w", m.name, err)
		}
		c := Case{Fixture: true, Case: m.name, What: m.what, StatusList: m.list, Expect: m.expect,
			Input: Input{VPToken: tok, Nonce: p.Nonce, Audience: p.Audience, Now: p.Now.Format(time.RFC3339)}}
		data, err := json.MarshalIndent(c, "", "  ")
		if err != nil {
			return 0, err
		}
		if err := write(filepath.Join("cases", m.name+".json"), append(data, '\n')); err != nil {
			return 0, err
		}
	}
	return len(makers), nil
}

func serveStatus(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve-status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "", "directory holding <name>.jwt files (required)")
	listen := fs.String("listen", ":8080", "address to listen on")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *dir == "" || *listen == "" {
		_, _ = fmt.Fprintln(stderr, "serve-status: --dir and --listen are required")
		return 2
	}
	if info, err := os.Stat(*dir); err != nil || !info.IsDir() {
		_, _ = fmt.Fprintln(stderr, "serve-status: --dir is not a directory")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serve(ctx, *dir, *listen, stderr)
}

// serve answers status-list requests from dir on listen until ctx is done.
func serve(ctx context.Context, dir, listen string, stderr io.Writer) int {
	srv := &http.Server{Addr: listen, ReadHeaderTimeout: 5 * time.Second, Handler: statusHandler(dir, stderr)}
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe() }()
	_, _ = fmt.Fprintf(stderr, "serve-status: serving %s on %s\n", dir, listen)
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			_, _ = fmt.Fprintln(stderr, "serve-status:", err)
			return 1
		}
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		_, _ = fmt.Fprintln(stderr, "serve-status: stopped")
	}
	return 0
}

// statusHandler serves GET /<name>.jwt from dir with the status-list media type. Every request is
// logged with its quoted path and status; anything else (another method, another suffix, a path
// with separators, an absent file) is 404, which a proof reads as "list unavailable".
func statusHandler(dir string, stderr io.Writer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		status := http.StatusNotFound
		defer func() { _, _ = fmt.Fprintf(stderr, "serve-status: %s %q %d\n", r.Method, r.URL.Path, status) }()
		if r.Method != http.MethodGet || !strings.HasSuffix(name, ".jwt") || strings.ContainsAny(name, "/\\") {
			http.NotFound(w, r)
			return
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		status = http.StatusOK
		w.Header().Set("Content-Type", statuslist.MediaType)
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(data)
	})
}

// seeded is a deterministic byte stream: SHA-256 chained from a seed.
type seededReader struct {
	state []byte
	buf   []byte
}

func seeded(seed string) io.Reader {
	s := sha256.Sum256([]byte(seed))
	return &seededReader{state: s[:]}
}

func (r *seededReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if len(r.buf) == 0 {
			next := sha256.Sum256(r.state)
			r.state = next[:]
			r.buf = append([]byte(nil), next[:]...)
		}
		k := copy(p[n:], r.buf)
		r.buf = r.buf[k:]
		n += k
	}
	return n, nil
}
