package atls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/cmc"
)

// Defaults applied when the corresponding Config field is zero.
const (
	DefaultHandshakeTimeout        = 10 * time.Second
	DefaultChannelLifetime         = 15 * time.Minute
	DefaultMaxConcurrentHandshakes = 8
)

// minRSABits is the smallest RSA key the crypto baseline (BSI TR-02102, ZT-50) accepts here.
const minRSABits = 4096

// Config configures one end of an attested channel. The zero value is not usable: TLS,
// CmcdAddr and ExpectedPeerIdentity are required.
type Config struct {
	// TLS carries this end's certificate and the zone trust anchors. It is cloned, never
	// modified. Certificates must hold exactly one static certificate; dynamic certificate
	// callbacks are refused because the channel binding reads only the static certificate.
	// A listener verifies clients against ClientCAs (or RootCAs when ClientCAs is nil); a dialer
	// verifies the server against RootCAs. Version, client-authentication, key-exchange and
	// session-resumption settings are overridden by the wrapper's policy.
	TLS *tls.Config

	// CmcdAddr is the host:port of this zone's cmcd, reached over gRPC.
	CmcdAddr string

	// Policies are optional attestation policies passed to the verifier with every report.
	Policies []byte

	// ExpectedPeerIdentity is the identity the peer's leaf certificate must carry: a URI SAN
	// when the value contains "://" (for example "spiffe://zone-b/gateway"), a DNS SAN
	// otherwise.
	ExpectedPeerIdentity string

	// HandshakeTimeout bounds the whole handshake, attestation and PeerVerifier included. Zero
	// means DefaultHandshakeTimeout. Dial also honours the context deadline, whichever is sooner.
	HandshakeTimeout time.Duration

	// ChannelLifetime bounds PeerAttestation.ValidUntil. Zero means DefaultChannelLifetime.
	ChannelLifetime time.Duration

	// MaxConcurrentHandshakes caps concurrent handshakes per listener and across all Dial calls
	// of the process. Zero means DefaultMaxConcurrentHandshakes.
	MaxConcurrentHandshakes int

	// PeerVerifier, when set, is asked after a successful attestation whether the peer may
	// connect. Any error refuses the channel. It runs within the handshake deadline and slot: a
	// verifier still running at the deadline refuses the channel with ErrHandshakeTimeout.
	PeerVerifier PeerVerifier

	// inProcess selects the in-process CMC (libapi). Set only through atlstest.
	inProcess *cmc.Config
	// rewrite is a test seam on the result callback. Set only through atlstest.
	rewrite func(*ar.AttestationResult) bool
}

type role int

const (
	roleClient role = iota
	roleServer
)

// prepared is a validated Config with defaults applied.
type prepared struct {
	role             role
	base             *tls.Config
	cmcdAddr         string
	inProcess        *cmc.Config
	policies         []byte
	expected         string
	handshakeTimeout time.Duration
	lifetime         time.Duration
	maxConcurrent    int
	verifier         PeerVerifier
	rewrite          func(*ar.AttestationResult) bool
}

func configError(format string, args ...any) error {
	return refuse(ErrConfig, fmt.Sprintf(format, args...), nil)
}

func (c Config) prepare(r role) (*prepared, error) {
	if c.TLS == nil {
		return nil, configError("TLS configuration is required")
	}
	if c.TLS.GetCertificate != nil || c.TLS.GetClientCertificate != nil {
		return nil, configError("dynamic certificate callbacks are not supported: " +
			"the channel binding reads only the static certificate in TLS.Certificates")
	}
	if c.TLS.GetConfigForClient != nil {
		return nil, configError("GetConfigForClient is not supported: it would bypass the TLS policy")
	}
	if c.TLS.InsecureSkipVerify {
		return nil, configError("InsecureSkipVerify is not allowed")
	}
	if len(c.TLS.Certificates) != 1 {
		return nil, configError("TLS.Certificates must hold exactly one static certificate, got %d",
			len(c.TLS.Certificates))
	}
	cert := c.TLS.Certificates[0]
	if len(cert.Certificate) == 0 || cert.PrivateKey == nil {
		return nil, configError("TLS certificate has no certificate chain or no private key")
	}
	leaf := cert.Leaf
	if leaf == nil {
		var err error
		leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, configError("cannot parse the TLS leaf certificate: %v", err)
		}
		// CMC dereferences Leaf when it reports a failed TLS dial.
		cert.Leaf = leaf
	}
	if err := checkKeyAlgorithm(leaf.PublicKey); err != nil {
		return nil, configError("own TLS certificate: %v", err)
	}

	var anchors *x509.CertPool
	switch r {
	case roleServer:
		anchors = c.TLS.ClientCAs
		if anchors == nil {
			anchors = c.TLS.RootCAs
		}
	default:
		anchors = c.TLS.RootCAs
	}
	if anchors == nil {
		return nil, configError("zone trust anchors are required (RootCAs, or ClientCAs on a listener)")
	}

	if c.inProcess == nil && strings.TrimSpace(c.CmcdAddr) == "" {
		return nil, configError("CmcdAddr is required")
	}
	if err := checkIdentity(c.ExpectedPeerIdentity); err != nil {
		return nil, err
	}
	if c.HandshakeTimeout < 0 || c.ChannelLifetime < 0 || c.MaxConcurrentHandshakes < 0 {
		return nil, configError("HandshakeTimeout, ChannelLifetime and MaxConcurrentHandshakes must not be negative")
	}

	p := &prepared{
		role:             r,
		cmcdAddr:         c.CmcdAddr,
		inProcess:        c.inProcess,
		policies:         c.Policies,
		expected:         c.ExpectedPeerIdentity,
		handshakeTimeout: c.HandshakeTimeout,
		lifetime:         c.ChannelLifetime,
		maxConcurrent:    c.MaxConcurrentHandshakes,
		verifier:         c.PeerVerifier,
		rewrite:          c.rewrite,
	}
	if p.handshakeTimeout == 0 {
		p.handshakeTimeout = DefaultHandshakeTimeout
	}
	if p.lifetime == 0 {
		p.lifetime = DefaultChannelLifetime
	}
	if p.maxConcurrent == 0 {
		p.maxConcurrent = DefaultMaxConcurrentHandshakes
	}

	base := c.TLS.Clone()
	base.Certificates = []tls.Certificate{cert}
	base.MinVersion = tls.VersionTLS13
	base.MaxVersion = 0 // highest supported; never below TLS 1.3 given MinVersion
	// Key exchange restricted to NIST curves (BSI TR-02102-2), hybrid ML-KEM preferred.
	base.CurvePreferences = []tls.CurveID{
		tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024, tls.CurveP256, tls.CurveP384,
	}
	// Every channel is attested afresh; resumed sessions are not used.
	base.SessionTicketsDisabled = true
	base.ClientSessionCache = nil
	base.RootCAs = anchors
	if r == roleServer {
		base.ClientCAs = anchors
		base.ClientAuth = tls.RequireAndVerifyClientCert
	}
	p.base = base
	return p, nil
}

func checkIdentity(id string) error {
	if strings.TrimSpace(id) == "" {
		return configError("ExpectedPeerIdentity is required")
	}
	if strings.Contains(id, "://") {
		u, err := url.Parse(id)
		if err != nil || u.Scheme == "" {
			return configError("ExpectedPeerIdentity %q is not a valid URI", id)
		}
	}
	return nil
}

// checkKeyAlgorithm enforces the crypto baseline: ECDSA P-256 or P-384, or RSA with at least
// 4096 bits.
func checkKeyAlgorithm(pub any) error {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P256() || k.Curve == elliptic.P384() {
			return nil
		}
		return fmt.Errorf("ECDSA curve %s is outside the crypto baseline (P-256, P-384)", k.Curve.Params().Name)
	case *rsa.PublicKey:
		if k.N.BitLen() >= minRSABits {
			return nil
		}
		return fmt.Errorf("RSA-%d is outside the crypto baseline (RSA-%d or more)", k.N.BitLen(), minRSABits)
	default:
		return fmt.Errorf("key type %T is outside the crypto baseline (ECDSA P-256/P-384, RSA-%d)", pub, minRSABits)
	}
}

// connTLS returns a per-connection TLS configuration whose verification callback records into rec.
func (p *prepared) connTLS(rec *recorder) *tls.Config {
	cfg := p.base.Clone()
	callerVerify := p.base.VerifyConnection
	if p.role == roleClient {
		// The client verifies the server chain itself, below, against the zone anchors: the
		// peer is identified by ExpectedPeerIdentity, not by the host name it was dialled at.
		cfg.InsecureSkipVerify = true
	}
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if err := p.verifyPeer(cs); err != nil {
			rec.setIdentityErr(err)
			return err
		}
		if callerVerify != nil {
			if err := callerVerify(cs); err != nil {
				rec.setIdentityErr(err)
				return err
			}
		}
		return nil
	}
	return cfg
}

// verifyPeer checks the peer's certificate chain against the zone anchors (client side; the
// server side has crypto/tls do it), its key algorithm and its identity.
func (p *prepared) verifyPeer(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return fmt.Errorf("peer presented no certificate")
	}
	leaf := cs.PeerCertificates[0]
	if p.role == roleClient {
		inter := x509.NewCertPool()
		for _, c := range cs.PeerCertificates[1:] {
			inter.AddCert(c)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots:         p.base.RootCAs,
			Intermediates: inter,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err != nil {
			return fmt.Errorf("peer certificate does not chain to the zone trust anchors: %w", err)
		}
	}
	if err := checkKeyAlgorithm(leaf.PublicKey); err != nil {
		return fmt.Errorf("peer certificate: %w", err)
	}
	if !hasIdentity(leaf, p.expected) {
		return fmt.Errorf("peer certificate does not carry the expected identity %q", p.expected)
	}
	return nil
}

func hasIdentity(leaf *x509.Certificate, id string) bool {
	if strings.Contains(id, "://") {
		for _, u := range leaf.URIs {
			if u.String() == id {
				return true
			}
		}
		return false
	}
	for _, name := range leaf.DNSNames {
		if strings.EqualFold(name, id) {
			return true
		}
	}
	return false
}

// handshakeContext bounds ctx by the configured handshake timeout.
func (p *prepared) handshakeContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, p.handshakeTimeout)
}
