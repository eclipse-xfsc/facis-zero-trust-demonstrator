package bdd

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/cucumber/godog"
)

// tlsEndpoints checks the TLS minimum of the endpoints of a target that a client outside the cluster
// can reach: its public ingress hosts. Each is tried once with TLS 1.3 only and once with each older
// version only. It stands behind TDR-BDD-07 without proving it: the row is about every relevant
// endpoint, and the TLS listeners inside the cluster (the mesh, istiod, SPIRE, the admission
// webhooks) are not reachable from here.
//
//	BDD_TLS_ENDPOINTS   comma-separated host:port of endpoints that answer HTTP/1.1;
//	                    "host:port@address:port" dials the address and asks for the host (a
//	                    cluster reached through a port mapping)
//	BDD_TLS_CA_FILE     PEM of the CA that issued the endpoints' certificates; unset means the
//	                    system roots
//
// In the cluster dry run every step is skipped, so a pull request lists the scenario as not run.
type tlsEndpoints struct {
	dryRun    bool
	endpoints []tlsEndpoint
	roots     *x509.CertPool
	failures  []string
}

type tlsEndpoint struct {
	name    string // host:port as the target is known: the HTTP authority
	host    string // the server name asked for and verified
	address string // what is dialled
}

// olderVersions are tried one at a time: a server may refuse TLS 1.2 and still accept an older
// version, since a client names the versions it supports as a set (RFC 8446, section 4.2.1).
var olderVersions = []uint16{tls.VersionTLS12, tls.VersionTLS11, tls.VersionTLS10}

func (t *tlsEndpoints) thePublicEndpoints() error {
	if t.dryRun {
		return godog.ErrSkip
	}
	list := os.Getenv("BDD_TLS_ENDPOINTS")
	if strings.TrimSpace(list) == "" {
		return errors.New("BDD_TLS_ENDPOINTS is not set: the scenario needs the target's TLS endpoints")
	}
	for _, entry := range strings.Split(list, ",") {
		name, address, mapped := strings.Cut(strings.TrimSpace(entry), "@")
		host, _, err := net.SplitHostPort(name)
		if err != nil || host == "" {
			return fmt.Errorf("BDD_TLS_ENDPOINTS: %q is not host:port", entry)
		}
		if !mapped {
			address = name
		}
		t.endpoints = append(t.endpoints, tlsEndpoint{name: name, host: host, address: address})
	}
	if file := os.Getenv("BDD_TLS_CA_FILE"); file != "" {
		pem, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("BDD_TLS_CA_FILE: %w", err)
		}
		t.roots = x509.NewCertPool()
		if !t.roots.AppendCertsFromPEM(pem) {
			return fmt.Errorf("BDD_TLS_CA_FILE: no certificate in %s", file)
		}
	}
	return nil
}

// handshake completes a handshake at exactly one protocol version, verifying the certificate for
// the host. HTTP/1.1 is the one protocol asked for, so that the exchange after a TLS 1.3 handshake
// is one the endpoint has agreed to.
func (t *tlsEndpoints) handshake(endpoint tlsEndpoint, version uint16) (*tls.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return tls.DialWithDialer(dialer, "tcp", endpoint.address, &tls.Config{
		ServerName: endpoint.host,
		RootCAs:    t.roots,
		MinVersion: version,
		MaxVersion: version,
		NextProtos: []string{"http/1.1"},
	})
}

// exchange sends one HTTP request and reads the status line: a handshake that the server only
// tolerates until the first byte of application data is not a success. Any status is one.
func exchange(conn *tls.Conn, authority string) error {
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", authority); err != nil {
		return err
	}
	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(status, "HTTP/") {
		return fmt.Errorf("no HTTP answer: %q", status)
	}
	return nil
}

func (t *tlsEndpoints) everyVersionIsAttempted() error {
	if t.dryRun {
		return godog.ErrSkip
	}
	for _, endpoint := range t.endpoints {
		conn, err := t.handshake(endpoint, tls.VersionTLS13)
		if err == nil {
			err = exchange(conn, endpoint.name)
			_ = conn.Close()
		}
		if err != nil {
			t.failures = append(t.failures, fmt.Sprintf("%s: TLS 1.3 did not succeed: %v", endpoint.name, err))
		}
		for _, version := range olderVersions {
			// Only the handshake decides, and only the server's own refusal of the version
			// counts. A timeout, a reset or a certificate error would also end the attempt, and
			// would prove nothing about the version.
			conn, err := t.handshake(endpoint, version)
			switch {
			case err == nil:
				_ = conn.Close()
				t.failures = append(t.failures, fmt.Sprintf("%s: %s was accepted", endpoint.name, tls.VersionName(version)))
			case !refusedProtocolVersion(err):
				t.failures = append(t.failures, fmt.Sprintf("%s: %s ended without the protocol-version alert: %v", endpoint.name, tls.VersionName(version), err))
			}
		}
	}
	return nil
}

// refusedProtocolVersion reports whether err is the peer's protocol_version alert, which a server
// sends when it supports none of the versions the client offers (RFC 8446, section 6.2). crypto/tls
// reports an alert from the peer as a net.OpError of the operation "remote error" and does not
// export the alert's type, so its text is what there is to compare.
func refusedProtocolVersion(err error) bool {
	var remote *net.OpError
	return errors.As(err, &remote) && remote.Op == "remote error" &&
		remote.Err != nil && remote.Err.Error() == "tls: protocol version not supported"
}

func (t *tlsEndpoints) tls13CompletesAndEveryOlderVersionIsRefused() error {
	if t.dryRun {
		return godog.ErrSkip
	}
	if len(t.failures) > 0 {
		return errors.New(strings.Join(t.failures, "\n"))
	}
	return nil
}

func registerTLSEndpoints(ctx *godog.ScenarioContext, dryRun bool) {
	t := &tlsEndpoints{}
	ctx.Before(func(c context.Context, _ *godog.Scenario) (context.Context, error) {
		*t = tlsEndpoints{dryRun: dryRun}
		return c, nil
	})
	ctx.Step(`^the public TLS endpoints of the target$`, t.thePublicEndpoints)
	ctx.Step(`^each is attempted with TLS 1\.3 and with every older TLS version$`, t.everyVersionIsAttempted)
	ctx.Step(`^TLS 1\.3 completes a request and the server refuses every older version$`, t.tls13CompletesAndEveryOlderVersionIsRefused)
}
