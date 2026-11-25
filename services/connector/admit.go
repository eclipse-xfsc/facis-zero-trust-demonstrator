package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/policyhook/envoyhook"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/policyhook/hook"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/trustlist"
)

// The TRAIN allow list of the zone's entry (ZT-18). `connector admit-peers` answers the entry
// proxy's ext_authz check for every request a counter-connector sends: the peer is admitted only
// when a subject alternative name (URI or DNS) of the client certificate it presented on the
// inter-zone TLS connection is the ServiceTypeIdentifier of an active service in the trust list of
// the configured trust framework. The list is retrieved from the TSPA and verified
// (internal/trustlist: the trust-list VC's JsonWebSignature2020 proof under the configured issuer
// DID, its validity window, the list's hash), kept for at most the refresh interval and never past
// the VC's expiry. Every decision is one IF-01 decision event on stdout.
const (
	reasonPeerNotListed    = "CHAN-ZONE-UNKNOWN"      // 403: no SAN of the peer is an active service of the list
	reasonTrustUnreachable = "CHAN-TRUST-UNREACHABLE" // 503: the list cannot be retrieved or verified - fail closed
)

type peerAdmitter struct {
	lists     *trustlist.Verifier
	did       string // the trust list issuer, pinned: the TCR's DNS walk is not repeated here
	vcURL     string
	framework string
	refresh   time.Duration
	events    *eventSink

	// ponytail: one lock around the fetch; requests wait for one retrieval per refresh interval.
	mu      sync.Mutex
	list    any
	until   time.Time // of the kept list
	expires time.Time // of its VC
}

// current is the verified trust list and its VC's expiry.
func (a *peerAdmitter) current(ctx context.Context) (any, time.Time, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.lists.Now()
	if a.list != nil && now.Before(a.until) {
		return a.list, a.expires, nil
	}
	a.list = nil
	list, expires, err := a.lists.TrustList(ctx, a.did, a.vcURL)
	if err != nil {
		return nil, time.Time{}, err
	}
	a.list, a.expires, a.until = list, expires, now.Add(a.refresh)
	if expires.Before(a.until) {
		a.until = expires
	}
	return list, expires, nil
}

// peerNames are the URI and DNS subject alternative names of the certificate the proxy forwards
// (URL-encoded PEM). The proxy has verified it against the peers' CA before the check is asked.
func peerNames(forwarded string) []string {
	raw, err := url.QueryUnescape(forwarded)
	if err != nil {
		return nil
	}
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	var names []string
	for _, u := range cert.URIs {
		names = append(names, u.String())
	}
	return append(names, cert.DNSNames...)
}

// Evaluate implements envoyhook.Evaluator.
func (a *peerAdmitter) Evaluate(ctx context.Context, req hook.Request) hook.Outcome {
	id := req.Headers.Get("X-Request-Id")
	names := peerNames(req.PeerCertificate)
	list, expires, err := a.current(ctx)
	if err != nil {
		return a.refuse(id, http.StatusServiceUnavailable, "trust_list_unavailable", reasonTrustUnreachable,
			fmt.Sprintf("framework=%s: %v", a.framework, err))
	}
	for _, name := range names {
		if trustlist.ListsActive(list, name) {
			a.events.emit("decision", id, eventPayload{State: "allowed", Detail: fmt.Sprintf(
				"peer=%s listed active in the trust list of %s, issuer %s, valid until %s",
				name, a.framework, a.did, expires.UTC().Format(time.RFC3339))})
			return hook.Outcome{Allowed: true, CorrelationID: id}
		}
	}
	return a.refuse(id, http.StatusForbidden, "peer_not_listed", reasonPeerNotListed,
		fmt.Sprintf("peer=%s not an active service of the trust list of %s", strings.Join(names, ","), a.framework))
}

func (a *peerAdmitter) refuse(id string, status int, msg, code, detail string) hook.Outcome {
	a.events.emit("decision", id, eventPayload{State: "denied", ReasonCode: code, Detail: detail})
	body, _ := json.Marshal(hook.Refusal{Error: msg, ReasonCode: code})
	return hook.Outcome{CorrelationID: id, Status: status, ReasonCode: code, Body: body, SetHeaders: []hook.Header{
		{Name: "content-type", Value: hook.ContentTypeJSON}, {Name: hook.HeaderReasonCode, Value: code}}}
}

type admitOptions struct {
	addr, tspaURL, framework, issuer, caFile, zone string
	refresh                                        time.Duration
}

func parseAdmit(args []string, env func(string) string, stderr io.Writer) (admitOptions, error) {
	var o admitOptions
	fs := flag.NewFlagSet("connector admit-peers", flag.ContinueOnError)
	fs.SetOutput(stderr)
	for _, f := range []struct {
		name, variable, def, help string
		dst                       *string
	}{
		{"addr", "CONNECTOR_ADMIT_ADDR", "127.0.0.1:50051", "ext_authz gRPC listener", &o.addr},
		{"tspa-url", "CONNECTOR_TSPA_URL", "", "the TSPA's REST base, http(s)://host[:port]/.../tspa/v1", &o.tspaURL},
		{"trust-framework", "CONNECTOR_TRUST_FRAMEWORK", "", "the trust framework whose list names the counter-connectors", &o.framework},
		{"trust-list-issuer", "CONNECTOR_TRUST_LIST_ISSUER", "", "did:web of the trust list's issuer; its DID document is fetched over HTTPS", &o.issuer},
		{"trust-ca-file", "CONNECTOR_TRUST_CA_FILE", "", "PEM CA bundle for the HTTPS fetches; default the system roots", &o.caFile},
		{"zone", "CONNECTOR_ZONE", "", "the zone this entry serves, a or b: the source of its events", &o.zone},
	} {
		def := f.def
		if v := env(f.variable); v != "" {
			def = v
		}
		fs.StringVar(f.dst, f.name, def, f.help+" ($"+f.variable+")")
	}
	fs.DurationVar(&o.refresh, "refresh", 5*time.Minute, "how long a verified list is kept, never past its VC's expiry")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	u, err := url.Parse(o.tspaURL)
	switch {
	case fs.NArg() > 0:
		return o, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	case err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "":
		return o, errors.New("--tspa-url must be an http(s) URL")
	case o.framework == "" || strings.ContainsAny(o.framework, "/?#"):
		return o, errors.New("--trust-framework is required")
	case !strings.HasPrefix(o.issuer, "did:web:"):
		return o, errors.New("--trust-list-issuer must be a did:web")
	case o.zone != "a" && o.zone != "b":
		return o, errors.New("--zone must be a or b")
	case o.refresh <= 0:
		return o, errors.New("--refresh must be positive")
	}
	return o, nil
}

func admitPeers(args []string, stdout, stderr io.Writer) int {
	o, err := parseAdmit(args, os.Getenv, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		_, _ = fmt.Fprintf(stderr, "connector: %v\n", err)
		return exitUsage
	}
	client := &http.Client{Timeout: 3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if o.caFile != "" {
		pemBytes, err := os.ReadFile(o.caFile)
		pool := x509.NewCertPool()
		if err != nil || !pool.AppendCertsFromPEM(pemBytes) {
			_, _ = fmt.Fprintf(stderr, "connector: --trust-ca-file holds no PEM certificate\n")
			return exitUsage
		}
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	}
	admitter := &peerAdmitter{lists: &trustlist.Verifier{HTTP: client, Now: time.Now}, did: o.issuer, framework: o.framework,
		vcURL: strings.TrimRight(o.tspaURL, "/") + "/" + o.framework + "/vc/trust-list", refresh: o.refresh,
		events: newEventSink(stdout, o.zone)}
	ln, err := net.Listen("tcp", o.addr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "connector: %v\n", err)
		return exitFailed
	}
	srv := grpc.NewServer(grpc.MaxRecvMsgSize(64*1024), grpc.MaxSendMsgSize(64*1024))
	envoyhook.RegisterAuthz(srv, admitter)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	go func() { <-ctx.Done(); srv.GracefulStop() }()
	if err := srv.Serve(ln); err != nil {
		_, _ = fmt.Fprintf(stderr, "connector: %v\n", err)
		return exitFailed
	}
	return exitOK
}
