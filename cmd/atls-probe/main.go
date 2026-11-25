// Command atls-probe exercises the attested channel of internal/atls between separate
// processes, against real cmcd attesters, and leaves a machine-readable record of every run.
//
//	atls-probe server --listen ADDR --cmcd ADDR --cert FILE --key FILE --ca FILE... --peer-id ID --record FILE [--hold DUR] [--interval DUR] [--sessions N]
//	atls-probe client --connect ADDR --cmcd ADDR --cert FILE --key FILE --ca FILE... --peer-id ID --record FILE [--hold DUR] [--interval DUR]
//	atls-probe relay  --listen ADDR --upstream ADDR --cert FILE --key FILE [--upstream-cert FILE --upstream-key FILE] --ca FILE... --record FILE
//
// server and client open the channel only through internal/atls, with one static certificate
// and the cmcd of their zone. relay is a man-in-the-middle over plain TLS that forwards the
// attestation exchange between two TLS sessions.
//
// Exit status: 0 when the channel was established (relay: bytes were forwarded both ways),
// 2 when it was not (refused, no peer), 1 for a usage or configuration error.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/cmd/atls-probe/internal/material"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/cmd/atls-probe/internal/record"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/cmd/atls-probe/internal/relay"
)

// Set at build time by the proof scripts:
//
//	-ldflags "-X main.commit=<sha> -X main.dirty=<true|false>"
var (
	commit string
	dirty  string
)

// Exit statuses.
const (
	exitEstablished = 0
	exitConfig      = 1
	exitNoChannel   = 2
)

const usage = `usage:
  atls-probe server --listen ADDR --cmcd ADDR --cert FILE --key FILE --ca FILE... --peer-id ID --record FILE [--hold DUR] [--interval DUR] [--sessions N]
  atls-probe client --connect ADDR --cmcd ADDR --cert FILE --key FILE --ca FILE... --peer-id ID --record FILE [--hold DUR] [--interval DUR]
  atls-probe relay  --listen ADDR --upstream ADDR --cert FILE --key FILE [--upstream-cert FILE --upstream-key FILE] --ca FILE... --record FILE

Run "atls-probe <mode> -h" for the flags of a mode.
exit status: 0 channel established (relay: forwarded), 2 no channel (refused, no peer), 1 usage or configuration error
`

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return exitConfig
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	p := &probe{stderr: stderr, env: record.NewEnvironment(commit, dirty == "true")}
	switch args[0] {
	case "server":
		return p.channel(ctx, "server", args[1:])
	case "client":
		return p.channel(ctx, "client", args[1:])
	case "relay":
		return p.relay(ctx, args[1:])
	case "-h", "--help", "help":
		_, _ = fmt.Fprint(stderr, usage)
		return exitEstablished
	default:
		_, _ = fmt.Fprintf(stderr, "atls-probe: unknown mode %q\n%s", args[0], usage)
		return exitConfig
	}
}

type probe struct {
	stderr io.Writer
	env    record.Environment
}

func (p *probe) logf(format string, args ...any) {
	_, _ = fmt.Fprintf(p.stderr, "%s atls-probe: %s\n",
		time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), fmt.Sprintf(format, args...))
}

// files is a flag that may be given more than once.
type files []string

func (f *files) String() string     { return strings.Join(*f, ",") }
func (f *files) Set(v string) error { *f = append(*f, v); return nil }

// common are the flags every mode takes.
type common struct {
	cert, key string
	cas       files
	record    string
}

func (c *common) register(fs *flag.FlagSet) {
	fs.StringVar(&c.cert, "cert", "", "this end's `file` with one PEM certificate (leaf first)")
	fs.StringVar(&c.key, "key", "", "`file` with the certificate's PEM private key")
	fs.Var(&c.cas, "ca", "`file` with PEM trust anchors of the zones; repeat for several")
	fs.StringVar(&c.record, "record", "", "`file` the JSON record of the run is written to")
}

// finish writes the record a last time and returns the exit status.
func (p *probe) finish(rec *record.File, code int) int {
	rec.Update(func(r *record.Record) {
		r.FinishedAt, _ = record.Stamp(time.Now())
		r.ExitCode = &code
	})
	if err := rec.Save(); err != nil {
		p.logf("%v", err)
		if code == exitEstablished {
			return exitConfig
		}
	}
	return code
}

// configError records and reports a run that never started.
func (p *probe) configError(rec *record.File, err error) int {
	p.logf("configuration error: %v", err)
	rec.Update(func(r *record.Record) {
		r.Outcome = record.OutcomeConfigError
		r.ConfigError = err.Error()
	})
	return p.finish(rec, exitConfig)
}

func (p *probe) relay(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("atls-probe relay", flag.ContinueOnError)
	fs.SetOutput(p.stderr)
	var c common
	c.register(fs)
	listen := fs.String("listen", "", "`address` the dialing end is pointed at")
	upstream := fs.String("upstream", "", "`address` of the real listener")
	upCert := fs.String("upstream-cert", "", "certificate `file` shown to the listener (default: --cert)")
	upKey := fs.String("upstream-key", "", "key `file` of --upstream-cert (default: --key)")
	acceptTimeout := fs.Duration("accept-timeout", 2*time.Minute, "how long to wait for the dialing end; 0 waits until stopped")
	handshakeTimeout := fs.Duration("handshake-timeout", 10*time.Second, "bound of each TLS handshake")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitEstablished
		}
		return exitConfig
	}

	rec := record.New(c.record, "relay", "man-in-the-middle", p.env)
	rec.Update(func(r *record.Record) {
		r.ListenAddr = *listen
		r.Relay = &record.Relay{UpstreamAddr: *upstream}
	})
	switch {
	case fs.NArg() > 0:
		return p.configError(rec, fmt.Errorf("unexpected argument %q", fs.Arg(0)))
	case c.record == "":
		return p.configError(rec, errors.New("--record is required"))
	case *listen == "" || *upstream == "":
		return p.configError(rec, errors.New("--listen and --upstream are required"))
	case (*upCert == "") != (*upKey == ""):
		return p.configError(rec, errors.New("--upstream-cert and --upstream-key go together"))
	}
	m, err := material.Load(c.cert, c.key, c.cas)
	if err != nil {
		return p.configError(rec, err)
	}
	up := m.Cert
	if *upCert != "" {
		if up, err = material.LoadCert(*upCert, *upKey); err != nil {
			return p.configError(rec, err)
		}
	}
	rec.Update(func(r *record.Record) {
		r.CertFingerprint = material.Fingerprint(m.Cert.Leaf)
		r.Identities = material.Identities(m.Cert.Leaf)
	})

	forwarded, err := relay.Run(ctx, relay.Config{
		Listen:           *listen,
		Upstream:         *upstream,
		DownstreamCert:   m.Cert,
		UpstreamCert:     up,
		Anchors:          m.Anchors,
		AcceptTimeout:    *acceptTimeout,
		HandshakeTimeout: *handshakeTimeout,
		Ready: func(addr net.Addr) {
			rec.Update(func(r *record.Record) { r.ListenAddr = addr.String() })
			_ = rec.Save()
		},
		Logf: p.logf,
	}, rec)
	if err != nil {
		return p.configError(rec, err)
	}
	if !forwarded {
		return p.finish(rec, exitNoChannel)
	}
	return p.finish(rec, exitEstablished)
}
