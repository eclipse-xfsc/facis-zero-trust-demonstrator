// Command train-resolve-probe verifies one attested peer against TRAIN with the gateway's own code
// (internal/trainresolve) and records what happened, so that the resolution can be proven without
// a channel: the proofs hand it the peer's identity and measurement as the attested channel would,
// point it at a Trust Content Resolver and read the verdict, the reason code, whether the answer
// came from the cache, and what TRAIN held.
//
//	go run ./cmd/train-resolve-probe -tcr http://127.0.0.1:8087 -identity spiffe://zone-b.example/gateway \
//	    -digest <64 hex>[,<64 hex>] [-pointer DOMAIN]... [-ca FILE] [-ttl 300s] [-resolve-timeout 5s] \
//	    [-handshake-timeout 10s] [-repeat N | -until-code CODE -deadline DUR] [-interval 2s] [-record FILE]
//
// One process keeps one verifier, so repeated verifications share its cache: -repeat N verifies N
// times, -until-code CODE verifies every -interval until the verdict carries that code or -deadline
// passes, and records when the transition happened, which is how a staleness window is measured.
// Every verification is one JSON line (schema train-resolve-probe-record/v1) on stdout and, with
// -record, appended to that file; -until-code ends with a transition line
// (train-resolve-probe-transition/v1). Exit 0 when the last verification accepted the peer (or, with
// -until-code, when the code was observed before the deadline), 2 when it refused (or the code was
// not observed), 1 for a usage or configuration error. No secret is read or written.
package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/trainresolve"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// list is a repeatable string flag.
type list []string

func (l *list) String() string     { return strings.Join(*l, ",") }
func (l *list) Set(s string) error { *l = append(*l, s); return nil }

type record struct {
	Schema        string   `json:"schema"`
	At            string   `json:"ts"`
	Attempt       int      `json:"attempt"`
	Identity      string   `json:"identity"`
	Key           string   `json:"key,omitempty"`
	Pointers      []string `json:"pointers,omitempty"`
	Outcome       string   `json:"outcome"`
	Code          string   `json:"code,omitempty"`
	Reason        string   `json:"reason,omitempty"`
	FromCache     bool     `json:"fromCache"`
	ExpectedCount int      `json:"expectedCount"`
	EntryUUID     string   `json:"entryUUID,omitempty"`
	TrustList     string   `json:"trustList,omitempty"`
	ElapsedMs     int64    `json:"elapsedMs"`
	Stats         stats    `json:"stats"`
}

type stats struct {
	Hits, Misses, Flights, Refusals int64
}

type transition struct {
	Schema            string `json:"schema"`
	UntilCode         string `json:"untilCode"`
	Attempts          int    `json:"attempts"`
	Observed          bool   `json:"observed"`
	FirstAcceptedAt   string `json:"firstAcceptedAt,omitempty"`
	TransitionAt      string `json:"transitionAt,omitempty"`
	TransitionAfterMs int64  `json:"transitionAfterMs,omitempty"`
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("train-resolve-probe", flag.ContinueOnError)
	fs.SetOutput(stderr)
	tcrURL := fs.String("tcr", "", "origin of the Trust Content Resolver, scheme and host only")
	identity := fs.String("identity", "", "the peer's authenticated identity, as the channel reports it (a SPIFFE ID or a DNS SAN)")
	digests := fs.String("digest", "", "the peer's measurement(s), 64 hex characters each, comma separated; empty to probe a peer without a measurement")
	hashAlg := fs.String("hash-alg", "SHA-256", "the algorithm the evidence states for the digests")
	var pointers list
	fs.Var(&pointers, "pointer", "trust-scheme pointer (zone domain); repeatable; without it the pointer is the host of the identity URI")
	caFile := fs.String("ca", "", "PEM file with the roots the resolver's certificate must chain to (default: the system roots)")
	requireDID := fs.Bool("require-did-verified", false, "also require the resolver's DID configuration check")
	ttl := fs.Duration("ttl", trainresolve.DefaultTTL, "how long a resolution is served from the cache")
	resolveTimeout := fs.Duration("resolve-timeout", trainresolve.DefaultResolveTimeout, "budget of one resolution at the resolver")
	handshakeTimeout := fs.Duration("handshake-timeout", 10*time.Second, "deadline of one verification, as the channel's handshake would give it")
	repeat := fs.Int("repeat", 1, "verify this many times")
	untilCode := fs.String("until-code", "", "verify every -interval until the verdict carries this reason code or -deadline passes")
	deadline := fs.Duration("deadline", 10*time.Minute, "with -until-code: how long to wait for the code")
	interval := fs.Duration("interval", 2*time.Second, "pause between verifications")
	recordFile := fs.String("record", "", "append every record line to this file as well")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	complain := func(a ...any) int {
		_, _ = fmt.Fprintln(stderr, append([]any{"train-resolve-probe:"}, a...)...)
		return 1
	}
	if *tcrURL == "" || *identity == "" || fs.NArg() != 0 || *repeat < 1 || *interval < 0 {
		return complain("usage: train-resolve-probe -tcr <origin> -identity <id> [-digest <hex>[,<hex>]] [-pointer DOMAIN]... [-ca FILE] [-repeat N | -until-code CODE -deadline DUR] [-interval DUR] [-record FILE]")
	}

	var roots *x509.CertPool
	if *caFile != "" {
		pem, err := os.ReadFile(*caFile)
		if err != nil {
			return complain(err)
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return complain("no certificate in", *caFile)
		}
	}
	tcr, err := trainresolve.NewTCR(trainresolve.TCRConfig{BaseURL: *tcrURL, Client: trainresolve.NewHTTPClient(roots), RequireDIDVerified: *requireDID})
	if err != nil {
		return complain(err)
	}
	key := trainresolve.DefaultKey
	if len(pointers) > 0 {
		key = trainresolve.WithPointers(pointers...)
	}
	v := trainresolve.New(tcr, key)
	v.TTL = *ttl
	v.ResolveTimeout = *resolveTimeout

	peer := trainresolve.Peer{Identity: *identity}
	for _, d := range strings.Split(*digests, ",") {
		if d = strings.TrimSpace(d); d != "" {
			peer.Digests = append(peer.Digests, trainresolve.Digest{Hex: d, HashAlg: *hashAlg})
		}
	}

	out := stdout
	if *recordFile != "" {
		f, err := os.OpenFile(*recordFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return complain(err)
		}
		defer func() { _ = f.Close() }()
		out = io.MultiWriter(stdout, f)
	}
	enc := json.NewEncoder(out)

	verify := func(attempt int) record {
		rec := record{Schema: "train-resolve-probe-record/v1", Attempt: attempt, Identity: *identity}
		if l, err := key(*identity); err == nil {
			rec.Key, rec.Pointers = l.Key, l.Pointers
		}
		ctx, cancel := context.WithTimeout(context.Background(), *handshakeTimeout)
		start := time.Now()
		out, err := v.Check(ctx, peer)
		cancel()
		rec.ElapsedMs = time.Since(start).Milliseconds()
		rec.At = start.UTC().Format(time.RFC3339Nano)
		rec.FromCache = out.FromCache
		rec.ExpectedCount, rec.EntryUUID, rec.TrustList = len(out.Expected.Values), out.Expected.EntryUUID, out.Expected.TrustList
		if err == nil {
			rec.Outcome = "accepted"
		} else {
			rec.Outcome = "refused"
			rec.Code = trainresolve.CodeOf(err)
			var e *trainresolve.Error
			if errors.As(err, &e) {
				rec.Reason = e.Reason
				if e.Err != nil {
					rec.Reason += ": " + e.Err.Error()
				}
			} else {
				rec.Reason = err.Error()
			}
		}
		rec.Stats = stats{v.Stats.Hits.Load(), v.Stats.Misses.Load(), v.Stats.Flights.Load(), v.Stats.Refusals.Load()}
		_ = enc.Encode(rec)
		return rec
	}

	if *untilCode == "" {
		var last record
		for i := 1; i <= *repeat; i++ {
			if i > 1 {
				time.Sleep(*interval)
			}
			last = verify(i)
		}
		if last.Outcome == "accepted" {
			return 0
		}
		return 2
	}

	tr := transition{Schema: "train-resolve-probe-transition/v1", UntilCode: *untilCode}
	end := time.Now().Add(*deadline)
	var firstAccepted time.Time
	for attempt := 1; ; attempt++ {
		rec := verify(attempt)
		tr.Attempts = attempt
		at, _ := time.Parse(time.RFC3339Nano, rec.At)
		if rec.Outcome == "accepted" && firstAccepted.IsZero() {
			firstAccepted = at
			tr.FirstAcceptedAt = rec.At
		}
		if rec.Code == *untilCode {
			tr.Observed = true
			tr.TransitionAt = rec.At
			if !firstAccepted.IsZero() {
				tr.TransitionAfterMs = at.Sub(firstAccepted).Milliseconds()
			}
			break
		}
		if time.Now().Add(*interval).After(end) {
			break
		}
		time.Sleep(*interval)
	}
	_ = enc.Encode(tr)
	if tr.Observed {
		return 0
	}
	return 2
}
