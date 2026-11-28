// Command attestation-provision provisions a zone's mock attestation evidence from its
// configuration in Git (deployment/attestation/<zone>.json, ADR-0011 class 3).
//
//	attestation-provision render --zone FILE --out DIR [--signed-at RFC3339]
//	attestation-provision check  --zone FILE --cmcd ADDR --ca FILE...
//
// render writes, under DIR: unsigned/manifest.json and unsigned/image-description.json, the
// reference values the pipeline signs (CMC's metatool) and the zone's estserver serves;
// measurements.json, the container measurement log the zone's cmcd reads (ctrLog); and
// expected.json, each component's template hash and the aggregate the evidence must sign.
//
// check is the startup check of a zone's gateway: it obtains a fresh report from the zone's cmcd,
// verifies it against the metadata CAs, and requires its measured values to be those of the
// configuration. It prints what it verified as JSON.
//
// Exit status: 0 on success; 2 when check obtained a report and rejected it (verification failed,
// or its measured values differ from the configuration); 3 when no report could be obtained from
// cmcd; 1 for a usage or configuration error.
package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/atls/provision"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "render":
		err = render(os.Args[2:])
	case "check":
		err = check(os.Args[2:])
	default:
		usage()
	}
	if code := exitCode(err); code != 0 {
		fmt.Fprintln(os.Stderr, "attestation-provision:", err)
		os.Exit(code)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: attestation-provision render --zone FILE --out DIR [--signed-at RFC3339]\n"+
		"       attestation-provision check --zone FILE --cmcd ADDR --ca FILE...")
	os.Exit(1)
}

type checkFailed struct{ error }

func (e checkFailed) Unwrap() error { return e.error }

// exitCode is the exit status for an error of render or check.
func exitCode(err error) int {
	var failed checkFailed
	switch {
	case err == nil:
		return 0
	case errors.Is(err, provision.ErrNoReport):
		return 3
	case errors.As(err, &failed):
		return 2
	}
	return 1
}

// expected is what the evidence of a zone must carry: written by render, printed by check.
type expected struct {
	Zone       string            `json:"zone"`
	Components map[string]string `json:"template_hashes"`
	Aggregate  string            `json:"aggregate"`
}

func render(args []string) error {
	fs := flag.NewFlagSet("render", flag.ContinueOnError)
	zoneFile := fs.String("zone", "", "the zone's configuration in Git")
	out := fs.String("out", "", "output directory")
	signedAt := fs.String("signed-at", "", "the signing time, RFC 3339 (default now)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *zoneFile == "" || *out == "" || fs.NArg() != 0 {
		return errors.New("render needs --zone and --out")
	}
	at := time.Now()
	if *signedAt != "" {
		var err error
		if at, err = time.Parse(time.RFC3339, *signedAt); err != nil {
			return fmt.Errorf("--signed-at: %w", err)
		}
	}
	z, err := provision.Load(*zoneFile)
	if err != nil {
		return err
	}
	metadata, err := z.Metadata(at)
	if err != nil {
		return err
	}
	log, err := z.MeasurementLog()
	if err != nil {
		return err
	}
	ms, err := z.Measurements()
	if err != nil {
		return err
	}
	exp := expected{Zone: z.Zone, Components: map[string]string{}, Aggregate: fmt.Sprintf("%x", provision.Aggregate(ms))}
	for _, m := range ms {
		exp.Components[m.Name] = fmt.Sprintf("%x", m.TemplateHash)
	}
	expJSON, err := json.MarshalIndent(exp, "", "  ")
	if err != nil {
		return err
	}
	files := map[string][]byte{"measurements.json": log, "expected.json": expJSON}
	for name, data := range metadata {
		files[filepath.Join("unsigned", name)] = data
	}
	for name, data := range files {
		path := filepath.Join(*out, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			return err
		}
	}
	return nil
}

type caFlags []string

func (c *caFlags) String() string     { return strings.Join(*c, ",") }
func (c *caFlags) Set(v string) error { *c = append(*c, v); return nil }

func check(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	zoneFile := fs.String("zone", "", "the zone's configuration in Git")
	cmcd := fs.String("cmcd", "", "the zone's cmcd, host:port")
	timeout := fs.Duration("timeout", 30*time.Second, "how long to wait for cmcd")
	var cas caFlags
	fs.Var(&cas, "ca", "a metadata CA certificate (PEM); repeatable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *zoneFile == "" || *cmcd == "" || len(cas) == 0 || fs.NArg() != 0 {
		return errors.New("check needs --zone, --cmcd and at least one --ca")
	}
	z, err := provision.Load(*zoneFile)
	if err != nil {
		return err
	}
	var roots []*x509.Certificate
	for _, f := range cas {
		raw, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		for block, rest := pem.Decode(raw); block != nil; block, rest = pem.Decode(rest) {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return fmt.Errorf("%s: %w", f, err)
			}
			roots = append(roots, cert)
		}
	}
	if len(roots) == 0 {
		return errors.New("no CA certificate in --ca")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	ev, err := provision.Check(ctx, *cmcd, roots, z)
	if err != nil {
		return checkFailed{err}
	}
	out := expected{Zone: z.Zone, Components: map[string]string{}, Aggregate: fmt.Sprintf("%x", ev.Aggregate)}
	for name, h := range ev.Verified {
		out.Components[name] = fmt.Sprintf("%x", h)
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}
