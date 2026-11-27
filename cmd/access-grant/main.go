// Command access-grant signs an approval for the privileged-operations runner, with the approver's
// own key, and checks one. It holds no privileged credential: a grant does nothing until the runner,
// which checks it again on every call, performs an operation with it.
//
//	access-grant sign   -key approver.pem -kid <approver sub> < grant.json > grant.jws
//	access-grant verify -trust trust.json -caller <sub> -operation <op> < grant.jws
//
// verify checks the signature, the bounds and the role against the given trust file, not the
// runner's revocation list.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/accessrunner"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: access-grant sign|verify ...")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "sign":
		err = sign(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	default:
		err = errors.New("unknown command")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "access-grant:", err)
		os.Exit(1)
	}
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	keyFile := fs.String("key", "", "the approver's EC P-256 private key, PEM")
	kid := fs.String("kid", "", "the approver's Keycloak subject id")
	if err := fs.Parse(args); err != nil {
		return err
	}
	raw, err := os.ReadFile(*keyFile)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return errors.New("no PEM key")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	var g accessrunner.Grant
	dec := json.NewDecoder(io.LimitReader(os.Stdin, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&g); err != nil {
		return err
	}
	if g.Approver != *kid {
		return errors.New("the grant names another approver")
	}
	if g.PolicyVersion == "" {
		g.PolicyVersion = accessrunner.PolicyVersion()
	}
	compact, err := accessrunner.Sign(context.Background(), g, *kid, func(_ context.Context, in []byte) ([]byte, error) {
		sum := sha256.Sum256(in)
		r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
		if err != nil {
			return nil, err
		}
		return append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...), nil
	})
	if err != nil {
		return err
	}
	fmt.Println(compact)
	return nil
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	trustFile := fs.String("trust", "", "the runner's trust configuration, JSON")
	caller := fs.String("caller", "", "the caller's Keycloak subject id")
	operation := fs.String("operation", "", "the operation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	raw, err := os.ReadFile(*trustFile)
	if err != nil {
		return err
	}
	var trust accessrunner.Trust
	if err := json.Unmarshal(raw, &trust); err != nil {
		return err
	}
	compact, err := io.ReadAll(io.LimitReader(os.Stdin, 64<<10))
	if err != nil {
		return err
	}
	g, err := accessrunner.VerifyGrant(strings.TrimSpace(string(compact)), trust, *caller, *operation, time.Now(), func(string) (bool, error) { return false, nil })
	if err != nil {
		return err
	}
	fmt.Printf("valid for %s until %s (revocation not checked)\n", g.Subject, time.Unix(g.NotAfter, 0).UTC().Format(time.RFC3339))
	return nil
}
