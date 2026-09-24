// Command imageverify verifies images with the admission provider's own code (internal/cosignverify):
// signature by a trusted key, SBOM and mock attestations, single-platform linux/amd64. The release
// runs it on every image digest it produced; any refusal fails the run.
//
//	go run ./cmd/imageverify -key cosign.pub -repository ghcr.io/org/repo ghcr.io/org/repo/svc@sha256:...
//
// For a private registry, -registry-username names the user and IMAGEVERIFY_PASSWORD holds the password
// or token (never on the command line); the credentials are sent to the repository's registry only.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/cosignverify"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/ociclient"
)

func main() {
	keyFile := flag.String("key", "", "trusted cosign public key (PEM)")
	repository := flag.String("repository", "", `allowed repository prefix, "host/path"`)
	plainHTTP := flag.String("insecure-plain-http-registry", "", "a registry host spoken to over http (a local test registry only)")
	username := flag.String("registry-username", "", "user for the repository's registry; the password is read from IMAGEVERIFY_PASSWORD")
	flag.Parse()
	if *keyFile == "" || *repository == "" || flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: imageverify -key <cosign.pub> -repository <host/path> <image@sha256:...>...")
		os.Exit(2)
	}
	pem, err := os.ReadFile(*keyFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "imageverify:", err)
		os.Exit(2)
	}
	keys, err := cosignverify.ParsePublicKeys(pem)
	if err != nil {
		fmt.Fprintln(os.Stderr, "imageverify:", err)
		os.Exit(2)
	}
	var opts ociclient.Options
	if *plainHTTP != "" {
		opts.PlainHTTP = []string{*plainHTTP}
	}
	if *username != "" {
		registry, _, _ := strings.Cut(*repository, "/")
		opts.Credentials = map[string]ociclient.Credential{registry: {Username: *username, Password: os.Getenv("IMAGEVERIFY_PASSWORD")}}
	}
	v := cosignverify.New(ociclient.New(opts), &cosignverify.Policy{Repositories: []string{*repository}, Keys: keys, Revision: "release"}, 1)
	failed := 0
	for _, image := range flag.Args() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		r := v.VerifyImage(ctx, image)
		cancel()
		if r.OK() {
			fmt.Printf("verified  %s\n", image)
			continue
		}
		failed++
		fmt.Printf("REFUSED   %s: %s: %s\n", image, r.Code, r.Detail)
	}
	if failed > 0 {
		os.Exit(1)
	}
}
