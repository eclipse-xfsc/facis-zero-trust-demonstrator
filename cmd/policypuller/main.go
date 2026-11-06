// Command policypuller hands a zone's Argo CD the admission policy package a registry serves (ZT-12,
// chain A): it resolves the package's channel tag to a digest, verifies the cosign signature of that
// digest with the provider's own code (internal/cosignverify), refuses a package older than the one
// the zone already follows, and writes the digest into the parent Application's values, from which
// Argo CD renders the children that read the package by digest. It runs as a CronJob in Argo CD's
// namespace; each run is one pull, and the Application's annotations and Events carry what it did.
//
//	policypuller -repository harbor.example.org/facis/policy/admission -tag main \
//	  -key /etc/policy-puller/trust/cosign.pub -application ztd-admission
//
// Exit status: 0 when the digest was applied or was already the one followed, 1 when the package was
// refused (unsigned, not a policy package, older than the followed one, or no package at the tag),
// 3 when the registry or the API server could not be reached - nothing is changed in either case,
// and the zone keeps the last digest it verified - and 2 on a usage error.
//
// For a private registry, -registry-username names the user and POLICYPULLER_PASSWORD holds the
// password or token (never on the command line); the credentials are sent to that registry only.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/cosignverify"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/ociclient"
)

const namespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

func main() {
	repository := flag.String("repository", "", `the policy package repository, "host/path"`)
	tag := flag.String("tag", "main", "the channel tag the zone follows")
	keyFile := flag.String("key", "", "trusted cosign public key (PEM)")
	application := flag.String("application", "ztd-admission", "the parent Application whose values carry the digest")
	namespace := flag.String("namespace", "", "the Application's namespace (default: the pod's own)")
	plainHTTP := flag.String("insecure-plain-http-registry", "", "a registry host spoken to over http (a local test registry only)")
	username := flag.String("registry-username", "", "user for the package's registry; the password is read from POLICYPULLER_PASSWORD")
	timeout := flag.Duration("timeout", 2*time.Minute, "deadline for the whole run")
	flag.Parse()
	if *repository == "" || *keyFile == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: policypuller -repository <host/path> -key <cosign.pub> [-tag main] [-application ztd-admission]")
		os.Exit(2)
	}
	registry, repo, ok := strings.Cut(*repository, "/")
	if !ok || repo == "" {
		fmt.Fprintln(os.Stderr, "policypuller: -repository must be host/path")
		os.Exit(2)
	}
	pem, err := os.ReadFile(*keyFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "policypuller:", err)
		os.Exit(2)
	}
	keys, err := cosignverify.ParsePublicKeys(pem)
	if err != nil {
		fmt.Fprintln(os.Stderr, "policypuller:", err)
		os.Exit(2)
	}
	ns := *namespace
	if ns == "" {
		b, err := os.ReadFile(namespaceFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "policypuller: -namespace is not set and the pod's namespace cannot be read:", err)
			os.Exit(2)
		}
		ns = strings.TrimSpace(string(b))
	}
	var opts ociclient.Options
	if *plainHTTP != "" {
		opts.PlainHTTP = []string{*plainHTTP}
	}
	if *username != "" {
		opts.Credentials = map[string]ociclient.Credential{registry: {Username: *username, Password: os.Getenv("POLICYPULLER_PASSWORD")}}
	}
	kube, err := inClusterKube()
	if err != nil {
		fmt.Fprintln(os.Stderr, "policypuller:", err)
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	p := &Puller{
		Registry: registry, Repository: repo, Tag: *tag, Keys: keys,
		Namespace: ns, Application: *application,
		Client: ociclient.New(opts), Kube: kube,
	}
	out, err := p.Pull(ctx)
	var refused *Refusal
	var unavailable *Unavailable
	switch {
	case errors.As(err, &refused):
		fmt.Printf("REFUSED   %s:%s: %s: %s\n", *repository, *tag, refused.Reason, refused.Detail)
		os.Exit(1)
	case errors.As(err, &unavailable):
		fmt.Printf("UNAVAILABLE  %s\n", unavailable.Detail)
		os.Exit(3)
	case err != nil:
		fmt.Fprintln(os.Stderr, "policypuller:", err)
		os.Exit(3)
	case out.Changed:
		fmt.Printf("applied   %s@%s (created %s) to %s/%s\n", *repository, out.Digest, out.Created, ns, *application)
	default:
		fmt.Printf("current   %s@%s already followed by %s/%s\n", *repository, out.Digest, ns, *application)
	}
}
