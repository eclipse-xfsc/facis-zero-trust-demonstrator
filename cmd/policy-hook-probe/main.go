// Command policy-hook-probe verifies the guard's policy hook against a real Envoy.
//
//	policy-hook-probe serve --listen ADDR --fixtures DIR [--ops ADDR] [--events FILE] [--source NAME] ...
//	policy-hook-probe prove all|PROOF --out DIR --envoy-image REF --fixtures DIR --templates DIR [options]
//
// serve runs the policy hook as its own process: the ext_authz and ext_proc services on one
// gRPC listener, deciding from the contract fixtures, with a health endpoint beside it.
//
// prove starts an echo upstream, the hook (as a child process, so it can be killed and frozen)
// and Envoy from the pinned image, drives requests through Envoy and writes the records of what
// happened to --out. The proofs are header-mutation, deny-response, filter-parity, latency and
// fail-closed; "all" runs them in that order against one upstream and one hook.
//
// Exit status: 0 when the proofs ran and their records were written (the verdict is drawn from
// the records by scripts/verify-policy-hook/verify.sh), 1 when they could not run.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

const usage = `usage:
  policy-hook-probe serve --listen ADDR --fixtures DIR [--ops ADDR] [--events FILE] [--source NAME] [--run-id ID]
                          [--source-id SPIFFE-ID] [--published-base-url URL] [--peer-zone ZONE] [--audience AUD]
                          [--decision-timeout DUR]
  policy-hook-probe prove all|PROOF --out DIR --envoy-image REF --fixtures DIR --templates DIR
                          [--timeout DUR] [--margin DUR] [--requests N] [--warmup N] [--concurrency LIST]

PROOF is one of: header-mutation, deny-response, filter-parity, latency, fail-closed.
Run "policy-hook-probe <mode> -h" for the flags of a mode.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	switch args[0] {
	case "serve":
		return serve(ctx, args[1:], stderr)
	case "prove":
		return prove(ctx, args[1:], stderr)
	case "-h", "--help", "help":
		_, _ = fmt.Fprint(stderr, usage)
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "policy-hook-probe: unknown mode %q\n%s", args[0], usage)
		return 1
	}
}
