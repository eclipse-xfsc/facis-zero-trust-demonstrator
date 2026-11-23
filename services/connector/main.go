// Command connector is the Connector's service: the zone's OAuth 2.0 authorization surface
// (docs/oauth2-provider.md). It issues DPoP-bound, ES256-signed access tokens through an OpenBao
// transit key, registers clients behind a policy gate with every decision audited, and publishes
// its signing key. The same binary registers a client through the registrar, the way a participant
// obtains its credentials (docs/connector.md).
//
//	connector serve       run the service until SIGTERM
//	connector register    register one client through the registrar and write its credentials file
//
// The database URL comes from --database-url or CONNECTOR_DATABASE_URL and is never logged; the
// OpenBao token and the HMAC and registrar secrets are read from files, never from a flag or a
// variable. Exit codes of serve: 0 drained, 1 failed, 2 usage. Of register: 0 registered and
// written, 1 refused by the connector, 2 usage, 3 no answer an IF-02 call gives or a local
// failure, 4 registered but the credentials not delivered.
package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
)

const (
	exitOK     = 0
	exitFailed = 1
	exitUsage  = 2
)

const usage = `usage:
  connector serve      run the service until SIGTERM; JSON records on stdout
  connector register   register one client through the registrar and write its credentials file

flags of register:
  --connector URL                    the connector's base URL ($CONNECTOR_URL)
  --registration-endpoint URL        the registration endpoint as the connector names it, when it differs
                                     from <connector>/oauth2/register ($CONNECTOR_REGISTRATION_ENDPOINT)
  --registrar-id ID                  client id of the registrar ($CONNECTOR_REGISTRAR_ID)
  --registrar-secret-file PATH       file holding the registrar's client secret ($CONNECTOR_REGISTRAR_SECRET_FILE)
  --client-name NAME                 name of the client to register
  --scope LIST                       space- or comma-separated scopes of the client
  --audience LIST                    comma-separated absolute http(s) URLs the client may name
  --grant-types LIST                 comma-separated grant types (default client_credentials)
  --metadata-file PATH               send this JSON object as the client metadata instead of the four flags above
  --delegable-scopes LIST            scopes the connector lets the registrar delegate, left out of its token
                                     ($CONNECTOR_REGISTRAR_DELEGABLE_SCOPES)
  --out PATH                         the credentials file to write, {"client_id","client_secret"}; refused when it exists
  --request-id ID                    X-Request-Id of both calls, 1 to 128 visible ASCII characters
  --timeout DURATION                 deadline for both calls together (default 30s)

flags of serve (each defaults to the CONNECTOR_* variable of the same name):
  --addr ADDR                        API listener (default :8080)
  --ops-addr ADDR                    ops listener, /healthz and /readyz for the kubelet (default :9090)
  --database-url URL                 PostgreSQL connection URL
  --openbao-url URL                  OpenBao URL, http(s)://host[:port]
  --openbao-token-file PATH          file holding the OpenBao token, read on every call
  --issuer URL                       iss of the access tokens, https://...
  --signing-key NAME                 transit key that signs the access tokens
  --signing-key-version N            pinned version of that key
  --registration-endpoint URL        absolute URL of POST /oauth2/register, as clients reach it
  --token-secret-file PATH           file holding the access-token HMAC secret (32 bytes or more)
  --registration-secret-file PATH    file holding the registration-token HMAC secret (32 bytes or more)
  --registrar-id ID                  client id of the registrar, seeded at start
  --registrar-secret-file PATH       file holding the registrar's client secret (32 bytes or more)
  --registrar-scopes LIST            comma-separated scopes of the registrar, connector:client_registration among them
  --registrar-audiences LIST         comma-separated audiences of the registrar: the registration endpoint and
                                     the resource audiences registered clients may name
  --registrar-delegable-scopes LIST  comma-separated scopes the registrar may grant to the clients it registers
                                     beyond its own token's (verified-presentation scopes)
  --vp-trusted-issuers-file PATH     JSON file of the IF-03 issuers and their public keys; enables the
                                     verified-presentation grant
  --vp-scope-map-file PATH           JSON file mapping outcome claims to scopes, required with the issuers file
  --access-token-lifespan DURATION   access-token lifetime (default 5m0s)
  --dpop-enforce=BOOL                require a DPoP proof from every client (default true)
  --dpop-nonce=BOOL                  challenge with a server DPoP nonce (default true)
  --zone a|b                         the zone this connector serves: the source of its security-state events
  --readiness-timeout DURATION       budget of one /readyz evaluation (default 2s)
  --drain-delay DURATION             time /readyz answers 503 before the listeners close on SIGTERM (default 5s)
  --shutdown-timeout DURATION        drain of the listeners on SIGTERM (default 10s)
  --log-level LEVEL                  debug, info, warn or error (default info)
`

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return exitUsage
	}
	switch args[0] {
	case "serve":
		return serve(args[1:], stdout, stderr)
	case "register":
		return register(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		_, _ = fmt.Fprint(stdout, usage)
		return exitOK
	default:
		_, _ = fmt.Fprintf(stderr, "connector: unknown command %q\n%s", args[0], usage)
		return exitUsage
	}
}
