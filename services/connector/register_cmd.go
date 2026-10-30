package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/connectorclient"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/dpopproof"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
)

// Exit codes of register, beyond the shared ones: refused is the connector's answer, unreachable
// covers everything that left no answer an IF-02 call gives (and a local failure before anything
// was sent), not written means the client exists but its credentials were not delivered.
const (
	exitRefused     = 1
	exitUnreachable = 3
	exitNotWritten  = 4
)

type registerOptions struct {
	connector, endpoint        string
	registrarID, registrarFile string
	clientName, scope          string
	audience, grantTypes       []string
	delegable                  []string
	metadataFile, out          string
	requestID                  string
	timeout                    time.Duration
}

// parseRegister reads the register flags. The environment fills what the command line did not
// set, after parsing, as serve does.
func parseRegister(args []string, env func(string) string, stderr io.Writer) (registerOptions, error) {
	var o registerOptions
	var scope, audience, grantTypes, delegable string
	fs := flag.NewFlagSet("connector register", flag.ContinueOnError)
	fs.SetOutput(stderr)
	strs := []struct {
		name, variable, def, help string
		dst                       *string
	}{
		{"connector", "CONNECTOR_URL", "", "the connector's base URL; /oauth2/token and /oauth2/register below it", &o.connector},
		{"registration-endpoint", "CONNECTOR_REGISTRATION_ENDPOINT", "", "the registration endpoint as the connector names it, when it differs from <connector>/oauth2/register", &o.endpoint},
		{"registrar-id", "CONNECTOR_REGISTRAR_ID", "", "client id of the registrar", &o.registrarID},
		{"registrar-secret-file", "CONNECTOR_REGISTRAR_SECRET_FILE", "", "file holding the registrar's client secret", &o.registrarFile},
		{"client-name", "", "", "name of the client to register", &o.clientName},
		{"scope", "", "", "space- or comma-separated scopes of the client", &scope},
		{"audience", "", "", "comma-separated absolute http(s) URLs the client may name", &audience},
		{"grant-types", "", "client_credentials", "comma-separated grant types of the client", &grantTypes},
		{"delegable-scopes", "CONNECTOR_REGISTRAR_DELEGABLE_SCOPES", "", "comma-separated scopes the connector lets the registrar delegate (its --registrar-delegable-scopes): left out of the registrar's token, which need not carry them", &delegable},
		{"metadata-file", "", "", "send this JSON object as the client metadata instead of the four flags above", &o.metadataFile},
		{"out", "", "", "the credentials file to write; refused when it exists", &o.out},
		{"request-id", "", "", "X-Request-Id of both calls (1 to 128 visible ASCII characters), the correlation id of the connector's records", &o.requestID},
	}
	for _, s := range strs {
		help := s.help
		if s.variable != "" {
			help += " ($" + s.variable + ")"
		}
		fs.StringVar(s.dst, s.name, s.def, help)
	}
	fs.DurationVar(&o.timeout, "timeout", 30*time.Second, "deadline for both calls together")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if fs.NArg() > 0 {
		return o, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	for _, s := range strs {
		if s.variable != "" && !set[s.name] {
			if v := env(s.variable); v != "" {
				*s.dst = v
			}
		}
	}
	if o.connector == "" {
		return o, errors.New("missing: set --connector or CONNECTOR_URL")
	}
	base, err := connectorclient.BaseURL(o.connector)
	if err != nil {
		return o, errors.New("--connector must be an absolute http(s):// URL without credentials, query or fragment")
	}
	o.connector = base
	if o.endpoint == "" {
		o.endpoint = base + "/oauth2/register"
	}
	if !absoluteHTTPURL(o.endpoint) {
		return o, errors.New("--registration-endpoint must be an absolute http(s):// URL without credentials, query or fragment")
	}
	if o.registrarID == "" {
		return o, errors.New("missing: set --registrar-id or CONNECTOR_REGISTRAR_ID")
	}
	if o.registrarFile == "" {
		return o, errors.New("missing: set --registrar-secret-file or CONNECTOR_REGISTRAR_SECRET_FILE")
	}
	if o.out == "" {
		return o, errors.New("missing: set --out to the credentials file to write")
	}
	if o.requestID != "" && !validCorrelationID(o.requestID) {
		return o, errors.New("--request-id must be 1 to 128 visible ASCII characters, or the connector replaces it")
	}
	if o.timeout <= 0 {
		return o, errors.New("--timeout must be longer than 0")
	}
	o.delegable = splitList(delegable)
	if o.metadataFile != "" {
		for _, name := range []string{"client-name", "scope", "audience", "grant-types"} {
			if set[name] {
				return o, errors.New("--metadata-file replaces --client-name, --scope, --audience and --grant-types; set one or the other")
			}
		}
		return o, nil
	}
	// The connector would refuse what follows too, but only after the registrar was issued a token.
	o.scope = strings.Join(splitList(strings.ReplaceAll(scope, " ", ",")), " ")
	o.audience = splitList(audience)
	o.grantTypes = splitList(grantTypes)
	if o.clientName == "" || o.scope == "" || len(o.audience) == 0 {
		return o, errors.New("missing: set --client-name, --scope and --audience, or --metadata-file")
	}
	if !validClientName(o.clientName) {
		return o, errors.New("--client-name must be 1 to 128 printable characters, without leading or trailing spaces")
	}
	if !validScopes(o.scope) {
		return o, errors.New("--scope must list distinct scope tokens, never " + connectorclient.RegistrationScope)
	}
	if !distinct(o.audience) {
		return o, errors.New("--audience must not repeat a URL")
	}
	for _, a := range o.audience {
		if !absoluteHTTPURL(a) {
			return o, errors.New("--audience must list absolute http(s):// URLs without credentials, query or fragment")
		}
	}
	if len(o.grantTypes) == 0 || !distinct(o.grantTypes) {
		return o, errors.New("--grant-types must name one or more distinct grant types")
	}
	return o, nil
}

// register registers one client through the registrar and writes its credentials file. It prints
// one line on success and the refusal's reason on stderr otherwise; never a secret, a token, a
// proof or a header.
func register(args []string, stdout, stderr io.Writer) int {
	o, err := parseRegister(args, os.Getenv, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		_, _ = fmt.Fprintf(stderr, "connector register: %v\n", err)
		return exitUsage
	}
	secret, err := readSecret(o.registrarFile, "registrar secret")
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "connector register: %v\n", err)
		return exitUsage
	}
	// The registrar's token must carry what the client registers: the registration scope plus the
	// client's scopes, and the registration endpoint plus the client's audiences. A registrar not
	// allowed them is refused the token, which is the right answer before anything is registered.
	// A delegable scope is the exception: the connector grants it to the client through the
	// registrar's delegation ceiling, so the token need not carry it, and cannot when it is a
	// verified-presentation scope.
	reg := connectorclient.Registration{ClientName: o.clientName, GrantTypes: o.grantTypes, Scope: o.scope, Audience: o.audience}
	tokenScope := registrarTokenScope(o.scope, o.delegable)
	tokenAudience := append([]string{o.endpoint}, o.audience...)
	if o.metadataFile != "" {
		metadata, err := os.ReadFile(o.metadataFile)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "connector register: metadata file: %v\n", err)
			return exitUsage
		}
		members, err := jose.ParseObject(metadata)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "connector register: metadata file: not one JSON object without duplicate members")
			return exitUsage
		}
		reg = connectorclient.Registration{Metadata: metadata}
		// A malformed scope or audience member is the policy's to refuse; here it only shapes the token.
		var audience []string
		if raw, present := members["audience"]; present {
			_ = json.Unmarshal(raw, &audience)
		}
		tokenAudience = append([]string{o.endpoint}, audience...)
		scope, _, _ := jose.String(members, "scope")
		tokenScope = registrarTokenScope(scope, o.delegable)
	}
	// The file is reserved before any call: an existing target or a directory that cannot take it
	// is known before anything is registered, and the target appears only complete.
	file, err := connectorclient.ReserveCredentials(o.out)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "connector register: %v\n", err)
		return exitUsage
	}
	defer file.Abandon()

	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	key, err := dpopproof.NewProcessKey()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "connector register: local failure, nothing sent: %v\n", err)
		return exitUnreachable
	}
	// --timeout bounds both calls; no per-request cap below it.
	client := &connectorclient.Client{BaseURL: o.connector, ClientID: o.registrarID, ClientSecret: string(secret),
		RequestID: o.requestID, HTTP: &http.Client{}}
	issued, err := client.ClientCredentialsToken(ctx, key, tokenScope, tokenAudience)
	if err != nil {
		return reportRegisterError(stderr, "registrar token", err)
	}
	creds, err := client.Register(ctx, key, o.endpoint, issued.AccessToken, reg)
	if err != nil {
		return reportRegisterError(stderr, "registration", err)
	}
	if err := file.Write(creds); err != nil {
		_, _ = fmt.Fprintf(stderr, "connector register: registered client %s but could not write its credentials: %v\n"+
			"the client exists without its secret delivered: delete its oauth2_client row and run again\n", creds.ClientID, err)
		return exitNotWritten
	}
	_, _ = fmt.Fprintf(stdout, "registered client_id=%s credentials=%s\n", creds.ClientID, o.out)
	return exitOK
}

// reportRegisterError writes what a failed call allows to be said and maps it to an exit code.
func reportRegisterError(stderr io.Writer, call string, err error) int {
	var e *connectorclient.Error
	if !errors.As(err, &e) {
		_, _ = fmt.Fprintf(stderr, "connector register: %s: %v\n", call, err)
		return exitUnreachable
	}
	switch e.Kind {
	case connectorclient.KindRefused:
		line := fmt.Sprintf("connector register: %s refused: %s (%d)", call, e.Reason, e.Status)
		if e.Description != "" {
			line += ": " + e.Description
		}
		_, _ = fmt.Fprintln(stderr, line)
		return exitRefused
	case connectorclient.KindUnread:
		_, _ = fmt.Fprintf(stderr, "connector register: %s: %v\n"+
			"the client exists without its secret delivered: delete its oauth2_client row and run again\n", call, err)
		return exitNotWritten
	case connectorclient.KindProof:
		_, _ = fmt.Fprintf(stderr, "connector register: %s: local failure, nothing sent: %v\n", call, err)
		return exitUnreachable
	}
	_, _ = fmt.Fprintf(stderr, "connector register: %s: %v\n", call, err)
	if call == "registration" {
		_, _ = fmt.Fprintln(stderr, "the client may have been registered without its secret delivered: "+
			"look for its client_name in oauth2_client before running again")
	}
	return exitUnreachable
}

// registrarTokenScope is the scope the registrar's token asks for: the registration scope plus the
// client's scopes that are not delegable.
func registrarTokenScope(clientScope string, delegable []string) string {
	scopes := []string{connectorclient.RegistrationScope}
	for _, s := range strings.Fields(clientScope) {
		if !slices.Contains(delegable, s) && !slices.Contains(scopes, s) {
			scopes = append(scopes, s)
		}
	}
	return strings.Join(scopes, " ")
}
