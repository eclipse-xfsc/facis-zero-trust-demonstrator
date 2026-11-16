package verificationclient_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/connectorclient"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/oid4vp"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/sdjwt/sdjwtfixture"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/statuslist"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/verificationclient"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/verificationclient/fixtureholder"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/verificationtest"
)

const (
	verifierIssuer = "https://verifier.zone-b.test"
	verifierKid    = "verifier-1"
	clientID       = "zone-a-token-store"
	audience       = "https://api.zone-b.test"
)

type setup struct {
	verifier *verificationtest.Verifier
	status   *verificationtest.Status
	client   *verificationclient.Client
	trusted  if03.Issuers
}

func newSetup(t *testing.T) setup {
	t.Helper()
	key := sdjwtfixture.TestOtherIssuerKey() // the verifier's own key, distinct from the credential issuer's
	status := &verificationtest.Status{}
	v := verificationtest.Start(t, verificationtest.Options{Issuer: verifierIssuer, Kid: verifierKid, Key: key, Policy: verificationtest.Policy(status)})
	holder, err := fixtureholder.New(verificationtest.Credential(t, "participant-operator", "write", time.Now()), sdjwtfixture.TestHolderKey(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return setup{verifier: v, status: status, client: &verificationclient.Client{BaseURL: v.URL, Holder: holder},
		trusted: if03.Issuers{verifierIssuer: {verifierKid: &key.PublicKey}}}
}

func challenge(value string) connectorclient.Challenge {
	return connectorclient.Challenge{Value: value, ClientID: clientID, Audience: audience, ExpiresAt: time.Now().Add(2 * time.Minute)}
}

func expect(ch connectorclient.Challenge) if03.Expect {
	return if03.Expect{ClientID: ch.ClientID, Challenge: ch.Value, Audience: ch.Audience}
}

func TestEveryCallPresentsAgainAndYieldsAFreshVerifiedOutcome(t *testing.T) {
	s := newSetup(t)
	seen := map[string]bool{}
	for _, value := range []string{"challenge-0000000000000001", "challenge-0000000000000002", "challenge-0000000000000003"} {
		ch := challenge(value)
		jws, err := s.client.Outcome(t.Context(), ch)
		if err != nil {
			t.Fatalf("outcome for %s: %v", value, err)
		}
		o, err := if03.Verify(jws, s.trusted, expect(ch), time.Now())
		if err != nil {
			t.Fatalf("the consumer refuses the hook's outcome: %v", err)
		}
		if o.Claims.Role != "participant-operator" || o.Claims.Entitlement != "write" || len(o.CredentialRefs) != 1 {
			t.Errorf("outcome content: %+v", o)
		}
		if seen[o.OutcomeID] {
			t.Errorf("outcome_id %s was issued twice", o.OutcomeID)
		}
		seen[o.OutcomeID] = true
	}
	distinct := map[string]bool{}
	for _, vp := range s.verifier.Presentations() {
		distinct[vp] = true
	}
	if len(distinct) != 3 {
		t.Errorf("three calls must be three distinct presentations, got %d", len(distinct))
	}
}

// TestOutcomesThroughTheHookFollowTheIF03Contract runs the whole exchange for each result a
// verification can have and checks what comes out of the hook against the IF-03 v1 schemas: only
// members they define, every required one, bound to the challenge the hook was called with, and
// accepted or refused by the consumer as the contract says. The outcome is produced by the
// in-test verification service; the hook passes it on unchanged and asks only for the shape of a
// compact JWS, so this pins the exchange and the test service, not a deployed one.
func TestOutcomesThroughTheHookFollowTheIF03Contract(t *testing.T) {
	headerSchema := readSchema(t, "../../docs/contracts/if03-jws-header.v1.schema.json")
	payloadSchema := readSchema(t, "../../docs/contracts/if03-verification-outcome.v1.schema.json")
	var reasonSchema struct {
		Pattern string `json:"pattern"`
	}
	if err := json.Unmarshal(payloadSchema.Properties["reason_code"], &reasonSchema); err != nil || reasonSchema.Pattern == "" {
		t.Fatal("the IF-03 schema no longer gives reason_code a pattern; this test must be revised")
	}
	reason := regexp.MustCompile(reasonSchema.Pattern)

	for _, c := range []struct {
		name       string
		arrange    func(s *setup)
		status     string
		reasonCode string
		role       string
	}{
		{"verified", func(*setup) {}, if03.StatusVerified, "", "participant-operator"},
		{"revoked", func(s *setup) { s.status.Set(statuslist.Invalid, nil) }, if03.StatusRevoked, if03.CodeRevoked, "participant-operator"},
		{"status list unavailable", func(s *setup) { s.status.Set(statuslist.Valid, statuslist.ErrUnavailable) }, if03.StatusFailed, if03.CodeStatusUnavailable, "participant-operator"},
		{"not a credential", func(s *setup) {
			s.client.Holder = holderFunc(func(oid4vp.Request) (string, error) { return "not-a-presentation", nil })
		},
			if03.StatusFailed, if03.CodeInvalid, if03.RoleUnverified},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newSetup(t)
			c.arrange(&s)
			ch := challenge("challenge-contract-0000001")
			jws, err := s.client.Outcome(t.Context(), ch)
			if err != nil {
				t.Fatalf("a signed outcome is not an error of the hook: %v", err)
			}
			parts := strings.Split(jws, ".")
			if len(parts) != 3 {
				t.Fatalf("not a compact JWS: %d parts", len(parts))
			}
			header, payload := members(t, parts[0]), members(t, parts[1])
			headerSchema.check(t, "header", header)
			payloadSchema.check(t, "payload", payload)
			var claims map[string]json.RawMessage
			if json.Unmarshal(payload["claims"], &claims) != nil {
				t.Fatal("claims is not an object")
			}
			payloadSchema.claims.check(t, "claims", claims)

			var o if03.Outcome
			raw, _ := jose.DecodeB64(parts[1])
			if err := json.Unmarshal(raw, &o); err != nil {
				t.Fatal(err)
			}
			if o.Status != c.status || o.ReasonCode != c.reasonCode || o.Claims.Role != c.role {
				t.Errorf("status %q reason %q role %q; want %q %q %q", o.Status, o.ReasonCode, o.Claims.Role, c.status, c.reasonCode, c.role)
			}
			if (o.Status == if03.StatusVerified) != (o.ReasonCode == "") || (o.ReasonCode != "" && !reason.MatchString(o.ReasonCode)) {
				t.Errorf("reason_code %q does not fit status %q", o.ReasonCode, o.Status)
			}
			if o.ClientID != ch.ClientID || o.Challenge != ch.Value || o.Audience != ch.Audience {
				t.Errorf("outcome is not bound to the challenge: %+v", o)
			}

			_, err = if03.Verify(jws, s.trusted, expect(ch), time.Now())
			var refused *if03.Error
			switch {
			case c.status == if03.StatusVerified && err != nil:
				t.Errorf("verified outcome refused: %v", err)
			case c.status != if03.StatusVerified && (!errors.As(err, &refused) || refused.Code != if03.CodeNotVerified):
				t.Errorf("a %s outcome must be refused with %s, got %v", c.status, if03.CodeNotVerified, err)
			}
		})
	}
}

func TestAnOutcomeForAnotherAudienceIsRefusedByTheConsumer(t *testing.T) {
	s := newSetup(t)
	s.verifier.Set(verificationtest.Behaviour{Audience: "https://other.zone-b.test"})
	ch := challenge("challenge-audience-0000001")
	jws, err := s.client.Outcome(t.Context(), ch)
	if err != nil {
		t.Fatal(err)
	}
	var refused *if03.Error
	if _, err := if03.Verify(jws, s.trusted, expect(ch), time.Now()); !errors.As(err, &refused) || refused.Code != if03.CodeMismatch {
		t.Errorf("got %v; want %s", err, if03.CodeMismatch)
	}
}

func TestNoOutcomeIsAFixedTextError(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef"
	good := func(base string) map[string]any {
		return map[string]any{"request_id": id, "nonce": "challenge-failure-0000001", "client_id": audience,
			"response_uri":  base + verificationclient.ResponsesPath + id,
			"response_mode": oid4vp.ResponseModeDirectPost, "dcql_query": json.RawMessage(oid4vp.DCQLQuery("c", verificationtest.CredentialVCT)),
			"expires_at": time.Now().Add(2 * time.Minute).UTC().Format(time.RFC3339)}
	}
	for _, c := range []struct {
		name string
		// request and response answer the two calls; nil means the default good answer.
		request  func(w http.ResponseWriter, base string)
		response func(w http.ResponseWriter)
		want     error
		posted   bool // whether a presentation may reach the service
	}{
		{name: "service unavailable", request: func(w http.ResponseWriter, _ string) { w.WriteHeader(http.StatusServiceUnavailable) }, want: verificationclient.ErrRequest},
		{name: "request refused", request: func(w http.ResponseWriter, _ string) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"reason_code": "CRED-REQUEST-INVALID"})
		}, want: verificationclient.ErrRequest},
		{name: "200 instead of 201", request: func(w http.ResponseWriter, base string) { writeJSON(w, http.StatusOK, good(base)) }, want: verificationclient.ErrRequest},
		{name: "another nonce", request: func(w http.ResponseWriter, base string) {
			a := good(base)
			a["nonce"] = "challenge-of-someone-else1"
			writeJSON(w, http.StatusCreated, a)
		}, want: verificationclient.ErrRequest},
		{name: "another audience", request: func(w http.ResponseWriter, base string) {
			a := good(base)
			a["client_id"] = "https://other.zone-b.test"
			writeJSON(w, http.StatusCreated, a)
		}, want: verificationclient.ErrRequest},
		{name: "another response mode", request: func(w http.ResponseWriter, base string) {
			a := good(base)
			a["response_mode"] = "fragment"
			writeJSON(w, http.StatusCreated, a)
		}, want: verificationclient.ErrRequest},
		{name: "request id unfit for a path", request: func(w http.ResponseWriter, base string) {
			a := good(base)
			a["request_id"], a["response_uri"] = "../../oauth2/token", base+"/v1/responses/../../oauth2/token"
			writeJSON(w, http.StatusCreated, a)
		}, want: verificationclient.ErrRequest},
		{name: "no query", request: func(w http.ResponseWriter, base string) {
			a := good(base)
			delete(a, "dcql_query")
			writeJSON(w, http.StatusCreated, a)
		}, want: verificationclient.ErrRequest},
		{name: "answer too large", request: func(w http.ResponseWriter, base string) {
			a := good(base)
			a["padding"] = strings.Repeat("x", 70<<10)
			writeJSON(w, http.StatusCreated, a)
		}, want: verificationclient.ErrRequest},
		{name: "redirected", request: func(w http.ResponseWriter, base string) {
			w.Header().Set("Location", base+"/elsewhere")
			w.WriteHeader(http.StatusTemporaryRedirect)
		}, want: verificationclient.ErrRequest},
		{name: "request unknown at the response", response: func(w http.ResponseWriter) {
			writeJSON(w, http.StatusNotFound, map[string]any{"reason_code": "CRED-REQUEST-UNKNOWN"})
		}, want: verificationclient.ErrResponse, posted: true},
		{name: "no outcome member", response: func(w http.ResponseWriter) { writeJSON(w, http.StatusOK, map[string]any{"status": "verified"}) },
			want: verificationclient.ErrResponse, posted: true},
		{name: "outcome is not a JWS", response: func(w http.ResponseWriter) { writeJSON(w, http.StatusOK, map[string]any{"outcome": "verified"}) },
			want: verificationclient.ErrResponse, posted: true},
		{name: "outcome with empty segments", response: func(w http.ResponseWriter) { writeJSON(w, http.StatusOK, map[string]any{"outcome": ".."}) },
			want: verificationclient.ErrResponse, posted: true},
		{name: "outcome that is not base64url", response: func(w http.ResponseWriter) {
			writeJSON(w, http.StatusOK, map[string]any{"outcome": "<html>.</html>."})
		}, want: verificationclient.ErrResponse, posted: true},
		{name: "outcome with whitespace around it", response: func(w http.ResponseWriter) { writeJSON(w, http.StatusOK, map[string]any{"outcome": " a.b.c\n"}) },
			want: verificationclient.ErrResponse, posted: true},
		{name: "response answer too large", response: func(w http.ResponseWriter) {
			writeJSON(w, http.StatusOK, map[string]any{"outcome": "a.b.c", "padding": strings.Repeat("x", 70<<10)})
		}, want: verificationclient.ErrResponse, posted: true},
		{name: "response redirected", response: func(w http.ResponseWriter) {
			w.Header().Set("Location", "/elsewhere")
			w.WriteHeader(http.StatusTemporaryRedirect)
		}, want: verificationclient.ErrResponse, posted: true},
		{name: "signer failure", response: func(w http.ResponseWriter) { w.WriteHeader(http.StatusInternalServerError) }, want: verificationclient.ErrResponse, posted: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			var posted, elsewhere atomic.Int32
			var base string
			mux := http.NewServeMux()
			mux.HandleFunc("POST /v1/requests", func(w http.ResponseWriter, _ *http.Request) {
				if c.request != nil {
					c.request(w, base)
					return
				}
				writeJSON(w, http.StatusCreated, good(base))
			})
			mux.HandleFunc("POST /v1/responses/{id}", func(w http.ResponseWriter, _ *http.Request) {
				posted.Add(1)
				if c.response == nil {
					writeJSON(w, http.StatusOK, map[string]any{"outcome": "a.b.c"})
					return
				}
				c.response(w)
			})
			mux.HandleFunc("/", func(http.ResponseWriter, *http.Request) { elsewhere.Add(1) })
			srv := httptest.NewServer(mux)
			defer srv.Close()
			base = srv.URL

			s := newSetup(t)
			s.client.BaseURL = srv.URL
			// A client of the caller's own that would follow redirects: the hook still must not.
			s.client.HTTP = &http.Client{}
			jws, err := s.client.Outcome(t.Context(), challenge("challenge-failure-0000001"))
			if !errors.Is(err, c.want) || jws != "" {
				t.Fatalf("got %q, %v; want %v", jws, err, c.want)
			}
			if stage := verificationclient.Stage(err); (c.want == verificationclient.ErrRequest) != (stage == "request") || (c.want == verificationclient.ErrResponse) != (stage == "response") {
				t.Errorf("stage %q for %v", stage, err)
			}
			if strings.Contains(err.Error(), "CRED-") || strings.Contains(err.Error(), srv.URL) {
				t.Errorf("the error repeats what the service said: %v", err)
			}
			if (posted.Load() > 0) != c.posted {
				t.Errorf("presentations posted: %d", posted.Load())
			}
			if elsewhere.Load() != 0 {
				t.Error("the client followed the service somewhere else")
			}
		})
	}
}

func TestThePresentationGoesToTheConfiguredServiceOnly(t *testing.T) {
	s := newSetup(t)
	var foreign atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { foreign.Add(1) }))
	defer other.Close()

	// A service in front of the real one that names another host as the response_uri.
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstream, err := http.NewRequestWithContext(r.Context(), r.Method, s.verifier.URL+r.URL.Path, r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		upstream.Header = r.Header.Clone()
		resp, err := http.DefaultClient.Do(upstream)
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		if uri, ok := body["response_uri"].(string); ok {
			body["response_uri"] = other.URL + uri[len(s.verifier.URL):]
		}
		writeJSON(w, resp.StatusCode, body)
	}))
	defer front.Close()

	s.client.BaseURL = front.URL
	real := s.client.Holder
	var told string
	s.client.Holder = holderFunc(func(req oid4vp.Request) (string, error) {
		told = req.ResponseURI
		return real.Present(context.Background(), req)
	})
	ch := challenge("challenge-samehost-0000001")
	jws, err := s.client.Outcome(t.Context(), ch)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(told, front.URL+verificationclient.ResponsesPath) {
		t.Errorf("the holder was told to respond at %q, not at the configured service", told)
	}
	if _, err := if03.Verify(jws, s.trusted, expect(ch), time.Now()); err != nil {
		t.Errorf("outcome: %v", err)
	}
	if foreign.Load() != 0 {
		t.Error("the presentation was posted to the address the answer named")
	}
}

func TestAHolderThatPresentsNothingStopsBeforeThePost(t *testing.T) {
	for name, holder := range map[string]verificationclient.Holder{
		"error":     holderFunc(func(oid4vp.Request) (string, error) { return "", errors.New("wallet locked: pin 1234") }),
		"empty":     holderFunc(func(oid4vp.Request) (string, error) { return "", nil }),
		"oversized": holderFunc(func(oid4vp.Request) (string, error) { return strings.Repeat("a", oid4vp.MaxVPToken+1), nil }),
	} {
		t.Run(name, func(t *testing.T) {
			s := newSetup(t)
			s.client.Holder = holder
			_, err := s.client.Outcome(t.Context(), challenge("challenge-noholder-0000001"))
			if !errors.Is(err, verificationclient.ErrHolder) || strings.Contains(err.Error(), "1234") || verificationclient.Stage(err) != "holder" {
				t.Fatalf("got %v", err)
			}
			if len(s.verifier.Presentations()) != 0 {
				t.Error("something was presented")
			}
		})
	}
}

func TestTheHolderIsAskedForTheChallengeAndTheAudience(t *testing.T) {
	s := newSetup(t)
	real := s.client.Holder
	var got oid4vp.Request
	s.client.Holder = holderFunc(func(req oid4vp.Request) (string, error) {
		got = req
		return real.Present(context.Background(), req)
	})
	ch := challenge("challenge-request-00000001")
	if _, err := s.client.Outcome(t.Context(), ch); err != nil {
		t.Fatal(err)
	}
	if got.Nonce != ch.Value || got.ClientID != ch.Audience || !strings.HasPrefix(got.ResponseURI, s.verifier.URL+verificationclient.ResponsesPath) ||
		!strings.Contains(string(got.DCQL), verificationtest.CredentialVCT) {
		t.Errorf("request handed to the holder: %+v", got)
	}
}

func TestTheCallIsBoundedByItsTimeout(t *testing.T) {
	s := newSetup(t)
	s.verifier.Set(verificationtest.Behaviour{Hang: true})
	s.client.Timeout = 300 * time.Millisecond
	start := time.Now()
	_, err := s.client.Outcome(t.Context(), challenge("challenge-timeout-00000001"))
	if !errors.Is(err, verificationclient.ErrResponse) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v; want no outcome because the deadline passed", err)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("a silent service held the call for %s", took)
	}
}

func TestACancelledCallIsToldFromAFailure(t *testing.T) {
	s := newSetup(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := s.client.Outcome(ctx, challenge("challenge-cancel-000000001"))
	if !errors.Is(err, verificationclient.ErrRequest) || !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v; want no request because the caller cancelled", err)
	}
	if _, err := s.client.Outcome(t.Context(), challenge("challenge-cancel-000000002")); err != nil || errors.Is(err, context.Canceled) {
		t.Errorf("a live call after it: %v", err)
	}
}

func TestAHolderOutlivedByItsCallIsToldFromARefusal(t *testing.T) {
	s := newSetup(t)
	ctx, cancel := context.WithCancel(t.Context())
	s.client.Holder = holderFunc(func(oid4vp.Request) (string, error) {
		cancel() // the caller gives up while the holder is at work
		return "", errors.New("interrupted")
	})
	_, err := s.client.Outcome(ctx, challenge("challenge-holdercancel-001"))
	if !errors.Is(err, verificationclient.ErrHolder) || !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v; want a holder failure that names the cancellation", err)
	}
}

func TestAnUnreachableServiceYieldsNoOutcome(t *testing.T) {
	s := newSetup(t)
	gone := httptest.NewServer(http.NotFoundHandler())
	gone.Close() // nothing listens at its address any more
	s.client.BaseURL = gone.URL
	_, err := s.client.Outcome(t.Context(), challenge("challenge-gone-0000000001"))
	if !errors.Is(err, verificationclient.ErrRequest) || strings.Contains(err.Error(), gone.URL) {
		t.Fatalf("got %v", err)
	}
}

func TestStageNamesOnlyTheHooksOwnErrors(t *testing.T) {
	for want, err := range map[string]error{
		"config": verificationclient.ErrConfig, "request": verificationclient.ErrRequest,
		"holder": verificationclient.ErrHolder, "response": verificationclient.ErrResponse,
		"": errors.New("something else"),
	} {
		if got := verificationclient.Stage(err); got != want {
			t.Errorf("Stage(%v) = %q; want %q", err, got, want)
		}
	}
	if verificationclient.Stage(nil) != "" {
		t.Error("a nil error has a stage")
	}
}

func TestAServiceRefusingRequestsYieldsNoOutcome(t *testing.T) {
	s := newSetup(t)
	s.verifier.Set(verificationtest.Behaviour{RefuseRequests: true})
	if _, err := s.client.Outcome(t.Context(), challenge("challenge-refused-00000001")); !errors.Is(err, verificationclient.ErrRequest) {
		t.Fatalf("got %v", err)
	}
}

func TestAMisconfiguredClientIsRefusedBeforeAnyCall(t *testing.T) {
	s := newSetup(t)
	for name, c := range map[string]verificationclient.Client{
		"no holder":         {BaseURL: s.verifier.URL},
		"no url":            {Holder: s.client.Holder},
		"url with a query":  {BaseURL: s.verifier.URL + "?x=1", Holder: s.client.Holder},
		"not http":          {BaseURL: "file:///etc/passwd", Holder: s.client.Holder},
		"negative timeout":  {BaseURL: s.verifier.URL, Holder: s.client.Holder, Timeout: -time.Second},
		"timeout too large": {BaseURL: s.verifier.URL, Holder: s.client.Holder, Timeout: verificationclient.MaxTimeout + time.Second},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := c.Outcome(t.Context(), challenge("challenge-config-000000001")); !errors.Is(err, verificationclient.ErrConfig) {
				t.Errorf("got %v", err)
			}
		})
	}
	good := challenge("challenge-config-000000002")
	for name, edit := range map[string]func(*connectorclient.Challenge){
		"no challenge value": func(c *connectorclient.Challenge) { c.Value = "" },
		"no client":          func(c *connectorclient.Challenge) { c.ClientID = "" },
		"no audience":        func(c *connectorclient.Challenge) { c.Audience = "" },
		"no expiry":          func(c *connectorclient.Challenge) { c.ExpiresAt = time.Time{} },
	} {
		ch := good
		edit(&ch)
		if _, err := s.client.Outcome(t.Context(), ch); !errors.Is(err, verificationclient.ErrConfig) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	if n := s.verifier.Calls(); n != 0 {
		t.Errorf("a misconfigured client reached the service %d times", n)
	}
	if _, err := s.client.Outcome(t.Context(), good); err != nil || s.verifier.Calls() != 2 {
		t.Errorf("the same client, complete: %v after %d calls", err, s.verifier.Calls())
	}
}

type holderFunc func(oid4vp.Request) (string, error)

func (f holderFunc) Present(_ context.Context, req oid4vp.Request) (string, error) { return f(req) }

func writeJSON(w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func members(t *testing.T, segment string) map[string]json.RawMessage {
	t.Helper()
	raw, err := jose.DecodeB64(segment)
	if err != nil {
		t.Fatal(err)
	}
	out, err := jose.ParseObject(raw)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// schema is the part of a JSON Schema this test reads: which members an object may and must have.
type schema struct {
	Properties           map[string]json.RawMessage `json:"properties"`
	Required             []string                   `json:"required"`
	AdditionalProperties *bool                      `json:"additionalProperties"`
	claims               *schema
}

func readSchema(t *testing.T, path string) *schema {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var s schema
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	if len(s.Properties) == 0 || len(s.Required) == 0 || s.AdditionalProperties == nil || *s.AdditionalProperties {
		t.Fatalf("%s: the schema no longer closes its member set; this test must be revised", path)
	}
	if nested, ok := s.Properties["claims"]; ok {
		var c schema
		if err := json.Unmarshal(nested, &c); err != nil || len(c.Properties) == 0 {
			t.Fatalf("%s: claims schema unreadable", path)
		}
		s.claims = &c
	}
	return &s
}

func (s *schema) check(t *testing.T, what string, got map[string]json.RawMessage) {
	t.Helper()
	for name := range got {
		if _, ok := s.Properties[name]; !ok {
			t.Errorf("%s member %q is not in the IF-03 schema", what, name)
		}
	}
	for _, name := range s.Required {
		if _, ok := got[name]; !ok {
			t.Errorf("%s lacks the required member %q", what, name)
		}
	}
}
