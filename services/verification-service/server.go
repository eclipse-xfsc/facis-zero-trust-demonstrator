package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03/if03fixture"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/meshcaller"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/oid4vp"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/presentation"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/sdjwt"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/statuslist"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/verificationclient"
)

// Reason codes of the request endpoints (docs/contracts/reason-codes.json).
const (
	codeRequestInvalid = "CRED-REQUEST-INVALID"
	codeRequestUnknown = "CRED-REQUEST-UNKNOWN"
)

const (
	validity = 90 * time.Second  // of a signed outcome: inside IF-03's 60 to 120 s
	maxAhead = 150 * time.Second // a request's expires_at: the challenge's 120 s and 30 s of skew
)

var (
	challengePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,256}$`)
	requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
)

// server is the presentation API of docs/contracts/verification.v1.openapi.yaml.
type server struct {
	store     store
	callers   meshcaller.Authenticator // the one identity allowed to call, from the mesh
	trust     atomic.Pointer[trustState]
	sign      jose.SignFunc // the outcome key, in transit
	issuer    string        // iss of the outcomes
	kid       string        // the outcome key's id, as the consumers' trust set names it
	publicURL string        // the service's own base URL, for response_uri
	log       *slog.Logger
	now       func() time.Time
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+verificationclient.RequestsPath, s.create)
	mux.HandleFunc("POST "+verificationclient.ResponsesPath+"{id}", s.respond)
	return mux
}

// caller is the mesh identity of the request, or "" after answering 403. The contract leaves the
// authentication of the caller to the deployment; this is that deployment's second line behind the
// mesh's own authorization policy.
func (s *server) caller(w http.ResponseWriter, r *http.Request) string {
	c, err := s.callers.Authenticate(r)
	if err != nil {
		s.log.WarnContext(r.Context(), "caller refused", "path", r.URL.Path)
		answer(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
		return ""
	}
	return c.SPIFFEID
}

func (s *server) create(w http.ResponseWriter, r *http.Request) {
	caller := s.caller(w, r)
	if caller == "" {
		return
	}
	var in struct {
		Challenge string    `json:"challenge"`
		ClientID  string    `json:"client_id"`
		Audience  string    `json:"audience"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 8<<10))
	dec.DisallowUnknownFields()
	decodeErr := dec.Decode(&in)
	now := s.now()
	audience, err := url.Parse(in.Audience)
	if decodeErr != nil || !challengePattern.MatchString(in.Challenge) || in.ClientID == "" || len(in.ClientID) > 256 ||
		err != nil || !audience.IsAbs() || !in.ExpiresAt.After(now) || in.ExpiresAt.After(now.Add(maxAhead)) {
		s.refuse(w, r, http.StatusBadRequest, codeRequestInvalid, "malformed-request", "")
		return
	}
	policy := s.policyAt(now)
	if policy == nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	req := request{id: randomID(), challenge: in.Challenge, clientID: in.ClientID, audience: in.Audience, caller: caller, expires: in.ExpiresAt}
	switch err := s.store.create(r.Context(), req, now); {
	case errors.Is(err, errChallengeUsed):
		s.refuse(w, r, http.StatusBadRequest, codeRequestInvalid, "challenge-replayed", "")
		return
	case err != nil:
		s.log.ErrorContext(r.Context(), "request not stored", "err", err)
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	var accepted []string
	for vct, ok := range policy.AcceptedVCT {
		if ok {
			accepted = append(accepted, vct)
		}
	}
	s.log.InfoContext(r.Context(), "request created", "request_id", req.id, "caller", caller, "client_id", req.clientID, "audience", req.audience)
	answer(w, http.StatusCreated, map[string]any{
		"request_id": req.id, "nonce": req.challenge, "client_id": req.audience,
		"response_uri":  strings.TrimRight(s.publicURL, "/") + verificationclient.ResponsesPath + req.id,
		"response_mode": oid4vp.ResponseModeDirectPost,
		"dcql_query":    oid4vp.DCQLQuery("credential", accepted...),
		"expires_at":    req.expires.UTC().Format(time.RFC3339),
	})
}

func (s *server) respond(w http.ResponseWriter, r *http.Request) {
	caller := s.caller(w, r)
	if caller == "" {
		return
	}
	id := r.PathValue("id")
	r.Body = http.MaxBytesReader(w, r.Body, 2*oid4vp.MaxVPToken)
	formErr := r.ParseForm()
	if s.policyAt(s.now()) == nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable) // not consumed
		return
	}
	if !requestIDPattern.MatchString(id) {
		s.refuse(w, r, http.StatusNotFound, codeRequestUnknown, "unknown", "")
		return
	}
	// The request is consumed before anything is judged: one presentation per request.
	now := s.now()
	req, why, err := s.store.consume(r.Context(), id, caller, now)
	switch {
	case err != nil:
		s.log.ErrorContext(r.Context(), "request not read", "err", err)
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	case why != "":
		s.refuse(w, r, http.StatusNotFound, codeRequestUnknown, why, "")
		return
	}
	// The update may have waited on the row past the request's expiry: read the clock again and
	// judge with that time, never with the one taken before the wait.
	if now = s.now(); !req.expires.After(now) {
		s.refuse(w, r, http.StatusNotFound, codeRequestUnknown, "expired", id)
		return
	}
	// The policy at the time of judging: an issuer whose trust list expired meanwhile is out.
	policy := s.policyAt(now)
	if policy == nil {
		_ = s.store.record(r.Context(), id, "", "", "", "no-trusted-issuer")
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	if formErr != nil {
		s.refuse(w, r, http.StatusBadRequest, codeRequestInvalid, "malformed-form", id)
		return
	}
	vpToken, err := oid4vp.ParseDirectPost(r.PostForm)
	if err != nil {
		s.refuse(w, r, http.StatusBadRequest, codeRequestInvalid, "malformed-vp-token", id)
		return
	}
	binding := presentation.Binding{Nonce: req.challenge, Audience: req.audience, Now: now}
	verdict, err := policy.Judge(r.Context(), vpToken, binding)
	if err != nil {
		s.log.ErrorContext(r.Context(), "policy incomplete", "err", err)
		http.Error(w, "policy", http.StatusInternalServerError)
		return
	}
	detail := ""
	if verdict.ReasonCode == if03.CodeInvalid {
		detail = invalidDetail(*policy, vpToken, binding)
	}
	at := now.UTC().Truncate(time.Second)
	o := if03.Outcome{
		Issuer: s.issuer, OutcomeID: if03fixture.NewUUID(), ClientID: req.clientID, Challenge: req.challenge, Audience: req.audience,
		Claims: if03.Claims{Role: if03.RoleUnverified}, CredentialRefs: verdict.CredentialRefs,
		VerifiedAt: at, ExpiresAt: at.Add(validity), Status: verdict.Status, ReasonCode: verdict.ReasonCode,
	}
	if verdict.Claims != nil {
		o.Claims = if03.Claims{Role: verdict.Claims["role"], Entitlement: verdict.Claims["entitlement"]}
	}
	payload, err := json.Marshal(o) // if03.Outcome carries exactly the members of the v1 payload schema
	if err == nil {
		var jws string
		if jws, err = jose.Sign(r.Context(), jose.Header{Typ: if03.Typ, Kid: s.kid}, payload, s.sign); err == nil {
			if err := s.store.record(r.Context(), id, o.OutcomeID, o.Status, o.ReasonCode, detail); err != nil {
				s.log.ErrorContext(r.Context(), "outcome not recorded", "request_id", id, "err", err)
			}
			s.log.InfoContext(r.Context(), "outcome signed", "request_id", id, "caller", caller, "outcome_id", o.OutcomeID,
				"status", o.Status, "reason_code", o.ReasonCode, "detail", detail, "role", o.Claims.Role)
			out := map[string]any{"outcome": jws, "status": o.Status}
			if o.ReasonCode != "" {
				out["reason_code"] = o.ReasonCode
			}
			answer(w, http.StatusOK, out)
			return
		}
	}
	s.log.ErrorContext(r.Context(), "outcome not signed", "request_id", id, "err", err)
	_ = s.store.record(r.Context(), id, "", "", "", "signer-failed")
	http.Error(w, "signer", http.StatusInternalServerError)
}

// invalidDetail names why a presentation was CRED-INVALID, for the service's records: the outcome's
// reason code is IF-03's and stays CRED-INVALID, but a wrong holder key and an expired credential
// must be told apart by whoever reads the records. It verifies once more with the same library and
// classifies the error; it decides nothing.
func invalidDetail(p presentation.Policy, vpToken string, b presentation.Binding) string {
	parsed, err := sdjwt.Parse(vpToken)
	if err != nil {
		return "malformed-presentation"
	}
	_, err = sdjwt.Verify(parsed, p.Trusted, p.AcceptedVCT, sdjwt.Expect{Nonce: b.Nonce, Audience: b.Audience, Now: b.Now, Skew: p.Skew, KeyBindingMaxAge: p.KeyBindingMaxAge})
	for _, c := range []struct {
		err  error
		name string
	}{
		{sdjwt.ErrKeyBinding, "holder-binding"}, {sdjwt.ErrExpired, "credential-expired"},
		{sdjwt.ErrIssuerSignature, "issuer-signature"}, {sdjwt.ErrDisclosure, "disclosure"},
		{sdjwt.ErrVCT, "credential-type"}, {sdjwt.ErrMalformed, "malformed-presentation"},
	} {
		if errors.Is(err, c.err) {
			return c.name
		}
	}
	return "credential-claims" // verified, but without a role or a status reference
}

// refuse answers a refusal of the contract and records why; id, when set, is a consumed request.
func (s *server) refuse(w http.ResponseWriter, r *http.Request, status int, code, why, id string) {
	if id != "" {
		if err := s.store.record(r.Context(), id, "", "", code, why); err != nil {
			s.log.ErrorContext(r.Context(), "refusal not recorded", "request_id", id, "err", err)
		}
	}
	s.log.InfoContext(r.Context(), "request refused", "reason_code", code, "detail", why, "path", r.URL.Path)
	answer(w, status, map[string]any{"error": strings.ToLower(http.StatusText(status)), "reason_code": code})
}

func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func answer(w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// trustState is the policy of the last refresh and the deadline of each issuer whose listing has
// one: the expiry of the trust-list VC that listed it.
type trustState struct {
	policy presentation.Policy
	until  map[string]time.Time
}

// policyAt is the policy in force at now: an issuer whose listing has expired since the refresh
// is withdrawn at once, not at the next refresh. Nil when no issuer is left.
func (s *server) policyAt(now time.Time) *presentation.Policy {
	st := s.trust.Load()
	if st == nil {
		return nil
	}
	p := st.policy
	var expired []string
	for iss, deadline := range st.until {
		if !now.Before(deadline) {
			expired = append(expired, iss)
		}
	}
	if len(expired) > 0 {
		p.Trusted = maps.Clone(p.Trusted)
		for _, iss := range expired {
			delete(p.Trusted, iss)
		}
	}
	if len(p.Trusted) == 0 {
		return nil
	}
	return &p
}

// trustConfig is where the policy's trust comes from.
type trustConfig struct {
	keysFile       string   // credential issuers and their keys (if03.ParseIssuers' format)
	listed         lister   // TRAIN: the TCR, or the pinned fixture list
	acceptedVCT    []string // credential types accepted
	statusPrefixes []string // where status lists may be fetched from
	statusHTTP     *http.Client
}

// refresh rebuilds the policy from the issuer keys and the trust source, asking the trust source
// again every time. It fails closed: keys that cannot be read or parsed withdraw every issuer and
// the service is not ready until a refresh succeeds; an issuer the trust source does not list now
// is dropped.
func (t trustConfig) refresh(ctx context.Context, s *server) {
	keyed, err := readIssuers(t.keysFile)
	if err != nil {
		s.log.ErrorContext(ctx, "issuer keys not read; every issuer is withdrawn and the service is not ready", "err", err)
		s.trust.Store(nil)
		return
	}
	set, until, dropped := trusted(ctx, keyed, t.listed)
	if len(dropped) > 0 {
		s.log.WarnContext(ctx, "issuers not listed by the trust source", "issuers", dropped)
	}
	if len(set) == 0 {
		s.log.ErrorContext(ctx, "no trusted issuer; the service is not ready")
		s.trust.Store(nil)
		return
	}
	vct := map[string]bool{}
	for _, v := range t.acceptedVCT {
		vct[v] = true
	}
	// A new status-list client per trust set: it believes a list only when signed by a trusted issuer.
	p := presentation.Policy{Trusted: set, AcceptedVCT: vct,
		Status: &statuslist.Client{HTTP: t.statusHTTP, Trusted: set, AllowedPrefixes: t.statusPrefixes}}
	s.trust.Store(&trustState{policy: p, until: until})
	s.log.InfoContext(ctx, "trust set loaded", "issuers", len(set))
}
