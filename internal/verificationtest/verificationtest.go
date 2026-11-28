// Package verificationtest runs a verification service for tests: the two endpoints of the
// verification contract, the presentation policy of internal/presentation and an IF-03 outcome
// signed with a process key. It is test support only. It keeps its requests in memory, signs with a
// key the test hands it and can be told to misbehave, so it is never a deployment's verifier.
package verificationtest

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03/if03fixture"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/oid4vp"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/presentation"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/sdjwt"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/sdjwt/sdjwtfixture"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/statuslist"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/verificationclient"
)

// Reason codes of the request endpoints (registered in docs/contracts/reason-codes.json).
const (
	CodeRequestInvalid = "CRED-REQUEST-INVALID"
	CodeRequestUnknown = "CRED-REQUEST-UNKNOWN"
)

const validity = 90 * time.Second

// MaxAhead is how far in the future a request's expires_at may lie: the connector's challenge
// lifetime (120 s) and the clock skew the outcome's consumers allow (30 s).
const MaxAhead = 150 * time.Second

// Options configure the verifier.
type Options struct {
	Issuer string            // iss of the outcomes
	Kid    string            // the signing key's id
	Key    *ecdsa.PrivateKey // signs the outcomes
	// Policy judges every presentation. Its Status is usually a *Status, so that a test can revoke.
	Policy presentation.Policy
	Now    func() time.Time // nil: time.Now
}

// Behaviour is what a test can make the verifier do wrong.
type Behaviour struct {
	RefuseRequests bool   // answer 503 to every new request
	Hang           bool   // never answer a presentation (until the caller gives up)
	Audience       string // sign outcomes for this audience instead of the request's
}

// Verifier is a running verification service.
type Verifier struct {
	URL string

	o        Options
	mu       sync.Mutex
	behave   Behaviour
	open     map[string]request // request_id → request
	outcomes []if03.Outcome     // every outcome signed, in order (Raw unset)
	judged   []string           // every vp_token judged, in order
	calls    int                // every request that reached either endpoint
}

type request struct {
	challenge, clientID, audience string
	expires                       time.Time
}

// Start runs the verifier until the test ends.
func Start(t testing.TB, o Options) *Verifier {
	t.Helper()
	if o.Issuer == "" || o.Kid == "" || o.Key == nil {
		t.Fatal("verificationtest: issuer, kid and key are required")
	}
	v := &Verifier{o: o, open: map[string]request{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+verificationclient.RequestsPath, v.create)
	mux.HandleFunc("POST "+verificationclient.ResponsesPath+"{id}", v.respond)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	v.URL = srv.URL
	return v
}

// Set changes the verifier's behaviour.
func (v *Verifier) Set(b Behaviour) { v.mu.Lock(); v.behave = b; v.mu.Unlock() }

// Outcomes are the outcomes signed so far, oldest first.
func (v *Verifier) Outcomes() []if03.Outcome {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]if03.Outcome(nil), v.outcomes...)
}

// Calls is how many requests reached the verifier, whatever it answered.
func (v *Verifier) Calls() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.calls
}

// Presentations are the vp_tokens judged so far, oldest first.
func (v *Verifier) Presentations() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]string(nil), v.judged...)
}

func (v *Verifier) now() time.Time {
	if v.o.Now != nil {
		return v.o.Now()
	}
	return time.Now()
}

var challengePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,256}$`)

func (v *Verifier) create(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Challenge string    `json:"challenge"`
		ClientID  string    `json:"client_id"`
		Audience  string    `json:"audience"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 8<<10))
	dec.DisallowUnknownFields()
	decodeErr := dec.Decode(&in) // before the lock: a slow body holds up no one else
	now := v.now()
	v.mu.Lock()
	defer v.mu.Unlock()
	v.calls++
	if v.behave.RefuseRequests {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	audience, err := url.Parse(in.Audience)
	if decodeErr != nil || !challengePattern.MatchString(in.Challenge) || in.ClientID == "" || len(in.ClientID) > 256 ||
		err != nil || !audience.IsAbs() ||
		!in.ExpiresAt.After(now) || in.ExpiresAt.After(now.Add(MaxAhead)) {
		refuse(w, http.StatusBadRequest, CodeRequestInvalid)
		return
	}
	for id, open := range v.open {
		if !open.expires.After(now) {
			delete(v.open, id) // an expired request is no longer open
			continue
		}
		if open.challenge == in.Challenge {
			refuse(w, http.StatusBadRequest, CodeRequestInvalid)
			return
		}
	}
	id := randomID()
	v.open[id] = request{challenge: in.Challenge, clientID: in.ClientID, audience: in.Audience, expires: in.ExpiresAt}
	var accepted []string
	for vct, ok := range v.o.Policy.AcceptedVCT {
		if ok {
			accepted = append(accepted, vct)
		}
	}
	answer(w, http.StatusCreated, map[string]any{
		"request_id": id, "nonce": in.Challenge, "client_id": in.Audience,
		"response_uri":  v.URL + verificationclient.ResponsesPath + id,
		"response_mode": oid4vp.ResponseModeDirectPost,
		"dcql_query":    oid4vp.DCQLQuery("credential", accepted...),
		"expires_at":    in.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

func (v *Verifier) respond(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	r.Body = http.MaxBytesReader(w, r.Body, 2*oid4vp.MaxVPToken)
	formErr := r.ParseForm()

	// The request is consumed before anything is judged: one presentation per challenge.
	v.mu.Lock()
	v.calls++
	req, known := v.open[id]
	delete(v.open, id)
	behave := v.behave
	v.mu.Unlock()
	now := v.now()
	if !known || !req.expires.After(now) {
		refuse(w, http.StatusNotFound, CodeRequestUnknown)
		return
	}
	if behave.Hang {
		<-r.Context().Done()
		return
	}
	if formErr != nil {
		refuse(w, http.StatusBadRequest, CodeRequestInvalid)
		return
	}
	vpToken, err := oid4vp.ParseDirectPost(r.PostForm)
	if err != nil {
		refuse(w, http.StatusBadRequest, CodeRequestInvalid)
		return
	}
	verdict, err := v.o.Policy.Judge(r.Context(), vpToken, presentation.Binding{Nonce: req.challenge, Audience: req.audience, Now: now})
	if err != nil {
		http.Error(w, "policy", http.StatusInternalServerError)
		return
	}
	audience := req.audience
	if behave.Audience != "" {
		audience = behave.Audience
	}
	o := if03.Outcome{
		Issuer: v.o.Issuer, OutcomeID: if03fixture.NewUUID(), ClientID: req.clientID, Challenge: req.challenge, Audience: audience,
		Claims: if03.Claims{Role: if03.RoleUnverified}, CredentialRefs: verdict.CredentialRefs,
		VerifiedAt: now.UTC().Truncate(time.Second), ExpiresAt: now.UTC().Truncate(time.Second).Add(validity),
		Status: verdict.Status, ReasonCode: verdict.ReasonCode,
	}
	if verdict.Claims != nil {
		o.Claims = if03.Claims{Role: verdict.Claims["role"], Entitlement: verdict.Claims["entitlement"]}
	}
	jws, err := Sign(r.Context(), o, v.o.Kid, v.o.Key)
	if err != nil {
		http.Error(w, "signer", http.StatusInternalServerError)
		return
	}
	v.mu.Lock()
	v.outcomes = append(v.outcomes, o)
	v.judged = append(v.judged, vpToken)
	v.mu.Unlock()
	out := map[string]any{"outcome": jws, "status": o.Status}
	if o.ReasonCode != "" {
		out["reason_code"] = o.ReasonCode
	}
	answer(w, http.StatusOK, out)
}

// Sign is o as a compact IF-03 JWS. The payload is o itself: if03.Outcome carries the members of
// the v1 payload schema, so the producer here and the consumer's parser cannot drift apart.
func Sign(ctx context.Context, o if03.Outcome, kid string, key *ecdsa.PrivateKey) (string, error) {
	raw, err := json.Marshal(o)
	if err != nil {
		return "", err
	}
	return jose.Sign(ctx, jose.Header{Typ: if03.Typ, Kid: kid}, raw, func(_ context.Context, in []byte) ([]byte, error) {
		return if03fixture.SignES256(key, in)
	})
}

// The test credential's issuer, key id and type; its keys are sdjwtfixture's test keys.
const (
	CredentialIssuer = "https://issuer.fixture.invalid"
	CredentialKid    = "fixture-issuer-1"
	CredentialVCT    = "https://facis.example/credentials/participant"
)

// Credential issues a test SD-JWT VC with role and entitlement disclosed, as a holder keeps it:
// "<issuer JWT>~<disclosure>~<disclosure>~". Its holder key is sdjwtfixture.TestHolderKey.
func Credential(t testing.TB, role, entitlement string, issuedAt time.Time) string {
	t.Helper()
	issued, err := sdjwtfixture.Issue(context.Background(), sdjwtfixture.IssueOptions{
		IssuerKey: sdjwtfixture.TestIssuerKey(), Kid: CredentialKid, Issuer: CredentialIssuer, VCT: CredentialVCT,
		JTI:    "urn:uuid:" + if03fixture.NewUUID(),
		Claims: []sdjwtfixture.Claim{{Name: "role", Value: role}, {Name: "entitlement", Value: entitlement}}, Disclosable: []string{"role", "entitlement"},
		Holder: &sdjwtfixture.TestHolderKey().PublicKey, IssuedAt: issuedAt,
		Status: &sdjwt.StatusRef{URI: "https://status.fixture.invalid/lists/participant.jwt", Index: 42},
	})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := sdjwtfixture.Select(issued, "role", "entitlement")
	if err != nil {
		t.Fatal(err)
	}
	return credential
}

// Policy trusts the test credential's issuer and type and reads revocation from status.
func Policy(status statuslist.Checker) presentation.Policy {
	return presentation.Policy{
		Trusted:     if03.Issuers{CredentialIssuer: {CredentialKid: &sdjwtfixture.TestIssuerKey().PublicKey}},
		AcceptedVCT: map[string]bool{CredentialVCT: true}, Status: status,
	}
}

// Status is a statuslist.Checker a test sets: the state of every credential's entry.
type Status struct {
	mu     sync.Mutex
	status statuslist.Status
	err    error
}

var _ statuslist.Checker = (*Status)(nil)

// Set makes every later check answer status, or fail with err when it is not nil.
func (s *Status) Set(status statuslist.Status, err error) {
	s.mu.Lock()
	s.status, s.err = status, err
	s.mu.Unlock()
}

// Status implements statuslist.Checker.
func (s *Status) Status(context.Context, string, string, int) (statuslist.Status, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status, s.err
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

func refuse(w http.ResponseWriter, status int, code string) {
	answer(w, status, map[string]any{"error": strings.ToLower(http.StatusText(status)), "reason_code": code})
}
