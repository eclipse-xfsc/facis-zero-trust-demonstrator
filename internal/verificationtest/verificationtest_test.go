package verificationtest_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/sdjwt/sdjwtfixture"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/verificationclient"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/verificationtest"
)

// The request rules of the verification contract (docs/contracts/verification.v1.openapi.yaml), as
// this test service keeps them: the rules a caller of the hook relies on without exercising them.

type service struct {
	t     *testing.T
	v     *verificationtest.Verifier
	clock atomic.Int64 // offset from the wall clock
}

func start(t *testing.T) *service {
	t.Helper()
	s := &service{t: t}
	s.v = verificationtest.Start(t, verificationtest.Options{Issuer: "https://verifier.zone-b.test", Kid: "verifier-1",
		Key: sdjwtfixture.TestOtherIssuerKey(), Policy: verificationtest.Policy(&verificationtest.Status{}), Now: s.now})
	return s
}

func (s *service) now() time.Time { return time.Now().Add(time.Duration(s.clock.Load())) }

type answer struct {
	status int
	body   map[string]any
}

func (s *service) post(path, contentType string, body []byte) answer {
	s.t.Helper()
	resp, err := http.Post(s.v.URL+path, contentType, bytes.NewReader(body))
	if err != nil {
		s.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	a := answer{status: resp.StatusCode}
	_ = json.NewDecoder(resp.Body).Decode(&a.body)
	return a
}

func (s *service) request(challenge string, ahead time.Duration, edit func(map[string]any)) answer {
	s.t.Helper()
	body := map[string]any{"challenge": challenge, "client_id": "zone-a-token-store", "audience": "https://api.zone-b.test",
		"expires_at": s.now().Add(ahead).UTC().Format(time.RFC3339Nano)}
	if edit != nil {
		edit(body)
	}
	raw, _ := json.Marshal(body)
	return s.post(verificationclient.RequestsPath, "application/json", raw)
}

func (s *service) respond(id any, form url.Values) answer {
	s.t.Helper()
	return s.post(verificationclient.ResponsesPath+id.(string), "application/x-www-form-urlencoded", []byte(form.Encode()))
}

func (a answer) want(t *testing.T, what string, status int, code string) {
	t.Helper()
	got, _ := a.body["reason_code"].(string)
	if a.status != status || got != code {
		t.Errorf("%s: answered %d %q; want %d %q", what, a.status, got, status, code)
	}
}

func TestARequestIsAnsweredOnce(t *testing.T) {
	s := start(t)
	created := s.request("challenge-once-00000000001", time.Minute, nil)
	if created.status != http.StatusCreated {
		t.Fatalf("request: %d", created.status)
	}
	id := created.body["request_id"]
	vp := url.Values{"vp_token": {"not-a-presentation"}}
	first := s.respond(id, vp)
	if first.status != http.StatusOK || first.body["status"] != "failed" || first.body["reason_code"] != "CRED-INVALID" || first.body["outcome"] == nil {
		t.Fatalf("a presentation that is not a credential is still judged and answered with an outcome: %+v", first)
	}
	s.respond(id, vp).want(t, "the same request again", http.StatusNotFound, verificationtest.CodeRequestUnknown)
	s.respond("0123456789abcdef0123456789abcdef", vp).want(t, "a request never created", http.StatusNotFound, verificationtest.CodeRequestUnknown)
	if n := len(s.v.Outcomes()); n != 1 {
		t.Errorf("%d outcomes were signed for one request", n)
	}
}

func TestAMalformedResponseConsumesTheRequest(t *testing.T) {
	s := start(t)
	id := s.request("challenge-malformed-000001", time.Minute, nil).body["request_id"]
	s.respond(id, url.Values{"state": {"x"}}).want(t, "no vp_token", http.StatusBadRequest, verificationtest.CodeRequestInvalid)
	s.respond(id, url.Values{"vp_token": {"not-a-presentation"}}).want(t, "the request after a malformed response", http.StatusNotFound, verificationtest.CodeRequestUnknown)
	if n := len(s.v.Outcomes()); n != 0 {
		t.Errorf("%d outcomes were signed", n)
	}
}

func TestOneRequestIsOpenPerChallenge(t *testing.T) {
	s := start(t)
	const challenge = "challenge-open-00000000001"
	first := s.request(challenge, time.Minute, nil)
	if first.status != http.StatusCreated {
		t.Fatalf("request: %d", first.status)
	}
	s.request(challenge, time.Minute, nil).want(t, "a second request while the first is open", http.StatusBadRequest, verificationtest.CodeRequestInvalid)
	if other := s.request("challenge-open-00000000002", time.Minute, nil); other.status != http.StatusCreated {
		t.Errorf("another challenge meanwhile: %d", other.status)
	}
	// Answered, the challenge has no open request any more.
	s.respond(first.body["request_id"], url.Values{"vp_token": {"not-a-presentation"}})
	if again := s.request(challenge, time.Minute, nil); again.status != http.StatusCreated {
		t.Errorf("a request for the challenge after the first was answered: %d", again.status)
	}
}

func TestARequestEndsWithItsChallenge(t *testing.T) {
	s := start(t)
	const challenge = "challenge-expiry-000000001"
	created := s.request(challenge, time.Minute, nil)
	if created.status != http.StatusCreated {
		t.Fatalf("request: %d", created.status)
	}
	s.clock.Add(int64(61 * time.Second))
	s.respond(created.body["request_id"], url.Values{"vp_token": {"not-a-presentation"}}).
		want(t, "a presentation after the challenge expired", http.StatusNotFound, verificationtest.CodeRequestUnknown)
	if n := len(s.v.Outcomes()); n != 0 {
		t.Errorf("%d outcomes were signed for an expired request", n)
	}

	// An expired request that was never answered does not keep its challenge closed.
	const unanswered = "challenge-expiry-000000002"
	if s.request(unanswered, time.Minute, nil).status != http.StatusCreated {
		t.Fatal("request")
	}
	s.clock.Add(int64(61 * time.Second))
	if again := s.request(unanswered, time.Minute, nil); again.status != http.StatusCreated {
		t.Errorf("a request for a challenge whose earlier request expired: %d", again.status)
	}
}

func TestTheRequestBodyIsChecked(t *testing.T) {
	s := start(t)
	if ok := s.request("challenge-bounds-000000001", verificationtest.MaxAhead-time.Second, nil); ok.status != http.StatusCreated {
		t.Fatalf("an expiry just inside the bound: %d", ok.status)
	}
	for name, c := range map[string]struct {
		ahead time.Duration
		edit  func(map[string]any)
	}{
		"expiry past the bound":   {ahead: verificationtest.MaxAhead + 2*time.Second},
		"expiry in the past":      {ahead: -time.Second},
		"challenge too short":     {ahead: time.Minute, edit: func(b map[string]any) { b["challenge"] = "short" }},
		"challenge with a slash":  {ahead: time.Minute, edit: func(b map[string]any) { b["challenge"] = "challenge/0000000000000001" }},
		"no client":               {ahead: time.Minute, edit: func(b map[string]any) { b["client_id"] = "" }},
		"client id too long":      {ahead: time.Minute, edit: func(b map[string]any) { b["client_id"] = string(bytes.Repeat([]byte("c"), 257)) }},
		"audience not a URI":      {ahead: time.Minute, edit: func(b map[string]any) { b["audience"] = "zone-b api" }},
		"audience without scheme": {ahead: time.Minute, edit: func(b map[string]any) { b["audience"] = "api.zone-b.test" }},
		"unknown member":          {ahead: time.Minute, edit: func(b map[string]any) { b["wallet"] = "ocm" }},
	} {
		s.request("challenge-bounds-000000002", c.ahead, c.edit).want(t, name, http.StatusBadRequest, verificationtest.CodeRequestInvalid)
	}
	if not := s.post(verificationclient.RequestsPath, "application/json", []byte("{")); not.status != http.StatusBadRequest {
		t.Errorf("a body that is not JSON: %d", not.status)
	}
}

func TestBehaviourSwitches(t *testing.T) {
	s := start(t)
	s.v.Set(verificationtest.Behaviour{RefuseRequests: true})
	if refused := s.request("challenge-switch-000000001", time.Minute, nil); refused.status != http.StatusServiceUnavailable {
		t.Errorf("a refusing service answered %d", refused.status)
	}
	s.v.Set(verificationtest.Behaviour{})
	if ok := s.request("challenge-switch-000000001", time.Minute, nil); ok.status != http.StatusCreated {
		t.Errorf("after the switch was cleared: %d", ok.status)
	}
	if n := s.v.Calls(); n != 2 {
		t.Errorf("%d calls counted; want 2", n)
	}
}
