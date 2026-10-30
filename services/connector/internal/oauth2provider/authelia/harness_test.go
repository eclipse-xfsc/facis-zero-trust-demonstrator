package authelia

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/dpoptest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider/memstore"
)

const (
	testSecret    = "s3cret-for-tests"
	resourceScope = "resource.read"
)

// harness runs a provider behind a real HTTP server. Every test builds its
// own, so no state is shared between tests.
type harness struct {
	t        *testing.T
	stores   oauth2provider.Stores
	provider oauth2provider.Provider

	// replay records what the provider hands to the replay store.
	replay *recordingReplayStore

	// clockOffset shifts the stores' clock forward, in nanoseconds.
	clockOffset atomic.Int64

	tokenURL    string
	registerURL string
	resourceURL string
}

func newHarness(t *testing.T, configure func(*oauth2provider.Config)) *harness {
	t.Helper()

	h := &harness{t: t}

	// The registration endpoint URL is part of the provider's configuration,
	// so the server has to exist before the provider does.
	var handler atomic.Value

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.Load().(http.Handler).ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)

	h.tokenURL = server.URL + "/token"
	h.registerURL = server.URL + "/register"
	h.resourceURL = server.URL + "/resource"

	cfg := oauth2provider.Config{
		Secret: []byte("token-signing-secret-at-least-32-bytes!"),
		DPoP: oauth2provider.DPoPConfig{
			ProofLifespan: time.Minute,
			ClockSkew:     10 * time.Second,
			NonceLifespan: time.Minute,
		},
		Registration: oauth2provider.RegistrationConfig{
			Secret:      []byte("registration-secret-at-least-32-bytes!!"),
			EndpointURL: h.registerURL,
			GrantTypes:  []string{"client_credentials"},
		},
	}

	if configure != nil {
		configure(&cfg)
	}

	h.stores = memstore.New(func() time.Time {
		return time.Now().Add(time.Duration(h.clockOffset.Load()))
	})

	h.replay = &recordingReplayStore{inner: h.stores.DPoPReplay}
	h.stores.DPoPReplay = h.replay

	provider, err := New(cfg, h.stores)
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}

	h.provider = provider

	mux := http.NewServeMux()
	mux.Handle("/token", provider.TokenHandler())
	mux.Handle("/register", provider.RegistrationHandler())
	mux.HandleFunc("/resource", h.serveResource)
	handler.Store(http.Handler(mux))

	return h
}

// recordingReplayStore passes every call through and keeps what it was given.
type recordingReplayStore struct {
	inner oauth2provider.DPoPReplayStore

	mu   sync.Mutex
	uses []oauth2provider.DPoPProofUse
}

func (s *recordingReplayStore) MarkUsed(ctx context.Context, use oauth2provider.DPoPProofUse) (bool, error) {
	s.mu.Lock()
	s.uses = append(s.uses, use)
	s.mu.Unlock()

	return s.inner.MarkUsed(ctx, use)
}

func (s *recordingReplayStore) last() oauth2provider.DPoPProofUse {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.uses) == 0 {
		return oauth2provider.DPoPProofUse{}
	}

	return s.uses[len(s.uses)-1]
}

// serveResource is a minimal protected resource.
func (h *harness) serveResource(w http.ResponseWriter, r *http.Request) {
	access, err := h.provider.ValidateResourceRequest(r)
	if err != nil {
		refusal, ok := err.(*oauth2provider.Error)
		if !ok {
			http.Error(w, "unexpected error type", http.StatusInternalServerError)

			return
		}

		if refusal.DPoPNonce != "" {
			w.Header().Set("DPoP-Nonce", refusal.DPoPNonce)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(refusal.Status)
		_ = json.NewEncoder(w).Encode(map[string]any{oauth2provider.ReasonField: refusal.Code})

		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"client_id": access.ClientID, "jkt": access.Thumbprint})
}

func (h *harness) advanceClock(d time.Duration) { h.clockOffset.Add(int64(d)) }

// seedClient provisions a client directly, as an operator would.
func (h *harness) seedClient(id string, dpopBound bool, scopes, audience []string) {
	h.t.Helper()

	hash, err := bcrypt.GenerateFromPassword([]byte(testSecret), bcrypt.MinCost)
	if err != nil {
		h.t.Fatalf("hash secret: %v", err)
	}

	err = h.stores.Clients.CreateClient(h.t.Context(), oauth2provider.Client{
		ID:         id,
		SecretHash: hash,
		GrantTypes: []string{"client_credentials"},
		Scopes:     scopes,
		Audience:   audience,
		DPoPBound:  dpopBound,
	})
	if err != nil {
		h.t.Fatalf("seed client: %v", err)
	}
}

// result is a decoded HTTP response.
type result struct {
	status int
	header http.Header
	body   map[string]any
}

func (r result) str(member string) string {
	value, _ := r.body[member].(string)

	return value
}

func (r result) reason() oauth2provider.Code {
	return oauth2provider.Code(r.str(oauth2provider.ReasonField))
}

func (h *harness) do(request *http.Request) result {
	h.t.Helper()

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		h.t.Fatalf("%s %s: %v", request.Method, request.URL, err)
	}
	raw, err := io.ReadAll(response.Body)
	if closeErr := response.Body.Close(); err == nil {
		err = closeErr
	}

	if err != nil {
		h.t.Fatalf("read response: %v", err)
	}

	out := result{status: response.StatusCode, header: response.Header}
	if len(raw) != 0 {
		if err = json.Unmarshal(raw, &out.body); err != nil {
			h.t.Fatalf("decode response %q: %v", raw, err)
		}
	}

	return out
}

// token requests an access token with the client_credentials grant. proof may
// be empty.
func (h *harness) token(clientID, proof string, scopes []string, audience string) result {
	h.t.Helper()

	form := url.Values{"grant_type": {"client_credentials"}}
	if len(scopes) != 0 {
		form.Set("scope", strings.Join(scopes, " "))
	}

	if audience != "" {
		form.Set("audience", audience)
	}

	return h.tokenWithSecret(clientID, testSecret, proof, form)
}

func (h *harness) tokenWithSecret(clientID, secret, proof string, form url.Values) result {
	h.t.Helper()

	request, err := http.NewRequest(http.MethodPost, h.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		h.t.Fatal(err)
	}

	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(secret))

	if proof != "" {
		request.Header.Set("DPoP", proof)
	}

	return h.do(request)
}

// register posts RFC 7591 client metadata. authorization is the complete
// Authorization header value and may be empty.
func (h *harness) register(authorization string, metadata map[string]any) result {
	h.t.Helper()

	return h.registerWithProof(authorization, "", metadata)
}

// registerWithProof is register with a DPoP proof, which may be empty.
func (h *harness) registerWithProof(authorization, proof string, metadata map[string]any) result {
	h.t.Helper()

	body, err := json.Marshal(metadata)
	if err != nil {
		h.t.Fatal(err)
	}

	request, err := http.NewRequest(http.MethodPost, h.registerURL, bytes.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}

	request.Header.Set("Content-Type", "application/json")

	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}

	if proof != "" {
		request.Header.Set("DPoP", proof)
	}

	return h.do(request)
}

// resource calls the protected resource.
func (h *harness) resource(authorization, proof string) result {
	h.t.Helper()

	request, err := http.NewRequest(http.MethodGet, h.resourceURL, nil)
	if err != nil {
		h.t.Fatal(err)
	}

	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}

	if proof != "" {
		request.Header.Set("DPoP", proof)
	}

	return h.do(request)
}

// tokenProof mints a valid proof for the token endpoint.
func (h *harness) tokenProof(key *dpoptest.Key) string {
	return dpoptest.Mint(h.t, key, dpoptest.Proof{Method: http.MethodPost, URL: h.tokenURL})
}

// boundToken seeds a DPoP-bound client and returns an access token bound to
// key.
func (h *harness) boundToken(key *dpoptest.Key) string {
	h.t.Helper()

	h.seedClient("participant", true, []string{resourceScope}, nil)

	issued := h.token("participant", h.tokenProof(key), []string{resourceScope}, "")
	if issued.status != http.StatusOK {
		h.t.Fatalf("token request: status %d, body %v", issued.status, issued.body)
	}

	return issued.str("access_token")
}
