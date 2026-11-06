package authelia

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"authelia.com/provider/oauth2"
	hoauth2 "authelia.com/provider/oauth2/handler/oauth2"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/dpoptest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider"
)

// A token bound to a key stays bound when the process restarts and reads it back from the store:
// it still needs a proof by that key, with DPoP enforcement on and off, for opaque and for signed
// tokens whatever CONNECTOR_TEST_TOKENS says.
func TestStore_BoundTokenStaysBoundAcrossRestart(t *testing.T) {
	for _, signed := range []bool{false, true} {
		for name, enforce := range map[string]bool{"enforcement on": true, "enforcement off": false} {
			if signed {
				name = "jwt, " + name
			} else {
				name = "opaque, " + name
			}

			t.Run(name, func(t *testing.T) { boundTokenStaysBound(t, signed, enforce) })
		}
	}
}

func boundTokenStaysBound(t *testing.T, signed, enforce bool) {
	h := newHarness(t, func(c *oauth2provider.Config) {
		c.DPoP.Enforce = enforce
		c.AccessTokenSigner = nil

		if signed {
			c.Issuer = "https://connector.example"
			c.AccessTokenSigner = newTestSigner(t)
		}
	})
	key := dpoptest.NewKey(t)
	token := h.boundToken(key)

	if isJWT := strings.Count(token, ".") == 2; isJWT != signed {
		t.Fatalf("token %.16s… is a JWT: %v, want %v", token, isJWT, signed)
	}

	h.restart()

	proof := dpoptest.Mint(t, key, dpoptest.Proof{Method: http.MethodGet, URL: h.resourceURL, AccessToken: token})
	if got := h.resource("DPoP "+token, proof); got.status != http.StatusOK {
		t.Fatalf("with its proof after restart: status %d, body %v", got.status, got.body)
	}

	if got := h.resource("DPoP "+token, ""); got.status != http.StatusUnauthorized {
		t.Errorf("without a proof after restart: status %d, want 401", got.status)
	}

	if got := h.resource("Bearer "+token, ""); got.status != http.StatusUnauthorized {
		t.Errorf("as a bearer token after restart: status %d, want 401", got.status)
	}

	thief := dpoptest.NewKey(t)
	stolen := dpoptest.Mint(t, thief, dpoptest.Proof{Method: http.MethodGet, URL: h.resourceURL, AccessToken: token})
	if got := h.resource("DPoP "+token, stolen); got.reason() != oauth2provider.CodeDPoPKeyMismatch {
		t.Errorf("with another key after restart: reason %q, want %q", got.reason(), oauth2provider.CodeDPoPKeyMismatch)
	}
}

// The database holds signatures, hashes and bindings, never a usable token or a client secret.
func TestStore_RowsHoldNoCredential(t *testing.T) {
	h := newHarness(t, nil)
	if h.pool == nil {
		t.Skipf("needs %s=pg", storeEnv)
	}

	token := h.boundToken(dpoptest.NewKey(t))

	rows, err := h.pool.Query(t.Context(), `SELECT t::text FROM oauth2_token t UNION ALL SELECT c::text FROM oauth2_client c`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	n := 0
	for rows.Next() {
		var row string
		if err := rows.Scan(&row); err != nil {
			t.Fatal(err)
		}
		n++

		for _, canary := range []string{token, testSecret} {
			if strings.Contains(row, canary) {
				t.Errorf("a row contains a credential: %.12s…", canary)
			}
		}
	}

	if n < 2 {
		t.Fatalf("read %d rows, want the client and its token", n)
	}
}

func TestSessionCodec_RoundTripKeepsBindingAndExpiry(t *testing.T) {
	exp := time.Now().Add(time.Hour).UTC().Truncate(time.Second)

	in := &oauth2.DefaultSession{Subject: "participant"}
	in.SetExpiresAt(oauth2.AccessToken, exp)
	in.SetDPoPJWKThumbprint("jkt-1")

	raw, gotExp, err := encodeSession(in, "")
	if err != nil {
		t.Fatal(err)
	}

	if !gotExp.Equal(exp) {
		t.Errorf("expiry = %v, want %v", gotExp, exp)
	}

	out := &oauth2.DefaultSession{}
	if err := decodeSession(raw, out); err != nil {
		t.Fatal(err)
	}

	if out.GetDPoPJWKThumbprint() != "jkt-1" || out.GetSubject() != "participant" || !out.GetExpiresAt(oauth2.AccessToken).Equal(exp) {
		t.Errorf("decoded %+v", out)
	}
}

// The library hands the store a DefaultSession on one path and a JWTSession on another for the same
// token; the binding, subject and expiry survive either way.
func TestSessionCodec_CrossesSessionTypes(t *testing.T) {
	exp := time.Now().Add(time.Hour).UTC().Truncate(time.Second)

	def := &oauth2.DefaultSession{Subject: "participant"}
	def.SetExpiresAt(oauth2.AccessToken, exp)
	def.SetDPoPJWKThumbprint("jkt-1")
	def.SetClientCertificateSHA256Thumbprint("x5t-1")

	jwt := &hoauth2.JWTSession{}
	jwt.SetSubject("participant")
	jwt.SetExpiresAt(oauth2.AccessToken, exp)
	jwt.SetDPoPJWKThumbprint("jkt-1")
	jwt.SetClientCertificateSHA256Thumbprint("x5t-1")

	for name, tc := range map[string]struct{ in, out oauth2.Session }{
		"default to jwt": {def, &hoauth2.JWTSession{}},
		"jwt to default": {jwt, &oauth2.DefaultSession{}},
	} {
		t.Run(name, func(t *testing.T) {
			raw, _, err := encodeSession(tc.in, "")
			if err != nil {
				t.Fatal(err)
			}
			if err := decodeSession(raw, tc.out); err != nil {
				t.Fatal(err)
			}

			bound := tc.out.(oauth2.DPoPBoundSession)
			cert := tc.out.(certBoundSession)
			if bound.GetDPoPJWKThumbprint() != "jkt-1" || cert.GetClientCertificateSHA256Thumbprint() != "x5t-1" ||
				tc.out.GetSubject() != "participant" || !tc.out.GetExpiresAt(oauth2.AccessToken).Equal(exp) {
				t.Errorf("decoded %+v", tc.out)
			}
		})
	}
}

func TestSessionCodec_RefusesWhatItCannotCarry(t *testing.T) {
	exp := time.Now().Add(time.Hour)

	t.Run("no expiry", func(t *testing.T) {
		if _, _, err := encodeSession(&oauth2.DefaultSession{}, ""); err == nil {
			t.Fatal("encoded a session without an expiry")
		}
	})

	t.Run("no expiry stored", func(t *testing.T) {
		if err := decodeSession([]byte(`{"v":1,"exp":{}}`), &oauth2.DefaultSession{}); err == nil {
			t.Fatal("decoded a session without an expiry")
		}
	})

	t.Run("other version", func(t *testing.T) {
		if err := decodeSession([]byte(`{"v":2,"exp":{}}`), &oauth2.DefaultSession{}); err == nil {
			t.Fatal("decoded a session of another version")
		}
	})

	t.Run("library JSON", func(t *testing.T) {
		// The library's own session JSON has no version, so it is refused instead of being read
		// with its binding dropped.
		if err := decodeSession([]byte(`{"expires_at":{},"jwk_thumbprint":"jkt-1"}`), &oauth2.DefaultSession{}); err == nil {
			t.Fatal("decoded unversioned library JSON")
		}
	})

	t.Run("binding into a session that cannot carry it", func(t *testing.T) {
		in := &oauth2.DefaultSession{}
		in.SetExpiresAt(oauth2.AccessToken, exp)
		in.SetDPoPJWKThumbprint("jkt-1")

		raw, _, err := encodeSession(in, "")
		if err != nil {
			t.Fatal(err)
		}

		if err := decodeSession(raw, &unboundSession{}); err == nil {
			t.Fatal("a bound session decoded into one that cannot hold the binding")
		}
	})
}

// unboundSession is a session with no way to record a DPoP binding: its SetDPoPJWKThumbprint shadows
// the embedded one with another signature, so it does not implement oauth2.DPoPBoundSession.
type unboundSession struct{ oauth2.DefaultSession }

func (*unboundSession) SetDPoPJWKThumbprint() {}

var _ oauth2.Session = (*unboundSession)(nil)
