package accessrunner

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/tokenverify"
)

// ErrCaller is any failure to authenticate the caller; its detail is never returned.
var ErrCaller = errors.New("caller_unauthenticated")

// Callers verifies the caller's access token: issued by the realm to the runner's login client
// (azp), for the runner (aud), an access token (typ Bearer), unexpired with no grace, signed ES256
// with a key of the realm's key set.
type Callers struct {
	Issuer   string // https://<keycloak>/realms/<realm>
	JWKSURL  string
	Audience string // the runner's audience
	Client   string // the login client, azp
	HTTP     *http.Client
	Now      func() time.Time

	mu        sync.Mutex
	keys      map[string]*ecdsa.PublicKey
	fetchedOK time.Time // the last successful fetch
	attempted time.Time // the last fetch, successful or not
}

const (
	keyRefresh  = time.Minute      // the key set is fetched again after this
	keyMaxStale = 5 * time.Minute  // and not used at all after this without a successful fetch
	keyThrottle = 10 * time.Second // between two fetches
)

// Authenticate returns the caller's subject id.
func (c *Callers) Authenticate(ctx context.Context, authorization string) (string, error) {
	token, ok := strings.CutPrefix(authorization, "Bearer ")
	if !ok || token == "" {
		return "", ErrCaller
	}
	_, payload, err := jose.Verify(token, jose.HeaderPolicy{Typ: "JWT", KidNeeded: true}, func(h jose.Header) (*ecdsa.PublicKey, error) {
		return c.key(ctx, h.Kid)
	})
	if err != nil {
		return "", ErrCaller
	}
	var claims struct {
		Iss string          `json:"iss"`
		Sub string          `json:"sub"`
		Azp string          `json:"azp"`
		Typ string          `json:"typ"`
		Exp int64           `json:"exp"`
		Aud json.RawMessage `json:"aud"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return "", ErrCaller
	}
	var audiences []string
	if json.Unmarshal(claims.Aud, &audiences) != nil {
		var one string
		if json.Unmarshal(claims.Aud, &one) != nil {
			return "", ErrCaller
		}
		audiences = []string{one}
	}
	now := c.now()
	if claims.Iss != c.Issuer || claims.Sub == "" || claims.Azp != c.Client || claims.Typ != "Bearer" ||
		!slices.Contains(audiences, c.Audience) || now.Unix() >= claims.Exp {
		return "", ErrCaller
	}
	return claims.Sub, nil
}

func (c *Callers) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// key returns the realm key kid. The key set is fetched again when kid is unknown or the set is
// older than keyRefresh, at most every keyThrottle; a set older than keyMaxStale is not used, so a
// key the realm removed stops verifying within that.
func (c *Callers) key(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	_, known := c.keys[kid]
	if (!known || now.Sub(c.fetchedOK) > keyRefresh) && now.Sub(c.attempted) >= keyThrottle {
		c.attempted = now
		if keys, err := c.fetch(ctx); err == nil {
			c.keys, c.fetchedOK = keys, c.now()
		}
		// The fetch may have taken time: staleness is judged now.
		now = c.now()
	}
	if now.Sub(c.fetchedOK) > keyMaxStale {
		return nil, errors.New("key set stale")
	}
	if k, ok := c.keys[kid]; ok {
		return k, nil
	}
	return nil, errors.New("unknown key")
}

func (c *Callers) fetch(ctx context.Context) (map[string]*ecdsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.JWKSURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, errors.New("key set unavailable")
	}
	// Only the realm's EC P-256 keys are kept; its RSA keys sign other clients' tokens.
	return tokenverify.ParseKeySet(body)
}
