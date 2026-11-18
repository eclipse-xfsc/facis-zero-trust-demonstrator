package accessrunner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// ErrPrivilegedTarget refuses an operation on a user who holds a privileged role.
var ErrPrivilegedTarget = errors.New("target_privileged")

// ErrNoSuchUser refuses an operation on a user that does not exist.
var ErrNoSuchUser = errors.New("target_not_found")

// PrivilegedRealmRoles are the realm roles that make a user privileged; any role of the
// realm-management client does too.
var PrivilegedRealmRoles = []string{"ztd-operator", "admin"}

// Keycloak calls the realm's admin API as the runner's confidential client.
type Keycloak struct {
	Base       string // https://<keycloak>
	Realm      string
	ClientID   string
	SecretFile string
	HTTP       *http.Client
}

func (k *Keycloak) token(ctx context.Context) (string, error) {
	secret, err := os.ReadFile(k.SecretFile)
	if err != nil {
		return "", errors.New("runner credential unavailable")
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {k.ClientID}, "client_secret": {strings.TrimSpace(string(secret))}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, k.Base+"/realms/"+url.PathEscape(k.Realm)+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := k.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out) != nil || out.AccessToken == "" {
		return "", errors.New("runner token refused")
	}
	return out.AccessToken, nil
}

func (k *Keycloak) admin(ctx context.Context, token, method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, k.Base+"/admin/realms/"+url.PathEscape(k.Realm)+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := k.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("admin %s %s: status %d", method, path, resp.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out)
	}
	return nil
}

// User is what the runner returns about a user.
type User struct {
	Username string `json:"username"`
	Enabled  bool   `json:"enabled"`
}

// ListUsers returns the first 100 users of the realm.
func (k *Keycloak) ListUsers(ctx context.Context) ([]User, error) {
	token, err := k.token(ctx)
	if err != nil {
		return nil, err
	}
	var users []User
	if err := k.admin(ctx, token, http.MethodGet, "/users?max=100&briefRepresentation=true", nil, &users); err != nil {
		return nil, err
	}
	return users, nil
}

// SetEnabled enables or disables the user with exactly this username, unless the user holds a
// privileged role, directly, through a group or through a composite. Any lookup that fails
// refuses the operation.
func (k *Keycloak) SetEnabled(ctx context.Context, username string, enabled bool) error {
	token, err := k.token(ctx)
	if err != nil {
		return err
	}
	var found []struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	}
	if err := k.admin(ctx, token, http.MethodGet, "/users?exact=true&username="+url.QueryEscape(username), nil, &found); err != nil {
		return err
	}
	if len(found) != 1 || found[0].Username != strings.ToLower(username) {
		return ErrNoSuchUser
	}
	id := url.PathEscape(found[0].ID)
	var realmRoles []struct {
		Name string `json:"name"`
	}
	if err := k.admin(ctx, token, http.MethodGet, "/users/"+id+"/role-mappings/realm/composite", nil, &realmRoles); err != nil {
		return err
	}
	for _, r := range realmRoles {
		for _, p := range PrivilegedRealmRoles {
			if r.Name == p {
				return ErrPrivilegedTarget
			}
		}
	}
	var clients []struct {
		ID string `json:"id"`
	}
	if err := k.admin(ctx, token, http.MethodGet, "/clients?clientId=realm-management", nil, &clients); err != nil {
		return err
	}
	if len(clients) != 1 {
		return errors.New("realm-management client not found")
	}
	var clientRoles []json.RawMessage
	if err := k.admin(ctx, token, http.MethodGet, "/users/"+id+"/role-mappings/clients/"+url.PathEscape(clients[0].ID)+"/composite", nil, &clientRoles); err != nil {
		return err
	}
	if len(clientRoles) > 0 {
		return ErrPrivilegedTarget
	}
	return k.admin(ctx, token, http.MethodPut, "/users/"+id, map[string]bool{"enabled": enabled}, nil)
}
