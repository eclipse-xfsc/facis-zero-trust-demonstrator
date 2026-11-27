package accessrunner_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/accessrunner"
)

// it is the environment scripts/verify-access-runner/verify.sh sets up: a kind cluster with the plane
// namespaces ztd-data and ztd-other each running the deployment "app", and a Keycloak whose realm
// facis-ztd was applied by the chart's import job with the runner's clients.
type it struct {
	t          *testing.T
	kubeconfig string
	keycloak   string
	adminPass  string
	redirect   string
	repo       string
	work       string
	http       *http.Client
}

func (e *it) kubectl(args ...string) string {
	e.t.Helper()
	out, err := exec.Command("kubectl", append([]string{"--kubeconfig", e.kubeconfig}, args...)...).CombinedOutput()
	if err != nil {
		e.t.Fatalf("kubectl %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// admin calls the facis-ztd admin API as Keycloak's bootstrap administrator: the test's own setup
// and its observation of effects, never the runner's path.
func (e *it) admin(method, path string, body any) (int, []byte, http.Header) {
	e.t.Helper()
	resp, err := e.http.PostForm(e.keycloak+"/realms/master/protocol/openid-connect/token",
		url.Values{"grant_type": {"password"}, "client_id": {"admin-cli"}, "username": {"admin"}, "password": {e.adminPass}})
	if err != nil {
		e.t.Fatal(err)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&tok)
	_ = resp.Body.Close()
	var reader io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, e.keycloak+"/admin/realms/facis-ztd"+path, reader)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err = e.http.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw, resp.Header
}

func lastSegment(location string) string { return location[strings.LastIndexByte(location, '/')+1:] }

// user creates a user with a password and returns its id.
func (e *it) user(name string) string {
	e.t.Helper()
	status, raw, header := e.admin(http.MethodPost, "/users", map[string]any{"username": name, "enabled": true, "email": name + "@ztd.test",
		"emailVerified": true, "firstName": name, "lastName": "test",
		"credentials": []map[string]any{{"type": "password", "value": "pw-" + name + "-Aa1!", "temporary": false}}})
	if status != http.StatusCreated {
		e.t.Fatalf("creating %s: %d %s", name, status, raw)
	}
	return lastSegment(header.Get("Location"))
}

func (e *it) enabled(id string) bool {
	e.t.Helper()
	_, raw, _ := e.admin(http.MethodGet, "/users/"+id, nil)
	var u struct{ Enabled bool }
	_ = json.Unmarshal(raw, &u)
	return u.Enabled
}

// login runs the authorization-code flow with PKCE (S256) of the login client ztd-access, as a
// browser would, and returns the access token.
func (e *it) login(name string) string {
	e.t.Helper()
	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar, Timeout: 15 * time.Second, Transport: e.http.Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	verifier := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"client_id": {"ztd-access"}, "redirect_uri": {e.redirect}, "response_type": {"code"}, "scope": {"openid"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}, "state": {"it"}}
	resp, err := browser.Get(e.keycloak + "/realms/facis-ztd/protocol/openid-connect/auth?" + q.Encode())
	if err != nil {
		e.t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	m := regexp.MustCompile(`action="([^"]+)"`).FindSubmatch(page)
	if m == nil {
		e.t.Fatalf("no login form for %s: %d", name, resp.StatusCode)
	}
	resp, err = browser.PostForm(html.UnescapeString(string(m[1])), url.Values{"username": {name}, "password": {"pw-" + name + "-Aa1!"}})
	if err != nil {
		e.t.Fatal(err)
	}
	_ = resp.Body.Close()
	location, _ := url.Parse(resp.Header.Get("Location"))
	code := location.Query().Get("code")
	if resp.StatusCode != http.StatusFound || code == "" {
		e.t.Fatalf("login of %s: %d %s", name, resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, err = e.http.PostForm(e.keycloak+"/realms/facis-ztd/protocol/openid-connect/token", url.Values{"grant_type": {"authorization_code"},
		"client_id": {"ztd-access"}, "code": {code}, "redirect_uri": {e.redirect}, "code_verifier": {verifier}})
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil || tok.AccessToken == "" {
		e.t.Fatalf("token for %s: %d", name, resp.StatusCode)
	}
	return tok.AccessToken
}

// passwordToken is an access token of the realm's admin-cli client for the caller: a real token of
// the realm, issued to another client.
func (e *it) passwordToken() string {
	e.t.Helper()
	resp, err := e.http.PostForm(e.keycloak+"/realms/facis-ztd/protocol/openid-connect/token", url.Values{"grant_type": {"password"},
		"client_id": {"admin-cli"}, "username": {"it-caller"}, "password": {"pw-it-caller-Aa1!"}})
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&tok)
	if tok.AccessToken == "" {
		e.t.Fatalf("no admin-cli token: %d", resp.StatusCode)
	}
	return tok.AccessToken
}

func TestRunnerAgainstKindAndKeycloak(t *testing.T) {
	if os.Getenv("ACCESS_IT_KUBECONFIG") == "" {
		t.Skip("scripts/verify-access-runner/verify.sh runs this test")
	}
	caPEM, err := os.ReadFile(os.Getenv("ACCESS_IT_KEYCLOAK_CA"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	tlsTransport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}
	e := &it{t: t, kubeconfig: os.Getenv("ACCESS_IT_KUBECONFIG"), keycloak: os.Getenv("ACCESS_IT_KEYCLOAK"),
		adminPass: os.Getenv("ACCESS_IT_ADMIN_PASSWORD"), redirect: os.Getenv("ACCESS_IT_REDIRECT"), work: t.TempDir(),
		http: &http.Client{Timeout: 15 * time.Second, Transport: tlsTransport}}
	out, _ := exec.Command("go", "list", "-m", "-f", "{{.Dir}}").Output()
	e.repo = strings.TrimSpace(string(out))

	// People: the caller, the approver, a plain user, and two privileged users, one by a direct
	// realm-management role and one by a group carrying ztd-operator.
	caller, approver := e.user("it-caller"), e.user("it-approver")
	plain := e.user("it-plain")
	direct, grouped := e.user("it-priv-direct"), e.user("it-priv-group")
	_, clients, _ := e.admin(http.MethodGet, "/clients?clientId=realm-management", nil)
	var rm []struct{ ID string }
	_ = json.Unmarshal(clients, &rm)
	_, role, _ := e.admin(http.MethodGet, "/clients/"+rm[0].ID+"/roles/manage-users", nil)
	var roleRep map[string]any
	_ = json.Unmarshal(role, &roleRep)
	if status, raw, _ := e.admin(http.MethodPost, "/users/"+direct+"/role-mappings/clients/"+rm[0].ID, []any{roleRep}); status != http.StatusNoContent {
		t.Fatalf("mapping manage-users: %d %s", status, raw)
	}
	_, _, gh := e.admin(http.MethodPost, "/groups", map[string]string{"name": "it-operators"})
	group := lastSegment(gh.Get("Location"))
	_, op, _ := e.admin(http.MethodGet, "/roles/ztd-operator", nil)
	var opRep map[string]any
	_ = json.Unmarshal(op, &opRep)
	e.admin(http.MethodPost, "/groups/"+group+"/role-mappings/realm", []any{opRep})
	if status, _, _ := e.admin(http.MethodPut, "/users/"+grouped+"/groups/"+group, nil); status != http.StatusNoContent {
		t.Fatal("adding the group member")
	}

	// The approver's key; the chart installed with it.
	approverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk := jose.PublicJWK(&approverKey.PublicKey)
	values, _ := json.Marshal(map[string]any{
		"image": map[string]string{"digest": "sha256:" + strings.Repeat("0", 64)}, "replicas": 0, "target": "kind/facis-ztd",
		"planeNamespaces": []string{"ztd-data"},
		"approvers":       []any{map[string]any{"sub": approver, "key": map[string]string{"kty": "EC", "crv": "P-256", "x": jwk.X, "y": jwk.Y}}},
		"keycloak":        map[string]any{"base": e.keycloak, "secretRef": map[string]string{"name": "access-runner-client"}},
		"tls":             map[string]string{"secretName": "access-runner-tls"},
	})
	valuesFile := filepath.Join(e.work, "values.json")
	_ = os.WriteFile(valuesFile, values, 0o600)
	if out, err := exec.Command("helm", "--kubeconfig", e.kubeconfig, "upgrade", "--install", "access", filepath.Join(e.repo, "deployment/helm/access"),
		"-n", "ztd-access", "-f", valuesFile, "--wait", "--timeout", "120s").CombinedOutput(); err != nil {
		t.Fatalf("helm: %v\n%s", err, out)
	}

	// The runner, out of the cluster, as the chart's ServiceAccount, with the chart's configuration.
	var cfg map[string]any
	_ = json.Unmarshal([]byte(e.kubectl("-n", "ztd-access", "get", "configmap", "ztd-access-runner-config", "-o", `jsonpath={.data.config\.json}`)), &cfg)
	tokenFile := filepath.Join(e.work, "sa-token")
	_ = os.WriteFile(tokenFile, []byte(e.kubectl("-n", "ztd-access", "create", "token", "ztd-access-runner", "--duration", "1h")), 0o600)
	caFile := filepath.Join(e.work, "ca.crt")
	ca, _ := base64.StdEncoding.DecodeString(e.kubectl("config", "view", "--raw", "-o", "jsonpath={.clusters[0].cluster.certificate-authority-data}"))
	_ = os.WriteFile(caFile, ca, 0o600)
	secretFile := filepath.Join(e.work, "client-secret")
	_ = os.WriteFile(secretFile, []byte(os.Getenv("ACCESS_IT_RUNNER_SECRET")), 0o600)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	_ = l.Close()
	cfg["addr"] = addr
	cfg["tls_cert_file"], cfg["tls_key_file"] = os.Getenv("ACCESS_IT_RUNNER_CERT"), os.Getenv("ACCESS_IT_RUNNER_KEY")
	cfg["kube"] = map[string]any{"api": e.kubectl("config", "view", "-o", "jsonpath={.clusters[0].cluster.server}"), "token_file": tokenFile, "ca_file": caFile, "namespace": "ztd-access"}
	cfg["keycloak"].(map[string]any)["secret_file"] = secretFile
	cfg["keycloak"].(map[string]any)["ca_file"] = os.Getenv("ACCESS_IT_KEYCLOAK_CA")
	rawCfg, _ := json.Marshal(cfg)
	cfgFile := filepath.Join(e.work, "config.json")
	_ = os.WriteFile(cfgFile, rawCfg, 0o600)
	bin := filepath.Join(e.work, "access-runner")
	if out, err := exec.Command("go", "build", "-o", bin, "github.com/eclipse-xfsc/facis-zero-trust-demonstrator/cmd/access-runner").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	logs := &bytes.Buffer{}
	runner := exec.Command(bin, "-config", cfgFile)
	runner.Stdout, runner.Stderr = logs, logs
	if err := runner.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runner.Process.Kill(); _ = runner.Wait() })
	for i := 0; ; i++ {
		if resp, err := e.http.Get("https://" + addr + "/healthz"); err == nil && resp.StatusCode == http.StatusOK {
			_ = resp.Body.Close()
			break
		}
		if i == 50 {
			t.Fatalf("the runner never answered:\n%s", logs.String())
		}
		time.Sleep(100 * time.Millisecond)
	}

	if resp, err := http.Get("http://" + addr + "/healthz"); err == nil && resp.StatusCode == http.StatusOK {
		_ = resp.Body.Close()
		t.Fatal("the runner answered over plain HTTP")
	}

	sign := func(g accessrunner.Grant) string {
		compact, err := accessrunner.Sign(context.Background(), g, approver, func(_ context.Context, in []byte) ([]byte, error) {
			sum := sha256.Sum256(in)
			r, s, err := ecdsa.Sign(rand.Reader, approverKey, sum[:])
			if err != nil {
				return nil, err
			}
			return append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...), nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return compact
	}
	now := time.Now().Unix()
	grant := func(role string, ops []string, notAfter int64) string {
		return sign(accessrunner.Grant{ID: fmt.Sprintf("it-%s-%d", role, notAfter), Subject: caller, Role: role, Operations: ops, Target: "kind/facis-ztd",
			PolicyVersion: accessrunner.PolicyVersion(), Approver: approver, ApprovedAt: now - 5, NotBefore: now - 5, NotAfter: notAfter, Reason: "integration"})
	}
	call := func(token, operation, compact string, params map[string]any) (int, map[string]any) {
		body, _ := json.Marshal(map[string]any{"grant": compact, "params": params})
		req, _ := http.NewRequest(http.MethodPost, "https://"+addr+"/v1/operations/"+operation, bytes.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := e.http.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	template := func(ns string) map[string]any {
		var d map[string]any
		_ = json.Unmarshal([]byte(e.kubectl("-n", ns, "get", "deployment", "app", "-o", "json")), &d)
		return d["spec"].(map[string]any)["template"].(map[string]any)
	}
	without := func(tpl map[string]any) string {
		meta := tpl["metadata"].(map[string]any)
		if a, ok := meta["annotations"].(map[string]any); ok {
			delete(a, accessrunner.RestartAnnotation)
			if len(a) == 0 {
				delete(meta, "annotations")
			}
		}
		raw, _ := json.Marshal(tpl)
		return string(raw)
	}

	token := e.login("it-caller")
	operator := grant("cluster-operator", []string{accessrunner.OpClusterRestart, accessrunner.OpClusterLogs}, now+3600)
	userAdmin := grant("user-admin", []string{accessrunner.OpListUsers, accessrunner.OpDisableUser, accessrunner.OpEnableUser}, now+3600)

	t.Run("cluster-restart changes the annotation and nothing else", func(t *testing.T) {
		before := template("ztd-data")
		status, out := call(token, accessrunner.OpClusterRestart, operator, map[string]any{"namespace": "ztd-data", "deployment": "app"})
		after := template("ztd-data")
		annotations, _ := after["metadata"].(map[string]any)["annotations"].(map[string]any)
		if status != http.StatusOK || annotations[accessrunner.RestartAnnotation] == nil {
			t.Fatalf("restart: %d %v", status, out)
		}
		if without(before) != without(after) {
			t.Fatal("the restart changed the pod template beyond the annotation")
		}
	})
	t.Run("cluster-logs returns the pod's log", func(t *testing.T) {
		// The restart above rolls the deployment: read a pod of the finished rollout.
		e.kubectl("-n", "ztd-data", "rollout", "status", "deployment/app", "--timeout=120s")
		pod := e.kubectl("-n", "ztd-data", "get", "pods", "-l", "app=app", "--field-selector=status.phase=Running", "-o", "jsonpath={.items[0].metadata.name}")
		status, out := call(token, accessrunner.OpClusterLogs, operator, map[string]any{"namespace": "ztd-data", "pod": pod, "lines": 10})
		if lines, _ := out["result"].(string); status != http.StatusOK || !strings.Contains(lines, "Starting up on port") {
			t.Fatalf("logs: %d %v", status, out)
		}
	})
	t.Run("user-admin lists, disables and enables a plain user", func(t *testing.T) {
		status, out := call(token, accessrunner.OpListUsers, userAdmin, map[string]any{})
		listed, _ := json.Marshal(out["result"])
		if status != http.StatusOK || !strings.Contains(string(listed), `{"enabled":true,"username":"it-plain"}`) {
			t.Fatalf("list: %d %s", status, listed)
		}
		if status, out := call(token, accessrunner.OpDisableUser, userAdmin, map[string]any{"username": "it-plain"}); status != http.StatusOK || e.enabled(plain) {
			t.Fatalf("disable: %d %v", status, out)
		}
		if status, out := call(token, accessrunner.OpEnableUser, userAdmin, map[string]any{"username": "it-plain"}); status != http.StatusOK || !e.enabled(plain) {
			t.Fatalf("enable: %d %v", status, out)
		}
	})

	refused := func(t *testing.T, name string, status int, out map[string]any, wantStatus int, reason string) {
		t.Helper()
		if status != wantStatus || out["outcome"] != "refused" || out["reason"] != reason {
			t.Errorf("%s: %d %v, want %d %s", name, status, out, wantStatus, reason)
		}
	}
	t.Run("refusals change nothing", func(t *testing.T) {
		data, _ := json.Marshal(template("ztd-data"))
		other, _ := json.Marshal(template("ztd-other"))
		approverToken := e.login("it-approver")
		self := sign(accessrunner.Grant{ID: "it-self", Subject: approver, Role: "cluster-operator", Operations: []string{accessrunner.OpClusterRestart},
			Target: "kind/facis-ztd", PolicyVersion: accessrunner.PolicyVersion(), Approver: approver, ApprovedAt: now - 5, NotBefore: now - 5, NotAfter: now + 600, Reason: "self"})
		restart := map[string]any{"namespace": "ztd-data", "deployment": "app"}
		parts := strings.Split(operator, ".")
		for _, c := range []struct {
			name, token, operation, grant string
			params                        map[string]any
			status                        int
			reason                        string
		}{
			{"no token", "", accessrunner.OpClusterRestart, operator, restart, 401, "caller_unauthenticated"},
			{"a token of another client", e.passwordToken(), accessrunner.OpClusterRestart, operator, restart, 401, "caller_unauthenticated"},
			{"another caller's grant", approverToken, accessrunner.OpClusterRestart, operator, restart, 403, "grant_subject_mismatch"},
			{"approved by the subject", approverToken, accessrunner.OpClusterRestart, self, restart, 403, "grant_self_approved"},
			{"a tampered grant", token, accessrunner.OpClusterRestart, parts[0] + "." + strings.Split(userAdmin, ".")[1] + "." + parts[2], restart, 403, "grant_signature_invalid"},
			{"an operation outside the grant", token, accessrunner.OpDisableUser, operator, map[string]any{"username": "it-plain"}, 403, "grant_operation_not_granted"},
			{"a namespace outside the plane", token, accessrunner.OpClusterRestart, operator, map[string]any{"namespace": "ztd-other", "deployment": "app"}, 400, "params_invalid"},
			{"a field beyond the operation's", token, accessrunner.OpClusterRestart, operator, map[string]any{"namespace": "ztd-data", "deployment": "app", "image": "evil"}, 400, "params_invalid"},
			{"a privileged user by role", token, accessrunner.OpDisableUser, userAdmin, map[string]any{"username": "it-priv-direct"}, 403, "target_privileged"},
			{"a privileged user by group", token, accessrunner.OpDisableUser, userAdmin, map[string]any{"username": "it-priv-group"}, 403, "target_privileged"},
		} {
			status, out := call(c.token, c.operation, c.grant, c.params)
			refused(t, c.name, status, out, c.status, c.reason)
		}
		if now, _ := json.Marshal(template("ztd-data")); string(now) != string(data) {
			t.Error("a refusal changed the deployment in ztd-data")
		}
		if now, _ := json.Marshal(template("ztd-other")); string(now) != string(other) {
			t.Error("a refusal changed the deployment in ztd-other")
		}
		if !e.enabled(direct) || !e.enabled(grouped) || !e.enabled(plain) {
			t.Error("a refusal disabled a user")
		}
	})

	t.Run("revocation is read on every call", func(t *testing.T) {
		id := fmt.Sprintf("it-user-admin-%d", now+3600)
		e.kubectl("-n", "ztd-access", "patch", "configmap", "ztd-access-revocations", "--type", "merge", "-p", `{"data":{"revoked":"`+id+`"}}`)
		status, out := call(token, accessrunner.OpListUsers, userAdmin, map[string]any{})
		refused(t, "revoked", status, out, 403, "grant_revoked")
		// An upgrade and a rollback of the chart leave the list as it is.
		for _, args := range [][]string{{"upgrade", "access", filepath.Join(e.repo, "deployment/helm/access"), "-n", "ztd-access", "-f", valuesFile, "--wait"},
			{"rollback", "access", "1", "-n", "ztd-access", "--wait"}} {
			if out, err := exec.Command("helm", append([]string{"--kubeconfig", e.kubeconfig}, args...)...).CombinedOutput(); err != nil {
				t.Fatalf("helm %s: %v\n%s", args[0], err, out)
			}
			status, out := call(token, accessrunner.OpListUsers, userAdmin, map[string]any{})
			refused(t, "revoked after helm "+args[0], status, out, 403, "grant_revoked")
		}
		// Uninstalled and installed again, the release keeps the list too.
		for _, args := range [][]string{{"uninstall", "access", "-n", "ztd-access", "--wait"},
			{"install", "access", filepath.Join(e.repo, "deployment/helm/access"), "-n", "ztd-access", "-f", valuesFile, "--wait"}} {
			if out, err := exec.Command("helm", append([]string{"--kubeconfig", e.kubeconfig}, args...)...).CombinedOutput(); err != nil {
				t.Fatalf("helm %s: %v\n%s", args[0], err, out)
			}
		}
		status, out = call(token, accessrunner.OpListUsers, userAdmin, map[string]any{})
		refused(t, "revoked after a reinstall", status, out, 403, "grant_revoked")
		e.kubectl("-n", "ztd-access", "patch", "configmap", "ztd-access-revocations", "--type", "merge", "-p", `{"data":{"revoked":""}}`)
		if status, _ := call(token, accessrunner.OpListUsers, userAdmin, map[string]any{}); status != http.StatusOK {
			t.Error("not served once unrevoked")
		}
		e.kubectl("-n", "ztd-access", "delete", "configmap", "ztd-access-revocations")
		status, out = call(token, accessrunner.OpListUsers, userAdmin, map[string]any{})
		refused(t, "revocation list missing", status, out, 503, "revocation_state_unavailable")
		e.kubectl("-n", "ztd-access", "create", "configmap", "ztd-access-revocations", "--from-literal=revoked=")
	})

	t.Run("a grant ends at its time, with the same caller token", func(t *testing.T) {
		end := time.Now().Unix() + 8
		short := grant("user-admin", []string{accessrunner.OpListUsers}, end)
		if status, out := call(token, accessrunner.OpListUsers, short, map[string]any{}); status != http.StatusOK {
			t.Fatalf("before its end: %d %v", status, out)
		}
		time.Sleep(time.Until(time.Unix(end, 0)) + 500*time.Millisecond)
		status, out := call(token, accessrunner.OpListUsers, short, map[string]any{})
		refused(t, "after its end", status, out, 403, "grant_expired")
	})

	t.Run("the runner's ServiceAccount can do its operations and nothing else", func(t *testing.T) {
		as := []string{"--kubeconfig", e.kubeconfig, "auth", "can-i", "--as", "system:serviceaccount:ztd-access:ztd-access-runner"}
		for _, c := range []struct {
			args []string
			want string
		}{
			{[]string{"patch", "deployments", "-n", "ztd-data"}, "yes"},
			{[]string{"get", "pods", "--subresource=log", "-n", "ztd-data"}, "yes"},
			{[]string{"get", "configmaps/ztd-access-revocations", "-n", "ztd-access"}, "yes"},
			{[]string{"patch", "deployments", "-n", "ztd-other"}, "no"},
			{[]string{"get", "secrets", "-n", "ztd-data"}, "no"},
			{[]string{"create", "pods", "--subresource=exec", "-n", "ztd-data"}, "no"},
			{[]string{"get", "pods", "--subresource=log", "-n", "ztd-other"}, "no"},
			{[]string{"delete", "deployments", "-n", "ztd-data"}, "no"},
			{[]string{"create", "rolebindings", "-n", "ztd-data"}, "no"},
			{[]string{"create", "serviceaccounts", "--subresource=token", "-n", "ztd-access"}, "no"},
			{[]string{"update", "configmaps/ztd-access-revocations", "-n", "ztd-access"}, "no"},
		} {
			out, _ := exec.Command("kubectl", append(as, c.args...)...).Output()
			if got := strings.TrimSpace(string(out)); got != c.want {
				t.Errorf("can-i %v: %s, want %s", c.args, got, c.want)
			}
		}
	})

	// The audit records name the authenticated caller and the grant's approver, never a token or a grant.
	if strings.Contains(logs.String(), token) || strings.Contains(logs.String(), operator) {
		t.Error("the runner logged a credential")
	}
	if !strings.Contains(logs.String(), `"caller_sub":"`+caller+`"`) || !strings.Contains(logs.String(), `"approver_sub":"`+approver+`"`) {
		t.Errorf("the audit records lack the caller or the approver:\n%s", logs.String())
	}
}
