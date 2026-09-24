package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/cosignverify"
)

// fakeVerifier answers by image name; "slow" blocks until the deadline, like a stalled registry.
type fakeVerifier map[string]cosignverify.Result

func (f fakeVerifier) VerifyImage(ctx context.Context, image string) cosignverify.Result {
	if image == "slow" {
		<-ctx.Done()
		return cosignverify.Result{Code: cosignverify.CodeProviderDown, Detail: ctx.Err().Error()}
	}
	return f[image]
}

func okTrust() *trust { return &trust{} }

func newHandler(v verifier, tr *trust) *handler {
	return &handler{verifier: v, trust: tr, timeout: 200 * time.Millisecond, metrics: newMetrics(&cosignverify.Stats{})}
}

func post(t *testing.T, h http.Handler, body string) (int, providerResponse) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	var resp providerResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not JSON: %v: %s", err, rec.Body)
	}
	if resp.APIVersion != apiVersion || resp.Kind != "ProviderResponse" {
		t.Errorf("response header = %s %s", resp.APIVersion, resp.Kind)
	}
	return rec.Code, resp
}

func request(keys ...string) string {
	b, _ := json.Marshal(map[string]any{"apiVersion": apiVersion, "kind": "ProviderRequest", "request": map[string]any{"keys": keys}})
	return string(b)
}

func TestItems(t *testing.T) {
	v := fakeVerifier{
		"good": {},
		"bad":  {Code: cosignverify.CodeUnsigned, Detail: "no valid signature"},
	}
	h := newHandler(v, okTrust())
	status, resp := post(t, h, request("good", "bad"))
	if status != http.StatusOK || !resp.Response.Idempotent || resp.Response.SystemError != "" {
		t.Fatalf("status %d, response %+v", status, resp.Response)
	}
	want := []item{{Key: "good", Value: verifiedValue}, {Key: "bad", Error: "ADM-UNSIGNED: no valid signature"}}
	if fmt.Sprint(resp.Response.Items) != fmt.Sprint(want) {
		t.Errorf("items = %+v, want %+v", resp.Response.Items, want)
	}
}

func TestSystemErrors(t *testing.T) {
	h := newHandler(fakeVerifier{}, okTrust())
	many := make([]string, maxKeys+1)
	for name, body := range map[string]string{
		"malformed":   "{",
		"wrong kind":  `{"apiVersion":"` + apiVersion + `","kind":"Other","request":{"keys":["a"]}}`,
		"wrong group": `{"apiVersion":"v1","kind":"ProviderRequest","request":{"keys":["a"]}}`,
		"too many":    request(many...),
	} {
		status, resp := post(t, h, body)
		if status != http.StatusBadRequest || !strings.HasPrefix(resp.Response.SystemError, cosignverify.CodeProviderDown) || len(resp.Response.Items) != 0 {
			t.Errorf("%s: status %d, response %+v", name, status, resp.Response)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: status %d", rec.Code)
	}
}

func TestInvalidTrustIsASystemError(t *testing.T) {
	dir := t.TempDir()
	tr := &trust{file: filepath.Join(dir, "missing.json"), apply: func(*cosignverify.Policy) {}}
	if tr.load() == nil {
		t.Fatal("missing policy file loaded")
	}
	_, resp := post(t, newHandler(fakeVerifier{"good": {}}, tr), request("good"))
	if !strings.Contains(resp.Response.SystemError, "trust policy unavailable") || len(resp.Response.Items) != 0 {
		t.Errorf("response %+v", resp.Response)
	}
}

func TestTimeoutDenies(t *testing.T) {
	h := newHandler(fakeVerifier{"good": {}}, okTrust())
	start := time.Now()
	_, resp := post(t, h, request("slow", "good"))
	if d := time.Since(start); d > h.timeout+500*time.Millisecond {
		t.Errorf("answered after %s, deadline %s", d, h.timeout)
	}
	if e := resp.Response.Items[0].Error; !strings.HasPrefix(e, cosignverify.CodeProviderDown+": verification did not finish") {
		t.Errorf("slow item error = %q", e)
	}
	if resp.Response.Items[1].Value != verifiedValue {
		t.Errorf("fast item = %+v", resp.Response.Items[1])
	}
}

func TestTrustReload(t *testing.T) {
	file := filepath.Join(t.TempDir(), "policy.json")
	key := publicKeyPEM(t)
	write := func(repos []string, keys string) {
		b, _ := json.Marshal(map[string]any{"repositories": repos, "publicKeys": keys})
		if err := os.WriteFile(file, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write([]string{"ghcr.io/org"}, key)
	var applied []*cosignverify.Policy
	tr := &trust{file: file, apply: func(p *cosignverify.Policy) { applied = append(applied, p) }}
	if err := tr.load(); err != nil || len(applied) != 1 || fmt.Sprint(applied[0].Repositories) != "[ghcr.io/org]" {
		t.Fatalf("first load: %v, %+v", err, applied)
	}
	if err := tr.load(); err != nil || len(applied) != 1 {
		t.Errorf("unchanged files re-applied: %d", len(applied))
	}
	write([]string{"ghcr.io/org", "ghcr.io/other"}, key)
	if err := tr.load(); err != nil || len(applied) != 2 || applied[1].Revision == applied[0].Revision {
		t.Errorf("edit not applied with a new revision: %v, %+v", err, applied)
	}
	// A broken edit is not papered over by the previous policy.
	write([]string{"ghcr.io/org"}, "not a key")
	if tr.load() == nil || tr.err() == nil {
		t.Error("invalid key accepted")
	}
	write([]string{"ghcr.io/org"}, key)
	if tr.load() != nil || tr.err() != nil || len(applied) != 3 {
		t.Errorf("recovery: err %v, applied %d", tr.err(), len(applied))
	}
	write(nil, key)
	if tr.load() == nil {
		t.Error("empty allow-list accepted")
	}
	if err := os.WriteFile(file, []byte(`{"repositories":["ghcr.io/org"],"publicKeys":"`+strings.ReplaceAll(key, "\n", `\n`)+`","extra":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if tr.load() == nil {
		t.Error("unknown field accepted")
	}
	// A valid policy followed by anything else is an invalid edit, not the valid policy.
	write([]string{"ghcr.io/org"}, key)
	valid, _ := os.ReadFile(file)
	for name, suffix := range map[string]string{"garbage": "x", "second object": string(valid)} {
		if err := os.WriteFile(file, append(append([]byte{}, valid...), suffix...), 0o600); err != nil {
			t.Fatal(err)
		}
		if tr.load() == nil || tr.err() == nil {
			t.Errorf("policy with trailing %s accepted", name)
		}
	}
}

func TestMetrics(t *testing.T) {
	stats := &cosignverify.Stats{}
	stats.Hits.Add(3)
	stats.Misses.Add(1)
	h := newHandler(fakeVerifier{"good": {}, "bad": {Code: cosignverify.CodeUnsigned}}, okTrust())
	h.metrics = newMetrics(stats)
	post(t, h, request("good", "bad"))
	post(t, h, "{")
	rec := httptest.NewRecorder()
	h.metrics.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, want := range []string{
		"ztd_admission_cache_hits_total 3\n",
		"ztd_admission_cache_misses_total 1\n",
		"ztd_admission_system_errors_total 1\n",
		`ztd_admission_verdicts_total{code="ADM-UNSIGNED"} 1`,
		`ztd_admission_verdicts_total{code="allowed"} 1`,
		`ztd_admission_request_duration_seconds_bucket{le="+Inf"} 2`,
		"ztd_admission_request_duration_seconds_count 2\n",
	} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("metrics lack %q:\n%s", want, rec.Body)
		}
	}
}

// TestMutualTLS runs the real TLS configuration: TLS 1.3 only, and a client certificate chaining to
// the client CA is required. Rotating the client CA file takes effect on reload.
func TestMutualTLS(t *testing.T) {
	dir := t.TempDir()
	serverCA, clientCA, otherCA := newCA(t, "server-ca"), newCA(t, "gatekeeper-ca"), newCA(t, "other-ca")
	serverCert := serverCA.issue(t, "provider", false)
	writePEM(t, filepath.Join(dir, "tls.crt"), serverCert.certPEM)
	writePEM(t, filepath.Join(dir, "tls.key"), serverCert.keyPEM)
	writePEM(t, filepath.Join(dir, "ca.crt"), clientCA.certPEM)
	tf := &tlsFiles{certFile: filepath.Join(dir, "tls.crt"), keyFile: filepath.Join(dir, "tls.key"), clientCAFile: filepath.Join(dir, "ca.crt")}
	if err := tf.load(); err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: newHandler(fakeVerifier{"good": {}}, okTrust()), TLSConfig: tf.serverConfig(), ReadHeaderTimeout: time.Second}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	url := "https://" + ln.Addr().String() + "/"

	call := func(cert *keyPair, maxVersion uint16) error {
		roots := x509.NewCertPool()
		roots.AddCert(serverCA.cert)
		cfg := &tls.Config{RootCAs: roots, ServerName: "provider", MaxVersion: maxVersion}
		if cert != nil {
			pair, err := tls.X509KeyPair(cert.certPEM, cert.keyPEM)
			if err != nil {
				t.Fatal(err)
			}
			cfg.Certificates = []tls.Certificate{pair}
		}
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 5 * time.Second}
		resp, err := client.Post(url, "application/json", strings.NewReader(request("good")))
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("status %d", resp.StatusCode)
		}
		return nil
	}

	gatekeeper := clientCA.issue(t, "gatekeeper-webhook-service.gatekeeper-system.svc", true)
	stranger := otherCA.issue(t, "gatekeeper-webhook-service.gatekeeper-system.svc", true)
	if err := call(gatekeeper, 0); err != nil {
		t.Fatalf("Gatekeeper's client certificate refused: %v", err)
	}
	if call(nil, 0) == nil {
		t.Error("request without a client certificate accepted")
	}
	if call(stranger, 0) == nil {
		t.Error("client certificate from another CA accepted")
	}
	if call(gatekeeper, tls.VersionTLS12) == nil {
		t.Error("TLS 1.2 accepted")
	}

	// Rotation: the new CA replaces the old one on reload.
	writePEM(t, filepath.Join(dir, "ca.crt"), otherCA.certPEM)
	if err := tf.load(); err != nil {
		t.Fatal(err)
	}
	if call(stranger, 0) != nil || call(gatekeeper, 0) == nil {
		t.Error("client CA rotation not applied")
	}
}

type keyPair struct {
	cert            *x509.Certificate
	key             *ecdsa.PrivateKey
	certPEM, keyPEM []byte
}

func newCA(t *testing.T, name string) *keyPair {
	t.Helper()
	return makeCert(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: name}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}, nil)
}

func (ca *keyPair) issue(t *testing.T, name string, client bool) *keyPair {
	t.Helper()
	usage := x509.ExtKeyUsageServerAuth
	if client {
		usage = x509.ExtKeyUsageClientAuth
	}
	return makeCert(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
	}, ca)
}

func makeCert(t *testing.T, tmpl *x509.Certificate, parent *keyPair) *keyPair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl.SerialNumber = big.NewInt(time.Now().UnixNano())
	tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	signer, parentCert := key, tmpl
	if parent != nil {
		signer, parentCert = parent.key, parent.cert
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	return &keyPair{cert: cert, key: key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})}
}

func writePEM(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func publicKeyPEM(t *testing.T) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}
