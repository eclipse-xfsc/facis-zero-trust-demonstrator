package guard

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/connectorclient"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/dpopproof"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/policyhook/envoyhook"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/policyhook/hook"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/policyevaluator"
	"go.yaml.in/yaml/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// grpcMethodUnderTest is the sample gRPC call: the standard health service, whose client and
// server ship with the gRPC library, so the test needs no generated code of its own.
const grpcMethodUnderTest = "/grpc.health.v1.Health/Check"

// TestGuardedGRPCThroughEnvoy sends gRPC and REST calls through Envoy from the pinned image,
// configured with the envoy.yaml the guard chart renders for the gRPC option, to the guard's
// runtime as the ext_authz hook and the policy evaluator's own rule set, both built from the
// configuration the same render produces. The token and the DPoP proof are real and verified; the
// token store's two internal endpoints and the protected resource are stand-ins of the test.
//
// It runs when GUARD_ENVOY_IMAGE names the image (scripts/tools/pins.env, ENVOY_IMAGE) and needs
// docker and helm. It proves the guard path. It does not prove the mesh: no sidecar is in front of
// Envoy here, so the caller's identity header is the test's own.
func TestGuardedGRPCThroughEnvoy(t *testing.T) {
	image := os.Getenv("GUARD_ENVOY_IMAGE")
	if image == "" {
		t.Skip("GUARD_ENVOY_IMAGE is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()

	// Where the test's listeners bind and how the Envoy container reaches them: its own network
	// namespace on Linux, published ports and the host's name elsewhere.
	bind, fromEnvoy, hostNetwork := "0.0.0.0", "host.docker.internal", false
	if runtime.GOOS == "linux" {
		bind, fromEnvoy, hostNetwork = "127.0.0.1", "127.0.0.1", true
	}
	listen := func() net.Listener {
		l, err := net.Listen("tcp", bind+":0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.Close() })
		return l
	}
	port := func(l net.Listener) int { return l.Addr().(*net.TCPAddr).Port }
	local := func(l net.Listener) string { return fmt.Sprintf("http://127.0.0.1:%d", port(l)) }

	// The chart's render with the gRPC option: Envoy's bootstrap and both configurations.
	rendered := renderGuardChart(t, ctx)
	var cfg Config
	if err := json.Unmarshal([]byte(rendered.guardConfig), &cfg); err != nil {
		t.Fatal(err)
	}
	var policyCfg policyevaluator.Config
	if err := json.Unmarshal([]byte(rendered.policyConfig), &policyCfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.GRPCMethods) != 1 || cfg.GRPCMethods[0] != grpcMethodUnderTest || len(policyCfg.GRPCMethods) != 1 {
		t.Fatalf("the render did not carry the gRPC method to both configurations: %v %v", cfg.GRPCMethods, policyCfg.GRPCMethods)
	}

	// The signing key of the tokens and its key set.
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := dependencyKey{private}
	jwk := key.JWK()
	jwk.Kid = "test"
	jkt, err := jwk.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}

	// The policy evaluator's rule set, reached as the guard reaches it. The mesh would name the
	// guard as the caller; here the test does.
	policy, err := policyevaluator.New(policyCfg)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var inputs []hook.Input
	var substituted []hook.SubstituteRequest
	dependencies := http.NewServeMux()
	dependencies.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []jose.JWK{jwk}})
	})
	dependencies.HandleFunc("/decision", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var in hook.Input
		_ = json.Unmarshal(body, &in)
		mu.Lock()
		inputs = append(inputs, in)
		mu.Unlock()
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		r.Header.Set("X-Forwarded-Client-Cert", "URI="+policyCfg.GuardCallers[0])
		policy.ServeHTTP(w, r)
	})
	dependencies.HandleFunc("/internal/replay-check", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]bool{"fresh": true})
	})
	dependencies.HandleFunc("/internal/substitute", func(w http.ResponseWriter, r *http.Request) {
		var req hook.SubstituteRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		mu.Lock()
		substituted = append(substituted, req)
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{"authorization": "DPoP upstream-token", "dpop": "upstream-proof", "expires_at": time.Now().Add(time.Minute).UTC().Format(time.RFC3339)})
	})
	dependencyListener := listen()
	go func() { _ = http.Serve(dependencyListener, dependencies) }()

	// The guard's runtime as Envoy's ext_authz hook.
	cfg.JWKSURL, cfg.PolicyURL, cfg.StoreURL = local(dependencyListener)+"/jwks", local(dependencyListener), local(dependencyListener)
	guardRuntime, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	hookListener := listen()
	hookServer := grpc.NewServer()
	envoyhook.RegisterAuthz(hookServer, guardRuntime)
	go func() { _ = hookServer.Serve(hookListener) }()
	t.Cleanup(hookServer.Stop)

	// The protected resource: a gRPC health service and the REST route, each recording what
	// reached it.
	var grpcCalls []metadata.MD
	record := func(ctx context.Context) {
		md, _ := metadata.FromIncomingContext(ctx)
		mu.Lock()
		grpcCalls = append(grpcCalls, md)
		mu.Unlock()
	}
	resourceGRPC := grpc.NewServer(
		grpc.UnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			record(ctx)
			return handler(ctx, req)
		}),
		// Streaming methods are recorded too: the health service's Watch is one, and a call that
		// reached it must not pass as a call that was refused.
		grpc.StreamInterceptor(func(srv any, stream grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
			record(stream.Context())
			return handler(srv, stream)
		}))
	healthpb.RegisterHealthServer(resourceGRPC, health.NewServer())
	grpcListener := listen()
	go func() { _ = resourceGRPC.Serve(grpcListener) }()
	t.Cleanup(resourceGRPC.Stop)
	var restCalls []http.Header
	restListener := listen()
	go func() {
		_ = http.Serve(restListener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			restCalls = append(restCalls, r.Header.Clone())
			mu.Unlock()
			_, _ = w.Write([]byte(`{"ok":true}`))
		}))
	}()

	// Envoy, with the rendered bootstrap. Only where things are changes: the ports its listener
	// and admin bind, the addresses of the hook and the resource, and the hook cluster's type, since
	// the hook is no longer a literal loopback address.
	listenerPort, adminPort := freePort(t), freePort(t)
	bootstrap := rendered.envoy
	for _, change := range [][2]string{
		{"socket_address: {address: 0.0.0.0, port_value: 8080}", fmt.Sprintf("socket_address: {address: 0.0.0.0, port_value: %d}", listenerPort)},
		{"socket_address: {address: 127.0.0.1, port_value: 9901}", fmt.Sprintf("socket_address: {address: 0.0.0.0, port_value: %d}", adminPort)},
		{"socket_address: {address: 127.0.0.1, port_value: 50051}", fmt.Sprintf("socket_address: {address: %s, port_value: %d}", fromEnvoy, port(hookListener))},
		{"socket_address: {address: ztd-protected-resource, port_value: 9090}", fmt.Sprintf("socket_address: {address: %s, port_value: %d}", fromEnvoy, port(grpcListener))},
		{"socket_address: {address: ztd-protected-resource, port_value: 8080}", fmt.Sprintf("socket_address: {address: %s, port_value: %d}", fromEnvoy, port(restListener))},
		{"type: STATIC", "type: STRICT_DNS"},
	} {
		if strings.Count(bootstrap, change[0]) != 1 {
			t.Fatalf("the rendered bootstrap does not hold %q exactly once", change[0])
		}
		bootstrap = strings.Replace(bootstrap, change[0], change[1], 1)
	}
	name := fmt.Sprintf("ztd-guard-grpc-%d", os.Getpid())
	args := []string{"run", "--detach", "--rm", "--name", name}
	if hostNetwork {
		args = append(args, "--network", "host")
	} else {
		args = append(args, "--publish", fmt.Sprintf("127.0.0.1:%d:%d", listenerPort, listenerPort), "--publish", fmt.Sprintf("127.0.0.1:%d:%d", adminPort, adminPort))
	}
	args = append(args, image, "envoy", "--config-yaml", bootstrap, "--log-level", "warn")
	if out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput(); err != nil {
		t.Fatalf("docker run: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "--force", name).Run() })
	waitForEnvoy(t, ctx, name, fmt.Sprintf("http://127.0.0.1:%d/ready", adminPort))

	// A caller: the Participant's identity as the mesh would state it, a token and a proof.
	participant := cfg.AllowedCallers[0]
	authority := strings.TrimPrefix(cfg.PublishedBaseURL, "http://")
	credential := func(scope, path string) (token, proof string) {
		now := time.Now()
		payload, _ := json.Marshal(map[string]any{"iss": cfg.Issuer, "sub": "participant", "client_id": "participant", "aud": cfg.InboundAudience, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": "grpc-" + scope + path, "scope": scope, "cnf": map[string]string{"jkt": jkt}})
		token, err := jose.Sign(ctx, jose.Header{Typ: "at+jwt", Kid: "test"}, payload, key.Sign)
		if err != nil {
			t.Fatal(err)
		}
		proof, err = dpopproof.Build(ctx, key, dpopproof.Claims{HTM: "POST", HTU: cfg.PublishedBaseURL + path, ATH: connectorclient.ATH(token)})
		if err != nil {
			t.Fatal(err)
		}
		return token, proof
	}
	conn, err := grpc.NewClient(fmt.Sprintf("127.0.0.1:%d", listenerPort), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithAuthority(authority))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := healthpb.NewHealthClient(conn)
	call := func(headers ...string) error {
		callCtx, stop := context.WithTimeout(metadata.AppendToOutgoingContext(ctx, headers...), 20*time.Second)
		defer stop()
		response, err := client.Check(callCtx, &healthpb.HealthCheckRequest{})
		if err == nil && response.GetStatus() != healthpb.HealthCheckResponse_SERVING {
			t.Errorf("the resource answered %v", response.GetStatus())
		}
		return err
	}
	count := func() (int, int) {
		mu.Lock()
		defer mu.Unlock()
		return len(grpcCalls), len(restCalls)
	}

	t.Run("a gRPC call with the right credential reaches the resource with the substituted one", func(t *testing.T) {
		token, proof := credential("report:read", grpcMethodUnderTest)
		if err := call("authorization", "DPoP "+token, "dpop", proof, "x-forwarded-client-cert", "URI="+participant); err != nil {
			t.Fatalf("the call was refused: %v", err)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(grpcCalls) != 1 {
			t.Fatalf("the resource was called %d times", len(grpcCalls))
		}
		got := grpcCalls[0]
		if v := got.Get("authorization"); len(v) != 1 || v[0] != "DPoP upstream-token" {
			t.Errorf("the resource received the authorization %v, not the substituted token", v)
		}
		if v := got.Get("dpop"); len(v) != 1 || v[0] != "upstream-proof" {
			t.Errorf("the resource received the proof %v, not the substituted one", v)
		}
		if v := got.Get("x-forwarded-client-cert"); len(v) != 0 {
			t.Errorf("the caller's identity header reached the resource: %v", v)
		}
		in := inputs[len(inputs)-1]
		if in.Request.GRPCService != "grpc.health.v1.Health" || in.Request.Path != grpcMethodUnderTest || in.Request.Method != "POST" || in.Source.SPIFFEID != participant || !in.Token.ProofValid {
			t.Errorf("the policy input does not describe the gRPC call: %+v", in.Request)
		}
		if target := substituted[len(substituted)-1].TargetURI; target != cfg.PublishedBaseURL+grpcMethodUnderTest {
			t.Errorf("the upstream proof was asked for %q", target)
		}
	})

	for _, refused := range []struct {
		name    string
		headers func() []string
		code    codes.Code
	}{
		{"no credential", func() []string { return []string{"x-forwarded-client-cert", "URI=" + participant} }, codes.Unauthenticated},
		{"a proof made for the REST route", func() []string {
			token, proof := credential("report:read", "/demo")
			return []string{"authorization", "DPoP " + token, "dpop", proof, "x-forwarded-client-cert", "URI=" + participant}
		}, codes.Unauthenticated},
		{"a token the policy has no rule for", func() []string {
			token, proof := credential("report:other", grpcMethodUnderTest)
			return []string{"authorization", "DPoP " + token, "dpop", proof, "x-forwarded-client-cert", "URI=" + participant}
		}, codes.PermissionDenied},
		{"a caller the guard does not admit", func() []string {
			token, proof := credential("report:read", grpcMethodUnderTest)
			return []string{"authorization", "DPoP " + token, "dpop", proof, "x-forwarded-client-cert", "URI=spiffe://zone-b.trust.invalid/ns/default/sa/someone-else"}
		}, codes.PermissionDenied},
	} {
		t.Run("a gRPC call with "+refused.name+" is refused before the resource", func(t *testing.T) {
			before, _ := count()
			err := call(refused.headers()...)
			if status.Code(err) != refused.code {
				t.Errorf("the call ended with %v, want %v", err, refused.code)
			}
			if after, _ := count(); after != before {
				t.Errorf("the resource was called")
			}
		})
	}

	t.Run("a gRPC method the guard does not name is no route", func(t *testing.T) {
		token, proof := credential("report:read", "/grpc.health.v1.Health/Watch")
		beforeGRPC, beforeREST := count()
		callCtx, stop := context.WithTimeout(metadata.AppendToOutgoingContext(ctx, "authorization", "DPoP "+token, "dpop", proof, "x-forwarded-client-cert", "URI="+participant), 10*time.Second)
		defer stop()
		// Envoy has no route for the path and answers 404, which a gRPC client reads as
		// Unimplemented. A deadline or a reset would mean the call got further than that.
		err := conn.Invoke(callCtx, "/grpc.health.v1.Health/Watch", &healthpb.HealthCheckRequest{}, &healthpb.HealthCheckResponse{})
		if status.Code(err) != codes.Unimplemented {
			t.Errorf("the call ended with %v, want Unimplemented", err)
		}
		if afterGRPC, afterREST := count(); afterGRPC != beforeGRPC || afterREST != beforeREST {
			t.Error("the resource was called")
		}
	})

	t.Run("the REST route is served through the same listener", func(t *testing.T) {
		token, proof := credential("report:read", "/demo")
		request, _ := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/demo", listenerPort), nil)
		request.Host = authority
		request.Header.Set("Authorization", "DPoP "+token)
		request.Header.Set("DPoP", proof)
		request.Header.Set("X-Forwarded-Client-Cert", "URI="+participant)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		_, rest := count()
		if response.StatusCode != http.StatusOK || rest != 1 {
			t.Fatalf("status %d, resource called %d times", response.StatusCode, rest)
		}
		mu.Lock()
		defer mu.Unlock()
		if got := restCalls[0].Get("Authorization"); got != "DPoP upstream-token" {
			t.Errorf("the resource received the authorization %q", got)
		}
		if in := inputs[len(inputs)-1]; in.Request.GRPCService != "" || in.Request.Path != "/demo" {
			t.Errorf("the policy input of the REST call names a gRPC service: %+v", in.Request)
		}
	})
}

type guardRender struct{ envoy, guardConfig, policyConfig string }

// renderGuardChart renders the guard chart with its CI values and the gRPC option, and returns
// the three documents of its ConfigMaps.
func renderGuardChart(t *testing.T, ctx context.Context) guardRender {
	t.Helper()
	chart := "../../deployment/helm/guard"
	out, err := exec.CommandContext(ctx, "helm", "template", "guard", chart, "-f", chart+"/ci/values.yaml",
		"--set", "grpc.methods={"+grpcMethodUnderTest+"}", "--show-only", "templates/config.yaml").CombinedOutput()
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	var render guardRender
	dec := yaml.NewDecoder(strings.NewReader(string(out)))
	for {
		var object struct {
			Metadata struct{ Name string }
			Data     map[string]string
		}
		if err := dec.Decode(&object); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("helm template output: %v", err)
		}
		switch object.Metadata.Name {
		case "ztd-guard-config":
			render.envoy, render.guardConfig = object.Data["envoy.yaml"], object.Data["config.json"]
		case "ztd-policy-config":
			render.policyConfig = object.Data["config.json"]
		}
	}
	if render.envoy == "" || render.guardConfig == "" || render.policyConfig == "" {
		t.Fatal("the render lacks a configuration document")
	}
	return render
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func waitForEnvoy(t *testing.T, ctx context.Context, container, ready string) {
	t.Helper()
	client := &http.Client{Timeout: time.Second}
	for {
		if response, err := client.Get(ready); err == nil {
			body, _ := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK && strings.HasPrefix(string(body), "LIVE") {
				return
			}
		}
		if out, err := exec.CommandContext(ctx, "docker", "inspect", "--format", "{{.State.Running}}", container).Output(); err != nil || strings.TrimSpace(string(out)) != "true" {
			logs, _ := exec.Command("docker", "logs", container).CombinedOutput()
			t.Fatalf("Envoy stopped:\n%s", logs)
		}
		select {
		case <-ctx.Done():
			t.Fatal("Envoy never became ready")
		case <-time.After(200 * time.Millisecond):
		}
	}
}
