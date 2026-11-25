// Command chartcheck protects runtime chart boundaries using Helm's actual output.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

type object = map[string]any

func at(v any, path ...string) any {
	for _, key := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[key]
	}
	return v
}
func list(v any) []any { a, _ := v.([]any); return a }
func need(ok bool, message string) error {
	if !ok {
		return errors.New(message)
	}
	return nil
}

// render renders the chart with ci/values.yaml and, when variant is set, ci/<variant>-values.yaml.
func render(chart, variant string) ([]object, error) {
	args := []string{"template", "check", chart, "-n", "chart-check", "-f", filepath.Join(chart, "ci/values.yaml")}
	if variant != "" {
		args = append(args, "-f", filepath.Join(chart, "ci/"+variant+"-values.yaml"))
	}
	out, err := exec.Command("helm", args...).Output()
	if err != nil {
		return nil, errors.New("runtime Helm render failed")
	}
	dec := yaml.NewDecoder(bytes.NewReader(out))
	var docs []object
	for {
		var d object
		err := dec.Decode(&d)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.New("rendered YAML invalid")
		}
		if len(d) > 0 {
			docs = append(docs, d)
		}
	}
	return docs, nil
}
func find(docs []object, kind, name string) object {
	for _, d := range docs {
		if d["kind"] == kind && (name == "" || at(d, "metadata", "name") == name) {
			return d
		}
	}
	return nil
}
func check(root, chart string) error {
	name := filepath.Base(chart)
	if name == "application-service" {
		return checkGuarded(root)
	}
	if name == "tsa-policy" {
		return checkTSA(root, chart)
	}
	if name != "guard" && name != "token-store" && name != "connector" {
		return nil
	}
	runtime := name == "token-store"
	if runtime {
		if _, err := os.Stat(filepath.Join(chart, "ci/runtime-values.yaml")); errors.Is(err, os.ErrNotExist) {
			return nil
		}
	}
	variant := map[string]string{"token-store": "runtime", "connector": "schema"}[name]
	docs, err := render(chart, variant)
	if err != nil {
		return err
	}
	if name == "guard" {
		data, err := os.ReadFile(filepath.Join(chart, "values.yaml"))
		if err != nil {
			return err
		}
		var values object
		if yaml.Unmarshal(data, &values) != nil {
			return errors.New("invalid guard values")
		}
		pins, err := os.ReadFile(filepath.Join(root, "scripts/tools/pins.env"))
		if err != nil {
			return err
		}
		digest := ""
		for _, line := range strings.Split(string(pins), "\n") {
			if strings.HasPrefix(line, "ENVOY_IMAGE=") {
				_, digest, _ = strings.Cut(line, "@")
			}
		}
		repository, _ := at(values, "images", "envoy", "repository").(string)
		return need(digest != "" && at(values, "images", "envoy", "digest") == digest && strings.HasPrefix(repository, "ghcr.io/eclipse-xfsc/") && !strings.Contains(repository, ":"), "guard Envoy default must use the admitted repository and pinned digest")
	}
	deployment := find(docs, "Deployment", "")
	selector := at(deployment, "spec", "selector", "matchLabels")
	peer := find(docs, "PeerAuthentication", "")
	if err := need(at(peer, "spec", "mtls", "mode") == "STRICT" && reflect.DeepEqual(at(peer, "spec", "selector", "matchLabels"), selector), "runtime STRICT policy must select the server"); err != nil {
		return err
	}
	if !runtime {
		// The connector's selector has no component label, so its migration Job's pods must differ in
		// one of the selector's own labels or the Service and the policies take them for the service.
		labels := at(find(docs, "Job", "ztd-connector-migrate"), "spec", "template", "metadata", "labels")
		apart := false
		for key, value := range selector.(map[string]any) {
			apart = apart || at(labels, key) != value
		}
		return need(labels != nil && apart, "the connector's selector must not select the schema Job's pods")
	}
	refused, renderErr := exec.Command("helm", "template", "check", chart, "-f", filepath.Join(chart, "ci/values.yaml"), "-f", filepath.Join(chart, "ci/runtime-values.yaml"), "--set-json", "networkPolicy.schemaEgress=[]").CombinedOutput()
	if renderErr == nil || !strings.Contains(string(refused), "networkPolicy.schemaEgress must include the database lane") {
		return errors.New("schema policy without database egress must fail rendering")
	}
	mounted := false
	for _, v := range list(at(deployment, "spec", "template", "spec", "volumes")) {
		if at(v, "name") == "acquisition" {
			mounted = at(v, "configMap", "items") == nil && at(v, "configMap", "name") != nil
		}
	}
	if err := need(mounted, "runtime public-key ConfigMap must be mounted in full"); err != nil {
		return err
	}
	for _, d := range docs {
		if d["kind"] == "Job" {
			if err := need(at(d, "spec", "template", "metadata", "annotations", "sidecar.istio.io/nativeSidecar") == "true", "runtime schema Jobs require native sidecars"); err != nil {
				return err
			}
		}
	}
	server := find(docs, "NetworkPolicy", "ztd-token-store")
	schema := find(docs, "NetworkPolicy", "ztd-token-store-schema")
	if err := need(at(server, "spec", "podSelector", "matchLabels", "app.kubernetes.io/component") == "server", "server NetworkPolicy must exclude schema Jobs"); err != nil {
		return err
	}
	if err := need(at(schema, "spec", "podSelector", "matchLabels", "app.kubernetes.io/component") == "schema", "schema policy must precede Jobs"); err != nil {
		return err
	}
	policyWeight, err := strconv.Atoi(fmt.Sprint(at(schema, "metadata", "annotations", "helm.sh/hook-weight")))
	if err != nil {
		return errors.New("schema policy weight must be numeric")
	}
	for _, d := range docs {
		if d["kind"] == "Job" {
			jobWeight, err := strconv.Atoi(fmt.Sprint(at(d, "metadata", "annotations", "helm.sh/hook-weight")))
			if err != nil || policyWeight >= jobWeight {
				return errors.New("schema policy must precede every schema Job")
			}
		}
	}
	if err := need(reflect.DeepEqual(at(schema, "spec", "policyTypes"), []any{"Egress"}), "schema policy must be egress-only"); err != nil {
		return err
	}
	ports := map[int]bool{}
	for _, lane := range list(at(schema, "spec", "egress")) {
		for _, port := range list(at(lane, "ports")) {
			n, _ := at(port, "port").(int)
			ports[n] = true
		}
	}
	if err := need(ports[53] && ports[5432] && ports[15012], "schema policy must include DNS, configured database and istiod"); err != nil {
		return err
	}
	// The caller's identity comes from the sidecar's XFCC, sound only if the sidecar replaces a client's:
	// SANITIZE_SET is mesh-wide (zone-policy's EnvoyFilter), as zone-policy refuses a per-pod proxy configuration.
	for _, d := range append([]object{deployment}, docs...) {
		if d["kind"] == "Deployment" || d["kind"] == "Job" {
			if err := need(at(d, "spec", "template", "metadata", "annotations", "proxy.istio.io/config") == nil, "runtime pods may not set proxy.istio.io/config (refused by zone-policy)"); err != nil {
				return err
			}
		}
	}
	mesh, err := render(filepath.Join(root, "deployment/helm/zone-policy"), "")
	if err != nil {
		return err
	}
	patches := list(at(find(mesh, "EnvoyFilter", "xfcc-sanitize-set"), "spec", "configPatches"))
	sanitized := len(patches) == 1 && at(patches[0], "match", "context") == "SIDECAR_INBOUND" &&
		at(patches[0], "patch", "value", "typed_config", "forward_client_cert_details") == "SANITIZE_SET"
	if err := need(sanitized, "the mesh must sanitize caller identity on every inbound sidecar (zone-policy EnvoyFilter xfcc-sanitize-set)"); err != nil {
		return err
	}
	return checkDenialLog(mesh)
}

// checkDenialLog holds the mesh-wide Telemetry to the refusals it must log: the authorization's (HTTP and
// TCP) and the STRICT listener's, which closes a connection without mutual TLS (filter_chain_not_found).
func checkDenialLog(mesh []object) error {
	logging := list(at(find(mesh, "Telemetry", "mesh-default"), "spec", "accessLogging"))
	filter := ""
	if len(logging) == 1 {
		filter, _ = at(logging[0], "filter", "expression").(string)
	}
	for _, clause := range []string{
		`response.code_details.startsWith("rbac_access_denied")`,
		`connection.termination_details.startsWith("rbac_access_denied")`,
		`response.code_details == "filter_chain_not_found"`,
	} {
		if !strings.Contains(filter, clause) {
			return errors.New("the mesh must log refusals only, and every kind of them (zone-policy Telemetry mesh-default): its filter lacks " + clause)
		}
	}
	return need(len(strings.Split(filter, "||")) == 3, "the mesh denial log must hold refusals only (zone-policy Telemetry mesh-default): its filter has another clause")
}
func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: chartcheck REPO CHART")
		os.Exit(2)
	}
	if err := check(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("runtime chart boundaries passed")
}

// checkGuarded renders the checked-in examples and compares their effective audience configuration.
func checkGuarded(root string) error {
	app := filepath.Join(root, "deployment/helm/application-service")
	readValues := func(path string) (object, error) {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var values object
		err = yaml.Unmarshal(data, &values)
		return values, err
	}
	participant, err := readValues(filepath.Join(app, "ci/guarded-participant-values.yaml"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	resource, err := readValues(filepath.Join(app, "ci/guarded-resource-values.yaml"))
	if err != nil {
		return err
	}
	inbound := at(participant, "env", "PARTICIPANT_AUDIENCE")
	upstream := at(resource, "env", "PROTECTED_RESOURCE_AUDIENCE")
	if inbound == nil || upstream == nil || inbound == upstream {
		return errors.New("guarded example audiences must be present and distinct")
	}
	for _, name := range []string{"participant", "resource"} {
		if err := exec.Command("helm", "template", "check", app, "-f", filepath.Join(app, "ci/guarded-"+name+"-values.yaml")).Run(); err != nil {
			return fmt.Errorf("guarded %s example failed render", name)
		}
	}
	connector := filepath.Join(root, "deployment/helm/connector")
	cv, err := readValues(filepath.Join(connector, "ci/guarded-connector-values.yaml"))
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(at(cv, "oauth", "exclusiveAudiences"), []any{inbound, upstream}) {
		return errors.New("connector exclusive audiences must match guarded examples")
	}
	if err := exec.Command("helm", "template", "check", connector, "-f", filepath.Join(connector, "ci/values.yaml"), "-f", filepath.Join(connector, "ci/guarded-connector-values.yaml")).Run(); err != nil {
		return errors.New("guarded Connector example failed render")
	}
	guard := filepath.Join(root, "deployment/helm/guard")
	if _, err := os.Stat(guard); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	gv, err := readValues(filepath.Join(guard, "ci/values.yaml"))
	if err != nil {
		return err
	}
	if at(gv, "config", "inbound_audience") != inbound || at(gv, "config", "upstream_audience") != upstream {
		return errors.New("guard audiences must match Participant and Resource examples")
	}
	_, err = render(guard, "")
	return err
}

// checkTSA holds the TSA chart to its pins and trust root, and proves that declaring another bundle
// changes only the bundle ConfigMap: the pod template, and so the running pod, stays as it is.
func checkTSA(root, chart string) error {
	data, err := os.ReadFile(filepath.Join(chart, "values.yaml"))
	if err != nil {
		return err
	}
	var values object
	if yaml.Unmarshal(data, &values) != nil {
		return errors.New("invalid tsa-policy values")
	}
	pins, err := os.ReadFile(filepath.Join(root, "scripts/tools/pins.env"))
	if err != nil {
		return err
	}
	for image, pin := range map[string]string{"tsa": "TSA_POLICY_IMAGE=", "nats": "NATS_IMAGE="} {
		digest := ""
		for _, line := range strings.Split(string(pins), "\n") {
			if strings.HasPrefix(line, pin) {
				_, digest, _ = strings.Cut(line, "@")
			}
		}
		repository, _ := at(values, "images", image, "repository").(string)
		if err := need(digest != "" && at(values, "images", image, "digest") == digest && strings.HasPrefix(repository, "ghcr.io/eclipse-xfsc/"), image+" default must be the mirrored repository at the pinned digest"); err != nil {
			return err
		}
	}
	key, err := os.ReadFile(filepath.Join(root, "docs/contracts/keys/interim-cosign.pub"))
	if err != nil {
		return err
	}
	if err := need(strings.TrimSpace(fmt.Sprint(at(values, "trustRoot"))) == strings.TrimSpace(string(key)), "trustRoot default must be the repository signing key"); err != nil {
		return err
	}
	template := func(ref, revision string) (object, object, error) {
		out, err := exec.Command("helm", "template", "check", chart, "-n", "chart-check", "-f", filepath.Join(chart, "ci/values.yaml"),
			"--set", "bundle.ref="+ref, "--set", "bundle.revision="+revision).Output()
		if err != nil {
			return nil, nil, errors.New("tsa-policy render failed")
		}
		var docs []object
		dec := yaml.NewDecoder(bytes.NewReader(out))
		for {
			var d object
			if err := dec.Decode(&d); err == io.EOF {
				break
			} else if err != nil {
				return nil, nil, err
			}
			docs = append(docs, d)
		}
		pod, _ := at(find(docs, "Deployment", "tsa-policy-engine"), "spec", "template").(object)
		return pod, find(docs, "ConfigMap", "tsa-policy-bundle"), nil
	}
	repo := at(values, "bundle", "repository").(string)
	refA, refB := repo+"@sha256:"+strings.Repeat("a", 64), repo+"@sha256:"+strings.Repeat("b", 64)
	basePod, baseBundle, err := template(refA, "r1")
	if err != nil {
		return err
	}
	// The reference alone, the revision alone, and both: each is a new declaration.
	for _, change := range [][2]string{{refB, "r1"}, {refA, "r2"}, {refB, "r2"}} {
		pod, bundle, err := template(change[0], change[1])
		if err != nil {
			return err
		}
		if err := need(basePod != nil && reflect.DeepEqual(basePod, pod) && !reflect.DeepEqual(baseBundle, bundle),
			"a bundle change must change the bundle ConfigMap and nothing in the pod template"); err != nil {
			return err
		}
	}
	return nil
}
