// Command chartcheck protects runtime chart boundaries using Helm's actual output.
package main

import (
	"bytes"
	"encoding/json"
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
func render(chart string, runtime bool) ([]object, error) {
	args := []string{"template", "check", chart, "-n", "chart-check", "-f", filepath.Join(chart, "ci/values.yaml")}
	if runtime {
		args = append(args, "-f", filepath.Join(chart, "ci/runtime-values.yaml"))
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
	if name != "guard" && name != "token-store" && name != "connector" {
		return nil
	}
	runtime := name == "token-store"
	if runtime {
		if _, err := os.Stat(filepath.Join(chart, "ci/runtime-values.yaml")); errors.Is(err, os.ErrNotExist) {
			return nil
		}
	}
	docs, err := render(chart, runtime)
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
		return nil
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
	// Ensure public runtime annotations remain JSON accepted by the proxy.
	var proxy object
	raw, _ := at(deployment, "spec", "template", "metadata", "annotations", "proxy.istio.io/config").(string)
	return need(json.Unmarshal([]byte(raw), &proxy) == nil && at(proxy, "proxyHeaders", "forwardedClientCert") == "SANITIZE_SET", "runtime proxy must sanitize caller identity")
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
	_, err = render(guard, false)
	return err
}
