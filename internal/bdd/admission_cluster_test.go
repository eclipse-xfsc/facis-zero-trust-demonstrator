package bdd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/cucumber/godog"
)

// admissionProof runs ZT-72 against a real cluster with the admission tester identity: a correctly
// signed image starts, and each non-compliant image is refused by the API server before a pod exists.
// Every input comes from the environment; a missing one fails the scenario and is named.
//
//	KUBECONFIG        kubeconfig of the ztd-adm-tester identity (never an administrator)
//	BDD_ADM_FIXTURES  file of "<case> <image digest reference>" lines (the admission-fixtures workflow output)
//	BDD_ADM_NAMESPACE namespace under admission control (default ztd-adm-001)
//	BDD_TARGET        target name, BDD_RUN_ID run identifier
//
// In the cluster dry run (BDD_MODE=cluster-dryrun) every step is skipped, so a pull request lists the
// row as not run and can never report it as passed.
type admissionProof struct {
	dryRun    bool
	namespace string
	target    string
	run       string
	fixtures  map[string]string
	signedPod string
	signed    string            // outcome of the signed image
	refusals  map[string]string // case -> API server answer
	evidence  string
}

// The non-compliant cases and the reason code each must be refused with.
var admissionRefusals = []struct{ name, want string }{
	{"unsigned", "ADM-UNSIGNED"},
	{"wrongkey", "ADM-UNSIGNED"},
	{"tag", "ADM-NOT-DIGEST"},
	{"nosbom", "ADM-SBOM-MISSING"},
	{"nomock", "ADM-NO-ATTESTATION"},
}

func (a *admissionProof) gatekeeperIsConfigured(ctx context.Context) error {
	if a.dryRun {
		return godog.ErrSkip
	}
	for _, name := range []string{"KUBECONFIG", "BDD_ADM_FIXTURES"} {
		if os.Getenv(name) == "" {
			return fmt.Errorf("the admission proof needs %s", name)
		}
	}
	a.namespace = envOr("BDD_ADM_NAMESPACE", "ztd-adm-001")
	a.target = envOr("BDD_TARGET", "local")
	a.run = strings.ToLower(regexp.MustCompile(`[^a-zA-Z0-9-]`).ReplaceAllString(envOr("BDD_RUN_ID", fmt.Sprintf("local-%d", time.Now().Unix())), "-"))
	if len(a.run) > 20 {
		a.run = a.run[len(a.run)-20:]
	}
	content, err := os.ReadFile(os.Getenv("BDD_ADM_FIXTURES"))
	if err != nil {
		return err
	}
	a.fixtures = map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(content)), "\n") {
		if name, ref, ok := strings.Cut(strings.TrimSpace(line), " "); ok {
			a.fixtures[name] = ref
		}
	}
	for _, name := range []string{"app", "unsigned", "wrongkey", "nosbom", "nomock"} {
		if !strings.Contains(a.fixtures[name], "@sha256:") {
			return fmt.Errorf("fixture %q missing or not a digest reference in %s", name, os.Getenv("BDD_ADM_FIXTURES"))
		}
	}
	// A mutable tag of the signed image's repository.
	a.fixtures["tag"] = strings.SplitN(a.fixtures["app"], "@", 2)[0] + ":fixture"
	a.evidence = repoPath(filepath.Join("bundles/bdd/evidence/bdd-zt-072", a.target, "secure-pod-startup"))
	if err := os.MkdirAll(a.evidence, 0o755); err != nil {
		return err
	}
	// The policy is in force: a server-side dry run of a mutable tag is refused by Gatekeeper.
	out, err := kubectl(a.pod("ztd-zt72-probe", a.fixtures["tag"]), "create", "--dry-run=server", "-f", "-")
	if err == nil || !strings.Contains(out, "validation.gatekeeper.sh") || !strings.Contains(out, "ADM-NOT-DIGEST") {
		return fmt.Errorf("admission policy not in force in %s: %s", a.namespace, out)
	}
	return nil
}

func (a *admissionProof) imagesSubmitted(ctx context.Context) error {
	if a.dryRun {
		return godog.ErrSkip
	}
	a.signedPod = "ztd-zt72-signed-" + a.run
	if out, err := submit(a.pod(a.signedPod, a.fixtures["app"])); err == nil {
		a.signed = "admitted"
	} else {
		a.signed = "refused: " + out
	}
	a.refusals = map[string]string{}
	for _, c := range admissionRefusals {
		name := "ztd-zt72-" + c.name + "-" + a.run
		out, err := submit(a.pod(name, a.fixtures[c.name]))
		if err == nil {
			a.refusals[c.name] = "admitted"
			_, _ = kubectl("", "-n", a.namespace, "delete", "pod", name, "--wait=false")
			continue
		}
		a.refusals[c.name] = out
	}
	return nil
}

func (a *admissionProof) signedStartsOthersDenied(ctx context.Context) error {
	if a.dryRun {
		return godog.ErrSkip
	}
	var problems []string
	if a.signed != "admitted" {
		problems = append(problems, "signed image "+a.signed)
	} else if out, err := kubectl("", "-n", a.namespace, "wait", "--for=condition=Ready", "pod/"+a.signedPod, "--timeout=180s"); err != nil {
		problems = append(problems, "signed pod did not start: "+out)
	}
	for _, c := range admissionRefusals {
		got := a.refusals[c.name]
		if !strings.Contains(got, "denied the request") || !strings.Contains(got, c.want) {
			problems = append(problems, fmt.Sprintf("%s: want a denial with %s, got %s", c.name, c.want, got))
		}
		if err := a.absent("ztd-zt72-" + c.name + "-" + a.run); err != nil {
			problems = append(problems, c.name+": "+err.Error())
		}
	}
	if err := a.writeEvidence(problems); err != nil {
		return err
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "\n"))
	}
	return nil
}

// writeEvidence records what was admitted and refused, the pod that ran, the policy and key the proof
// used (by content hash), and labels it: non-target cluster, interim key, not the client trust chain.
func (a *admissionProof) writeEvidence(problems []string) error {
	podJSON, _ := kubectl("", "-n", a.namespace, "get", "pod", a.signedPod, "-o", "json")
	var pod struct {
		Spec struct {
			NodeName string `json:"nodeName"`
		} `json:"spec"`
		Status struct {
			Phase             string `json:"phase"`
			ContainerStatuses []struct {
				Image   string `json:"image"`
				ImageID string `json:"imageID"`
				Ready   bool   `json:"ready"`
			} `json:"containerStatuses"`
		} `json:"status"`
	}
	_ = json.Unmarshal([]byte(podJSON), &pod)
	policy := map[string]string{}
	files, _ := filepath.Glob(repoPath("deployment/admission/*/*.yaml"))
	files = append(files, repoPath("deployment/admission/gatekeeper-values.yaml"), repoPath("deployment/admission/exemptions.yaml"), repoPath("docs/contracts/keys/interim-cosign.pub"))
	sort.Strings(files)
	for _, f := range files {
		if content, err := os.ReadFile(f); err == nil {
			sum := sha256.Sum256(content)
			rel, _ := filepath.Rel(repoRoot, f)
			policy[rel] = hex.EncodeToString(sum[:])
		}
	}
	record := map[string]any{
		"label":     "non-target cluster; interim signing key; not the client trust chain",
		"target":    a.target,
		"run":       a.run,
		"namespace": a.namespace,
		"fixtures":  a.fixtures,
		"signed":    map[string]any{"image": a.fixtures["app"], "outcome": a.signed, "pod": a.signedPod, "node": pod.Spec.NodeName, "phase": pod.Status.Phase, "containers": pod.Status.ContainerStatuses},
		"refusals":  a.refusals,
		"policy":    policy,
		"problems":  problems,
	}
	b, _ := json.MarshalIndent(record, "", "  ")
	if err := os.WriteFile(filepath.Join(a.evidence, "admission.json"), b, 0o644); err != nil {
		return err
	}
	scenario, _ := json.MarshalIndent(map[string]any{
		"row": "ZT-72", "target": a.target, "run": a.run,
		"chart": "admission fixtures signed with the interim key (non-target)", "fixture": false,
	}, "", "  ")
	return os.WriteFile(filepath.Join(a.evidence, "scenario.json"), scenario, 0o644)
}

// pod is a manifest that meets the restricted Pod Security Standard, so a refusal is always the
// admission policy's.
func (a *admissionProof) pod(name, image string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata: {name: %s, namespace: %s}
spec:
  securityContext: {runAsNonRoot: true, runAsUser: 65534, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: app
      image: %q
      command: [sleep, "3600"]
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}}
`, name, a.namespace, image)
}

// absent requires the API server to answer NotFound for the pod; any other failure to observe it is
// an error, never taken for absence.
func (a *admissionProof) absent(name string) error {
	out, err := kubectl("", "-n", a.namespace, "get", "pod", name, "-o", "name")
	switch {
	case err == nil:
		return fmt.Errorf("pod %s exists", name)
	case strings.Contains(out, "NotFound"):
		return nil
	default:
		return fmt.Errorf("cannot observe pod %s: %s", name, out)
	}
}

// cleanup removes the signed pod and waits until it is gone; a pod left behind fails the scenario.
func (a *admissionProof) cleanup() error {
	if a.signedPod == "" {
		return nil
	}
	if out, err := kubectl("", "-n", a.namespace, "delete", "pod", a.signedPod, "--ignore-not-found", "--wait=true", "--timeout=120s"); err != nil {
		return fmt.Errorf("removing %s: %s", a.signedPod, out)
	}
	return a.absent(a.signedPod)
}

// verifying matches the provider's fail-closed answer while an image's verification is still running
// (a cold cache): the verification finishes and its verdict is cached, so the same request is retried.
var verifying = regexp.MustCompile(`ADM-PROVIDER-DOWN: verification (still in progress|did not finish)`)

// submit creates a pod, retrying only while its image is still being verified; any other answer -
// admission or a refusal with a verdict - is final.
func submit(manifest string) (string, error) {
	for attempt := 0; ; attempt++ {
		out, err := kubectl(manifest, "create", "-f", "-")
		if err == nil || !verifying.MatchString(out) || attempt == 12 {
			return out, err
		}
		time.Sleep(5 * time.Second)
	}
}

func kubectl(stdin string, args ...string) (string, error) {
	cmd := exec.Command("kubectl", args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func registerAdmissionProof(ctx *godog.ScenarioContext, dryRun bool) {
	a := &admissionProof{}
	ctx.Before(func(c context.Context, _ *godog.Scenario) (context.Context, error) {
		*a = admissionProof{dryRun: dryRun}
		return c, nil
	})
	ctx.After(func(c context.Context, _ *godog.Scenario, err error) (context.Context, error) {
		if a.dryRun {
			return c, nil
		}
		return c, a.cleanup()
	})
	ctx.Step(`^Gatekeeper is configured with the approved admission policy$`, a.gatekeeperIsConfigured)
	ctx.Step(`^one correctly signed image and one unsigned/non-compliant image are submitted for pod creation$`, a.imagesSubmitted)
	ctx.Step(`^the signed compliant pod may start AND the unsigned/non-compliant pod is denied before startup\.$`, a.signedStartsOthersDenied)
}
