package bdd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/policyhook/hook"
)

// participantMockProof runs ZT-74 on a throwaway kind cluster: it runs the participant-backend mock
// proof (scripts/verify-guard-catalogue/verify.sh --participant) and decides the row from the records
// the proof writes. The proof installs the Participant service in token mode in the mesh, configured
// with the Connector's and the guard's addresses; the Participant bootstraps at the Connector, is asked
// for one report through the guard and for one more while the policy engine is away, and its IF-01 v2
// lines are posted to the feed bridge and read back by the UI's identity. The trusted channel of this
// row is the zone's mesh (mutual TLS between workload identities, a DPoP-bound token through the
// Connector's guard), as for ZT-73; it is not the attested inter-zone channel.
//
//	BDD_TARGET  target name, BDD_RUN_ID run identifier
//	GUARD_CATALOGUE_KIND_CLUSTER, GUARD_CATALOGUE_REGISTRY_NAME, GUARD_CATALOGUE_HOST_REGISTRY
//	            the verifier's own names, when its defaults are taken
//
// The verifier creates and removes its own cluster and keeps its own kubeconfig: no existing cluster or
// context is touched. The record is written to bundles/bdd/evidence/bdd-zt-074/<target>/<run>, which git
// ignores. In the cluster dry run every step is skipped, so a pull request lists the row as not run.
type participantMockProof struct {
	dryRun   bool
	evidence string
	exit     int
	output   string
}

// participantMockRun is the proof's run.json.
type participantMockRun struct {
	ServedID            string `json:"served_id"`
	RefusedID           string `json:"refused_id"`
	ParticipantRunID    string `json:"participant_run_id"`
	ParticipantIdentity string `json:"participant_identity"`
	ConnectorURL        string `json:"connector_url"`
	GuardURL            string `json:"guard_url"`
	ClientID            string `json:"client_id"`
}

// decideParticipantMock decides ZT-74 from a record directory of the proof and returns one line naming
// what it found.
//
// Configured with the approved Connector endpoints: the running Deployment is in token mode and names
// the run's Connector and its guard as its only two destinations.
//
// Behaves as a participant backend using the trusted channel: its lifecycle went through registering,
// registered, presenting and acquiring_token to ready; the request it was asked for was answered 200 with
// the resource's data and is in the resource's record; and the receivers' sidecars counted requests
// served over mutual TLS from the Participant's identity to the Connector and to the guard, and from the
// guard's identity to the resource. The request made while the policy engine was away was answered 503
// without data and never reached the resource.
//
// Publishes its registration/request/status events: the feed read back from the bridge holds, under the
// Participant's one run id, its registration event, its status events up to ready, and one request event
// per request with its outcome under the request's own id. The served request's id is also the id of the
// resource's access event; the refused one's is on no other event. The guard's Envoy names each request
// itself, so its decisions are joined by caller and token instead: the feed holds exactly two guard
// decisions for the Participant's identity with its registered client's token, one allowed and one
// denied POL-PDP-UNAVAILABLE.
func decideParticipantMock(dir string) (string, error) {
	read := func(name string) (string, error) {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return "", fmt.Errorf("the proof wrote no %s: %w", name, err)
		}
		return string(raw), nil
	}
	readJSON := func(name string, into any) error {
		text, err := read(name)
		if err != nil {
			return err
		}
		if err := json.Unmarshal([]byte(text), into); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		return nil
	}
	var run participantMockRun
	if err := readJSON("run.json", &run); err != nil {
		return "", err
	}
	identity := regexp.MustCompile(`^(spiffe://[^/]+/ns/[^/]+/sa/)ztd-participant$`).FindStringSubmatch(run.ParticipantIdentity)
	if run.ServedID == "" || run.RefusedID == "" || run.ServedID == run.RefusedID || run.ParticipantRunID == "" || identity == nil ||
		run.ConnectorURL == "" || run.GuardURL == "" || run.ClientID == "" {
		return "", fmt.Errorf("run.json does not name the run: %+v", run)
	}

	var config map[string]string
	if err := readJSON("config.json", &config); err != nil {
		return "", err
	}
	if config["PARTICIPANT_ADAPTER_MODE"] != "token" || config["PARTICIPANT_CONNECTOR_URL"] != run.ConnectorURL || config["PARTICIPANT_RESOURCE_URL"] != run.GuardURL {
		return "", fmt.Errorf("the Participant is not configured in token mode with the Connector %s and its guard %s: %v", run.ConnectorURL, run.GuardURL, config)
	}

	var state struct {
		Mode, State string
		History     []struct{ State string }
	}
	if err := readJSON("state.json", &state); err != nil {
		return "", err
	}
	var steps []string
	for _, h := range state.History {
		steps = append(steps, h.State)
	}
	if state.Mode != "token" || state.State != "ready" || !strings.Contains(strings.Join(steps, " "), "registering registered presenting acquiring_token ready") {
		return "", fmt.Errorf("the Participant did not register, present, acquire its token and become ready: mode %s, state %s, history %v", state.Mode, state.State, steps)
	}

	// answer splits a recorded HTTP answer into its status and its JSON body.
	type demoAnswer struct {
		Mode, Outcome, ReasonCode, CorrelationID string
		SafeData                                 map[string]any
	}
	answer := func(name string) (string, demoAnswer, error) {
		var a demoAnswer
		text, err := read(name)
		if err != nil {
			return "", a, err
		}
		head, body, _ := strings.Cut(strings.ReplaceAll(text, "\r\n", "\n"), "\n\n")
		fields := strings.Fields(head)
		if len(fields) < 2 || json.Unmarshal([]byte(body), &a) != nil {
			return "", a, fmt.Errorf("%s holds no answer of the Participant: %.200q", name, text)
		}
		return fields[1], a, nil
	}
	status, served, err := answer("served.http")
	if err != nil {
		return "", err
	}
	// The resource's data is the report or its summary, each with an id.
	data, _ := served.SafeData["report"].(map[string]any)
	if data == nil {
		data, _ = served.SafeData["summary"].(map[string]any)
	}
	if id, _ := data["id"].(string); status != "200" || served.Mode != "token" || served.Outcome != "success" || served.CorrelationID != run.ServedID || id == "" {
		return "", fmt.Errorf("the request was not served: status %s, %+v", status, served)
	}
	status, refused, err := answer("refused.http")
	if err != nil {
		return "", err
	}
	if status != "503" || refused.Outcome != "unavailable" || refused.CorrelationID != run.RefusedID || len(refused.SafeData) != 0 {
		return "", fmt.Errorf("the request made without the policy engine was not refused without data: status %s, %+v", status, refused)
	}
	resource, err := read("resource.log")
	if err != nil {
		return "", err
	}
	if !strings.Contains(resource, run.ServedID) || strings.Contains(resource, run.RefusedID) {
		return "", errors.New("the resource's record does not hold the served request alone")
	}

	// The hops, from the receivers' sidecars.
	hops, err := read("hops.jsonl")
	if err != nil {
		return "", err
	}
	served200 := map[string]int{}
	scanner := bufio.NewScanner(strings.NewReader(hops))
	scanner.Buffer(make([]byte, 1<<16), 1<<22)
	for scanner.Scan() {
		var h struct {
			Source, Destination, Security string
			ResponseCode                  string `json:"response_code"`
			Requests                      int
		}
		if json.Unmarshal(scanner.Bytes(), &h) == nil && h.Security == "mutual_tls" && h.ResponseCode == "200" {
			served200[h.Source+" "+h.Destination] += h.Requests
		}
	}
	for _, hop := range [][2]string{{"ztd-participant", "ztd-connector"}, {"ztd-participant", "ztd-guard"}, {"ztd-guard", "ztd-protected-resource"}} {
		if served200[identity[1]+hop[0]+" "+identity[1]+hop[1]] < 1 {
			return "", fmt.Errorf("no request from %s to %s was served over mutual TLS between their identities", hop[0], hop[1])
		}
	}

	// The feed, as read back from the bridge.
	feed, err := read("feed.jsonl")
	if err != nil {
		return "", err
	}
	seen := map[string]int{}
	scanner = bufio.NewScanner(strings.NewReader(feed))
	scanner.Buffer(make([]byte, 1<<16), 1<<22)
	for scanner.Scan() {
		var e hook.Event
		if json.Unmarshal(scanner.Bytes(), &e) != nil || e.Version != 2 {
			continue
		}
		switch {
		case e.RunID == run.ParticipantRunID && strings.HasPrefix(e.Source, "participant-") && e.Kind == "step":
			// Lifecycle events carry the run's id, a request event its request's.
			if e.Payload.Detail == "request" {
				seen["request "+e.Payload.State+" "+e.Payload.ReasonCode+" "+e.CorrelationID]++
			} else if e.CorrelationID == run.ParticipantRunID {
				seen[e.Payload.Detail+" "+e.Payload.State]++
			}
		case strings.HasPrefix(e.Source, "protected-resource-") && e.Kind == "step":
			seen["access "+e.Payload.State+" "+e.CorrelationID]++
		case strings.HasPrefix(e.Source, "guard") && e.Kind == "decision" &&
			e.Payload.CallerSPIFFEID == run.ParticipantIdentity && e.Payload.TokenSubject == run.ClientID:
			seen["guard "+e.Payload.State+" "+e.Payload.ReasonCode]++
			seen["guard"]++
		}
		if e.CorrelationID == run.RefusedID {
			seen["refused id"]++
		}
	}
	for _, want := range []string{"registration registered", "status presenting", "status acquiring_token", "status ready"} {
		if seen[want] < 1 {
			return "", fmt.Errorf("the feed holds no %q event of the Participant's run %s", want, run.ParticipantRunID)
		}
	}
	var success string
	for key, n := range seen {
		if strings.HasPrefix(key, "request success ") && strings.HasSuffix(key, " "+run.ServedID) && n == 1 {
			success = strings.Fields(key)[2]
		}
	}
	if success == "" || seen["access success "+run.ServedID] != 1 {
		return "", fmt.Errorf("the feed does not hold one successful request event and the resource's access event under %s", run.ServedID)
	}
	if seen["request unavailable APP-TOKEN-RESOURCE-UNAVAILABLE "+run.RefusedID] != 1 || seen["refused id"] != 1 {
		return "", fmt.Errorf("the feed does not hold the unavailable request event, and it alone, under %s", run.RefusedID)
	}
	if seen["guard allowed "] != 1 || seen["guard denied POL-PDP-UNAVAILABLE"] != 1 || seen["guard"] != 2 {
		return "", fmt.Errorf("the feed does not hold exactly one allowed and one POL-PDP-UNAVAILABLE guard decision for the caller %s with its client's token", run.ParticipantIdentity)
	}
	return fmt.Sprintf("run %s: registered, presenting, acquiring_token and ready on the feed; request %s served 200 (%s) with the resource's access event and the guard's allowed decision for %s; request %s refused 503 with the guard's POL-PDP-UNAVAILABLE; participant -> connector, participant -> guard and guard -> resource over mutual TLS",
		run.ParticipantRunID, run.ServedID, success, run.ParticipantIdentity, run.RefusedID), nil
}

func (p *participantMockProof) mockIsConfigured() error {
	if p.dryRun {
		return godog.ErrSkip
	}
	for _, name := range []string{"BDD_TARGET", "BDD_RUN_ID"} {
		if os.Getenv(name) == "" {
			return fmt.Errorf("the participant mock proof needs %s", name)
		}
	}
	safe := regexp.MustCompile(`[^a-zA-Z0-9._-]`)
	p.evidence = repoPath(filepath.Join("bundles/bdd/evidence/bdd-zt-074",
		safe.ReplaceAllString(os.Getenv("BDD_TARGET"), "-"), safe.ReplaceAllString(os.Getenv("BDD_RUN_ID"), "-")))
	return os.MkdirAll(p.evidence, 0o755)
}

func (p *participantMockProof) scenarioRuns(ctx context.Context) error {
	if p.dryRun {
		return godog.ErrSkip
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, repoPath("scripts/verify-guard-catalogue/verify.sh"), "--participant", "--out", p.evidence)
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	p.output, p.exit = string(out), 0
	// The verifier empties its output directory first: its own log is written after it ran.
	if werr := os.WriteFile(filepath.Join(p.evidence, "verify.log"), out, 0o644); werr != nil {
		return werr
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		p.exit = exitErr.ExitCode()
	} else if err != nil {
		return fmt.Errorf("the verifier did not run: %w", err)
	}
	return nil
}

func (p *participantMockProof) behavesAndPublishes() error {
	if p.dryRun {
		return godog.ErrSkip
	}
	summary, err := decideParticipantMock(p.evidence)
	if err != nil {
		return fmt.Errorf("%w; verifier exit %d: %s; record %s", err, p.exit, lastLines(p.output, 3), p.evidence)
	}
	if p.exit != 0 {
		return fmt.Errorf("the row's records hold but %d check(s) of the run failed; record %s", p.exit, p.evidence)
	}
	fmt.Printf("ZT-74: %s; record %s\n", summary, p.evidence)
	return nil
}

func registerParticipantMockProof(ctx *godog.ScenarioContext, dryRun bool) {
	p := &participantMockProof{}
	ctx.Before(func(c context.Context, _ *godog.Scenario) (context.Context, error) {
		*p = participantMockProof{dryRun: dryRun}
		return c, nil
	})
	ctx.Step(`^the participant-backend mock is configured with the approved Connector endpoints$`, p.mockIsConfigured)
	ctx.Step(`^the demonstrator scenario runs$`, p.scenarioRuns)
	ctx.Step(`^the mock behaves as a participant backend using the trusted channel and publishes its registration/request/status events to the visualization\.$`, p.behavesAndPublishes)
}
