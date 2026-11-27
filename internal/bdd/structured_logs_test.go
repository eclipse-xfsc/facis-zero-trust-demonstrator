package bdd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/cucumber/godog"
)

// rejectedStart is one service and a start it must refuse: the arguments and environment hold a
// configuration that cannot work, so the process stops on its own and what it wrote is the log of
// that refusal.
type rejectedStart struct {
	pkg  string
	args []string
	env  []string
	// refusal is the message of the ERROR record the start must end with: without it a service
	// that failed for another reason, a taken port for one, would pass as a rejected configuration.
	refusal string
}

var rejectedStarts = []rejectedStart{
	{pkg: "./cmd/guard", args: []string{"-config", "/nonexistent/guard.json"}, refusal: "guard stopped"},
	{pkg: "./cmd/policy-evaluator", args: []string{"-config", "/nonexistent/policy.json"}, refusal: "policy evaluator stopped"},
	{pkg: "./cmd/participant", env: []string{"PARTICIPANT_ADAPTER_MODE=neither"}, refusal: "participant configuration rejected"},
	{pkg: "./cmd/protected-resource", env: []string{"PROTECTED_RESOURCE_MODE=neither"}, refusal: "protected resource configuration rejected"},
	{pkg: "./services/connector", args: []string{"serve"}, refusal: "connector configuration rejected"},
	{pkg: "./services/token-store", args: []string{"serve"}, refusal: "token-store configuration rejected"},
	{pkg: "./services/admission-provider", args: []string{"-tls-cert", "/nonexistent/tls.crt"}, refusal: "admission-provider stopped"},
}

type structuredLogs struct {
	dir     string
	outputs map[string]string
}

func (s *structuredLogs) theServiceBinaries() error {
	dir, err := os.MkdirTemp("", "ztd-structured-logs-")
	if err != nil {
		return err
	}
	s.dir = dir
	args := []string{"build", "-o", dir + string(filepath.Separator)}
	for _, start := range rejectedStarts {
		args = append(args, start.pkg)
	}
	cmd := exec.Command("go", args...)
	cmd.Dir = repoPath(".")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("building the services: %w\n%s", err, output)
	}
	return nil
}

func (s *structuredLogs) eachServiceIsStartedWithAConfigurationItRejects() error {
	s.outputs = map[string]string{}
	for _, start := range rejectedStarts {
		name := filepath.Base(start.pkg)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cmd := exec.CommandContext(ctx, filepath.Join(s.dir, name), start.args...)
		// Nothing of the caller's environment reaches the service: a variable set on the
		// machine running the pack could otherwise make the configuration acceptable.
		cmd.Env = append([]string{}, start.env...)
		var output bytes.Buffer
		cmd.Stdout, cmd.Stderr = &output, &output
		err := cmd.Run()
		timedOut := ctx.Err() != nil
		cancel()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || timedOut {
			return fmt.Errorf("%s did not refuse its configuration (%v):\n%s", name, err, output.String())
		}
		s.outputs[name] = output.String()
	}
	return nil
}

func (s *structuredLogs) everyLineIsAJSONLogRecord() error {
	var problems []string
	for _, start := range rejectedStarts {
		name := filepath.Base(start.pkg)
		output := s.outputs[name]
		reported := false
		for _, line := range strings.Split(strings.TrimRight(output, "\n"), "\n") {
			var record struct {
				Level string `json:"level"`
				Msg   string `json:"msg"`
			}
			if err := json.Unmarshal([]byte(line), &record); err != nil || record.Level == "" || record.Msg == "" {
				problems = append(problems, fmt.Sprintf("%s: not a JSON log record: %q", name, line))
				continue
			}
			reported = reported || (record.Level == "ERROR" && record.Msg == start.refusal)
		}
		if !reported {
			problems = append(problems, fmt.Sprintf("%s: stopped without the ERROR record %q", name, start.refusal))
		}
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "\n"))
	}
	return nil
}

func registerStructuredLogs(ctx *godog.ScenarioContext) {
	logs := &structuredLogs{}
	ctx.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		if logs.dir != "" {
			_ = os.RemoveAll(logs.dir)
		}
		*logs = structuredLogs{}
		return ctx, nil
	})
	ctx.Step(`^the service binaries of the demonstrator$`, logs.theServiceBinaries)
	ctx.Step(`^each service is started with a configuration it rejects$`, logs.eachServiceIsStartedWithAConfigurationItRejects)
	ctx.Step(`^every line each service writes is a JSON log record$`, logs.everyLineIsAJSONLogRecord)
}
