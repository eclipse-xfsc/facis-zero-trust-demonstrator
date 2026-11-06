package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"text/template"
	"time"
)

// Markers enclose the one part of a bootstrap that differs between the hook filters.
const (
	markerBegin = "# policy-hook-filter: begin"
	markerEnd   = "# policy-hook-filter: end"
)

// bootstrapData fills a bootstrap template.
type bootstrapData struct {
	// BindAddress is what the listener and admin bind to inside the container.
	BindAddress string
	ListenPort  int
	AdminPort   int
	// UpstreamHost and HookHost are the echo upstream and the policy hook as the container
	// reaches them.
	UpstreamHost string
	UpstreamPort int
	HookHost     string
	HookPort     int
	// Timeout is the Envoy duration the hook call is bounded by, for example 0.25s.
	Timeout string
}

// renderBootstrap fills the template at path with d.
func renderBootstrap(path string, d bootstrapData) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	t, err := template.New("bootstrap").Option("missingkey=error").Parse(string(b))
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	var out bytes.Buffer
	if err := t.Execute(&out, d); err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	return out.String(), nil
}

// envoyDuration formats d as Envoy writes durations.
func envoyDuration(d time.Duration) string { return fmt.Sprintf("%gs", d.Seconds()) }

// splitFilterBlock returns the text before the begin marker, the block between the markers
// (markers excluded) and the text after the end marker.
func splitFilterBlock(cfg string) (before, block, after string, err error) {
	i := strings.Index(cfg, markerBegin)
	j := strings.Index(cfg, markerEnd)
	if i < 0 || j < 0 || j < i {
		return "", "", "", errors.New("the bootstrap does not carry the filter markers in order")
	}
	return cfg[:i], cfg[i+len(markerBegin) : j], cfg[j+len(markerEnd):], nil
}

// identicalOutsideFilterBlock reports whether a and b differ only between the markers.
func identicalOutsideFilterBlock(a, b string) (bool, error) {
	ab, _, aa, err := splitFilterBlock(a)
	if err != nil {
		return false, err
	}
	bb, _, ba, err := splitFilterBlock(b)
	if err != nil {
		return false, err
	}
	return ab == bb && aa == ba, nil
}

// envoyInstance is a running Envoy container.
type envoyInstance struct {
	name string
}

// startEnvoyContainer runs Envoy detached from image with the whole configuration on the command
// line (no mount): in the host's network namespace when hostNetwork is set (Linux), otherwise
// with ports published on 127.0.0.1.
func startEnvoyContainer(ctx context.Context, image, name, configYAML string, hostNetwork bool, ports []int) (*envoyInstance, error) {
	args := []string{"run", "--detach", "--rm", "--name", name}
	if hostNetwork {
		args = append(args, "--network", "host")
	} else {
		for _, p := range ports {
			args = append(args, "--publish", fmt.Sprintf("127.0.0.1:%d:%d", p, p))
		}
	}
	args = append(args, image, "envoy", "--config-yaml", configYAML, "--log-level", "warn")
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("docker run: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return &envoyInstance{name: name}, nil
}

// waitReady polls the admin /ready endpoint until Envoy reports LIVE or the context ends.
func (e *envoyInstance) waitReady(ctx context.Context, adminURL string) error {
	client := &http.Client{Timeout: time.Second}
	for {
		resp, err := client.Get(adminURL + "/ready")
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK && strings.HasPrefix(string(body), "LIVE") {
				return nil
			}
		}
		if out, err := exec.CommandContext(ctx, "docker", "inspect", "--format", "{{.State.Running}}", e.name).Output(); err != nil || strings.TrimSpace(string(out)) != "true" {
			logs, _ := exec.CommandContext(ctx, "docker", "logs", e.name).CombinedOutput()
			return fmt.Errorf("envoy container %s exited:\n%s", e.name, tail(logs, 40))
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("envoy %s not ready: %w", e.name, ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// stop removes the container.
func (e *envoyInstance) stop() { _ = exec.Command("docker", "rm", "--force", e.name).Run() }

func tail(b []byte, n int) string {
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
