package bdd

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"github.com/cucumber/godog"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/connectorgateway"
)

// This row uses cluster mode because its proof owns external cmcd processes.
// Its target is local processes, never a zone or Kubernetes context.
type attestedGatewayProof struct {
	dry    bool
	dir    string
	cancel context.CancelFunc
	done   chan error
	log    *os.File
}

func (p *attestedGatewayProof) established() error {
	if p.dry {
		return godog.ErrSkip
	}
	root := repoPath("bundles/bdd/evidence/bdd-zt-019/local")
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	dir, err := os.MkdirTemp(root, time.Now().UTC().Format("20060102T150405Z")+"-")
	if err != nil {
		return err
	}
	p.dir = dir
	p.log, err = os.Create(filepath.Join(dir, "runner.log"))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	p.cancel = cancel
	cmd := exec.CommandContext(ctx, "bash", repoPath("scripts/verify-attested-gateway/verify.sh"), "--out", dir)
	cmd.Dir = repoPath(".")
	cmd.Env = append(os.Environ(), "GATEWAY_CONTROL_DIR="+dir)
	cmd.Stdout = p.log
	cmd.Stderr = p.log
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
	cmd.WaitDelay = 5 * time.Second
	if err = cmd.Start(); err != nil {
		return err
	}
	p.done = make(chan error, 1)
	go func() { p.done <- cmd.Wait() }()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		if data, readErr := os.ReadFile(filepath.Join(dir, "ready.json")); readErr == nil {
			var entries []connectorgateway.Event
			if err = json.Unmarshal(data, &entries); err == nil {
				return establishedGateway(entries)
			}
		}
		select {
		case err = <-p.done:
			p.done = nil
			return fmt.Errorf("gateway setup exited before establishing a channel (%v); see %s", err, dir)
		case <-ctx.Done():
			return fmt.Errorf("gateway setup timed out; see %s", dir)
		case <-tick.C:
		}
	}
}
func (p *attestedGatewayProof) forwarded() error {
	if p.dry {
		return godog.ErrSkip
	}
	if p.done == nil {
		return fmt.Errorf("no running gateway proof")
	}
	if err := os.WriteFile(filepath.Join(p.dir, "forward"), []byte("forward\n"), 0o600); err != nil {
		return err
	}
	err := <-p.done
	p.done = nil
	if err != nil {
		return fmt.Errorf("gateway proof failed: %w; see %s", err, p.dir)
	}
	return nil
}
func (p *attestedGatewayProof) preserved() error {
	if p.dry {
		return godog.ErrSkip
	}
	data, err := os.ReadFile(filepath.Join(p.dir, "attested-gateway/record.json"))
	if err != nil {
		return err
	}
	return decideGateway(data)
}
func establishedGateway(entries []connectorgateway.Event) error {
	var left, right *connectorgateway.Event
	for i := range entries {
		e := &entries[i]
		if e.Decision != "established" {
			continue
		}
		if e.Role == "egress" {
			left = e
		}
		if e.Role == "ingress" {
			right = e
		}
	}
	if left == nil || right == nil || left.Peer != "spiffe://b/gateway" || right.Peer != "spiffe://a/gateway" || left.TLSVersion != tls.VersionTLS13 || right.TLSVersion != tls.VersionTLS13 || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(left.Binding) || left.Binding != right.Binding {
		return fmt.Errorf("no matching mutually attested TLS 1.3 channel at both connectors")
	}
	return nil
}
func decideGateway(data []byte) error {
	var r struct {
		Passed    bool                     `json:"passed"`
		Proof     string                   `json:"proof"`
		Events    []connectorgateway.Event `json:"events"`
		WireBytes int                      `json:"interConnectorTLSBytes"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return err
	}
	if !r.Passed || r.Proof != "http-grpc-two-cmcd" {
		return fmt.Errorf("HTTP/gRPC real-cmcd proof did not pass")
	}
	if err := establishedGateway(r.Events); err != nil {
		return err
	}
	// The three refusals of the proof, each by its recorded reason: a plaintext peer at the
	// ingress, a TLS peer that never attests at the ingress, and the egress facing such a peer.
	const plain, unattested = "atls: peer does not speak attested TLS 1.3", "atls: handshake timed out"
	refused := map[string]int{}
	for _, e := range r.Events {
		if e.Decision == "refused" {
			refused[e.Role+" "+e.Reason]++
		}
	}
	if refused["ingress "+plain] != 1 || refused["ingress "+unattested] != 1 || refused["egress "+unattested] != 1 {
		return fmt.Errorf("missing a recorded refusal of an unprotected path: %v", refused)
	}
	if r.WireBytes <= 0 {
		return fmt.Errorf("no TLS bytes recorded on the inter-connector hop")
	}
	return nil
}
func registerAttestedGateway(ctx *godog.ScenarioContext, dry bool) {
	p := &attestedGatewayProof{dry: dry}
	ctx.After(func(c context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		if p.cancel != nil {
			p.cancel()
		}
		if p.done != nil {
			<-p.done
			p.done = nil
		}
		if p.log != nil {
			_ = p.log.Close()
			p.log = nil
		}
		return c, nil
	})
	ctx.Step(`^two Zero Trust Connectors with an established attested TLS channel$`, p.established)
	ctx.Step(`^an upstream request including relevant HTTP/gRPC metadata is forwarded through the connector pair$`, p.forwarded)
	ctx.Step(`^the request reaches the counter side over that protected channel with required call information preserved AND no unprotected inter-connector path is used\.$`, p.preserved)
}
