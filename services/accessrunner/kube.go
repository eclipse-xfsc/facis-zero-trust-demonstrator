package accessrunner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// Kube calls the Kubernetes API as the runner's ServiceAccount, read from its token file on every
// call (the kubelet rotates it).
type Kube struct {
	API       string // https://kubernetes.default.svc
	TokenFile string
	HTTP      *http.Client
	Namespace string // the runner's own namespace, where its revocation list is
}

// dnsLabel is a Kubernetes namespace, deployment, pod or container name.
var dnsLabel = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)

func (k *Kube) do(ctx context.Context, method, path, contentType string, body []byte) (int, []byte, error) {
	token, err := os.ReadFile(k.TokenFile)
	if err != nil {
		return 0, nil, errors.New("runner credential unavailable")
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(k.API, "/")+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := k.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, raw, err
}

// Revoked reports whether id is on the revocation list, the ConfigMap ztd-access-revocations
// (key "revoked", one grant id per line), read now through the API.
func (k *Kube) Revoked(ctx context.Context, id string) (bool, error) {
	status, raw, err := k.do(ctx, http.MethodGet, "/api/v1/namespaces/"+url.PathEscape(k.Namespace)+"/configmaps/ztd-access-revocations", "", nil)
	if err != nil || status != http.StatusOK {
		return false, errors.New("revocation list unavailable")
	}
	var cm struct {
		Data map[string]string `json:"data"`
	}
	if json.Unmarshal(raw, &cm) != nil {
		return false, errors.New("revocation list unreadable")
	}
	list, ok := cm.Data["revoked"]
	if !ok {
		return false, errors.New("revocation list has no revoked key")
	}
	revoked := false
	for _, line := range strings.Split(list, "\n") {
		switch {
		case line == "":
		case !GrantID.MatchString(line):
			return false, errors.New("revocation list holds a line that is not a grant id")
		case line == id:
			revoked = true
		}
	}
	return revoked, nil
}

// Restart sets the restart annotation of the deployment's pod template and nothing else.
func (k *Kube) Restart(ctx context.Context, namespace, deployment string, at time.Time) error {
	patch, _ := json.Marshal(map[string]any{"spec": map[string]any{"template": map[string]any{"metadata": map[string]any{
		"annotations": map[string]string{RestartAnnotation: at.UTC().Format(time.RFC3339)}}}}})
	status, _, err := k.do(ctx, http.MethodPatch, fmt.Sprintf("/apis/apps/v1/namespaces/%s/deployments/%s", namespace, deployment),
		"application/strategic-merge-patch+json", patch)
	if err != nil || status != http.StatusOK {
		return fmt.Errorf("restart: status %d", status)
	}
	return nil
}

// Logs returns the last lines of a container's log.
func (k *Kube) Logs(ctx context.Context, namespace, pod, container string, lines int) (string, error) {
	q := url.Values{"tailLines": {fmt.Sprint(lines)}}
	if container != "" {
		q.Set("container", container)
	}
	status, raw, err := k.do(ctx, http.MethodGet, fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/log?%s", namespace, pod, q.Encode()), "", nil)
	if err != nil || status != http.StatusOK {
		return "", fmt.Errorf("logs: status %d", status)
	}
	return string(raw), nil
}
