package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// kubeClient is the three calls the puller makes to the API server, with the pod's own service
// account: read the Application, merge-patch it, create an Event on it.
//
// ponytail: a first-party client instead of client-go, which would add some sixty modules for one
// resource and one verb each.
type kubeClient struct {
	base  string
	token string
	http  *http.Client
}

const serviceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// inClusterKube reads the pod's service account: the API address from the environment, the token
// and the cluster CA from the mounted secret.
func inClusterKube() (*kubeClient, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errors.New("not in a cluster: KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT are not set")
	}
	token, err := os.ReadFile(serviceAccountDir + "/token")
	if err != nil {
		return nil, err
	}
	ca, err := os.ReadFile(serviceAccountDir + "/ca.crt")
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("the service account's ca.crt holds no certificate")
	}
	return &kubeClient{
		base:  "https://" + host + ":" + port,
		token: strings.TrimSpace(string(token)),
		http:  &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}},
	}, nil
}

// application is the part of an Argo CD Application the puller reads.
type application struct {
	Metadata struct {
		Name        string            `json:"name"`
		Namespace   string            `json:"namespace"`
		UID         string            `json:"uid"`
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
	Spec struct {
		Source struct {
			Helm struct {
				ValuesObject struct {
					Package struct {
						Digest string `json:"digest"`
					} `json:"package"`
				} `json:"valuesObject"`
			} `json:"helm"`
		} `json:"source"`
	} `json:"spec"`
}

func applicationPath(namespace, name string) string {
	return "/apis/argoproj.io/v1alpha1/namespaces/" + namespace + "/applications/" + name
}

func (k *kubeClient) getApplication(ctx context.Context, namespace, name string) (*application, error) {
	body, err := k.do(ctx, http.MethodGet, applicationPath(namespace, name), "", nil)
	if err != nil {
		return nil, err
	}
	var app application
	if err := json.Unmarshal(body, &app); err != nil {
		return nil, fmt.Errorf("application: %w", err)
	}
	return &app, nil
}

// patchApplication sends a JSON merge patch: maps merge, so the digest lands inside the values the
// installer wrote, and a null removes an annotation.
func (k *kubeClient) patchApplication(ctx context.Context, namespace, name string, patch map[string]any) error {
	body, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	_, err = k.do(ctx, http.MethodPatch, applicationPath(namespace, name), "application/merge-patch+json", body)
	return err
}

// createEvent records what the puller did on the Application, as `kubectl describe` shows it.
func (k *kubeClient) createEvent(ctx context.Context, namespace string, app *application, kind, reason, message string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	event := map[string]any{
		"apiVersion": "v1",
		"kind":       "Event",
		"metadata":   map[string]any{"generateName": app.Metadata.Name + ".", "namespace": namespace},
		"involvedObject": map[string]any{
			"apiVersion": "argoproj.io/v1alpha1", "kind": "Application",
			"name": app.Metadata.Name, "namespace": app.Metadata.Namespace, "uid": app.Metadata.UID,
		},
		"reason":         reason,
		"message":        message,
		"type":           kind,
		"source":         map[string]any{"component": "policy-puller"},
		"firstTimestamp": now,
		"lastTimestamp":  now,
		"count":          1,
	}
	body, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = k.do(ctx, http.MethodPost, "/api/v1/namespaces/"+namespace+"/events", "application/json", body)
	return err
}

const maxResponse = 4 << 20

func (k *kubeClient) do(ctx context.Context, method, path, contentType string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, k.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+k.token)
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := k.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return nil, err
	}
	if len(out) > maxResponse {
		return nil, errors.New("API response too large")
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var status struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(out, &status)
		return nil, fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, status.Message)
	}
	return out, nil
}
