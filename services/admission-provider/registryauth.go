package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/ociclient"
)

// registryCredentials reads the read credentials the provider uses for private registries: a Docker
// config file, as the .dockerconfigjson key of a kubernetes.io/dockerconfigjson Secret holds it. Each
// entry of "auths" gives a username and password, or "auth", base64 of "username:password". Keys may
// carry a scheme or a path ("https://harbor.example.org/v1/"); the credential applies to the host.
// A file that names no usable credential is an error: the operator asked for authentication.
func registryCredentials(path string) (map[string]ociclient.Credential, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config struct {
		Auths map[string]struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Auth     string `json:"auth"`
		} `json:"auths"`
	}
	if err := json.Unmarshal(raw, &config); err != nil {
		return nil, fmt.Errorf("%s: not a Docker config: %w", path, err)
	}
	if len(config.Auths) == 0 {
		return nil, fmt.Errorf("%s: no registry under \"auths\"", path)
	}
	creds := make(map[string]ociclient.Credential, len(config.Auths))
	for key, entry := range config.Auths {
		host := registryHost(key)
		cred := ociclient.Credential{Username: entry.Username, Password: entry.Password}
		if entry.Auth != "" {
			decoded, err := base64.StdEncoding.DecodeString(entry.Auth)
			if err != nil {
				return nil, fmt.Errorf("%s: the auth of %s is not base64", path, host)
			}
			user, pass, ok := strings.Cut(string(decoded), ":")
			if !ok {
				return nil, fmt.Errorf("%s: the auth of %s is not username:password", path, host)
			}
			cred = ociclient.Credential{Username: user, Password: pass}
		}
		if host == "" || cred.Username == "" || cred.Password == "" {
			return nil, errors.New(path + ": an entry without a registry, a username or a password")
		}
		creds[host] = cred
	}
	return creds, nil
}

// registryHost reduces a Docker config key to the registry host an image reference names.
func registryHost(key string) string {
	if _, rest, ok := strings.Cut(key, "://"); ok {
		key = rest
	}
	host, _, _ := strings.Cut(key, "/")
	return host
}
