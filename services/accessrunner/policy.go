// Package accessrunner is the demonstrator's privileged-operations runner: the one holder of the
// credentials for its administrative operations, which it performs for a caller only with an
// approval signed by someone else, checked on every call and valid for a bounded time.
package accessrunner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
)

// The operations the runner performs. Nothing else is reachable through it.
const (
	OpClusterRestart = "cluster-restart"     // set the restartedAt annotation of a deployment's pod template
	OpClusterLogs    = "cluster-logs"        // read the last lines of a pod's log
	OpListUsers      = "keycloak-list-users" // list the realm's users
	OpDisableUser    = "keycloak-disable-user"
	OpEnableUser     = "keycloak-enable-user"
)

// Roles are what an approval may grant, each a fixed set of operations.
var Roles = map[string][]string{
	"cluster-operator": {OpClusterLogs, OpClusterRestart},
	"user-admin":       {OpDisableUser, OpEnableUser, OpListUsers},
}

// RestartAnnotation is the one field cluster-restart changes.
const RestartAnnotation = "ztd.facis.io/restartedAt"

// MaxGrant is the longest an approval may last.
const MaxGrantSeconds = 8 * 60 * 60

// PolicyVersion is the digest of the roles and their operations. A grant names the version it was
// approved under, so it cannot be used once the roles change.
func PolicyVersion() string {
	names := make([]string, 0, len(Roles))
	for name := range Roles {
		names = append(names, name)
	}
	slices.Sort(names)
	ordered := make([][2]any, 0, len(names))
	for _, name := range names {
		ops := slices.Clone(Roles[name])
		slices.Sort(ops)
		ordered = append(ordered, [2]any{name, ops})
	}
	raw, _ := json.Marshal(struct {
		Roles      [][2]any `json:"roles"`
		Annotation string   `json:"annotation"`
		MaxSeconds int      `json:"max_seconds"`
	}{ordered, RestartAnnotation, MaxGrantSeconds})
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
