package accessrunner

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"time"
)

// Server is the runner's HTTP API: POST /v1/operations/{operation} with the caller's access token in
// Authorization and {"grant": "<JWS>", "params": {...}} as the body.
type Server struct {
	Trust    Trust
	Callers  *Callers
	Kube     *Kube
	Keycloak *Keycloak
	Plane    []string // the namespaces cluster operations may touch
	Log      *slog.Logger
	Now      func() time.Time
}

// ErrParams refuses parameters outside an operation's form.
var ErrParams = errors.New("params_invalid")

var username = regexp.MustCompile(`^[a-z0-9][a-z0-9._@-]{0,254}$`)

type params struct {
	Namespace  string `json:"namespace"`
	Deployment string `json:"deployment"`
	Pod        string `json:"pod"`
	Container  string `json:"container"`
	Lines      int    `json:"lines"`
	Username   string `json:"username"`
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("POST /v1/operations/{operation}", s.operate)
	return mux
}

func (s *Server) operate(w http.ResponseWriter, r *http.Request) {
	operation := r.PathValue("operation")
	audit := []any{"operation", operation}
	refuse := func(status int, reason error) {
		s.Log.Warn("privileged operation refused", append(audit, "outcome", "refused", "reason", reason.Error())...)
		writeJSON(w, status, map[string]string{"outcome": "refused", "reason": reason.Error()})
	}
	caller, err := s.Callers.Authenticate(r.Context(), r.Header.Get("Authorization"))
	if err != nil {
		refuse(http.StatusUnauthorized, ErrCaller)
		return
	}
	audit = append(audit, "caller_sub", caller)
	var body struct {
		Grant  string `json:"grant"`
		Params params `json:"params"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if dec.Decode(&body) != nil {
		refuse(http.StatusBadRequest, ErrParams)
		return
	}
	revoked := func(id string) (bool, error) { return s.Kube.Revoked(r.Context(), id) }
	grant, err := VerifyGrant(body.Grant, s.Trust, caller, operation, s.now(), revoked)
	if err != nil {
		status := http.StatusForbidden
		if errors.Is(err, ErrRevocationState) {
			status = http.StatusServiceUnavailable
		}
		refuse(status, err)
		return
	}
	audit = append(audit, "grant_id", grant.ID, "approver_sub", grant.Approver)
	p := body.Params
	if err := s.check(operation, p); err != nil {
		refuse(http.StatusBadRequest, err)
		return
	}
	audit = append(audit, "params", p)
	// The checks may have taken time: the grant must still be valid when the operation starts.
	if s.now().Unix() >= grant.NotAfter {
		refuse(http.StatusForbidden, ErrGrantExpired)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	result, err := s.dispatch(ctx, operation, p)
	if err != nil {
		switch {
		case errors.Is(err, ErrPrivilegedTarget), errors.Is(err, ErrNoSuchUser):
			refuse(http.StatusForbidden, err)
		default:
			s.Log.Error("privileged operation failed", append(audit, "outcome", "failed")...)
			writeJSON(w, http.StatusBadGateway, map[string]string{"outcome": "failed"})
		}
		return
	}
	s.Log.Info("privileged operation done", append(audit, "outcome", "done")...)
	writeJSON(w, http.StatusOK, map[string]any{"outcome": "done", "result": result})
}

// check holds an operation's parameters to its form.
func (s *Server) check(operation string, p params) error {
	inPlane := slices.Contains(s.Plane, p.Namespace)
	switch operation {
	case OpClusterRestart:
		if !inPlane || !dnsLabel.MatchString(p.Deployment) || p.Pod != "" || p.Container != "" || p.Lines != 0 || p.Username != "" {
			return ErrParams
		}
	case OpClusterLogs:
		if !inPlane || !dnsLabel.MatchString(p.Pod) || (p.Container != "" && !dnsLabel.MatchString(p.Container)) ||
			p.Lines < 1 || p.Lines > 1000 || p.Deployment != "" || p.Username != "" {
			return ErrParams
		}
	case OpDisableUser, OpEnableUser:
		if !username.MatchString(p.Username) || p.Namespace != "" || p.Deployment != "" || p.Pod != "" || p.Container != "" || p.Lines != 0 {
			return ErrParams
		}
	case OpListUsers:
		if p != (params{}) {
			return ErrParams
		}
	default:
		return ErrParams
	}
	return nil
}

func (s *Server) dispatch(ctx context.Context, operation string, p params) (any, error) {
	switch operation {
	case OpClusterRestart:
		return nil, s.Kube.Restart(ctx, p.Namespace, p.Deployment, s.now())
	case OpClusterLogs:
		return s.Kube.Logs(ctx, p.Namespace, p.Pod, p.Container, p.Lines)
	case OpListUsers:
		return s.Keycloak.ListUsers(ctx)
	case OpDisableUser:
		return nil, s.Keycloak.SetEnabled(ctx, p.Username, false)
	case OpEnableUser:
		return nil, s.Keycloak.SetEnabled(ctx, p.Username, true)
	}
	return nil, ErrParams
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
