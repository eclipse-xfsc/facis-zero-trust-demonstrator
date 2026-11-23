package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/dpopproof"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/meshcaller"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/replay"
)

// The contract's default window (token-store.v1, replay-check): a proof is accepted when
// now - 60 s <= iat <= now + 30 s and kept until iat + 90 s, and a caller's not_after may lie at most
// 90 s after iat. The exposure after the record is lost is the longest a proof stays acceptable from
// one instant: iat may lie 30 s ahead, so 30 s + 90 s.
const (
	replayPast      = 60 * time.Second
	replayFuture    = 30 * time.Second
	replayKeep      = 90 * time.Second
	replayExposure  = replayFuture + replayKeep
	epochEvery      = 10 * time.Second
	replaySweepEach = time.Minute
	maxReplayBody   = 4 << 10
	// replayOpTimeout bounds every database operation of the replay check and its upkeep, so a
	// stalled query neither holds a connection nor delays the next epoch check for long.
	replayOpTimeout = 2 * time.Second
)

var jktPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

type replayCheck struct {
	JKT      string `json:"jkt"`
	HTM      string `json:"htm"`
	HTU      string `json:"htu"`
	JTI      string `json:"jti"`
	IAT      *int64 `json:"iat"`
	NotAfter *int64 `json:"not_after"`
}

// handleReplayCheck is POST /internal/replay-check. The caller is authenticated first; nothing is
// read from the body of a refused meshcaller.
func (s *Server) handleReplayCheck(w http.ResponseWriter, r *http.Request) {
	if c, err := s.callers.Authenticate(r); err != nil || !s.replayCaller(c) {
		s.refuse(w, r, http.StatusForbidden, "TOK-CALLER-DENIED")
		return
	}
	var req replayCheck
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxReplayBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.Decode(&struct{}{}) != io.EOF || req.IAT == nil ||
		!jktPattern.MatchString(req.JKT) || req.HTM == "" || req.HTU == "" || req.JTI == "" || len(req.JTI) > 256 {
		s.refuse(w, r, http.StatusUnprocessableEntity, "TOK-PROOF-INVALID")
		return
	}
	// The record is keyed on the normalised htu, the form every other consumer of proof_jti
	// (dpopproof, the Connector) records, so two spellings of one target are one proof.
	htu, err := dpopproof.NormalizeURI(req.HTU)
	if err != nil {
		s.refuse(w, r, http.StatusUnprocessableEntity, "TOK-PROOF-INVALID")
		return
	}
	now := s.now()
	iat := time.Unix(*req.IAT, 0)
	var notAfter time.Time
	if req.NotAfter != nil {
		notAfter = time.Unix(*req.NotAfter, 0)
		if notAfter.Before(now) || notAfter.After(iat.Add(replayKeep)) {
			s.refuse(w, r, http.StatusUnprocessableEntity, "TOK-PROOF-INVALID")
			return
		}
	} else {
		if iat.Before(now.Add(-replayPast)) || iat.After(now.Add(replayFuture)) {
			s.refuse(w, r, http.StatusUnprocessableEntity, "TOK-PROOF-INVALID")
			return
		}
		notAfter = iat.Add(replayKeep)
	}
	ctx, cancel := context.WithTimeout(r.Context(), replayOpTimeout)
	defer cancel()
	fresh, err := s.replay.TryUse(ctx, replay.Use{JKT: req.JKT, Method: req.HTM, URI: htu, JTI: req.JTI, NotAfter: notAfter})
	switch {
	case err != nil:
		s.log.WarnContext(r.Context(), "replay record unavailable")
		s.refuse(w, r, http.StatusServiceUnavailable, "TOK-STORE-UNAVAILABLE")
	case !fresh:
		s.refuse(w, r, http.StatusConflict, "TOK-REPLAY")
	default:
		writeJSON(w, http.StatusOK, map[string]bool{"fresh": true})
	}
}

func (s *Server) replayCaller(c meshcaller.Caller) bool {
	for _, id := range s.cfg.ReplayCallers {
		if c.SPIFFEID == id {
			return true
		}
	}
	return false
}

// refuse answers with the contract's refusal body: the reason code and the correlation id, never
// anything the caller sent.
func (s *Server) refuse(w http.ResponseWriter, r *http.Request, status int, code string) {
	body := map[string]string{"reason_code": code}
	if f, ok := fieldsFrom(r.Context()); ok {
		body["correlation_id"] = f.correlationID
	}
	writeJSON(w, status, body)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// maintainReplay keeps the replay record honest while the store runs: it checks the epoch sentinel
// at start, every epochEvery and whenever the pool opened a new connection, warning when the record
// may have been lost, and sweeps expired records. It returns when ctx ends.
func (s *Server) maintainReplay(ctx context.Context) {
	check := func() {
		opCtx, cancel := context.WithTimeout(ctx, replayOpTimeout)
		defer cancel()
		lost, err := s.replay.CheckEpoch(opCtx, s.now())
		switch {
		case err != nil:
			s.log.DebugContext(ctx, "replay epoch not checked", "error", err.Error())
		case lost:
			s.log.WarnContext(ctx, "replay record may have been lost (first start, or database crash recovery): "+
				"a DPoP proof may be replayed once within its acceptance window",
				slog.String("window", replayExposure.String()))
		}
	}
	check()
	epoch := time.NewTicker(epochEvery)
	defer epoch.Stop()
	sweep := time.NewTicker(replaySweepEach)
	defer sweep.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-epoch.C:
			check()
		case <-s.reconnected:
			check()
		case <-sweep.C:
			opCtx, cancel := context.WithTimeout(ctx, replayOpTimeout)
			if _, err := s.replay.Sweep(opCtx, s.now()); err != nil && !errors.Is(err, context.Canceled) {
				s.log.DebugContext(ctx, "replay sweep failed", "error", err.Error())
			}
			cancel()
		}
	}
}
