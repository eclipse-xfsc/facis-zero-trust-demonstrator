package acquire

import (
	"context"
	"errors"
	"regexp"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/transit"
)

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// SweepOrphans deletes the KV values under KVPrefix whose token_id has no upstream_token row and
// that were created more than OrphanAge ago, longer than any activation transaction can stay open
// (D10). Age is checked first; absence is then checked under the token's advisory lock in READ
// COMMITTED and the value deleted before the lock is released (deleteIfNoRow), so an activation that
// committed after the sweep first looked keeps its value. A value with a row, in any state, is never
// touched here. It returns how many it deleted.
func (a *Acquirer) SweepOrphans(ctx context.Context) (int, error) {
	names, err := a.Secrets.List(ctx, a.kvPrefix())
	if err != nil {
		return 0, err
	}
	deleted := 0
	for _, id := range names {
		if !uuidPattern.MatchString(id) {
			continue // a sub-folder or a name that is not ours
		}
		path := a.kvPrefix() + "/" + id
		created, err := a.Secrets.CreatedTime(ctx, path)
		if errors.Is(err, transit.ErrNotFound) {
			continue
		}
		if err != nil {
			return deleted, err
		}
		if a.now().Sub(created) <= OrphanAge {
			continue
		}
		if a.sweepPause != nil {
			a.sweepPause(id)
		}
		gone, err := a.deleteIfNoRow(ctx, id, path)
		if err != nil {
			return deleted, err
		}
		if !gone {
			continue
		}
		deleted++
		if _, err := a.DB.Exec(ctx, auditSQL, "upstream.orphan_deleted", nil, nil, nil, id, CodeOrphan, nil); err != nil {
			a.log().ErrorContext(ctx, "audit row not written", "token_id", id, "reason_code", CodeOrphan)
		}
		a.log().InfoContext(ctx, "orphaned upstream token value deleted", "token_id", id)
	}
	return deleted, nil
}
