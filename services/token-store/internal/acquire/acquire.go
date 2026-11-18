// Package acquire obtains an upstream token from the peer zone's Connector and activates it (design D10).
package acquire

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/connectorclient"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/transit"
)

// KVPrefix is where upstream token values live in KV v2: KVPrefix + "/" + token_id, create-only.
const KVPrefix = "ztd/token-store/upstream"

// Timing of the activation transaction and its settlement (D10). The transaction cannot stay open
// longer than statementTimeout per statement and idleTimeout between them; reconciliation waits
// settleWait for it, longer than both; the orphan sweep leaves values younger than OrphanAge alone,
// longer than any of them.
const (
	statementTimeout = 5 * time.Second
	idleTimeout      = 10 * time.Second
	settleWait       = 30 * time.Second
	OrphanAge        = 10 * time.Minute
	// cleanupTimeout bounds each step that must still run after the caller's context ended: a
	// rollback, the deletion of a value whose transaction confirmed rolled back, a failure's audit
	// row. A step that does not finish in time leaves its value to the orphan sweep.
	cleanupTimeout = 2 * time.Second
)

// Reason codes of acquisition, on audit rows and errors. The CRED-OUTCOME-* codes of IF-03 are
// used as they are, whether A's own check or the peer's refusal produced them.
const (
	CodeChallenge         = "ACQ-CHALLENGE-FAILED"    // no challenge from the peer
	CodeOutcomeSource     = "ACQ-OUTCOME-UNAVAILABLE" // the outcome source failed
	CodeStore             = "ACQ-STORE-UNAVAILABLE"   // A's database could not record the receipt
	CodePeerRefused       = "ACQ-PEER-REFUSED"        // the peer refused with another reason
	CodePeerLost          = "ACQ-PEER-RESPONSE-LOST"  // no readable answer: terminal for the outcome
	CodeTokenInvalid      = "ACQ-TOKEN-INVALID"       // the issued token failed A's checks
	CodeKVWrite           = "ACQ-KV-WRITE"            // the value could not be written
	CodeActivationRefused = "ACQ-ACTIVATION-REFUSED"  // the receipt was no longer consumable
	CodeActivationFailed  = "ACQ-ACTIVATION-FAILED"   // the transaction confirmed rolled back
	CodeCommitUnknown     = "ACQ-COMMIT-UNKNOWN"      // reconciliation could not settle it
	CodeOrphan            = "ACQ-ORPHAN-DELETED"      // the sweep removed a value without a row
	CodeClaimLost         = "ACQ-CLAIM-LOST"          // a renewal's fence no longer held: result discarded
)

// Error is a failed acquisition: a reason code and fixed text, never anything a peer sent.
type Error struct {
	Code string
	Err  error
}

func (e *Error) Error() string { return "acquire: " + e.Code + ": " + e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

func fail(code, text string) *Error { return &Error{Code: code, Err: errors.New(text)} }

// Route is one upstream route and how to acquire its token.
type Route struct {
	Name             string
	PeerZone         string
	Audience         string
	Tenant           string
	ConnectorURL     string // the peer Connector's base URL; /oauth2/challenge and /oauth2/token below it
	ClientID         string
	ClientSecretFile string // read per acquisition, never logged
	Outcomes         OutcomeSource
}

// Token is an activated upstream token: the committed active row, never the value.
type Token struct {
	ID        string
	ExpiresAt time.Time
}

// Acquirer acquires upstream tokens. Safe for concurrent use.
type Acquirer struct {
	DB         *pgxpool.Pool
	Signer     transit.Signer
	Secrets    transit.Secrets
	KeyName    string       // the store's transit key
	Trusted    if03.Issuers // IF-03 issuers A accepts: the peer's verifier keys
	HTTPClient *http.Client // nil: 10 s timeout; redirects are never followed
	Log        *slog.Logger
	Now        func() time.Time

	// Prefix replaces KVPrefix when set; tests use it so each sweeps only its own values.
	Prefix string

	// commit settles the activation transaction; tests replace it to lose an acknowledgement.
	commit func(context.Context, pgx.Tx) error
	// sweepPause runs in the sweep between the age check and the locked re-check; tests use it to
	// commit an activation there.
	sweepPause func(tokenID string)
}

func (a *Acquirer) kvPrefix() string {
	if a.Prefix != "" {
		return a.Prefix
	}
	return KVPrefix
}

// Fence is a renewal claim (D11): the row being renewed and the claim as it was recorded.
type Fence struct {
	TokenID   string
	ClaimedBy string
	ClaimedAt time.Time
}

// Acquire runs D10 for route: challenge from the peer, outcome, A's receipt, the grant with a
// transit-signed proof (one nonce retry), the response checks, the KV write, and one A transaction
// that consumes the receipt and activates the row. Every refusal and failure is audited and returned
// as *Error. A failure after the grant was sent is terminal for that outcome: the next call starts
// with a fresh challenge and outcome.
//
// The route has at most one live row (active or renewing; migration 4). The activation retires the
// route's live rows that have expired, in the same transaction; a live row that has not expired makes
// the activation fail (ACQ-ACTIVATION-FAILED, the value deleted): Acquire never replaces a valid
// token, Replace does.
func (a *Acquirer) Acquire(ctx context.Context, r Route) (Token, error) {
	return a.acquire(ctx, r, nil)
}

// Replace is Acquire for a renewal: the activation transaction retires the row f names and inserts
// the new one only if that row is still state 'renewing' under exactly this claim. Otherwise the
// worker lost its claim: nothing commits, the new value is deleted and the error is ACQ-CLAIM-LOST.
func (a *Acquirer) Replace(ctx context.Context, r Route, f Fence) (Token, error) {
	return a.acquire(ctx, r, &f)
}

func (a *Acquirer) acquire(ctx context.Context, r Route, fence *Fence) (Token, error) {
	at := attempt{a: a, r: r, id: newUUID(), fence: fence}
	tok, err := at.run(ctx)
	if err != nil {
		var e *Error
		if !errors.As(err, &e) {
			e = &Error{Code: CodeStore, Err: err}
		}
		kind := "upstream.failed"
		if e.Code == CodeTokenInvalid || e.Code == CodePeerRefused || strings.HasPrefix(e.Code, "CRED-") {
			kind = "upstream.refused"
		}
		at.audit(ctx, kind, e.Code, at.tokenID)
		a.log().WarnContext(ctx, "upstream acquisition refused or failed", "route", r.Name, "attempt", at.id,
			"reason_code", e.Code, "outcome_id", at.outcomeID, "token_id", at.tokenID)
		return Token{}, e
	}
	a.log().InfoContext(ctx, "upstream token acquired", "route", r.Name, "attempt", at.id, "token_id", tok.ID,
		"outcome_id", at.outcomeID, "expires_at", tok.ExpiresAt)
	return tok, nil
}

type attempt struct {
	a         *Acquirer
	r         Route
	id        string // correlation_id of the attempt's audit rows
	outcomeID string
	tokenID   string
	detail    string // the failed response check, for the audit row
	fence     *Fence // set for a renewal
}

func (at *attempt) run(ctx context.Context) (Token, error) {
	a, r := at.a, at.r
	base, err := connectorclient.BaseURL(r.ConnectorURL)
	if err != nil {
		return Token{}, fail(CodeChallenge, "connector URL is not an absolute http(s) URL")
	}
	secret, err := readSecret(r.ClientSecretFile)
	if err != nil {
		return Token{}, fail(CodeStore, "client secret unreadable")
	}
	if r.Outcomes == nil {
		return Token{}, fail(CodeOutcomeSource, "route has no outcome source")
	}
	key, err := LoadKey(ctx, a.DB, a.Signer, a.KeyName)
	if err != nil {
		return Token{}, fail(CodeStore, "store key unavailable")
	}
	b := &connectorclient.Client{BaseURL: base, ClientID: r.ClientID, ClientSecret: secret, HTTP: a.HTTPClient, Now: a.now}

	// 1. Challenge from B.
	ch, err := b.Challenge(ctx, r.Audience)
	if err != nil {
		return Token{}, at.mapped(err)
	}
	// 2. Outcome.
	jws, err := r.Outcomes.Outcome(ctx, ch)
	if err != nil {
		return Token{}, fail(CodeOutcomeSource, "outcome source failed")
	}
	// 3. A's own verification and receipt.
	o, err := if03.Verify(jws, a.Trusted, if03.Expect{ClientID: r.ClientID, Challenge: ch.Value, Audience: r.Audience}, a.now())
	if err != nil {
		var ie *if03.Error
		if errors.As(err, &ie) {
			return Token{}, &Error{Code: ie.Code, Err: errors.New("outcome refused by the store")}
		}
		return Token{}, fail(if03.CodeSignature, "outcome refused by the store")
	}
	at.outcomeID = o.OutcomeID
	if err := at.recordReceipt(ctx, o); err != nil {
		return Token{}, err
	}
	// 4. The grant at B. From here on, an unreadable answer is terminal for this outcome.
	var token tokenResponse
	if token, err = b.Grant(ctx, key, jws, ch.Value, r.Audience); err != nil {
		return Token{}, at.mapped(err)
	}
	// 5. Response checks.
	claims, err := b.Check(token, key.JKT(), r.Audience)
	if err != nil {
		return Token{}, at.mapped(err)
	}
	// 6. KV create-only.
	at.tokenID = newUUID()
	path := a.kvPrefix() + "/" + at.tokenID
	if err := a.Secrets.Create(ctx, path, []byte(token.AccessToken)); err != nil {
		// Nothing activated. A value that was written despite the error has no row and is swept.
		return Token{}, fail(CodeKVWrite, "upstream token value not written")
	}
	// 7. One A transaction.
	return at.activate(ctx, key, path, claims)
}

// recordReceipt inserts A's receipt, verified and unconsumed. An outcome A has seen before is never
// used again.
func (at *attempt) recordReceipt(ctx context.Context, o if03.Outcome) error {
	claims, _ := json.Marshal(o.Claims)
	var refs any
	if len(o.CredentialRefs) > 0 {
		refs, _ = json.Marshal(o.CredentialRefs)
	}
	tag, err := at.a.DB.Exec(ctx, `INSERT INTO verified_outcome
		(outcome_id, issuer, client_id, challenge, audience, status, claims, credential_refs, verified_at, expires_at, received_at)
		VALUES ($1, $2, $3, $4, $5, 'verified', $6, $7, $8, $9, $10) ON CONFLICT (outcome_id) DO NOTHING`,
		o.OutcomeID, o.Issuer, o.ClientID, o.Challenge, o.Audience, claims, refs, o.VerifiedAt, o.ExpiresAt, at.a.now())
	if err != nil {
		return fail(CodeStore, "receipt not recorded")
	}
	if tag.RowsAffected() == 0 {
		return fail(if03.CodeConsumed, "outcome already received")
	}
	return nil
}

// mapped turns a connectorclient error into acquisition's reason codes; a failed response check is
// kept for the audit row. The CRED-OUTCOME-* codes the peer answered are used as they are.
func (at *attempt) mapped(err error) error {
	var ce *connectorclient.Error
	if !errors.As(err, &ce) {
		return fail(CodePeerLost, "no readable answer from the peer")
	}
	switch ce.Kind {
	case connectorclient.KindChallenge:
		return &Error{Code: CodeChallenge, Err: ce}
	case connectorclient.KindProof:
		// Nothing was sent: the outcome is unused, but the attempt ends here all the same.
		return &Error{Code: CodeStore, Err: ce}
	case connectorclient.KindRefused:
		if strings.HasPrefix(ce.Reason, "CRED-") {
			return &Error{Code: ce.Reason, Err: ce}
		}
		return &Error{Code: CodePeerRefused, Err: ce}
	case connectorclient.KindTokenInvalid:
		at.detail = ce.Check
		return &Error{Code: CodeTokenInvalid, Err: ce}
	default:
		return &Error{Code: CodePeerLost, Err: ce}
	}
}

// activate is the A transaction: consume the receipt, insert the active row and its audit row,
// commit. The transaction first takes an advisory lock on token_id that it holds until it ends, so
// reconciliation can wait for it to settle.
func (at *attempt) activate(ctx context.Context, key *Key, path string, tok connectorclient.Issued) (Token, error) {
	a := at.a
	tx, err := a.DB.Begin(ctx)
	if err != nil {
		return at.rolledBack(ctx, path, CodeActivationFailed)
	}
	if code, err := at.stage(ctx, tx, key, path, tok); err != nil {
		// COMMIT was never sent: the transaction did not commit.
		rollback(ctx, tx)
		return at.rolledBack(ctx, path, code)
	}
	commit := a.commit
	if commit == nil {
		commit = func(ctx context.Context, tx pgx.Tx) error { return tx.Commit(ctx) }
	}
	err = commit(ctx, tx)
	switch {
	case err == nil:
		return Token{ID: at.tokenID, ExpiresAt: tok.ExpiresAt}, nil
	case errors.Is(err, pgx.ErrTxCommitRollback):
		// The server answered COMMIT with ROLLBACK: the transaction had failed before it.
		return at.rolledBack(ctx, path, CodeActivationFailed)
	default:
		// Any other answer, a server error included, does not prove a rollback: a FATAL
		// termination can arrive after the commit took effect. The row decides, once the
		// transaction has settled; a COMMIT refused with an error leaves no row and lands there too.
		// A caller whose context has ended does not wait for that: the value stays for the orphan
		// sweep, which applies the same rule.
		if ctx.Err() != nil {
			return Token{}, fail(CodeCommitUnknown, "activation outcome unknown and the caller gone; value kept for the orphan sweep")
		}
		return at.reconcile(ctx, path, tok)
	}
}

// stage runs the activation's statements. On an error the returned code says why the transaction
// must not commit.
func (at *attempt) stage(ctx context.Context, tx pgx.Tx, key *Key, path string, tok connectorclient.Issued) (code string, err error) {
	now := at.a.now()
	renewAfter := tok.IssuedAt.Add(tok.ExpiresAt.Sub(tok.IssuedAt) * 3 / 4)
	if _, err := tx.Exec(ctx, `SELECT set_config('statement_timeout', $2, true),
		set_config('idle_in_transaction_session_timeout', $3, true), pg_advisory_xact_lock(hashtextextended($1::text, 0))`,
		at.tokenID, ms(statementTimeout), ms(idleTimeout)); err != nil {
		return CodeActivationFailed, err
	}
	tag, err := tx.Exec(ctx, `UPDATE verified_outcome SET consumed_at = $3
		WHERE outcome_id = $1 AND audience = $2 AND status = 'verified' AND consumed_at IS NULL AND expires_at > $3`,
		at.outcomeID, at.r.Audience, now)
	if err != nil {
		return CodeActivationFailed, err
	}
	if tag.RowsAffected() == 0 {
		return CodeActivationRefused, errors.New("receipt not consumable")
	}
	// The row this one replaces stops being live first, in this transaction: the route goes from the
	// old live row to the new one in one commit, never through two or none.
	if at.fence != nil {
		tag, err = tx.Exec(ctx, `UPDATE upstream_token SET state = 'retired', updated_at = $4
			WHERE token_id = $1 AND state = 'renewing' AND claimed_by = $2 AND claimed_at = $3`,
			at.fence.TokenID, at.fence.ClaimedBy, at.fence.ClaimedAt, now)
		if err != nil {
			return CodeActivationFailed, err
		}
		if tag.RowsAffected() != 1 {
			return CodeClaimLost, errors.New("renewal claim lost")
		}
	} else if _, err := tx.Exec(ctx, `UPDATE upstream_token SET state = 'retired', updated_at = $4
		WHERE peer_zone = $1 AND audience = $2 AND tenant = $3 AND state IN ('active', 'renewing') AND expires_at <= $4`,
		at.r.PeerZone, at.r.Audience, at.r.Tenant, now); err != nil {
		return CodeActivationFailed, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO upstream_token
		(token_id, peer_zone, audience, tenant, outcome_id, token_ref, key_ref, state, issued_at, expires_at, renew_after)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 'active', $8, $9, $10)`,
		at.tokenID, at.r.PeerZone, at.r.Audience, at.r.Tenant, at.outcomeID, path, key.Ref(), tok.IssuedAt, tok.ExpiresAt, renewAfter); err != nil {
		return CodeActivationFailed, err
	}
	kind := "upstream.acquired"
	if at.fence != nil {
		kind = "upstream.renewed"
	}
	if _, err = tx.Exec(ctx, auditSQL, kind, at.id, at.r.ClientID, at.outcomeID, at.tokenID, nil, at.auditDetail()); err != nil {
		return CodeActivationFailed, err
	}
	return "", nil
}

// rolledBack handles a transaction confirmed not committed: the value is deleted.
func (at *attempt) rolledBack(ctx context.Context, path, code string) (Token, error) {
	at.deleteValue(ctx, path)
	switch code {
	case CodeActivationRefused:
		return Token{}, fail(code, "receipt not consumable")
	case CodeClaimLost:
		return Token{}, fail(code, "renewal claim lost; result discarded")
	}
	return Token{}, fail(CodeActivationFailed, "activation rolled back")
}

// reconcile waits for the activation transaction to end (its advisory lock is free once it
// committed or aborted; the server's timeouts bound how long that takes), then reads the row by
// token_id. Only a missing row lets the value go; if the wait or the read fails, or the caller's
// deadline comes first, the value stays for the orphan sweep, which applies the same rule.
func (at *attempt) reconcile(ctx context.Context, path string, tok connectorclient.Issued) (Token, error) {
	rctx, cancel := context.WithTimeout(ctx, settleWait+5*time.Second)
	defer cancel()
	deleted, err := at.a.deleteIfNoRow(rctx, at.tokenID, path)
	switch {
	case err != nil:
		return Token{}, fail(CodeCommitUnknown, "activation outcome unknown; value kept for the orphan sweep")
	case !deleted:
		return Token{ID: at.tokenID, ExpiresAt: tok.ExpiresAt}, nil
	default:
		return Token{}, fail(CodeActivationFailed, "activation did not commit")
	}
}

// deleteIfNoRow deletes the KV value at path only if token_id has no upstream_token row, deciding
// under the token's advisory lock, the one activation holds until it ends: the wait covers an
// activation still in flight, and the deletion happens before the lock is released, so no
// activation of that token_id can commit between the check and the deletion. READ COMMITTED is
// explicit and the lock and the check are separate statements, so the check reads a snapshot taken
// after the wait, whatever the database's default isolation is.
func (a *Acquirer) deleteIfNoRow(ctx context.Context, tokenID, path string) (deleted bool, err error) {
	tx, err := a.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return false, err
	}
	defer rollback(ctx, tx)
	if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', $1, true)`, ms(settleWait)); err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))`, tokenID); err != nil {
		return false, err
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM upstream_token WHERE token_id = $1)`, tokenID).Scan(&exists); err != nil {
		return false, err
	}
	if exists {
		return false, nil
	}
	if err := a.Secrets.Delete(ctx, path); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

func ms(d time.Duration) string { return strconv.FormatInt(d.Milliseconds(), 10) }

// rollback ends tx even when ctx has ended, within cleanupTimeout; a connection that cannot is
// closed by pgx, which ends the transaction and its locks on the server.
func rollback(ctx context.Context, tx pgx.Tx) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
	defer cancel()
	_ = tx.Rollback(rctx)
}

func (at *attempt) deleteValue(ctx context.Context, path string) {
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
	defer cancel()
	if err := at.a.Secrets.Delete(dctx, path); err != nil {
		// Left for the orphan sweep: it has no row.
		at.a.log().WarnContext(ctx, "upstream token value not deleted; left for the orphan sweep", "token_id", at.tokenID)
	}
}

const auditSQL = `INSERT INTO audit_event (kind, correlation_id, client_id, outcome_id, token_id, reason_code, detail)
	VALUES ($1, $2, $3, $4, $5, $6, $7)`

func (at *attempt) auditDetail() []byte {
	d := map[string]string{"route": at.r.Name, "peer_zone": at.r.PeerZone, "audience": at.r.Audience}
	if at.fence != nil {
		d["replaces"] = at.fence.TokenID
	}
	if at.detail != "" {
		d["check"] = at.detail
	}
	b, _ := json.Marshal(d)
	return b
}

// audit writes a refusal or failure row outside any transaction, best effort.
func (at *attempt) audit(ctx context.Context, kind, code, tokenID string) {
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
	defer cancel()
	if _, err := at.a.DB.Exec(actx, auditSQL, kind, at.id, at.r.ClientID, nullable(at.outcomeID), nullable(tokenID), code, at.auditDetail()); err != nil {
		at.a.log().ErrorContext(ctx, "audit row not written", "attempt", at.id, "reason_code", code)
	}
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (a *Acquirer) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *Acquirer) log() *slog.Logger {
	if a.Log != nil {
		return a.Log
	}
	return slog.New(slog.DiscardHandler)
}

func readSecret(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	s := strings.TrimRight(string(b), "\r\n")
	if s == "" {
		return "", errors.New("empty")
	}
	return s, nil
}
