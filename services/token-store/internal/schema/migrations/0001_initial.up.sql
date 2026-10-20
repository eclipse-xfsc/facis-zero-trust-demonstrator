-- The zone's authorization database: the tables behind the connector's OAuth2 surface (IF-02) and
-- the token store (token-store.v1). Timestamps are timestamptz throughout; states are text with a
-- CHECK, so a later migration widens a set without a type change. Expired rows are swept by the
-- services, not by the schema.

-- Connector OAuth2 surface ------------------------------------------------------------------------

-- Clients, registered dynamically or provisioned by other means. The secret is stored as its bcrypt
-- hash only; the RFC 7591 metadata document is kept as registered, null for provisioned clients.
CREATE TABLE oauth2_client (
    client_id   text        PRIMARY KEY,
    secret_hash bytea,
    grant_types text[]      NOT NULL DEFAULT '{}',
    scopes      text[]      NOT NULL DEFAULT '{}',
    audience    text[]      NOT NULL DEFAULT '{}',
    dpop_bound  boolean     NOT NULL DEFAULT false,
    metadata    jsonb,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- Issued tokens, keyed by the token's signature: the database never holds a usable credential.
-- Access and registration tokens share the table and are told apart by kind. The session is the
-- provider's opaque serialized state; its expiry is lifted into expires_at so rows can be swept.
CREATE TABLE oauth2_token (
    kind               text        NOT NULL CHECK (kind IN ('access', 'registration')),
    signature          text        NOT NULL,
    request_id         text        NOT NULL,
    client_id          text        NOT NULL REFERENCES oauth2_client (client_id) ON DELETE CASCADE,
    requested_at       timestamptz NOT NULL,
    requested_scopes   text[]      NOT NULL DEFAULT '{}',
    granted_scopes     text[]      NOT NULL DEFAULT '{}',
    requested_audience text[]      NOT NULL DEFAULT '{}',
    granted_audience   text[]      NOT NULL DEFAULT '{}',
    session            bytea       NOT NULL,
    expires_at         timestamptz NOT NULL,
    PRIMARY KEY (kind, signature)
);
CREATE INDEX oauth2_token_expires_at_idx ON oauth2_token (expires_at);
CREATE INDEX oauth2_token_client_idx ON oauth2_token (client_id);

-- Server-issued DPoP nonces. Unlogged on purpose: a nonce lost in a crash costs the client one
-- retry with a fresh challenge, nothing more.
CREATE UNLOGGED TABLE oauth2_dpop_nonce (
    nonce      text        PRIMARY KEY,
    expires_at timestamptz NOT NULL
);
CREATE INDEX oauth2_dpop_nonce_expires_at_idx ON oauth2_dpop_nonce (expires_at);

-- Token store ---------------------------------------------------------------------------------------

-- The store's outbound signing keys live in the key-value store; a row holds the reference and the
-- key's thumbprint, never key material. A retired key stays so the proofs minted under it can be
-- attributed.
CREATE TABLE signing_key (
    key_ref    text        PRIMARY KEY,
    jkt        text        NOT NULL UNIQUE,
    alg        text        NOT NULL,
    state      text        NOT NULL CHECK (state IN ('active', 'retired')),
    created_at timestamptz NOT NULL DEFAULT now(),
    retired_at timestamptz,
    CHECK ((state = 'retired') = (retired_at IS NOT NULL))
);

-- Verification outcomes received over IF-03. An outcome is consumed at most once: consumption sets
-- consumed_at in the same transaction that inserts the upstream token it authorises, and the
-- token's unique outcome reference makes a second row impossible even outside that path.
CREATE TABLE verified_outcome (
    outcome_id      uuid        PRIMARY KEY,
    issuer          text        NOT NULL,
    client_id       text        NOT NULL,
    challenge       text        NOT NULL,
    audience        text        NOT NULL,
    status          text        NOT NULL CHECK (status IN ('verified', 'failed', 'revoked')),
    claims          jsonb       NOT NULL,
    credential_refs jsonb,
    verified_at     timestamptz NOT NULL,
    expires_at      timestamptz NOT NULL,
    received_at     timestamptz NOT NULL DEFAULT now(),
    consumed_at     timestamptz
);

-- Upstream tokens the store holds for substitution. The value is a reference into the key-value
-- store, never the token. A route is (peer_zone, audience, tenant), with the empty tenant standing
-- for "no tenant" so the route key stays comparable and indexable. Renewal is single-flight: one
-- worker claims a due token through claimed_at and claimed_by, and a staleness sweep releases the
-- claim of a worker that died.
CREATE TABLE upstream_token (
    token_id    uuid        PRIMARY KEY,
    peer_zone   text        NOT NULL,
    audience    text        NOT NULL,
    tenant      text        NOT NULL DEFAULT '',
    outcome_id  uuid        NOT NULL UNIQUE REFERENCES verified_outcome (outcome_id),
    token_ref   text        NOT NULL,
    key_ref     text        NOT NULL REFERENCES signing_key (key_ref),
    state       text        NOT NULL CHECK (state IN ('active', 'renewing', 'failed', 'retired')),
    issued_at   timestamptz NOT NULL,
    expires_at  timestamptz NOT NULL,
    renew_after timestamptz NOT NULL,
    claimed_at  timestamptz,
    claimed_by  text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    CHECK (renew_after <= expires_at),
    CHECK ((claimed_at IS NULL) = (claimed_by IS NULL))
);
-- Substitution: the valid token of a route, newest first.
CREATE INDEX upstream_token_route_idx
    ON upstream_token (peer_zone, audience, tenant, expires_at DESC) WHERE state = 'active';
-- Renewal: the tokens due, scanned with FOR UPDATE SKIP LOCKED.
CREATE INDEX upstream_token_renewal_idx
    ON upstream_token (renew_after) WHERE state = 'active' AND claimed_at IS NULL;

-- One-time DPoP proof identifiers, the replay check of the store's API, keyed as the API keys them.
-- A conflict on insert is a replay. Unlogged on purpose: after a crash the table is empty, so a
-- proof can be replayed at most once inside its own acceptance window, which the API documents.
CREATE UNLOGGED TABLE proof_jti (
    jkt       text        NOT NULL,
    htm       text        NOT NULL,
    htu       text        NOT NULL,
    jti       text        NOT NULL,
    not_after timestamptz NOT NULL,
    PRIMARY KEY (jkt, htm, htu, jti)
);
CREATE INDEX proof_jti_not_after_idx ON proof_jti (not_after);

-- The audit trail: registration decisions, outcome consumption and refusal, every renewal attempt
-- with its reason. Append-only; kind names the event and the optional references point at what it
-- concerns.
CREATE TABLE audit_event (
    event_id       bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at             timestamptz NOT NULL DEFAULT now(),
    kind           text        NOT NULL,
    correlation_id text,
    client_id      text,
    outcome_id     uuid,
    token_id       uuid,
    reason_code    text,
    detail         jsonb
);
CREATE INDEX audit_event_at_idx ON audit_event (at);
CREATE INDEX audit_event_token_idx ON audit_event (token_id) WHERE token_id IS NOT NULL;
CREATE INDEX audit_event_outcome_idx ON audit_event (outcome_id) WHERE outcome_id IS NOT NULL;
