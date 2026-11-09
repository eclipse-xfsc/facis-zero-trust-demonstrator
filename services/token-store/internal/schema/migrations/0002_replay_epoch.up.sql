-- The replay record's sentinel. Unlogged like proof_jti, so crash recovery resets both: a service
-- that finds the row missing knows the replay record may have been lost, whether or not the server
-- process restarted, and warns that a proof may be replayed once inside its acceptance window.
CREATE UNLOGGED TABLE replay_epoch (
    id         smallint    PRIMARY KEY CHECK (id = 1),
    started_at timestamptz NOT NULL
);
