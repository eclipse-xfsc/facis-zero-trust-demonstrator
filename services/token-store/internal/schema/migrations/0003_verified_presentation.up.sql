-- The connector's verified-presentation grant (IF-02 v1.1). A client first obtains a challenge,
-- bound to it and to one audience; the grant then consumes the challenge and the IF-03 outcome
-- (recorded in verified_outcome) and stores the token in one transaction. Consumed challenges and
-- outcomes are never reset or deleted while a replay is possible.

CREATE TABLE oauth2_challenge (
    challenge   text        PRIMARY KEY,
    client_id   text        NOT NULL REFERENCES oauth2_client (client_id) ON DELETE CASCADE,
    audience    text        NOT NULL,
    expires_at  timestamptz NOT NULL,
    consumed_at timestamptz
);
CREATE INDEX oauth2_challenge_expires_at_idx ON oauth2_challenge (expires_at) WHERE consumed_at IS NULL;

-- The grant a token was issued through (empty for a registration access token), and the outcome a
-- verified-presentation token was issued on. A verified-presentation token always has an outcome,
-- no other token has one, and one outcome stands behind one token at most, even on a path that
-- skipped the consumption check.
ALTER TABLE oauth2_token
    ADD COLUMN grant_type text NOT NULL DEFAULT '',
    ADD COLUMN outcome_id uuid UNIQUE REFERENCES verified_outcome (outcome_id),
    ADD CONSTRAINT oauth2_token_vp_has_outcome
        CHECK (grant_type <> 'urn:facis:params:oauth:grant-type:verified-presentation' OR outcome_id IS NOT NULL),
    ADD CONSTRAINT oauth2_token_outcome_only_vp
        CHECK (outcome_id IS NULL OR (kind = 'access' AND grant_type = 'urn:facis:params:oauth:grant-type:verified-presentation'));
