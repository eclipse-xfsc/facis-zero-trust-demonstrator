-- Reverts 0001_initial: every table it created, in reverse dependency order.
DROP TABLE audit_event;
DROP TABLE proof_jti;
DROP TABLE upstream_token;
DROP TABLE verified_outcome;
DROP TABLE signing_key;
DROP TABLE oauth2_dpop_nonce;
DROP TABLE oauth2_token;
DROP TABLE oauth2_client;
