-- Reverts 0003_verified_presentation.
ALTER TABLE oauth2_token DROP COLUMN outcome_id, DROP COLUMN grant_type;
DROP TABLE oauth2_challenge;
