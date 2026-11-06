-- At most one active version per transit key. key_ref is transit:<name>:v<n> (internal/transit
-- ParseRef), so the key's name is the second colon-separated field. Rotation retires the version in
-- use and activates the next one in one transaction (token-store keys rotate); a second active
-- version of one key is refused by the database even on a path that skipped that order, as
-- migration 4 does for a route's live tokens.
--
-- A database written before this migration may hold two active versions of one key: the store then
-- registered transit's latest version on every acquisition without retiring the previous row. Only
-- the highest version stays active; the others are retired now, as a rotation would have done, so
-- the index below can be created. The live tokens bound to the retired versions are retired with
-- them, as a rotation does: substitution reads only tokens of an active key, and a live row would
-- block the route's re-acquisition (one live row per route, migration 4) until it expired. Only
-- well-formed references take part; a malformed active row is left as it is (the store refuses it
-- at start), and two of one name make the index below fail loudly rather than be rewritten blindly.
WITH retired AS (
    UPDATE signing_key SET state = 'retired', retired_at = now()
     WHERE key_ref IN (
        SELECT key_ref FROM (
            SELECT key_ref,
                   row_number() OVER (
                       PARTITION BY split_part(key_ref, ':', 2)
                       ORDER BY CASE WHEN split_part(key_ref, ':', 3) ~ '^v[1-9][0-9]*$'
                                     THEN substr(split_part(key_ref, ':', 3), 2)::int END DESC NULLS LAST,
                                created_at DESC, key_ref DESC) AS rank
              FROM signing_key
             WHERE state = 'active'
               AND split_part(key_ref, ':', 1) = 'transit'
               AND split_part(key_ref, ':', 3) ~ '^v[1-9][0-9]*$'
               AND split_part(key_ref, ':', 4) = '') ranked
         WHERE rank > 1)
    RETURNING key_ref)
UPDATE upstream_token SET state = 'retired', updated_at = now()
 WHERE key_ref IN (SELECT key_ref FROM retired) AND state IN ('active', 'renewing');
CREATE UNIQUE INDEX signing_key_one_active_per_key
    ON signing_key ((split_part(key_ref, ':', 2))) WHERE state = 'active';
