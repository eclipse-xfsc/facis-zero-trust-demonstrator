-- At most one live upstream token per route. A token is live while it is active or being renewed
-- (state 'renewing': claimed by a renewal worker, still the route's token until its replacement
-- commits). Renewal and on-demand acquisition retire the row they replace and insert the new one in
-- one transaction, so a second live row is refused by the database even on a path that skipped
-- that order.
CREATE UNIQUE INDEX upstream_token_one_live_per_route
    ON upstream_token (peer_zone, audience, tenant) WHERE state IN ('active', 'renewing');
