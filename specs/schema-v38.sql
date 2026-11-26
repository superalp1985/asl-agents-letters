CREATE TABLE group_invite_requests (
    request_id TEXT PRIMARY KEY CHECK(length(request_id) = 32),
    group_id TEXT NOT NULL REFERENCES asl_groups(group_id),
    requester_agent_id TEXT NOT NULL CHECK(length(requester_agent_id) BETWEEN 1 AND 128),
    requester_peer_id TEXT NOT NULL CHECK(length(requester_peer_id) BETWEEN 1 AND 128),
    mls_epoch INTEGER NOT NULL CHECK(mls_epoch BETWEEN 0 AND 9223372036854775806),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms > 0),
    created_at_ms INTEGER NOT NULL CHECK(created_at_ms > 0),
    state TEXT NOT NULL CHECK(state IN ('pending','approved','rejected','expired')),
    UNIQUE(group_id, requester_peer_id)
) STRICT;

CREATE INDEX group_invite_requests_owner
ON group_invite_requests(group_id,state,expires_at_ms,created_at_ms);
