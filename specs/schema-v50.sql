CREATE INDEX IF NOT EXISTS mls_shard_forward_outbox_owner_relay
ON mls_shard_forward_outbox(source_wire_id,target_wire_id,content_id)
WHERE state='pending' AND delivery_kind='owner_relay';

CREATE INDEX IF NOT EXISTS mls_shard_forward_outbox_owner_reply
ON mls_shard_forward_outbox(target_wire_id,target_peer_id)
WHERE state='pending' AND delivery_kind='owner_reply';

CREATE TABLE IF NOT EXISTS mls_group_fetch_relays (
    request_id BLOB PRIMARY KEY
        CHECK(length(request_id)=16),
    logical_root BLOB NOT NULL
        CHECK(length(logical_root)=32),
    requester_room BLOB NOT NULL
        CHECK(length(requester_room)=32),
    source_room BLOB NOT NULL
        CHECK(length(source_room)=32),
    requester_agent TEXT NOT NULL
        CHECK(length(requester_agent) BETWEEN 1 AND 128),
    requester_peer TEXT NOT NULL
        CHECK(length(requester_peer) BETWEEN 1 AND 128),
    content_id BLOB NOT NULL
        CHECK(length(content_id)=32),
    created_at_ms INTEGER NOT NULL
        CHECK(created_at_ms>=0),
    expires_at_ms INTEGER NOT NULL
        CHECK(expires_at_ms>created_at_ms),
    CHECK(requester_room<>source_room)
) STRICT;

CREATE INDEX IF NOT EXISTS mls_group_fetch_relays_lookup
ON mls_group_fetch_relays(source_room,request_id,expires_at_ms);

CREATE INDEX IF NOT EXISTS mls_group_fetch_relays_expiry
ON mls_group_fetch_relays(expires_at_ms);
