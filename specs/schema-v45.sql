CREATE TABLE mls_shard_bindings (
    child_wire_id BLOB PRIMARY KEY
        REFERENCES mls_room_states(wire_group_id) ON DELETE CASCADE
        CHECK(length(child_wire_id)=32),
    root_wire_id BLOB NOT NULL CHECK(length(root_wire_id)=32),
    shard_index INTEGER NOT NULL CHECK(shard_index BETWEEN 1 AND 19),
    owner_agent_id BLOB NOT NULL CHECK(length(owner_agent_id)=32),
    owner_peer_id TEXT NOT NULL REFERENCES peers(peer_id),
    revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 9223372036854775806),
    issued_at_ms INTEGER NOT NULL CHECK(issued_at_ms>=0),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>issued_at_ms),
    binding_cbor BLOB NOT NULL CHECK(length(binding_cbor) BETWEEN 1 AND 768),
    CHECK(root_wire_id<>child_wire_id),
    UNIQUE(root_wire_id,shard_index)
) STRICT;

CREATE TABLE mls_shard_forward_receipts (
    root_wire_id BLOB NOT NULL CHECK(length(root_wire_id)=32),
    source_wire_id BLOB NOT NULL CHECK(length(source_wire_id)=32),
    target_wire_id BLOB NOT NULL CHECK(length(target_wire_id)=32),
    source_agent_id BLOB NOT NULL CHECK(length(source_agent_id)=32),
    source_peer_id TEXT NOT NULL,
    source_message_id BLOB NOT NULL CHECK(length(source_message_id)=16),
    observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms>=0),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>observed_at_ms),
    PRIMARY KEY(root_wire_id,source_wire_id,target_wire_id,source_peer_id,source_message_id)
) STRICT;

CREATE INDEX mls_shard_forward_receipts_expiry
ON mls_shard_forward_receipts(expires_at_ms);
