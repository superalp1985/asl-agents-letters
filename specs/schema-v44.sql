CREATE TABLE group_removal_requests (
    wire_id BLOB NOT NULL REFERENCES mls_room_states(wire_group_id) ON DELETE CASCADE,
    request_id BLOB NOT NULL CHECK(length(request_id)=16),
    requester TEXT NOT NULL REFERENCES peers(peer_id),
    target TEXT NOT NULL REFERENCES peers(peer_id),
    mls_epoch INTEGER NOT NULL CHECK(mls_epoch>=0),
    policy_revision INTEGER NOT NULL CHECK(policy_revision>=0),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>0),
    PRIMARY KEY(wire_id,request_id),
    UNIQUE(wire_id,requester,target)
) STRICT;

CREATE TABLE mls_room_shards (
    root_wire_id BLOB NOT NULL REFERENCES mls_room_states(wire_group_id) ON DELETE CASCADE,
    shard_wire_id BLOB NOT NULL UNIQUE REFERENCES mls_room_states(wire_group_id) ON DELETE CASCADE,
    shard_index INTEGER NOT NULL CHECK(shard_index BETWEEN 1 AND 19),
    CHECK(root_wire_id<>shard_wire_id),
    PRIMARY KEY(root_wire_id,shard_index)
) STRICT;
