CREATE TABLE mls_room_states (
    local_group_id TEXT PRIMARY KEY REFERENCES asl_groups(group_id),
    wire_group_id BLOB NOT NULL UNIQUE CHECK(length(wire_group_id) = 32),
    sealed_snapshot BLOB NOT NULL CHECK(length(sealed_snapshot) BETWEEN 1 AND 2097152),
    revision INTEGER NOT NULL DEFAULT 1 CHECK(revision >= 1)
) STRICT;
