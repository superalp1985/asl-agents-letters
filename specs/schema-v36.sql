CREATE TABLE group_access_policies (
    group_id TEXT PRIMARY KEY REFERENCES asl_groups(group_id) ON DELETE CASCADE,
    revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 9223372036854775806),
    permissions INTEGER NOT NULL CHECK(permissions BETWEEN 0 AND 7),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms>=0)
) STRICT;

CREATE TABLE group_access_members (
    group_id TEXT NOT NULL REFERENCES asl_groups(group_id) ON DELETE CASCADE,
    peer_id TEXT NOT NULL REFERENCES peers(peer_id),
    role TEXT NOT NULL CHECK(role IN ('admin','member')),
    muted INTEGER NOT NULL CHECK(muted IN (0,1)),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms>=0),
    PRIMARY KEY(group_id,peer_id)
) STRICT;

CREATE INDEX group_access_members_role
ON group_access_members(group_id,role,peer_id);
