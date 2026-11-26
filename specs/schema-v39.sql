CREATE TABLE migration_group_hints (
    wire_group_id BLOB PRIMARY KEY
        CHECK(length(wire_group_id)=32 AND wire_group_id<>zeroblob(32)),
    local_name TEXT NOT NULL CHECK(length(local_name) BETWEEN 1 AND 160),
    owner_agent_id TEXT NOT NULL REFERENCES agents(agent_id),
    last_epoch INTEGER NOT NULL CHECK(last_epoch BETWEEN 0 AND 9223372036854775806),
    imported_at_ms INTEGER NOT NULL CHECK(imported_at_ms>0)
) STRICT;

CREATE INDEX migration_group_hints_owner
ON migration_group_hints(owner_agent_id,imported_at_ms);
