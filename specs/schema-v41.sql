ALTER TABLE group_access_policies ADD COLUMN owner_peer_id TEXT;

CREATE TABLE resource_budget_grants (
    conversation_id TEXT NOT NULL CHECK(length(conversation_id) BETWEEN 1 AND 128),
    kind INTEGER NOT NULL CHECK(kind BETWEEN 1 AND 4),
    granted INTEGER NOT NULL CHECK(granted >= 0),
    consumed INTEGER NOT NULL CHECK(consumed BETWEEN 0 AND granted),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
    PRIMARY KEY(conversation_id, kind)
) STRICT;
