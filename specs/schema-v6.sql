CREATE TABLE paired_contacts (
    agent_id BLOB PRIMARY KEY CHECK(length(agent_id) = 32),
    paired_at_ms INTEGER NOT NULL CHECK(paired_at_ms >= 0),
    invite_id BLOB NOT NULL UNIQUE CHECK(length(invite_id) = 16)
) STRICT, WITHOUT ROWID;

CREATE TABLE pairing_invite_receipts (
    invite_id BLOB PRIMARY KEY CHECK(length(invite_id) = 16),
    agent_id BLOB NOT NULL CHECK(length(agent_id) = 32),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms >= 0)
) STRICT, WITHOUT ROWID;

CREATE INDEX pairing_invite_receipts_expiry
ON pairing_invite_receipts(expires_at_ms);
