CREATE TABLE observed_remote_profiles (
    agent_id TEXT PRIMARY KEY REFERENCES agents(agent_id),
    agent_key BLOB NOT NULL CHECK(length(agent_key) = 32),
    chain_id INTEGER NOT NULL REFERENCES chain_state_cache(chain_id),
    checkpoint_hash BLOB NOT NULL CHECK(length(checkpoint_hash) = 32),
    registry_sequence INTEGER NOT NULL CHECK(registry_sequence >= 1),
    profile_sequence BLOB NOT NULL CHECK(length(profile_sequence) = 8),
    topics_json TEXT NOT NULL CHECK(length(topics_json) BETWEEN 2 AND 49 AND json_valid(topics_json)),
    issued_at_ms INTEGER NOT NULL CHECK(issued_at_ms >= 0),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms > issued_at_ms),
    observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms >= issued_at_ms)
) STRICT, WITHOUT ROWID;
