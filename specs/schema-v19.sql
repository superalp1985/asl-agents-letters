CREATE TABLE direct_inbound_observations (
    agent_id TEXT NOT NULL CHECK(length(agent_id) BETWEEN 32 AND 44),
    peer_id TEXT NOT NULL CHECK(length(peer_id) BETWEEN 1 AND 175),
    message_id TEXT NOT NULL CHECK(length(message_id) = 32),
    root_task_id TEXT NOT NULL CHECK(length(root_task_id) = 32),
    observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms >= 0),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms > observed_at_ms),
    intent INTEGER NOT NULL CHECK(intent BETWEEN 1 AND 6),
    result_shape INTEGER NOT NULL CHECK(result_shape BETWEEN 1 AND 3),
    constraint_count INTEGER NOT NULL CHECK(constraint_count BETWEEN 0 AND 16),
    topics_json TEXT NOT NULL CHECK(length(topics_json) <= 2048),
    PRIMARY KEY(agent_id, message_id)
) STRICT, WITHOUT ROWID;

CREATE INDEX direct_inbound_observations_expiry
    ON direct_inbound_observations(expires_at_ms);

CREATE INDEX direct_inbound_observations_recent
    ON direct_inbound_observations(observed_at_ms DESC, agent_id, message_id);
