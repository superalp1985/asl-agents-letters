CREATE TABLE direct_inbound_conversations (
    agent_id TEXT NOT NULL REFERENCES agents(agent_id),
    root_task_id TEXT NOT NULL CHECK(length(root_task_id) = 32),
    rounds_used INTEGER NOT NULL CHECK(rounds_used BETWEEN 1 AND 3),
    messages_used INTEGER NOT NULL CHECK(messages_used BETWEEN 1 AND 6),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms >= 0),
    PRIMARY KEY(agent_id, root_task_id)
) STRICT;
CREATE INDEX direct_inbound_conversations_expiry
ON direct_inbound_conversations(expires_at_ms);
