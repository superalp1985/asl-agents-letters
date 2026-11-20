CREATE TABLE pairing_prompt_log (
    invite_id BLOB PRIMARY KEY CHECK(length(invite_id) = 16),
    agent_id BLOB NOT NULL CHECK(length(agent_id) = 32),
    shown_at_ms INTEGER NOT NULL CHECK(shown_at_ms >= 0)
) STRICT, WITHOUT ROWID;

CREATE INDEX pairing_prompt_log_agent_time
ON pairing_prompt_log(agent_id, shown_at_ms);

CREATE INDEX pairing_prompt_log_time
ON pairing_prompt_log(shown_at_ms);
