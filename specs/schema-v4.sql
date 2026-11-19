CREATE TABLE transfer_cooldowns (
    content_id TEXT PRIMARY KEY CHECK(length(content_id) = 64),
    retry_after_ms INTEGER NOT NULL CHECK(retry_after_ms >= 0),
    reason TEXT NOT NULL CHECK(length(reason) <= 64)
) STRICT;
CREATE INDEX transfer_cooldowns_expiry ON transfer_cooldowns(retry_after_ms);
