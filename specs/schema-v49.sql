CREATE TABLE IF NOT EXISTS mls_shard_forward_outbox (
    forward_id BLOB PRIMARY KEY
        CHECK(length(forward_id)=16),
    source_message_id BLOB NOT NULL
        CHECK(length(source_message_id)=16),
    logical_root BLOB NOT NULL
        CHECK(length(logical_root)=32),
    source_wire_id BLOB NOT NULL
        CHECK(length(source_wire_id)=32),
    target_wire_id BLOB NOT NULL
        CHECK(length(target_wire_id)=32),
    target_binding_revision INTEGER NOT NULL
        CHECK(target_binding_revision BETWEEN 0 AND 9223372036854775806),
    frame_cbor BLOB NOT NULL
        CHECK(length(frame_cbor) BETWEEN 1 AND 262144),
    observed_at_ms INTEGER NOT NULL
        CHECK(observed_at_ms>=0),
    expires_at_ms INTEGER NOT NULL
        CHECK(expires_at_ms>observed_at_ms),
    created_at_ms INTEGER NOT NULL
        CHECK(created_at_ms>=0),
    next_attempt_ms INTEGER NOT NULL
        CHECK(next_attempt_ms>=0),
    attempts INTEGER NOT NULL DEFAULT 0
        CHECK(attempts BETWEEN 0 AND 2147483647),
    state TEXT NOT NULL DEFAULT 'pending'
        CHECK(state IN ('pending','terminal')),
    terminal_reason TEXT
        CHECK(terminal_reason IS NULL OR length(terminal_reason) BETWEEN 1 AND 64),
    terminal_at_ms INTEGER
        CHECK(terminal_at_ms IS NULL OR terminal_at_ms>=0),
    CHECK(source_wire_id<>target_wire_id),
    CHECK(
        (state='pending' AND terminal_reason IS NULL AND terminal_at_ms IS NULL)
        OR
        (state='terminal' AND terminal_reason IS NOT NULL AND terminal_at_ms IS NOT NULL)
    )
) STRICT;

CREATE INDEX IF NOT EXISTS mls_shard_forward_outbox_due
ON mls_shard_forward_outbox(next_attempt_ms)
WHERE state='pending';

CREATE INDEX IF NOT EXISTS mls_shard_forward_outbox_expiry
ON mls_shard_forward_outbox(expires_at_ms)
WHERE state='pending';

CREATE INDEX IF NOT EXISTS mls_shard_forward_outbox_terminal
ON mls_shard_forward_outbox(terminal_at_ms)
WHERE state='terminal';
