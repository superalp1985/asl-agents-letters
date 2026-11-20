CREATE TABLE mls_sync_log (
    room_id TEXT NOT NULL REFERENCES mls_room_states(local_group_id),
    base_epoch INTEGER NOT NULL CHECK(base_epoch >= 0 AND base_epoch < 9223372036854775807),
    seq INTEGER NOT NULL CHECK(seq = base_epoch + 1),
    base_binding BLOB NOT NULL CHECK(length(base_binding) = 32),
    next_binding BLOB NOT NULL CHECK(length(next_binding) = 32),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms > 0),
    event_id TEXT NOT NULL UNIQUE REFERENCES group_events(event_id) ON DELETE CASCADE,
    PRIMARY KEY(room_id, base_epoch)
) STRICT;
CREATE INDEX mls_sync_log_expiry ON mls_sync_log(expires_at_ms, event_id);
