CREATE TABLE mcp_recovery_downloads (
    transfer_id TEXT PRIMARY KEY NOT NULL REFERENCES transfers(transfer_id) ON DELETE CASCADE,
    subject BLOB NOT NULL CHECK(length(subject)=32),
    grant_epoch INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL
) STRICT;
