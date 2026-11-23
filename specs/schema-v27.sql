ALTER TABLE write_grants ADD COLUMN inbox_retention_days INTEGER NOT NULL DEFAULT 0
    CHECK (inbox_retention_days BETWEEN 0 AND 30 AND (kind='inbox' OR inbox_retention_days=0));

CREATE TABLE received_file_retention (
    transfer_id TEXT PRIMARY KEY REFERENCES transfers(transfer_id) ON DELETE CASCADE,
    expires_at_ms INTEGER NOT NULL,
    write_stamp INTEGER NOT NULL
) STRICT;
CREATE INDEX received_file_expiry ON received_file_retention(expires_at_ms);
