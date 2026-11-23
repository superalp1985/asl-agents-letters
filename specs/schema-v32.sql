CREATE TABLE mcp_recovery_download_decisions (
    approval_id TEXT PRIMARY KEY NOT NULL REFERENCES transfer_consents(approval_id) ON DELETE CASCADE,
    subject BLOB NOT NULL CHECK(length(subject)=32)
) STRICT;
