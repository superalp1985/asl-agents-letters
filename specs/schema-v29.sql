ALTER TABLE mcp_recovery_grant ADD COLUMN replay_floor_ms INTEGER NOT NULL DEFAULT 0;
ALTER TABLE mcp_recovery_tasks ADD COLUMN request_id BLOB CHECK (request_id IS NULL OR length(request_id) = 16);
ALTER TABLE mcp_recovery_tasks ADD COLUMN request_digest BLOB CHECK (
    (request_id IS NULL AND request_digest IS NULL)
    OR (request_id IS NOT NULL AND request_digest IS NOT NULL AND length(request_digest) = 32)
);
CREATE UNIQUE INDEX mcp_recovery_request_id ON mcp_recovery_tasks(request_id)
    WHERE request_id IS NOT NULL;
