ALTER TABLE mcp_recovery_tasks ADD COLUMN result_snapshot BLOB
    CHECK (result_snapshot IS NULL OR length(result_snapshot) BETWEEN 1 AND 13312);
