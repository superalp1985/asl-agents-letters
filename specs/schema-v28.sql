CREATE TABLE mcp_recovery_grant (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    subject BLOB NOT NULL CHECK (length(subject) = 32)
) STRICT;

CREATE TABLE mcp_recovery_tasks (
    task_id BLOB PRIMARY KEY NOT NULL CHECK (length(task_id) = 16),
    status TEXT NOT NULL CHECK (status IN ('queued','active','complete','expired','failed','interrupted')),
    expires_at_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE mcp_recovery_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id BLOB NOT NULL REFERENCES mcp_recovery_tasks(task_id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('queued','active','complete','expired','failed','interrupted'))
) STRICT;
