-- Only a new Extractor selection has a reviewable revision. Do not backfill
-- authority from the legacy private setting, profile metadata or snapshots.
CREATE TABLE local_avatar_selection (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    generation BLOB NOT NULL CHECK(length(generation) = 16),
    sanitizer_version INTEGER NOT NULL CHECK(sanitizer_version >= 1),
    image BLOB NOT NULL CHECK(length(image) BETWEEN 1 AND 65536)
) STRICT;

CREATE TABLE avatar_reference_grant (
    singleton INTEGER PRIMARY KEY REFERENCES local_avatar_selection(singleton) ON DELETE CASCADE,
    agent_id BLOB NOT NULL CHECK(length(agent_id) = 32),
    grant_id BLOB NOT NULL CHECK(length(grant_id) = 16),
    resource_key BLOB NOT NULL CHECK(length(resource_key) = 16),
    epoch INTEGER NOT NULL CHECK(epoch >= 1),
    content_id BLOB NOT NULL CHECK(length(content_id) = 32)
) STRICT;
