CREATE TABLE semantic_context_resources (
    resource_key TEXT NOT NULL REFERENCES resources(resource_key) ON DELETE CASCADE,
    authority BLOB NOT NULL CHECK(length(authority)=32 AND authority<>zeroblob(32)),
    namespace INTEGER NOT NULL CHECK(namespace BETWEEN 0 AND 4294967295),
    revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 65535),
    digest BLOB NOT NULL CHECK(length(digest)=32 AND digest<>zeroblob(32)),
    content_id TEXT NOT NULL REFERENCES snapshots(content_id),
    file_size INTEGER NOT NULL CHECK(file_size BETWEEN 1 AND 8388608),
    indexed_at_ms INTEGER NOT NULL CHECK(indexed_at_ms>=0),
    PRIMARY KEY(resource_key,authority,namespace,revision,digest)
) STRICT;

CREATE INDEX semantic_context_resources_lookup
ON semantic_context_resources(authority,namespace,revision,digest);
