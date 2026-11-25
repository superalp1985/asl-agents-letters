CREATE TABLE semantic_context_candidates (
    authority BLOB NOT NULL CHECK(length(authority)=32 AND authority<>zeroblob(32)),
    namespace INTEGER NOT NULL CHECK(namespace BETWEEN 0 AND 4294967295),
    revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 65535),
    digest BLOB NOT NULL CHECK(length(digest)=32),
    signed_bundle BLOB NOT NULL CHECK(length(signed_bundle) BETWEEN 1 AND 8388608),
    stored_at_ms INTEGER NOT NULL CHECK(stored_at_ms>=0),
    PRIMARY KEY(authority,namespace,revision,digest),
    UNIQUE(authority,namespace,revision)
) STRICT;
