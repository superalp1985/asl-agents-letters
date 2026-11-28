CREATE TABLE dht_record_cache (
    agent_id TEXT NOT NULL,
    kind INTEGER NOT NULL CHECK(kind BETWEEN 1 AND 3),
    sequence INTEGER NOT NULL CHECK(sequence >= 0),
    registry_sequence INTEGER NOT NULL CHECK(registry_sequence >= 0),
    record BLOB NOT NULL CHECK(length(record) BETWEEN 1 AND 8192),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
    PRIMARY KEY(agent_id, kind)
) STRICT;

CREATE TABLE dht_provider_cache (
    key TEXT PRIMARY KEY CHECK(length(key) = 64),
    provider_id TEXT NOT NULL,
    addresses_json TEXT NOT NULL CHECK(json_valid(addresses_json)),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0)
) STRICT;

CREATE INDEX dht_provider_cache_expiry ON dht_provider_cache(expires_at_ms);
