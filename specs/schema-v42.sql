CREATE TABLE group_file_policies (
    group_id TEXT NOT NULL REFERENCES asl_groups(group_id) ON DELETE CASCADE,
    content_id BLOB NOT NULL CHECK(length(content_id)=32),
    permissions INTEGER NOT NULL CHECK(permissions BETWEEN 0 AND 7),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms>=0),
    PRIMARY KEY(group_id,content_id)
) STRICT;

CREATE TABLE group_admin_capabilities (
    group_id TEXT NOT NULL REFERENCES asl_groups(group_id) ON DELETE CASCADE,
    peer_id TEXT NOT NULL REFERENCES peers(peer_id),
    capabilities INTEGER NOT NULL CHECK(capabilities BETWEEN 0 AND 7),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms>=0),
    PRIMARY KEY(group_id,peer_id)
) STRICT;

CREATE INDEX group_admin_capabilities_peer
ON group_admin_capabilities(peer_id,group_id);

CREATE TABLE dht_provider_cache_v42 (
    key TEXT NOT NULL CHECK(length(key) = 64),
    provider_id TEXT NOT NULL,
    addresses_json TEXT NOT NULL CHECK(json_valid(addresses_json)),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
    PRIMARY KEY(key, provider_id)
) STRICT;

INSERT OR REPLACE INTO dht_provider_cache_v42(
    key, provider_id, addresses_json, expires_at_ms, updated_at_ms
)
SELECT key, provider_id, addresses_json, expires_at_ms, updated_at_ms
FROM dht_provider_cache;

DROP TABLE dht_provider_cache;
ALTER TABLE dht_provider_cache_v42 RENAME TO dht_provider_cache;
CREATE INDEX dht_provider_cache_expiry ON dht_provider_cache(expires_at_ms);
