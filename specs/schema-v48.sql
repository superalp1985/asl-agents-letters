DROP VIEW IF EXISTS logical_group_agents;
DROP VIEW IF EXISTS logical_group_peers;

CREATE INDEX IF NOT EXISTS mls_room_shards_root
ON mls_room_shards(root_wire_id, shard_index);
