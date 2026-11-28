DROP VIEW IF EXISTS logical_group_agents;
DROP VIEW IF EXISTS logical_group_peers;

CREATE VIEW logical_group_agents AS
WITH RECURSIVE room_tree(root_wire_id, shard_wire_id, local_group_id) AS (
    SELECT state.wire_group_id, state.wire_group_id, state.local_group_id
    FROM mls_room_states state
    WHERE NOT EXISTS(
        SELECT 1 FROM mls_room_shards shard
        WHERE shard.shard_wire_id=state.wire_group_id
    )
    UNION ALL
    SELECT tree.root_wire_id, shard.shard_wire_id, state.local_group_id
    FROM room_tree tree
    JOIN mls_room_shards shard ON shard.root_wire_id=tree.root_wire_id
    JOIN mls_room_states state ON state.wire_group_id=shard.shard_wire_id
)
SELECT DISTINCT tree.root_wire_id, peer.agent_id
FROM room_tree tree
JOIN group_members member
  ON member.group_id=tree.local_group_id AND member.state='active'
JOIN peers peer ON peer.peer_id=member.peer_id;

CREATE VIEW logical_group_peers AS
WITH RECURSIVE room_tree(root_wire_id, shard_wire_id, local_group_id) AS (
    SELECT state.wire_group_id, state.wire_group_id, state.local_group_id
    FROM mls_room_states state
    WHERE NOT EXISTS(
        SELECT 1 FROM mls_room_shards shard
        WHERE shard.shard_wire_id=state.wire_group_id
    )
    UNION ALL
    SELECT tree.root_wire_id, shard.shard_wire_id, state.local_group_id
    FROM room_tree tree
    JOIN mls_room_shards shard ON shard.root_wire_id=tree.root_wire_id
    JOIN mls_room_states state ON state.wire_group_id=shard.shard_wire_id
)
SELECT DISTINCT tree.root_wire_id, tree.shard_wire_id, tree.local_group_id,
       member.peer_id, member.role
FROM room_tree tree
JOIN group_members member
  ON member.group_id=tree.local_group_id AND member.state='active';

CREATE INDEX mls_room_shards_root ON mls_room_shards(root_wire_id, shard_index);
