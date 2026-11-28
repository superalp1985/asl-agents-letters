//! Bounded member projection used by layered group routing.

use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, PeerId},
    task::GroupId,
};
use rusqlite::{OptionalExtension, params};

use crate::{Store, chain::agent_text, database_error};

pub const MAX_LAYERED_GROUP_MEMBERS: usize = 10_000;

pub(crate) const LOGICAL_GROUP_PEERS_CTE: &str = "
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
),
logical_group_peers AS (
    SELECT DISTINCT tree.root_wire_id, tree.shard_wire_id, tree.local_group_id,
           member.peer_id, member.role, peer.agent_id
    FROM room_tree tree
    JOIN group_members member
      ON member.group_id=tree.local_group_id AND member.state='active'
    JOIN peers peer ON peer.peer_id=member.peer_id
)
";

impl Store {
    pub fn logical_group_member_count(&self, root: Hash32) -> Result<usize, AslError> {
        let sql = format!(
            "{LOGICAL_GROUP_PEERS_CTE}
             SELECT COUNT(DISTINCT agent_id)
             FROM logical_group_peers
             WHERE root_wire_id=?1"
        );
        let count: i64 = self
            .connection
            .query_row(&sql, [root.as_bytes().as_slice()], |row| row.get(0))
            .map_err(database_error)?;
        usize::try_from(count).map_err(|_| AslError::InvalidDatabase)
    }

    pub fn logical_group_has_agent(&self, root: Hash32, agent: AgentId) -> Result<bool, AslError> {
        if agent.0 == [0; 32] {
            return Err(AslError::InvalidMessage);
        }
        let sql = format!(
            "{LOGICAL_GROUP_PEERS_CTE}
             SELECT EXISTS(
                 SELECT 1 FROM logical_group_peers
                 WHERE root_wire_id=?1 AND agent_id=?2
             )"
        );
        self.connection
            .query_row(
                &sql,
                params![root.as_bytes().as_slice(), agent_text(agent)],
                |row| row.get(0),
            )
            .map_err(database_error)
    }

    pub fn group_topology_members(&self, group_id: &GroupId) -> Result<Vec<PeerId>, AslError> {
        let wire: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT wire_group_id FROM mls_room_states WHERE local_group_id=?1",
                [hex::encode(group_id.0.as_bytes())],
                |row| row.get(0),
            )
            .optional()
            .map_err(database_error)?;
        let Some(wire) = wire else {
            let group = hex::encode(group_id.0.as_bytes());
            let mut statement = self
                .connection
                .prepare(
                    "SELECT peer_id FROM group_members
                     WHERE group_id=?1 AND state='active'
                     ORDER BY peer_id LIMIT ?2",
                )
                .map_err(database_error)?;
            let rows = statement
                .query_map(
                    params![
                        group,
                        i64::try_from(MAX_LAYERED_GROUP_MEMBERS + 1)
                            .map_err(|_| AslError::InvalidMessage)?
                    ],
                    |row| row.get::<_, String>(0),
                )
                .map_err(database_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(database_error)?;
            return rows
                .into_iter()
                .map(|peer| {
                    let bytes = bs58::decode(peer)
                        .into_vec()
                        .map_err(|_| AslError::InvalidDatabase)?;
                    PeerId::from_bytes(bytes).map_err(|_| AslError::InvalidDatabase)
                })
                .collect();
        };
        let wire: [u8; 32] = wire.try_into().map_err(|_| AslError::InvalidDatabase)?;
        let root = self.mls_logical_root(Hash32(wire))?;
        let sql = format!(
            "{LOGICAL_GROUP_PEERS_CTE}
             SELECT peer_id FROM logical_group_peers
             WHERE root_wire_id=?1
             ORDER BY peer_id LIMIT ?2"
        );
        let mut statement = self.connection.prepare(&sql).map_err(database_error)?;
        let rows = statement
            .query_map(
                params![
                    root.as_bytes().as_slice(),
                    i64::try_from(MAX_LAYERED_GROUP_MEMBERS + 1)
                        .map_err(|_| AslError::InvalidMessage)?
                ],
                |row| row.get::<_, String>(0),
            )
            .map_err(database_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(database_error)?;
        if rows.len() > MAX_LAYERED_GROUP_MEMBERS {
            return Err(AslError::QuotaExceeded);
        }
        rows.into_iter()
            .map(|peer| {
                let bytes = bs58::decode(peer)
                    .into_vec()
                    .map_err(|_| AslError::InvalidDatabase)?;
                PeerId::from_bytes(bytes).map_err(|_| AslError::InvalidDatabase)
            })
            .collect()
    }
}
