//! Bounded member projection used by layered group routing.

use asl_types::{error::AslError, ids::PeerId, task::GroupId};
use rusqlite::params;

use crate::{Store, database_error};

pub const MAX_LAYERED_GROUP_MEMBERS: usize = 10_000;

impl Store {
    pub fn group_topology_members(&self, group_id: &GroupId) -> Result<Vec<PeerId>, AslError> {
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
