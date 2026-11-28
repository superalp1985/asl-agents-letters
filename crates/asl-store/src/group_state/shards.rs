use asl_types::{
    error::AslError,
    ids::{Hash32, PeerId},
    task::GroupId,
};
use rusqlite::{OptionalExtension, Transaction, params};

use super::{sql_number, transition::peer_text};
use crate::{Store, database_error};

pub(super) fn link_shard(
    tx: &Transaction<'_>,
    root: Hash32,
    shard: Hash32,
    creator: &PeerId,
) -> Result<(), AslError> {
    let authorized: bool = tx
        .query_row(
            "SELECT EXISTS(
           SELECT 1 FROM mls_room_states r JOIN asl_groups g ON g.group_id=r.local_group_id
           LEFT JOIN group_access_policies p ON p.group_id=g.group_id
           JOIN group_members m ON m.group_id=g.group_id AND m.peer_id=?2 AND m.state='active'
           WHERE r.wire_group_id=?1
             AND coalesce(p.owner_peer_id,g.creator_peer_id)=?2 AND g.state='active'
             AND NOT EXISTS (SELECT 1 FROM mls_room_shards WHERE shard_wire_id=?1))",
            params![root.as_bytes(), peer_text(creator)],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    if !authorized {
        return Err(AslError::PolicyDenied);
    }
    let next: i64 = tx
        .query_row(
            "SELECT coalesce(max(shard_index),0)+1 FROM mls_room_shards WHERE root_wire_id=?1",
            [root.as_bytes()],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    if next > 19 {
        return Err(AslError::QuotaExceeded);
    }
    tx.execute(
        "INSERT INTO mls_room_shards VALUES (?1,?2,?3)",
        params![root.as_bytes(), shard.as_bytes(), next],
    )
    .map_err(database_error)?;
    Ok(())
}

pub(super) fn inherit_root_policy(
    tx: &Transaction<'_>,
    root: Hash32,
    shard: &GroupId,
    creator: &PeerId,
    now: i64,
) -> Result<(), AslError> {
    let shard = hex::encode(shard.0.as_bytes());
    let creator = peer_text(creator);
    tx.execute(
        "INSERT INTO group_access_policies(
             group_id,revision,permissions,owner_peer_id,updated_at_ms)
         SELECT ?1,p.revision,p.permissions,coalesce(p.owner_peer_id,g.creator_peer_id),?2
         FROM mls_room_states r
         JOIN asl_groups g ON g.group_id=r.local_group_id
         JOIN group_access_policies p ON p.group_id=g.group_id
         WHERE r.wire_group_id=?3
           AND coalesce(p.owner_peer_id,g.creator_peer_id)=?4",
        params![shard, now, root.as_bytes(), creator],
    )
    .map_err(database_error)?;
    tx.execute(
        "INSERT INTO group_file_policies(group_id,content_id,permissions,updated_at_ms)
         SELECT ?1,f.content_id,f.permissions,?2
         FROM mls_room_states r
         JOIN group_file_policies f ON f.group_id=r.local_group_id
         WHERE r.wire_group_id=?3",
        params![shard, now, root.as_bytes()],
    )
    .map_err(database_error)?;
    tx.execute(
        "INSERT INTO group_access_members(group_id,peer_id,role,muted,updated_at_ms)
         SELECT ?1,a.peer_id,a.role,a.muted,?2
         FROM mls_room_states r
         JOIN group_access_members a ON a.group_id=r.local_group_id
         JOIN group_members m ON m.group_id=?1 AND m.peer_id=a.peer_id AND m.state='active'
         WHERE r.wire_group_id=?3",
        params![shard, now, root.as_bytes()],
    )
    .map_err(database_error)?;
    tx.execute(
        "INSERT INTO group_admin_capabilities(group_id,peer_id,capabilities,updated_at_ms)
         SELECT ?1,c.peer_id,c.capabilities,?2
         FROM mls_room_states r
         JOIN group_admin_capabilities c ON c.group_id=r.local_group_id
         JOIN group_access_members a
           ON a.group_id=?1 AND a.peer_id=c.peer_id AND a.role='admin'
         WHERE r.wire_group_id=?3",
        params![shard, now, root.as_bytes()],
    )
    .map_err(database_error)?;
    Ok(())
}

impl Store {
    pub fn mls_shard_parent(&self, room: Hash32) -> Result<Option<(Hash32, u16)>, AslError> {
        self.connection
            .query_row(
                "SELECT root_wire_id,shard_index FROM mls_room_shards WHERE shard_wire_id=?1",
                [room.as_bytes()],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(database_error)?
            .map(|(root, index)| {
                Ok((
                    Hash32(root.try_into().map_err(|_| AslError::InvalidDatabase)?),
                    u16::try_from(index).map_err(|_| AslError::InvalidDatabase)?,
                ))
            })
            .transpose()
    }

    pub fn mls_logical_root(&self, room: Hash32) -> Result<Hash32, AslError> {
        let root = self
            .connection
            .query_row(
                "SELECT root_wire_id FROM mls_room_shards WHERE shard_wire_id=?1
                 UNION ALL
                 SELECT root_wire_id FROM mls_shard_bindings WHERE child_wire_id=?1
                 LIMIT 1",
                [room.as_bytes()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(database_error)?;
        match root {
            Some(bytes) => Ok(Hash32(
                bytes.try_into().map_err(|_| AslError::InvalidDatabase)?,
            )),
            None if self.mls_room_progress(room)?.is_some() => Ok(room),
            None => Err(AslError::NotFound),
        }
    }

    pub fn mls_room_shards(&self, root: Hash32) -> Result<Vec<Hash32>, AslError> {
        let mut statement = self.connection.prepare(
            "SELECT shard_wire_id FROM mls_room_shards WHERE root_wire_id=?1 ORDER BY shard_index",
        ).map_err(database_error)?;
        let rows = statement
            .query_map([root.as_bytes()], |row| row.get::<_, Vec<u8>>(0))
            .map_err(database_error)?;
        rows.map(|bytes| {
            Ok(Hash32(
                bytes
                    .map_err(database_error)?
                    .try_into()
                    .map_err(|_| AslError::InvalidDatabase)?,
            ))
        })
        .collect()
    }

    pub fn mls_room_shard_entries(&self, root: Hash32) -> Result<Vec<(u16, Hash32)>, AslError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT shard_index,shard_wire_id FROM mls_room_shards
                 WHERE root_wire_id=?1 ORDER BY shard_index",
            )
            .map_err(database_error)?;
        let rows = statement
            .query_map([root.as_bytes()], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(database_error)?;
        rows.map(|row| {
            let (index, room) = row.map_err(database_error)?;
            Ok((
                u16::try_from(index).map_err(|_| AslError::InvalidDatabase)?,
                Hash32(room.try_into().map_err(|_| AslError::InvalidDatabase)?),
            ))
        })
        .collect()
    }

    pub fn choose_mls_shard(
        &self,
        root: Hash32,
        creator: &PeerId,
        recipient: &PeerId,
        member_limit: usize,
        now_ms: u64,
    ) -> Result<Hash32, AslError> {
        let mut rooms = self.mls_room_shards(root)?;
        rooms.insert(0, root);
        let owner = self.group_access_owner(root)?.ok_or(AslError::NotFound)?;
        if &owner != creator || creator == recipient {
            return Err(AslError::PolicyDenied);
        }
        let recipient = peer_text(recipient);
        let mut best: Option<(usize, Hash32)> = None;
        for room in rooms {
            let (load, exists, local_creator): (i64, bool, bool) = self
                .connection
                .query_row(
                    "SELECT
                   (SELECT count(*) FROM group_members m
                    WHERE m.group_id=g.group_id AND m.state='active')
                     + (SELECT count(DISTINCT i.recipient_peer_id) FROM mls_outgoing_invites i
                        WHERE i.wire_group_id=s.wire_group_id AND i.expires_at_ms>?2
                          AND i.base_epoch=g.mls_epoch AND i.welcome IS NULL),
                   EXISTS(SELECT 1 FROM group_members m
                          WHERE m.group_id=g.group_id AND m.peer_id=?3 AND m.state='active')
                     OR EXISTS(SELECT 1 FROM mls_outgoing_invites i
                               WHERE i.wire_group_id=s.wire_group_id AND i.expires_at_ms>?2
                                 AND i.base_epoch=g.mls_epoch AND i.recipient_peer_id=?3
                                 AND i.welcome IS NULL),
                   g.creator_peer_id=?4
                 FROM mls_room_states s JOIN asl_groups g ON g.group_id=s.local_group_id
                 WHERE s.wire_group_id=?1",
                    params![
                        room.as_bytes(),
                        sql_number(now_ms)?,
                        recipient,
                        peer_text(creator)
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(database_error)?;
            if exists {
                return Ok(room);
            }
            let load = usize::try_from(load).map_err(|_| AslError::InvalidDatabase)?;
            if local_creator
                && self
                    .mls_room_progress(room)?
                    .is_some_and(|(state, _)| state == "active")
                && load < member_limit
                && best.is_none_or(|(current, _)| load < current)
            {
                best = Some((load, room));
            }
        }
        best.map(|(_, room)| room).ok_or(AslError::QuotaExceeded)
    }
}
