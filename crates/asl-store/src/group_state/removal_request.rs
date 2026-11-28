use asl_types::{
    error::AslError,
    ids::{Hash32, Id128, PeerId},
    protocol::{GROUP_REMOVAL_REQUEST_TTL_MS, GroupRemovalRequest},
};
use rusqlite::{OptionalExtension, params};

use super::{sql_number, transition::peer_text};
use crate::{Store, database_error, group_access::GroupAdminCapabilityKind};

pub struct PendingGroupRemoval {
    pub id: Id128,
    pub target: PeerId,
    pub requester: PeerId,
    pub expires_at_ms: u64,
}

impl Store {
    pub fn check_group_removal_request(
        &self,
        room: Hash32,
        requester: &PeerId,
        target: &PeerId,
    ) -> Result<(PeerId, u64, u64), AslError> {
        let (state, epoch) = self.mls_room_progress(room)?.ok_or(AslError::NotFound)?;
        let saved = self
            .mls_room_for_reconciliation(room)?
            .ok_or(AslError::NotFound)?;
        let owner = self.group_access_owner(room)?.ok_or(AslError::NotFound)?;
        if state != "active"
            || requester == target
            || target == &saved.creator
            || target == &owner
            || !saved.members.contains(target)
            || !self.group_admin_has_capability(
                &saved.snapshot.local_id,
                requester,
                GroupAdminCapabilityKind::ManageMembers,
            )?
        {
            return Err(AslError::PolicyDenied);
        }
        let revision = self.group_access_policy(&saved.snapshot.local_id)?.revision;
        Ok((saved.creator, epoch, revision))
    }

    pub fn record_group_removal_request(
        &self,
        room: Hash32,
        local: &PeerId,
        requester: &PeerId,
        request: &GroupRemovalRequest,
        now_ms: u64,
    ) -> Result<(), AslError> {
        let (creator, epoch, revision) =
            self.check_group_removal_request(room, requester, &request.target)?;
        if local != &creator
            || !(1..=GROUP_REMOVAL_REQUEST_TTL_MS)
                .contains(&request.expires_at_ms.saturating_sub(now_ms))
        {
            return Err(AslError::PolicyDenied);
        }
        let now = sql_number(now_ms)?;
        let tx = self
            .connection
            .unchecked_transaction()
            .map_err(database_error)?;
        tx.execute(
            "DELETE FROM group_removal_requests WHERE expires_at_ms<=?1",
            [now],
        )
        .map_err(database_error)?;
        tx.execute(
            "INSERT OR IGNORE INTO group_removal_requests
             (wire_id,request_id,requester,target,mls_epoch,policy_revision,expires_at_ms)
             SELECT ?1,?2,?3,?4,?5,?6,?7
             WHERE (SELECT count(*) FROM group_removal_requests)<128
               AND (SELECT count(*) FROM group_removal_requests WHERE wire_id=?1)<16",
            params![
                room.as_bytes(),
                request.message_id.as_bytes(),
                peer_text(requester),
                peer_text(&request.target),
                sql_number(epoch)?,
                sql_number(revision)?,
                sql_number(request.expires_at_ms)?
            ],
        )
        .map_err(database_error)?;
        tx.commit().map_err(database_error)
    }

    pub fn group_removal_requests(
        &self,
        room: Hash32,
        local: &PeerId,
        now_ms: u64,
    ) -> Result<Vec<PendingGroupRemoval>, AslError> {
        let mut stmt = self
            .connection
            .prepare(
                "SELECT r.request_id,r.requester,r.target,r.expires_at_ms
             FROM group_removal_requests r
             JOIN mls_room_states s ON s.wire_group_id=r.wire_id
             JOIN asl_groups g ON g.group_id=s.local_group_id
             LEFT JOIN group_access_policies p ON p.group_id=g.group_id
             WHERE r.wire_id=?1 AND g.creator_peer_id=?2 AND g.state='active'
               AND r.mls_epoch=g.mls_epoch AND r.policy_revision=coalesce(p.revision,0)
               AND r.expires_at_ms>?3 ORDER BY r.expires_at_ms,r.request_id LIMIT 16",
            )
            .map_err(database_error)?;
        let rows = stmt
            .query_map(
                params![room.as_bytes(), peer_text(local), sql_number(now_ms)?],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .map_err(database_error)?;
        rows.map(|row| {
            let (id, requester, target, expires) = row.map_err(database_error)?;
            Ok(PendingGroupRemoval {
                id: Id128(id.try_into().map_err(|_| AslError::InvalidDatabase)?),
                requester: parse_peer(&requester)?,
                target: parse_peer(&target)?,
                expires_at_ms: super::unsigned(expires)?,
            })
        })
        .collect()
    }

    pub fn review_group_removal(
        &self,
        room: Hash32,
        id: Id128,
        local: &PeerId,
        now_ms: u64,
    ) -> Result<PeerId, AslError> {
        let pending = self
            .group_removal_requests(room, local, now_ms)?
            .into_iter()
            .find(|pending| pending.id == id)
            .ok_or(AslError::NotFound)?;
        self.check_group_removal_request(room, &pending.requester, &pending.target)?;
        Ok(pending.target)
    }

    pub fn forget_group_removal(&self, room: Hash32, id: Id128) -> Result<(), AslError> {
        self.connection
            .query_row(
                "DELETE FROM group_removal_requests WHERE wire_id=?1 AND request_id=?2 RETURNING 1",
                params![room.as_bytes(), id.as_bytes()],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(database_error)?;
        Ok(())
    }
}

fn parse_peer(text: &str) -> Result<PeerId, AslError> {
    let bytes = bs58::decode(text)
        .into_vec()
        .map_err(|_| AslError::InvalidDatabase)?;
    PeerId::from_bytes(bytes).map_err(|_| AslError::InvalidDatabase)
}
