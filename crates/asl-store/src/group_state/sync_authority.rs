use std::collections::BTreeSet;

use asl_types::{
    error::AslError,
    ids::{Hash32, PeerId},
    protocol::{GROUP_ADMIN_MANAGE_MEMBERS, MAX_GROUP_MEMBERS},
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use super::{
    MlsJournalKind, MlsMemberEvidence, MlsRoomUpdate, MlsSyncStoredStep, RoomVersion,
    recovery::{active_members, require_member},
    sql_number, sync_log,
    transition::{commit_candidate, peer_text},
    unsigned,
};
use crate::{Store, database_error};

pub struct MlsSyncReadAuthority<'a> {
    pub wire_id: Hash32,
    pub expected: RoomVersion,
    pub creator: &'a PeerId,
    pub owner: &'a PeerId,
    pub requester: &'a PeerId,
    pub members: &'a [MlsMemberEvidence],
    pub chain_id: u64,
}

pub struct MlsSyncAddAuthority<'a> {
    pub source: &'a PeerId,
    pub added: &'a PeerId,
    pub members: &'a [MlsMemberEvidence],
    pub chain_id: u64,
}

pub struct MlsRemoveAuthority<'a> {
    pub source: &'a PeerId,
    pub committer: &'a PeerId,
    pub removed: &'a PeerId,
    pub survivors: &'a [MlsMemberEvidence],
    pub chain_id: u64,
}

impl Store {
    /// Select a room to compare against its creator's head. Active rooms are
    /// included because another member may have advanced the creator's tree.
    pub fn next_mls_sync_room(
        &self,
        peer: &PeerId,
        after: Option<(Hash32, bool)>,
    ) -> Result<Option<Hash32>, AslError> {
        let boundary = after.as_ref().map(|(room, _)| room.as_bytes());
        let include_boundary = after.is_some_and(|(_, include)| include);
        let room: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT s.wire_group_id FROM mls_room_states s
                 JOIN asl_groups g ON g.group_id=s.local_group_id
                 LEFT JOIN group_access_policies p ON p.group_id=g.group_id
                 JOIN group_members m ON m.group_id=s.local_group_id
                 WHERE g.state IN ('needs_sync','active')
                   AND coalesce(p.owner_peer_id,g.creator_peer_id)=?1
                   AND m.peer_id=?1 AND m.state='active'
                   AND (?2 IS NULL OR s.wire_group_id>?2 OR (?3 AND s.wire_group_id=?2))
                 ORDER BY s.wire_group_id LIMIT 1",
                params![peer_text(peer), boundary, include_boundary],
                |r| r.get(0),
            )
            .optional()
            .map_err(database_error)?;
        room.map(|raw| {
            raw.try_into()
                .map(Hash32)
                .map_err(|_| AslError::InvalidDatabase)
        })
        .transpose()
    }

    pub fn has_mls_sync_member(&self, wire_id: Hash32, peer: &PeerId) -> Result<bool, AslError> {
        self.connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM mls_room_states s
                 JOIN asl_groups g ON g.group_id=s.local_group_id
                 JOIN group_members m ON m.group_id=s.local_group_id
                 WHERE s.wire_group_id=?1 AND g.state IN ('needs_sync','active')
                   AND m.peer_id=?2 AND m.state='active')",
                params![wire_id.as_bytes(), peer_text(peer)],
                |r| r.get(0),
            )
            .map_err(database_error)
    }

    /// Recheck the paused room and its current persisted device authority
    /// under one read snapshot. The caller verifies every step of the
    /// requested suffix against the same sealed snapshot before serving it.
    pub fn read_authorized_mls_sync_step(
        &self,
        authority: MlsSyncReadAuthority<'_>,
        history: Option<(u64, Hash32)>,
        current_time: impl Fn() -> Result<u64, AslError>,
        verify: impl FnMut(&MlsSyncStoredStep) -> Result<bool, AslError>,
    ) -> Result<Option<MlsSyncStoredStep>, AslError> {
        let MlsSyncReadAuthority {
            wire_id,
            expected,
            creator,
            owner,
            requester,
            members,
            chain_id,
        } = authority;
        let tx = self
            .connection
            .unchecked_transaction()
            .map_err(database_error)?;
        let former = active_members(&tx, wire_id, creator)?;
        if room_version(&tx, wire_id, creator)? != expected
            || !former.contains(requester)
            || !former.contains(owner)
            || member_ids(members)? != former.iter().map(peer_text).collect()
        {
            return Err(AslError::PolicyVersionConflict);
        }
        let now_ms = current_time()?;
        for member in members {
            require_member(&tx, member, chain_id, now_ms)?;
        }
        let step = history
            .map(|(base, head)| {
                sync_log::read_step(&tx, wire_id, base, Some(head), current_time, verify)
            })
            .transpose()?
            .flatten();
        tx.commit().map_err(database_error)?;
        Ok(step)
    }

    /// Commit exactly one verified Add. The network source and original
    /// committer must both be in the unchanged base roster.
    pub fn commit_verified_mls_sync_add(
        &mut self,
        update: MlsRoomUpdate<'_>,
        authority: MlsSyncAddAuthority<'_>,
        recorded_at_ms: u64,
        mut current_time: impl FnMut() -> Result<u64, AslError>,
    ) -> Result<RoomVersion, AslError> {
        let MlsSyncAddAuthority {
            source,
            added,
            members,
            chain_id,
        } = authority;
        let event = update.event.as_ref().ok_or(AslError::InvalidPolicyState)?;
        if !matches!(event.kind, MlsJournalKind::SyncCommit(_))
            || added == source
            || added == event.sender
            || member_ids(members)? != update.members.iter().map(peer_text).collect()
        {
            return Err(AslError::InvalidPolicyState);
        }
        let recorded_at = sql_number(recorded_at_ms)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        if room_version(&tx, update.wire_id, event.sender)? != update.expected {
            return Err(AslError::PolicyVersionConflict);
        }
        let former = active_members(&tx, update.wire_id, event.sender)?;
        if !former.contains(source) || former.contains(added) {
            return Err(AslError::PolicyDenied);
        }
        let now_ms = current_time()?;
        let mut added_member = None;
        for member in members {
            if &member.certificate.peer_id == added {
                added_member = Some(member);
            } else {
                require_member(&tx, member, chain_id, now_ms)?;
            }
        }
        added_member
            .ok_or(AslError::InvalidPolicyState)?
            .register(&tx, chain_id, now_ms)?;
        let version = commit_candidate(&tx, update, Some(added), recorded_at)?;
        let now_ms = current_time()?;
        if members
            .iter()
            .any(|member| now_ms >= member.certificate.expires_at_ms)
        {
            return Err(AslError::ExpiredMessage);
        }
        tx.commit().map_err(database_error)?;
        Ok(version)
    }

    /// Persist a single Remove by the current policy owner or a delegated
    /// member administrator. The removed leaf's
    /// authority may have expired; it is never used as a source or survivor.
    pub fn commit_verified_mls_remove(
        &mut self,
        update: MlsRoomUpdate<'_>,
        authority: MlsRemoveAuthority<'_>,
        recorded_at_ms: u64,
        mut current_time: impl FnMut() -> Result<u64, AslError>,
    ) -> Result<RoomVersion, AslError> {
        let MlsRemoveAuthority {
            source,
            committer,
            removed,
            survivors,
            chain_id,
        } = authority;
        let event = update.event.as_ref().ok_or(AslError::InvalidPolicyState)?;
        let projection = member_ids(survivors)?;
        if !matches!(event.kind, MlsJournalKind::SyncCommit(_))
            || removed == source
            || removed == committer
            || removed == event.sender
            || committer != event.sender
            || projection != update.members.iter().map(peer_text).collect()
        {
            return Err(AslError::InvalidPolicyState);
        }
        let recorded_at = sql_number(recorded_at_ms)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        if room_version_wire(&tx, update.wire_id)? != update.expected {
            return Err(AslError::PolicyVersionConflict);
        }
        if !remove_authorized(&tx, update.wire_id, committer)? {
            return Err(AslError::PolicyDenied);
        }
        let creator = room_creator(&tx, update.wire_id)?;
        let former = active_members(&tx, update.wire_id, &creator)?;
        if !former.contains(source)
            || !former.contains(committer)
            || !former.contains(removed)
            || projection
                != former
                    .iter()
                    .filter(|p| *p != removed)
                    .map(peer_text)
                    .collect()
        {
            return Err(AslError::PolicyDenied);
        }
        let now_ms = current_time()?;
        for member in survivors {
            require_member(&tx, member, chain_id, now_ms)?;
        }
        let version = commit_candidate(&tx, update, None, recorded_at)?;
        let now_ms = current_time()?;
        if survivors
            .iter()
            .any(|m| now_ms >= m.certificate.expires_at_ms)
        {
            return Err(AslError::ExpiredMessage);
        }
        tx.commit().map_err(database_error)?;
        Ok(version)
    }
}

fn room_creator(connection: &Connection, wire_id: Hash32) -> Result<PeerId, AslError> {
    let creator: String = connection
        .query_row(
            "SELECT g.creator_peer_id FROM mls_room_states s
             JOIN asl_groups g ON g.group_id=s.local_group_id
             WHERE s.wire_group_id=?1 AND g.state IN ('needs_sync','active')",
            [wire_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    PeerId::from_bytes(
        bs58::decode(creator)
            .into_vec()
            .map_err(|_| AslError::InvalidDatabase)?,
    )
    .map_err(|_| AslError::InvalidDatabase)
}

fn room_version_wire(connection: &Connection, wire_id: Hash32) -> Result<RoomVersion, AslError> {
    let (revision, mls_epoch, membership_epoch, policy_revision) = connection
        .query_row(
            "SELECT s.revision,g.mls_epoch,g.membership_epoch,p.revision
             FROM mls_room_states s JOIN asl_groups g ON g.group_id=s.local_group_id
             CROSS JOIN policy_state p WHERE s.wire_group_id=?1
               AND g.state IN ('needs_sync','active') AND p.singleton=1",
            [wire_id.as_bytes()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .map_err(database_error)?;
    Ok(RoomVersion {
        revision: unsigned(revision)?,
        mls_epoch: unsigned(mls_epoch)?,
        membership_epoch: unsigned(membership_epoch)?,
        policy_revision: unsigned(policy_revision)?,
    })
}

fn remove_authorized(
    connection: &Connection,
    wire_id: Hash32,
    committer: &PeerId,
) -> Result<bool, AslError> {
    connection
        .query_row(
            "SELECT CASE
                 WHEN coalesce(p.owner_peer_id,g.creator_peer_id)=?2 THEN 1
                 ELSE EXISTS(
                   SELECT 1 FROM group_access_members m
                   LEFT JOIN group_admin_capabilities c
                     ON c.group_id=m.group_id AND c.peer_id=m.peer_id
                   WHERE m.group_id=g.group_id AND m.peer_id=?2
                     AND m.role='admin' AND coalesce(m.muted,0)=0
                     AND (c.capabilities IS NULL OR (c.capabilities & ?3)<>0)
                 )
               END
             FROM mls_room_states s
             JOIN asl_groups g ON g.group_id=s.local_group_id
             LEFT JOIN group_access_policies p ON p.group_id=g.group_id
             JOIN group_members gm
               ON gm.group_id=g.group_id AND gm.peer_id=?2 AND gm.state='active'
             WHERE s.wire_group_id=?1 AND g.state IN ('needs_sync','active')",
            params![
                wire_id.as_bytes(),
                peer_text(committer),
                i64::from(GROUP_ADMIN_MANAGE_MEMBERS)
            ],
            |row| row.get(0),
        )
        .map_err(database_error)
}

pub(super) fn member_ids(members: &[MlsMemberEvidence]) -> Result<BTreeSet<String>, AslError> {
    if members.len() > MAX_GROUP_MEMBERS {
        return Err(AslError::QuotaExceeded);
    }
    let ids: BTreeSet<_> = members
        .iter()
        .map(|member| peer_text(&member.certificate.peer_id))
        .collect();
    if ids.len() != members.len() {
        return Err(AslError::InvalidPolicyState);
    }
    Ok(ids)
}

pub(super) fn room_version(
    connection: &Connection,
    wire_id: Hash32,
    creator: &PeerId,
) -> Result<RoomVersion, AslError> {
    let (revision, mls_epoch, membership_epoch, policy_revision) = connection
        .query_row(
            "SELECT s.revision,g.mls_epoch,g.membership_epoch,p.revision
             FROM mls_room_states s JOIN asl_groups g ON g.group_id=s.local_group_id
             CROSS JOIN policy_state p WHERE s.wire_group_id=?1
               AND g.creator_peer_id=?2 AND g.state IN ('needs_sync','active')
               AND p.singleton=1",
            params![wire_id.as_bytes(), peer_text(creator)],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()
        .map_err(database_error)?
        .ok_or(AslError::PolicyVersionConflict)?;
    Ok(RoomVersion {
        revision: unsigned(revision)?,
        mls_epoch: unsigned(mls_epoch)?,
        membership_epoch: unsigned(membership_epoch)?,
        policy_revision: unsigned(policy_revision)?,
    })
}
