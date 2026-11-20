use std::collections::BTreeSet;

use asl_types::{
    error::AslError,
    ids::{Hash32, Id128, PeerId},
    protocol::{MAX_GROUP_MEMBERS, MAX_GROUP_MLS_OBJECT_BYTES, MAX_GROUP_PAYLOAD_BYTES},
    task::GroupId,
};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};

use super::{MAX_SEALED_ROOM_BYTES, MLS_SYNC_RETENTION_MS, MlsEpochBindings, sql_number, sync_log};
use crate::{Store, current_time_ms, database_error};

const EXPIRY_PRUNE_BATCH: i64 = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoomVersion {
    pub revision: u64,
    pub mls_epoch: u64,
    pub membership_epoch: u64,
    pub policy_revision: u64,
}

#[derive(Clone, Copy)]
pub enum MlsJournalKind {
    /// The message ID inside the authenticated application plaintext.
    Application(Id128),
    Commit,
    SyncCommit(MlsEpochBindings),
}

pub struct MlsJournalEntry<'a> {
    pub sender: &'a PeerId,
    pub kind: MlsJournalKind,
    pub ciphertext: &'a [u8],
}

pub struct MlsRoomUpdate<'a> {
    pub local_id: &'a GroupId,
    pub wire_id: Hash32,
    pub expected: RoomVersion,
    pub mls_epoch: u64,
    /// Bound to expected.revision + 1 and mls_epoch by the seal operation.
    pub sealed_snapshot: &'a [u8],
    pub members: &'a [PeerId],
    /// Only the first projection of an already staged room may omit an event.
    pub event: Option<MlsJournalEntry<'a>>,
}

impl Store {
    /// Persist an already validated MLS candidate, but keep the room closed
    /// to file grants until a Core reconciliation path exists.
    pub fn commit_mls_room_candidate(
        &mut self,
        update: MlsRoomUpdate<'_>,
    ) -> Result<RoomVersion, AslError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let version = commit_candidate(&tx, update, None, current_time_ms())?;
        tx.commit().map_err(database_error)?;
        Ok(version)
    }
}

pub(super) fn commit_candidate(
    tx: &Transaction<'_>,
    update: MlsRoomUpdate<'_>,
    only_add: Option<&PeerId>,
    now: i64,
) -> Result<RoomVersion, AslError> {
    if update.members.len() > MAX_GROUP_MEMBERS
        || update.sealed_snapshot.is_empty()
        || update.sealed_snapshot.len() > MAX_SEALED_ROOM_BYTES
    {
        return Err(AslError::QuotaExceeded);
    }
    let projection: BTreeSet<_> = update.members.iter().map(peer_text).collect();
    if projection.len() != update.members.len() {
        return Err(AslError::InvalidPolicyState);
    }
    let expected = update.expected;
    let room = hex::encode(update.local_id.0.as_bytes());
    let row = tx.query_row(
            "SELECT s.revision,g.mls_epoch,g.membership_epoch,p.revision,g.creator_peer_id
             FROM mls_room_states s JOIN asl_groups g ON g.group_id=s.local_group_id
             CROSS JOIN policy_state p
             WHERE s.local_group_id=?1 AND s.wire_group_id=?2 AND g.state='needs_sync' AND p.singleton=1",
            params![room, update.wire_id.as_bytes()],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?, r.get::<_, i64>(3)?, r.get::<_, String>(4)?)),
        ).optional().map_err(database_error)?.ok_or(AslError::PolicyVersionConflict)?;
    if (row.0, row.1, row.2, row.3)
        != (
            sql_number(expected.revision)?,
            sql_number(expected.mls_epoch)?,
            sql_number(expected.membership_epoch)?,
            sql_number(expected.policy_revision)?,
        )
    {
        return Err(AslError::PolicyVersionConflict);
    }
    let former = tx.prepare(
            "SELECT peer_id FROM group_members WHERE group_id=?1 AND state='active' ORDER BY peer_id LIMIT ?2",
        ).map_err(database_error)?
            .query_map(params![room, (MAX_GROUP_MEMBERS + 1) as i64], |r| r.get::<_, String>(0))
            .map_err(database_error)?
            .collect::<Result<BTreeSet<_>, _>>().map_err(database_error)?;
    if former.len() > MAX_GROUP_MEMBERS {
        return Err(AslError::InvalidDatabase);
    }

    if let Some(recipient) = only_add {
        let recipient = peer_text(recipient);
        if projection.difference(&former).ne([&recipient]) || !former.is_subset(&projection) {
            return Err(AslError::InvalidPolicyState);
        }
    }
    let changed = former != projection;
    let next_epoch = sql_number(update.mls_epoch)?;
    if let Some(event) = update.event {
        let event_sender = peer_text(event.sender);
        if !former.contains(&event_sender)
            || event.ciphertext.is_empty()
            || match event.kind {
                MlsJournalKind::Application(_) => {
                    changed
                        || update.mls_epoch != expected.mls_epoch
                        || event.ciphertext.len() > MAX_GROUP_PAYLOAD_BYTES
                }
                MlsJournalKind::Commit | MlsJournalKind::SyncCommit(_) => {
                    expected.mls_epoch.checked_add(1) != Some(update.mls_epoch)
                        || event.ciphertext.len() > MAX_GROUP_MLS_OBJECT_BYTES
                }
            }
        {
            return Err(AslError::InvalidPolicyState);
        }
        let mut replay_key = blake3::Hasher::new_derive_key("ASL-MLS-ROOM-EVENT-v1");
        replay_key.update(update.wire_id.as_bytes());
        let kind = match event.kind {
            MlsJournalKind::Application(message_id) => {
                replay_key.update(&[0]);
                replay_key.update(message_id.as_bytes());
                replay_key.update(event.sender.as_bytes());
                "application"
            }
            MlsJournalKind::Commit | MlsJournalKind::SyncCommit(_) => {
                replay_key.update(&[1]);
                replay_key.update(&expected.mls_epoch.to_be_bytes());
                replay_key.update(event.ciphertext);
                "commit"
            }
        };
        let event_id = hex::encode(&replay_key.finalize().as_bytes()[..Id128::LENGTH]);
        let retention = MLS_SYNC_RETENTION_MS as i64;
        let expires_at_ms = if matches!(event.kind, MlsJournalKind::SyncCommit(_)) {
            now.checked_add(retention)
                .ok_or(AslError::InvalidPolicyState)?
        } else {
            now.saturating_add(retention)
        };
        let inserted = tx.execute(
                "INSERT INTO group_events(event_id,group_id,mls_epoch,sender_peer_id,kind,ciphertext,created_at_ms,expires_at_ms)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(event_id) DO NOTHING",
                params![
                    event_id, room, row.1, event_sender, kind,
                    event.ciphertext, now, expires_at_ms
                ],
            ).map_err(database_error)?;
        if inserted != 1 {
            return Err(AslError::PolicyVersionConflict);
        }
        if let MlsJournalKind::SyncCommit(bindings) = event.kind {
            sync_log::insert(
                tx,
                &room,
                row.1,
                next_epoch,
                &event_id,
                bindings,
                expires_at_ms,
            )?;
        }
    } else if expected.revision != 1
        || !former.is_empty()
        || projection.is_empty()
        || update.mls_epoch != expected.mls_epoch
    {
        return Err(AslError::InvalidPolicyState);
    }

    let revision = row.0.checked_add(1).ok_or(AslError::QuotaExceeded)?;
    for peer in former.difference(&projection) {
        tx.execute(
            "UPDATE group_members SET state='removed' WHERE group_id=?1 AND peer_id=?2",
            params![room, peer],
        )
        .map_err(database_error)?;
        tx.execute(
            "UPDATE mls_outgoing_invites SET welcome=NULL
                 WHERE wire_group_id=?1 AND (recipient_peer_id=?2 OR creator_peer_id=?2)
                   AND welcome IS NOT NULL",
            params![update.wire_id.as_bytes(), peer],
        )
        .map_err(database_error)?;
    }
    for peer in projection.difference(&former) {
        tx.execute(
            "INSERT INTO group_members(group_id,peer_id,role,state,joined_at_ms)
                 VALUES (?1,?2,?3,'active',?4) ON CONFLICT(group_id,peer_id) DO UPDATE
                 SET role=excluded.role,state=excluded.state,joined_at_ms=excluded.joined_at_ms",
            params![
                room,
                peer,
                if peer == &row.4 { "creator" } else { "member" },
                now
            ],
        )
        .map_err(database_error)?;
    }
    // The projection is still paused, so neither authority version changes.
    tx.execute(
        "UPDATE asl_groups SET mls_epoch=?2,updated_at_ms=?3 WHERE group_id=?1",
        params![room, next_epoch, now],
    )
    .map_err(database_error)?;
    if row.1 != next_epoch {
        sync_log::trim_room(tx, &room, next_epoch)?;
    }
    tx.execute(
        "UPDATE mls_room_states SET sealed_snapshot=?2,revision=?3 WHERE local_group_id=?1",
        params![room, update.sealed_snapshot, revision],
    )
    .map_err(database_error)?;
    Ok(RoomVersion {
        revision: revision as u64,
        mls_epoch: update.mls_epoch,
        ..expected
    })
}

pub(super) fn prune_expired_events(tx: &Transaction<'_>, now: i64) -> Result<(), AslError> {
    // The foreign key removes the matching sync rows with the ciphertext.
    tx.execute(
        "DELETE FROM group_events WHERE event_id IN (
            SELECT event_id FROM group_events WHERE expires_at_ms<=?1
            ORDER BY expires_at_ms LIMIT ?2
         )",
        params![now, EXPIRY_PRUNE_BATCH],
    )
    .map_err(database_error)?;
    Ok(())
}

pub(super) fn peer_text(peer: &PeerId) -> String {
    bs58::encode(peer.as_bytes()).into_string()
}
