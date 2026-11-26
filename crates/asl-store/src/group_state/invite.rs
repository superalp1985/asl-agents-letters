use std::collections::BTreeSet;

use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId},
    protocol::MAX_GROUP_MEMBERS,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use super::{
    MAX_SEALED_ROOM_BYTES, MlsMemberEvidence, PendingMlsRoom, RoomVersion, insert_mls_room,
    recovery::require_member, sql_number, transition::peer_text,
};
use crate::{Store, database_error};

pub(super) const INVITE_TTL_MS: u64 = 5 * 60 * 1_000;
const AGENT_WINDOW_MS: i64 = 24 * 60 * 60 * 1_000;
const GLOBAL_WINDOW_MS: i64 = 60 * 60 * 1_000;
const MAX_OPEN_INVITES: i64 = 5;
const MAX_HOURLY_INVITES: i64 = 20;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MlsIncomingInvite {
    pub id: Id128,
    pub wire_id: Hash32,
    pub base_epoch: u64,
    pub inviter: AgentId,
    pub inviter_device: PeerId,
    pub recipient: AgentId,
    pub recipient_device: PeerId,
    pub expires_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MlsJoinKey {
    pub request_id: Id128,
    pub package_ref: Hash32,
}

pub struct MlsInviteEndpoints<'a> {
    pub inviter: &'a MlsMemberEvidence,
    pub recipient: &'a MlsMemberEvidence,
    pub chain_id: u64,
}

impl MlsInviteEndpoints<'_> {
    fn check(&self, invite: &MlsIncomingInvite) -> Result<[&MlsMemberEvidence; 2], AslError> {
        let endpoints = [
            (self.inviter, invite.inviter, &invite.inviter_device),
            (self.recipient, invite.recipient, &invite.recipient_device),
        ];
        for (member, agent, device) in endpoints {
            if member.certificate.agent_id != agent || &member.certificate.peer_id != device {
                return Err(AslError::InvalidDeviceCertificate);
            }
        }
        Ok([self.inviter, self.recipient])
    }

    fn require(
        &self,
        db: &Connection,
        invite: &MlsIncomingInvite,
        now_ms: u64,
    ) -> Result<(), AslError> {
        for member in self.check(invite)? {
            require_member(db, member, self.chain_id, now_ms)?;
        }
        Ok(())
    }
}

pub struct MlsJoinedRoom<'a> {
    pub invite: &'a MlsIncomingInvite,
    pub key: MlsJoinKey,
    pub room: PendingMlsRoom<'a>,
    pub members: &'a [MlsMemberEvidence],
    pub chain_id: u64,
    pub expected_policy_revision: u64,
}

impl Store {
    /// Reserve a prompt only for a Core-authenticated, locally targeted invite.
    /// Recording it does not authorize producing an MLS key package.
    pub fn receive_mls_invite(
        &mut self,
        invite: &MlsIncomingInvite,
        now_ms: u64,
    ) -> Result<bool, AslError> {
        self.receive_mls_invite_inner(invite, None, now_ms)
    }

    pub fn receive_verified_mls_invite(
        &mut self,
        invite: &MlsIncomingInvite,
        endpoints: MlsInviteEndpoints<'_>,
        now_ms: u64,
    ) -> Result<bool, AslError> {
        self.receive_mls_invite_inner(invite, Some(endpoints), now_ms)
    }

    fn receive_mls_invite_inner(
        &mut self,
        invite: &MlsIncomingInvite,
        endpoints: Option<MlsInviteEndpoints<'_>>,
        now_ms: u64,
    ) -> Result<bool, AslError> {
        if invite.id.0 == [0; 16]
            || invite.wire_id.0 == [0; 32]
            || invite.inviter.0 == [0; 32]
            || invite.recipient.0 == [0; 32]
            || invite.inviter_device == invite.recipient_device
            || invite.base_epoch >= i64::MAX as u64
            || invite.expires_at_ms > i64::MAX as u64
            || !matches!(
                invite.expires_at_ms.checked_sub(now_ms),
                Some(1..=INVITE_TTL_MS)
            )
        {
            return Err(AslError::InvalidMessage);
        }
        let now = sql_number(now_ms)?;
        let agent = bs58::encode(invite.inviter.as_bytes()).into_string();
        let inviter = peer_text(&invite.inviter_device);
        let tx = immediate(&mut self.connection)?;
        prune(&tx, now)?;
        let can_prompt = tx
            .query_row(
                "SELECT NOT EXISTS (
                       SELECT 1 FROM mls_room_states s JOIN asl_groups g ON g.group_id=s.local_group_id
                       WHERE s.wire_group_id=?2 AND (
                           g.state<>'needs_sync' OR g.creator_peer_id<>?8 OR g.mls_epoch>=?9
                       )
                   )
                   AND NOT EXISTS (
                       SELECT 1 FROM mls_incoming_invites
                       WHERE invite_id=?1 OR (inviter_agent_id=?3 AND shown_at_ms>?4)
                   )
                   AND (SELECT count(*) FROM mls_incoming_invites WHERE shown_at_ms>?5) < ?6
                   AND (SELECT count(*) FROM mls_incoming_invites WHERE state<>'closed') < ?7",
                params![
                    invite.id.as_bytes(),
                    invite.wire_id.as_bytes(),
                    agent,
                    now - AGENT_WINDOW_MS,
                    now - GLOBAL_WINDOW_MS,
                    MAX_HOURLY_INVITES,
                    MAX_OPEN_INVITES,
                    inviter,
                    sql_number(invite.base_epoch)?,
                ],
                |row| row.get::<_, bool>(0),
            )
            .map_err(database_error)?;
        if !can_prompt {
            tx.commit().map_err(database_error)?;
            return Ok(false);
        }
        if let Some(endpoints) = endpoints {
            for member in endpoints.check(invite)? {
                member.register(&tx, endpoints.chain_id, now_ms)?;
            }
        }
        tx.execute(
            "INSERT INTO mls_incoming_invites
                 (invite_id,wire_group_id,base_epoch,inviter_agent_id,inviter_peer_id,
                  recipient_agent_id,recipient_peer_id,shown_at_ms,expires_at_ms)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                invite.id.as_bytes(),
                invite.wire_id.as_bytes(),
                sql_number(invite.base_epoch)?,
                agent,
                inviter,
                bs58::encode(invite.recipient.as_bytes()).into_string(),
                bs58::encode(invite.recipient_device.as_bytes()).into_string(),
                now,
                sql_number(invite.expires_at_ms)?,
            ],
        )
        .map_err(database_error)?;
        tx.commit().map_err(database_error)?;
        Ok(true)
    }

    /// Called only after explicit local approval. Persist the DPAPI-sealed
    /// single-use package and signer before allowing Core to send the request.
    pub fn save_mls_join_package(
        &mut self,
        invite: &MlsIncomingInvite,
        key: MlsJoinKey,
        sealed_package: &[u8],
        now_ms: u64,
    ) -> Result<bool, AslError> {
        self.save_mls_join_package_inner(invite, key, sealed_package, None, now_ms)
    }

    pub fn save_verified_mls_join_package(
        &mut self,
        invite: &MlsIncomingInvite,
        key: MlsJoinKey,
        sealed_package: &[u8],
        endpoints: MlsInviteEndpoints<'_>,
        now_ms: u64,
    ) -> Result<bool, AslError> {
        self.save_mls_join_package_inner(invite, key, sealed_package, Some(endpoints), now_ms)
    }

    fn save_mls_join_package_inner(
        &mut self,
        invite: &MlsIncomingInvite,
        key: MlsJoinKey,
        sealed_package: &[u8],
        endpoints: Option<MlsInviteEndpoints<'_>>,
        now_ms: u64,
    ) -> Result<bool, AslError> {
        if key.request_id.0 == [0; 16]
            || key.request_id == invite.id
            || key.package_ref.0 == [0; 32]
            || !(1..=MAX_SEALED_ROOM_BYTES).contains(&sealed_package.len())
        {
            return Err(AslError::InvalidPolicyState);
        }
        let tx = immediate(&mut self.connection)?;
        if let Some(endpoints) = endpoints {
            endpoints.require(&tx, invite, now_ms)?;
        }
        prune(&tx, sql_number(now_ms)?)?;
        if !matches_invite(&tx, invite, now_ms)? {
            tx.commit().map_err(database_error)?;
            return Ok(false);
        }
        let updated = tx
            .execute(
                "UPDATE mls_incoming_invites
                 SET state='approved', request_id=?2, package_ref=?3, sealed_package=?4
                 WHERE invite_id=?1 AND state='pending'
                   AND NOT EXISTS (
                       SELECT 1 FROM mls_incoming_invites WHERE wire_group_id=?5 AND state='approved'
                   )",
                params![
                    invite.id.as_bytes(),
                    key.request_id.as_bytes(),
                    key.package_ref.as_bytes(),
                    sealed_package,
                    invite.wire_id.as_bytes(),
                ],
            )
            .map_err(database_error)?;
        tx.commit().map_err(database_error)?;
        Ok(updated == 1)
    }

    pub fn pending_mls_join_package(
        &mut self,
        invite: &MlsIncomingInvite,
        now_ms: u64,
    ) -> Result<Option<(MlsJoinKey, Vec<u8>)>, AslError> {
        self.pending_mls_join_package_inner(invite, None, now_ms)
    }

    pub fn verified_mls_join_package(
        &mut self,
        invite: &MlsIncomingInvite,
        endpoints: MlsInviteEndpoints<'_>,
        now_ms: u64,
    ) -> Result<Option<(MlsJoinKey, Vec<u8>)>, AslError> {
        self.pending_mls_join_package_inner(invite, Some(endpoints), now_ms)
    }

    fn pending_mls_join_package_inner(
        &mut self,
        invite: &MlsIncomingInvite,
        endpoints: Option<MlsInviteEndpoints<'_>>,
        now_ms: u64,
    ) -> Result<Option<(MlsJoinKey, Vec<u8>)>, AslError> {
        let tx = immediate(&mut self.connection)?;
        if let Some(endpoints) = endpoints {
            endpoints.require(&tx, invite, now_ms)?;
        }
        prune(&tx, sql_number(now_ms)?)?;
        if !matches_invite(&tx, invite, now_ms)? {
            tx.commit().map_err(database_error)?;
            return Ok(None);
        }
        let row: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = tx
            .query_row(
                "SELECT request_id,package_ref,sealed_package FROM mls_incoming_invites
             WHERE invite_id=?1 AND state='approved'",
                [invite.id.as_bytes()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(database_error)?;
        tx.commit().map_err(database_error)?;
        row.map(|(request_id, package_ref, sealed)| {
            let key = MlsJoinKey {
                request_id: Id128(
                    request_id
                        .try_into()
                        .map_err(|_| AslError::InvalidDatabase)?,
                ),
                package_ref: Hash32(
                    package_ref
                        .try_into()
                        .map_err(|_| AslError::InvalidDatabase)?,
                ),
            };
            Ok((key, sealed))
        })
        .transpose()
    }

    /// List live, unapproved prompts for exactly this local agent and device.
    pub fn list_pending_mls_invites(
        &self,
        recipient: AgentId,
        device: &PeerId,
        now_ms: u64,
    ) -> Result<Vec<MlsIncomingInvite>, AslError> {
        list_invites(
            &self.connection,
            recipient,
            device,
            sql_number(now_ms)?,
            "pending",
        )
    }

    /// Core must re-admit the exact inviter before any retransmission.
    pub fn recover_mls_joins(
        &mut self,
        recipient: AgentId,
        device: &PeerId,
        now_ms: u64,
    ) -> Result<Vec<MlsIncomingInvite>, AslError> {
        let now = sql_number(now_ms)?;
        let tx = immediate(&mut self.connection)?;
        prune(&tx, now)?;
        let invites = list_invites(&tx, recipient, device, now, "approved")?;
        tx.commit().map_err(database_error)?;
        Ok(invites)
    }

    pub fn reject_mls_invite(
        &mut self,
        invite: &MlsIncomingInvite,
        now_ms: u64,
    ) -> Result<bool, AslError> {
        let tx = immediate(&mut self.connection)?;
        if !matches_invite(&tx, invite, now_ms)? {
            return Ok(false);
        }
        let changed = tx
            .execute(
                "UPDATE mls_incoming_invites SET state='closed'
             WHERE invite_id=?1 AND state='pending'",
                [invite.id.as_bytes()],
            )
            .map_err(database_error)?;
        tx.commit().map_err(database_error)?;
        Ok(changed == 1)
    }

    /// Install the Core-verified exact Welcome candidate and roster while
    /// consuming the approved package. The new room still cannot grant access.
    pub fn finish_mls_join(
        &mut self,
        join: MlsJoinedRoom<'_>,
        current_time: impl FnMut() -> Result<u64, AslError>,
    ) -> Result<RoomVersion, AslError> {
        self.finish_mls_admission(join, None, current_time)
    }

    /// Replace the paused room with an independently approved, forward Welcome.
    /// Core must supply a fresh sealed snapshot at `expected.revision + 1`,
    /// without the previous MLS ratchet, sync history, or sync budget.
    pub fn finish_mls_rejoin(
        &mut self,
        join: MlsJoinedRoom<'_>,
        expected: RoomVersion,
        current_time: impl FnMut() -> Result<u64, AslError>,
    ) -> Result<RoomVersion, AslError> {
        self.finish_mls_admission(join, Some(expected), current_time)
    }

    fn finish_mls_admission(
        &mut self,
        join: MlsJoinedRoom<'_>,
        expected: Option<RoomVersion>,
        mut current_time: impl FnMut() -> Result<u64, AslError>,
    ) -> Result<RoomVersion, AslError> {
        let invite = join.invite;
        let roster = join.members;
        if join.room.wire_id != invite.wire_id
            || join.room.creator != &invite.inviter_device
            || invite.base_epoch.checked_add(1) != Some(join.room.mls_epoch)
            || !(1..=MAX_SEALED_ROOM_BYTES).contains(&join.room.sealed_snapshot.len())
            || roster.len() > MAX_GROUP_MEMBERS
            || !roster.iter().any(|member| {
                member.certificate.peer_id == invite.recipient_device
                    && member.certificate.agent_id == invite.recipient
            })
            || !roster.iter().any(|member| {
                member.certificate.peer_id == invite.inviter_device
                    && member.certificate.agent_id == invite.inviter
            })
            || roster
                .iter()
                .map(|member| member.certificate.peer_id.as_bytes())
                .collect::<BTreeSet<_>>()
                .len()
                != roster.len()
        {
            return Err(AslError::InvalidPolicyState);
        }
        let tx = immediate(&mut self.connection)?;
        let now_ms = current_time()?;
        let revision = tx
            .query_row(
                "SELECT revision FROM policy_state WHERE singleton=1",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map_err(database_error)?;
        if revision != sql_number(join.expected_policy_revision)?
            || expected
                .is_some_and(|version| version.policy_revision != join.expected_policy_revision)
            || !matches_invite(&tx, invite, now_ms)?
        {
            return Err(AslError::PolicyVersionConflict);
        }
        let consumed = tx
            .execute(
                "UPDATE mls_incoming_invites SET state='closed', sealed_package=NULL
             WHERE invite_id=?1 AND state='approved' AND request_id=?2 AND package_ref=?3",
                params![
                    invite.id.as_bytes(),
                    join.key.request_id.as_bytes(),
                    join.key.package_ref.as_bytes()
                ],
            )
            .map_err(database_error)?;
        if consumed != 1 {
            return Err(AslError::PolicyVersionConflict);
        }
        for member in roster {
            member.register(&tx, join.chain_id, now_ms)?;
        }
        let now = sql_number(now_ms)?;
        let local_id = hex::encode(join.room.local_id.0.as_bytes());
        let version = if let Some(expected) = expected {
            replace_paused_room(&tx, &join, &local_id, expected, now)?
        } else {
            insert_mls_room(&tx, &join.room, now, false)?;
            RoomVersion {
                revision: 1,
                mls_epoch: join.room.mls_epoch,
                membership_epoch: 1,
                policy_revision: join.expected_policy_revision,
            }
        };
        {
            let mut stmt = tx
                .prepare(
                    "INSERT INTO group_members(group_id,peer_id,role,state,joined_at_ms)
                 VALUES (?1,?2,?3,'active',?4)",
                )
                .map_err(database_error)?;
            for member in roster {
                let device = &member.certificate.peer_id;
                let peer = peer_text(device);
                let role = if device == &invite.inviter_device {
                    "creator"
                } else {
                    "member"
                };
                stmt.execute(params![local_id, peer, role, now])
                    .map_err(database_error)?;
            }
        }
        let final_time = current_time()?;
        if final_time >= invite.expires_at_ms
            || roster
                .iter()
                .any(|member| final_time >= member.certificate.expires_at_ms)
        {
            return Err(AslError::ExpiredMessage);
        }
        tx.commit().map_err(database_error)?;
        Ok(version)
    }

    pub fn prune_mls_expired(&mut self, now_ms: u64) -> Result<(), AslError> {
        let tx = immediate(&mut self.connection)?;
        let now = sql_number(now_ms)?;
        prune(&tx, now)?;
        super::outgoing::prune(&tx, now)?;
        super::transition::prune_expired_events(&tx, now)?;
        tx.commit().map_err(database_error)
    }
}

fn replace_paused_room(
    tx: &Transaction<'_>,
    join: &MlsJoinedRoom<'_>,
    local_id: &str,
    expected: RoomVersion,
    now: i64,
) -> Result<RoomVersion, AslError> {
    let revision = sql_number(expected.revision)?;
    let next_revision = revision.checked_add(1).ok_or(AslError::QuotaExceeded)?;
    let updated = tx
        .execute(
            "UPDATE mls_room_states SET sealed_snapshot=?3,revision=?4
             WHERE local_group_id=?1 AND wire_group_id=?2 AND revision=?5 AND EXISTS (
                 SELECT 1 FROM asl_groups WHERE group_id=?1 AND state='needs_sync'
                   AND creator_peer_id=?6 AND mls_epoch=?7 AND membership_epoch=?8
                   AND mls_epoch<?9
             )",
            params![
                local_id,
                join.room.wire_id.as_bytes(),
                join.room.sealed_snapshot,
                next_revision,
                revision,
                peer_text(join.room.creator),
                sql_number(expected.mls_epoch)?,
                sql_number(expected.membership_epoch)?,
                sql_number(join.invite.base_epoch)?,
            ],
        )
        .map_err(database_error)?;
    if updated != 1 {
        return Err(AslError::PolicyVersionConflict);
    }
    // The room remains paused. Preserve its local label and all authority versions.
    tx.execute(
        "UPDATE asl_groups SET mls_epoch=?2,updated_at_ms=?3 WHERE group_id=?1",
        params![local_id, sql_number(join.room.mls_epoch)?, now],
    )
    .map_err(database_error)?;
    tx.execute("DELETE FROM group_members WHERE group_id=?1", [local_id])
        .map_err(database_error)?;
    tx.execute("DELETE FROM mls_sync_log WHERE room_id=?1", [local_id])
        .map_err(database_error)?;
    // Preserve replay markers and package consumption, not old branch replies.
    tx.execute(
        "UPDATE mls_outgoing_invites SET welcome=NULL WHERE wire_group_id=?1 AND welcome IS NOT NULL",
        [join.room.wire_id.as_bytes()],
    )
    .map_err(database_error)?;
    close_room_invites(tx, join.room.wire_id)?;
    tx.execute(
        "DELETE FROM migration_group_hints WHERE wire_group_id=?1",
        [join.room.wire_id.as_bytes()],
    )
    .map_err(database_error)?;
    Ok(RoomVersion {
        revision: next_revision as u64,
        mls_epoch: join.room.mls_epoch,
        ..expected
    })
}

/// Close approvals from the previous room state without freeing prompt quota.
/// Room creation must also call this to prevent a new-room approval becoming a rejoin.
pub(super) fn close_room_invites(tx: &Transaction<'_>, wire_id: Hash32) -> Result<(), AslError> {
    tx.execute(
        "UPDATE mls_incoming_invites SET state='closed', sealed_package=NULL
         WHERE wire_group_id=?1 AND state<>'closed'",
        [wire_id.as_bytes()],
    )
    .map_err(database_error)?;
    Ok(())
}

fn immediate(connection: &mut Connection) -> Result<Transaction<'_>, AslError> {
    connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(database_error)
}

fn decode_base58(value: &str) -> Result<Vec<u8>, AslError> {
    bs58::decode(value)
        .into_vec()
        .map_err(|_| AslError::InvalidDatabase)
}

pub(super) fn list_invites(
    connection: &Connection,
    recipient: AgentId,
    device: &PeerId,
    now: i64,
    state: &str,
) -> Result<Vec<MlsIncomingInvite>, AslError> {
    let mut stmt = connection
        .prepare(
            "SELECT i.invite_id,i.wire_group_id,i.base_epoch,i.inviter_agent_id,i.inviter_peer_id,i.expires_at_ms
             FROM mls_incoming_invites AS i
             LEFT JOIN mls_room_states s ON s.wire_group_id=i.wire_group_id
             LEFT JOIN asl_groups g ON g.group_id=s.local_group_id
             WHERE i.recipient_agent_id=?1 AND i.recipient_peer_id=?2 AND i.state=?4
               AND i.shown_at_ms<=?3 AND i.expires_at_ms>?3 AND (
                   s.wire_group_id IS NULL OR (
                       g.state='needs_sync' AND g.creator_peer_id=i.inviter_peer_id AND g.mls_epoch<i.base_epoch
                   )
               )
             ORDER BY i.shown_at_ms,i.invite_id LIMIT ?5",
        )
        .map_err(database_error)?;
    let mut rows = stmt
        .query(params![
            bs58::encode(recipient.as_bytes()).into_string(),
            bs58::encode(device.as_bytes()).into_string(),
            now,
            state,
            MAX_OPEN_INVITES,
        ])
        .map_err(database_error)?;
    let mut invites = Vec::new();
    while let Some(row) = rows.next().map_err(database_error)? {
        let id: Vec<u8> = row.get(0).map_err(database_error)?;
        let wire: Vec<u8> = row.get(1).map_err(database_error)?;
        let agent: String = row.get(3).map_err(database_error)?;
        let peer: String = row.get(4).map_err(database_error)?;
        invites.push(MlsIncomingInvite {
            id: Id128(id.try_into().map_err(|_| AslError::InvalidDatabase)?),
            wire_id: Hash32(wire.try_into().map_err(|_| AslError::InvalidDatabase)?),
            base_epoch: super::unsigned(row.get(2).map_err(database_error)?)?,
            inviter: AgentId(
                decode_base58(&agent)?
                    .try_into()
                    .map_err(|_| AslError::InvalidDatabase)?,
            ),
            inviter_device: PeerId::from_bytes(decode_base58(&peer)?)
                .map_err(|_| AslError::InvalidDatabase)?,
            recipient,
            recipient_device: device.clone(),
            expires_at_ms: super::unsigned(row.get(5).map_err(database_error)?)?,
        });
    }
    Ok(invites)
}

fn matches_invite(
    connection: &Connection,
    invite: &MlsIncomingInvite,
    now_ms: u64,
) -> Result<bool, AslError> {
    connection
        .query_row(
            "SELECT EXISTS(
            SELECT 1 FROM mls_incoming_invites i
            LEFT JOIN mls_room_states s ON s.wire_group_id=i.wire_group_id
            LEFT JOIN asl_groups g ON g.group_id=s.local_group_id
            WHERE i.invite_id=?1 AND i.wire_group_id=?2 AND i.base_epoch=?3
              AND i.inviter_agent_id=?4 AND i.inviter_peer_id=?5 AND i.recipient_agent_id=?6
              AND i.recipient_peer_id=?7 AND i.expires_at_ms=?8 AND i.shown_at_ms<=?9 AND i.expires_at_ms>?9
              AND i.state<>'closed' AND (
                  s.wire_group_id IS NULL OR (
                      g.state='needs_sync' AND g.creator_peer_id=i.inviter_peer_id AND g.mls_epoch<i.base_epoch
                  )
              )
         )",
            params![
                invite.id.as_bytes(),
                invite.wire_id.as_bytes(),
                sql_number(invite.base_epoch)?,
                bs58::encode(invite.inviter.as_bytes()).into_string(),
                bs58::encode(invite.inviter_device.as_bytes()).into_string(),
                bs58::encode(invite.recipient.as_bytes()).into_string(),
                bs58::encode(invite.recipient_device.as_bytes()).into_string(),
                sql_number(invite.expires_at_ms)?,
                sql_number(now_ms)?,
            ],
            |r| r.get(0),
        )
        .map_err(database_error)
}

fn prune(tx: &Transaction<'_>, now: i64) -> Result<(), AslError> {
    tx.execute(
        "DELETE FROM mls_incoming_invites WHERE shown_at_ms<=?1",
        [now - AGENT_WINDOW_MS],
    )
    .map_err(database_error)?;
    tx.execute(
        "UPDATE mls_incoming_invites SET state='closed', sealed_package=NULL
         WHERE state<>'closed' AND expires_at_ms<=?1",
        [now],
    )
    .map_err(database_error)?;
    Ok(())
}
