use std::collections::BTreeSet;

use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId},
    protocol::MAX_GROUP_MEMBERS,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use super::{
    MAX_SEALED_ROOM_BYTES, MlsMemberEvidence, PendingMlsRoom, RoomVersion, insert_mls_room,
    recovery::require_member, sql_number,
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
        let inviter = bs58::encode(invite.inviter_device.as_bytes()).into_string();
        let tx = immediate(&mut self.connection)?;
        prune(&tx, now)?;
        let added = tx
            .execute(
                "INSERT INTO mls_incoming_invites
                    (invite_id,wire_group_id,base_epoch,inviter_agent_id,inviter_peer_id,
                     recipient_agent_id,recipient_peer_id,shown_at_ms,expires_at_ms)
                 SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9
                 WHERE NOT EXISTS (SELECT 1 FROM mls_room_states WHERE wire_group_id=?2)
                   AND NOT EXISTS (
                       SELECT 1 FROM mls_incoming_invites
                       WHERE inviter_agent_id=?4 AND shown_at_ms>?10
                   )
                   AND (SELECT count(*) FROM mls_incoming_invites WHERE shown_at_ms>?11) < ?12
                   AND (SELECT count(*) FROM mls_incoming_invites WHERE state<>'closed') < ?13
                 ON CONFLICT(invite_id) DO NOTHING",
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
                    now - AGENT_WINDOW_MS,
                    now - GLOBAL_WINDOW_MS,
                    MAX_HOURLY_INVITES,
                    MAX_OPEN_INVITES,
                ],
            )
            .map_err(database_error)?;
        tx.commit().map_err(database_error)?;
        Ok(added == 1)
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
        if key.request_id.0 == [0; 16]
            || key.request_id == invite.id
            || key.package_ref.0 == [0; 32]
            || !(1..=MAX_SEALED_ROOM_BYTES).contains(&sealed_package.len())
        {
            return Err(AslError::InvalidPolicyState);
        }
        let tx = immediate(&mut self.connection)?;
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
        let tx = immediate(&mut self.connection)?;
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
        let mut invites = Vec::new();
        {
            let mut stmt = tx.prepare(
                "SELECT invite_id,wire_group_id,base_epoch,inviter_agent_id,inviter_peer_id,expires_at_ms
                 FROM mls_incoming_invites AS i
                 WHERE recipient_agent_id=?1 AND recipient_peer_id=?2 AND state='approved'
                   AND shown_at_ms<=?3 AND NOT EXISTS (
                       SELECT 1 FROM mls_room_states AS s WHERE s.wire_group_id=i.wire_group_id
                   )
                 ORDER BY shown_at_ms,invite_id LIMIT ?4",
            ).map_err(database_error)?;
            let mut rows = stmt
                .query(params![
                    bs58::encode(recipient.as_bytes()).into_string(),
                    bs58::encode(device.as_bytes()).into_string(),
                    now,
                    MAX_OPEN_INVITES,
                ])
                .map_err(database_error)?;
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
        }
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
        tx.execute(
            "UPDATE mls_incoming_invites SET state='closed', sealed_package=NULL WHERE invite_id=?1",
            [invite.id.as_bytes()],
        ).map_err(database_error)?;
        tx.commit().map_err(database_error)?;
        Ok(true)
    }

    /// Install the Core-verified exact Welcome candidate and roster while
    /// consuming the approved package. The new room still cannot grant access.
    pub fn finish_mls_join(
        &mut self,
        join: MlsJoinedRoom<'_>,
        now_ms: u64,
    ) -> Result<RoomVersion, AslError> {
        let invite = join.invite;
        let roster = join.members;
        if join.room.wire_id != invite.wire_id
            || join.room.creator != &invite.inviter_device
            || invite.base_epoch.checked_add(1) != Some(join.room.mls_epoch)
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
        let revision = tx
            .query_row(
                "SELECT revision FROM policy_state WHERE singleton=1",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map_err(database_error)?;
        if revision != sql_number(join.expected_policy_revision)?
            || !matches_invite(&tx, invite, now_ms)?
        {
            return Err(AslError::PolicyVersionConflict);
        }
        for member in roster {
            require_member(&tx, member, join.chain_id, now_ms)?;
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
        let now = sql_number(now_ms)?;
        insert_mls_room(&tx, &join.room, now)?;
        tx.execute(
            "UPDATE mls_incoming_invites SET state='closed', sealed_package=NULL
             WHERE wire_group_id=?1 AND state<>'closed'",
            [invite.wire_id.as_bytes()],
        )
        .map_err(database_error)?;
        let local_id = hex::encode(join.room.local_id.0.as_bytes());
        {
            let mut stmt = tx
                .prepare(
                    "INSERT INTO group_members(group_id,peer_id,role,state,joined_at_ms)
                 VALUES (?1,?2,?3,'active',?4)",
                )
                .map_err(database_error)?;
            for member in roster {
                let device = &member.certificate.peer_id;
                let peer = bs58::encode(device.as_bytes()).into_string();
                let role = if device == &invite.inviter_device {
                    "creator"
                } else {
                    "member"
                };
                stmt.execute(params![local_id, peer, role, now])
                    .map_err(database_error)?;
            }
        }
        tx.commit().map_err(database_error)?;
        Ok(RoomVersion {
            revision: 1,
            mls_epoch: join.room.mls_epoch,
            membership_epoch: 1,
            policy_revision: join.expected_policy_revision,
        })
    }

    pub fn prune_mls_invites(&mut self, now_ms: u64) -> Result<(), AslError> {
        let tx = immediate(&mut self.connection)?;
        let now = sql_number(now_ms)?;
        prune(&tx, now)?;
        super::outgoing::prune(&tx, now)?;
        tx.commit().map_err(database_error)
    }
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

fn matches_invite(
    connection: &Connection,
    invite: &MlsIncomingInvite,
    now_ms: u64,
) -> Result<bool, AslError> {
    connection
        .query_row(
            "SELECT EXISTS(
            SELECT 1 FROM mls_incoming_invites
            WHERE invite_id=?1 AND wire_group_id=?2 AND base_epoch=?3
              AND inviter_agent_id=?4 AND inviter_peer_id=?5 AND recipient_agent_id=?6
              AND recipient_peer_id=?7 AND expires_at_ms=?8 AND shown_at_ms<=?9 AND expires_at_ms>?9
              AND state<>'closed'
              AND NOT EXISTS (SELECT 1 FROM mls_room_states WHERE wire_group_id=?2)
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
