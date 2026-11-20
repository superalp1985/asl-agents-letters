use std::collections::BTreeSet;

use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId},
    protocol::{GroupBody, GroupMembership, GroupPacket, MAX_GROUP_MEMBERS},
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use super::{
    MlsJournalKind, MlsMemberEvidence, MlsRoomUpdate, RoomVersion,
    invite::INVITE_TTL_MS,
    recovery::require_member,
    sql_number,
    transition::{commit_candidate, peer_text},
};
use crate::{Store, database_error};

const MAX_OUTGOING_INVITES: i64 = 64;
const MAX_CONSUMED_KEY_PACKAGES: i64 = 4_096;

/// Core supplies its current local device, the admitted connection identity,
/// and the reference computed from the verified KeyPackage.
pub struct MlsWelcomeRequest<'a> {
    pub local_creator: &'a PeerId,
    pub recipient: AgentId,
    pub device: &'a PeerId,
    pub packet: &'a GroupPacket,
    pub package_ref: Hash32,
    /// `KeyPackage::life_time().not_after()` converted to milliseconds.
    pub package_expires_at_ms: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub enum MlsInviteResponse {
    Pending,
    Committed(GroupPacket),
}

impl Store {
    /// Persist the exact Invite before sending. Core must independently verify
    /// creator authority and the target's current chain and connection evidence.
    pub fn issue_mls_invite(
        &mut self,
        creator: &PeerId,
        packet: &GroupPacket,
        now_ms: u64,
    ) -> Result<(), AslError> {
        self.issue_mls_invite_inner(creator, packet, None, now_ms)
            .map(|_| ())
    }

    /// Persist an Invite only while Core's room version and supplied member
    /// evidence still match storage, including the creator and exact target.
    /// An explicit retry returns the original unexpired Invite without
    /// extending its lifetime or replacing its ID.
    pub fn issue_verified_mls_invite(
        &mut self,
        creator: &PeerId,
        packet: &GroupPacket,
        expected: RoomVersion,
        members: &[MlsMemberEvidence],
        chain_id: u64,
        now_ms: u64,
    ) -> Result<GroupPacket, AslError> {
        self.issue_mls_invite_inner(
            creator,
            packet,
            Some((expected, VerifiedInviteMembers { members, chain_id })),
            now_ms,
        )
    }

    fn issue_mls_invite_inner(
        &mut self,
        creator: &PeerId,
        packet: &GroupPacket,
        verified: Option<(RoomVersion, VerifiedInviteMembers<'_>)>,
        now_ms: u64,
    ) -> Result<GroupPacket, AslError> {
        packet.validate_request()?;
        let GroupBody::Membership(GroupMembership::Invite {
            agent,
            device,
            expires_at_ms,
        }) = &packet.body
        else {
            return Err(AslError::InvalidMessage);
        };
        if device == creator
            || !matches!(expires_at_ms.checked_sub(now_ms), Some(1..=INVITE_TTL_MS))
        {
            return Err(AslError::InvalidMessage);
        }
        let now = sql_number(now_ms)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        if let Some((expected, members)) = &verified {
            if packet.epoch != expected.mls_epoch {
                return Err(AslError::PolicyVersionConflict);
            }
            require_room_version(&tx, packet.group_id, *expected)?;
            let target = members
                .members
                .iter()
                .find(|member| {
                    member.certificate.agent_id == *agent && &member.certificate.peer_id == device
                })
                .ok_or(AslError::InvalidDeviceCertificate)?;
            target.register(&tx, members.chain_id, now_ms)?;
            members.require(&tx, creator, (*agent, device), None, now_ms)?;
        }
        prune(&tx, now)?;
        if verified.is_some() {
            let original: Option<(Vec<u8>, i64)> = tx
                .query_row(
                    "SELECT i.invite_id,i.expires_at_ms FROM mls_outgoing_invites i
                     JOIN mls_room_states s ON s.wire_group_id=i.wire_group_id
                     JOIN asl_groups g ON g.group_id=s.local_group_id
                       AND g.creator_peer_id=i.creator_peer_id
                     JOIN group_members c ON c.group_id=g.group_id AND c.peer_id=i.creator_peer_id
                     WHERE i.wire_group_id=?1 AND i.base_epoch=?2 AND i.creator_peer_id=?3
                       AND i.recipient_agent_id=?4 AND i.recipient_peer_id=?5
                       AND i.created_at_ms<=?6 AND i.expires_at_ms>?6
                       AND i.request_id IS NULL AND c.role='creator' AND c.state='active'
                       AND NOT EXISTS (SELECT 1 FROM group_members m
                         WHERE m.group_id=g.group_id AND m.peer_id=i.recipient_peer_id
                           AND m.state='active')",
                    params![
                        packet.group_id.as_bytes(),
                        sql_number(packet.epoch)?,
                        peer_text(creator),
                        agent_text(*agent),
                        peer_text(device),
                        now,
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(database_error)?;
            if let Some((id, expiry)) = original {
                let original = GroupPacket {
                    message_id: Id128(id.try_into().map_err(|_| AslError::InvalidDatabase)?),
                    body: GroupBody::Membership(GroupMembership::Invite {
                        agent: *agent,
                        device: device.clone(),
                        expires_at_ms: u64::try_from(expiry)
                            .map_err(|_| AslError::InvalidDatabase)?,
                    }),
                    ..packet.clone()
                };
                original.validate_request()?;
                tx.commit().map_err(database_error)?;
                return Ok(original);
            }
        }
        let inserted = tx
            .execute(
                "INSERT INTO mls_outgoing_invites
                (invite_id,wire_group_id,base_epoch,creator_peer_id,recipient_agent_id,
                 recipient_peer_id,created_at_ms,expires_at_ms)
             SELECT ?1,?2,?3,?4,?5,?6,?7,?8
             FROM mls_room_states s JOIN asl_groups g ON g.group_id=s.local_group_id
             JOIN group_members c ON c.group_id=g.group_id AND c.peer_id=g.creator_peer_id
             JOIN peers p ON p.peer_id=?6 AND p.agent_id=?5
             JOIN device_identities d ON d.peer_id=p.peer_id AND d.agent_id=p.agent_id
             JOIN device_identities own ON own.peer_id=g.creator_peer_id
             WHERE s.wire_group_id=?2 AND g.mls_epoch=?3 AND g.creator_peer_id=?4
               AND g.state='needs_sync' AND c.role='creator' AND c.state='active'
               AND d.revoked_at_ms IS NULL AND d.certificate_expires_ms>?7
               AND own.revoked_at_ms IS NULL AND own.certificate_expires_ms>?7
               AND NOT EXISTS (SELECT 1 FROM group_members
                   WHERE group_id=g.group_id AND peer_id=?6 AND state='active')
               AND (SELECT count(*) FROM mls_outgoing_invites) < ?9
             ON CONFLICT DO NOTHING",
                params![
                    packet.message_id.as_bytes(),
                    packet.group_id.as_bytes(),
                    sql_number(packet.epoch)?,
                    peer_text(creator),
                    agent_text(*agent),
                    peer_text(device),
                    now,
                    sql_number(*expires_at_ms)?,
                    MAX_OUTGOING_INVITES,
                ],
            )
            .map_err(database_error)?;
        if inserted != 1 {
            return Err(AslError::PolicyVersionConflict);
        }
        tx.commit().map_err(database_error)?;
        Ok(packet.clone())
    }

    /// A retry never constructs a second Welcome or applies a second Add.
    /// Core must recheck live chain and local policy before sending anything.
    pub fn mls_invite_response(
        &self,
        request: &MlsWelcomeRequest<'_>,
        now_ms: u64,
    ) -> Result<Option<MlsInviteResponse>, AslError> {
        let invite = request.invite_id()?;
        if request.package_expires_at_ms <= now_ms {
            return Ok(None);
        }
        match lookup(&self.connection, request, invite, sql_number(now_ms)?)? {
            Some(StoredInvite::Pending) => Ok(Some(MlsInviteResponse::Pending)),
            Some(StoredInvite::Committed(welcome)) => Ok(Some(MlsInviteResponse::Committed(
                request.welcome(invite, welcome)?,
            ))),
            None => Ok(None),
        }
    }

    /// Re-read a committed reply and its current room/device evidence from
    /// the same SQLite snapshot. No plaintext is recovered or room activated.
    pub fn replay_verified_mls_welcome(
        &self,
        request: &MlsWelcomeRequest<'_>,
        expected: RoomVersion,
        members: &[MlsMemberEvidence],
        chain_id: u64,
        now_ms: u64,
    ) -> Result<GroupPacket, AslError> {
        let invite = request.invite_id()?;
        if request.package_expires_at_ms <= now_ms {
            return Err(AslError::ExpiredMessage);
        }
        let tx = self
            .connection
            .unchecked_transaction()
            .map_err(database_error)?;
        require_room_version(&tx, request.packet.group_id, expected)?;
        VerifiedInviteMembers { members, chain_id }.require(
            &tx,
            request.local_creator,
            (request.recipient, request.device),
            None,
            now_ms,
        )?;
        let Some(StoredInvite::Committed(welcome)) =
            lookup(&tx, request, invite, sql_number(now_ms)?)?
        else {
            return Err(AslError::PolicyVersionConflict);
        };
        let reply = request.welcome(invite, welcome)?;
        tx.commit().map_err(database_error)?;
        Ok(reply)
    }

    /// Seal the already validated Add, its journal event and the exact
    /// Welcome in one transaction. Callers must discard failed candidates.
    pub fn commit_mls_invite_welcome(
        &mut self,
        request: &MlsWelcomeRequest<'_>,
        update: MlsRoomUpdate<'_>,
        welcome: Vec<u8>,
        now_ms: u64,
    ) -> Result<RoomVersion, AslError> {
        self.commit_mls_invite_welcome_inner(request, update, welcome, None, now_ms)
    }

    /// Recheck the full Core-verified Add roster against storage before
    /// atomically saving the Commit and Welcome. The room stays paused.
    pub fn commit_verified_mls_invite_welcome(
        &mut self,
        request: &MlsWelcomeRequest<'_>,
        update: MlsRoomUpdate<'_>,
        welcome: Vec<u8>,
        members: &[MlsMemberEvidence],
        chain_id: u64,
        now_ms: u64,
    ) -> Result<RoomVersion, AslError> {
        self.commit_mls_invite_welcome_inner(
            request,
            update,
            welcome,
            Some(VerifiedInviteMembers { members, chain_id }),
            now_ms,
        )
    }

    fn commit_mls_invite_welcome_inner(
        &mut self,
        request: &MlsWelcomeRequest<'_>,
        update: MlsRoomUpdate<'_>,
        welcome: Vec<u8>,
        verified: Option<VerifiedInviteMembers<'_>>,
        now_ms: u64,
    ) -> Result<RoomVersion, AslError> {
        let invite = request.invite_id()?;
        if request.package_expires_at_ms <= now_ms {
            return Err(AslError::ExpiredMessage);
        }
        let reply = request.welcome(invite, welcome)?;
        let GroupBody::Membership(GroupMembership::Welcome { message, .. }) = &reply.body else {
            unreachable!("constructed as a Welcome");
        };
        let event = update.event.as_ref().ok_or(AslError::InvalidPolicyState)?;
        if !matches!(
            event.kind,
            MlsJournalKind::Commit | MlsJournalKind::SyncCommit(_)
        ) || update.wire_id != reply.group_id
            || update.expected.mls_epoch != request.packet.epoch
            || update.mls_epoch != reply.epoch
        {
            return Err(AslError::InvalidPolicyState);
        }
        let now = sql_number(now_ms)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let Some(StoredInvite::Pending) = lookup(&tx, request, invite, now)? else {
            return Err(AslError::PolicyVersionConflict);
        };
        if request.local_creator != event.sender {
            return Err(AslError::InvalidPolicyState);
        }
        if let Some(members) = verified {
            members.require(
                &tx,
                request.local_creator,
                (request.recipient, request.device),
                Some(update.members),
                now_ms,
            )?;
        }
        let version = commit_candidate(&tx, update, Some(request.device), now)?;
        let consumed = tx
            .execute(
                "INSERT INTO mls_consumed_key_packages(package_ref,expires_at_ms)
             SELECT ?1,?2
             WHERE (SELECT count(*) FROM mls_consumed_key_packages WHERE expires_at_ms>?3) < ?4
             ON CONFLICT DO NOTHING",
                params![
                    request.package_ref.as_bytes(),
                    sql_number(request.package_expires_at_ms)?,
                    now,
                    MAX_CONSUMED_KEY_PACKAGES,
                ],
            )
            .map_err(database_error)?;
        if consumed != 1 {
            return Err(AslError::PolicyVersionConflict);
        }
        tx.execute(
            "UPDATE mls_outgoing_invites SET request_id=?2,package_ref=?3,welcome=?4 WHERE invite_id=?1",
            params![
                invite.as_bytes(), request.packet.message_id.as_bytes(),
                request.package_ref.as_bytes(), message,
            ],
        )
        .map_err(database_error)?;
        tx.commit().map_err(database_error)?;
        Ok(version)
    }
}

struct VerifiedInviteMembers<'a> {
    members: &'a [MlsMemberEvidence],
    chain_id: u64,
}

impl VerifiedInviteMembers<'_> {
    fn require(
        &self,
        tx: &Transaction<'_>,
        creator: &PeerId,
        (agent, device): (AgentId, &PeerId),
        projection: Option<&[PeerId]>,
        now_ms: u64,
    ) -> Result<(), AslError> {
        if self.members.len() > MAX_GROUP_MEMBERS {
            return Err(AslError::InvalidPolicyState);
        }
        let peers: BTreeSet<_> = self
            .members
            .iter()
            .map(|member| member.certificate.peer_id.as_bytes())
            .collect();
        if peers.len() != self.members.len()
            || !peers.contains(creator.as_bytes())
            || !self.members.iter().any(|member| {
                member.certificate.agent_id == agent && &member.certificate.peer_id == device
            })
            || projection.is_some_and(|projection| {
                projection.len() != peers.len()
                    || projection
                        .iter()
                        .map(PeerId::as_bytes)
                        .collect::<BTreeSet<_>>()
                        != peers
            })
        {
            return Err(AslError::InvalidPolicyState);
        }
        for member in self.members {
            require_member(tx, member, self.chain_id, now_ms)?;
        }
        Ok(())
    }
}

fn require_room_version(
    tx: &Transaction<'_>,
    wire_id: Hash32,
    expected: RoomVersion,
) -> Result<(), AslError> {
    let matches: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM mls_room_states s
             JOIN asl_groups g ON g.group_id=s.local_group_id CROSS JOIN policy_state p
             WHERE s.wire_group_id=?1 AND g.state='needs_sync' AND p.singleton=1
               AND s.revision=?2 AND g.mls_epoch=?3 AND g.membership_epoch=?4 AND p.revision=?5)",
            params![
                wire_id.as_bytes(),
                sql_number(expected.revision)?,
                sql_number(expected.mls_epoch)?,
                sql_number(expected.membership_epoch)?,
                sql_number(expected.policy_revision)?,
            ],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    if !matches {
        return Err(AslError::PolicyVersionConflict);
    }
    Ok(())
}

impl MlsWelcomeRequest<'_> {
    fn invite_id(&self) -> Result<Id128, AslError> {
        self.packet.validate_request()?;
        match self.packet.body {
            GroupBody::Membership(GroupMembership::KeyPackage { invite, .. })
                if invite != self.packet.message_id && self.package_ref.0 != [0; 32] =>
            {
                Ok(invite)
            }
            _ => Err(AslError::InvalidMessage),
        }
    }

    fn welcome(&self, invite: Id128, message: Vec<u8>) -> Result<GroupPacket, AslError> {
        let reply = GroupPacket {
            message_id: self.packet.message_id,
            group_id: self.packet.group_id,
            epoch: self.packet.epoch + 1,
            body: GroupBody::Membership(GroupMembership::Welcome {
                invite,
                package_ref: self.package_ref,
                message,
            }),
        };
        self.packet.match_reply(&reply)?;
        Ok(reply)
    }
}

enum StoredInvite {
    Pending,
    Committed(Vec<u8>),
}

fn lookup(
    connection: &Connection,
    request: &MlsWelcomeRequest<'_>,
    invite: Id128,
    now: i64,
) -> Result<Option<StoredInvite>, AslError> {
    connection.query_row(
        "SELECT i.welcome FROM mls_outgoing_invites i
         JOIN mls_room_states s ON s.wire_group_id=i.wire_group_id
         JOIN asl_groups g ON g.group_id=s.local_group_id AND g.creator_peer_id=i.creator_peer_id
         JOIN group_members c ON c.group_id=g.group_id AND c.peer_id=i.creator_peer_id
         JOIN device_identities d ON d.peer_id=i.recipient_peer_id AND d.agent_id=i.recipient_agent_id
         JOIN device_identities own ON own.peer_id=i.creator_peer_id
         LEFT JOIN group_members m ON m.group_id=g.group_id AND m.peer_id=i.recipient_peer_id AND m.state='active'
         WHERE i.invite_id=?1 AND i.wire_group_id=?2 AND i.base_epoch=?3
           AND i.recipient_agent_id=?4 AND i.recipient_peer_id=?5 AND i.creator_peer_id=?9
           AND i.created_at_ms<=?6 AND i.expires_at_ms>?6
           AND g.state='needs_sync' AND c.role='creator' AND c.state='active'
           AND d.revoked_at_ms IS NULL AND d.certificate_expires_ms>?6
           AND own.revoked_at_ms IS NULL AND own.certificate_expires_ms>?6
           AND ((i.request_id IS NULL AND m.peer_id IS NULL AND g.mls_epoch=i.base_epoch
                 AND NOT EXISTS (SELECT 1 FROM mls_consumed_key_packages p WHERE p.package_ref=?8))
             OR (i.request_id=?7 AND i.package_ref=?8 AND i.welcome IS NOT NULL
                 AND EXISTS (SELECT 1 FROM mls_consumed_key_packages p
                     WHERE p.package_ref=?8 AND p.expires_at_ms=?10)
                 AND m.peer_id IS NOT NULL AND g.mls_epoch>i.base_epoch))",
        params![
            invite.as_bytes(), request.packet.group_id.as_bytes(), sql_number(request.packet.epoch)?,
            agent_text(request.recipient), peer_text(request.device), now,
            request.packet.message_id.as_bytes(), request.package_ref.as_bytes(),
            peer_text(request.local_creator), sql_number(request.package_expires_at_ms)?,
        ],
        |row| match row.get::<_, Option<Vec<u8>>>(0)? {
            Some(welcome) => Ok(StoredInvite::Committed(welcome)),
            None => Ok(StoredInvite::Pending),
        },
    ).optional().map_err(database_error)
}

pub(super) fn prune(connection: &Connection, now: i64) -> Result<(), AslError> {
    connection
        .execute(
            "DELETE FROM mls_outgoing_invites AS i WHERE expires_at_ms<=?1
               OR (request_id IS NULL AND EXISTS (
                   SELECT 1 FROM mls_room_states s JOIN asl_groups g ON g.group_id=s.local_group_id
                   WHERE s.wire_group_id=i.wire_group_id AND g.mls_epoch<>i.base_epoch
               ))",
            [now],
        )
        .map_err(database_error)?;
    connection
        .execute(
            "DELETE FROM mls_consumed_key_packages WHERE expires_at_ms<=?1",
            [now],
        )
        .map_err(database_error)?;
    Ok(())
}

fn agent_text(agent: AgentId) -> String {
    bs58::encode(agent.as_bytes()).into_string()
}
