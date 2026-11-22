use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, PeerId},
    protocol::{DeviceCertificate, MAX_GROUP_MEMBERS},
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use super::{
    MlsRoomSnapshot, RoomVersion, read_mls_room_snapshot, sql_number,
    sync_authority::{member_ids, room_version},
    transition::peer_text,
};
use crate::{
    Store,
    chain::{agent_text, decode_agent_text},
    database_error,
    transfer_peers::DeviceRegistration,
};

pub struct MlsRoomRecovery {
    pub snapshot: MlsRoomSnapshot,
    pub creator: PeerId,
    pub members: Vec<PeerId>,
}

pub struct MlsRoomActivation<'a> {
    pub wire_id: Hash32,
    pub expected: RoomVersion,
    pub creator: &'a PeerId,
    pub creator_device: &'a PeerId,
    pub members: &'a [MlsMemberEvidence],
    pub chain_id: u64,
    pub now_ms: u64,
}

/// Core-verified chain and device facts. SQLite compares them to current
/// persisted authority; it does not validate the underlying signatures.
pub struct MlsMemberEvidence {
    pub certificate: DeviceCertificate,
    pub device_key: [u8; 32],
    pub registry_sequence: u64,
    pub controller: [u8; 20],
    pub directory_commitment: Hash32,
}

impl MlsMemberEvidence {
    pub(super) fn register(
        &self,
        tx: &Transaction<'_>,
        chain_id: u64,
        now_ms: u64,
    ) -> Result<(), AslError> {
        DeviceRegistration {
            certificate: &self.certificate,
            device_key: self.device_key,
            chain_id,
            registry_sequence: self.registry_sequence,
            controller: &self.controller,
            directory_commitment: self.directory_commitment.as_bytes(),
        }
        .register(tx, now_ms)
        .map_err(|error| match error {
            AslError::InvalidIdentity => AslError::InvalidDeviceCertificate,
            error => error,
        })
    }
}

impl Store {
    /// Read a known room and its active device projection from one SQLite
    /// snapshot. Callers still establish freshness before any authorization.
    pub fn mls_room_for_reconciliation(
        &self,
        wire_id: Hash32,
    ) -> Result<Option<MlsRoomRecovery>, AslError> {
        let tx = self
            .connection
            .unchecked_transaction()
            .map_err(database_error)?;
        let room = match read_mls_room_snapshot(&tx, wire_id, false)? {
            Some((snapshot, creator)) => {
                let creator = parse_peer(&creator)?;
                let members = active_members(&tx, wire_id, &creator)?;
                Some(MlsRoomRecovery {
                    snapshot,
                    creator,
                    members,
                })
            }
            None => None,
        };
        tx.commit().map_err(database_error)?;
        Ok(room)
    }

    pub fn require_mls_member(
        &self,
        member: &MlsMemberEvidence,
        chain_id: u64,
        now_ms: u64,
    ) -> Result<(), AslError> {
        require_member(&self.connection, member, chain_id, now_ms)
    }

    /// Open a reconciled room only from the creator device's live head.
    /// Membership changes close the room again by advancing its member epoch.
    pub fn activate_mls_room_at_creator_head(
        &mut self,
        activation: MlsRoomActivation<'_>,
    ) -> Result<RoomVersion, AslError> {
        if activation.creator_device != activation.creator {
            return Err(AslError::PolicyDenied);
        }
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(database_error)?;
        if room_version(&tx, activation.wire_id, activation.creator)? != activation.expected {
            return Err(AslError::PolicyVersionConflict);
        }
        let projection = active_members(&tx, activation.wire_id, activation.creator)?;
        if member_ids(activation.members)? != projection.iter().map(peer_text).collect() {
            return Err(AslError::PolicyVersionConflict);
        }
        for member in activation.members {
            require_member(&tx, member, activation.chain_id, activation.now_ms)?;
        }
        let local_id: String = tx
            .query_row(
                "SELECT local_group_id FROM mls_room_states WHERE wire_group_id=?1",
                [activation.wire_id.as_bytes()],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        let updated = tx
            .execute(
                "UPDATE asl_groups SET state='active',updated_at_ms=?4
                 WHERE group_id=?1 AND state='needs_sync' AND creator_peer_id=?2
                   AND mls_epoch=?3 AND membership_epoch=?5",
                params![
                    local_id,
                    peer_text(activation.creator),
                    sql_number(activation.expected.mls_epoch)?,
                    sql_number(activation.now_ms)?,
                    sql_number(activation.expected.membership_epoch)?,
                ],
            )
            .map_err(database_error)?;
        if updated != 1 {
            return Err(AslError::PolicyVersionConflict);
        }
        tx.commit().map_err(database_error)?;
        Ok(activation.expected)
    }

    /// Maps an MLS device leaf back to its stable AgentId for local group
    /// conversation budgets. MLS admission already verified the leaf itself.
    pub fn mls_peer_agent(&self, peer: &PeerId) -> Result<Option<AgentId>, AslError> {
        let value: Option<String> = self
            .connection
            .query_row(
                "SELECT d.agent_id FROM device_identities d
                 JOIN peers p USING(peer_id,agent_id)
                 JOIN agents a USING(agent_id)
                 WHERE d.peer_id=?1 AND d.revoked_at_ms IS NULL
                   AND a.identity_state IN ('pending_anchor','verified')",
                [peer_text(peer)],
                |row| row.get(0),
            )
            .optional()
            .map_err(database_error)?;
        value.map(|text| decode_agent_text(&text)).transpose()
    }
}

pub(super) fn require_member(
    db: &Connection,
    member: &MlsMemberEvidence,
    chain_id: u64,
    now_ms: u64,
) -> Result<(), AslError> {
    let cert = &member.certificate;
    if !(cert.issued_at_ms..cert.expires_at_ms).contains(&now_ms) {
        return Err(AslError::InvalidDeviceCertificate);
    }
    let integer = |n| i64::try_from(n).map_err(|_| AslError::InvalidDeviceCertificate);
    let matches: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM device_identities d JOIN peers p USING(peer_id,agent_id)
             JOIN identity_registry_states r USING(agent_id) JOIN agents a USING(agent_id)
             WHERE d.peer_id=?1 AND d.agent_id=?2 AND d.revoked_at_ms IS NULL
               AND d.certificate_serial=?3 AND d.certificate_expires_ms=?4 AND d.certificate_cbor=?5
               AND r.chain_id=?6 AND r.sequence=?7 AND r.controller_address=?8
               AND r.state_commitment=?9 AND r.status='active'
               AND a.identity_state IN ('pending_anchor','verified'))",
            params![
                peer_text(&cert.peer_id),
                agent_text(cert.agent_id),
                integer(cert.serial)?,
                integer(cert.expires_at_ms)?,
                cert.to_canonical_cbor()?,
                integer(chain_id)?,
                integer(member.registry_sequence)?,
                &member.controller,
                member.directory_commitment.as_bytes(),
            ],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    if !matches {
        return Err(AslError::InvalidDeviceCertificate);
    }
    Ok(())
}

pub(super) fn active_members(
    tx: &Transaction<'_>,
    wire_id: Hash32,
    creator: &PeerId,
) -> Result<Vec<PeerId>, AslError> {
    let mut stmt = tx
        .prepare_cached(
            "SELECT m.peer_id,m.role FROM mls_room_states s
             JOIN group_members m ON m.group_id=s.local_group_id
             WHERE s.wire_group_id=?1 AND m.state='active' ORDER BY m.peer_id LIMIT ?2",
        )
        .map_err(database_error)?;
    let mut rows = stmt
        .query(params![wire_id.as_bytes(), (MAX_GROUP_MEMBERS + 1) as i64])
        .map_err(database_error)?;
    let mut members = Vec::new();
    let mut found_creator = false;
    while let Some(row) = rows.next().map_err(database_error)? {
        if members.len() == MAX_GROUP_MEMBERS {
            return Err(AslError::InvalidDatabase);
        }
        let peer_text: String = row.get(0).map_err(database_error)?;
        let peer = parse_peer(&peer_text)?;
        let role: String = row.get(1).map_err(database_error)?;
        match (role.as_str(), &peer == creator) {
            ("creator", true) if !found_creator => found_creator = true,
            ("member", false) => {}
            _ => return Err(AslError::InvalidDatabase),
        }
        members.push(peer);
    }
    if !found_creator {
        return Err(AslError::InvalidDatabase);
    }
    Ok(members)
}

fn parse_peer(text: &str) -> Result<PeerId, AslError> {
    let bytes = bs58::decode(text)
        .into_vec()
        .map_err(|_| AslError::InvalidDatabase)?;
    PeerId::from_bytes(bytes).map_err(|_| AslError::InvalidDatabase)
}
