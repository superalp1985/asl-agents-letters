use asl_types::{
    error::AslError,
    ids::{Hash32, PeerId},
    protocol::{DeviceCertificate, MAX_GROUP_MEMBERS},
};
use rusqlite::{Connection, Transaction, params};

use super::{MlsRoomSnapshot, read_mls_room_snapshot, transition::peer_text};
use crate::{Store, chain::agent_text, database_error};

pub struct MlsRoomRecovery {
    pub snapshot: MlsRoomSnapshot,
    pub creator: PeerId,
    pub members: Vec<PeerId>,
}

/// Core-verified chain and device facts. SQLite compares them to current
/// persisted authority; it does not validate the underlying signatures.
pub struct MlsMemberEvidence {
    pub certificate: DeviceCertificate,
    pub registry_sequence: u64,
    pub controller: [u8; 20],
    pub directory_commitment: Hash32,
}

impl Store {
    /// Read a paused room and its active device projection from one SQLite snapshot.
    /// Missing or non-paused rooms return `None`; a room without a consistent
    /// projection cannot be reconciled. This does not activate the room.
    pub fn mls_room_for_reconciliation(
        &self,
        wire_id: Hash32,
    ) -> Result<Option<MlsRoomRecovery>, AslError> {
        let tx = self
            .connection
            .unchecked_transaction()
            .map_err(database_error)?;
        let room = match read_mls_room_snapshot(&tx, wire_id, true)? {
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

fn active_members(
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
