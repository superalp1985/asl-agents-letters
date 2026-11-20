use std::io;

use asl_types::{
    error::AslError,
    ids::{AgentId, PeerId},
    protocol::DeviceCertificate,
};
use rusqlite::{Connection, ErrorCode, TransactionBehavior, params};

use crate::{Store, chain::agent_text, database_error, search::direct::DirectRequester};

pub(crate) struct DeviceRegistration<'a> {
    pub certificate: &'a DeviceCertificate,
    pub device_key: [u8; 32],
    pub chain_id: u64,
    pub registry_sequence: u64,
    pub controller: &'a [u8; 20],
    pub directory_commitment: &'a [u8; 32],
}

impl Store {
    pub(crate) fn has_registered_transfer_peer(
        &self,
        agent: AgentId,
        peer: &PeerId,
    ) -> Result<bool, AslError> {
        self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM peers p JOIN device_identities d USING(peer_id,agent_id)
             WHERE p.peer_id=?1 AND p.agent_id=?2 AND d.revoked_at_ms IS NULL)",
            params![bs58::encode(peer.as_bytes()).into_string(), agent_text(agent)],
            |row| row.get(0),
        ).map_err(database_error)
    }

    /// Core supplies the revalidated session, its signed certificate, and the Ed25519
    /// key recovered from its transport PeerId. A manifest cannot replace a device.
    pub fn register_transfer_peer(
        &mut self,
        source: &DirectRequester,
        chain_id: u64,
        certificate: &DeviceCertificate,
        device_key: [u8; 32],
        now_ms: u64,
    ) -> Result<(), AslError> {
        if certificate.agent_id != source.agent || certificate.peer_id != source.peer {
            return Err(AslError::InvalidDeviceCertificate);
        }
        if now_ms >= source.session_expires_at_ms {
            return Err(AslError::ExpiredMessage);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(registration_error)?;
        DeviceRegistration {
            certificate,
            device_key,
            chain_id,
            registry_sequence: source.registry_sequence,
            controller: &source.controller,
            directory_commitment: &source.directory_commitment,
        }
        .register(&tx, now_ms)?;
        tx.commit().map_err(registration_error)
    }
}

impl DeviceRegistration<'_> {
    pub(crate) fn register(&self, tx: &Connection, now_ms: u64) -> Result<(), AslError> {
        let certificate = self.certificate;
        if !(certificate.issued_at_ms..certificate.expires_at_ms).contains(&now_ms) {
            return Err(AslError::ExpiredMessage);
        }
        let integer = |n| i64::try_from(n).map_err(|_| AslError::InvalidDeviceCertificate);
        let agent = agent_text(certificate.agent_id);
        let peer = bs58::encode(certificate.peer_id.as_bytes()).into_string();
        let key = hex::encode(self.device_key);
        let cbor = certificate.to_canonical_cbor()?;
        let serial = integer(certificate.serial)?;
        let expires = integer(certificate.expires_at_ms)?;
        let now = integer(now_ms)?;
        let current: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM identity_registry_states r JOIN agents a USING(agent_id)
             WHERE r.agent_id=?1 AND r.chain_id=?2 AND r.status='active' AND r.sequence=?3
               AND r.controller_address=?4 AND r.state_commitment=?5
               AND a.identity_state IN ('pending_anchor','verified'))",
            params![agent, integer(self.chain_id)?, integer(self.registry_sequence)?,
                self.controller, self.directory_commitment],
            |r| r.get(0),
        ).map_err(registration_error)?;
        if !current {
            return Err(AslError::InvalidIdentity);
        }

        // Either unique key (PeerId or AgentId/serial) may already exist.
        // Only the exact, unrevoked device row can supply the foreign key.
        tx.execute(
            "INSERT INTO device_identities(peer_id,agent_id,public_key_hex,certificate_cbor,
                certificate_serial,certificate_expires_ms,created_at_ms)
             VALUES (?1,?2,?3,?4,?5,?6,?7) ON CONFLICT DO NOTHING",
            params![peer, agent, key, cbor, serial, expires, now],
        )
        .map_err(registration_error)?;
        let matched = tx.execute(
            "INSERT INTO peers(peer_id,agent_id,last_seen_ms)
             SELECT peer_id,agent_id,?7 FROM device_identities
             WHERE peer_id=?1 AND agent_id=?2 AND public_key_hex=?3 AND certificate_cbor=?4
               AND certificate_serial=?5 AND certificate_expires_ms=?6 AND revoked_at_ms IS NULL
             ON CONFLICT(peer_id) DO UPDATE SET last_seen_ms=max(peers.last_seen_ms,excluded.last_seen_ms)
             WHERE peers.agent_id=excluded.agent_id",
            params![peer, agent, key, cbor, serial, expires, now],
        ).map_err(registration_error)?;
        if matched != 1 {
            return Err(AslError::InvalidDeviceCertificate);
        }
        Ok(())
    }
}

fn registration_error(error: rusqlite::Error) -> AslError {
    if error
        .sqlite_error_code()
        .is_some_and(|code| matches!(code, ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked))
    {
        return io::Error::from(io::ErrorKind::WouldBlock).into();
    }
    database_error(error)
}
