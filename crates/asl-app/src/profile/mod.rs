mod admission;
mod history;
mod proof_response;
mod publisher;
mod session;

use asl_types::{
    error::AslError,
    ids::AgentId,
    record::{
        RecordPayload, SignedRecord, UnsignedRecord, decode_record, device_directory_commitment,
        encode_record, record_signing_bytes,
    },
};

use crate::{
    chain::{IdentityResolution, IdentityResolver, RegistryStateV1, RegistryStatus},
    identity::{AgentIdentity, verify_device_certificate, verify_root_signature},
};

pub use admission::{AdmissionBatch, AdmittedNetworkEvent, CoreAdmission};
pub use history::RecordHistory;
pub use proof_response::serve_local_identity_proof;
pub use publisher::{AvatarReference, ProfileConfiguration, ProfilePublisher};
pub use session::{DeviceAdmissionError, DeviceSession};

/// Verified for this call's local resolver state. A cached value does not
/// replace resolving fresh state again when a network connection is admitted.
#[derive(Clone, Debug)]
pub struct VerifiedRecord {
    signed: SignedRecord,
    bytes: Vec<u8>,
    registry_state: RegistryStateV1,
}

impl VerifiedRecord {
    pub fn signed(&self) -> &SignedRecord {
        &self.signed
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn registry_sequence(&self) -> u64 {
        self.registry_state.sequence
    }
}

pub fn sign_record(
    identity: &AgentIdentity,
    payload: RecordPayload,
    sequence: u64,
    issued_at_ms: u64,
    lifetime_ms: u64,
) -> Result<Vec<u8>, AslError> {
    if payload.agent_id() != identity.agent_id() || lifetime_ms == 0 {
        return Err(AslError::InvalidIdentity);
    }
    let record = UnsignedRecord {
        payload,
        sequence,
        issued_at_ms,
        expires_at_ms: issued_at_ms
            .checked_add(lifetime_ms)
            .ok_or(AslError::InvalidMessage)?,
    };
    let message = record_signing_bytes(&record)?;
    let signature = identity.sign_domain_message(&message)?;
    encode_record(&SignedRecord { record, signature })
}

pub fn verify_record(
    bytes: &[u8],
    expected_agent: AgentId,
    now_ms: u64,
    resolver: &mut dyn IdentityResolver,
) -> Result<VerifiedRecord, AslError> {
    let signed = decode_record(bytes)?;
    let record = &signed.record;
    if record.payload.agent_id() != expected_agent {
        return Err(AslError::InvalidIdentity);
    }
    if now_ms < record.issued_at_ms || now_ms >= record.expires_at_ms {
        return Err(AslError::ExpiredMessage);
    }
    let state = resolve_active(expected_agent, now_ms, resolver)?;
    verify_root_signature(
        &record_signing_bytes(record)?,
        signed.signature,
        state.controller,
    )?;
    if let RecordPayload::DeviceDirectory(directory) = &record.payload {
        if directory.registry_sequence != state.sequence
            || device_directory_commitment(directory)?.0 != state.state_commitment
        {
            return Err(AslError::InvalidIdentity);
        }
        for certificate in &directory.devices {
            verify_device_certificate(
                certificate,
                expected_agent,
                &certificate.peer_id,
                state.controller,
                1,
                now_ms,
            )?;
        }
    }
    Ok(VerifiedRecord {
        signed,
        bytes: bytes.to_vec(),
        registry_state: state,
    })
}

fn resolve_active(
    agent: AgentId,
    now_ms: u64,
    resolver: &mut dyn IdentityResolver,
) -> Result<RegistryStateV1, AslError> {
    if resolver.interface_version() != 1 {
        return Err(AslError::InvalidIdentity);
    }
    match resolver.resolve(agent, now_ms / 1_000) {
        IdentityResolution::Verified(identity)
            if identity.agent_id() == agent
                && identity.state().status == RegistryStatus::Active =>
        {
            Ok(identity.state())
        }
        _ => Err(AslError::InvalidIdentity),
    }
}

#[cfg(test)]
mod tests;
