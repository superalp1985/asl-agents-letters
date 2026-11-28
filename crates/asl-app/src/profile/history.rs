use std::collections::{HashMap, HashSet};

use asl_types::{
    error::AslError,
    ids::{AgentId, PeerId},
    protocol::DeviceCertificate,
    record::{RecordKind, RecordPayload},
};

use crate::chain::IdentityResolver;

use super::{VerifiedRecord, verify_record};

#[derive(Clone)]
struct ObservedRecord {
    sequence: u64,
    hash: blake3::Hash,
    policy_revoked: Option<bool>,
}

/// One owner's bounded, in-memory observations. The DHT/store adapter must
/// retain these watermarks durably rather than clearing them on record expiry.
#[derive(Clone)]
pub struct RecordHistory {
    agent_id: AgentId,
    records: HashMap<RecordKind, ObservedRecord>,
    device_serials: HashMap<u64, Option<PeerId>>,
    latest_devices: HashMap<PeerId, DeviceCertificate>,
    revoked: HashSet<u64>,
    observation_limit: usize,
}

impl RecordHistory {
    pub fn new(agent_id: AgentId, observation_limit: usize) -> Result<Self, AslError> {
        if !(1..=4_096).contains(&observation_limit) {
            return Err(AslError::InvalidPolicyState);
        }
        Ok(Self {
            agent_id,
            records: HashMap::new(),
            device_serials: HashMap::new(),
            latest_devices: HashMap::new(),
            revoked: HashSet::new(),
            observation_limit,
        })
    }

    pub fn accept(
        &mut self,
        bytes: &[u8],
        now_ms: u64,
        resolver: &mut dyn IdentityResolver,
    ) -> Result<VerifiedRecord, AslError> {
        let verified = verify_record(bytes, self.agent_id, now_ms, resolver)?;
        self.observe(&verified)?;
        Ok(verified)
    }

    pub(super) fn observe(&mut self, verified: &VerifiedRecord) -> Result<(), AslError> {
        let record = &verified.signed.record;
        if record.payload.agent_id() != self.agent_id {
            return Err(AslError::InvalidIdentity);
        }
        let kind = record.payload.kind();
        let hash = blake3::hash(verified.bytes());
        if let Some(previous) = self.records.get(&kind) {
            if record.sequence < previous.sequence {
                return Err(AslError::PolicyVersionConflict);
            }
            if record.sequence == previous.sequence && hash != previous.hash {
                let contact_policy_tie_break = match &record.payload {
                    RecordPayload::ContactPolicy(candidate) => {
                        match (candidate.revoked, previous.policy_revoked) {
                            (true, Some(false)) => true,
                            (false, Some(true)) => false,
                            _ => hash.as_bytes() < previous.hash.as_bytes(),
                        }
                    }
                    _ => false,
                };
                if !contact_policy_tie_break {
                    return Err(AslError::PolicyVersionConflict);
                }
            }
        }

        if let RecordPayload::DeviceDirectory(directory) = &record.payload {
            let mut serials = self.device_serials.clone();
            let mut latest = self.latest_devices.clone();
            let mut revoked = self.revoked.clone();
            for certificate in &directory.devices {
                if revoked.contains(&certificate.serial)
                    || serials
                        .get(&certificate.serial)
                        .is_some_and(|peer| peer.as_ref() != Some(&certificate.peer_id))
                    || latest.get(&certificate.peer_id).is_some_and(|previous| {
                        certificate.serial < previous.serial
                            || (certificate.serial == previous.serial && certificate != previous)
                    })
                {
                    return Err(AslError::PolicyVersionConflict);
                }
                serials.insert(certificate.serial, Some(certificate.peer_id.clone()));
                latest.insert(certificate.peer_id.clone(), certificate.clone());
            }
            for serial in &directory.revoked_serials {
                revoked.insert(*serial);
                serials.entry(*serial).or_insert(None);
            }
            if serials.len() > self.observation_limit {
                return Err(AslError::PolicyDenied);
            }
            self.device_serials = serials;
            self.latest_devices = latest;
            self.revoked = revoked;
        }
        self.records.insert(
            kind,
            ObservedRecord {
                sequence: record.sequence,
                hash,
                policy_revoked: match &record.payload {
                    RecordPayload::ContactPolicy(value) => Some(value.revoked),
                    _ => None,
                },
            },
        );
        Ok(())
    }

    pub(super) fn check(&self, verified: &VerifiedRecord) -> Result<(), AslError> {
        self.clone().observe(verified)
    }

    pub(super) fn matches_directory(&self, agent: AgentId, hash: blake3::Hash) -> bool {
        self.agent_id == agent
            && self
                .records
                .get(&RecordKind::DeviceDirectory)
                .is_some_and(|record| record.hash == hash)
    }

    pub fn highest_sequence(&self, kind: RecordKind) -> Option<u64> {
        self.records.get(&kind).map(|record| record.sequence)
    }

    pub fn highest_device_serial(&self, peer: &PeerId) -> Option<u64> {
        self.latest_devices.get(peer).map(|device| device.serial)
    }

    pub fn observed_revocation(&self, serial: u64) -> bool {
        self.revoked.contains(&serial)
    }
}
