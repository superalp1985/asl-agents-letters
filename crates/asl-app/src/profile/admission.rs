use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

use asl_net::codec::{BulkRequest, BulkResponse};
use asl_store::Store;
use asl_store::search::direct::DirectRequester;
use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId},
    protocol::{
        ASL_PROTOCOL_MAJOR, ASL_PROTOCOL_MINOR, Feature, Hello, IdentityProof, PairingExchange,
        PairingInvite, WireFrame,
    },
    record::{MAX_RECORD_LIFETIME_MS, RecordKind, RecordPayload, decode_record},
};
use rand::{TryRng, rngs::SysRng};

use crate::{
    chain::{DurableIdentityResolver, IdentityResolution, IdentityResolver, RegistryStatus},
    identity::AgentIdentity,
    network::{NetworkCommand, NetworkEvent},
    transfer::{MatchedBulkResponse, VerifiedFetchManifest},
};

use super::{DeviceSession, RecordHistory, serve_local_identity_proof, sign_record};

#[cfg(windows)]
mod group_rooms;
#[cfg(windows)]
pub use group_rooms::{
    MlsApplicationDispatch, MlsApplicationReceive, MlsApplicationSendToConnection, MlsInviteSend,
    MlsJoinSend, MlsNetworkOutcome, ReconciledMlsRoom,
};

pub(crate) const MAX_ADMISSION_CONNECTIONS: usize = 16;
const MAX_DEVICE_OBSERVATIONS: usize = 128;
const MAX_DHT_RECORD_OWNERS: usize = 10_000;
const DEVICE_DIRECTORY_RENEWAL_MS: u64 = 5 * 60 * 1_000;
const MAX_PENDING_PROOFS: usize = MAX_ADMISSION_CONNECTIONS;
const PROOF_BUDGET_CAPACITY: u8 = 2;
const PROOF_BUDGET_REFILL: Duration = Duration::from_millis(500);
const MAX_QUEUED_PROOF_AGE: Duration = Duration::from_secs(10);

pub struct CoreAdmission {
    local_hello: Hello,
    local_signed_directory: Vec<u8>,
    local_directory_lease: DirectoryLease,
    local_controller: Option<[u8; 20]>,
    resolver: DurableIdentityResolver,
    peers: HashMap<[u8; 16], PeerAdmission>,
    blocked_agents: std::collections::HashSet<AgentId>,
    dht_histories: HashMap<AgentId, RecordHistory>,
    pending_proofs: VecDeque<[u8; 16]>,
    proof_budget: ProofVerificationBudget,
    #[cfg(windows)]
    mls_joins: group_rooms::MlsJoinAttempts,
    #[cfg(windows)]
    mls_sync: group_rooms::MlsSyncRuntime,
    #[cfg(windows)]
    mls_application_budget: ProofVerificationBudget,
    #[cfg(windows)]
    group_directories: Option<group_rooms::GroupDirectoryCache>,
}

struct PeerAdmission {
    session: DeviceSession,
    hello_request_id: [u8; 16],
    hello_response_seen: bool,
    remote_hello: Option<Hello>,
    pending_proof_id: Option<[u8; 16]>,
    pending_proof: Option<QueuedProof>,
    history: Option<RecordHistory>,
    admitted_agent: Option<AgentId>,
}

struct DirectoryLease {
    hash: blake3::Hash,
    issued_at_ms: u64,
    expires_at_ms: u64,
    record_sequence: u64,
    record_issued_at_ms: u64,
}

impl DirectoryLease {
    fn verified(record: &super::VerifiedRecord) -> Result<Self, AslError> {
        let signed = &record.signed().record;
        let RecordPayload::DeviceDirectory(directory) = &signed.payload else {
            return Err(AslError::InvalidDeviceCertificate);
        };
        let expires_at_ms = directory
            .devices
            .iter()
            .fold(signed.expires_at_ms, |limit, cert| {
                limit.min(cert.expires_at_ms)
            });
        let issued_at_ms = directory
            .devices
            .iter()
            .fold(signed.issued_at_ms, |limit, cert| {
                limit.max(cert.issued_at_ms)
            });
        Ok(Self {
            hash: blake3::hash(record.bytes()),
            issued_at_ms,
            expires_at_ms,
            record_sequence: signed.sequence,
            record_issued_at_ms: signed.issued_at_ms,
        })
    }
}

struct QueuedProof {
    proof: IdentityProof,
    received_at: Instant,
}

fn is_context_frame(frame: &WireFrame) -> bool {
    matches!(
        frame,
        WireFrame::ContextRequest(_)
            | WireFrame::ContextOffer(_)
            | WireFrame::ContextAgreement(_)
            | WireFrame::ContextExpression(_)
    )
}

fn is_context_request(frame: &WireFrame) -> bool {
    matches!(
        frame,
        WireFrame::ContextRequest(_) | WireFrame::ContextExpression(_)
    )
}

fn is_context_response(frame: &WireFrame) -> bool {
    matches!(frame, WireFrame::ContextOffer(_))
}

struct ProofVerificationBudget {
    tokens: u8,
    last_refill: Instant,
}

impl ProofVerificationBudget {
    fn new(now: Instant) -> Self {
        Self {
            tokens: PROOF_BUDGET_CAPACITY,
            last_refill: now,
        }
    }

    fn try_acquire(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last_refill);
        let intervals = elapsed.as_millis() / PROOF_BUDGET_REFILL.as_millis();
        if intervals > 0 {
            let refill = intervals.min(u128::from(PROOF_BUDGET_CAPACITY)) as u8;
            self.tokens = self
                .tokens
                .saturating_add(refill)
                .min(PROOF_BUDGET_CAPACITY);
            let elapsed_intervals = intervals.min(u128::from(u32::MAX)) as u32;
            self.last_refill = self
                .last_refill
                .checked_add(PROOF_BUDGET_REFILL * elapsed_intervals)
                .unwrap_or(now);
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmittedNetworkEvent {
    OperationAccepted {
        operation_id: [u8; 16],
    },
    OperationFailed {
        operation_id: [u8; 16],
        code: crate::ipc::NetworkErrorCode,
    },
    Listening {
        kind: asl_net::transport::TransportKind,
        address: std::net::SocketAddr,
    },
    RelayReserved {
        relay_peer_id: PeerId,
        address: Vec<u8>,
    },
    RelayUnavailable {
        relay_peer_id: PeerId,
    },
    PeerAdmitted {
        connection_id: [u8; 16],
        peer_id: PeerId,
        agent_id: AgentId,
    },
    PeerDisconnected {
        connection_id: [u8; 16],
        peer_id: Option<PeerId>,
        agent_id: Option<AgentId>,
    },
    ControlRequest {
        connection_id: [u8; 16],
        agent_id: AgentId,
        response_id: [u8; 16],
        request: WireFrame,
    },
    ControlResponse {
        connection_id: [u8; 16],
        agent_id: AgentId,
        request_id: [u8; 16],
        response: WireFrame,
    },
    PairingInviteReceived {
        connection_id: [u8; 16],
        agent_id: AgentId,
        response_id: [u8; 16],
        invite: PairingInvite,
    },
    PairingExchangeReceived {
        connection_id: [u8; 16],
        agent_id: AgentId,
        request_id: [u8; 16],
        invite: PairingInvite,
        exchange: PairingExchange,
    },
    PairingAccepted {
        agent_id: AgentId,
    },
    PairingDeclined {
        agent_id: AgentId,
    },
    BulkRequest {
        connection_id: [u8; 16],
        agent_id: AgentId,
        response_id: [u8; 16],
        request: BulkRequest,
    },
    BulkResponse {
        connection_id: [u8; 16],
        agent_id: AgentId,
        peer_id: PeerId,
        request_id: [u8; 16],
        response: BulkResponse,
    },
    BulkTransferResponse(MatchedBulkResponse),
    FetchManifestReceived(VerifiedFetchManifest),
    FetchManifestCorrupt(crate::transfer::CorruptFetchManifest),
    RequestFailed {
        connection_id: [u8; 16],
        agent_id: AgentId,
        peer_id: PeerId,
        request_id: [u8; 16],
        protocol: crate::ipc::NetworkProtocol,
        code: crate::ipc::NetworkErrorCode,
    },
    NetworkError {
        code: crate::ipc::NetworkErrorCode,
    },
    DhtRecordAvailable {
        agent_id: AgentId,
        kind: RecordKind,
        sequence: u64,
        registry_sequence: u64,
        record: Vec<u8>,
    },
    MailboxRecordAvailable(asl_net::mailbox::MailboxRecord),
}

#[derive(Default)]
pub struct AdmissionBatch {
    pub commands: Vec<NetworkCommand>,
    pub events: Vec<AdmittedNetworkEvent>,
}

impl CoreAdmission {
    pub fn for_local_identity(
        identity: &crate::identity::AgentIdentity,
        local_peer_id: PeerId,
        local_signed_directory: Vec<u8>,
        resolver: DurableIdentityResolver,
        now_ms: u64,
    ) -> Result<Self, AslError> {
        let signed = decode_record(&local_signed_directory)?;
        let RecordPayload::DeviceDirectory(directory) = signed.record.payload else {
            return Err(AslError::InvalidDeviceCertificate);
        };
        if directory.agent_id != identity.agent_id() {
            return Err(AslError::InvalidIdentity);
        }
        let device_certificate = directory
            .devices
            .into_iter()
            .find(|certificate| certificate.peer_id == local_peer_id)
            .ok_or(AslError::InvalidDeviceCertificate)?;
        let local_hello = Hello {
            message_id: Id128(fresh_id()?),
            agent_id: identity.agent_id(),
            peer_id: local_peer_id.clone(),
            device_certificate,
            major: ASL_PROTOCOL_MAJOR,
            minor: ASL_PROTOCOL_MINOR,
            features: vec![Feature::ActNl],
        };
        let mut admission = Self::new(
            local_peer_id,
            local_hello,
            local_signed_directory,
            resolver,
            now_ms,
        )?;
        if admission.verified_controller(identity.agent_id(), now_ms)?
            != identity.controller_address()
        {
            return Err(AslError::InvalidIdentity);
        }
        admission.local_controller = Some(identity.controller_address());
        Ok(admission)
    }

    /// The local advertisement must already be represented by an active,
    /// locally verified registry state and a signed directory containing its
    /// exact device certificate.
    pub fn new(
        local_peer_id: PeerId,
        local_hello: Hello,
        local_signed_directory: Vec<u8>,
        mut resolver: DurableIdentityResolver,
        now_ms: u64,
    ) -> Result<Self, AslError> {
        if local_hello.major != 1
            || local_hello.peer_id != local_peer_id
            || local_hello.device_certificate.peer_id != local_peer_id
            || local_hello.device_certificate.agent_id != local_hello.agent_id
        {
            return Err(AslError::InvalidIdentity);
        }
        if !resolver
            .retain_local_identity(local_hello.agent_id, None, now_ms / 1_000)
            .map_err(|_| AslError::InvalidIdentity)?
        {
            return Err(AslError::InvalidIdentity);
        }

        let mut history = RecordHistory::new(local_hello.agent_id, MAX_DEVICE_OBSERVATIONS)?;
        let verified = history.accept(&local_signed_directory, now_ms, &mut resolver)?;
        let RecordPayload::DeviceDirectory(directory) = &verified.signed().record.payload else {
            return Err(AslError::InvalidDeviceCertificate);
        };
        if !directory.devices.contains(&local_hello.device_certificate) {
            return Err(AslError::InvalidDeviceCertificate);
        }
        let mut dht_histories = HashMap::new();
        dht_histories.insert(local_hello.agent_id, history);

        Ok(Self {
            local_hello,
            local_signed_directory,
            local_directory_lease: DirectoryLease::verified(&verified)?,
            local_controller: None,
            resolver,
            peers: HashMap::new(),
            blocked_agents: std::collections::HashSet::new(),
            dht_histories,
            pending_proofs: VecDeque::new(),
            proof_budget: ProofVerificationBudget::new(Instant::now()),
            #[cfg(windows)]
            mls_joins: group_rooms::MlsJoinAttempts::default(),
            #[cfg(windows)]
            mls_sync: group_rooms::MlsSyncRuntime::default(),
            #[cfg(windows)]
            mls_application_budget: ProofVerificationBudget::new(Instant::now()),
            #[cfg(windows)]
            group_directories: None,
        })
    }

    pub fn refresh_local_identity(
        &mut self,
        light_client: crate::chain::EthereumLightClient,
        proof: &crate::chain::IdentityProofV1,
        now_ms: u64,
    ) -> Result<bool, AslError> {
        if !self.refresh_local_chain(light_client, proof, now_ms)? {
            return Ok(false);
        }
        self.check_local_directory(now_ms)?;
        Ok(true)
    }

    pub(crate) fn refresh_local_chain(
        &mut self,
        light_client: crate::chain::EthereumLightClient,
        proof: &crate::chain::IdentityProofV1,
        now_ms: u64,
    ) -> Result<bool, AslError> {
        let agent_id = self.local_hello.agent_id;
        let now_secs = now_ms / 1_000;
        self.resolver
            .update_light_client(light_client, now_secs)
            .map_err(|_| AslError::InvalidIdentity)?;
        let Some(controller) = self.local_controller else {
            return Err(AslError::InvalidIdentity);
        };
        self.resolver
            .accept_local_refresh_proof(agent_id, controller, proof, now_secs)
            .map_err(|_| AslError::InvalidIdentity)
    }

    pub(crate) fn clear_local_chain(&mut self) {
        self.resolver.clear_local_identity();
    }

    pub(crate) fn local_chain_is_current(&self, now_ms: u64) -> bool {
        self.resolver.local_identity_is_current(now_ms / 1_000)
    }

    fn local_is_current(&self, now_ms: u64) -> bool {
        self.local_chain_is_current(now_ms) && self.local_directory_is_current(now_ms)
    }

    pub(crate) fn prepare_local_profile(
        &mut self,
        identity: &AgentIdentity,
        store: &asl_store::Store,
        approval: &asl_store::public_profile::ProfileSigningApproval,
        sequence: u64,
        now_ms: u64,
    ) -> Result<Option<Vec<u8>>, AslError> {
        use asl_policy::PolicyEngine;
        use asl_store::public_profile::profile_topic;

        if !self.local_is_current(now_ms)
            || self.local_hello.agent_id != identity.agent_id()
            || approval.agent_id != identity.agent_id()
        {
            return Err(AslError::InvalidIdentity);
        }
        let mut publisher = super::ProfilePublisher::new(identity, sequence);
        publisher.configure(super::ProfileConfiguration {
            capabilities: approval.topics.iter().copied().map(profile_topic).collect(),
            avatar: approval.avatar().map(|grant| super::AvatarReference {
                grant_id: grant.grant_id.clone(),
                resource_key: grant.resource_key.clone(),
                epoch: grant.epoch,
                content_id: grant.content_id,
            }),
        });
        let task = asl_types::task::TaskId(Id128(fresh_id()?));
        let policy = PolicyEngine::new(
            store.profile_signing_policy(approval, task.clone())?,
            10_000,
        )?;
        publisher.poll_record(now_ms, task, &policy, &mut self.resolver)
    }

    fn check_local_directory_record(
        &self,
        verified: &super::VerifiedRecord,
    ) -> Result<(), AslError> {
        let RecordPayload::DeviceDirectory(directory) = &verified.signed().record.payload else {
            return Err(AslError::InvalidDeviceCertificate);
        };
        if !directory
            .devices
            .contains(&self.local_hello.device_certificate)
        {
            return Err(AslError::InvalidDeviceCertificate);
        }
        if self
            .local_controller
            .is_some_and(|controller| controller != verified.registry_state.controller)
        {
            return Err(AslError::InvalidIdentity);
        }
        let agent = self.local_hello.agent_id;
        self.dht_histories
            .get(&agent)
            .ok_or(AslError::InvalidPolicyState)?
            .check(verified)?;
        for history in self.peers.values().filter_map(|peer| {
            (peer.admitted_agent == Some(agent))
                .then_some(peer.history.as_ref())
                .flatten()
        }) {
            history.check(verified)?;
        }
        Ok(())
    }

    pub(crate) fn check_local_directory(&mut self, now_ms: u64) -> Result<(), AslError> {
        if !self.local_chain_is_current(now_ms) {
            return Err(AslError::InvalidIdentity);
        }
        let verified = super::verify_record(
            &self.local_signed_directory,
            self.local_hello.agent_id,
            now_ms,
            &mut self.resolver,
        )?;
        self.check_local_directory_record(&verified)
    }

    pub(crate) fn local_directory_is_current(&self, now_ms: u64) -> bool {
        let lease = &self.local_directory_lease;
        let agent = self.local_hello.agent_id;
        (lease.issued_at_ms..lease.expires_at_ms).contains(&now_ms)
            && self
                .dht_histories
                .get(&agent)
                .is_some_and(|history| history.matches_directory(agent, lease.hash))
    }

    pub(crate) fn local_directory_renewal_due(&self, now_ms: u64) -> bool {
        self.local_directory_lease
            .record_issued_at_ms
            .checked_add(DEVICE_DIRECTORY_RENEWAL_MS)
            .is_none_or(|deadline| now_ms >= deadline)
    }

    pub(crate) fn update_local_device_directory_source(
        &mut self,
        signed_source: Vec<u8>,
        identity: &AgentIdentity,
        store: &mut Store,
        now_ms: u64,
    ) -> Result<bool, AslError> {
        if !self.local_chain_is_current(now_ms) || identity.agent_id() != self.local_hello.agent_id
        {
            return Err(AslError::InvalidIdentity);
        }
        let source = decode_record(&signed_source)?;
        let RecordPayload::DeviceDirectory(source_directory) = &source.record.payload else {
            return Err(AslError::InvalidDeviceCertificate);
        };
        if source_directory.agent_id != self.local_hello.agent_id {
            return Err(AslError::InvalidIdentity);
        }
        let current = decode_record(&self.local_signed_directory)?;
        let current_sequence = self.local_directory_lease.record_sequence;
        if source.record.sequence <= current_sequence
            && source.record.payload == current.record.payload
        {
            return Ok(false);
        }

        let verified = super::verify_record(
            &signed_source,
            self.local_hello.agent_id,
            now_ms,
            &mut self.resolver,
        )?;
        let replacement = if source.record.sequence > current_sequence {
            signed_source
        } else {
            if self.verified_controller(self.local_hello.agent_id, now_ms)?
                != identity.controller_address()
            {
                return Err(AslError::InvalidIdentity);
            }
            let minimum = source
                .record
                .sequence
                .max(current_sequence)
                .checked_add(1)
                .ok_or(AslError::PolicyVersionConflict)?;
            let sequence =
                store.reserve_device_directory_sequence(self.local_hello.agent_id, minimum)?;
            sign_record(
                identity,
                verified.signed().record.payload.clone(),
                sequence,
                now_ms,
                MAX_RECORD_LIFETIME_MS,
            )?
        };
        self.renew_local_device_directory(replacement, now_ms)
    }

    pub(crate) fn renew_local_device_directory_if_due(
        &mut self,
        identity: &AgentIdentity,
        store: &mut Store,
        now_ms: u64,
    ) -> Result<bool, AslError> {
        if !self.local_directory_renewal_due(now_ms) {
            return Ok(false);
        }
        if !self.local_chain_is_current(now_ms) {
            return Err(AslError::InvalidIdentity);
        }
        let current = decode_record(&self.local_signed_directory)?;
        let RecordPayload::DeviceDirectory(directory) = current.record.payload else {
            return Err(AslError::InvalidDeviceCertificate);
        };
        if directory.agent_id != self.local_hello.agent_id
            || identity.agent_id() != self.local_hello.agent_id
        {
            return Err(AslError::InvalidIdentity);
        }
        let minimum = current
            .record
            .sequence
            .max(self.local_directory_lease.record_sequence)
            .checked_add(1)
            .ok_or(AslError::PolicyVersionConflict)?;
        let sequence =
            store.reserve_device_directory_sequence(self.local_hello.agent_id, minimum)?;
        let renewed = sign_record(
            identity,
            RecordPayload::DeviceDirectory(directory),
            sequence,
            now_ms,
            MAX_RECORD_LIFETIME_MS,
        )?;
        self.renew_local_device_directory(renewed, now_ms)
    }

    /// Reload the signed envelope without changing the device or Hello.
    pub(crate) fn renew_local_device_directory(
        &mut self,
        signed_directory: Vec<u8>,
        now_ms: u64,
    ) -> Result<bool, AslError> {
        if !self.local_chain_is_current(now_ms) {
            return Err(AslError::InvalidIdentity);
        }
        if self.local_signed_directory == signed_directory {
            return Ok(false);
        }
        let agent = self.local_hello.agent_id;
        let verified = super::verify_record(&signed_directory, agent, now_ms, &mut self.resolver)?;
        self.check_local_directory_record(&verified)?;
        let lease = DirectoryLease::verified(&verified)?;
        self.dht_histories
            .get_mut(&agent)
            .ok_or(AslError::InvalidPolicyState)?
            .observe(&verified)?;
        self.local_signed_directory = signed_directory;
        self.local_directory_lease = lease;
        Ok(true)
    }

    pub fn close_all(&mut self) -> AdmissionBatch {
        let mut batch = AdmissionBatch::default();
        let connections: Vec<_> = self.peers.keys().copied().collect();
        for connection_id in connections {
            self.close(connection_id, &mut batch);
        }
        batch
    }

    pub fn block_agent(&mut self, agent_id: AgentId) -> AdmissionBatch {
        self.blocked_agents.insert(agent_id);
        let connections = self
            .peers
            .iter()
            .filter_map(|(connection_id, peer)| {
                (peer.admitted_agent == Some(agent_id)
                    || peer
                        .remote_hello
                        .as_ref()
                        .is_some_and(|hello| hello.agent_id == agent_id))
                .then_some(*connection_id)
            })
            .collect::<Vec<_>>();
        let mut batch = AdmissionBatch::default();
        for connection_id in connections {
            self.close(connection_id, &mut batch);
        }
        batch
    }

    pub fn unblock_agent(&mut self, agent_id: AgentId) {
        self.blocked_agents.remove(&agent_id);
    }

    pub fn poll(&mut self, now_ms: u64) -> AdmissionBatch {
        #[cfg(windows)]
        {
            self.mls_joins.expire(now_ms);
            self.mls_sync.expire(now_ms);
        }
        let mut batch = AdmissionBatch::default();
        self.drain_proofs(now_ms, &mut batch);
        batch
    }

    #[cfg(test)]
    pub(crate) fn exhaust_proof_budget_for_test(&mut self) {
        self.proof_budget.tokens = 0;
        self.proof_budget.last_refill = Instant::now();
    }

    /// Processes raw Net events and emits only handshake commands or events
    /// whose Agent identity has been revalidated for this exact connection.
    pub fn handle_event(&mut self, event: NetworkEvent, now_ms: u64) -> AdmissionBatch {
        if !self.local_is_current(now_ms)
            && !matches!(&event, NetworkEvent::PeerDisconnected { .. })
        {
            return crate::supervisor::reject_unadmitted_event(event);
        }
        let mut batch = AdmissionBatch::default();
        match event {
            NetworkEvent::OperationAccepted { operation_id } => {
                batch
                    .events
                    .push(AdmittedNetworkEvent::OperationAccepted { operation_id });
            }
            NetworkEvent::OperationFailed { operation_id, code } => {
                batch
                    .events
                    .push(AdmittedNetworkEvent::OperationFailed { operation_id, code });
            }
            NetworkEvent::Listening { kind, address } => {
                batch
                    .events
                    .push(AdmittedNetworkEvent::Listening { kind, address });
            }
            NetworkEvent::RelayReserved {
                relay_peer_id,
                address,
            } => batch.events.push(AdmittedNetworkEvent::RelayReserved {
                relay_peer_id,
                address,
            }),
            NetworkEvent::RelayUnavailable { relay_peer_id } => {
                batch
                    .events
                    .push(AdmittedNetworkEvent::RelayUnavailable { relay_peer_id });
            }
            NetworkEvent::DiscoveryCandidate { .. }
            | NetworkEvent::DhtProviders { .. }
            | NetworkEvent::GossipReceived { .. } => {}
            NetworkEvent::DhtRecordCandidate {
                candidate_id,
                key,
                value,
            } => self.admit_dht_record(candidate_id, key, value, now_ms, &mut batch),
            NetworkEvent::TransportConnected {
                connection_id,
                peer_id,
            } => self.connected(connection_id, peer_id, &mut batch),
            NetworkEvent::PeerDisconnected { connection_id } => {
                #[cfg(windows)]
                {
                    self.mls_joins.disconnect(connection_id);
                    self.mls_sync.disconnect(connection_id);
                }
                let (peer_id, agent_id) =
                    self.peers
                        .remove(&connection_id)
                        .map_or((None, None), |mut peer| {
                            let agent = peer.admitted_agent;
                            let peer_id = peer.session.peer_id().clone();
                            peer.session.close();
                            (Some(peer_id), agent)
                        });
                self.pending_proofs
                    .retain(|pending| *pending != connection_id);
                batch.events.push(AdmittedNetworkEvent::PeerDisconnected {
                    connection_id,
                    peer_id,
                    agent_id,
                });
            }
            NetworkEvent::IdentityProofRequested {
                connection_id,
                response_id,
                request,
            } => {
                if !self.peers.contains_key(&connection_id) {
                    self.close(connection_id, &mut batch);
                    return batch;
                }
                let response = serve_local_identity_proof(
                    &self.local_hello,
                    &self.local_signed_directory,
                    &request,
                    &mut self.resolver,
                    now_ms,
                );
                match response {
                    Ok(Some(proof)) => {
                        batch.commands.push(NetworkCommand::ReplyIdentityProof {
                            connection_id,
                            response_id,
                            proof,
                        });
                    }
                    Ok(None) => {}
                    Err(_) => self.close(connection_id, &mut batch),
                }
            }
            NetworkEvent::IdentityProofReceived {
                connection_id,
                proof,
            } => self.queue_proof(connection_id, proof, &mut batch),
            NetworkEvent::UnverifiedPairingInvite {
                connection_id,
                response_id,
                invite,
            } => {
                if let Some(agent_id) = self.current_agent(connection_id, now_ms) {
                    batch
                        .events
                        .push(AdmittedNetworkEvent::PairingInviteReceived {
                            connection_id,
                            agent_id,
                            response_id,
                            invite,
                        });
                } else {
                    self.close(connection_id, &mut batch);
                }
            }
            NetworkEvent::UnverifiedPairingExchangeResponse {
                connection_id,
                request_id,
                invite,
                exchange,
            } => {
                if let Some(agent_id) = self.current_agent(connection_id, now_ms) {
                    batch
                        .events
                        .push(AdmittedNetworkEvent::PairingExchangeReceived {
                            connection_id,
                            agent_id,
                            request_id,
                            invite,
                            exchange,
                        });
                } else {
                    self.close(connection_id, &mut batch);
                }
            }
            NetworkEvent::UnverifiedControlRequest {
                connection_id,
                response_id,
                request,
            } => match request {
                WireFrame::Hello(hello) => {
                    self.receive_hello(connection_id, Some(response_id), hello, now_ms, &mut batch)
                }
                request => {
                    if let Some(agent_id) = self.current_agent(connection_id, now_ms) {
                        if (is_context_frame(&request)
                            && !self.peer_supports_contexts(connection_id))
                            || is_context_response(&request)
                        {
                            return batch;
                        }
                        if matches!(request, WireFrame::Expression(_))
                            && !self.peer_supports_expression(connection_id)
                        {
                            return batch;
                        }
                        batch.events.push(AdmittedNetworkEvent::ControlRequest {
                            connection_id,
                            agent_id,
                            response_id,
                            request,
                        });
                    } else {
                        self.close(connection_id, &mut batch);
                    }
                }
            },
            NetworkEvent::UnverifiedControlResponse {
                connection_id,
                request_id,
                response,
            } => {
                let is_hello_response = self
                    .peers
                    .get(&connection_id)
                    .is_some_and(|peer| peer.hello_request_id == request_id);
                if is_hello_response {
                    let hello = match response {
                        WireFrame::Hello(hello) => Some(hello),
                        _ => None,
                    };
                    if let Some(hello) = hello {
                        let already_seen = self
                            .peers
                            .get(&connection_id)
                            .is_some_and(|peer| peer.hello_response_seen);
                        if already_seen {
                            self.close(connection_id, &mut batch);
                        } else if mark_hello_response_seen(&mut self.peers, connection_id) {
                            self.receive_hello(connection_id, None, hello, now_ms, &mut batch);
                        } else {
                            self.close(connection_id, &mut batch);
                        }
                    } else {
                        self.close(connection_id, &mut batch);
                    }
                } else if let Some(agent_id) = self.current_agent(connection_id, now_ms) {
                    if (is_context_frame(&response) && !self.peer_supports_contexts(connection_id))
                        || is_context_request(&response)
                    {
                        return batch;
                    }
                    if matches!(response, WireFrame::Expression(_)) {
                        // Expression letters use fresh requests. A correlated legacy
                        // query response must never create an unsolicited letter.
                        return batch;
                    }
                    batch.events.push(AdmittedNetworkEvent::ControlResponse {
                        connection_id,
                        agent_id,
                        request_id,
                        response,
                    });
                } else {
                    self.close(connection_id, &mut batch);
                }
            }
            NetworkEvent::UnverifiedBulkRequest {
                connection_id,
                response_id,
                request,
            } => {
                if let Some(agent_id) = self.current_agent(connection_id, now_ms) {
                    batch.events.push(AdmittedNetworkEvent::BulkRequest {
                        connection_id,
                        agent_id,
                        response_id,
                        request,
                    });
                } else {
                    self.close(connection_id, &mut batch);
                }
            }
            NetworkEvent::UnverifiedBulkResponse {
                connection_id,
                request_id,
                response,
            } => {
                if let Ok((agent_id, peer_id)) = self.admitted_peer_identity(connection_id, now_ms)
                {
                    batch.events.push(AdmittedNetworkEvent::BulkResponse {
                        connection_id,
                        agent_id,
                        peer_id,
                        request_id,
                        response,
                    });
                } else {
                    self.close(connection_id, &mut batch);
                }
            }
            // The group driver needs the store and fresh member directories;
            // raw group frames do not go to generic local or Agent handlers.
            NetworkEvent::UnverifiedGroupRequest { .. }
            | NetworkEvent::UnverifiedGroupResponse { .. } => {}
            NetworkEvent::RequestFailed {
                connection_id,
                request_id,
                protocol,
                code,
            } => {
                if protocol == crate::ipc::NetworkProtocol::Group {
                    #[cfg(windows)]
                    {
                        self.mls_joins.fail(connection_id, request_id);
                        self.mls_sync.fail(connection_id, request_id);
                    }
                    return batch;
                }
                let is_pending_handshake = self.peers.get(&connection_id).is_some_and(|peer| {
                    (peer.hello_request_id == request_id
                        && protocol == crate::ipc::NetworkProtocol::Control)
                        || (peer.pending_proof_id == Some(request_id)
                            && protocol == crate::ipc::NetworkProtocol::IdentityProof)
                });
                if is_pending_handshake {
                    if self
                        .peers
                        .get(&connection_id)
                        .is_some_and(|peer| peer.admitted_agent.is_none())
                    {
                        self.close(connection_id, &mut batch);
                    }
                } else if let Ok((agent_id, peer_id)) =
                    self.admitted_peer_identity(connection_id, now_ms)
                {
                    batch.events.push(AdmittedNetworkEvent::RequestFailed {
                        connection_id,
                        agent_id,
                        peer_id,
                        request_id,
                        protocol,
                        code,
                    });
                } else if self.peers.contains_key(&connection_id) {
                    self.close(connection_id, &mut batch);
                }
            }
            NetworkEvent::NetworkError { code } => {
                batch
                    .events
                    .push(AdmittedNetworkEvent::NetworkError { code });
            }
        }
        self.drain_proofs(now_ms, &mut batch);
        batch
    }

    fn admit_dht_record(
        &mut self,
        candidate_id: [u8; 16],
        key: [u8; 32],
        value: Vec<u8>,
        now_ms: u64,
        batch: &mut AdmissionBatch,
    ) {
        let reject = || NetworkCommand::DecideDhtRecord {
            candidate_id,
            accept: false,
        };
        if let Ok(record) = asl_net::mailbox::decode_mailbox_record_for_key(
            &asl_net::dht::RecordKey::new(&key),
            &value,
        ) {
            if record.recipient_id != self.local_hello.agent_id.0
                || record.validate_at(now_ms).is_err()
            {
                batch.commands.push(reject());
            } else {
                batch.commands.push(NetworkCommand::DecideDhtRecord {
                    candidate_id,
                    accept: true,
                });
                batch
                    .events
                    .push(AdmittedNetworkEvent::MailboxRecordAvailable(record));
            }
            return;
        }
        let Ok(signed) = decode_record(&value) else {
            batch.commands.push(reject());
            return;
        };
        let agent_id = signed.record.payload.agent_id();
        let kind = signed.record.payload.kind();
        let Ok(expected_key) = asl_net::dht::identity_record_key(agent_id, kind) else {
            batch.commands.push(reject());
            return;
        };
        if expected_key.as_ref() != key
            || (!self.dht_histories.contains_key(&agent_id)
                && self.dht_histories.len() >= MAX_DHT_RECORD_OWNERS)
        {
            batch.commands.push(reject());
            return;
        }
        let Ok(verified) = super::verify_record(&value, agent_id, now_ms, &mut self.resolver)
        else {
            batch.commands.push(reject());
            return;
        };
        let history = self.dht_histories.entry(agent_id).or_insert_with(|| {
            RecordHistory::new(agent_id, MAX_DEVICE_OBSERVATIONS)
                .expect("fixed DHT history limit is valid")
        });
        if history.observe(&verified).is_err() {
            batch.commands.push(reject());
            return;
        }

        #[cfg(windows)]
        if let Some(directories) = &mut self.group_directories {
            directories.observe(&verified);
        }
        batch.commands.push(NetworkCommand::DecideDhtRecord {
            candidate_id,
            accept: true,
        });
        batch.events.push(AdmittedNetworkEvent::DhtRecordAvailable {
            agent_id,
            kind,
            sequence: verified.signed().record.sequence,
            registry_sequence: verified.registry_sequence(),
            record: value,
        });
    }

    pub fn authorize_control_command(
        &mut self,
        connection_id: [u8; 16],
        request_id: [u8; 16],
        request: WireFrame,
        now_ms: u64,
    ) -> Result<NetworkCommand, AslError> {
        if is_context_frame(&request) && !self.peer_supports_contexts(connection_id) {
            return Err(AslError::IncompatibleVersion);
        }
        if is_context_response(&request) {
            return Err(AslError::InvalidMessage);
        }
        if matches!(&request, WireFrame::Expression(_))
            && !self.peer_supports_expression(connection_id)
        {
            return Err(AslError::IncompatibleVersion);
        }
        if matches!(
            &request,
            WireFrame::Hello(_) | WireFrame::IdentityProofRequest(_) | WireFrame::IdentityProof(_)
        ) || !request.is_control()
        {
            return Err(AslError::InvalidMessage);
        }
        self.require_agent(connection_id, now_ms)?;
        Ok(NetworkCommand::SendControl {
            connection_id,
            request_id,
            request,
        })
    }

    pub fn authorize_control_reply(
        &mut self,
        connection_id: [u8; 16],
        response_id: [u8; 16],
        response: WireFrame,
        now_ms: u64,
    ) -> Result<NetworkCommand, AslError> {
        if is_context_frame(&response) && !self.peer_supports_contexts(connection_id) {
            return Err(AslError::IncompatibleVersion);
        }
        if is_context_request(&response) {
            return Err(AslError::InvalidMessage);
        }
        if matches!(
            &response,
            WireFrame::Hello(_)
                | WireFrame::IdentityProofRequest(_)
                | WireFrame::IdentityProof(_)
                | WireFrame::Expression(_)
        ) || !response.is_control()
        {
            return Err(AslError::InvalidMessage);
        }
        self.require_agent(connection_id, now_ms)?;
        Ok(NetworkCommand::ReplyControl {
            connection_id,
            response_id,
            response,
        })
    }

    pub fn authorize_bulk_command(
        &mut self,
        connection_id: [u8; 16],
        request: BulkRequest,
        now_ms: u64,
    ) -> Result<NetworkCommand, AslError> {
        self.require_agent(connection_id, now_ms)?;
        Ok(NetworkCommand::SendBulk {
            connection_id,
            request,
        })
    }

    pub fn authorize_bulk_reply(
        &mut self,
        connection_id: [u8; 16],
        response_id: [u8; 16],
        response: BulkResponse,
        now_ms: u64,
    ) -> Result<NetworkCommand, AslError> {
        self.require_agent(connection_id, now_ms)?;
        Ok(NetworkCommand::ReplyBulk {
            connection_id,
            response_id,
            response,
        })
    }

    fn connected(&mut self, connection_id: [u8; 16], peer_id: PeerId, batch: &mut AdmissionBatch) {
        if self.peers.contains_key(&connection_id) || self.peers.len() >= MAX_ADMISSION_CONNECTIONS
        {
            self.close(connection_id, batch);
            return;
        }
        let request_id = match fresh_id() {
            Ok(id) => id,
            Err(_) => {
                self.close(connection_id, batch);
                return;
            }
        };
        self.peers.insert(
            connection_id,
            PeerAdmission {
                session: DeviceSession::from_ipc_connection(connection_id, peer_id),
                hello_request_id: request_id,
                hello_response_seen: false,
                remote_hello: None,
                pending_proof_id: None,
                pending_proof: None,
                history: None,
                admitted_agent: None,
            },
        );
        batch.commands.push(NetworkCommand::SendControl {
            connection_id,
            request_id,
            request: WireFrame::Hello(self.local_hello.clone()),
        });
    }

    fn receive_hello(
        &mut self,
        connection_id: [u8; 16],
        response_id: Option<[u8; 16]>,
        hello: Hello,
        now_ms: u64,
        batch: &mut AdmissionBatch,
    ) {
        if self.blocked_agents.contains(&hello.agent_id) {
            self.close(connection_id, batch);
            return;
        }
        let Some(peer) = self.peers.get(&connection_id) else {
            self.close(connection_id, batch);
            return;
        };
        if let Some(previous) = peer.remote_hello.clone() {
            if previous != hello {
                self.close(connection_id, batch);
                return;
            }
            if let Some(response_id) = response_id {
                batch.commands.push(NetworkCommand::ReplyControl {
                    connection_id,
                    response_id,
                    response: WireFrame::Hello(self.local_hello.clone()),
                });
            }
            return;
        }

        let history = match RecordHistory::new(hello.agent_id, MAX_DEVICE_OBSERVATIONS) {
            Ok(history) => history,
            Err(_) => {
                self.close(connection_id, batch);
                return;
            }
        };
        let proof_request = match self
            .peers
            .get_mut(&connection_id)
            .ok_or(AslError::InvalidIdentity)
            .and_then(|peer| {
                peer.session
                    .begin_network_hello_ipc(hello.clone(), &self.resolver, now_ms)
                    .map_err(|_| AslError::InvalidIdentity)
            }) {
            Ok(request) => request,
            Err(_) => {
                self.close(connection_id, batch);
                return;
            }
        };
        let Some(peer) = self.peers.get_mut(&connection_id) else {
            self.close(connection_id, batch);
            return;
        };
        peer.remote_hello = Some(hello);
        peer.pending_proof_id = Some(proof_request.request_id.0);
        peer.history = Some(history);
        if let Some(response_id) = response_id {
            batch.commands.push(NetworkCommand::ReplyControl {
                connection_id,
                response_id,
                response: WireFrame::Hello(self.local_hello.clone()),
            });
        }
        batch.commands.push(NetworkCommand::RequestIdentityProof {
            connection_id,
            request: proof_request,
        });
    }

    fn queue_proof(
        &mut self,
        connection_id: [u8; 16],
        proof: IdentityProof,
        batch: &mut AdmissionBatch,
    ) {
        let pending = self.peers.get(&connection_id).is_some_and(|peer| {
            peer.pending_proof_id == Some(proof.request_id.0)
                && peer.pending_proof.is_none()
                && peer.history.is_some()
        });
        if !pending || self.pending_proofs.len() >= MAX_PENDING_PROOFS {
            self.close(connection_id, batch);
            return;
        }
        if let Some(peer) = self.peers.get_mut(&connection_id) {
            peer.pending_proof = Some(QueuedProof {
                proof,
                received_at: Instant::now(),
            });
        }
        self.pending_proofs.push_back(connection_id);
    }

    fn drain_proofs(&mut self, now_ms: u64, batch: &mut AdmissionBatch) {
        while self.local_is_current(now_ms) {
            let Some(connection_id) = self.pending_proofs.front().copied() else {
                return;
            };
            let Some(queued) = self
                .peers
                .get(&connection_id)
                .and_then(|peer| peer.pending_proof.as_ref())
            else {
                self.pending_proofs.pop_front();
                continue;
            };
            if queued.received_at.elapsed() >= MAX_QUEUED_PROOF_AGE {
                self.pending_proofs.pop_front();
                self.close(connection_id, batch);
                continue;
            }
            if !self.proof_budget.try_acquire(Instant::now()) {
                return;
            }
            self.pending_proofs.pop_front();
            let Some(proof) = self
                .peers
                .get_mut(&connection_id)
                .and_then(|peer| peer.pending_proof.take())
                .map(|queued| queued.proof)
            else {
                continue;
            };
            self.finish_proof(connection_id, proof, now_ms, batch);
        }
    }

    fn finish_proof(
        &mut self,
        connection_id: [u8; 16],
        proof: IdentityProof,
        now_ms: u64,
        batch: &mut AdmissionBatch,
    ) {
        let verified = self.peers.get_mut(&connection_id).and_then(|peer| {
            peer.session
                .finish_network_hello_ipc(
                    connection_id,
                    &proof,
                    peer.history.as_mut()?,
                    &mut self.resolver,
                    now_ms,
                )
                .ok()
        });
        let Some(_verified) = verified else {
            self.close(connection_id, batch);
            return;
        };
        let admitted = self.peers.get_mut(&connection_id).and_then(|peer| {
            peer.pending_proof_id = None;
            let agent_id = peer
                .session
                .current_agent(peer.history.as_ref()?, &mut self.resolver, now_ms)
                .ok()?;
            Some((agent_id, peer.session.peer_id().clone()))
        });
        match admitted {
            Some((agent_id, peer_id)) => {
                if self.blocked_agents.contains(&agent_id) {
                    self.close(connection_id, batch);
                    return;
                }
                if agent_id == self.local_hello.agent_id
                    && (self
                        .dht_histories
                        .get_mut(&agent_id)
                        .is_none_or(|history| history.observe(&_verified).is_err())
                        || !self.local_is_current(now_ms))
                {
                    self.close(connection_id, batch);
                    return;
                }
                if let Some(peer) = self.peers.get_mut(&connection_id) {
                    peer.admitted_agent = Some(agent_id);
                }
                #[cfg(windows)]
                self.observe_admitted_mls_directory(&_verified);
                batch.events.push(AdmittedNetworkEvent::PeerAdmitted {
                    connection_id,
                    peer_id,
                    agent_id,
                });
            }
            None => self.close(connection_id, batch),
        }
    }

    fn current_agent(&mut self, connection_id: [u8; 16], now_ms: u64) -> Option<AgentId> {
        if !self.local_is_current(now_ms) {
            return None;
        }
        let peer = self.peers.get_mut(&connection_id)?;
        let history = peer.history.as_ref()?;
        match peer
            .session
            .current_agent(history, &mut self.resolver, now_ms)
        {
            Ok(agent_id)
                if peer.admitted_agent == Some(agent_id)
                    && !self.blocked_agents.contains(&agent_id) =>
            {
                Some(agent_id)
            }
            _ => None,
        }
    }

    fn require_agent(&mut self, connection_id: [u8; 16], now_ms: u64) -> Result<AgentId, AslError> {
        self.current_agent(connection_id, now_ms)
            .ok_or(AslError::InvalidIdentity)
    }

    pub(crate) fn admitted_peer_identity(
        &mut self,
        connection_id: [u8; 16],
        now_ms: u64,
    ) -> Result<(AgentId, PeerId), AslError> {
        let agent_id = self.require_agent(connection_id, now_ms)?;
        let peer_id = self
            .peers
            .get(&connection_id)
            .ok_or(AslError::InvalidIdentity)?
            .session
            .peer_id()
            .clone();
        Ok((agent_id, peer_id))
    }

    /// Authenticates a group leaf against the exact certificate from this
    /// connection's verified hello. This does not establish room membership.
    pub fn verify_admitted_group_leaf(
        &mut self,
        connection_id: [u8; 16],
        wire_room: Hash32,
        leaf: &openmls::prelude::CredentialWithKey,
        now_ms: u64,
    ) -> Result<(), AslError> {
        let agent = self.require_agent(connection_id, now_ms)?;
        let peer = self
            .peers
            .get(&connection_id)
            .ok_or(AslError::InvalidIdentity)?;
        let hello = peer
            .remote_hello
            .as_ref()
            .ok_or(AslError::InvalidDeviceCertificate)?;
        let (registry, _) = peer
            .session
            .admission_facts()
            .ok_or(AslError::InvalidIdentity)?;
        if hello.device_certificate.agent_id != agent
            || &hello.device_certificate.peer_id != peer.session.peer_id()
        {
            return Err(AslError::InvalidDeviceCertificate);
        }
        super::group_credential::verify_binding(
            wire_room,
            leaf,
            &hello.device_certificate,
            registry.controller,
        )
    }

    /// Authenticates a leaf for a route that was selected from the current
    /// room roster. The roster load already rechecked every member's current
    /// signed directory against the chain; this additional check only binds
    /// the MLS leaf to the still-admitted transport device and its local
    /// admission facts. Re-running the full Hello chain gate here would turn a
    /// valid route into a second, independently-timed admission decision.
    pub(crate) fn verify_group_route_leaf(
        &self,
        connection_id: [u8; 16],
        wire_room: Hash32,
        leaf: &openmls::prelude::CredentialWithKey,
        now_ms: u64,
    ) -> Result<(), AslError> {
        if !self.local_is_current(now_ms) {
            return Err(AslError::InvalidIdentity);
        }
        let peer = self
            .peers
            .get(&connection_id)
            .ok_or(AslError::InvalidIdentity)?;
        let agent = peer.admitted_agent.ok_or(AslError::InvalidIdentity)?;
        let (registry, expires_at_ms) = peer
            .session
            .admission_facts()
            .ok_or(AslError::InvalidIdentity)?;
        if now_ms >= expires_at_ms {
            return Err(AslError::ExpiredMessage);
        }
        let hello = peer
            .remote_hello
            .as_ref()
            .ok_or(AslError::InvalidDeviceCertificate)?;
        if hello.device_certificate.agent_id != agent
            || &hello.device_certificate.peer_id != peer.session.peer_id()
        {
            return Err(AslError::InvalidDeviceCertificate);
        }
        super::group_credential::verify_binding(
            wire_room,
            leaf,
            &hello.device_certificate,
            registry.controller,
        )
    }

    pub(crate) fn register_manifest_source(
        &mut self,
        store: &mut asl_store::Store,
        manifest: &VerifiedFetchManifest,
        now_ms: u64,
    ) -> Result<(), AslError> {
        if manifest.expires_at_ms <= now_ms {
            return Err(AslError::ExpiredMessage);
        }
        self.register_connected_transfer_peer(
            store,
            manifest.connection_id,
            manifest.agent_id,
            &manifest.peer_id,
            now_ms,
        )
    }

    pub(crate) fn register_connected_transfer_peer(
        &mut self,
        store: &mut asl_store::Store,
        connection: [u8; 16],
        expected_agent: AgentId,
        expected_peer: &PeerId,
        now_ms: u64,
    ) -> Result<(), AslError> {
        let agent = self.require_agent(connection, now_ms)?;
        let source = self
            .direct_requester(connection, agent)
            .ok_or(AslError::InvalidIdentity)?;
        if source.agent != expected_agent || &source.peer != expected_peer {
            return Err(AslError::InvalidIdentity);
        }
        // This hello cannot change after finish_proof checked it against the signed
        // directory. require_agent just rechecked the session and its chain state.
        let hello = self
            .peers
            .get(&connection)
            .and_then(|p| p.remote_hello.as_ref())
            .ok_or(AslError::InvalidDeviceCertificate)?;
        let device_key = transport_ed25519_key(&source.peer)?;
        store.register_transfer_peer(
            &source,
            self.resolver.deployment().chain_id,
            &hello.device_certificate,
            device_key,
            now_ms,
        )
    }

    pub(crate) fn verified_controller(
        &mut self,
        agent_id: AgentId,
        now_ms: u64,
    ) -> Result<[u8; 20], AslError> {
        match self.resolver.resolve(agent_id, now_ms / 1_000) {
            IdentityResolution::Verified(identity)
                if identity.agent_id() == agent_id
                    && identity.state().status == RegistryStatus::Active =>
            {
                Ok(identity.state().controller)
            }
            _ => Err(AslError::InvalidIdentity),
        }
    }

    pub(crate) fn peer_supports_expression(&self, connection_id: [u8; 16]) -> bool {
        self.local_hello.minor >= 1
            && self
                .peers
                .get(&connection_id)
                .and_then(|peer| peer.remote_hello.as_ref())
                .is_some_and(|hello| hello.major == 1 && hello.minor >= 1)
    }

    pub(crate) fn peer_supports_contexts(&self, connection_id: [u8; 16]) -> bool {
        self.local_hello.minor >= 2
            && self
                .peers
                .get(&connection_id)
                .and_then(|peer| peer.remote_hello.as_ref())
                .is_some_and(|hello| hello.major == 1 && hello.minor >= 2)
    }

    pub(crate) fn peer_supports_act(&self, connection_id: [u8; 16]) -> bool {
        self.local_hello.minor >= 3
            && self.local_hello.features.contains(&Feature::ActNl)
            && self
                .peers
                .get(&connection_id)
                .and_then(|peer| peer.remote_hello.as_ref())
                .is_some_and(|hello| {
                    hello.major == 1 && hello.minor >= 3 && hello.features.contains(&Feature::ActNl)
                })
    }

    pub(crate) fn direct_requester(
        &self,
        connection_id: [u8; 16],
        agent: AgentId,
    ) -> Option<DirectRequester> {
        // The event pump has just admitted this control request. The full
        // chain check runs again at handoff, not twice on ingress.
        let peer = self.peers.get(&connection_id)?;
        if peer.admitted_agent != Some(agent) {
            return None;
        }
        let (registry, session_expires_at_ms) = peer.session.admission_facts()?;
        Some(DirectRequester {
            agent,
            peer: peer.session.peer_id().clone(),
            session_expires_at_ms,
            registry_sequence: registry.sequence,
            directory_commitment: registry.state_commitment,
            controller: registry.controller,
        })
    }

    pub(crate) fn admitted_connections(&self, now_ms: u64) -> Vec<(AgentId, [u8; 16], PeerId)> {
        if !self.local_is_current(now_ms) {
            return Vec::new();
        }
        let mut admitted = self
            .peers
            .iter()
            .filter_map(|(connection_id, peer)| {
                let agent_id = peer.admitted_agent?;
                let (_, expires_at_ms) = peer.session.admission_facts()?;
                (now_ms < expires_at_ms)
                    .then(|| (agent_id, *connection_id, peer.session.peer_id().clone()))
            })
            .collect::<Vec<_>>();
        admitted.sort_by(|left, right| {
            left.0
                .as_bytes()
                .cmp(right.0.as_bytes())
                .then_with(|| left.2.as_bytes().cmp(right.2.as_bytes()))
                .then_with(|| left.1.cmp(&right.1))
        });
        admitted
    }

    pub(crate) fn connecting_peers(&self) -> Vec<PeerId> {
        self.peers
            .values()
            .map(|peer| peer.session.peer_id().clone())
            .collect()
    }

    fn close(&mut self, connection_id: [u8; 16], batch: &mut AdmissionBatch) {
        self.invalidate_connection(connection_id);
        if !batch.commands.iter().any(
            |command| matches!(command, NetworkCommand::CloseConnection { connection_id: id } if *id == connection_id),
        ) {
            batch
                .commands
                .push(NetworkCommand::CloseConnection { connection_id });
        }
    }

    pub(crate) fn invalidate_connection(&mut self, connection_id: [u8; 16]) {
        #[cfg(windows)]
        {
            self.mls_joins.disconnect(connection_id);
            self.mls_sync.disconnect(connection_id);
        }
        self.pending_proofs
            .retain(|pending| *pending != connection_id);
        if let Some(mut peer) = self.peers.remove(&connection_id) {
            peer.session.close();
        }
    }
}

pub(super) fn transport_ed25519_key(peer: &PeerId) -> Result<[u8; 32], AslError> {
    let invalid = || AslError::InvalidDeviceCertificate;
    let transport = libp2p_identity::PeerId::from_bytes(peer.as_bytes()).map_err(|_| invalid())?;
    if transport.as_ref().code() != 0 {
        return Err(invalid());
    }
    let key = libp2p_identity::PublicKey::try_decode_protobuf(transport.as_ref().digest())
        .map_err(|_| invalid())?;
    if key.to_peer_id() != transport {
        return Err(invalid());
    }
    Ok(key.try_into_ed25519().map_err(|_| invalid())?.to_bytes())
}

fn mark_hello_response_seen(
    peers: &mut HashMap<[u8; 16], PeerAdmission>,
    connection_id: [u8; 16],
) -> bool {
    let Some(peer) = peers.get_mut(&connection_id) else {
        return false;
    };
    peer.hello_response_seen = true;
    true
}

pub(crate) fn fresh_id() -> Result<[u8; 16], AslError> {
    for _ in 0..8 {
        let mut id = [0; 16];
        SysRng
            .try_fill_bytes(&mut id)
            .map_err(|_| AslError::InvalidIdentity)?;
        if id != [0; 16] {
            return Ok(id);
        }
    }
    Err(AslError::InvalidIdentity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_device_key_requires_an_embedded_ed25519_key() {
        let mut hashed = vec![0x12, 32];
        hashed.extend([7; 32]);
        for bytes in [hashed, vec![0, 1, 0xff]] {
            let peer = PeerId::from_bytes(bytes).unwrap();
            assert!(matches!(
                transport_ed25519_key(&peer),
                Err(AslError::InvalidDeviceCertificate)
            ));
        }
    }

    #[test]
    fn proof_budget_limits_bursts_and_refills_at_two_per_second() {
        let start = Instant::now();
        let mut budget = ProofVerificationBudget::new(start);

        assert!(budget.try_acquire(start));
        assert!(budget.try_acquire(start));
        assert!(!budget.try_acquire(start));
        assert!(!budget.try_acquire(start + Duration::from_millis(499)));
        assert!(budget.try_acquire(start + Duration::from_millis(500)));
        assert!(!budget.try_acquire(start + Duration::from_millis(500)));
        assert!(budget.try_acquire(start + Duration::from_secs(5)));
        assert!(budget.try_acquire(start + Duration::from_secs(5)));
        assert!(!budget.try_acquire(start + Duration::from_secs(5)));
    }

    #[test]
    fn proof_budget_does_not_refill_when_time_moves_backwards() {
        let start = Instant::now();
        let mut budget = ProofVerificationBudget::new(start);

        assert!(budget.try_acquire(start));
        assert!(budget.try_acquire(start));
        assert!(!budget.try_acquire(start - Duration::from_secs(1)));
        assert!(budget.try_acquire(start + PROOF_BUDGET_REFILL));
    }
}
