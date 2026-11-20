use std::{error::Error, fmt};

use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId},
    protocol::{Hello, IdentityProof as WireIdentityProof, IdentityProofRequest},
    record::RecordPayload,
};

use crate::chain::{ChainError, DurableIdentityResolver, IdentityResolver, RegistryStateV1};
use asl_net::transport::{AuthenticatedPeer, LocalConnectionId, LocalTransport, RequestToken};
use rand::{TryRng, rngs::SysRng};

use super::{RecordHistory, VerifiedRecord, resolve_active, verify_record};

enum State {
    AwaitingHello,
    AwaitingProof(Box<PendingProof>),
    Admitted {
        agent: AgentId,
        registry: RegistryStateV1,
        directory_hash: blake3::Hash,
        expires_at_ms: u64,
        last_checked_ms: u64,
    },
    Closed,
}

#[derive(Eq, PartialEq)]
enum ConnectionBinding {
    InProcess(AuthenticatedPeer),
    Ipc([u8; 16]),
}

struct PendingProof {
    hello: Hello,
    request: IdentityProofRequest,
    token: Option<RequestToken>,
    started_at_ms: u64,
}

#[derive(Debug)]
pub enum DeviceAdmissionError {
    Chain(ChainError),
    Session(AslError),
}

impl fmt::Display for DeviceAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Chain(error) => error.fmt(formatter),
            Self::Session(error) => error.fmt(formatter),
        }
    }
}

impl Error for DeviceAdmissionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Chain(error) => Some(error),
            Self::Session(error) => Some(error),
        }
    }
}

/// One Core gate per authenticated transport connection. Never construct it
/// using a PeerId claimed in a remote payload.
pub struct DeviceSession {
    peer: PeerId,
    transport: Option<ConnectionBinding>,
    state: State,
}

impl DeviceSession {
    pub fn from_transport(connection: AuthenticatedPeer) -> Self {
        Self {
            peer: connection.peer_id().clone(),
            transport: Some(ConnectionBinding::InProcess(connection)),
            state: State::AwaitingHello,
        }
    }

    pub fn peer_id(&self) -> &PeerId {
        &self.peer
    }

    pub fn connection_id(&self) -> Option<LocalConnectionId> {
        match self.transport.as_ref() {
            Some(ConnectionBinding::InProcess(connection)) => Some(connection.connection_id()),
            Some(ConnectionBinding::Ipc(_)) | None => None,
        }
    }

    pub fn ipc_connection_id(&self) -> Option<[u8; 16]> {
        match self.transport.as_ref() {
            Some(ConnectionBinding::Ipc(connection_id)) => Some(*connection_id),
            Some(ConnectionBinding::InProcess(_)) | None => None,
        }
    }

    /// Create a Core identity gate from `NetworkEvent::TransportConnected`.
    /// The connection ID and peer must come from that authenticated event.
    pub fn from_ipc_connection(connection_id: [u8; 16], peer: PeerId) -> Self {
        Self {
            peer,
            transport: Some(ConnectionBinding::Ipc(connection_id)),
            state: State::AwaitingHello,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_test_peer(peer: asl_types::ids::PeerId) -> Self {
        Self {
            peer,
            transport: None,
            state: State::AwaitingHello,
        }
    }

    fn require_live(&self) -> Result<(), AslError> {
        match &self.transport {
            Some(ConnectionBinding::InProcess(connection)) if connection.is_live() => Ok(()),
            Some(ConnectionBinding::Ipc(_)) => Ok(()),
            #[cfg(test)]
            None => Ok(()),
            _ => Err(AslError::InvalidIdentity),
        }
    }

    pub fn accept_hello(
        &mut self,
        hello: &Hello,
        signed_directory: &[u8],
        history: &mut RecordHistory,
        resolver: &mut dyn IdentityResolver,
        now_ms: u64,
    ) -> Result<(), AslError> {
        self.consume_hello_attempt()?;
        self.verify_hello(hello, signed_directory, history, resolver, now_ms)
            .map(drop)
    }

    /// Starts exactly one proof exchange, using a checkpoint and request ID
    /// selected locally. The transport chooses the already authenticated device.
    pub fn begin_network_hello(
        &mut self,
        hello: Hello,
        transport: &mut LocalTransport,
        resolver: &DurableIdentityResolver,
        now_ms: u64,
    ) -> Result<RequestToken, DeviceAdmissionError> {
        let request = self.prepare_network_hello(hello, resolver, now_ms)?;
        let Some(ConnectionBinding::InProcess(connection)) = self.transport.as_ref() else {
            self.close();
            return Err(DeviceAdmissionError::Session(AslError::InvalidIdentity));
        };
        let token = match transport.send_identity_proof_request(connection, request) {
            Ok(token) => token,
            Err(error) => {
                self.close();
                return Err(DeviceAdmissionError::Session(error.into()));
            }
        };
        let State::AwaitingProof(pending) = &mut self.state else {
            self.close();
            return Err(DeviceAdmissionError::Session(AslError::InvalidMessage));
        };
        pending.token = Some(token.clone());
        Ok(token)
    }

    /// Produces the same locally selected proof request for delivery through
    /// the Core/Net IPC boundary.
    pub fn begin_network_hello_ipc(
        &mut self,
        hello: Hello,
        resolver: &DurableIdentityResolver,
        now_ms: u64,
    ) -> Result<IdentityProofRequest, DeviceAdmissionError> {
        if !matches!(self.transport.as_ref(), Some(ConnectionBinding::Ipc(_))) {
            self.close();
            return Err(DeviceAdmissionError::Session(AslError::InvalidIdentity));
        }
        self.prepare_network_hello(hello, resolver, now_ms)
    }

    fn prepare_network_hello(
        &mut self,
        hello: Hello,
        resolver: &DurableIdentityResolver,
        now_ms: u64,
    ) -> Result<IdentityProofRequest, DeviceAdmissionError> {
        self.consume_hello_attempt()
            .map_err(DeviceAdmissionError::Session)?;
        self.check_hello(&hello, now_ms)
            .map_err(DeviceAdmissionError::Session)?;
        let finalized = resolver
            .light_client()
            .finalized(now_ms / 1_000)
            .map_err(DeviceAdmissionError::Chain)?;
        let mut request_id = [0; 16];
        SysRng
            .try_fill_bytes(&mut request_id)
            .map_err(|_| DeviceAdmissionError::Session(AslError::InvalidIdentity))?;
        let request = IdentityProofRequest {
            request_id: Id128(request_id),
            agent_id: hello.agent_id,
            checkpoint_hash: Hash32(finalized.block_hash()),
        };
        self.state = State::AwaitingProof(Box::new(PendingProof {
            hello,
            request: request.clone(),
            token: None,
            started_at_ms: now_ms,
        }));
        Ok(request)
    }

    /// Consumes a proof response from the driver on this connection.
    pub fn finish_network_hello(
        &mut self,
        connection: &AuthenticatedPeer,
        token: RequestToken,
        proof: &WireIdentityProof,
        history: &mut RecordHistory,
        resolver: &mut DurableIdentityResolver,
        now_ms: u64,
    ) -> Result<(), DeviceAdmissionError> {
        let State::AwaitingProof(pending) = std::mem::replace(&mut self.state, State::Closed)
        else {
            return Err(DeviceAdmissionError::Session(AslError::InvalidMessage));
        };
        if !matches!(
            self.transport.as_ref(),
            Some(ConnectionBinding::InProcess(bound)) if bound == connection
        ) || !token.belongs_to(connection)
            || pending.token.as_ref() != Some(&token)
        {
            return Err(DeviceAdmissionError::Session(AslError::InvalidIdentity));
        }
        self.finish_proof(*pending, proof, history, resolver, now_ms)
            .map(drop)
    }

    /// Completes a proof response received over IPC. The NetworkBridge has
    /// already bound its request token to this connection; Core additionally
    /// checks the local pending request id before chain verification.
    pub fn finish_network_hello_ipc(
        &mut self,
        connection_id: [u8; 16],
        proof: &WireIdentityProof,
        history: &mut RecordHistory,
        resolver: &mut DurableIdentityResolver,
        now_ms: u64,
    ) -> Result<VerifiedRecord, DeviceAdmissionError> {
        let State::AwaitingProof(pending) = std::mem::replace(&mut self.state, State::Closed)
        else {
            return Err(DeviceAdmissionError::Session(AslError::InvalidMessage));
        };
        if !matches!(
            self.transport.as_ref(),
            Some(ConnectionBinding::Ipc(bound)) if *bound == connection_id
        ) || pending.token.is_some()
            || pending.request.request_id != proof.request_id
        {
            return Err(DeviceAdmissionError::Session(AslError::InvalidIdentity));
        }
        self.finish_proof(*pending, proof, history, resolver, now_ms)
    }

    fn finish_proof(
        &mut self,
        pending: PendingProof,
        proof: &WireIdentityProof,
        history: &mut RecordHistory,
        resolver: &mut DurableIdentityResolver,
        now_ms: u64,
    ) -> Result<VerifiedRecord, DeviceAdmissionError> {
        if now_ms < pending.started_at_ms {
            return Err(DeviceAdmissionError::Session(AslError::ExpiredMessage));
        }
        self.check_hello(&pending.hello, now_ms)
            .map_err(DeviceAdmissionError::Session)?;
        resolver
            .accept_wire_identity_proof(&pending.request, proof, now_ms / 1_000)
            .map_err(DeviceAdmissionError::Chain)?;
        self.verify_hello(
            &pending.hello,
            &proof.signed_directory,
            history,
            resolver,
            now_ms,
        )
        .map_err(DeviceAdmissionError::Session)
    }

    fn consume_hello_attempt(&mut self) -> Result<(), AslError> {
        if !matches!(
            std::mem::replace(&mut self.state, State::Closed),
            State::AwaitingHello
        ) {
            return Err(AslError::InvalidMessage);
        }
        Ok(())
    }

    fn verify_hello(
        &mut self,
        hello: &Hello,
        signed_directory: &[u8],
        history: &mut RecordHistory,
        resolver: &mut dyn IdentityResolver,
        now_ms: u64,
    ) -> Result<VerifiedRecord, AslError> {
        self.check_hello(hello, now_ms)?;
        let certificate = &hello.device_certificate;
        let verified = verify_record(signed_directory, hello.agent_id, now_ms, resolver)?;
        let record = &verified.signed().record;
        let RecordPayload::DeviceDirectory(directory) = &record.payload else {
            return Err(AslError::InvalidDeviceCertificate);
        };
        if !directory.devices.contains(certificate) {
            return Err(AslError::InvalidDeviceCertificate);
        }
        self.require_live()?;
        history.observe(&verified)?;
        self.state = State::Admitted {
            agent: hello.agent_id,
            registry: verified.registry_state,
            directory_hash: blake3::hash(verified.bytes()),
            expires_at_ms: record.expires_at_ms.min(certificate.expires_at_ms),
            last_checked_ms: now_ms,
        };
        Ok(verified)
    }

    fn check_hello(&self, hello: &Hello, now_ms: u64) -> Result<(), AslError> {
        self.require_live()?;
        if hello.major != 1 {
            return Err(AslError::IncompatibleVersion);
        }
        let certificate = &hello.device_certificate;
        if hello.peer_id != self.peer
            || certificate.peer_id != self.peer
            || certificate.agent_id != hello.agent_id
        {
            return Err(AslError::InvalidDeviceCertificate);
        }
        if now_ms < certificate.issued_at_ms || now_ms >= certificate.expires_at_ms {
            return Err(AslError::ExpiredMessage);
        }
        Ok(())
    }

    /// Recheck before admitting business traffic. A newer directory or an
    /// unavailable identity closes the gate; reconnecting requires a new hello.
    pub fn current_agent(
        &mut self,
        history: &RecordHistory,
        resolver: &mut dyn IdentityResolver,
        now_ms: u64,
    ) -> Result<AgentId, AslError> {
        if matches!(self.state, State::AwaitingHello | State::AwaitingProof(_)) {
            return Err(AslError::InvalidIdentity);
        }
        let State::Admitted {
            agent,
            registry,
            directory_hash,
            expires_at_ms,
            last_checked_ms,
        } = std::mem::replace(&mut self.state, State::Closed)
        else {
            return Err(AslError::InvalidIdentity);
        };
        self.require_live()?;
        if now_ms < last_checked_ms || now_ms >= expires_at_ms {
            return Err(AslError::ExpiredMessage);
        }
        if !history.matches_directory(agent, directory_hash)
            || resolve_active(agent, now_ms, resolver)? != registry
        {
            return Err(AslError::InvalidIdentity);
        }
        self.require_live()?;
        self.state = State::Admitted {
            agent,
            registry,
            directory_hash,
            expires_at_ms,
            last_checked_ms: now_ms,
        };
        Ok(agent)
    }

    pub fn close(&mut self) {
        self.state = State::Closed;
    }

    pub(super) fn admission_facts(&self) -> Option<(RegistryStateV1, u64)> {
        match self.state {
            State::Admitted {
                registry,
                expires_at_ms,
                ..
            } => Some((registry, expires_at_ms)),
            _ => None,
        }
    }
}
