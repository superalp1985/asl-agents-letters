use std::collections::HashMap;

use asl_net::codec::{BulkRequest, BulkResponse};
use asl_types::{
    error::AslError,
    ids::{AgentId, Id128, PeerId},
    protocol::{Hello, IdentityProof, WireFrame},
    record::{RecordPayload, decode_record},
};
use rand::{TryRng, rngs::SysRng};

use crate::{
    chain::DurableIdentityResolver,
    network::{NetworkCommand, NetworkEvent},
};

use super::{DeviceSession, RecordHistory, serve_local_identity_proof};

const MAX_ADMISSION_CONNECTIONS: usize = 16;
const MAX_DEVICE_OBSERVATIONS: usize = 128;

pub struct CoreAdmission {
    local_hello: Hello,
    local_signed_directory: Vec<u8>,
    resolver: DurableIdentityResolver,
    peers: HashMap<[u8; 16], PeerAdmission>,
}

struct PeerAdmission {
    session: DeviceSession,
    hello_request_id: [u8; 16],
    hello_response_seen: bool,
    remote_hello: Option<Hello>,
    pending_proof_id: Option<[u8; 16]>,
    history: Option<RecordHistory>,
    admitted_agent: Option<AgentId>,
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
    PeerAdmitted {
        connection_id: [u8; 16],
        peer_id: PeerId,
        agent_id: AgentId,
    },
    PeerDisconnected {
        connection_id: [u8; 16],
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
    BulkRequest {
        connection_id: [u8; 16],
        agent_id: AgentId,
        response_id: [u8; 16],
        request: BulkRequest,
    },
    BulkResponse {
        connection_id: [u8; 16],
        agent_id: AgentId,
        response: BulkResponse,
    },
    RequestFailed {
        connection_id: [u8; 16],
        agent_id: AgentId,
        request_id: [u8; 16],
        protocol: crate::ipc::NetworkProtocol,
        code: crate::ipc::NetworkErrorCode,
    },
    NetworkError {
        code: crate::ipc::NetworkErrorCode,
    },
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
            major: 1,
            minor: 0,
            features: Vec::new(),
        };
        Self::new(
            local_peer_id,
            local_hello,
            local_signed_directory,
            resolver,
            now_ms,
        )
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

        let mut history = RecordHistory::new(local_hello.agent_id, MAX_DEVICE_OBSERVATIONS)?;
        let verified = history.accept(&local_signed_directory, now_ms, &mut resolver)?;
        let RecordPayload::DeviceDirectory(directory) = &verified.signed().record.payload else {
            return Err(AslError::InvalidDeviceCertificate);
        };
        if !directory.devices.contains(&local_hello.device_certificate) {
            return Err(AslError::InvalidDeviceCertificate);
        }

        Ok(Self {
            local_hello,
            local_signed_directory,
            resolver,
            peers: HashMap::new(),
        })
    }

    /// Processes raw Net events and emits only handshake commands or events
    /// whose Agent identity has been revalidated for this exact connection.
    pub fn handle_event(&mut self, event: NetworkEvent, now_ms: u64) -> AdmissionBatch {
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
            NetworkEvent::TransportConnected {
                connection_id,
                peer_id,
            } => self.connected(connection_id, peer_id, &mut batch),
            NetworkEvent::PeerDisconnected { connection_id } => {
                let agent_id = self.peers.remove(&connection_id).and_then(|mut peer| {
                    let agent = peer.admitted_agent;
                    peer.session.close();
                    agent
                });
                batch.events.push(AdmittedNetworkEvent::PeerDisconnected {
                    connection_id,
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
            } => self.finish_proof(connection_id, proof, now_ms, &mut batch),
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
                response,
            } => {
                if let Some(agent_id) = self.current_agent(connection_id, now_ms) {
                    batch.events.push(AdmittedNetworkEvent::BulkResponse {
                        connection_id,
                        agent_id,
                        response,
                    });
                } else {
                    self.close(connection_id, &mut batch);
                }
            }
            NetworkEvent::RequestFailed {
                connection_id,
                request_id,
                protocol,
                code,
            } => {
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
                } else if let Some(agent_id) = self.current_agent(connection_id, now_ms) {
                    batch.events.push(AdmittedNetworkEvent::RequestFailed {
                        connection_id,
                        agent_id,
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
        batch
    }

    pub fn authorize_control_command(
        &mut self,
        connection_id: [u8; 16],
        request_id: [u8; 16],
        request: WireFrame,
        now_ms: u64,
    ) -> Result<NetworkCommand, AslError> {
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
        if matches!(
            &response,
            WireFrame::Hello(_) | WireFrame::IdentityProofRequest(_) | WireFrame::IdentityProof(_)
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

    fn finish_proof(
        &mut self,
        connection_id: [u8; 16],
        proof: IdentityProof,
        now_ms: u64,
        batch: &mut AdmissionBatch,
    ) {
        let pending = self
            .peers
            .get(&connection_id)
            .is_some_and(|peer| peer.pending_proof_id == Some(proof.request_id.0));
        if !pending {
            self.close(connection_id, batch);
            return;
        }
        if !self
            .peers
            .get(&connection_id)
            .is_some_and(|peer| peer.history.is_some())
        {
            self.close(connection_id, batch);
            return;
        }
        let proof_succeeded = self.peers.get_mut(&connection_id).is_some_and(|peer| {
            peer.history.as_mut().is_some_and(|history| {
                peer.session
                    .finish_network_hello_ipc(
                        connection_id,
                        &proof,
                        history,
                        &mut self.resolver,
                        now_ms,
                    )
                    .is_ok()
            })
        });
        if !proof_succeeded {
            self.close(connection_id, batch);
            return;
        }
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
                if let Some(peer) = self.peers.get_mut(&connection_id) {
                    peer.admitted_agent = Some(agent_id);
                }
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
        let peer = self.peers.get_mut(&connection_id)?;
        let history = peer.history.as_ref()?;
        match peer
            .session
            .current_agent(history, &mut self.resolver, now_ms)
        {
            Ok(agent_id) if peer.admitted_agent == Some(agent_id) => Some(agent_id),
            _ => None,
        }
    }

    fn require_agent(&mut self, connection_id: [u8; 16], now_ms: u64) -> Result<AgentId, AslError> {
        self.current_agent(connection_id, now_ms)
            .ok_or(AslError::InvalidIdentity)
    }

    fn close(&mut self, connection_id: [u8; 16], batch: &mut AdmissionBatch) {
        if let Some(mut peer) = self.peers.remove(&connection_id) {
            peer.session.close();
            batch
                .commands
                .push(NetworkCommand::CloseConnection { connection_id });
        } else if !batch.commands.iter().any(
            |command| matches!(command, NetworkCommand::CloseConnection { connection_id: id } if *id == connection_id),
        ) {
            batch
                .commands
                .push(NetworkCommand::CloseConnection { connection_id });
        }
    }
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

fn fresh_id() -> Result<[u8; 16], AslError> {
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
