use std::{net::SocketAddr, time::Duration};

use asl_net::{
    address_policy::AddressPolicy,
    codec::{BulkRequest, BulkResponse},
    transport::TransportKind,
};
use asl_types::{
    error::AslError,
    ids::PeerId,
    protocol::{IdentityProof, IdentityProofRequest, WireFrame},
};

use crate::{
    ipc::{IpcMessage, NetworkErrorCode, NetworkProtocol},
    profile::AdmittedNetworkEvent,
    supervisor::Supervisor,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NetworkCommand {
    Listen {
        operation_id: [u8; 16],
        kind: TransportKind,
        address: SocketAddr,
    },
    Dial {
        operation_id: [u8; 16],
        kind: TransportKind,
        address: SocketAddr,
        peer_id: PeerId,
    },
    CloseConnection {
        connection_id: [u8; 16],
    },
    RequestIdentityProof {
        connection_id: [u8; 16],
        request: IdentityProofRequest,
    },
    ReplyIdentityProof {
        connection_id: [u8; 16],
        response_id: [u8; 16],
        proof: IdentityProof,
    },
    /// Caller must pass Hello to DeviceSession and admit the peer before
    /// delivering any subsequent application control frame to an Agent.
    SendControl {
        connection_id: [u8; 16],
        request_id: [u8; 16],
        request: WireFrame,
    },
    ReplyControl {
        connection_id: [u8; 16],
        response_id: [u8; 16],
        response: WireFrame,
    },
    SendBulk {
        connection_id: [u8; 16],
        request: BulkRequest,
    },
    ReplyBulk {
        connection_id: [u8; 16],
        response_id: [u8; 16],
        response: BulkResponse,
    },
    SetAddressPolicy {
        operation_id: [u8; 16],
        policy: AddressPolicy,
    },
}

impl NetworkCommand {
    fn into_ipc(self) -> IpcMessage {
        match self {
            Self::Listen {
                operation_id,
                kind,
                address,
            } => IpcMessage::Listen {
                operation_id,
                kind,
                address,
            },
            Self::Dial {
                operation_id,
                kind,
                address,
                peer_id,
            } => IpcMessage::Dial {
                operation_id,
                kind,
                address,
                peer_id,
            },
            Self::CloseConnection { connection_id } => {
                IpcMessage::CloseConnection { connection_id }
            }
            Self::RequestIdentityProof {
                connection_id,
                request,
            } => IpcMessage::RequestIdentityProof {
                connection_id,
                request,
            },
            Self::ReplyIdentityProof {
                connection_id,
                response_id,
                proof,
            } => IpcMessage::ReplyIdentityProof {
                connection_id,
                response_id,
                proof,
            },
            Self::SendControl {
                connection_id,
                request_id,
                request,
            } => IpcMessage::SendControl {
                connection_id,
                request_id,
                request,
            },
            Self::ReplyControl {
                connection_id,
                response_id,
                response,
            } => IpcMessage::ReplyControl {
                connection_id,
                response_id,
                response,
            },
            Self::SendBulk {
                connection_id,
                request,
            } => IpcMessage::SendBulk {
                connection_id,
                request,
            },
            Self::ReplyBulk {
                connection_id,
                response_id,
                response,
            } => IpcMessage::ReplyBulk {
                connection_id,
                response_id,
                response,
            },
            Self::SetAddressPolicy {
                operation_id,
                policy,
            } => IpcMessage::SetAddressPolicy {
                operation_id,
                policy,
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NetworkEvent {
    OperationAccepted {
        operation_id: [u8; 16],
    },
    OperationFailed {
        operation_id: [u8; 16],
        code: NetworkErrorCode,
    },
    Listening {
        kind: TransportKind,
        address: SocketAddr,
    },
    /// The device transport is authenticated; the Agent identity is not.
    TransportConnected {
        connection_id: [u8; 16],
        peer_id: PeerId,
    },
    PeerDisconnected {
        connection_id: [u8; 16],
    },
    IdentityProofRequested {
        connection_id: [u8; 16],
        response_id: [u8; 16],
        request: IdentityProofRequest,
    },
    IdentityProofReceived {
        connection_id: [u8; 16],
        proof: IdentityProof,
    },
    /// Untrusted until Core completes the chain identity and device-certificate gate.
    UnverifiedControlRequest {
        connection_id: [u8; 16],
        response_id: [u8; 16],
        request: WireFrame,
    },
    UnverifiedControlResponse {
        connection_id: [u8; 16],
        request_id: [u8; 16],
        response: WireFrame,
    },
    UnverifiedBulkRequest {
        connection_id: [u8; 16],
        response_id: [u8; 16],
        request: BulkRequest,
    },
    UnverifiedBulkResponse {
        connection_id: [u8; 16],
        response: BulkResponse,
    },
    RequestFailed {
        connection_id: [u8; 16],
        request_id: [u8; 16],
        protocol: NetworkProtocol,
        code: NetworkErrorCode,
    },
    NetworkError {
        code: NetworkErrorCode,
    },
}

impl TryFrom<IpcMessage> for NetworkEvent {
    type Error = AslError;

    fn try_from(message: IpcMessage) -> Result<Self, Self::Error> {
        match message {
            IpcMessage::OperationAccepted { operation_id } => {
                Ok(Self::OperationAccepted { operation_id })
            }
            IpcMessage::OperationFailed { operation_id, code } => {
                Ok(Self::OperationFailed { operation_id, code })
            }
            IpcMessage::Listening { kind, address } => Ok(Self::Listening { kind, address }),
            IpcMessage::PeerAuthenticated {
                connection_id,
                peer_id,
            } => Ok(Self::TransportConnected {
                connection_id,
                peer_id,
            }),
            IpcMessage::PeerDisconnected { connection_id } => {
                Ok(Self::PeerDisconnected { connection_id })
            }
            IpcMessage::IdentityProofRequested {
                connection_id,
                response_id,
                request,
            } => Ok(Self::IdentityProofRequested {
                connection_id,
                response_id,
                request,
            }),
            IpcMessage::IdentityProofReceived {
                connection_id,
                proof,
            } => Ok(Self::IdentityProofReceived {
                connection_id,
                proof,
            }),
            IpcMessage::ControlRequested {
                connection_id,
                response_id,
                request,
            } => Ok(Self::UnverifiedControlRequest {
                connection_id,
                response_id,
                request,
            }),
            IpcMessage::ControlReceived {
                connection_id,
                request_id,
                response,
            } => Ok(Self::UnverifiedControlResponse {
                connection_id,
                request_id,
                response,
            }),
            IpcMessage::BulkRequested {
                connection_id,
                response_id,
                request,
            } => Ok(Self::UnverifiedBulkRequest {
                connection_id,
                response_id,
                request,
            }),
            IpcMessage::BulkReceived {
                connection_id,
                response,
            } => Ok(Self::UnverifiedBulkResponse {
                connection_id,
                response,
            }),
            IpcMessage::RequestFailed {
                connection_id,
                request_id,
                protocol,
                code,
            } => Ok(Self::RequestFailed {
                connection_id,
                request_id,
                protocol,
                code,
            }),
            IpcMessage::NetworkError { code } => Ok(Self::NetworkError { code }),
            _ => Err(AslError::InvalidMessage),
        }
    }
}

impl Supervisor {
    pub fn set_network_address_policy(
        &mut self,
        operation_id: [u8; 16],
        policy: AddressPolicy,
    ) -> Result<(), AslError> {
        self.send_network_command(NetworkCommand::SetAddressPolicy {
            operation_id,
            policy,
        })
    }

    pub fn listen_network(
        &mut self,
        operation_id: [u8; 16],
        kind: TransportKind,
        address: SocketAddr,
    ) -> Result<(), AslError> {
        self.send_network_command(NetworkCommand::Listen {
            operation_id,
            kind,
            address,
        })
    }

    pub fn dial_network(
        &mut self,
        operation_id: [u8; 16],
        kind: TransportKind,
        address: SocketAddr,
        peer_id: PeerId,
    ) -> Result<(), AslError> {
        self.send_network_command(NetworkCommand::Dial {
            operation_id,
            kind,
            address,
            peer_id,
        })
    }

    /// Commands are Core-only. Control payloads remain untrusted until the
    /// caller's per-connection DeviceSession has admitted the peer.
    pub(crate) fn send_network_command(&mut self, command: NetworkCommand) -> Result<(), AslError> {
        self.send_network_ipc(command.into_ipc())
    }

    pub(crate) fn receive_network_event(
        &mut self,
        timeout: Duration,
    ) -> Result<NetworkEvent, AslError> {
        NetworkEvent::try_from(self.receive_network_ipc(timeout)?)
    }

    pub fn receive_admitted_network_event(
        &mut self,
        timeout: Duration,
        now_ms: u64,
    ) -> Result<Vec<AdmittedNetworkEvent>, AslError> {
        let event = self.receive_network_event(timeout)?;
        let batch = self
            .admission
            .as_mut()
            .ok_or(AslError::InvalidIdentity)?
            .handle_event(event, now_ms);
        for command in batch.commands {
            self.send_network_command(command)?;
        }
        Ok(batch.events)
    }

    pub fn send_admitted_network_command(
        &mut self,
        command: NetworkCommand,
        now_ms: u64,
    ) -> Result<(), AslError> {
        let admission = self.admission.as_mut().ok_or(AslError::InvalidIdentity)?;
        let authorized = match &command {
            NetworkCommand::SendControl {
                connection_id,
                request_id,
                request,
            } => admission.authorize_control_command(
                *connection_id,
                *request_id,
                request.clone(),
                now_ms,
            )?,
            NetworkCommand::ReplyControl {
                connection_id,
                response_id,
                response,
            } => admission.authorize_control_reply(
                *connection_id,
                *response_id,
                response.clone(),
                now_ms,
            )?,
            NetworkCommand::SendBulk {
                connection_id,
                request,
            } => admission.authorize_bulk_command(*connection_id, request.clone(), now_ms)?,
            NetworkCommand::ReplyBulk {
                connection_id,
                response_id,
                response,
            } => admission.authorize_bulk_reply(
                *connection_id,
                *response_id,
                response.clone(),
                now_ms,
            )?,
            _ => return Err(AslError::InvalidMessage),
        };
        if authorized != command {
            return Err(AslError::InvalidMessage);
        }
        self.send_network_command(command)
    }
}
