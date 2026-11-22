use std::{net::SocketAddr, time::Duration};

use asl_net::{
    address_policy::AddressPolicy,
    codec::{BulkRequest, BulkResponse},
    relay::relay_endpoint_config,
    transport::{DhtLookupStatus, DhtProviderCandidate, DiscoveryCandidateState, TransportKind},
};
use asl_types::{
    error::AslError,
    ids::PeerId,
    protocol::{
        GroupPacket, IdentityProof, IdentityProofRequest, PairingExchange, PairingInvite, WireFrame,
    },
};

use crate::{
    ipc::{IpcMessage, NetworkErrorCode, NetworkProtocol},
    pairing::PairingAuthorization,
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
    RequestPairing {
        connection_id: [u8; 16],
        request_id: [u8; 16],
        invite: PairingInvite,
    },
    ReplyPairing {
        connection_id: [u8; 16],
        response_id: [u8; 16],
        exchange: PairingExchange,
    },
    AnswerPairingInvite {
        connection_id: [u8; 16],
        response_id: [u8; 16],
        invite: PairingInvite,
        authorization: PairingAuthorization,
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
    SendGroup {
        connection_id: [u8; 16],
        request_handle: [u8; 16],
        deadline_ms: u64,
        request: GroupPacket,
    },
    ReplyGroup {
        connection_id: [u8; 16],
        response_id: [u8; 16],
        response: GroupPacket,
    },
    SetAddressPolicy {
        operation_id: [u8; 16],
        policy: AddressPolicy,
    },
    ReserveRelay {
        operation_id: [u8; 16],
        address: Vec<u8>,
    },
    DialViaRelays {
        operation_id: [u8; 16],
        peer_id: PeerId,
    },
    DecideDhtRecord {
        candidate_id: [u8; 16],
        accept: bool,
    },
    FindProviders {
        lookup_id: [u8; 16],
        key: [u8; 32],
    },
    StartProviding {
        operation_id: [u8; 16],
        key: [u8; 32],
    },
    StopProviding {
        operation_id: [u8; 16],
        key: [u8; 32],
    },
}

impl NetworkCommand {
    pub(crate) fn into_ipc(self) -> Result<IpcMessage, AslError> {
        Ok(match self {
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
            Self::RequestPairing { .. }
            | Self::ReplyPairing { .. }
            | Self::AnswerPairingInvite { .. } => return Err(AslError::PolicyDenied),
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
            Self::SendGroup {
                connection_id,
                request_handle,
                deadline_ms,
                request,
            } => IpcMessage::SendGroup {
                connection_id,
                request_handle,
                deadline_ms,
                request,
            },
            Self::ReplyGroup {
                connection_id,
                response_id,
                response,
            } => IpcMessage::ReplyGroup {
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
            Self::ReserveRelay {
                operation_id,
                address,
            } => IpcMessage::ReserveRelay {
                operation_id,
                address,
            },
            Self::DialViaRelays {
                operation_id,
                peer_id,
            } => IpcMessage::DialViaRelays {
                operation_id,
                peer_id,
            },
            Self::DecideDhtRecord {
                candidate_id,
                accept,
            } => IpcMessage::DecideDhtRecord {
                candidate_id,
                accept,
            },
            Self::FindProviders { lookup_id, key } => IpcMessage::FindProviders { lookup_id, key },
            Self::StartProviding { operation_id, key } => {
                IpcMessage::StartProviding { operation_id, key }
            }
            Self::StopProviding { operation_id, key } => {
                IpcMessage::StopProviding { operation_id, key }
            }
        })
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
    RelayReserved {
        relay_peer_id: PeerId,
        address: Vec<u8>,
    },
    RelayUnavailable {
        relay_peer_id: PeerId,
    },
    DiscoveryCandidate {
        peer_id: PeerId,
        kind: TransportKind,
        address: SocketAddr,
        state: DiscoveryCandidateState,
    },
    DhtRecordCandidate {
        candidate_id: [u8; 16],
        key: [u8; 32],
        value: Vec<u8>,
    },
    DhtProviders {
        lookup_id: [u8; 16],
        status: DhtLookupStatus,
        providers: Vec<DhtProviderCandidate>,
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
    UnverifiedPairingInvite {
        connection_id: [u8; 16],
        response_id: [u8; 16],
        invite: PairingInvite,
    },
    UnverifiedPairingExchangeResponse {
        connection_id: [u8; 16],
        request_id: [u8; 16],
        invite: PairingInvite,
        exchange: PairingExchange,
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
        request_id: [u8; 16],
        response: BulkResponse,
    },
    UnverifiedGroupRequest {
        connection_id: [u8; 16],
        response_id: [u8; 16],
        deadline_ms: u64,
        request: GroupPacket,
    },
    UnverifiedGroupResponse {
        connection_id: [u8; 16],
        request_handle: [u8; 16],
        response: GroupPacket,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalNetworkObservation {
    DiscoveryCandidate {
        peer_id: PeerId,
        kind: TransportKind,
        address: SocketAddr,
        state: DiscoveryCandidateState,
    },
    DhtProviders {
        lookup_id: [u8; 16],
        status: DhtLookupStatus,
        providers: Vec<DhtProviderCandidate>,
    },
}

impl NetworkEvent {
    pub fn as_local_observation(&self) -> Option<LocalNetworkObservation> {
        match self {
            Self::DiscoveryCandidate {
                peer_id,
                kind,
                address,
                state,
            } => Some(LocalNetworkObservation::DiscoveryCandidate {
                peer_id: peer_id.clone(),
                kind: *kind,
                address: *address,
                state: *state,
            }),
            Self::DhtProviders {
                lookup_id,
                status,
                providers,
            } => Some(LocalNetworkObservation::DhtProviders {
                lookup_id: *lookup_id,
                status: *status,
                providers: providers.clone(),
            }),
            _ => None,
        }
    }
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
            IpcMessage::RelayReserved {
                relay_peer_id,
                address,
            } => Ok(Self::RelayReserved {
                relay_peer_id,
                address,
            }),
            IpcMessage::RelayUnavailable { relay_peer_id } => {
                Ok(Self::RelayUnavailable { relay_peer_id })
            }
            IpcMessage::DiscoveryCandidate {
                peer_id,
                kind,
                address,
                state,
            } => Ok(Self::DiscoveryCandidate {
                peer_id,
                kind,
                address,
                state,
            }),
            IpcMessage::DhtRecordCandidate {
                candidate_id,
                key,
                value,
            } => Ok(Self::DhtRecordCandidate {
                candidate_id,
                key,
                value,
            }),
            IpcMessage::DhtProviders {
                lookup_id,
                status,
                providers,
            } => Ok(Self::DhtProviders {
                lookup_id,
                status,
                providers,
            }),
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
            IpcMessage::PairingInviteRequested {
                connection_id,
                response_id,
                invite,
            } => Ok(Self::UnverifiedPairingInvite {
                connection_id,
                response_id,
                invite,
            }),
            IpcMessage::PairingExchangeReceived {
                connection_id,
                request_id,
                invite,
                exchange,
            } => Ok(Self::UnverifiedPairingExchangeResponse {
                connection_id,
                request_id,
                invite,
                exchange,
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
                request_id,
                response,
            } => Ok(Self::UnverifiedBulkResponse {
                connection_id,
                request_id,
                response,
            }),
            IpcMessage::GroupRequested {
                connection_id,
                response_id,
                deadline_ms,
                request,
            } => Ok(Self::UnverifiedGroupRequest {
                connection_id,
                response_id,
                deadline_ms,
                request,
            }),
            IpcMessage::GroupReceived {
                connection_id,
                request_handle,
                response,
            } => Ok(Self::UnverifiedGroupResponse {
                connection_id,
                request_handle,
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

    pub fn reserve_network_relay(
        &mut self,
        operation_id: [u8; 16],
        address: &str,
    ) -> Result<(), AslError> {
        let address = relay_endpoint_config(address).map_err(|_| AslError::InvalidMessage)?;
        self.send_network_command(NetworkCommand::ReserveRelay {
            operation_id,
            address,
        })
    }

    pub fn dial_network_via_relays(
        &mut self,
        operation_id: [u8; 16],
        peer_id: PeerId,
    ) -> Result<(), AslError> {
        self.send_network_command(NetworkCommand::DialViaRelays {
            operation_id,
            peer_id,
        })
    }

    /// Commands are Core-only. Control payloads remain untrusted until the
    /// caller's per-connection DeviceSession has admitted the peer.
    pub(crate) fn send_network_command(&mut self, command: NetworkCommand) -> Result<(), AslError> {
        if let NetworkCommand::CloseConnection { connection_id } = command {
            return self.queue_disconnect(connection_id);
        }
        self.send_network_ipc(command.into_ipc()?)
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
        self.flush_disconnects()?;
        let event = self.receive_network_event(timeout)?;
        let batch = self.handle_admitted_event(event, now_ms)?;
        for command in batch.commands {
            self.send_network_command(command)?;
        }
        let mut events = Vec::with_capacity(batch.events.len());
        for event in batch.events {
            self.observe_contact_binding_event(&event)?;
            if let AdmittedNetworkEvent::PairingInviteReceived { connection_id, .. } = &event {
                self.send_network_command(NetworkCommand::CloseConnection {
                    connection_id: *connection_id,
                })?;
                continue;
            }
            if matches!(
                &event,
                AdmittedNetworkEvent::PairingAccepted { .. }
                    | AdmittedNetworkEvent::PairingDeclined { .. }
            ) {
                continue;
            }
            if let Some(event) = self.verify_pairing_response(event, now_ms)? {
                events.push(event);
            }
        }
        Ok(events)
    }

    pub(crate) fn send_admitted_network_command(
        &mut self,
        command: NetworkCommand,
        now_ms: u64,
    ) -> Result<(), AslError> {
        self.pending_pairing_prompts.expire(now_ms);
        let command = match command {
            NetworkCommand::AnswerPairingInvite {
                connection_id,
                response_id,
                invite,
                authorization,
            } => {
                if !self
                    .pending_pairing_prompts
                    .authorizes(connection_id, response_id, &invite)
                {
                    return Err(AslError::PolicyDenied);
                }
                self.answer_pairing_invite(
                    connection_id,
                    response_id,
                    invite.clone(),
                    authorization,
                    now_ms,
                )?;
                self.pending_pairing_prompts.complete(invite.invite_id.0);
                return Ok(());
            }
            command => command,
        };
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
            NetworkCommand::SendBulk { .. } => return Err(AslError::PolicyDenied),
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
