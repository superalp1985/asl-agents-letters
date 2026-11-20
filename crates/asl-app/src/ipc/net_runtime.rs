use std::{
    collections::{HashMap, HashSet},
    io::{self, Stdin, Stdout, Write},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use asl_net::{
    codec::{BulkRequest, BulkResponse},
    transport::{
        AuthenticatedPeer, DialFailure, LocalConnectionId, LocalTransport, REQUEST_TIMEOUT,
        RequestToken, ResponseToken, TransportEvent,
    },
};
use asl_transfer::scheduler::MAX_ACTIVE_PER_SOURCE;
use asl_types::{
    error::AslError,
    ids::PeerId,
    protocol::{GroupPacket, IdentityProof, PairingExchange, PairingInvite, WireFrame},
};
use rand::{TryRng, rngs::SysRng};
use tokio::{runtime::Builder, sync::mpsc};

use super::{FrameReader, FrameWriter, IpcMessage, IpcRole, NetworkErrorCode, NetworkProtocol};
use crate::identity::DeviceIdentity;

const COMMAND_QUEUE_CAPACITY: usize = 8;
const MAX_PENDING_IPC_REQUESTS: usize = 96;
const RESPONSE_HANDLE_LIFETIME_MS: u64 = 10_000;
const RESPONSE_HANDLE_LIFETIME: Duration = Duration::from_millis(RESPONSE_HANDLE_LIFETIME_MS);
const PAIRING_RESPONSE_HANDLE_LIFETIME: Duration = Duration::from_secs(3 * 60);
const RESPONSE_SWEEP_INTERVAL: Duration = Duration::from_secs(1);

pub(super) fn run(identity: DeviceIdentity, input: Stdin, output: Stdout) -> Result<(), AslError> {
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(AslError::Io)?;
    runtime.block_on(run_async(identity, input, output))
}

async fn run_async(identity: DeviceIdentity, input: Stdin, output: Stdout) -> Result<(), AslError> {
    let peer_id = identity.peer_id();
    let transport = LocalTransport::new(identity.into_keypair())?;
    let mut bridge = NetworkBridge::new(transport);
    let mut writer = FrameWriter::new(output, IpcRole::Net, IpcRole::Core);
    writer.send(&IpcMessage::NetReady { peer_id })?;

    let (sender, mut commands) = mpsc::channel(COMMAND_QUEUE_CAPACITY);
    let reader_thread = thread::Builder::new()
        .name("asl-net-commands".into())
        .spawn(move || {
            let mut reader = FrameReader::new(input, IpcRole::Core, IpcRole::Net);
            loop {
                let frame = reader.receive();
                let terminal = match &frame {
                    Ok(frame) => matches!(frame.message, IpcMessage::Shutdown),
                    Err(_) => true,
                };
                if sender.blocking_send(frame).is_err() || terminal {
                    break;
                }
            }
        })
        .map_err(AslError::Io)?;

    let mut response_sweep = tokio::time::interval(RESPONSE_SWEEP_INTERVAL);
    let result = loop {
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else {
                    break Err(AslError::SandboxUnavailable);
                };
                let command = command?;
                match bridge.handle_command(command.message, &mut writer) {
                    Ok(true) => break Ok(()),
                    Ok(false) => {}
                    Err(code) => writer.send(&IpcMessage::NetworkError { code })?,
                }
            }
            event = bridge.transport.next_event() => {
                match event {
                    Ok(event) => bridge.handle_event(event, &mut writer)?,
                    Err(error) => writer.send(&IpcMessage::NetworkError {
                        code: error_code(&error),
                    })?,
                }
            }
            _ = response_sweep.tick() => bridge.expire_responses(),
        }
    };
    drop(commands);
    let _ = reader_thread.join();
    result
}

struct NetworkBridge {
    transport: LocalTransport,
    connections: HashMap<[u8; 16], AuthenticatedPeer>,
    connection_handles: HashMap<LocalConnectionId, [u8; 16]>,
    closing: HashSet<[u8; 16]>,
    responses: HashMap<[u8; 16], PendingResponse>,
    requests: HashMap<([u8; 16], [u8; 16], NetworkProtocol), PendingRequest>,
    pending_dials: HashMap<PeerId, [u8; 16]>,
}

impl NetworkBridge {
    fn new(transport: LocalTransport) -> Self {
        Self {
            transport,
            connections: HashMap::new(),
            connection_handles: HashMap::new(),
            closing: HashSet::new(),
            responses: HashMap::new(),
            requests: HashMap::new(),
            pending_dials: HashMap::new(),
        }
    }

    fn handle_command<W: Write>(
        &mut self,
        message: IpcMessage,
        writer: &mut FrameWriter<W>,
    ) -> Result<bool, NetworkErrorCode> {
        match message {
            IpcMessage::Shutdown => {
                writer
                    .send(&IpcMessage::Stopped)
                    .map_err(|_| NetworkErrorCode::Transport)?;
                Ok(true)
            }
            IpcMessage::Ping { nonce } => {
                writer
                    .send(&IpcMessage::Pong { nonce })
                    .map_err(|_| NetworkErrorCode::Transport)?;
                Ok(false)
            }
            IpcMessage::Listen {
                operation_id,
                kind,
                address,
            } => {
                let result = self.transport.listen(kind, address);
                self.send_operation_result(operation_id, result, writer)?;
                Ok(false)
            }
            IpcMessage::Dial {
                operation_id,
                kind,
                address,
                peer_id,
            } => {
                let result = self.transport.dial(kind, address, &peer_id);
                if result.is_ok() {
                    self.pending_dials.insert(peer_id, operation_id);
                }
                self.send_operation_result(operation_id, result, writer)?;
                Ok(false)
            }
            IpcMessage::ReserveRelay {
                operation_id,
                address,
            } => {
                let result = asl_net::relay::parse_relay_endpoint_bytes(address)
                    .map_err(|_| io::ErrorKind::InvalidInput.into())
                    .and_then(|address| self.transport.reserve_relay(&address).map(|_| ()));
                self.send_operation_result(operation_id, result, writer)?;
                Ok(false)
            }
            IpcMessage::DialViaRelays {
                operation_id,
                peer_id,
            } => {
                let result = self.transport.dial_via_relays(&peer_id);
                if result.is_ok() {
                    self.pending_dials.insert(peer_id, operation_id);
                }
                self.send_operation_result(operation_id, result, writer)?;
                Ok(false)
            }
            IpcMessage::SetAddressPolicy {
                operation_id,
                policy,
            } => {
                let result = self.transport.set_address_policy(policy);
                self.send_operation_result(operation_id, result, writer)?;
                Ok(false)
            }
            IpcMessage::DecideDhtRecord {
                candidate_id,
                accept,
            } => {
                self.transport
                    .decide_dht_record(candidate_id, accept)
                    .map_err(|error| error_code(&error))?;
                Ok(false)
            }
            IpcMessage::FindProviders { lookup_id, key } => {
                let result = self.transport.find_providers(key, lookup_id).map(|_| ());
                self.send_operation_result(lookup_id, result, writer)?;
                Ok(false)
            }
            IpcMessage::CloseConnection { connection_id } => {
                self.close_connection(connection_id)
                    .map_err(|error| error_code(&error))?;
                Ok(false)
            }
            IpcMessage::RequestIdentityProof {
                connection_id,
                request,
            } => {
                let request_id = request.request_id.0;
                if self.closing.contains(&connection_id) {
                    self.send_request_failure(
                        connection_id,
                        request_id,
                        NetworkProtocol::IdentityProof,
                        NetworkErrorCode::Disconnected,
                        writer,
                    )?;
                    return Ok(false);
                }
                let key = (connection_id, request_id, NetworkProtocol::IdentityProof);
                if self.requests.contains_key(&key)
                    || self.requests.len() >= MAX_PENDING_IPC_REQUESTS
                {
                    self.send_request_failure(
                        connection_id,
                        request_id,
                        NetworkProtocol::IdentityProof,
                        if self.requests.contains_key(&key) {
                            NetworkErrorCode::InvalidCommand
                        } else {
                            NetworkErrorCode::Capacity
                        },
                        writer,
                    )?;
                    return Ok(false);
                }
                let Some(connection) = self.connections.get(&connection_id) else {
                    self.send_request_failure(
                        connection_id,
                        request_id,
                        NetworkProtocol::IdentityProof,
                        NetworkErrorCode::Disconnected,
                        writer,
                    )?;
                    return Ok(false);
                };
                match self
                    .transport
                    .send_identity_proof_request(connection, request)
                {
                    Ok(token) => {
                        self.requests.insert(
                            key,
                            PendingRequest {
                                connection_id,
                                request_id,
                                token,
                            },
                        );
                    }
                    Err(error) => {
                        self.send_request_failure(
                            connection_id,
                            request_id,
                            NetworkProtocol::IdentityProof,
                            error_code(&error),
                            writer,
                        )?;
                    }
                }
                Ok(false)
            }
            IpcMessage::ReplyIdentityProof {
                connection_id,
                response_id,
                proof,
            } => {
                self.reply_identity_proof(connection_id, response_id, proof)
                    .map_err(|error| error_code(&error))?;
                Ok(false)
            }
            IpcMessage::RequestPairing {
                connection_id,
                request_id,
                invite,
            } => {
                self.send_pairing(connection_id, request_id, invite, writer)?;
                Ok(false)
            }
            IpcMessage::ReplyPairing {
                connection_id,
                response_id,
                exchange,
            } => {
                self.reply_pairing(connection_id, response_id, exchange)
                    .map_err(|error| error_code(&error))?;
                Ok(false)
            }
            IpcMessage::SendControl {
                connection_id,
                request_id,
                request,
            } => {
                self.send_control(connection_id, request_id, request, writer)?;
                Ok(false)
            }
            IpcMessage::ReplyControl {
                connection_id,
                response_id,
                response,
            } => {
                self.reply_control(connection_id, response_id, response)
                    .map_err(|error| error_code(&error))?;
                Ok(false)
            }
            IpcMessage::ReplyDirect {
                connection_id,
                response_id,
                expires_at_ms,
                response,
            } => {
                let now = crate::supervisor::unix_time_ms()
                    .map_err(|_| NetworkErrorCode::InvalidCommand)?;
                if now < expires_at_ms
                    && matches!(&response, WireFrame::Answer(_) | WireFrame::Offer(_))
                {
                    self.reply_control(connection_id, response_id, response)
                        .map_err(|error| error_code(&error))?;
                }
                Ok(false)
            }
            IpcMessage::SendBulk {
                connection_id,
                request,
            } => {
                self.send_bulk(connection_id, request, writer)?;
                Ok(false)
            }
            IpcMessage::ReplyBulk {
                connection_id,
                response_id,
                response,
            } => {
                self.reply_bulk(connection_id, response_id, response)
                    .map_err(|error| error_code(&error))?;
                Ok(false)
            }
            IpcMessage::SendGroup {
                connection_id,
                request_handle,
                deadline_ms,
                request,
            } => {
                self.send_group(connection_id, request_handle, deadline_ms, request, writer)?;
                Ok(false)
            }
            IpcMessage::ReplyGroup {
                connection_id,
                response_id,
                response,
            } => {
                self.reply_group(connection_id, response_id, response)
                    .map_err(|error| error_code(&error))?;
                Ok(false)
            }
            _ => Err(NetworkErrorCode::InvalidCommand),
        }
    }

    fn send_operation_result<W: Write>(
        &self,
        operation_id: [u8; 16],
        result: io::Result<()>,
        writer: &mut FrameWriter<W>,
    ) -> Result<(), NetworkErrorCode> {
        match result {
            Ok(()) => writer
                .send(&IpcMessage::OperationAccepted { operation_id })
                .map_err(|_| NetworkErrorCode::Transport),
            Err(error) => writer
                .send(&IpcMessage::OperationFailed {
                    operation_id,
                    code: error_code(&error),
                })
                .map_err(|_| NetworkErrorCode::Transport),
        }
    }

    fn close_connection(&mut self, connection_id: [u8; 16]) -> io::Result<()> {
        if self.closing.contains(&connection_id) {
            return Ok(());
        }
        let connection = self
            .connections
            .get(&connection_id)
            .ok_or(io::ErrorKind::NotConnected)?;
        self.transport.close_connection(connection)?;
        self.closing.insert(connection_id);
        self.responses
            .retain(|_, response| response.connection_id != connection_id);
        Ok(())
    }

    fn send_request_failure<W: Write>(
        &self,
        connection_id: [u8; 16],
        request_id: [u8; 16],
        protocol: NetworkProtocol,
        code: NetworkErrorCode,
        writer: &mut FrameWriter<W>,
    ) -> Result<(), NetworkErrorCode> {
        writer
            .send(&IpcMessage::RequestFailed {
                connection_id,
                request_id,
                protocol,
                code,
            })
            .map_err(|_| NetworkErrorCode::Transport)
    }

    fn send_control<W: Write>(
        &mut self,
        connection_id: [u8; 16],
        request_id: [u8; 16],
        request: WireFrame,
        writer: &mut FrameWriter<W>,
    ) -> Result<(), NetworkErrorCode> {
        if self.closing.contains(&connection_id) {
            return Err(NetworkErrorCode::Disconnected);
        }
        let key = (connection_id, request_id, NetworkProtocol::Control);
        if self.requests.contains_key(&key) {
            writer
                .send(&IpcMessage::RequestFailed {
                    connection_id,
                    request_id,
                    protocol: NetworkProtocol::Control,
                    code: NetworkErrorCode::InvalidCommand,
                })
                .map_err(|_| NetworkErrorCode::Transport)?;
            return Ok(());
        }
        if self.requests.len() >= MAX_PENDING_IPC_REQUESTS {
            writer
                .send(&IpcMessage::RequestFailed {
                    connection_id,
                    request_id,
                    protocol: NetworkProtocol::Control,
                    code: NetworkErrorCode::Capacity,
                })
                .map_err(|_| NetworkErrorCode::Transport)?;
            return Ok(());
        }
        let Some(connection) = self.connections.get(&connection_id) else {
            writer
                .send(&IpcMessage::RequestFailed {
                    connection_id,
                    request_id,
                    protocol: NetworkProtocol::Control,
                    code: NetworkErrorCode::Disconnected,
                })
                .map_err(|_| NetworkErrorCode::Transport)?;
            return Ok(());
        };
        match self.transport.send_control_request(connection, request) {
            Ok(token) => {
                self.requests.insert(
                    key,
                    PendingRequest {
                        connection_id,
                        request_id,
                        token,
                    },
                );
            }
            Err(error) => writer
                .send(&IpcMessage::RequestFailed {
                    connection_id,
                    request_id,
                    protocol: NetworkProtocol::Control,
                    code: error_code(&error),
                })
                .map_err(|_| NetworkErrorCode::Transport)?,
        }
        Ok(())
    }

    fn send_pairing<W: Write>(
        &mut self,
        connection_id: [u8; 16],
        request_id: [u8; 16],
        invite: PairingInvite,
        writer: &mut FrameWriter<W>,
    ) -> Result<(), NetworkErrorCode> {
        let protocol = NetworkProtocol::Pairing;
        let key = (connection_id, request_id, protocol);
        if self.closing.contains(&connection_id) {
            return self.send_request_failure(
                connection_id,
                request_id,
                protocol,
                NetworkErrorCode::Disconnected,
                writer,
            );
        }
        if invite.invite_id.0 != request_id || self.requests.contains_key(&key) {
            return self.send_request_failure(
                connection_id,
                request_id,
                protocol,
                NetworkErrorCode::InvalidCommand,
                writer,
            );
        }
        if self.requests.len() >= MAX_PENDING_IPC_REQUESTS {
            return self.send_request_failure(
                connection_id,
                request_id,
                protocol,
                NetworkErrorCode::Capacity,
                writer,
            );
        }
        let Some(connection) = self.connections.get(&connection_id) else {
            return self.send_request_failure(
                connection_id,
                request_id,
                protocol,
                NetworkErrorCode::Disconnected,
                writer,
            );
        };
        match self.transport.send_pairing_request(connection, invite) {
            Ok(token) => {
                self.requests.insert(
                    key,
                    PendingRequest {
                        connection_id,
                        request_id,
                        token,
                    },
                );
                Ok(())
            }
            Err(error) => self.send_request_failure(
                connection_id,
                request_id,
                protocol,
                error_code(&error),
                writer,
            ),
        }
    }

    fn send_bulk<W: Write>(
        &mut self,
        connection_id: [u8; 16],
        request: BulkRequest,
        writer: &mut FrameWriter<W>,
    ) -> Result<(), NetworkErrorCode> {
        let request_id = request.request_id.0;
        let protocol = NetworkProtocol::Bulk;
        let Some(connection) = self
            .connections
            .get(&connection_id)
            .filter(|_| !self.closing.contains(&connection_id))
        else {
            return self.send_request_failure(
                connection_id,
                request_id,
                protocol,
                NetworkErrorCode::Disconnected,
                writer,
            );
        };
        let key = (connection_id, request_id, protocol);
        if self.requests.contains_key(&key) {
            return self.send_request_failure(
                connection_id,
                request_id,
                protocol,
                NetworkErrorCode::InvalidCommand,
                writer,
            );
        }
        if self.requests.len() >= MAX_PENDING_IPC_REQUESTS
            || self
                .requests
                .keys()
                .filter(|(handle, _, pending_protocol)| {
                    *pending_protocol == protocol
                        && self
                            .connections
                            .get(handle)
                            .is_some_and(|pending| pending.peer_id() == connection.peer_id())
                })
                .count()
                >= usize::from(MAX_ACTIVE_PER_SOURCE)
        {
            return self.send_request_failure(
                connection_id,
                request_id,
                protocol,
                NetworkErrorCode::Capacity,
                writer,
            );
        }
        match self.transport.send_bulk_request(connection, request) {
            Ok(token) => {
                self.requests.insert(
                    key,
                    PendingRequest {
                        connection_id,
                        request_id,
                        token,
                    },
                );
            }
            Err(error) => {
                self.send_request_failure(
                    connection_id,
                    request_id,
                    protocol,
                    error_code(&error),
                    writer,
                )?;
            }
        }
        Ok(())
    }

    fn reply_identity_proof(
        &mut self,
        connection_id: [u8; 16],
        response_id: [u8; 16],
        proof: IdentityProof,
    ) -> io::Result<()> {
        if self.closing.contains(&connection_id) {
            return Err(io::ErrorKind::NotConnected.into());
        }
        let entry = self
            .responses
            .get(&response_id)
            .ok_or(io::ErrorKind::NotFound)?;
        if entry.connection_id != connection_id || entry.protocol != NetworkProtocol::IdentityProof
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let connection = self
            .connections
            .get(&connection_id)
            .ok_or(io::ErrorKind::NotConnected)?;
        self.transport
            .send_identity_proof_response(connection, &entry.token, proof)?;
        self.responses.remove(&response_id);
        Ok(())
    }

    fn reply_pairing(
        &mut self,
        connection_id: [u8; 16],
        response_id: [u8; 16],
        exchange: PairingExchange,
    ) -> io::Result<()> {
        if self.closing.contains(&connection_id) {
            return Err(io::ErrorKind::NotConnected.into());
        }
        let entry = self
            .responses
            .get(&response_id)
            .ok_or(io::ErrorKind::NotFound)?;
        if entry.connection_id != connection_id || entry.protocol != NetworkProtocol::Pairing {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        if entry.expires_at <= Instant::now() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let connection = self
            .connections
            .get(&connection_id)
            .ok_or(io::ErrorKind::NotConnected)?;
        self.transport
            .send_pairing_response(connection, &entry.token, exchange)?;
        self.responses.remove(&response_id);
        Ok(())
    }

    fn reply_control(
        &mut self,
        connection_id: [u8; 16],
        response_id: [u8; 16],
        response: WireFrame,
    ) -> io::Result<()> {
        if self.closing.contains(&connection_id) {
            return Err(io::ErrorKind::NotConnected.into());
        }
        let entry = self
            .responses
            .get(&response_id)
            .ok_or(io::ErrorKind::NotFound)?;
        if entry.connection_id != connection_id || entry.protocol != NetworkProtocol::Control {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        if entry.expires_at <= Instant::now() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let connection = self
            .connections
            .get(&connection_id)
            .ok_or(io::ErrorKind::NotConnected)?;
        self.transport
            .send_control_response(connection, &entry.token, response)?;
        self.responses.remove(&response_id);
        Ok(())
    }

    fn reply_bulk(
        &mut self,
        connection_id: [u8; 16],
        response_id: [u8; 16],
        response: BulkResponse,
    ) -> io::Result<()> {
        if self.closing.contains(&connection_id) {
            return Err(io::ErrorKind::NotConnected.into());
        }
        let entry = self
            .responses
            .get(&response_id)
            .ok_or(io::ErrorKind::NotFound)?;
        if entry.connection_id != connection_id || entry.protocol != NetworkProtocol::Bulk {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let connection = self
            .connections
            .get(&connection_id)
            .ok_or(io::ErrorKind::NotConnected)?;
        self.transport
            .send_bulk_response(connection, &entry.token, response)?;
        self.responses.remove(&response_id);
        Ok(())
    }

    fn send_group<W: Write>(
        &mut self,
        connection_id: [u8; 16],
        request_handle: [u8; 16],
        deadline_ms: u64,
        request: GroupPacket,
        writer: &mut FrameWriter<W>,
    ) -> Result<(), NetworkErrorCode> {
        let protocol = NetworkProtocol::Group;
        let now = Instant::now();
        let since_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| NetworkErrorCode::InvalidCommand)?;
        let remaining = Duration::from_millis(deadline_ms)
            .saturating_sub(since_epoch)
            .min(REQUEST_TIMEOUT);
        if remaining.is_zero() {
            return self.send_request_failure(
                connection_id,
                request_handle,
                protocol,
                NetworkErrorCode::TimedOut,
                writer,
            );
        }
        let key = (connection_id, request_handle, protocol);
        let result = match self.connections.get(&connection_id) {
            Some(connection) if !self.closing.contains(&connection_id) => {
                if self.requests.contains_key(&key) {
                    Err(NetworkErrorCode::InvalidCommand)
                } else if self.requests.len() >= MAX_PENDING_IPC_REQUESTS {
                    Err(NetworkErrorCode::Capacity)
                } else {
                    self.transport
                        .send_group_request(connection, request, now + remaining)
                        .map_err(|error| error_code(&error))
                }
            }
            _ => Err(NetworkErrorCode::Disconnected),
        };
        match result {
            Ok(token) => {
                self.requests.insert(
                    key,
                    PendingRequest {
                        connection_id,
                        request_id: request_handle,
                        token,
                    },
                );
                Ok(())
            }
            Err(code) => {
                self.send_request_failure(connection_id, request_handle, protocol, code, writer)
            }
        }
    }

    fn reply_group(
        &mut self,
        connection_id: [u8; 16],
        response_id: [u8; 16],
        response: GroupPacket,
    ) -> io::Result<()> {
        if self.closing.contains(&connection_id) {
            return Err(io::ErrorKind::NotConnected.into());
        }
        let entry = self
            .responses
            .get(&response_id)
            .ok_or(io::ErrorKind::NotFound)?;
        if entry.connection_id != connection_id || entry.protocol != NetworkProtocol::Group {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        if entry.expires_at <= Instant::now() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let connection = self
            .connections
            .get(&connection_id)
            .ok_or(io::ErrorKind::NotConnected)?;
        self.transport
            .send_group_response(connection, &entry.token, response)?;
        self.responses.remove(&response_id);
        Ok(())
    }

    fn handle_event<W: Write>(
        &mut self,
        event: TransportEvent,
        writer: &mut FrameWriter<W>,
    ) -> Result<(), AslError> {
        match event {
            TransportEvent::Listening(kind, address) => {
                writer.send(&IpcMessage::Listening { kind, address })?;
            }
            TransportEvent::RelayReserved {
                relay_peer_id,
                address,
            } => {
                writer.send(&IpcMessage::RelayReserved {
                    relay_peer_id: asl_types::ids::PeerId::from_bytes(relay_peer_id.to_bytes())
                        .map_err(|_| AslError::InvalidIdentity)?,
                    address: address.to_vec(),
                })?;
            }
            TransportEvent::RelayUnavailable { relay_peer_id } => {
                writer.send(&IpcMessage::RelayUnavailable {
                    relay_peer_id: asl_types::ids::PeerId::from_bytes(relay_peer_id.to_bytes())
                        .map_err(|_| AslError::InvalidIdentity)?,
                })?;
            }
            TransportEvent::DiscoveryCandidate(candidate) => {
                writer.send(&IpcMessage::DiscoveryCandidate {
                    peer_id: candidate.peer_id,
                    kind: candidate.kind,
                    address: candidate.address,
                    state: candidate.state,
                })?;
            }
            TransportEvent::DhtProviders {
                lookup_id,
                status,
                providers,
            } => {
                writer.send(&IpcMessage::DhtProviders {
                    lookup_id,
                    status,
                    providers,
                })?;
            }
            TransportEvent::DhtRecordCandidate {
                candidate_id,
                key,
                value,
            } => {
                writer.send(&IpcMessage::DhtRecordCandidate {
                    candidate_id,
                    key,
                    value,
                })?;
            }
            TransportEvent::InboundRejected => {}
            TransportEvent::Connected { connection } => {
                let connection_id = fresh_handle(&self.connections)?;
                let peer_id = connection.peer_id().clone();
                self.pending_dials.remove(&peer_id);
                self.connection_handles
                    .insert(connection.connection_id(), connection_id);
                self.connections.insert(connection_id, connection);
                writer.send(&IpcMessage::PeerAuthenticated {
                    connection_id,
                    peer_id,
                })?;
            }
            TransportEvent::Disconnected {
                connection_id,
                peer: _,
            } => {
                if let Some(handle) = self.connection_handles.remove(&connection_id) {
                    self.closing.remove(&handle);
                    self.connections.remove(&handle);
                    self.responses
                        .retain(|_, response| response.connection_id != handle);
                    let failed = self
                        .requests
                        .iter()
                        .filter(|(_, request)| request.connection_id == handle)
                        .map(|(key, _)| *key)
                        .collect::<Vec<_>>();
                    for key @ (_, request_id, protocol) in failed {
                        self.requests.remove(&key);
                        writer.send(&IpcMessage::RequestFailed {
                            connection_id: handle,
                            request_id,
                            protocol,
                            code: NetworkErrorCode::Disconnected,
                        })?;
                    }
                    writer.send(&IpcMessage::PeerDisconnected {
                        connection_id: handle,
                    })?;
                }
            }
            TransportEvent::DialFailed { peer_id, failure } => {
                let code = match failure {
                    DialFailure::PeerIdentityMismatch => NetworkErrorCode::Authentication,
                    DialFailure::Busy => NetworkErrorCode::Capacity,
                    DialFailure::Transport => NetworkErrorCode::Transport,
                };
                if let Some(operation_id) = self.pending_dials.remove(&peer_id) {
                    writer.send(&IpcMessage::OperationFailed { operation_id, code })?;
                } else {
                    writer.send(&IpcMessage::NetworkError { code })?;
                }
            }
            TransportEvent::IdentityProofRequest {
                connection,
                request,
                response,
            } => {
                self.forward_request(
                    connection,
                    NetworkProtocol::IdentityProof,
                    response,
                    |connection_id, response_id| IpcMessage::IdentityProofRequested {
                        connection_id,
                        response_id,
                        request,
                    },
                    writer,
                )?;
            }
            TransportEvent::PairingInviteRequest {
                connection,
                invite,
                response,
            } => {
                self.forward_request_with_lifetime(
                    connection,
                    NetworkProtocol::Pairing,
                    response,
                    PAIRING_RESPONSE_HANDLE_LIFETIME,
                    |connection_id, response_id| IpcMessage::PairingInviteRequested {
                        connection_id,
                        response_id,
                        invite,
                    },
                    writer,
                )?;
            }
            TransportEvent::PairingExchangeResponse {
                connection,
                request,
                invite,
                exchange,
            } => {
                if let Some(pending) = self.take_request(
                    connection.connection_id(),
                    &request,
                    NetworkProtocol::Pairing,
                ) {
                    writer.send(&IpcMessage::PairingExchangeReceived {
                        connection_id: pending.connection_id,
                        request_id: pending.request_id,
                        invite,
                        exchange,
                    })?;
                }
            }
            TransportEvent::IdentityProofResponse {
                connection,
                request,
                response,
            } => {
                if let Some(pending) = self.take_request(
                    connection.connection_id(),
                    &request,
                    NetworkProtocol::IdentityProof,
                ) {
                    writer.send(&IpcMessage::IdentityProofReceived {
                        connection_id: pending.connection_id,
                        proof: response,
                    })?;
                }
            }
            TransportEvent::ControlRequest {
                connection,
                request,
                response,
            } => {
                self.forward_request(
                    connection,
                    NetworkProtocol::Control,
                    response,
                    |connection_id, response_id| IpcMessage::ControlRequested {
                        connection_id,
                        response_id,
                        request,
                    },
                    writer,
                )?;
            }
            TransportEvent::ControlResponse {
                connection,
                request,
                response,
            } => {
                if let Some(pending) = self.take_request(
                    connection.connection_id(),
                    &request,
                    NetworkProtocol::Control,
                ) {
                    writer.send(&IpcMessage::ControlReceived {
                        connection_id: pending.connection_id,
                        request_id: pending.request_id,
                        response,
                    })?;
                }
            }
            TransportEvent::BulkRequest {
                connection,
                request,
                response,
            } => {
                self.forward_request(
                    connection,
                    NetworkProtocol::Bulk,
                    response,
                    |connection_id, response_id| IpcMessage::BulkRequested {
                        connection_id,
                        response_id,
                        request,
                    },
                    writer,
                )?;
            }
            TransportEvent::BulkResponse {
                connection,
                request,
                response,
            } => {
                if let Some(pending) =
                    self.take_request(connection.connection_id(), &request, NetworkProtocol::Bulk)
                {
                    writer.send(&IpcMessage::BulkReceived {
                        connection_id: pending.connection_id,
                        request_id: pending.request_id,
                        response,
                    })?;
                }
            }
            TransportEvent::GroupRequest {
                connection,
                request,
                response,
                deadline,
            } => {
                let now_ms = crate::supervisor::unix_time_ms()?;
                let remaining_ms = deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis();
                if remaining_ms == 0 {
                    return Ok(());
                }
                let deadline_ms = now_ms.saturating_add(remaining_ms as u64);
                self.forward_request_until(
                    connection,
                    NetworkProtocol::Group,
                    response,
                    deadline,
                    |connection_id, response_id| IpcMessage::GroupRequested {
                        connection_id,
                        response_id,
                        deadline_ms,
                        request,
                    },
                    writer,
                )?;
            }
            TransportEvent::GroupResponse {
                connection,
                request,
                response,
            } => {
                if let Some(pending) =
                    self.take_request(connection.connection_id(), &request, NetworkProtocol::Group)
                {
                    writer.send(&IpcMessage::GroupReceived {
                        connection_id: pending.connection_id,
                        request_handle: pending.request_id,
                        response,
                    })?;
                }
            }
            TransportEvent::RequestFailed {
                connection_id,
                request,
            } => {
                let failure_code = self
                    .connection_handles
                    .get(&connection_id)
                    .and_then(|handle| self.connections.get(handle))
                    .filter(|connection| connection.is_live())
                    .map_or(NetworkErrorCode::Disconnected, |_| {
                        NetworkErrorCode::TimedOut
                    });
                for protocol in [
                    NetworkProtocol::Control,
                    NetworkProtocol::IdentityProof,
                    NetworkProtocol::Bulk,
                    NetworkProtocol::Pairing,
                    NetworkProtocol::Group,
                ] {
                    if let Some(pending) = self.take_request(connection_id, &request, protocol) {
                        writer.send(&IpcMessage::RequestFailed {
                            connection_id: pending.connection_id,
                            request_id: pending.request_id,
                            protocol,
                            code: failure_code,
                        })?;
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    fn forward_request<W: Write>(
        &mut self,
        connection: AuthenticatedPeer,
        protocol: NetworkProtocol,
        token: ResponseToken,
        event: impl FnOnce([u8; 16], [u8; 16]) -> IpcMessage,
        writer: &mut FrameWriter<W>,
    ) -> Result<(), AslError> {
        self.forward_request_with_lifetime(
            connection,
            protocol,
            token,
            RESPONSE_HANDLE_LIFETIME,
            event,
            writer,
        )
    }

    fn forward_request_with_lifetime<W: Write>(
        &mut self,
        connection: AuthenticatedPeer,
        protocol: NetworkProtocol,
        token: ResponseToken,
        lifetime: Duration,
        event: impl FnOnce([u8; 16], [u8; 16]) -> IpcMessage,
        writer: &mut FrameWriter<W>,
    ) -> Result<(), AslError> {
        self.forward_request_until(
            connection,
            protocol,
            token,
            Instant::now() + lifetime,
            event,
            writer,
        )
    }

    fn forward_request_until<W: Write>(
        &mut self,
        connection: AuthenticatedPeer,
        protocol: NetworkProtocol,
        token: ResponseToken,
        expires_at: Instant,
        event: impl FnOnce([u8; 16], [u8; 16]) -> IpcMessage,
        writer: &mut FrameWriter<W>,
    ) -> Result<(), AslError> {
        let local_id = connection.connection_id();
        let Some(&connection_id) = self.connection_handles.get(&local_id) else {
            return Ok(());
        };
        if self.closing.contains(&connection_id) || Instant::now() >= expires_at {
            return Ok(());
        }
        let response_id = fresh_handle(&self.responses)?;
        self.responses.insert(
            response_id,
            PendingResponse {
                connection_id,
                protocol,
                token,
                expires_at,
            },
        );
        writer.send(&event(connection_id, response_id))?;
        Ok(())
    }

    fn take_request(
        &mut self,
        local_connection_id: LocalConnectionId,
        token: &RequestToken,
        protocol: NetworkProtocol,
    ) -> Option<PendingRequest> {
        let &connection_id = self.connection_handles.get(&local_connection_id)?;
        let key = self.requests.iter().find_map(|(key, request)| {
            (key.2 == protocol && request.connection_id == connection_id && request.token == *token)
                .then_some(*key)
        })?;
        self.requests.remove(&key)
    }

    fn expire_responses(&mut self) {
        let now = Instant::now();
        self.responses
            .retain(|_, response| response.expires_at > now);
    }
}

struct PendingResponse {
    connection_id: [u8; 16],
    protocol: NetworkProtocol,
    token: ResponseToken,
    expires_at: Instant,
}

struct PendingRequest {
    connection_id: [u8; 16],
    request_id: [u8; 16],
    token: RequestToken,
}

fn fresh_handle<T>(values: &HashMap<[u8; 16], T>) -> Result<[u8; 16], AslError> {
    for _ in 0..8 {
        let mut handle = [0; 16];
        SysRng
            .try_fill_bytes(&mut handle)
            .map_err(|_| AslError::InvalidIdentity)?;
        if handle != [0; 16] && !values.contains_key(&handle) {
            return Ok(handle);
        }
    }
    Err(AslError::InvalidIdentity)
}

fn error_code(error: &io::Error) -> NetworkErrorCode {
    match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::OutOfMemory => NetworkErrorCode::Capacity,
        io::ErrorKind::NotConnected | io::ErrorKind::BrokenPipe => NetworkErrorCode::Disconnected,
        io::ErrorKind::TimedOut => NetworkErrorCode::TimedOut,
        io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => {
            NetworkErrorCode::InvalidCommand
        }
        _ => NetworkErrorCode::Transport,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asl_net::{
        codec::{BulkOperation, BulkStatus},
        transport::TransportKind,
    };
    use asl_types::ids::{Id128, PeerId};
    use asl_types::protocol::{
        Answer, AnswerStatus, ConceptRef, GroupBody, GroupMembership, Intent, Query, ResultShape,
        ResultStatus, WireFrame,
    };
    use libp2p_identity::Keypair;
    use std::{
        io::Cursor,
        net::{IpAddr, Ipv4Addr, SocketAddr},
    };

    fn peer_id(keypair: &Keypair) -> PeerId {
        PeerId::from_bytes(keypair.public().to_peer_id().to_bytes()).unwrap()
    }

    fn read_event(bytes: Vec<u8>) -> IpcMessage {
        FrameReader::new(Cursor::new(bytes), IpcRole::Net, IpcRole::Core)
            .receive()
            .unwrap()
            .message
    }

    async fn next_event_from_either(
        listener: &mut NetworkBridge,
        dialer: &mut NetworkBridge,
    ) -> TransportEvent {
        tokio::select! {
            event = listener.transport.next_event() => event.unwrap(),
            event = dialer.transport.next_event() => event.unwrap(),
        }
    }

    fn bridge_event(bridge: &mut NetworkBridge, event: TransportEvent) -> IpcMessage {
        let mut writer = FrameWriter::new(Vec::new(), IpcRole::Net, IpcRole::Core);
        bridge.handle_event(event, &mut writer).unwrap();
        read_event(writer.into_inner())
    }

    async fn connected_bridges() -> ((NetworkBridge, [u8; 16]), (NetworkBridge, [u8; 16])) {
        connected_bridges_with(LocalTransport::new).await
    }

    async fn connected_bridges_with(
        make_transport: fn(Keypair) -> io::Result<LocalTransport>,
    ) -> ((NetworkBridge, [u8; 16]), (NetworkBridge, [u8; 16])) {
        let listener_key = Keypair::generate_ed25519();
        let listener_peer = peer_id(&listener_key);
        let mut listener = NetworkBridge::new(make_transport(listener_key).unwrap());
        listener
            .transport
            .listen(
                TransportKind::Tcp,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            )
            .unwrap();
        let listen_event = listener.transport.next_event().await.unwrap();
        let address = match listen_event {
            TransportEvent::Listening(TransportKind::Tcp, address) => address,
            event => panic!("unexpected listener event: {event:?}"),
        };

        let dialer_key = Keypair::generate_ed25519();
        let dialer_peer = peer_id(&dialer_key);
        let mut dialer = NetworkBridge::new(make_transport(dialer_key).unwrap());
        dialer
            .transport
            .dial(TransportKind::Tcp, address, &listener_peer)
            .unwrap();
        let (listener_event, dialer_event) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                listener.transport.next_event(),
                dialer.transport.next_event()
            )
        })
        .await
        .unwrap();

        let connection_handle =
            |bridge: &mut NetworkBridge, event, expected_peer| match bridge_event(bridge, event) {
                IpcMessage::PeerAuthenticated {
                    connection_id,
                    peer_id,
                } => {
                    assert_eq!(peer_id, expected_peer);
                    connection_id
                }
                event => panic!("unexpected connection event: {event:?}"),
            };
        let listener_id = connection_handle(&mut listener, listener_event.unwrap(), dialer_peer);
        let dialer_id = connection_handle(&mut dialer, dialer_event.unwrap(), listener_peer);
        ((listener, listener_id), (dialer, dialer_id))
    }

    #[tokio::test]
    async fn control_round_trip_crosses_both_driver_handle_mappings() {
        let ((mut listener, connection_id), (mut dialer, dialer_connection_id)) =
            connected_bridges().await;
        let now = crate::supervisor::unix_time_ms().unwrap();
        let request = WireFrame::Query(Query {
            message_id: Id128([61; 16]),
            root_task_id: Id128([62; 16]),
            created_at_ms: now,
            expires_at_ms: now + 5_000,
            intent_id: Intent::FindEvidence,
            topics: vec![ConceptRef::RUST],
            constraints: vec![],
            result_shape: ResultShape::Claims,
            budget: 1,
        });
        let request_id = [64; 16];
        let mut ignored_output = Vec::new();
        {
            let mut writer = FrameWriter::new(&mut ignored_output, IpcRole::Net, IpcRole::Core);
            assert!(
                !dialer
                    .handle_command(
                        IpcMessage::SendControl {
                            connection_id: dialer_connection_id,
                            request_id,
                            request: request.clone(),
                        },
                        &mut writer,
                    )
                    .unwrap()
            );
        }

        let request_event = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let event = next_event_from_either(&mut listener, &mut dialer).await;
                if matches!(&event, TransportEvent::ControlRequest { .. }) {
                    break event;
                }
                assert!(
                    !matches!(&event, TransportEvent::Disconnected { .. }),
                    "control request connection unexpectedly closed"
                );
            }
        })
        .await
        .unwrap();
        let mut request_bytes = Vec::new();
        {
            let mut writer = FrameWriter::new(&mut request_bytes, IpcRole::Net, IpcRole::Core);
            listener.handle_event(request_event, &mut writer).unwrap();
        }
        let response_id = match read_event(request_bytes) {
            IpcMessage::ControlRequested {
                connection_id: received_connection,
                response_id,
                request: received_request,
            } => {
                assert_eq!(received_connection, connection_id);
                assert_eq!(received_request, request);
                response_id
            }
            event => panic!("unexpected bridge request: {event:?}"),
        };

        let mut ignored_output = Vec::new();
        let now = crate::supervisor::unix_time_ms().unwrap();
        let response = WireFrame::Answer(Answer {
            message_id: Id128([63; 16]),
            root_task_id: Id128([62; 16]),
            created_at_ms: now,
            expires_at_ms: now + 5_000,
            status: AnswerStatus::NoMatch,
            claims: vec![],
            evidence_ids: vec![],
            result_status: ResultStatus::Unverified,
        });
        {
            let mut writer = FrameWriter::new(&mut ignored_output, IpcRole::Net, IpcRole::Core);
            let command = |expires_at_ms| IpcMessage::ReplyDirect {
                connection_id,
                response_id,
                expires_at_ms,
                response: response.clone(),
            };
            let expired = command(now.saturating_sub(1));
            assert!(!listener.handle_command(expired, &mut writer).unwrap());
            assert!(listener.responses.contains_key(&response_id));
            let live = command(now + 5_000);
            let bytes = super::super::encode_frame(IpcRole::Core, IpcRole::Net, 1, &live).unwrap();
            let decoded =
                super::super::decode_frame(&bytes, IpcRole::Core, IpcRole::Net, 1).unwrap();
            assert_eq!(decoded.message, live);
            assert!(
                !listener
                    .handle_command(decoded.message, &mut writer)
                    .unwrap()
            );
            assert!(!listener.responses.contains_key(&response_id));
        }

        let response_event = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let event = next_event_from_either(&mut listener, &mut dialer).await;
                if matches!(&event, TransportEvent::ControlResponse { .. }) {
                    break event;
                }
                assert!(
                    !matches!(&event, TransportEvent::Disconnected { .. }),
                    "control response connection unexpectedly closed"
                );
            }
        })
        .await
        .unwrap();
        let mut response_bytes = Vec::new();
        {
            let mut writer = FrameWriter::new(&mut response_bytes, IpcRole::Net, IpcRole::Core);
            dialer.handle_event(response_event, &mut writer).unwrap();
        }
        match read_event(response_bytes) {
            IpcMessage::ControlReceived {
                connection_id,
                request_id: received_request_id,
                response: received_response,
            } => {
                assert_eq!(connection_id, dialer_connection_id);
                assert_eq!(received_request_id, request_id);
                assert_eq!(received_response, response);
            }
            event => panic!("unexpected dialer response event: {event:?}"),
        }
    }

    fn command_output(bridge: &mut NetworkBridge, command: IpcMessage) -> Vec<u8> {
        let mut writer = FrameWriter::new(Vec::new(), IpcRole::Net, IpcRole::Core);
        assert!(!bridge.handle_command(command, &mut writer).unwrap());
        writer.into_inner()
    }

    fn group_request() -> GroupPacket {
        GroupPacket {
            message_id: Id128([71; 16]),
            group_id: [72; 32].into(),
            epoch: 2,
            body: GroupBody::Membership(GroupMembership::SyncRequest {
                epoch_binding: [73; 32].into(),
            }),
        }
    }

    async fn next_group_event(
        listener: &mut NetworkBridge,
        dialer: &mut NetworkBridge,
    ) -> TransportEvent {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let event = next_event_from_either(listener, dialer).await;
                match event {
                    TransportEvent::GroupRequest { .. } | TransportEvent::GroupResponse { .. } => {
                        break event;
                    }
                    TransportEvent::Disconnected { .. } | TransportEvent::RequestFailed { .. } => {
                        panic!("unexpected group transport failure: {event:?}");
                    }
                    _ => {}
                }
            }
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn group_reply_handles_are_single_use_and_late_events_cannot_complete_retries() {
        let ((mut listener, listener_id), (mut dialer, connection_id)) =
            connected_bridges_with(LocalTransport::new_with_loopback_groups).await;
        let request = group_request();
        let request_handle = [81; 16];
        let retry_handle = [82; 16];
        let send = |request_handle| IpcMessage::SendGroup {
            connection_id,
            request_handle,
            deadline_ms: crate::supervisor::unix_time_ms().unwrap() + 5_000,
            request: request.clone(),
        };
        assert!(command_output(&mut dialer, send(request_handle)).is_empty());
        assert_eq!(
            read_event(command_output(&mut dialer, send(request_handle))),
            IpcMessage::RequestFailed {
                connection_id,
                request_id: request_handle,
                protocol: NetworkProtocol::Group,
                code: NetworkErrorCode::InvalidCommand,
            }
        );

        let event = next_group_event(&mut listener, &mut dialer).await;
        let TransportEvent::GroupRequest { deadline, .. } = &event else {
            panic!("expected a group request");
        };
        let expiry = *deadline;
        let before_dispatch_ms = crate::supervisor::unix_time_ms().unwrap();
        let before_dispatch = Instant::now();
        let IpcMessage::GroupRequested {
            connection_id: received_connection,
            response_id,
            deadline_ms,
            request: received_request,
        } = bridge_event(&mut listener, event)
        else {
            panic!("expected a group request");
        };
        assert_eq!(received_connection, listener_id);
        assert_eq!(received_request, request);
        let after_dispatch = Instant::now();
        let after_dispatch_ms = crate::supervisor::unix_time_ms().unwrap();
        let remaining_ms = |now| expiry.saturating_duration_since(now).as_millis() as u64;
        assert!(
            (before_dispatch_ms + remaining_ms(after_dispatch)
                ..=after_dispatch_ms + remaining_ms(before_dispatch))
                .contains(&deadline_ms)
        );
        assert_eq!(listener.responses[&response_id].expires_at, expiry);

        let response = GroupPacket {
            body: GroupBody::Membership(GroupMembership::AtHead {
                epoch_binding: [73; 32].into(),
            }),
            ..request.clone()
        };
        assert_eq!(
            listener
                .reply_group([0; 16], response_id, response.clone())
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            listener
                .reply_bulk(
                    listener_id,
                    response_id,
                    BulkResponse {
                        request_id: request.message_id,
                        status: BulkStatus::NotFound,
                        payload: Vec::new(),
                    },
                )
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        let pending = listener.responses.get_mut(&response_id).unwrap();
        let live_expiry = std::mem::replace(&mut pending.expires_at, Instant::now());
        assert_eq!(
            listener
                .reply_group(listener_id, response_id, response.clone())
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        listener.responses.get_mut(&response_id).unwrap().expires_at = live_expiry;
        assert!(
            command_output(
                &mut listener,
                IpcMessage::ReplyGroup {
                    connection_id: listener_id,
                    response_id,
                    response: response.clone(),
                },
            )
            .is_empty()
        );
        assert_eq!(
            listener
                .reply_group(listener_id, response_id, response.clone())
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );

        let late_reply = next_group_event(&mut listener, &mut dialer).await;
        let TransportEvent::GroupResponse {
            connection,
            request: token,
            ..
        } = &late_reply
        else {
            panic!("expected a group response");
        };
        // Core can retry before the child processes the first attempt's failure.
        assert!(command_output(&mut dialer, send(retry_handle)).is_empty());
        let old_timeout = || TransportEvent::RequestFailed {
            connection_id: connection.connection_id(),
            request: token.clone(),
        };
        assert_eq!(
            bridge_event(&mut dialer, old_timeout()),
            IpcMessage::RequestFailed {
                connection_id,
                request_id: request_handle,
                protocol: NetworkProtocol::Group,
                code: NetworkErrorCode::TimedOut,
            }
        );
        let mut writer = FrameWriter::new(Vec::new(), IpcRole::Net, IpcRole::Core);
        dialer.handle_event(old_timeout(), &mut writer).unwrap();
        dialer.handle_event(late_reply, &mut writer).unwrap();
        assert!(writer.into_inner().is_empty());

        let event = next_group_event(&mut listener, &mut dialer).await;
        let IpcMessage::GroupRequested {
            connection_id: received_connection,
            response_id,
            request: retried_request,
            ..
        } = bridge_event(&mut listener, event)
        else {
            panic!("expected a retried group request");
        };
        assert_eq!(received_connection, listener_id);
        assert_eq!(retried_request, request);
        assert!(
            command_output(
                &mut listener,
                IpcMessage::ReplyGroup {
                    connection_id: listener_id,
                    response_id,
                    response: response.clone(),
                },
            )
            .is_empty()
        );
        let event = next_group_event(&mut listener, &mut dialer).await;
        assert_eq!(
            bridge_event(&mut dialer, event),
            IpcMessage::GroupReceived {
                connection_id,
                request_handle: retry_handle,
                response,
            }
        );
        assert!(dialer.requests.is_empty());
    }

    #[tokio::test]
    async fn group_send_that_expires_after_queueing_does_not_reach_the_other_net() {
        let ((mut listener, _), (mut dialer, connection_id)) =
            connected_bridges_with(LocalTransport::new_with_loopback_groups).await;
        let deadline = Instant::now() + Duration::from_millis(250);
        let token = dialer
            .transport
            .send_group_request(
                &dialer.connections[&connection_id],
                group_request(),
                deadline,
            )
            .unwrap();
        // Neither swarm is polled after enqueue until the local deadline has passed.
        tokio::time::sleep_until(deadline.into()).await;
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let event = next_event_from_either(&mut listener, &mut dialer).await;
                match event {
                    TransportEvent::RequestFailed { request, .. } => {
                        assert_eq!(request, token);
                        break;
                    }
                    TransportEvent::GroupRequest { .. } | TransportEvent::Disconnected { .. } => {
                        panic!("unexpected group transport event: {event:?}");
                    }
                    _ => {}
                }
            }
        })
        .await
        .unwrap();

        // Drive the same connection through a fresh request to observe any old
        // request that might have arrived after the sender's failure event.
        let fresh = GroupPacket {
            message_id: Id128([85; 16]),
            ..group_request()
        };
        dialer
            .transport
            .send_group_request(
                &dialer.connections[&connection_id],
                fresh.clone(),
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap();
        let TransportEvent::GroupRequest { request, .. } =
            next_group_event(&mut listener, &mut dialer).await
        else {
            panic!("expected a fresh group request");
        };
        assert_eq!(request, fresh);
    }

    #[tokio::test]
    async fn group_request_that_expires_before_ipc_has_no_response_handle() {
        let ((mut listener, _), (mut dialer, connection_id)) =
            connected_bridges_with(LocalTransport::new_with_loopback_groups).await;
        assert!(
            command_output(
                &mut dialer,
                IpcMessage::SendGroup {
                    connection_id,
                    request_handle: [84; 16],
                    deadline_ms: crate::supervisor::unix_time_ms().unwrap() + 5_000,
                    request: group_request(),
                },
            )
            .is_empty()
        );
        let mut event = next_group_event(&mut listener, &mut dialer).await;
        let TransportEvent::GroupRequest { deadline, .. } = &mut event else {
            panic!("expected a group request");
        };
        *deadline = Instant::now();
        let mut writer = FrameWriter::new(Vec::new(), IpcRole::Net, IpcRole::Core);
        listener.handle_event(event, &mut writer).unwrap();
        assert!(writer.into_inner().is_empty());
        assert!(listener.responses.is_empty());
    }

    #[tokio::test]
    async fn expired_group_send_is_rejected_before_transport() {
        let (_listener, (mut dialer, connection_id)) = connected_bridges().await;
        let now_ms = crate::supervisor::unix_time_ms().unwrap();
        // A live command on the default transport would fail as Transport, not TimedOut.
        assert_eq!(
            read_event(command_output(
                &mut dialer,
                IpcMessage::SendGroup {
                    connection_id,
                    request_handle: [83; 16],
                    deadline_ms: now_ms,
                    request: group_request(),
                },
            )),
            IpcMessage::RequestFailed {
                connection_id,
                request_id: [83; 16],
                protocol: NetworkProtocol::Group,
                code: NetworkErrorCode::TimedOut,
            }
        );
        assert!(dialer.requests.is_empty());
    }

    #[tokio::test]
    async fn default_transport_rejects_group_commands_without_retaining_requests() {
        let (_listener, (mut dialer, connection_id)) = connected_bridges().await;
        let request = group_request();
        let request_handle = [83; 16];
        assert_eq!(
            read_event(command_output(
                &mut dialer,
                IpcMessage::SendGroup {
                    connection_id,
                    request_handle,
                    deadline_ms: crate::supervisor::unix_time_ms().unwrap() + 5_000,
                    request,
                },
            )),
            IpcMessage::RequestFailed {
                connection_id,
                request_id: request_handle,
                protocol: NetworkProtocol::Group,
                code: NetworkErrorCode::Transport,
            }
        );
        assert!(dialer.requests.is_empty());
    }

    fn bulk_command(connection_id: [u8; 16], operation: BulkOperation, id: u8) -> IpcMessage {
        IpcMessage::SendBulk {
            connection_id,
            request: BulkRequest {
                operation,
                request_id: Id128([id; 16]),
                content_id: [id; 32].into(),
                lease_id: [4; 32].into(),
                chunk_index: 0,
            },
        }
    }

    async fn next_bulk_event(
        listener: &mut NetworkBridge,
        dialer: &mut NetworkBridge,
    ) -> TransportEvent {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let event = next_event_from_either(listener, dialer).await;
                match event {
                    TransportEvent::BulkRequest { .. } | TransportEvent::BulkResponse { .. } => {
                        break event;
                    }
                    TransportEvent::Disconnected { .. } | TransportEvent::RequestFailed { .. } => {
                        panic!("unexpected bulk transport failure: {event:?}");
                    }
                    _ => {}
                }
            }
        })
        .await
        .unwrap()
    }

    async fn receive_bulk_request(
        listener: &mut NetworkBridge,
        dialer: &mut NetworkBridge,
        listener_id: [u8; 16],
    ) -> ([u8; 16], BulkRequest) {
        let event = next_bulk_event(listener, dialer).await;
        match bridge_event(listener, event) {
            IpcMessage::BulkRequested {
                connection_id,
                response_id,
                request,
            } => {
                assert_eq!(connection_id, listener_id);
                (response_id, request)
            }
            event => panic!("unexpected bulk request event: {event:?}"),
        }
    }

    #[tokio::test]
    async fn outbound_bulk_capacity_is_shared_and_released_on_response() {
        let ((mut listener, listener_id), (mut dialer, connection_id)) = connected_bridges().await;

        // Queue mixed operations for different content before either transport is polled.
        for (operation, id) in [(BulkOperation::Manifest, 1), (BulkOperation::Chunk, 2)] {
            let command = bulk_command(connection_id, operation, id);
            assert!(command_output(&mut dialer, command).is_empty());
        }
        let inline = bulk_command(connection_id, BulkOperation::Inline, 3);
        assert_eq!(
            read_event(command_output(&mut dialer, inline.clone())),
            IpcMessage::RequestFailed {
                connection_id,
                request_id: [3; 16],
                protocol: NetworkProtocol::Bulk,
                code: NetworkErrorCode::Capacity,
            }
        );

        let (response_id, first) =
            receive_bulk_request(&mut listener, &mut dialer, listener_id).await;
        let (_, second) = receive_bulk_request(&mut listener, &mut dialer, listener_id).await;
        let mut accepted = [first.request_id.0, second.request_id.0];
        accepted.sort_unstable();
        assert_eq!(accepted, [[1; 16], [2; 16]]);

        let response = BulkResponse {
            request_id: first.request_id,
            status: BulkStatus::NotFound,
            payload: Vec::new(),
        };
        let reply = IpcMessage::ReplyBulk {
            connection_id: listener_id,
            response_id,
            response: response.clone(),
        };
        assert!(command_output(&mut listener, reply).is_empty());
        let event = next_bulk_event(&mut listener, &mut dialer).await;
        assert_eq!(
            bridge_event(&mut dialer, event),
            IpcMessage::BulkReceived {
                connection_id,
                request_id: first.request_id.0,
                response,
            }
        );

        assert!(command_output(&mut dialer, inline).is_empty());
        let (_, replacement) = receive_bulk_request(&mut listener, &mut dialer, listener_id).await;
        assert_eq!(replacement.request_id, Id128([3; 16]));
        assert_eq!(replacement.operation, BulkOperation::Inline);
    }

    #[tokio::test]
    async fn closing_connection_rejects_bulk_with_the_request_id() {
        let (_listener, (mut dialer, connection_id)) = connected_bridges().await;
        assert!(
            command_output(&mut dialer, IpcMessage::CloseConnection { connection_id }).is_empty()
        );
        let command = bulk_command(connection_id, BulkOperation::Manifest, 1);
        assert_eq!(
            read_event(command_output(&mut dialer, command)),
            IpcMessage::RequestFailed {
                connection_id,
                request_id: [1; 16],
                protocol: NetworkProtocol::Bulk,
                code: NetworkErrorCode::Disconnected,
            }
        );
    }
}
