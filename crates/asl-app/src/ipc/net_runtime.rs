use std::{
    collections::{HashMap, HashSet},
    io::{self, Stdin, Stdout, Write},
    thread,
    time::{Duration, Instant},
};

use asl_net::{
    codec::{BulkRequest, BulkResponse},
    transport::{
        AuthenticatedPeer, LocalConnectionId, LocalTransport, RequestToken, ResponseToken,
        TransportEvent,
    },
};
use asl_types::{
    error::AslError,
    protocol::{IdentityProof, WireFrame},
};
use rand::{TryRng, rngs::SysRng};
use tokio::{runtime::Builder, sync::mpsc};

use super::{FrameReader, FrameWriter, IpcMessage, IpcRole, NetworkErrorCode, NetworkProtocol};
use crate::identity::DeviceIdentity;

const COMMAND_QUEUE_CAPACITY: usize = 8;
const MAX_PENDING_IPC_REQUESTS: usize = 96;
const RESPONSE_HANDLE_LIFETIME: Duration = Duration::from_secs(10);
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
                self.send_operation_result(operation_id, result, writer)?;
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

    fn send_bulk<W: Write>(
        &mut self,
        connection_id: [u8; 16],
        request: BulkRequest,
        writer: &mut FrameWriter<W>,
    ) -> Result<(), NetworkErrorCode> {
        if self.closing.contains(&connection_id) {
            return Err(NetworkErrorCode::Disconnected);
        }
        let request_id = request.request_id.0;
        let key = (connection_id, request_id, NetworkProtocol::Bulk);
        if self.requests.contains_key(&key) {
            writer
                .send(&IpcMessage::RequestFailed {
                    connection_id,
                    request_id,
                    protocol: NetworkProtocol::Bulk,
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
                    protocol: NetworkProtocol::Bulk,
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
                    protocol: NetworkProtocol::Bulk,
                    code: NetworkErrorCode::Disconnected,
                })
                .map_err(|_| NetworkErrorCode::Transport)?;
            return Ok(());
        };
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
            Err(error) => writer
                .send(&IpcMessage::RequestFailed {
                    connection_id,
                    request_id,
                    protocol: NetworkProtocol::Bulk,
                    code: error_code(&error),
                })
                .map_err(|_| NetworkErrorCode::Transport)?,
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

    fn handle_event<W: Write>(
        &mut self,
        event: TransportEvent,
        writer: &mut FrameWriter<W>,
    ) -> Result<(), AslError> {
        match event {
            TransportEvent::Listening(kind, address) => {
                writer.send(&IpcMessage::Listening { kind, address })?;
            }
            TransportEvent::InboundRejected => {}
            TransportEvent::Connected { connection } => {
                let connection_id = fresh_handle(&self.connections)?;
                let peer_id = connection.peer_id().clone();
                self.connection_handles
                    .insert(connection.connection_id(), connection_id);
                self.connections.insert(connection_id, connection);
                writer.send(&IpcMessage::PeerAuthenticated {
                    connection_id,
                    peer_id,
                })?;
            }
            TransportEvent::Disconnected { connection_id, .. } => {
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
        let local_id = connection.connection_id();
        let Some(&connection_id) = self.connection_handles.get(&local_id) else {
            return Ok(());
        };
        if self.closing.contains(&connection_id) {
            return Ok(());
        }
        let response_id = fresh_handle(&self.responses)?;
        self.responses.insert(
            response_id,
            PendingResponse {
                connection_id,
                protocol,
                token,
                expires_at: Instant::now() + RESPONSE_HANDLE_LIFETIME,
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
    use asl_net::transport::TransportKind;
    use asl_types::ids::{Id128, PeerId};
    use asl_types::protocol::{Ack, WireFrame};
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

    #[tokio::test]
    async fn control_round_trip_crosses_both_driver_handle_mappings() {
        let listener_key = Keypair::generate_ed25519();
        let listener_peer = peer_id(&listener_key);
        let mut listener = NetworkBridge::new(LocalTransport::new(listener_key).unwrap());
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
        let mut dialer = NetworkBridge::new(LocalTransport::new(dialer_key).unwrap());
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
        let dialer_event = dialer_event.unwrap();

        let mut dialer_bytes = Vec::new();
        {
            let mut writer = FrameWriter::new(&mut dialer_bytes, IpcRole::Net, IpcRole::Core);
            dialer.handle_event(dialer_event, &mut writer).unwrap();
        }
        let dialer_connection_id = match read_event(dialer_bytes) {
            IpcMessage::PeerAuthenticated {
                connection_id,
                peer_id,
            } => {
                assert_eq!(peer_id, listener_peer);
                connection_id
            }
            event => panic!("unexpected dialer connection event: {event:?}"),
        };

        let mut connected_bytes = Vec::new();
        {
            let mut writer = FrameWriter::new(&mut connected_bytes, IpcRole::Net, IpcRole::Core);
            listener
                .handle_event(listener_event.unwrap(), &mut writer)
                .unwrap();
        }
        let connection_id = match read_event(connected_bytes) {
            IpcMessage::PeerAuthenticated {
                connection_id,
                peer_id,
            } => {
                assert_eq!(peer_id, dialer_peer);
                connection_id
            }
            event => panic!("unexpected bridge event: {event:?}"),
        };

        let request = WireFrame::Ack(Ack {
            message_id: Id128([61; 16]),
            received_id: Id128([62; 16]),
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
        {
            let mut writer = FrameWriter::new(&mut ignored_output, IpcRole::Net, IpcRole::Core);
            assert!(
                !listener
                    .handle_command(
                        IpcMessage::ReplyControl {
                            connection_id,
                            response_id,
                            response: WireFrame::Ack(Ack {
                                message_id: Id128([63; 16]),
                                received_id: Id128([61; 16]),
                            }),
                        },
                        &mut writer,
                    )
                    .unwrap()
            );
        }
        let response = WireFrame::Ack(Ack {
            message_id: Id128([63; 16]),
            received_id: Id128([61; 16]),
        });

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
}
