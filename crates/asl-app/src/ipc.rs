use std::env;
use std::io::{Read, Write};

use asl_net::{
    address_policy::AddressPolicy,
    codec::{BulkOperation, BulkRequest, BulkResponse, BulkStatus},
    dht::MAX_DHT_VALUE_BYTES,
    relay::MAX_RELAY_ENDPOINT_BYTES,
    transport::{DiscoveryCandidateState, TransportKind},
};
use asl_types::{
    error::AslError,
    ids::PeerId,
    manifest::MAX_MANIFEST_LEN,
    protocol::{
        IdentityProof, IdentityProofRequest, MAX_CONTROL_FRAME_BYTES, MAX_EXTENDED_FRAME_BYTES,
        WireFrame, decode_control, decode_frame as decode_asl_frame, encode_control,
        encode_frame as encode_asl_frame,
    },
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use zeroize::Zeroizing;

use crate::identity::{DeviceIdentity, MAX_DEVICE_KEY_BYTES};

mod net_runtime;

pub const MAX_IPC_FRAME_BYTES: usize = 4 * 1024 * 1024;
const HEADER_BYTES: usize = 20;
const TASK_BODY_HEADER_BYTES: usize = 21;
const DEVICE_IDENTITY_PRELUDE_MAGIC: [u8; 4] = *b"ASLK";
const DEVICE_IDENTITY_PRELUDE_VERSION: u16 = 1;
const DEVICE_IDENTITY_PRELUDE_HEADER_BYTES: usize = 10;
const MAX_DEVICE_IDENTITY_PRELUDE_BYTES: usize = MAX_DEVICE_KEY_BYTES;
pub const MAX_IPC_TASK_PAYLOAD_BYTES: usize =
    MAX_IPC_FRAME_BYTES - HEADER_BYTES - TASK_BODY_HEADER_BYTES;
pub const MAX_IPC_IDENTITY_PROOF_FRAME_BYTES: usize = MAX_EXTENDED_FRAME_BYTES;
pub const MAX_IPC_BULK_PAYLOAD_BYTES: usize = MAX_MANIFEST_LEN;
const MAGIC: [u8; 4] = *b"ASLI";
const VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum IpcRole {
    Core = 1,
    Net = 2,
    Worker = 3,
    Extractor = 4,
}

impl IpcRole {
    fn permits(self, receiver: Self, kind: u8) -> bool {
        matches!(
            (self, receiver, kind),
            (
                Self::Core,
                Self::Net | Self::Worker | Self::Extractor,
                2 | 4
            ) | (Self::Core, Self::Net, 14 | 15 | 17 | 18 | 24 | 25 | 28 | 29 | 33 | 40)
                | (Self::Core, Self::Net, 34 | 35)
                | (Self::Core, Self::Net, 32)
                | (Self::Core, Self::Worker, 6 | 9)
                | (
                    Self::Net | Self::Worker | Self::Extractor,
                    Self::Core,
                    1 | 3 | 5
                )
                | (Self::Net, Self::Core, 10..=13)
                | (Self::Net, Self::Core, 16 | 19..=23 | 26..=27 | 30..=31)
                | (Self::Net, Self::Core, 36..=39)
                | (Self::Worker | Self::Extractor, Self::Core, 7)
                | (Self::Worker, Self::Core, 8)
        )
    }

    pub(crate) fn startup_argument(self) -> Option<&'static str> {
        match self {
            Self::Core => None,
            Self::Net => Some("--asl-role=net"),
            Self::Worker => Some("--asl-role=worker"),
            Self::Extractor => Some("--asl-role=extractor"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WorkerOperation {
    ValidateControlFrame = 1,
}

impl WorkerOperation {
    fn from_wire(value: u8) -> Result<Self, AslError> {
        match value {
            1 => Ok(Self::ValidateControlFrame),
            _ => Err(AslError::InvalidMessage),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TaskStatus {
    Valid = 1,
    Invalid = 2,
}

impl TaskStatus {
    fn from_wire(value: u8) -> Result<Self, AslError> {
        match value {
            1 => Ok(Self::Valid),
            2 => Ok(Self::Invalid),
            _ => Err(AslError::InvalidMessage),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IpcMessage {
    Ready,
    Shutdown,
    Stopped,
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
    RunTask {
        task_id: [u8; 16],
        operation: WorkerOperation,
        payload: Vec<u8>,
    },
    TaskResult {
        task_id: [u8; 16],
        status: TaskStatus,
    },
    TaskStarted {
        task_id: [u8; 16],
    },
    TaskContinue {
        task_id: [u8; 16],
    },
    PeerAuthenticated {
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
    NetReady {
        peer_id: PeerId,
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
    ReserveRelay {
        operation_id: [u8; 16],
        address: Vec<u8>,
    },
    DialViaRelays {
        operation_id: [u8; 16],
        peer_id: PeerId,
    },
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
    ControlRequested {
        connection_id: [u8; 16],
        response_id: [u8; 16],
        request: WireFrame,
    },
    ControlReceived {
        connection_id: [u8; 16],
        request_id: [u8; 16],
        response: WireFrame,
    },
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
    BulkRequested {
        connection_id: [u8; 16],
        response_id: [u8; 16],
        request: BulkRequest,
    },
    BulkReceived {
        connection_id: [u8; 16],
        response: BulkResponse,
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
    RequestFailed {
        connection_id: [u8; 16],
        request_id: [u8; 16],
        protocol: NetworkProtocol,
        code: NetworkErrorCode,
    },
    NetworkError {
        code: NetworkErrorCode,
    },
    CloseConnection {
        connection_id: [u8; 16],
    },
    SetAddressPolicy {
        operation_id: [u8; 16],
        policy: AddressPolicy,
    },
    DecideDhtRecord {
        candidate_id: [u8; 16],
        accept: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum NetworkProtocol {
    Control = 1,
    IdentityProof = 2,
    Bulk = 3,
}

impl NetworkProtocol {
    fn from_wire(value: u8) -> Result<Self, AslError> {
        match value {
            1 => Ok(Self::Control),
            2 => Ok(Self::IdentityProof),
            3 => Ok(Self::Bulk),
            _ => Err(AslError::InvalidMessage),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NetworkErrorCode {
    InvalidCommand = 1,
    Capacity = 2,
    Disconnected = 3,
    TimedOut = 4,
    Transport = 5,
}

impl NetworkErrorCode {
    fn from_wire(value: u8) -> Result<Self, AslError> {
        match value {
            1 => Ok(Self::InvalidCommand),
            2 => Ok(Self::Capacity),
            3 => Ok(Self::Disconnected),
            4 => Ok(Self::TimedOut),
            5 => Ok(Self::Transport),
            _ => Err(AslError::InvalidMessage),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IpcFrame {
    pub role: IpcRole,
    pub sequence: u64,
    pub message: IpcMessage,
}

pub fn encode_frame(
    sender: IpcRole,
    receiver: IpcRole,
    sequence: u64,
    message: &IpcMessage,
) -> Result<Vec<u8>, AslError> {
    if sequence == 0 {
        return Err(AslError::InvalidMessage);
    }

    let (kind, body) = encode_message(message)?;
    if !sender.permits(receiver, kind) {
        return Err(AslError::InvalidMessage);
    }
    let total = HEADER_BYTES
        .checked_add(body.len())
        .filter(|length| *length <= MAX_IPC_FRAME_BYTES)
        .ok_or(AslError::InvalidMessage)?;
    let body_len = u32::try_from(body.len()).map_err(|_| AslError::InvalidMessage)?;
    let mut frame = Vec::with_capacity(total);
    frame.extend_from_slice(&MAGIC);
    frame.extend_from_slice(&VERSION.to_be_bytes());
    frame.push(sender as u8);
    frame.push(kind);
    frame.extend_from_slice(&sequence.to_be_bytes());
    frame.extend_from_slice(&body_len.to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

pub fn decode_frame(
    bytes: &[u8],
    expected_sender: IpcRole,
    receiver: IpcRole,
    expected_sequence: u64,
) -> Result<IpcFrame, AslError> {
    if bytes.len() < HEADER_BYTES || bytes.len() > MAX_IPC_FRAME_BYTES {
        return Err(AslError::InvalidMessage);
    }
    let (kind, body_len) = decode_header(
        bytes[..HEADER_BYTES].try_into().unwrap(),
        expected_sender,
        receiver,
        expected_sequence,
    )?;
    if bytes.len() - HEADER_BYTES != body_len {
        return Err(AslError::InvalidMessage);
    }
    Ok(IpcFrame {
        role: expected_sender,
        sequence: expected_sequence,
        message: decode_message(kind, &bytes[HEADER_BYTES..])?,
    })
}

fn decode_header(
    header: &[u8; HEADER_BYTES],
    expected_sender: IpcRole,
    receiver: IpcRole,
    expected_sequence: u64,
) -> Result<(u8, usize), AslError> {
    let kind = header[7];
    let sequence = u64::from_be_bytes(header[8..16].try_into().unwrap());
    let body_len = u32::from_be_bytes(header[16..20].try_into().unwrap()) as usize;
    if header[..4] != MAGIC
        || header[4..6] != VERSION.to_be_bytes()
        || header[6] != expected_sender as u8
        || !expected_sender.permits(receiver, kind)
        || sequence != expected_sequence
        || sequence == 0
        || max_body_bytes(kind).is_none_or(|limit| body_len > limit)
    {
        return Err(AslError::InvalidMessage);
    }
    Ok((kind, body_len))
}

fn encode_message(message: &IpcMessage) -> Result<(u8, Vec<u8>), AslError> {
    let mut body = Vec::new();
    let kind = match message {
        IpcMessage::Ready => 1,
        IpcMessage::Shutdown => 2,
        IpcMessage::Stopped => 3,
        IpcMessage::Ping { nonce } => {
            body.extend_from_slice(&nonce.to_be_bytes());
            4
        }
        IpcMessage::Pong { nonce } => {
            body.extend_from_slice(&nonce.to_be_bytes());
            5
        }
        IpcMessage::RunTask {
            task_id,
            operation,
            payload,
        } => {
            if payload.len() > MAX_IPC_TASK_PAYLOAD_BYTES {
                return Err(AslError::InvalidMessage);
            }
            body.extend_from_slice(task_id);
            body.push(*operation as u8);
            body.extend_from_slice(
                &u32::try_from(payload.len())
                    .map_err(|_| AslError::InvalidMessage)?
                    .to_be_bytes(),
            );
            body.extend_from_slice(payload);
            6
        }
        IpcMessage::TaskResult { task_id, status } => {
            body.extend_from_slice(task_id);
            body.push(*status as u8);
            7
        }
        IpcMessage::TaskStarted { task_id } => {
            body.extend_from_slice(task_id);
            8
        }
        IpcMessage::TaskContinue { task_id } => {
            body.extend_from_slice(task_id);
            9
        }
        IpcMessage::PeerAuthenticated {
            connection_id,
            peer_id,
        } => {
            let peer_bytes = peer_id.as_bytes();
            body.extend_from_slice(connection_id);
            body.extend_from_slice(
                &u16::try_from(peer_bytes.len())
                    .map_err(|_| AslError::InvalidMessage)?
                    .to_be_bytes(),
            );
            body.extend_from_slice(peer_bytes);
            10
        }
        IpcMessage::PeerDisconnected { connection_id } => {
            body.extend_from_slice(connection_id);
            11
        }
        IpcMessage::IdentityProofRequested {
            connection_id,
            response_id,
            request,
        } => {
            body.extend_from_slice(connection_id);
            body.extend_from_slice(response_id);
            append_identity_frame(&mut body, &WireFrame::IdentityProofRequest(request.clone()))?;
            12
        }
        IpcMessage::IdentityProofReceived {
            connection_id,
            proof,
        } => {
            body.extend_from_slice(connection_id);
            append_identity_frame(&mut body, &WireFrame::IdentityProof(proof.clone()))?;
            13
        }
        IpcMessage::NetReady { peer_id } => {
            let peer_bytes = peer_id.as_bytes();
            body.extend_from_slice(
                &u16::try_from(peer_bytes.len())
                    .map_err(|_| AslError::InvalidMessage)?
                    .to_be_bytes(),
            );
            body.extend_from_slice(peer_bytes);
            16
        }
        IpcMessage::RequestIdentityProof {
            connection_id,
            request,
        } => {
            body.extend_from_slice(connection_id);
            append_identity_frame(&mut body, &WireFrame::IdentityProofRequest(request.clone()))?;
            14
        }
        IpcMessage::ReplyIdentityProof {
            connection_id,
            response_id,
            proof,
        } => {
            body.extend_from_slice(connection_id);
            body.extend_from_slice(response_id);
            append_identity_frame(&mut body, &WireFrame::IdentityProof(proof.clone()))?;
            15
        }
        IpcMessage::Listen {
            operation_id,
            kind,
            address,
        } => {
            body.extend_from_slice(operation_id);
            body.push(transport_kind_code(*kind));
            append_socket_addr(&mut body, *address)?;
            17
        }
        IpcMessage::Dial {
            operation_id,
            kind,
            address,
            peer_id,
        } => {
            body.extend_from_slice(operation_id);
            body.push(transport_kind_code(*kind));
            append_socket_addr(&mut body, *address)?;
            let peer_bytes = peer_id.as_bytes();
            body.extend_from_slice(
                &u16::try_from(peer_bytes.len())
                    .map_err(|_| AslError::InvalidMessage)?
                    .to_be_bytes(),
            );
            body.extend_from_slice(peer_bytes);
            18
        }
        IpcMessage::ReserveRelay {
            operation_id,
            address,
        } => {
            if address.is_empty() || address.len() > MAX_RELAY_ENDPOINT_BYTES {
                return Err(AslError::InvalidMessage);
            }
            body.extend_from_slice(operation_id);
            body.extend_from_slice(
                &u16::try_from(address.len())
                    .map_err(|_| AslError::InvalidMessage)?
                    .to_be_bytes(),
            );
            body.extend_from_slice(address);
            34
        }
        IpcMessage::DialViaRelays {
            operation_id,
            peer_id,
        } => {
            body.extend_from_slice(operation_id);
            let peer_bytes = peer_id.as_bytes();
            body.extend_from_slice(
                &u16::try_from(peer_bytes.len())
                    .map_err(|_| AslError::InvalidMessage)?
                    .to_be_bytes(),
            );
            body.extend_from_slice(peer_bytes);
            35
        }
        IpcMessage::OperationAccepted { operation_id } => {
            body.extend_from_slice(operation_id);
            19
        }
        IpcMessage::OperationFailed { operation_id, code } => {
            body.extend_from_slice(operation_id);
            body.push(*code as u8);
            20
        }
        IpcMessage::Listening { kind, address } => {
            body.push(transport_kind_code(*kind));
            append_socket_addr(&mut body, *address)?;
            21
        }
        IpcMessage::RelayReserved {
            relay_peer_id,
            address,
        } => {
            if address.is_empty() || address.len() > MAX_RELAY_ENDPOINT_BYTES {
                return Err(AslError::InvalidMessage);
            }
            let peer_bytes = relay_peer_id.as_bytes();
            body.extend_from_slice(
                &u16::try_from(peer_bytes.len())
                    .map_err(|_| AslError::InvalidMessage)?
                    .to_be_bytes(),
            );
            body.extend_from_slice(peer_bytes);
            body.extend_from_slice(
                &u16::try_from(address.len())
                    .map_err(|_| AslError::InvalidMessage)?
                    .to_be_bytes(),
            );
            body.extend_from_slice(address);
            36
        }
        IpcMessage::RelayUnavailable { relay_peer_id } => {
            let peer_bytes = relay_peer_id.as_bytes();
            if peer_bytes.is_empty() || peer_bytes.len() > 128 {
                return Err(AslError::InvalidMessage);
            }
            body.extend_from_slice(
                &u16::try_from(peer_bytes.len())
                    .map_err(|_| AslError::InvalidMessage)?
                    .to_be_bytes(),
            );
            body.extend_from_slice(peer_bytes);
            37
        }
        IpcMessage::DiscoveryCandidate {
            peer_id,
            kind,
            address,
            state,
        } => {
            let peer_bytes = peer_id.as_bytes();
            if peer_bytes.is_empty() || peer_bytes.len() > 128 {
                return Err(AslError::InvalidMessage);
            }
            body.extend_from_slice(
                &u16::try_from(peer_bytes.len())
                    .map_err(|_| AslError::InvalidMessage)?
                    .to_be_bytes(),
            );
            body.extend_from_slice(peer_bytes);
            body.push(transport_kind_code(*kind));
            append_socket_addr(&mut body, *address)?;
            body.push(*state as u8);
            38
        }
        IpcMessage::ControlRequested {
            connection_id,
            response_id,
            request,
        } => {
            body.extend_from_slice(connection_id);
            body.extend_from_slice(response_id);
            append_control_frame(&mut body, request)?;
            22
        }
        IpcMessage::ControlReceived {
            connection_id,
            request_id,
            response,
        } => {
            body.extend_from_slice(connection_id);
            body.extend_from_slice(request_id);
            append_control_frame(&mut body, response)?;
            23
        }
        IpcMessage::SendControl {
            connection_id,
            request_id,
            request,
        } => {
            body.extend_from_slice(connection_id);
            body.extend_from_slice(request_id);
            append_control_frame(&mut body, request)?;
            24
        }
        IpcMessage::ReplyControl {
            connection_id,
            response_id,
            response,
        } => {
            body.extend_from_slice(connection_id);
            body.extend_from_slice(response_id);
            append_control_frame(&mut body, response)?;
            25
        }
        IpcMessage::BulkRequested {
            connection_id,
            response_id,
            request,
        } => {
            body.extend_from_slice(connection_id);
            body.extend_from_slice(response_id);
            append_bulk_request(&mut body, request);
            26
        }
        IpcMessage::BulkReceived {
            connection_id,
            response,
        } => {
            body.extend_from_slice(connection_id);
            append_bulk_response(&mut body, response)?;
            27
        }
        IpcMessage::SendBulk {
            connection_id,
            request,
        } => {
            body.extend_from_slice(connection_id);
            append_bulk_request(&mut body, request);
            28
        }
        IpcMessage::ReplyBulk {
            connection_id,
            response_id,
            response,
        } => {
            body.extend_from_slice(connection_id);
            body.extend_from_slice(response_id);
            append_bulk_response(&mut body, response)?;
            29
        }
        IpcMessage::RequestFailed {
            connection_id,
            request_id,
            protocol,
            code,
        } => {
            body.extend_from_slice(connection_id);
            body.extend_from_slice(request_id);
            body.push(*protocol as u8);
            body.push(*code as u8);
            30
        }
        IpcMessage::NetworkError { code } => {
            body.push(*code as u8);
            31
        }
        IpcMessage::CloseConnection { connection_id } => {
            body.extend_from_slice(connection_id);
            32
        }
        IpcMessage::SetAddressPolicy {
            operation_id,
            policy,
        } => {
            body.extend_from_slice(operation_id);
            body.push(address_policy_code(*policy));
            33
        }
        IpcMessage::DhtRecordCandidate {
            candidate_id,
            key,
            value,
        } => {
            if *candidate_id == [0; 16] || value.is_empty() || value.len() > MAX_DHT_VALUE_BYTES {
                return Err(AslError::InvalidMessage);
            }
            body.extend_from_slice(candidate_id);
            body.extend_from_slice(key);
            body.extend_from_slice(
                &u16::try_from(value.len())
                    .map_err(|_| AslError::InvalidMessage)?
                    .to_be_bytes(),
            );
            body.extend_from_slice(value);
            39
        }
        IpcMessage::DecideDhtRecord {
            candidate_id,
            accept,
        } => {
            if *candidate_id == [0; 16] {
                return Err(AslError::InvalidMessage);
            }
            body.extend_from_slice(candidate_id);
            body.push(u8::from(*accept));
            40
        }
    };
    if HEADER_BYTES + body.len() > MAX_IPC_FRAME_BYTES {
        return Err(AslError::InvalidMessage);
    }
    Ok((kind, body))
}

fn decode_message(kind: u8, body: &[u8]) -> Result<IpcMessage, AslError> {
    match kind {
        1 if body.is_empty() => Ok(IpcMessage::Ready),
        2 if body.is_empty() => Ok(IpcMessage::Shutdown),
        3 if body.is_empty() => Ok(IpcMessage::Stopped),
        4 if body.len() == 8 => Ok(IpcMessage::Ping {
            nonce: u64::from_be_bytes(body.try_into().unwrap()),
        }),
        5 if body.len() == 8 => Ok(IpcMessage::Pong {
            nonce: u64::from_be_bytes(body.try_into().unwrap()),
        }),
        6 if body.len() >= TASK_BODY_HEADER_BYTES => {
            let task_id = body[..16].try_into().unwrap();
            let operation = WorkerOperation::from_wire(body[16])?;
            let payload_len = u32::from_be_bytes(body[17..21].try_into().unwrap()) as usize;
            let expected_len = TASK_BODY_HEADER_BYTES
                .checked_add(payload_len)
                .ok_or(AslError::InvalidMessage)?;
            if body.len() != expected_len {
                return Err(AslError::InvalidMessage);
            }
            Ok(IpcMessage::RunTask {
                task_id,
                operation,
                payload: body[TASK_BODY_HEADER_BYTES..].to_vec(),
            })
        }
        7 if body.len() == 17 => Ok(IpcMessage::TaskResult {
            task_id: body[..16].try_into().unwrap(),
            status: TaskStatus::from_wire(body[16])?,
        }),
        8 if body.len() == 16 => Ok(IpcMessage::TaskStarted {
            task_id: body.try_into().unwrap(),
        }),
        9 if body.len() == 16 => Ok(IpcMessage::TaskContinue {
            task_id: body.try_into().unwrap(),
        }),
        10 if body.len() >= 18 => {
            let peer_length = u16::from_be_bytes(body[16..18].try_into().unwrap()) as usize;
            if body.len() != 18 + peer_length {
                return Err(AslError::InvalidMessage);
            }
            let peer_id =
                PeerId::from_bytes(body[18..].to_vec()).map_err(|_| AslError::InvalidMessage)?;
            Ok(IpcMessage::PeerAuthenticated {
                connection_id: body[..16].try_into().unwrap(),
                peer_id,
            })
        }
        11 if body.len() == 16 => Ok(IpcMessage::PeerDisconnected {
            connection_id: body.try_into().unwrap(),
        }),
        12 if body.len() >= 36 => Ok(IpcMessage::IdentityProofRequested {
            connection_id: body[..16].try_into().unwrap(),
            response_id: body[16..32].try_into().unwrap(),
            request: decode_identity_request(&body[32..])?,
        }),
        13 if body.len() >= 20 => Ok(IpcMessage::IdentityProofReceived {
            connection_id: body[..16].try_into().unwrap(),
            proof: decode_identity_proof(&body[16..])?,
        }),
        14 if body.len() >= 20 => Ok(IpcMessage::RequestIdentityProof {
            connection_id: body[..16].try_into().unwrap(),
            request: decode_identity_request(&body[16..])?,
        }),
        15 if body.len() >= 36 => Ok(IpcMessage::ReplyIdentityProof {
            connection_id: body[..16].try_into().unwrap(),
            response_id: body[16..32].try_into().unwrap(),
            proof: decode_identity_proof(&body[32..])?,
        }),
        16 if body.len() >= 3 => {
            let peer_length = u16::from_be_bytes(body[..2].try_into().unwrap()) as usize;
            if body.len() != 2 + peer_length {
                return Err(AslError::InvalidMessage);
            }
            let peer_id =
                PeerId::from_bytes(body[2..].to_vec()).map_err(|_| AslError::InvalidMessage)?;
            Ok(IpcMessage::NetReady { peer_id })
        }
        17 if body.len() >= 24 => {
            let kind = decode_transport_kind(body[16])?;
            let (address, length) = decode_socket_addr(&body[17..])?;
            if 17 + length != body.len() {
                return Err(AslError::InvalidMessage);
            }
            Ok(IpcMessage::Listen {
                operation_id: body[..16].try_into().unwrap(),
                kind,
                address,
            })
        }
        18 if body.len() >= 26 => {
            let kind = decode_transport_kind(body[16])?;
            let (address, address_length) = decode_socket_addr(&body[17..])?;
            let peer_length_offset = 17 + address_length;
            if body.len() < peer_length_offset + 2 {
                return Err(AslError::InvalidMessage);
            }
            let peer_length = u16::from_be_bytes(
                body[peer_length_offset..peer_length_offset + 2]
                    .try_into()
                    .unwrap(),
            ) as usize;
            let peer_offset = peer_length_offset + 2;
            if body.len() != peer_offset + peer_length {
                return Err(AslError::InvalidMessage);
            }
            let peer_id = PeerId::from_bytes(body[peer_offset..].to_vec())
                .map_err(|_| AslError::InvalidMessage)?;
            Ok(IpcMessage::Dial {
                operation_id: body[..16].try_into().unwrap(),
                kind,
                address,
                peer_id,
            })
        }
        34 if body.len() >= 19 => {
            let address_len = u16::from_be_bytes(body[16..18].try_into().unwrap()) as usize;
            if address_len == 0
                || address_len > MAX_RELAY_ENDPOINT_BYTES
                || body.len() != 18 + address_len
            {
                return Err(AslError::InvalidMessage);
            }
            Ok(IpcMessage::ReserveRelay {
                operation_id: body[..16].try_into().unwrap(),
                address: body[18..].to_vec(),
            })
        }
        35 if body.len() >= 19 => {
            let peer_len = u16::from_be_bytes(body[16..18].try_into().unwrap()) as usize;
            if peer_len == 0 || body.len() != 18 + peer_len {
                return Err(AslError::InvalidMessage);
            }
            Ok(IpcMessage::DialViaRelays {
                operation_id: body[..16].try_into().unwrap(),
                peer_id: PeerId::from_bytes(body[18..].to_vec())
                    .map_err(|_| AslError::InvalidMessage)?,
            })
        }
        19 if body.len() == 16 => Ok(IpcMessage::OperationAccepted {
            operation_id: body.try_into().unwrap(),
        }),
        20 if body.len() == 17 => Ok(IpcMessage::OperationFailed {
            operation_id: body[..16].try_into().unwrap(),
            code: NetworkErrorCode::from_wire(body[16])?,
        }),
        21 if body.len() >= 8 => {
            let kind = decode_transport_kind(body[0])?;
            let (address, length) = decode_socket_addr(&body[1..])?;
            if 1 + length != body.len() {
                return Err(AslError::InvalidMessage);
            }
            Ok(IpcMessage::Listening { kind, address })
        }
        36 if body.len() >= 6 => {
            let peer_len = u16::from_be_bytes(body[..2].try_into().unwrap()) as usize;
            let peer_offset = 2 + peer_len;
            if peer_len == 0 || body.len() < peer_offset + 2 {
                return Err(AslError::InvalidMessage);
            }
            let address_len =
                u16::from_be_bytes(body[peer_offset..peer_offset + 2].try_into().unwrap()) as usize;
            if address_len == 0
                || address_len > MAX_RELAY_ENDPOINT_BYTES
                || body.len() != peer_offset + 2 + address_len
            {
                return Err(AslError::InvalidMessage);
            }
            Ok(IpcMessage::RelayReserved {
                relay_peer_id: PeerId::from_bytes(body[2..peer_offset].to_vec())
                    .map_err(|_| AslError::InvalidMessage)?,
                address: body[peer_offset + 2..].to_vec(),
            })
        }
        37 if body.len() >= 3 => {
            let peer_len = u16::from_be_bytes(body[..2].try_into().unwrap()) as usize;
            if peer_len == 0 || peer_len > 128 || body.len() != 2 + peer_len {
                return Err(AslError::InvalidMessage);
            }
            Ok(IpcMessage::RelayUnavailable {
                relay_peer_id: PeerId::from_bytes(body[2..].to_vec())
                    .map_err(|_| AslError::InvalidMessage)?,
            })
        }
        38 if body.len() >= 11 => {
            let peer_len = u16::from_be_bytes(body[..2].try_into().unwrap()) as usize;
            let peer_end = 2 + peer_len;
            if peer_len == 0 || peer_len > 128 || body.len() < peer_end + 1 {
                return Err(AslError::InvalidMessage);
            }
            let kind = decode_transport_kind(body[peer_end])?;
            let (address, address_len) = decode_socket_addr(&body[peer_end + 1..])?;
            let state_offset = peer_end + 1 + address_len;
            if body.len() != state_offset + 1 {
                return Err(AslError::InvalidMessage);
            }
            let state = match body[state_offset] {
                1 => DiscoveryCandidateState::Discovered,
                2 => DiscoveryCandidateState::Expired,
                _ => return Err(AslError::InvalidMessage),
            };
            Ok(IpcMessage::DiscoveryCandidate {
                peer_id: PeerId::from_bytes(body[2..peer_end].to_vec())
                    .map_err(|_| AslError::InvalidMessage)?,
                kind,
                address,
                state,
            })
        }
        39 if body.len() >= 51 => {
            let value_len = u16::from_be_bytes(body[48..50].try_into().unwrap()) as usize;
            if body[..16] == [0; 16]
                || value_len == 0
                || value_len > MAX_DHT_VALUE_BYTES
                || body.len() != 50 + value_len
            {
                return Err(AslError::InvalidMessage);
            }
            Ok(IpcMessage::DhtRecordCandidate {
                candidate_id: body[..16].try_into().unwrap(),
                key: body[16..48].try_into().unwrap(),
                value: body[50..].to_vec(),
            })
        }
        40 if body.len() == 17 && body[..16] != [0; 16] && body[16] <= 1 => {
            Ok(IpcMessage::DecideDhtRecord {
                candidate_id: body[..16].try_into().unwrap(),
                accept: body[16] == 1,
            })
        }
        22 if body.len() >= 36 => Ok(IpcMessage::ControlRequested {
            connection_id: body[..16].try_into().unwrap(),
            response_id: body[16..32].try_into().unwrap(),
            request: decode_control_frame(&body[32..])?,
        }),
        23 if body.len() >= 36 => Ok(IpcMessage::ControlReceived {
            connection_id: body[..16].try_into().unwrap(),
            request_id: body[16..32].try_into().unwrap(),
            response: decode_control_frame(&body[32..])?,
        }),
        24 if body.len() >= 36 => Ok(IpcMessage::SendControl {
            connection_id: body[..16].try_into().unwrap(),
            request_id: body[16..32].try_into().unwrap(),
            request: decode_control_frame(&body[32..])?,
        }),
        25 if body.len() >= 36 => Ok(IpcMessage::ReplyControl {
            connection_id: body[..16].try_into().unwrap(),
            response_id: body[16..32].try_into().unwrap(),
            response: decode_control_frame(&body[32..])?,
        }),
        26 if body.len() == 16 + 16 + BULK_REQUEST_IPC_BYTES => Ok(IpcMessage::BulkRequested {
            connection_id: body[..16].try_into().unwrap(),
            response_id: body[16..32].try_into().unwrap(),
            request: decode_bulk_request(&body[32..])?,
        }),
        27 if body.len() >= 37 => Ok(IpcMessage::BulkReceived {
            connection_id: body[..16].try_into().unwrap(),
            response: decode_bulk_response(&body[16..])?,
        }),
        28 if body.len() == 16 + BULK_REQUEST_IPC_BYTES => Ok(IpcMessage::SendBulk {
            connection_id: body[..16].try_into().unwrap(),
            request: decode_bulk_request(&body[16..])?,
        }),
        29 if body.len() >= 53 => Ok(IpcMessage::ReplyBulk {
            connection_id: body[..16].try_into().unwrap(),
            response_id: body[16..32].try_into().unwrap(),
            response: decode_bulk_response(&body[32..])?,
        }),
        30 if body.len() == 34 => Ok(IpcMessage::RequestFailed {
            connection_id: body[..16].try_into().unwrap(),
            request_id: body[16..32].try_into().unwrap(),
            protocol: NetworkProtocol::from_wire(body[32])?,
            code: NetworkErrorCode::from_wire(body[33])?,
        }),
        31 if body.len() == 1 => Ok(IpcMessage::NetworkError {
            code: NetworkErrorCode::from_wire(body[0])?,
        }),
        32 if body.len() == 16 => Ok(IpcMessage::CloseConnection {
            connection_id: body.try_into().unwrap(),
        }),
        33 if body.len() == 17 => Ok(IpcMessage::SetAddressPolicy {
            operation_id: body[..16].try_into().unwrap(),
            policy: decode_address_policy(body[16])?,
        }),
        _ => Err(AslError::InvalidMessage),
    }
}

fn append_identity_frame(body: &mut Vec<u8>, frame: &WireFrame) -> Result<(), AslError> {
    let bytes = encode_asl_frame(frame)?;
    if bytes.len() > MAX_IPC_IDENTITY_PROOF_FRAME_BYTES {
        return Err(AslError::InvalidMessage);
    }
    body.extend_from_slice(
        &u32::try_from(bytes.len())
            .map_err(|_| AslError::InvalidMessage)?
            .to_be_bytes(),
    );
    body.extend_from_slice(&bytes);
    Ok(())
}

fn decode_identity_request(bytes: &[u8]) -> Result<IdentityProofRequest, AslError> {
    match decode_identity_frame(bytes)? {
        WireFrame::IdentityProofRequest(request) => Ok(request),
        _ => Err(AslError::InvalidMessage),
    }
}

fn decode_identity_proof(bytes: &[u8]) -> Result<IdentityProof, AslError> {
    match decode_identity_frame(bytes)? {
        WireFrame::IdentityProof(proof) => Ok(proof),
        _ => Err(AslError::InvalidMessage),
    }
}

fn decode_identity_frame(bytes: &[u8]) -> Result<WireFrame, AslError> {
    if bytes.len() < 4 {
        return Err(AslError::InvalidMessage);
    }
    let frame_length = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    if frame_length == 0
        || frame_length > MAX_IPC_IDENTITY_PROOF_FRAME_BYTES
        || bytes.len() != 4 + frame_length
    {
        return Err(AslError::InvalidMessage);
    }
    decode_asl_frame(&bytes[4..])
}

const BULK_REQUEST_IPC_BYTES: usize = 85;
const BULK_RESPONSE_HEADER_IPC_BYTES: usize = 21;

fn append_control_frame(body: &mut Vec<u8>, frame: &WireFrame) -> Result<(), AslError> {
    if !frame.is_control() {
        return Err(AslError::InvalidMessage);
    }
    let bytes = encode_control(frame)?;
    if bytes.len() > MAX_CONTROL_FRAME_BYTES {
        return Err(AslError::InvalidMessage);
    }
    append_length_prefixed(body, &bytes)
}

fn decode_control_frame(bytes: &[u8]) -> Result<WireFrame, AslError> {
    let payload = decode_length_prefixed(bytes, MAX_CONTROL_FRAME_BYTES)?;
    decode_control(payload)
}

fn append_length_prefixed(body: &mut Vec<u8>, bytes: &[u8]) -> Result<(), AslError> {
    body.extend_from_slice(
        &u32::try_from(bytes.len())
            .map_err(|_| AslError::InvalidMessage)?
            .to_be_bytes(),
    );
    body.extend_from_slice(bytes);
    Ok(())
}

fn decode_length_prefixed(bytes: &[u8], max: usize) -> Result<&[u8], AslError> {
    if bytes.len() < 4 {
        return Err(AslError::InvalidMessage);
    }
    let length = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    if length == 0 || length > max || bytes.len() != 4 + length {
        return Err(AslError::InvalidMessage);
    }
    Ok(&bytes[4..])
}

fn append_bulk_request(body: &mut Vec<u8>, request: &BulkRequest) {
    body.push(request.operation as u8);
    body.extend_from_slice(&request.request_id.0);
    body.extend_from_slice(&request.content_id.0);
    body.extend_from_slice(&request.lease_id.0);
    body.extend_from_slice(&request.chunk_index.to_be_bytes());
}

fn decode_bulk_request(bytes: &[u8]) -> Result<BulkRequest, AslError> {
    if bytes.len() != BULK_REQUEST_IPC_BYTES {
        return Err(AslError::InvalidMessage);
    }
    let operation = match bytes[0] {
        1 => BulkOperation::Manifest,
        2 => BulkOperation::Chunk,
        3 => BulkOperation::Inline,
        _ => return Err(AslError::InvalidMessage),
    };
    let chunk_index = u32::from_be_bytes(bytes[81..85].try_into().unwrap());
    if operation != BulkOperation::Chunk && chunk_index != 0 {
        return Err(AslError::InvalidMessage);
    }
    Ok(BulkRequest {
        operation,
        request_id: asl_types::ids::Id128(bytes[1..17].try_into().unwrap()),
        content_id: asl_types::ids::Hash32(bytes[17..49].try_into().unwrap()),
        lease_id: asl_types::ids::Hash32(bytes[49..81].try_into().unwrap()),
        chunk_index,
    })
}

fn append_bulk_response(body: &mut Vec<u8>, response: &BulkResponse) -> Result<(), AslError> {
    if response.payload.len() > MAX_IPC_BULK_PAYLOAD_BYTES
        || (response.status != BulkStatus::Success && !response.payload.is_empty())
    {
        return Err(AslError::InvalidMessage);
    }
    body.extend_from_slice(&response.request_id.0);
    body.push(response.status as u8);
    body.extend_from_slice(
        &u32::try_from(response.payload.len())
            .map_err(|_| AslError::InvalidMessage)?
            .to_be_bytes(),
    );
    body.extend_from_slice(&response.payload);
    Ok(())
}

fn decode_bulk_response(bytes: &[u8]) -> Result<BulkResponse, AslError> {
    if bytes.len() < BULK_RESPONSE_HEADER_IPC_BYTES {
        return Err(AslError::InvalidMessage);
    }
    let status = match bytes[16] {
        0 => BulkStatus::Success,
        1 => BulkStatus::NotFound,
        2 => BulkStatus::Busy,
        3 => BulkStatus::Expired,
        4 => BulkStatus::IntegrityFailed,
        5 => BulkStatus::Cancelled,
        _ => return Err(AslError::InvalidMessage),
    };
    let payload_len = u32::from_be_bytes(bytes[17..21].try_into().unwrap()) as usize;
    if payload_len > MAX_IPC_BULK_PAYLOAD_BYTES
        || bytes.len() != BULK_RESPONSE_HEADER_IPC_BYTES + payload_len
        || (status != BulkStatus::Success && payload_len != 0)
    {
        return Err(AslError::InvalidMessage);
    }
    Ok(BulkResponse {
        request_id: asl_types::ids::Id128(bytes[..16].try_into().unwrap()),
        status,
        payload: bytes[BULK_RESPONSE_HEADER_IPC_BYTES..].to_vec(),
    })
}

fn transport_kind_code(kind: TransportKind) -> u8 {
    match kind {
        TransportKind::Tcp => 1,
        TransportKind::Quic => 2,
    }
}

fn decode_transport_kind(value: u8) -> Result<TransportKind, AslError> {
    match value {
        1 => Ok(TransportKind::Tcp),
        2 => Ok(TransportKind::Quic),
        _ => Err(AslError::InvalidMessage),
    }
}

fn address_policy_code(policy: AddressPolicy) -> u8 {
    match policy {
        AddressPolicy::LoopbackOnly => 1,
        AddressPolicy::LanOnly => 2,
        AddressPolicy::InternetOnly => 3,
        AddressPolicy::Hybrid => 4,
        AddressPolicy::RelayOnly => 5,
    }
}

fn decode_address_policy(value: u8) -> Result<AddressPolicy, AslError> {
    match value {
        1 => Ok(AddressPolicy::LoopbackOnly),
        2 => Ok(AddressPolicy::LanOnly),
        3 => Ok(AddressPolicy::InternetOnly),
        4 => Ok(AddressPolicy::Hybrid),
        5 => Ok(AddressPolicy::RelayOnly),
        _ => Err(AslError::InvalidMessage),
    }
}

fn append_socket_addr(body: &mut Vec<u8>, address: SocketAddr) -> Result<(), AslError> {
    match address.ip() {
        IpAddr::V4(ip) => {
            body.push(4);
            body.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            if matches!(address, SocketAddr::V6(value) if value.scope_id() != 0 || value.flowinfo() != 0)
            {
                return Err(AslError::InvalidMessage);
            }
            body.push(6);
            body.extend_from_slice(&ip.octets());
        }
    }
    body.extend_from_slice(&address.port().to_be_bytes());
    Ok(())
}

fn decode_socket_addr(bytes: &[u8]) -> Result<(SocketAddr, usize), AslError> {
    let family = *bytes.first().ok_or(AslError::InvalidMessage)?;
    let (ip, length) = match family {
        4 if bytes.len() >= 7 => (
            IpAddr::V4(Ipv4Addr::new(bytes[1], bytes[2], bytes[3], bytes[4])),
            7,
        ),
        6 if bytes.len() >= 19 => (
            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[1..17]).unwrap())),
            19,
        ),
        _ => return Err(AslError::InvalidMessage),
    };
    let port_offset = length - 2;
    let port = u16::from_be_bytes(bytes[port_offset..length].try_into().unwrap());
    Ok((SocketAddr::new(ip, port), length))
}

fn max_body_bytes(kind: u8) -> Option<usize> {
    Some(match kind {
        1..=3 => 0,
        4..=5 => 8,
        6 => MAX_IPC_TASK_PAYLOAD_BYTES + TASK_BODY_HEADER_BYTES,
        7 => 17,
        8..=9 => 16,
        10 => 18 + 128,
        11 => 16,
        12 | 15 => 32 + 4 + MAX_IPC_IDENTITY_PROOF_FRAME_BYTES,
        13 | 14 => 16 + 4 + MAX_IPC_IDENTITY_PROOF_FRAME_BYTES,
        16 => 2 + 128,
        17 => 16 + 1 + 19,
        18 => 16 + 1 + 19 + 2 + 128,
        19 => 16,
        20 => 17,
        21 => 1 + 19,
        22..=25 => 32 + 4 + MAX_CONTROL_FRAME_BYTES,
        26 => 32 + BULK_REQUEST_IPC_BYTES,
        27 => 16 + BULK_RESPONSE_HEADER_IPC_BYTES + MAX_IPC_BULK_PAYLOAD_BYTES,
        28 => 16 + BULK_REQUEST_IPC_BYTES,
        29 => 32 + BULK_RESPONSE_HEADER_IPC_BYTES + MAX_IPC_BULK_PAYLOAD_BYTES,
        30 => 34,
        31 => 1,
        32 => 16,
        33 => 17,
        34 => 18 + MAX_RELAY_ENDPOINT_BYTES,
        35 => 16 + 2 + 128,
        36 => 2 + 128 + 2 + MAX_RELAY_ENDPOINT_BYTES,
        37 => 2 + 128,
        38 => 2 + 128 + 1 + 19 + 1,
        39 => 50 + MAX_DHT_VALUE_BYTES,
        40 => 17,
        _ => return None,
    })
}

pub struct FrameReader<R> {
    reader: R,
    expected_sender: IpcRole,
    receiver: IpcRole,
    next_sequence: Option<u64>,
}

impl<R: Read> FrameReader<R> {
    pub fn new(reader: R, expected_sender: IpcRole, receiver: IpcRole) -> Self {
        Self {
            reader,
            expected_sender,
            receiver,
            next_sequence: Some(1),
        }
    }

    pub fn receive(&mut self) -> Result<IpcFrame, AslError> {
        let sequence = self.next_sequence.ok_or(AslError::InvalidMessage)?;
        let mut header = [0u8; HEADER_BYTES];
        self.reader.read_exact(&mut header)?;
        let (kind, body_len) =
            decode_header(&header, self.expected_sender, self.receiver, sequence)?;
        let mut body = vec![0; body_len];
        self.reader.read_exact(&mut body)?;
        let message = decode_message(kind, &body)?;
        self.next_sequence = sequence.checked_add(1);
        Ok(IpcFrame {
            role: self.expected_sender,
            sequence,
            message,
        })
    }
}

pub struct FrameWriter<W> {
    writer: W,
    sender: IpcRole,
    receiver: IpcRole,
    next_sequence: Option<u64>,
    failed: bool,
}

impl<W: Write> FrameWriter<W> {
    pub fn new(writer: W, sender: IpcRole, receiver: IpcRole) -> Self {
        Self {
            writer,
            sender,
            receiver,
            next_sequence: Some(1),
            failed: false,
        }
    }

    pub fn send(&mut self, message: &IpcMessage) -> Result<(), AslError> {
        if self.failed {
            return Err(AslError::InvalidMessage);
        }
        let sequence = self.next_sequence.ok_or(AslError::InvalidMessage)?;
        let frame = encode_frame(self.sender, self.receiver, sequence, message)?;
        if let Err(error) = self
            .writer
            .write_all(&frame)
            .and_then(|()| self.writer.flush())
        {
            self.failed = true;
            return Err(error.into());
        }
        self.next_sequence = sequence.checked_add(1);
        Ok(())
    }

    pub fn into_inner(self) -> W {
        self.writer
    }
}

pub(crate) fn validate_control_payload(payload: &[u8]) -> TaskStatus {
    if decode_control(payload).is_ok() {
        TaskStatus::Valid
    } else {
        TaskStatus::Invalid
    }
}

pub fn run_net_child() -> Result<(), AslError> {
    run_child_for(&[IpcRole::Net])
}

pub fn run_worker_child() -> Result<(), AslError> {
    run_child_for(&[IpcRole::Worker, IpcRole::Extractor])
}

fn run_child_for(allowed_roles: &[IpcRole]) -> Result<(), AslError> {
    let mut arguments = env::args_os();
    let _executable = arguments.next();
    let argument = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or(AslError::InvalidMessage)?;
    if arguments.next().is_some() {
        return Err(AslError::InvalidMessage);
    }
    let role = allowed_roles
        .iter()
        .copied()
        .find(|role| role.startup_argument() == Some(argument.as_str()))
        .ok_or(AslError::InvalidMessage)?;

    let stdin = std::io::stdin();
    if role == IpcRole::Net {
        let identity = read_device_identity_prelude(&mut stdin.lock())?;
        return net_runtime::run(identity, stdin, std::io::stdout());
    }
    let stdout = std::io::stdout();
    let mut reader = FrameReader::new(stdin.lock(), IpcRole::Core, role);
    let mut writer = FrameWriter::new(stdout.lock(), role, IpcRole::Core);
    writer.send(&IpcMessage::Ready)?;
    loop {
        match reader.receive()?.message {
            IpcMessage::Shutdown => {
                writer.send(&IpcMessage::Stopped)?;
                return Ok(());
            }
            IpcMessage::Ping { nonce } => writer.send(&IpcMessage::Pong { nonce })?,
            IpcMessage::RunTask {
                task_id,
                operation: WorkerOperation::ValidateControlFrame,
                payload,
            } if role == IpcRole::Worker => {
                writer.send(&IpcMessage::TaskStarted { task_id })?;
                if reader.receive()?.message != (IpcMessage::TaskContinue { task_id }) {
                    return Err(AslError::InvalidMessage);
                }
                writer.send(&IpcMessage::TaskResult {
                    task_id,
                    status: validate_control_payload(&payload),
                })?;
            }
            _ => return Err(AslError::InvalidMessage),
        }
    }
}

pub(crate) fn write_device_identity_prelude<W: Write>(
    writer: &mut W,
    identity: &DeviceIdentity,
) -> Result<(), AslError> {
    let secret = identity.to_ipc_secret()?;
    let length = u32::try_from(secret.len()).map_err(|_| AslError::InvalidIdentity)?;
    let mut header = [0u8; DEVICE_IDENTITY_PRELUDE_HEADER_BYTES];
    header[..4].copy_from_slice(&DEVICE_IDENTITY_PRELUDE_MAGIC);
    header[4..6].copy_from_slice(&DEVICE_IDENTITY_PRELUDE_VERSION.to_be_bytes());
    header[6..].copy_from_slice(&length.to_be_bytes());
    writer.write_all(&header)?;
    writer.write_all(&secret)?;
    writer.flush()?;
    Ok(())
}

fn read_device_identity_prelude<R: Read>(reader: &mut R) -> Result<DeviceIdentity, AslError> {
    let mut header = [0u8; DEVICE_IDENTITY_PRELUDE_HEADER_BYTES];
    reader.read_exact(&mut header)?;
    if header[..4] != DEVICE_IDENTITY_PRELUDE_MAGIC {
        return Err(AslError::InvalidMessage);
    }
    if header[4..6] != DEVICE_IDENTITY_PRELUDE_VERSION.to_be_bytes() {
        return Err(AslError::IncompatibleVersion);
    }
    let length = u32::from_be_bytes(header[6..10].try_into().unwrap()) as usize;
    if length == 0 || length > MAX_DEVICE_IDENTITY_PRELUDE_BYTES {
        return Err(AslError::InvalidMessage);
    }
    let mut secret = Zeroizing::new(vec![0u8; length]);
    reader.read_exact(&mut secret)?;
    DeviceIdentity::from_ipc_secret(&secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::DeviceIdentity;
    use std::io::Cursor;

    fn ready_frame(sender: IpcRole, sequence: u64) -> Vec<u8> {
        encode_frame(sender, IpcRole::Core, sequence, &IpcMessage::Ready).unwrap()
    }

    #[test]
    fn fixed_messages_round_trip_with_role_and_sequence_binding() {
        let messages = [
            IpcMessage::Ready,
            IpcMessage::Shutdown,
            IpcMessage::Stopped,
            IpcMessage::Ping { nonce: 42 },
            IpcMessage::Pong { nonce: 42 },
            IpcMessage::RunTask {
                task_id: [3; 16],
                operation: WorkerOperation::ValidateControlFrame,
                payload: vec![0x82, 0x01, 0x02],
            },
            IpcMessage::TaskResult {
                task_id: [3; 16],
                status: TaskStatus::Invalid,
            },
            IpcMessage::TaskStarted { task_id: [3; 16] },
            IpcMessage::TaskContinue { task_id: [3; 16] },
            IpcMessage::NetReady {
                peer_id: DeviceIdentity::generate().unwrap().peer_id(),
            },
            IpcMessage::Listen {
                operation_id: [10; 16],
                kind: TransportKind::Tcp,
                address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            },
            IpcMessage::Dial {
                operation_id: [11; 16],
                kind: TransportKind::Quic,
                address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4001),
                peer_id: DeviceIdentity::generate().unwrap().peer_id(),
            },
            IpcMessage::CloseConnection {
                connection_id: [11; 16],
            },
            IpcMessage::SetAddressPolicy {
                operation_id: [26; 16],
                policy: AddressPolicy::LanOnly,
            },
            IpcMessage::ReserveRelay {
                operation_id: [27; 16],
                address: b"/ip4/127.0.0.1/tcp/4001/p2p/local-test".to_vec(),
            },
            IpcMessage::DialViaRelays {
                operation_id: [28; 16],
                peer_id: DeviceIdentity::generate().unwrap().peer_id(),
            },
            IpcMessage::OperationAccepted {
                operation_id: [10; 16],
            },
            IpcMessage::OperationFailed {
                operation_id: [11; 16],
                code: NetworkErrorCode::Transport,
            },
            IpcMessage::Listening {
                kind: TransportKind::Tcp,
                address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4001),
            },
            IpcMessage::RelayReserved {
                relay_peer_id: DeviceIdentity::generate().unwrap().peer_id(),
                address: b"/ip4/127.0.0.1/tcp/4001/p2p/local-test/p2p-circuit".to_vec(),
            },
            IpcMessage::RelayUnavailable {
                relay_peer_id: DeviceIdentity::generate().unwrap().peer_id(),
            },
            IpcMessage::DiscoveryCandidate {
                peer_id: DeviceIdentity::generate().unwrap().peer_id(),
                kind: TransportKind::Quic,
                address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)), 4002),
                state: DiscoveryCandidateState::Discovered,
            },
            IpcMessage::DhtRecordCandidate {
                candidate_id: [29; 16],
                key: [30; 32],
                value: vec![0x51, 0x52, 0x53],
            },
            IpcMessage::DecideDhtRecord {
                candidate_id: [31; 16],
                accept: true,
            },
            IpcMessage::ControlRequested {
                connection_id: [12; 16],
                response_id: [13; 16],
                request: WireFrame::Ack(asl_types::protocol::Ack {
                    message_id: asl_types::ids::Id128([14; 16]),
                    received_id: asl_types::ids::Id128([15; 16]),
                }),
            },
            IpcMessage::ControlReceived {
                connection_id: [12; 16],
                request_id: [16; 16],
                response: WireFrame::Ack(asl_types::protocol::Ack {
                    message_id: asl_types::ids::Id128([17; 16]),
                    received_id: asl_types::ids::Id128([14; 16]),
                }),
            },
            IpcMessage::SendControl {
                connection_id: [12; 16],
                request_id: [16; 16],
                request: WireFrame::Ack(asl_types::protocol::Ack {
                    message_id: asl_types::ids::Id128([14; 16]),
                    received_id: asl_types::ids::Id128([15; 16]),
                }),
            },
            IpcMessage::ReplyControl {
                connection_id: [12; 16],
                response_id: [13; 16],
                response: WireFrame::Ack(asl_types::protocol::Ack {
                    message_id: asl_types::ids::Id128([17; 16]),
                    received_id: asl_types::ids::Id128([14; 16]),
                }),
            },
            IpcMessage::BulkRequested {
                connection_id: [18; 16],
                response_id: [19; 16],
                request: BulkRequest {
                    operation: BulkOperation::Chunk,
                    request_id: asl_types::ids::Id128([20; 16]),
                    content_id: asl_types::ids::Hash32([21; 32]),
                    lease_id: asl_types::ids::Hash32([22; 32]),
                    chunk_index: 1,
                },
            },
            IpcMessage::BulkReceived {
                connection_id: [18; 16],
                response: BulkResponse {
                    request_id: asl_types::ids::Id128([20; 16]),
                    status: BulkStatus::Success,
                    payload: vec![23; 64],
                },
            },
            IpcMessage::SendBulk {
                connection_id: [18; 16],
                request: BulkRequest {
                    operation: BulkOperation::Manifest,
                    request_id: asl_types::ids::Id128([20; 16]),
                    content_id: asl_types::ids::Hash32([21; 32]),
                    lease_id: asl_types::ids::Hash32([22; 32]),
                    chunk_index: 0,
                },
            },
            IpcMessage::ReplyBulk {
                connection_id: [18; 16],
                response_id: [19; 16],
                response: BulkResponse {
                    request_id: asl_types::ids::Id128([20; 16]),
                    status: BulkStatus::NotFound,
                    payload: vec![],
                },
            },
            IpcMessage::RequestFailed {
                connection_id: [24; 16],
                request_id: [25; 16],
                protocol: NetworkProtocol::Bulk,
                code: NetworkErrorCode::TimedOut,
            },
            IpcMessage::NetworkError {
                code: NetworkErrorCode::Capacity,
            },
        ];
        for message in messages {
            let (sender, receiver) = match message {
                IpcMessage::Ready
                | IpcMessage::Stopped
                | IpcMessage::Pong { .. }
                | IpcMessage::NetReady { .. } => (IpcRole::Net, IpcRole::Core),
                IpcMessage::OperationAccepted { .. }
                | IpcMessage::OperationFailed { .. }
                | IpcMessage::Listening { .. }
                | IpcMessage::RelayReserved { .. }
                | IpcMessage::RelayUnavailable { .. }
                | IpcMessage::DiscoveryCandidate { .. }
                | IpcMessage::DhtRecordCandidate { .. }
                | IpcMessage::ControlRequested { .. }
                | IpcMessage::ControlReceived { .. }
                | IpcMessage::BulkRequested { .. }
                | IpcMessage::BulkReceived { .. }
                | IpcMessage::RequestFailed { .. }
                | IpcMessage::NetworkError { .. } => (IpcRole::Net, IpcRole::Core),
                IpcMessage::Shutdown
                | IpcMessage::Ping { .. }
                | IpcMessage::Listen { .. }
                | IpcMessage::Dial { .. }
                | IpcMessage::CloseConnection { .. }
                | IpcMessage::SendControl { .. }
                | IpcMessage::ReplyControl { .. }
                | IpcMessage::SendBulk { .. }
                | IpcMessage::ReplyBulk { .. }
                | IpcMessage::SetAddressPolicy { .. }
                | IpcMessage::DecideDhtRecord { .. } => (IpcRole::Core, IpcRole::Net),
                IpcMessage::ReserveRelay { .. } | IpcMessage::DialViaRelays { .. } => {
                    (IpcRole::Core, IpcRole::Net)
                }
                IpcMessage::RunTask { .. } => (IpcRole::Core, IpcRole::Worker),
                IpcMessage::TaskResult { .. } | IpcMessage::TaskStarted { .. } => {
                    (IpcRole::Worker, IpcRole::Core)
                }
                IpcMessage::TaskContinue { .. } => (IpcRole::Core, IpcRole::Worker),
                IpcMessage::PeerAuthenticated { .. }
                | IpcMessage::PeerDisconnected { .. }
                | IpcMessage::IdentityProofRequested { .. }
                | IpcMessage::IdentityProofReceived { .. } => (IpcRole::Net, IpcRole::Core),
                IpcMessage::RequestIdentityProof { .. } | IpcMessage::ReplyIdentityProof { .. } => {
                    (IpcRole::Core, IpcRole::Net)
                }
            };
            let bytes = encode_frame(sender, receiver, 7, &message).unwrap();
            let decoded = decode_frame(&bytes, sender, receiver, 7).unwrap();
            assert_eq!(decoded.message, message);
            assert_eq!(decoded.sequence, 7);
        }
    }

    #[test]
    fn device_identity_startup_prelude_round_trips_over_the_private_stream() {
        let identity = DeviceIdentity::generate().unwrap();
        let expected_peer_id = identity.peer_id();
        let mut bytes = Vec::new();

        write_device_identity_prelude(&mut bytes, &identity).unwrap();
        let received = read_device_identity_prelude(&mut Cursor::new(bytes)).unwrap();

        assert_eq!(received.peer_id(), expected_peer_id);
    }

    #[test]
    fn malformed_or_oversized_device_identity_preludes_are_rejected_before_body_read() {
        struct HeaderOnly {
            bytes: Cursor<Vec<u8>>,
            body_read: bool,
        }

        impl Read for HeaderOnly {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                if self.bytes.position() >= DEVICE_IDENTITY_PRELUDE_HEADER_BYTES as u64 {
                    self.body_read = true;
                }
                self.bytes.read(buffer)
            }
        }

        for (magic, version, length) in [
            (*b"NOPE", DEVICE_IDENTITY_PRELUDE_VERSION, 32_u32),
            (
                DEVICE_IDENTITY_PRELUDE_MAGIC,
                DEVICE_IDENTITY_PRELUDE_VERSION + 1,
                32,
            ),
            (
                DEVICE_IDENTITY_PRELUDE_MAGIC,
                DEVICE_IDENTITY_PRELUDE_VERSION,
                0,
            ),
            (
                DEVICE_IDENTITY_PRELUDE_MAGIC,
                DEVICE_IDENTITY_PRELUDE_VERSION,
                (MAX_DEVICE_IDENTITY_PRELUDE_BYTES + 1) as u32,
            ),
        ] {
            let mut header = Vec::new();
            header.extend_from_slice(&magic);
            header.extend_from_slice(&version.to_be_bytes());
            header.extend_from_slice(&length.to_be_bytes());
            let mut reader = HeaderOnly {
                bytes: Cursor::new(header),
                body_read: false,
            };

            assert!(read_device_identity_prelude(&mut reader).is_err());
            assert!(!reader.body_read);
        }
    }

    #[test]
    fn invalid_or_truncated_device_key_payloads_are_rejected() {
        for (length, payload) in [(1_u32, &[0xff][..]), (2, &[0x08][..])] {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&DEVICE_IDENTITY_PRELUDE_MAGIC);
            bytes.extend_from_slice(&DEVICE_IDENTITY_PRELUDE_VERSION.to_be_bytes());
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes.extend_from_slice(payload);
            assert!(read_device_identity_prelude(&mut Cursor::new(bytes)).is_err());
        }
    }

    #[test]
    fn net_ready_is_net_only_and_rejects_malformed_peer_ids() {
        let peer_id = DeviceIdentity::generate().unwrap().peer_id();
        let message = IpcMessage::NetReady {
            peer_id: peer_id.clone(),
        };
        let bytes = encode_frame(IpcRole::Net, IpcRole::Core, 1, &message).unwrap();
        assert_eq!(
            decode_frame(&bytes, IpcRole::Net, IpcRole::Core, 1)
                .unwrap()
                .message,
            message
        );
        assert!(encode_frame(IpcRole::Worker, IpcRole::Core, 1, &message).is_err());

        let mut malformed = bytes;
        malformed[HEADER_BYTES + 2] = 0xff;
        assert!(decode_frame(&malformed, IpcRole::Net, IpcRole::Core, 1).is_err());
    }

    #[test]
    fn rejects_unknown_role_kind_and_operation() {
        let mut bytes = ready_frame(IpcRole::Net, 1);
        bytes[6] = 99;
        assert!(decode_frame(&bytes, IpcRole::Net, IpcRole::Core, 1).is_err());

        let mut bytes = ready_frame(IpcRole::Net, 1);
        bytes[7] = 99;
        assert!(decode_frame(&bytes, IpcRole::Net, IpcRole::Core, 1).is_err());

        let mut bytes = encode_frame(
            IpcRole::Core,
            IpcRole::Worker,
            1,
            &IpcMessage::RunTask {
                task_id: [0; 16],
                operation: WorkerOperation::ValidateControlFrame,
                payload: Vec::new(),
            },
        )
        .unwrap();
        bytes[HEADER_BYTES + 16] = 99;
        assert!(decode_frame(&bytes, IpcRole::Core, IpcRole::Worker, 1).is_err());
    }

    #[test]
    fn rejects_wrong_direction_and_non_monotonic_sequences() {
        let bytes = encode_frame(IpcRole::Net, IpcRole::Core, 1, &IpcMessage::Ready).unwrap();
        assert!(decode_frame(&bytes, IpcRole::Net, IpcRole::Core, 2).is_err());
        assert!(encode_frame(IpcRole::Worker, IpcRole::Core, 1, &IpcMessage::Ready,).is_ok());
        assert!(
            encode_frame(
                IpcRole::Core,
                IpcRole::Net,
                1,
                &IpcMessage::TaskResult {
                    task_id: [0; 16],
                    status: TaskStatus::Valid,
                },
            )
            .is_err()
        );

        let first = ready_frame(IpcRole::Net, 1);
        let mut input = first.clone();
        input.extend_from_slice(&first);
        let mut reader = FrameReader::new(Cursor::new(input), IpcRole::Net, IpcRole::Core);
        assert!(matches!(
            reader.receive().unwrap().message,
            IpcMessage::Ready
        ));
        assert!(reader.receive().is_err());
    }

    #[test]
    fn enforces_four_mib_total_frame_limit() {
        let max_payload = MAX_IPC_TASK_PAYLOAD_BYTES;
        let message = IpcMessage::RunTask {
            task_id: [1; 16],
            operation: WorkerOperation::ValidateControlFrame,
            payload: vec![0; max_payload],
        };
        assert_eq!(
            encode_frame(IpcRole::Core, IpcRole::Worker, 1, &message)
                .unwrap()
                .len(),
            MAX_IPC_FRAME_BYTES
        );

        let oversized = IpcMessage::RunTask {
            task_id: [1; 16],
            operation: WorkerOperation::ValidateControlFrame,
            payload: vec![0; max_payload + 1],
        };
        assert!(encode_frame(IpcRole::Core, IpcRole::Worker, 1, &oversized).is_err());
    }

    #[test]
    fn rejects_oversized_identity_frame_before_reading_its_body() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        struct HeaderReader {
            bytes: Cursor<Vec<u8>>,
            body_reads: Arc<AtomicUsize>,
        }

        impl Read for HeaderReader {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                if self.bytes.position() >= HEADER_BYTES as u64 {
                    self.body_reads.fetch_add(1, Ordering::Relaxed);
                }
                self.bytes.read(buffer)
            }
        }

        let mut header = vec![0; HEADER_BYTES];
        header[..4].copy_from_slice(&MAGIC);
        header[4..6].copy_from_slice(&VERSION.to_be_bytes());
        header[6] = IpcRole::Net as u8;
        header[7] = 13;
        header[8..16].copy_from_slice(&1_u64.to_be_bytes());
        header[16..20]
            .copy_from_slice(&((MAX_IPC_FRAME_BYTES - HEADER_BYTES) as u32).to_be_bytes());
        let body_reads = Arc::new(AtomicUsize::new(0));
        let reader = HeaderReader {
            bytes: Cursor::new(header),
            body_reads: body_reads.clone(),
        };
        let mut frame_reader = FrameReader::new(reader, IpcRole::Net, IpcRole::Core);

        assert!(matches!(
            frame_reader.receive(),
            Err(AslError::InvalidMessage)
        ));
        assert_eq!(body_reads.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn rejects_invalid_network_headers_before_reading_the_body() {
        let mut header = vec![0; HEADER_BYTES];
        header[..4].copy_from_slice(&MAGIC);
        header[4..6].copy_from_slice(&VERSION.to_be_bytes());
        header[7] = 10;
        header[16..20].copy_from_slice(&18_u32.to_be_bytes());

        for (actual, expected, sequence) in [
            (IpcRole::Worker, IpcRole::Net, 1_u64),
            (IpcRole::Worker, IpcRole::Worker, 1),
            (IpcRole::Net, IpcRole::Net, 2),
        ] {
            header[6] = actual as u8;
            header[8..16].copy_from_slice(&sequence.to_be_bytes());
            let mut reader = FrameReader::new(Cursor::new(&header), expected, IpcRole::Core);
            assert!(matches!(reader.receive(), Err(AslError::InvalidMessage)));
        }
    }

    #[test]
    fn worker_result_contains_only_a_fixed_status() {
        assert_eq!(validate_control_payload(&[]), TaskStatus::Invalid);
        assert_eq!(validate_control_payload(&[0xff]), TaskStatus::Invalid);
    }
}
