use std::env;
use std::io::{Read, Write};

use asl_net::{
    address_policy::AddressPolicy,
    codec::{BulkOperation, BulkRequest, BulkResponse, BulkStatus},
    dht::{MAX_DHT_PROVIDER_ADDRESSES, MAX_DHT_VALUE_BYTES},
    relay::MAX_RELAY_ENDPOINT_BYTES,
    transport::{
        DhtLookupStatus, DhtProviderCandidate, DiscoveryCandidateState, MAX_GOSSIP_PAYLOAD_BYTES,
        MAX_REACHABILITY_ADDRESS_BYTES, ReachabilityState, ReachabilityStatus, RouteFailure,
        RouteState, RouteStatus, TransportKind, TraversalConfig,
    },
};
use asl_types::{
    error::AslError,
    ids::{AgentId, PeerId},
    manifest::MAX_MANIFEST_LEN,
    protocol::{
        GroupPacket, IdentityProof, IdentityProofRequest, MAX_CONTROL_FRAME_BYTES,
        MAX_EXTENDED_FRAME_BYTES, MAX_PAIRING_FRAME_BYTES, PairingExchange, PairingInvite,
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
const NET_STARTUP_PRELUDE_MAGIC: [u8; 4] = *b"ASLK";
const NET_STARTUP_PRELUDE_VERSION: u16 = 3;
const NET_STARTUP_PRELUDE_FLAG_OFFSET: usize = 10;
const NET_STARTUP_PRELUDE_CONFIG_LENGTH_OFFSET: usize = NET_STARTUP_PRELUDE_FLAG_OFFSET + 1;
const NET_STARTUP_PRELUDE_HEADER_BYTES: usize = NET_STARTUP_PRELUDE_CONFIG_LENGTH_OFFSET + 2;
const NET_STARTUP_TRAVERSAL_BYTES: usize = 91;
const MAX_DEVICE_IDENTITY_PRELUDE_BYTES: usize = MAX_DEVICE_KEY_BYTES;
pub const MAX_IPC_TASK_PAYLOAD_BYTES: usize =
    MAX_IPC_FRAME_BYTES - HEADER_BYTES - TASK_BODY_HEADER_BYTES;
pub const MAX_IPC_EXTRACTOR_INPUT_BYTES: usize =
    MAX_IPC_FRAME_BYTES - HEADER_BYTES - TASK_BODY_HEADER_BYTES;
pub const MAX_IPC_EXTRACTOR_OUTPUT_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_IPC_IDENTITY_PROOF_FRAME_BYTES: usize = MAX_EXTENDED_FRAME_BYTES;
pub const MAX_IPC_PAIRING_FRAME_BYTES: usize = MAX_PAIRING_FRAME_BYTES;
pub const MAX_IPC_BULK_PAYLOAD_BYTES: usize = MAX_MANIFEST_LEN;
const MAX_IPC_GROUP_FRAME_BYTES: usize = MAX_EXTENDED_FRAME_BYTES;
const MAX_IPC_DHT_PROVIDER_CANDIDATES: usize = 20;
const MAX_IPC_DHT_PROVIDER_ADDRESS_BYTES: usize = 512;
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
            ) | (Self::Core, Self::Net, 14 | 15 | 17 | 18 | 24 | 25 | 28 | 29 | 33 | 40 | 44 | 48 | 49 | 54..=62 | 64..=71 | 74..=76)
                | (Self::Core, Self::Net, 34 | 35 | 43)
                | (Self::Core, Self::Net, 32)
                | (Self::Core, Self::Net, 50..=51)
                | (Self::Core, Self::Worker, 6 | 9)
                | (Self::Core, Self::Extractor, 41)
                | (
                    Self::Net | Self::Worker | Self::Extractor,
                    Self::Core,
                    1 | 3 | 5
                )
                | (Self::Net, Self::Core, 10..=13)
                | (Self::Net, Self::Core, 16 | 19..=23 | 26..=27 | 30..=31)
                | (Self::Net, Self::Core, 36..=39 | 45..=47)
                | (Self::Net, Self::Core, 52..=53 | 63 | 68 | 72..=73)
                | (Self::Worker | Self::Extractor, Self::Core, 7)
                | (Self::Worker, Self::Core, 8)
                | (Self::Extractor, Self::Core, 42)
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
pub enum ExtractorOperation {
    PdfText = 1,
    Avatar = 2,
    DocumentText = 3,
}

impl ExtractorOperation {
    fn from_wire(value: u8) -> Result<Self, AslError> {
        match value {
            1 => Ok(Self::PdfText),
            2 => Ok(Self::Avatar),
            3 => Ok(Self::DocumentText),
            _ => Err(AslError::InvalidMessage),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ExtractorStatus {
    Completed = 1,
    Rejected = 2,
}

impl ExtractorStatus {
    fn from_wire(value: u8) -> Result<Self, AslError> {
        match value {
            1 => Ok(Self::Completed),
            2 => Ok(Self::Rejected),
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
    RunExtractorTask {
        task_id: [u8; 16],
        operation: ExtractorOperation,
        payload: Vec<u8>,
    },
    ExtractorResult {
        task_id: [u8; 16],
        status: ExtractorStatus,
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
    PairingInviteRequested {
        connection_id: [u8; 16],
        response_id: [u8; 16],
        invite: PairingInvite,
    },
    PairingExchangeReceived {
        connection_id: [u8; 16],
        request_id: [u8; 16],
        invite: PairingInvite,
        exchange: PairingExchange,
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
    ReachabilityChanged {
        status: ReachabilityStatus,
    },
    RouteChanged {
        status: RouteStatus,
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
    FindProviders {
        lookup_id: [u8; 16],
        key: [u8; 32],
    },
    LookupDhtRecord {
        operation_id: [u8; 16],
        key: [u8; 32],
    },
    RestoreDhtRecord {
        expires_at_ms: u64,
        value: Vec<u8>,
    },
    RestoreDhtProvider {
        key: [u8; 32],
        peer_id: PeerId,
        addresses: Vec<String>,
        expires_at_ms: u64,
    },
    PublishMailboxRecord {
        operation_id: [u8; 16],
        record: Vec<u8>,
    },
    StartProviding {
        operation_id: [u8; 16],
        key: [u8; 32],
    },
    StopProviding {
        operation_id: [u8; 16],
        key: [u8; 32],
    },
    PrepareProfile {
        operation_id: [u8; 16],
        agent: AgentId,
    },
    PublishProfile {
        operation_id: [u8; 16],
        value: Vec<u8>,
    },
    CancelProfile {
        operation_id: [u8; 16],
        receipt_id: [u8; 16],
    },
    PrepareDirectory {
        operation_id: [u8; 16],
        agent: AgentId,
    },
    PublishDirectory {
        operation_id: [u8; 16],
        value: Vec<u8>,
    },
    CancelDirectory {
        operation_id: [u8; 16],
        receipt_id: [u8; 16],
    },
    PrepareContactPolicy {
        operation_id: [u8; 16],
        agent: AgentId,
    },
    PublishContactPolicy {
        operation_id: [u8; 16],
        value: Vec<u8>,
    },
    CancelContactPolicy {
        operation_id: [u8; 16],
        receipt_id: [u8; 16],
    },
    LookupProfile {
        operation_id: [u8; 16],
        agent: AgentId,
    },
    DhtProviders {
        lookup_id: [u8; 16],
        status: DhtLookupStatus,
        providers: Vec<DhtProviderCandidate>,
    },
    DhtProviderObserved {
        key: [u8; 32],
        peer_id: PeerId,
        addresses: Vec<String>,
        expires_at_ms: u64,
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
    ReplyDirect {
        connection_id: [u8; 16],
        response_id: [u8; 16],
        expires_at_ms: u64,
        response: WireFrame,
    },
    BulkRequested {
        connection_id: [u8; 16],
        response_id: [u8; 16],
        request: BulkRequest,
    },
    BulkReceived {
        connection_id: [u8; 16],
        request_id: [u8; 16],
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
    SendGroup {
        connection_id: [u8; 16],
        /// Fresh Core attempt handle; not the packet's wire message ID.
        request_handle: [u8; 16],
        /// Unix millisecond at or after which the child must not send this attempt.
        deadline_ms: u64,
        request: GroupPacket,
    },
    ReplyGroup {
        connection_id: [u8; 16],
        response_id: [u8; 16],
        response: GroupPacket,
    },
    GroupRequested {
        connection_id: [u8; 16],
        response_id: [u8; 16],
        /// Child-local response handle deadline, in Unix milliseconds.
        deadline_ms: u64,
        request: GroupPacket,
    },
    GroupReceived {
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
    GossipSubscribe {
        operation_id: [u8; 16],
        key: [u8; 32],
    },
    GossipUnsubscribe {
        operation_id: [u8; 16],
        key: [u8; 32],
    },
    GossipPublish {
        operation_id: [u8; 16],
        key: [u8; 32],
        payload: Vec<u8>,
    },
    GossipReceived {
        key: [u8; 32],
        propagation_source: PeerId,
        message_id: [u8; 32],
        payload: Vec<u8>,
    },
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum NetworkProtocol {
    Control = 1,
    IdentityProof = 2,
    Bulk = 3,
    Pairing = 4,
    Group = 5,
}

impl NetworkProtocol {
    fn from_wire(value: u8) -> Result<Self, AslError> {
        match value {
            1 => Ok(Self::Control),
            2 => Ok(Self::IdentityProof),
            3 => Ok(Self::Bulk),
            4 => Ok(Self::Pairing),
            5 => Ok(Self::Group),
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
    Authentication = 6,
}

impl NetworkErrorCode {
    fn from_wire(value: u8) -> Result<Self, AslError> {
        match value {
            1 => Ok(Self::InvalidCommand),
            2 => Ok(Self::Capacity),
            3 => Ok(Self::Disconnected),
            4 => Ok(Self::TimedOut),
            5 => Ok(Self::Transport),
            6 => Ok(Self::Authentication),
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
        IpcMessage::RunExtractorTask {
            task_id,
            operation,
            payload,
        } => {
            if payload.len() > MAX_IPC_EXTRACTOR_INPUT_BYTES {
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
            41
        }
        IpcMessage::ExtractorResult {
            task_id,
            status,
            payload,
        } => {
            if payload.len() > MAX_IPC_EXTRACTOR_OUTPUT_BYTES
                || (*status == ExtractorStatus::Rejected && !payload.is_empty())
            {
                return Err(AslError::InvalidMessage);
            }
            body.extend_from_slice(task_id);
            body.push(*status as u8);
            body.extend_from_slice(
                &u32::try_from(payload.len())
                    .map_err(|_| AslError::InvalidMessage)?
                    .to_be_bytes(),
            );
            body.extend_from_slice(payload);
            42
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
        IpcMessage::PairingInviteRequested {
            connection_id,
            response_id,
            invite,
        } => {
            body.extend_from_slice(connection_id);
            body.extend_from_slice(response_id);
            append_pairing_invite(&mut body, invite)?;
            46
        }
        IpcMessage::PairingExchangeReceived {
            connection_id,
            request_id,
            invite,
            exchange,
        } => {
            if *request_id != invite.invite_id.0 || exchange.exchange_id != invite.invite_id {
                return Err(AslError::InvalidMessage);
            }
            body.extend_from_slice(connection_id);
            body.extend_from_slice(request_id);
            append_pairing_invite(&mut body, invite)?;
            append_pairing_exchange(&mut body, exchange)?;
            47
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
        IpcMessage::RequestPairing {
            connection_id,
            request_id,
            invite,
        } => {
            if *request_id != invite.invite_id.0 {
                return Err(AslError::InvalidMessage);
            }
            body.extend_from_slice(connection_id);
            body.extend_from_slice(request_id);
            append_pairing_invite(&mut body, invite)?;
            48
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
        IpcMessage::ReplyPairing {
            connection_id,
            response_id,
            exchange,
        } => {
            body.extend_from_slice(connection_id);
            body.extend_from_slice(response_id);
            append_pairing_exchange(&mut body, exchange)?;
            49
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
        IpcMessage::ReachabilityChanged { status } => {
            let address = status.public_address.as_deref().unwrap_or_default();
            if address.len() > MAX_REACHABILITY_ADDRESS_BYTES
                || (status.state != ReachabilityState::Public && !address.is_empty())
            {
                return Err(AslError::InvalidMessage);
            }
            body.push(status.state as u8);
            body.push(status.confidence);
            body.extend_from_slice(
                &u16::try_from(address.len())
                    .map_err(|_| AslError::InvalidMessage)?
                    .to_be_bytes(),
            );
            body.extend_from_slice(address);
            72
        }
        IpcMessage::RouteChanged { status } => {
            let peer = status.peer_id.as_bytes();
            if peer.is_empty() || peer.len() > 128 {
                return Err(AslError::InvalidMessage);
            }
            body.extend_from_slice(
                &u16::try_from(peer.len())
                    .map_err(|_| AslError::InvalidMessage)?
                    .to_be_bytes(),
            );
            body.extend_from_slice(peer);
            body.push(status.state as u8);
            let relay = status
                .relay_peer_id
                .as_ref()
                .map(PeerId::as_bytes)
                .unwrap_or_default();
            if relay.len() > 128 {
                return Err(AslError::InvalidMessage);
            }
            body.extend_from_slice(
                &u16::try_from(relay.len())
                    .map_err(|_| AslError::InvalidMessage)?
                    .to_be_bytes(),
            );
            body.extend_from_slice(relay);
            body.push(status.direct_attempts);
            body.push(status.relay_attempts);
            body.push(status.failure.map_or(0, |failure| failure as u8));
            73
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
        IpcMessage::ReplyDirect {
            connection_id,
            response_id,
            expires_at_ms,
            response,
        } => {
            body.extend_from_slice(connection_id);
            body.extend_from_slice(response_id);
            body.extend_from_slice(&expires_at_ms.to_be_bytes());
            append_control_frame(&mut body, response)?;
            43
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
            request_id,
            response,
        } => {
            if *request_id != response.request_id.0 {
                return Err(AslError::InvalidMessage);
            }
            body.extend_from_slice(connection_id);
            body.extend_from_slice(request_id);
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
        IpcMessage::SendGroup {
            connection_id,
            request_handle,
            deadline_ms,
            request,
        } => {
            if *deadline_ms == 0 {
                return Err(AslError::InvalidMessage);
            }
            request.validate_request()?;
            body.extend_from_slice(connection_id);
            body.extend_from_slice(request_handle);
            body.extend_from_slice(&deadline_ms.to_be_bytes());
            append_group_packet(&mut body, request)?;
            50
        }
        IpcMessage::ReplyGroup {
            connection_id,
            response_id,
            response,
        } => {
            body.extend_from_slice(connection_id);
            body.extend_from_slice(response_id);
            append_group_packet(&mut body, response)?;
            51
        }
        IpcMessage::GroupRequested {
            connection_id,
            response_id,
            deadline_ms,
            request,
        } => {
            if *deadline_ms == 0 {
                return Err(AslError::InvalidMessage);
            }
            request.validate_request()?;
            body.extend_from_slice(connection_id);
            body.extend_from_slice(response_id);
            body.extend_from_slice(&deadline_ms.to_be_bytes());
            append_group_packet(&mut body, request)?;
            52
        }
        IpcMessage::GroupReceived {
            connection_id,
            request_handle,
            response,
        } => {
            body.extend_from_slice(connection_id);
            body.extend_from_slice(request_handle);
            append_group_packet(&mut body, response)?;
            53
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
        IpcMessage::FindProviders { lookup_id, key } => {
            if *lookup_id == [0; 16] {
                return Err(AslError::InvalidMessage);
            }
            body.extend_from_slice(lookup_id);
            body.extend_from_slice(key);
            44
        }
        IpcMessage::LookupDhtRecord { operation_id, key } => {
            if *operation_id == [0; 16] {
                return Err(AslError::InvalidMessage);
            }
            body.extend_from_slice(operation_id);
            body.extend_from_slice(key);
            64
        }
        IpcMessage::RestoreDhtRecord {
            expires_at_ms,
            value,
        } => {
            if *expires_at_ms == 0 || value.is_empty() || value.len() > MAX_DHT_VALUE_BYTES {
                return Err(AslError::InvalidMessage);
            }
            body.extend_from_slice(&expires_at_ms.to_be_bytes());
            body.extend_from_slice(
                &u16::try_from(value.len())
                    .map_err(|_| AslError::InvalidMessage)?
                    .to_be_bytes(),
            );
            body.extend_from_slice(value);
            66
        }
        IpcMessage::RestoreDhtProvider {
            key,
            peer_id,
            addresses,
            expires_at_ms,
        } => {
            append_dht_provider_observation(&mut body, key, peer_id, addresses, *expires_at_ms)?;
            67
        }
        IpcMessage::PublishMailboxRecord {
            operation_id,
            record,
        } => {
            if *operation_id == [0; 16] || asl_net::mailbox::MailboxRecord::decode(record).is_err()
            {
                return Err(AslError::InvalidMessage);
            }
            body.extend_from_slice(operation_id);
            body.extend_from_slice(record);
            65
        }
        IpcMessage::StartProviding { operation_id, key } => {
            if *operation_id == [0; 16] {
                return Err(AslError::InvalidMessage);
            }
            body.extend_from_slice(operation_id);
            body.extend_from_slice(key);
            54
        }
        IpcMessage::StopProviding { operation_id, key } => {
            if *operation_id == [0; 16] {
                return Err(AslError::InvalidMessage);
            }
            body.extend_from_slice(operation_id);
            body.extend_from_slice(key);
            55
        }
        IpcMessage::PrepareProfile {
            operation_id,
            agent,
        } => {
            if *operation_id == [0; 16] {
                return Err(AslError::InvalidMessage);
            }
            body.extend_from_slice(operation_id);
            body.extend_from_slice(agent.as_bytes());
            56
        }
        IpcMessage::PublishProfile {
            operation_id,
            value,
        } => {
            if *operation_id == [0; 16] || value.is_empty() || value.len() > MAX_DHT_VALUE_BYTES {
                return Err(AslError::InvalidMessage);
            }
            body.extend_from_slice(operation_id);
            body.extend_from_slice(value);
            57
        }
        IpcMessage::LookupProfile {
            operation_id,
            agent,
        } => {
            if *operation_id == [0; 16] {
                return Err(AslError::InvalidMessage);
            }
            body.extend_from_slice(operation_id);
            body.extend_from_slice(agent.as_bytes());
            59
        }
        IpcMessage::CancelProfile {
            operation_id,
            receipt_id,
        } => {
            if *operation_id == [0; 16] || *receipt_id == [0; 16] || operation_id == receipt_id {
                return Err(AslError::InvalidMessage);
            }
            body.extend_from_slice(operation_id);
            body.extend_from_slice(receipt_id);
            58
        }
        IpcMessage::PrepareDirectory {
            operation_id,
            agent,
        } => {
            if *operation_id == [0; 16] {
                return Err(AslError::InvalidMessage);
            }
            body.extend_from_slice(operation_id);
            body.extend_from_slice(agent.as_bytes());
            69
        }
        IpcMessage::PublishDirectory {
            operation_id,
            value,
        } => {
            if *operation_id == [0; 16] || value.is_empty() || value.len() > MAX_DHT_VALUE_BYTES {
                return Err(AslError::InvalidMessage);
            }
            body.extend_from_slice(operation_id);
            body.extend_from_slice(value);
            70
        }
        IpcMessage::CancelDirectory {
            operation_id,
            receipt_id,
        } => {
            if *operation_id == [0; 16] || *receipt_id == [0; 16] || operation_id == receipt_id {
                return Err(AslError::InvalidMessage);
            }
            body.extend_from_slice(operation_id);
            body.extend_from_slice(receipt_id);
            71
        }
        IpcMessage::PrepareContactPolicy {
            operation_id,
            agent,
        } => {
            if *operation_id == [0; 16] {
                return Err(AslError::InvalidMessage);
            }
            body.extend_from_slice(operation_id);
            body.extend_from_slice(agent.as_bytes());
            74
        }
        IpcMessage::PublishContactPolicy {
            operation_id,
            value,
        } => {
            if *operation_id == [0; 16] || value.is_empty() || value.len() > MAX_DHT_VALUE_BYTES {
                return Err(AslError::InvalidMessage);
            }
            body.extend_from_slice(operation_id);
            body.extend_from_slice(value);
            75
        }
        IpcMessage::CancelContactPolicy {
            operation_id,
            receipt_id,
        } => {
            if *operation_id == [0; 16] || *receipt_id == [0; 16] || operation_id == receipt_id {
                return Err(AslError::InvalidMessage);
            }
            body.extend_from_slice(operation_id);
            body.extend_from_slice(receipt_id);
            76
        }
        IpcMessage::DhtProviders {
            lookup_id,
            status,
            providers,
        } => {
            if *lookup_id == [0; 16] || providers.len() > MAX_IPC_DHT_PROVIDER_CANDIDATES {
                return Err(AslError::InvalidMessage);
            }
            body.extend_from_slice(lookup_id);
            body.push(*status as u8);
            body.push(providers.len() as u8);
            let mut seen = std::collections::HashSet::new();
            for provider in providers {
                let peer_bytes = provider.peer_id.as_bytes();
                if peer_bytes.is_empty()
                    || peer_bytes.len() > 128
                    || !seen.insert(provider.peer_id.clone())
                {
                    return Err(AslError::InvalidMessage);
                }
                body.extend_from_slice(
                    &u16::try_from(peer_bytes.len())
                        .map_err(|_| AslError::InvalidMessage)?
                        .to_be_bytes(),
                );
                body.extend_from_slice(peer_bytes);
                match provider.endpoint {
                    Some((kind, address)) if address.port() != 0 => {
                        body.push(1);
                        body.push(transport_kind_code(kind));
                        append_socket_addr(&mut body, address)?;
                    }
                    Some(_) => return Err(AslError::InvalidMessage),
                    None => body.push(0),
                }
                body.push(u8::from(provider.relay_route_available));
            }
            45
        }
        IpcMessage::DhtProviderObserved {
            key,
            peer_id,
            addresses,
            expires_at_ms,
        } => {
            append_dht_provider_observation(&mut body, key, peer_id, addresses, *expires_at_ms)?;
            68
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
        IpcMessage::GossipSubscribe { operation_id, key } => {
            if *operation_id == [0; 16] {
                return Err(AslError::InvalidMessage);
            }
            body.extend_from_slice(operation_id);
            body.extend_from_slice(key);
            60
        }
        IpcMessage::GossipUnsubscribe { operation_id, key } => {
            if *operation_id == [0; 16] {
                return Err(AslError::InvalidMessage);
            }
            body.extend_from_slice(operation_id);
            body.extend_from_slice(key);
            61
        }
        IpcMessage::GossipPublish {
            operation_id,
            key,
            payload,
        } => {
            if *operation_id == [0; 16]
                || payload.is_empty()
                || payload.len() > MAX_GOSSIP_PAYLOAD_BYTES
            {
                return Err(AslError::InvalidMessage);
            }
            body.extend_from_slice(operation_id);
            body.extend_from_slice(key);
            body.extend_from_slice(
                &u16::try_from(payload.len())
                    .map_err(|_| AslError::InvalidMessage)?
                    .to_be_bytes(),
            );
            body.extend_from_slice(payload);
            62
        }
        IpcMessage::GossipReceived {
            key,
            propagation_source,
            message_id,
            payload,
        } => {
            if payload.is_empty() || payload.len() > MAX_GOSSIP_PAYLOAD_BYTES {
                return Err(AslError::InvalidMessage);
            }
            let peer = propagation_source.as_bytes();
            if peer.is_empty() || peer.len() > 128 {
                return Err(AslError::InvalidMessage);
            }
            body.extend_from_slice(key);
            body.extend_from_slice(
                &u16::try_from(peer.len())
                    .map_err(|_| AslError::InvalidMessage)?
                    .to_be_bytes(),
            );
            body.extend_from_slice(peer);
            body.extend_from_slice(message_id);
            body.extend_from_slice(
                &u16::try_from(payload.len())
                    .map_err(|_| AslError::InvalidMessage)?
                    .to_be_bytes(),
            );
            body.extend_from_slice(payload);
            63
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
        41 if body.len() >= TASK_BODY_HEADER_BYTES => {
            let task_id = body[..16].try_into().unwrap();
            let operation = ExtractorOperation::from_wire(body[16])?;
            let payload_len = u32::from_be_bytes(body[17..21].try_into().unwrap()) as usize;
            let expected_len = TASK_BODY_HEADER_BYTES
                .checked_add(payload_len)
                .ok_or(AslError::InvalidMessage)?;
            if body.len() != expected_len || payload_len > MAX_IPC_EXTRACTOR_INPUT_BYTES {
                return Err(AslError::InvalidMessage);
            }
            Ok(IpcMessage::RunExtractorTask {
                task_id,
                operation,
                payload: body[TASK_BODY_HEADER_BYTES..].to_vec(),
            })
        }
        42 if body.len() >= 21 => {
            let task_id = body[..16].try_into().unwrap();
            let status = ExtractorStatus::from_wire(body[16])?;
            let payload_len = u32::from_be_bytes(body[17..21].try_into().unwrap()) as usize;
            let expected_len = 21usize
                .checked_add(payload_len)
                .ok_or(AslError::InvalidMessage)?;
            if body.len() != expected_len
                || payload_len > MAX_IPC_EXTRACTOR_OUTPUT_BYTES
                || (status == ExtractorStatus::Rejected && payload_len != 0)
            {
                return Err(AslError::InvalidMessage);
            }
            Ok(IpcMessage::ExtractorResult {
                task_id,
                status,
                payload: body[21..].to_vec(),
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
        46 if body.len() >= 36 => Ok(IpcMessage::PairingInviteRequested {
            connection_id: body[..16].try_into().unwrap(),
            response_id: body[16..32].try_into().unwrap(),
            invite: decode_pairing_invite(&body[32..])?,
        }),
        47 if body.len() >= 40 => {
            let (invite, invite_length) = decode_pairing_invite_prefix(&body[32..])?;
            let exchange_offset = 32 + invite_length;
            let exchange = decode_pairing_exchange(&body[exchange_offset..])?;
            let request_id: [u8; 16] = body[16..32].try_into().unwrap();
            if request_id != invite.invite_id.0 || exchange.exchange_id != invite.invite_id {
                return Err(AslError::InvalidMessage);
            }
            Ok(IpcMessage::PairingExchangeReceived {
                connection_id: body[..16].try_into().unwrap(),
                request_id,
                invite,
                exchange,
            })
        }
        14 if body.len() >= 20 => Ok(IpcMessage::RequestIdentityProof {
            connection_id: body[..16].try_into().unwrap(),
            request: decode_identity_request(&body[16..])?,
        }),
        48 if body.len() >= 36 => {
            let request_id: [u8; 16] = body[16..32].try_into().unwrap();
            let invite = decode_pairing_invite(&body[32..])?;
            if request_id != invite.invite_id.0 {
                return Err(AslError::InvalidMessage);
            }
            Ok(IpcMessage::RequestPairing {
                connection_id: body[..16].try_into().unwrap(),
                request_id,
                invite,
            })
        }
        15 if body.len() >= 36 => Ok(IpcMessage::ReplyIdentityProof {
            connection_id: body[..16].try_into().unwrap(),
            response_id: body[16..32].try_into().unwrap(),
            proof: decode_identity_proof(&body[32..])?,
        }),
        49 if body.len() >= 36 => Ok(IpcMessage::ReplyPairing {
            connection_id: body[..16].try_into().unwrap(),
            response_id: body[16..32].try_into().unwrap(),
            exchange: decode_pairing_exchange(&body[32..])?,
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
        72 if body.len() >= 4 => {
            let state = match body[0] {
                1 => ReachabilityState::Unknown,
                2 => ReachabilityState::Private,
                3 => ReachabilityState::Public,
                _ => return Err(AslError::InvalidMessage),
            };
            let address_len = u16::from_be_bytes(body[2..4].try_into().unwrap()) as usize;
            if address_len > MAX_REACHABILITY_ADDRESS_BYTES
                || body.len() != 4 + address_len
                || (state != ReachabilityState::Public && address_len != 0)
            {
                return Err(AslError::InvalidMessage);
            }
            Ok(IpcMessage::ReachabilityChanged {
                status: ReachabilityStatus {
                    state,
                    confidence: body[1],
                    public_address: (address_len != 0).then(|| body[4..].to_vec()),
                },
            })
        }
        73 if body.len() >= 9 => {
            let peer_len = u16::from_be_bytes(body[..2].try_into().unwrap()) as usize;
            let peer_end = 2 + peer_len;
            if peer_len == 0 || peer_len > 128 || body.len() < peer_end + 6 {
                return Err(AslError::InvalidMessage);
            }
            let state = match body[peer_end] {
                1 => RouteState::DirectDialing,
                2 => RouteState::RelayDialing,
                3 => RouteState::HolePunching,
                4 => RouteState::Direct,
                5 => RouteState::HolePunched,
                6 => RouteState::Relayed,
                7 => RouteState::Failed,
                _ => return Err(AslError::InvalidMessage),
            };
            let relay_len =
                u16::from_be_bytes(body[peer_end + 1..peer_end + 3].try_into().unwrap()) as usize;
            let relay_end = peer_end + 3 + relay_len;
            if relay_len > 128 || body.len() != relay_end + 3 {
                return Err(AslError::InvalidMessage);
            }
            let relay_peer_id = (relay_len != 0)
                .then(|| PeerId::from_bytes(body[peer_end + 3..relay_end].to_vec()))
                .transpose()
                .map_err(|_| AslError::InvalidMessage)?;
            let failure = match body[relay_end + 2] {
                0 => None,
                1 => Some(RouteFailure::DirectUnavailable),
                2 => Some(RouteFailure::RelayUnavailable),
                3 => Some(RouteFailure::HolePunchFailed),
                4 => Some(RouteFailure::TimedOut),
                5 => Some(RouteFailure::PeerIdentityMismatch),
                6 => Some(RouteFailure::Disconnected),
                _ => return Err(AslError::InvalidMessage),
            };
            Ok(IpcMessage::RouteChanged {
                status: RouteStatus {
                    peer_id: PeerId::from_bytes(body[2..peer_end].to_vec())
                        .map_err(|_| AslError::InvalidMessage)?,
                    state,
                    relay_peer_id,
                    direct_attempts: body[relay_end],
                    relay_attempts: body[relay_end + 1],
                    failure,
                },
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
        44 if body.len() == 48 && body[..16] != [0; 16] => Ok(IpcMessage::FindProviders {
            lookup_id: body[..16].try_into().unwrap(),
            key: body[16..48].try_into().unwrap(),
        }),
        64 if body.len() == 48 && body[..16] != [0; 16] => Ok(IpcMessage::LookupDhtRecord {
            operation_id: body[..16].try_into().unwrap(),
            key: body[16..48].try_into().unwrap(),
        }),
        66 if body.len() >= 10 => {
            let expires_at_ms = u64::from_be_bytes(body[..8].try_into().unwrap());
            let length = u16::from_be_bytes(body[8..10].try_into().unwrap()) as usize;
            if expires_at_ms == 0
                || length == 0
                || length > MAX_DHT_VALUE_BYTES
                || body.len() != length + 10
            {
                return Err(AslError::InvalidMessage);
            }
            Ok(IpcMessage::RestoreDhtRecord {
                expires_at_ms,
                value: body[10..].to_vec(),
            })
        }
        67 => {
            let (key, peer_id, addresses, expires_at_ms) = decode_dht_provider_observation(body)?;
            Ok(IpcMessage::RestoreDhtProvider {
                key,
                peer_id,
                addresses,
                expires_at_ms,
            })
        }
        65 if (18..=17 + asl_net::mailbox::MAX_MAILBOX_RECORD_BYTES).contains(&body.len())
            && body[..16] != [0; 16]
            && asl_net::mailbox::MailboxRecord::decode(&body[16..]).is_ok() =>
        {
            Ok(IpcMessage::PublishMailboxRecord {
                operation_id: body[..16].try_into().unwrap(),
                record: body[16..].to_vec(),
            })
        }
        54 if body.len() == 48 && body[..16] != [0; 16] => Ok(IpcMessage::StartProviding {
            operation_id: body[..16].try_into().unwrap(),
            key: body[16..48].try_into().unwrap(),
        }),
        55 if body.len() == 48 && body[..16] != [0; 16] => Ok(IpcMessage::StopProviding {
            operation_id: body[..16].try_into().unwrap(),
            key: body[16..48].try_into().unwrap(),
        }),
        56 if body.len() == 48 && body[..16] != [0; 16] => Ok(IpcMessage::PrepareProfile {
            operation_id: body[..16].try_into().unwrap(),
            agent: AgentId(body[16..].try_into().unwrap()),
        }),
        57 if (17..=16 + MAX_DHT_VALUE_BYTES).contains(&body.len()) && body[..16] != [0; 16] => {
            Ok(IpcMessage::PublishProfile {
                operation_id: body[..16].try_into().unwrap(),
                value: body[16..].to_vec(),
            })
        }
        69 if body.len() == 48 && body[..16] != [0; 16] => Ok(IpcMessage::PrepareDirectory {
            operation_id: body[..16].try_into().unwrap(),
            agent: AgentId(body[16..].try_into().unwrap()),
        }),
        70 if (17..=16 + MAX_DHT_VALUE_BYTES).contains(&body.len()) && body[..16] != [0; 16] => {
            Ok(IpcMessage::PublishDirectory {
                operation_id: body[..16].try_into().unwrap(),
                value: body[16..].to_vec(),
            })
        }
        71 if body.len() == 32
            && body[..16] != [0; 16]
            && body[16..] != [0; 16]
            && body[..16] != body[16..] =>
        {
            Ok(IpcMessage::CancelDirectory {
                operation_id: body[..16].try_into().unwrap(),
                receipt_id: body[16..].try_into().unwrap(),
            })
        }
        74 if body.len() == 48 && body[..16] != [0; 16] => Ok(IpcMessage::PrepareContactPolicy {
            operation_id: body[..16].try_into().unwrap(),
            agent: AgentId(body[16..].try_into().unwrap()),
        }),
        75 if (17..=16 + MAX_DHT_VALUE_BYTES).contains(&body.len()) && body[..16] != [0; 16] => {
            Ok(IpcMessage::PublishContactPolicy {
                operation_id: body[..16].try_into().unwrap(),
                value: body[16..].to_vec(),
            })
        }
        76 if body.len() == 32
            && body[..16] != [0; 16]
            && body[16..] != [0; 16]
            && body[..16] != body[16..] =>
        {
            Ok(IpcMessage::CancelContactPolicy {
                operation_id: body[..16].try_into().unwrap(),
                receipt_id: body[16..].try_into().unwrap(),
            })
        }
        59 if body.len() == 48 && body[..16] != [0; 16] => Ok(IpcMessage::LookupProfile {
            operation_id: body[..16].try_into().unwrap(),
            agent: AgentId(body[16..].try_into().unwrap()),
        }),
        58 if body.len() == 32
            && body[..16] != [0; 16]
            && body[16..] != [0; 16]
            && body[..16] != body[16..] =>
        {
            Ok(IpcMessage::CancelProfile {
                operation_id: body[..16].try_into().unwrap(),
                receipt_id: body[16..].try_into().unwrap(),
            })
        }
        45 if body.len() >= 18 && body[..16] != [0; 16] => {
            let status = match body[16] {
                1 => DhtLookupStatus::Completed,
                2 => DhtLookupStatus::Failed,
                _ => return Err(AslError::InvalidMessage),
            };
            let count = body[17] as usize;
            if count > MAX_IPC_DHT_PROVIDER_CANDIDATES {
                return Err(AslError::InvalidMessage);
            }
            let mut offset = 18;
            let mut providers = Vec::with_capacity(count);
            let mut seen = std::collections::HashSet::new();
            for _ in 0..count {
                if body.len() < offset + 2 {
                    return Err(AslError::InvalidMessage);
                }
                let peer_len =
                    u16::from_be_bytes(body[offset..offset + 2].try_into().unwrap()) as usize;
                offset += 2;
                if peer_len == 0 || peer_len > 128 || body.len() < offset + peer_len + 1 {
                    return Err(AslError::InvalidMessage);
                }
                let peer_id = PeerId::from_bytes(body[offset..offset + peer_len].to_vec())
                    .map_err(|_| AslError::InvalidMessage)?;
                if !seen.insert(peer_id.clone()) {
                    return Err(AslError::InvalidMessage);
                }
                offset += peer_len;
                let endpoint = match body[offset] {
                    0 => {
                        offset += 1;
                        None
                    }
                    1 => {
                        if body.len() < offset + 2 {
                            return Err(AslError::InvalidMessage);
                        }
                        let kind = decode_transport_kind(body[offset + 1])?;
                        let (address, address_len) = decode_socket_addr(&body[offset + 2..])?;
                        if address.port() == 0 {
                            return Err(AslError::InvalidMessage);
                        }
                        offset += 2 + address_len;
                        Some((kind, address))
                    }
                    _ => return Err(AslError::InvalidMessage),
                };
                let relay_route_available = match body.get(offset) {
                    Some(0) => false,
                    Some(1) => true,
                    _ => return Err(AslError::InvalidMessage),
                };
                offset += 1;
                providers.push(DhtProviderCandidate {
                    peer_id,
                    endpoint,
                    relay_route_available,
                });
            }
            if offset != body.len() {
                return Err(AslError::InvalidMessage);
            }
            Ok(IpcMessage::DhtProviders {
                lookup_id: body[..16].try_into().unwrap(),
                status,
                providers,
            })
        }
        68 => {
            let (key, peer_id, addresses, expires_at_ms) = decode_dht_provider_observation(body)?;
            Ok(IpcMessage::DhtProviderObserved {
                key,
                peer_id,
                addresses,
                expires_at_ms,
            })
        }
        60 if body.len() == 48 && body[..16] != [0; 16] => Ok(IpcMessage::GossipSubscribe {
            operation_id: body[..16].try_into().unwrap(),
            key: body[16..48].try_into().unwrap(),
        }),
        61 if body.len() == 48 && body[..16] != [0; 16] => Ok(IpcMessage::GossipUnsubscribe {
            operation_id: body[..16].try_into().unwrap(),
            key: body[16..48].try_into().unwrap(),
        }),
        62 if body.len() >= 50 && body[..16] != [0; 16] => {
            let payload_len = u16::from_be_bytes(body[48..50].try_into().unwrap()) as usize;
            if payload_len == 0
                || payload_len > MAX_GOSSIP_PAYLOAD_BYTES
                || body.len() != 50 + payload_len
            {
                return Err(AslError::InvalidMessage);
            }
            Ok(IpcMessage::GossipPublish {
                operation_id: body[..16].try_into().unwrap(),
                key: body[16..48].try_into().unwrap(),
                payload: body[50..].to_vec(),
            })
        }
        63 if body.len() >= 68 => {
            let key = body[..32].try_into().unwrap();
            let peer_len = u16::from_be_bytes(body[32..34].try_into().unwrap()) as usize;
            if peer_len == 0 || peer_len > 128 || body.len() < 34 + peer_len + 32 + 2 {
                return Err(AslError::InvalidMessage);
            }
            let peer_end = 34 + peer_len;
            let payload_offset = peer_end + 32;
            let payload_len =
                u16::from_be_bytes(body[payload_offset..payload_offset + 2].try_into().unwrap())
                    as usize;
            if payload_len == 0
                || payload_len > MAX_GOSSIP_PAYLOAD_BYTES
                || body.len() != payload_offset + 2 + payload_len
            {
                return Err(AslError::InvalidMessage);
            }
            Ok(IpcMessage::GossipReceived {
                key,
                propagation_source: PeerId::from_bytes(body[34..peer_end].to_vec())
                    .map_err(|_| AslError::InvalidMessage)?,
                message_id: body[peer_end..payload_offset].try_into().unwrap(),
                payload: body[payload_offset + 2..].to_vec(),
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
        43 if body.len() >= 44 => Ok(IpcMessage::ReplyDirect {
            connection_id: body[..16].try_into().unwrap(),
            response_id: body[16..32].try_into().unwrap(),
            expires_at_ms: u64::from_be_bytes(body[32..40].try_into().unwrap()),
            response: decode_control_frame(&body[40..])?,
        }),
        26 if body.len() == 16 + 16 + BULK_REQUEST_IPC_BYTES => Ok(IpcMessage::BulkRequested {
            connection_id: body[..16].try_into().unwrap(),
            response_id: body[16..32].try_into().unwrap(),
            request: decode_bulk_request(&body[32..])?,
        }),
        27 if body.len() >= 53 => {
            let request_id: [u8; 16] = body[16..32].try_into().unwrap();
            let response = decode_bulk_response(&body[32..])?;
            if request_id != response.request_id.0 {
                return Err(AslError::InvalidMessage);
            }
            Ok(IpcMessage::BulkReceived {
                connection_id: body[..16].try_into().unwrap(),
                request_id,
                response,
            })
        }
        28 if body.len() == 16 + BULK_REQUEST_IPC_BYTES => Ok(IpcMessage::SendBulk {
            connection_id: body[..16].try_into().unwrap(),
            request: decode_bulk_request(&body[16..])?,
        }),
        29 if body.len() >= 53 => Ok(IpcMessage::ReplyBulk {
            connection_id: body[..16].try_into().unwrap(),
            response_id: body[16..32].try_into().unwrap(),
            response: decode_bulk_response(&body[32..])?,
        }),
        50 if body.len() >= 44 && body[32..40] != [0; 8] => {
            let request = decode_group_packet(&body[40..])?;
            request.validate_request()?;
            Ok(IpcMessage::SendGroup {
                connection_id: body[..16].try_into().unwrap(),
                request_handle: body[16..32].try_into().unwrap(),
                deadline_ms: u64::from_be_bytes(body[32..40].try_into().unwrap()),
                request,
            })
        }
        51 if body.len() >= 36 => Ok(IpcMessage::ReplyGroup {
            connection_id: body[..16].try_into().unwrap(),
            response_id: body[16..32].try_into().unwrap(),
            response: decode_group_packet(&body[32..])?,
        }),
        52 if body.len() >= 44 && body[32..40] != [0; 8] => {
            let request = decode_group_packet(&body[40..])?;
            request.validate_request()?;
            Ok(IpcMessage::GroupRequested {
                connection_id: body[..16].try_into().unwrap(),
                response_id: body[16..32].try_into().unwrap(),
                deadline_ms: u64::from_be_bytes(body[32..40].try_into().unwrap()),
                request,
            })
        }
        53 if body.len() >= 36 => Ok(IpcMessage::GroupReceived {
            connection_id: body[..16].try_into().unwrap(),
            request_handle: body[16..32].try_into().unwrap(),
            response: decode_group_packet(&body[32..])?,
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

fn append_pairing_invite(body: &mut Vec<u8>, invite: &PairingInvite) -> Result<(), AslError> {
    let bytes = encode_asl_frame(&WireFrame::PairingInvite(invite.clone()))?;
    if bytes.len() > MAX_IPC_PAIRING_FRAME_BYTES {
        return Err(AslError::InvalidMessage);
    }
    append_length_prefixed(body, &bytes)
}

fn append_pairing_exchange(body: &mut Vec<u8>, exchange: &PairingExchange) -> Result<(), AslError> {
    let bytes = encode_asl_frame(&WireFrame::PairingExchange(exchange.clone()))?;
    if bytes.len() > MAX_IPC_PAIRING_FRAME_BYTES {
        return Err(AslError::InvalidMessage);
    }
    append_length_prefixed(body, &bytes)
}

fn decode_pairing_invite(bytes: &[u8]) -> Result<PairingInvite, AslError> {
    let (invite, consumed) = decode_pairing_invite_prefix(bytes)?;
    if consumed != bytes.len() {
        return Err(AslError::InvalidMessage);
    }
    Ok(invite)
}

fn decode_pairing_invite_prefix(bytes: &[u8]) -> Result<(PairingInvite, usize), AslError> {
    let (frame, consumed) = decode_pairing_frame_prefix(bytes)?;
    match frame {
        WireFrame::PairingInvite(invite) => Ok((invite, consumed)),
        _ => Err(AslError::InvalidMessage),
    }
}

fn decode_pairing_exchange(bytes: &[u8]) -> Result<PairingExchange, AslError> {
    let (frame, consumed) = decode_pairing_frame_prefix(bytes)?;
    if consumed != bytes.len() {
        return Err(AslError::InvalidMessage);
    }
    match frame {
        WireFrame::PairingExchange(exchange) => Ok(exchange),
        _ => Err(AslError::InvalidMessage),
    }
}

fn decode_pairing_frame_prefix(bytes: &[u8]) -> Result<(WireFrame, usize), AslError> {
    if bytes.len() < 4 {
        return Err(AslError::InvalidMessage);
    }
    let frame_length = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    let consumed = 4usize
        .checked_add(frame_length)
        .filter(|length| {
            frame_length > 0
                && frame_length <= MAX_IPC_PAIRING_FRAME_BYTES
                && *length <= bytes.len()
        })
        .ok_or(AslError::InvalidMessage)?;
    Ok((decode_asl_frame(&bytes[4..consumed])?, consumed))
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

fn append_group_packet(body: &mut Vec<u8>, packet: &GroupPacket) -> Result<(), AslError> {
    let envelope = packet.clone().into_envelope()?;
    let bytes = encode_asl_frame(&WireFrame::GroupEnvelope(envelope))?;
    append_length_prefixed(body, &bytes)
}

fn decode_group_packet(bytes: &[u8]) -> Result<GroupPacket, AslError> {
    let payload = decode_length_prefixed(bytes, MAX_IPC_GROUP_FRAME_BYTES)?;
    match decode_asl_frame(payload)? {
        WireFrame::GroupEnvelope(envelope) => GroupPacket::from_envelope(envelope),
        _ => Err(AslError::InvalidMessage),
    }
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

fn append_dht_provider_observation(
    body: &mut Vec<u8>,
    key: &[u8; 32],
    peer_id: &PeerId,
    addresses: &[String],
    expires_at_ms: u64,
) -> Result<(), AslError> {
    let peer_bytes = peer_id.as_bytes();
    if expires_at_ms == 0
        || peer_bytes.is_empty()
        || peer_bytes.len() > 128
        || addresses.len() > MAX_DHT_PROVIDER_ADDRESSES
        || addresses
            .iter()
            .any(|address| address.is_empty() || address.len() > MAX_IPC_DHT_PROVIDER_ADDRESS_BYTES)
    {
        return Err(AslError::InvalidMessage);
    }
    body.extend_from_slice(key);
    body.extend_from_slice(
        &u16::try_from(peer_bytes.len())
            .map_err(|_| AslError::InvalidMessage)?
            .to_be_bytes(),
    );
    body.extend_from_slice(peer_bytes);
    body.extend_from_slice(&expires_at_ms.to_be_bytes());
    body.push(addresses.len() as u8);
    for address in addresses {
        body.extend_from_slice(
            &u16::try_from(address.len())
                .map_err(|_| AslError::InvalidMessage)?
                .to_be_bytes(),
        );
        body.extend_from_slice(address.as_bytes());
    }
    Ok(())
}

fn decode_dht_provider_observation(
    body: &[u8],
) -> Result<([u8; 32], PeerId, Vec<String>, u64), AslError> {
    if body.len() < 32 + 2 + 8 + 1 {
        return Err(AslError::InvalidMessage);
    }
    let key = body[..32].try_into().unwrap();
    let peer_len = u16::from_be_bytes(body[32..34].try_into().unwrap()) as usize;
    if peer_len == 0 || peer_len > 128 || body.len() < 34 + peer_len + 8 + 1 {
        return Err(AslError::InvalidMessage);
    }
    let peer_id = PeerId::from_bytes(body[34..34 + peer_len].to_vec())
        .map_err(|_| AslError::InvalidMessage)?;
    let mut offset = 34 + peer_len;
    let expires_at_ms = u64::from_be_bytes(body[offset..offset + 8].try_into().unwrap());
    offset += 8;
    if expires_at_ms == 0 {
        return Err(AslError::InvalidMessage);
    }
    let count = body[offset] as usize;
    offset += 1;
    if count > MAX_DHT_PROVIDER_ADDRESSES {
        return Err(AslError::InvalidMessage);
    }
    let mut addresses = Vec::with_capacity(count);
    for _ in 0..count {
        if body.len() < offset + 2 {
            return Err(AslError::InvalidMessage);
        }
        let length = u16::from_be_bytes(body[offset..offset + 2].try_into().unwrap()) as usize;
        offset += 2;
        if length == 0
            || length > MAX_IPC_DHT_PROVIDER_ADDRESS_BYTES
            || body.len() < offset + length
        {
            return Err(AslError::InvalidMessage);
        }
        addresses.push(
            String::from_utf8(body[offset..offset + length].to_vec())
                .map_err(|_| AslError::InvalidMessage)?,
        );
        offset += length;
    }
    if offset != body.len() {
        return Err(AslError::InvalidMessage);
    }
    Ok((key, peer_id, addresses, expires_at_ms))
}

fn max_body_bytes(kind: u8) -> Option<usize> {
    Some(match kind {
        1..=3 => 0,
        4..=5 => 8,
        6 => MAX_IPC_TASK_PAYLOAD_BYTES + TASK_BODY_HEADER_BYTES,
        41 => MAX_IPC_EXTRACTOR_INPUT_BYTES + TASK_BODY_HEADER_BYTES,
        42 => 21 + MAX_IPC_EXTRACTOR_OUTPUT_BYTES,
        43 => 40 + 4 + MAX_CONTROL_FRAME_BYTES,
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
        44 => 48,
        54..=56 => 48,
        57 => 16 + MAX_DHT_VALUE_BYTES,
        58 => 32,
        59 => 48,
        60..=61 => 48,
        62 => 50 + MAX_GOSSIP_PAYLOAD_BYTES,
        63 => 34 + 128 + 32 + 2 + MAX_GOSSIP_PAYLOAD_BYTES,
        64 => 48,
        65 => 16 + asl_net::mailbox::MAX_MAILBOX_RECORD_BYTES,
        66 => 8 + 2 + MAX_DHT_VALUE_BYTES,
        67 | 68 => {
            32 + 2
                + 128
                + 8
                + 1
                + MAX_DHT_PROVIDER_ADDRESSES * (2 + MAX_IPC_DHT_PROVIDER_ADDRESS_BYTES)
        }
        69 => 48,
        70 => 16 + MAX_DHT_VALUE_BYTES,
        71 => 32,
        72 => 4 + MAX_REACHABILITY_ADDRESS_BYTES,
        73 => 2 + 128 + 1 + 2 + 128 + 3,
        45 => 18 + MAX_IPC_DHT_PROVIDER_CANDIDATES * (2 + 128 + 1 + 2 + 19 + 1),
        46 | 48 => 32 + 4 + MAX_IPC_PAIRING_FRAME_BYTES,
        47 => 32 + 8 + 2 * MAX_IPC_PAIRING_FRAME_BYTES,
        49 => 32 + 4 + MAX_IPC_PAIRING_FRAME_BYTES,
        50 | 52 => 32 + 8 + 4 + MAX_IPC_GROUP_FRAME_BYTES,
        51 | 53 => 32 + 4 + MAX_IPC_GROUP_FRAME_BYTES,
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
        let frame = encode_frame(self.sender, self.receiver, 1, message)?;
        self.send_prepared(frame)
    }

    /// The ordered writer assigns the actual sequence after a local handoff.
    pub(crate) fn send_prepared(&mut self, mut frame: Vec<u8>) -> Result<(), AslError> {
        if self.failed {
            return Err(AslError::InvalidMessage);
        }
        let sequence = self.next_sequence.ok_or(AslError::InvalidMessage)?;
        frame[8..16].copy_from_slice(&sequence.to_be_bytes());
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

#[cfg(all(test, windows))]
pub(crate) fn run_net_pipe_fixture(
    mut input: std::io::PipeReader,
    output: std::io::PipeWriter,
) -> Result<(), AslError> {
    let (identity, loopback_groups, traversal) = read_net_startup_prelude(&mut input)?;
    net_runtime::run(identity, loopback_groups, traversal, input, output)
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
        let (identity, loopback_groups, traversal) = read_net_startup_prelude(&mut stdin.lock())?;
        return net_runtime::run(
            identity,
            loopback_groups,
            traversal,
            stdin,
            std::io::stdout(),
        );
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
            IpcMessage::RunExtractorTask {
                task_id,
                operation,
                payload,
            } if role == IpcRole::Extractor => {
                let result = crate::documents::process(operation, &payload);
                match result {
                    Ok(output) if output.len() <= MAX_IPC_EXTRACTOR_OUTPUT_BYTES => {
                        writer.send(&IpcMessage::ExtractorResult {
                            task_id,
                            status: ExtractorStatus::Completed,
                            payload: output,
                        })?;
                    }
                    _ => writer.send(&IpcMessage::ExtractorResult {
                        task_id,
                        status: ExtractorStatus::Rejected,
                        payload: Vec::new(),
                    })?,
                }
                if reader.receive()?.message != IpcMessage::Shutdown {
                    return Err(AslError::InvalidMessage);
                }
                writer.send(&IpcMessage::Stopped)?;
                return Ok(());
            }
            _ => return Err(AslError::InvalidMessage),
        }
    }
}

pub(crate) fn write_net_startup_prelude<W: Write>(
    writer: &mut W,
    identity: &DeviceIdentity,
    loopback_groups: bool,
    traversal: TraversalConfig,
) -> Result<(), AslError> {
    let traversal = traversal
        .validate()
        .map_err(|_| AslError::InvalidIdentity)?;
    let secret = identity.to_ipc_secret()?;
    let length = u32::try_from(secret.len()).map_err(|_| AslError::InvalidIdentity)?;
    let mut header = [0u8; NET_STARTUP_PRELUDE_HEADER_BYTES];
    header[..4].copy_from_slice(&NET_STARTUP_PRELUDE_MAGIC);
    header[4..6].copy_from_slice(&NET_STARTUP_PRELUDE_VERSION.to_be_bytes());
    header[6..NET_STARTUP_PRELUDE_FLAG_OFFSET].copy_from_slice(&length.to_be_bytes());
    header[NET_STARTUP_PRELUDE_FLAG_OFFSET] = u8::from(loopback_groups);
    header[NET_STARTUP_PRELUDE_CONFIG_LENGTH_OFFSET..]
        .copy_from_slice(&(NET_STARTUP_TRAVERSAL_BYTES as u16).to_be_bytes());
    writer.write_all(&header)?;
    writer.write_all(&encode_traversal_config(traversal))?;
    writer.write_all(&secret)?;
    writer.flush()?;
    Ok(())
}

fn read_net_startup_prelude<R: Read>(
    reader: &mut R,
) -> Result<(DeviceIdentity, bool, TraversalConfig), AslError> {
    let mut prefix = [0u8; NET_STARTUP_PRELUDE_FLAG_OFFSET];
    reader.read_exact(&mut prefix)?;
    if prefix[..4] != NET_STARTUP_PRELUDE_MAGIC {
        return Err(AslError::InvalidMessage);
    }
    if prefix[4..6] != NET_STARTUP_PRELUDE_VERSION.to_be_bytes() {
        return Err(AslError::IncompatibleVersion);
    }
    let length = u32::from_be_bytes(prefix[6..].try_into().unwrap()) as usize;
    if length == 0 || length > MAX_DEVICE_IDENTITY_PRELUDE_BYTES {
        return Err(AslError::InvalidMessage);
    }
    let mut suffix = [0u8; NET_STARTUP_PRELUDE_HEADER_BYTES - NET_STARTUP_PRELUDE_FLAG_OFFSET];
    reader.read_exact(&mut suffix)?;
    let loopback_groups = match suffix[0] {
        0 => false,
        1 => true,
        _ => return Err(AslError::InvalidMessage),
    };
    let config_length = u16::from_be_bytes(suffix[1..].try_into().unwrap()) as usize;
    if config_length != NET_STARTUP_TRAVERSAL_BYTES {
        return Err(AslError::InvalidMessage);
    }
    let mut traversal = [0u8; NET_STARTUP_TRAVERSAL_BYTES];
    reader.read_exact(&mut traversal)?;
    let traversal = decode_traversal_config(&traversal)?;
    let mut secret = Zeroizing::new(vec![0u8; length]);
    reader.read_exact(&mut secret)?;
    Ok((
        DeviceIdentity::from_ipc_secret(&secret)?,
        loopback_groups,
        traversal,
    ))
}

fn encode_traversal_config(config: TraversalConfig) -> [u8; NET_STARTUP_TRAVERSAL_BYTES] {
    let mut bytes = [0u8; NET_STARTUP_TRAVERSAL_BYTES];
    let mut offset = 0;
    for value in [
        config.connection_timeout_ms,
        config.idle_connection_timeout_ms,
        config.hole_punch_timeout_ms,
        config.identify_interval_ms,
        config.autonat_boot_delay_ms,
        config.autonat_retry_interval_ms,
        config.autonat_refresh_interval_ms,
        config.autonat_request_timeout_ms,
        config.relay_retry_base_ms,
        config.relay_retry_max_ms,
    ] {
        bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        offset += 8;
    }
    for value in [
        config.max_relay_endpoints,
        config.max_relay_routes_per_dial,
        config.max_pending_routes,
        config.max_relay_reservation_retries,
        config.autonat_max_peer_addresses,
    ] {
        bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
        offset += 2;
    }
    bytes[offset] = config.autonat_confidence_max;
    bytes
}

fn decode_traversal_config(
    bytes: &[u8; NET_STARTUP_TRAVERSAL_BYTES],
) -> Result<TraversalConfig, AslError> {
    let mut offset = 0;
    let mut next_u64 = || {
        let value = u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap());
        offset += 8;
        value
    };
    let connection_timeout_ms = next_u64();
    let idle_connection_timeout_ms = next_u64();
    let hole_punch_timeout_ms = next_u64();
    let identify_interval_ms = next_u64();
    let autonat_boot_delay_ms = next_u64();
    let autonat_retry_interval_ms = next_u64();
    let autonat_refresh_interval_ms = next_u64();
    let autonat_request_timeout_ms = next_u64();
    let relay_retry_base_ms = next_u64();
    let relay_retry_max_ms = next_u64();
    drop(next_u64);
    let mut next_u16 = || {
        let value = u16::from_be_bytes(bytes[offset..offset + 2].try_into().unwrap());
        offset += 2;
        value
    };
    let max_relay_endpoints = next_u16();
    let max_relay_routes_per_dial = next_u16();
    let max_pending_routes = next_u16();
    let max_relay_reservation_retries = next_u16();
    let autonat_max_peer_addresses = next_u16();
    drop(next_u16);
    TraversalConfig {
        connection_timeout_ms,
        idle_connection_timeout_ms,
        hole_punch_timeout_ms,
        identify_interval_ms,
        autonat_boot_delay_ms,
        autonat_retry_interval_ms,
        autonat_refresh_interval_ms,
        autonat_request_timeout_ms,
        relay_retry_base_ms,
        relay_retry_max_ms,
        max_relay_endpoints,
        max_relay_routes_per_dial,
        max_pending_routes,
        max_relay_reservation_retries,
        autonat_max_peer_addresses,
        autonat_confidence_max: bytes[offset],
    }
    .validate()
    .map_err(|_| AslError::InvalidMessage)
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
        let pair_invite = PairingInvite {
            invite_id: asl_types::ids::Id128([40; 16]),
            inviter: asl_types::ids::AgentId([41; 32]),
            target: asl_types::ids::AgentId([42; 32]),
            expires_at_ms: 100_000,
            nonce: asl_types::ids::Hash32([43; 32]),
            note: "Please pair.".into(),
            provenance: None,
            signature: asl_types::ids::Signature65([44; 65]),
        };
        let pair_exchange = PairingExchange {
            exchange_id: pair_invite.invite_id,
            agent_id: pair_invite.target,
            peer_id: DeviceIdentity::generate().unwrap().peer_id(),
            attempt: 1,
            accepted: false,
            signature: asl_types::ids::Signature65([45; 65]),
            transcript_hash: asl_types::ids::Hash32([46; 32]),
        };
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
            IpcMessage::RunExtractorTask {
                task_id: [30; 16],
                operation: ExtractorOperation::PdfText,
                payload: b"%PDF-1.7".to_vec(),
            },
            IpcMessage::ExtractorResult {
                task_id: [30; 16],
                status: ExtractorStatus::Completed,
                payload: b"bounded extracted text".to_vec(),
            },
            IpcMessage::ExtractorResult {
                task_id: [31; 16],
                status: ExtractorStatus::Rejected,
                payload: Vec::new(),
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
            IpcMessage::OperationFailed {
                operation_id: [12; 16],
                code: NetworkErrorCode::Authentication,
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
            IpcMessage::ReachabilityChanged {
                status: ReachabilityStatus {
                    state: ReachabilityState::Private,
                    confidence: 2,
                    public_address: None,
                },
            },
            IpcMessage::RouteChanged {
                status: RouteStatus {
                    peer_id: DeviceIdentity::generate().unwrap().peer_id(),
                    state: RouteState::Relayed,
                    relay_peer_id: Some(DeviceIdentity::generate().unwrap().peer_id()),
                    direct_attempts: 1,
                    relay_attempts: 1,
                    failure: Some(RouteFailure::HolePunchFailed),
                },
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
            IpcMessage::FindProviders {
                lookup_id: [32; 16],
                key: [33; 32],
            },
            IpcMessage::StartProviding {
                operation_id: [35; 16],
                key: [36; 32],
            },
            IpcMessage::StopProviding {
                operation_id: [37; 16],
                key: [38; 32],
            },
            IpcMessage::PrepareProfile {
                operation_id: [39; 16],
                agent: AgentId([40; 32]),
            },
            IpcMessage::PublishProfile {
                operation_id: [39; 16],
                value: vec![0x81, 0x01],
            },
            IpcMessage::CancelProfile {
                operation_id: [39; 16],
                receipt_id: [40; 16],
            },
            IpcMessage::LookupProfile {
                operation_id: [41; 16],
                agent: AgentId([42; 32]),
            },
            IpcMessage::PrepareDirectory {
                operation_id: [70; 16],
                agent: AgentId([71; 32]),
            },
            IpcMessage::PublishDirectory {
                operation_id: [70; 16],
                value: vec![0x82, 0x01, 0x02],
            },
            IpcMessage::CancelDirectory {
                operation_id: [70; 16],
                receipt_id: [72; 16],
            },
            IpcMessage::DhtProviders {
                lookup_id: [34; 16],
                status: DhtLookupStatus::Completed,
                providers: vec![
                    DhtProviderCandidate {
                        peer_id: DeviceIdentity::generate().unwrap().peer_id(),
                        endpoint: Some((
                            TransportKind::Quic,
                            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3)), 4010),
                        )),
                        relay_route_available: false,
                    },
                    DhtProviderCandidate {
                        peer_id: DeviceIdentity::generate().unwrap().peer_id(),
                        endpoint: None,
                        relay_route_available: true,
                    },
                ],
            },
            IpcMessage::PairingInviteRequested {
                connection_id: [47; 16],
                response_id: [48; 16],
                invite: pair_invite.clone(),
            },
            IpcMessage::PairingExchangeReceived {
                connection_id: [47; 16],
                request_id: pair_invite.invite_id.0,
                invite: pair_invite.clone(),
                exchange: pair_exchange.clone(),
            },
            IpcMessage::RequestPairing {
                connection_id: [47; 16],
                request_id: pair_invite.invite_id.0,
                invite: pair_invite,
            },
            IpcMessage::ReplyPairing {
                connection_id: [47; 16],
                response_id: [48; 16],
                exchange: pair_exchange,
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
                request_id: [20; 16],
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
                protocol: NetworkProtocol::Pairing,
                code: NetworkErrorCode::TimedOut,
            },
            IpcMessage::NetworkError {
                code: NetworkErrorCode::Capacity,
            },
            IpcMessage::LookupDhtRecord {
                operation_id: [61; 16],
                key: [62; 32],
            },
            IpcMessage::RestoreDhtRecord {
                expires_at_ms: u64::MAX - 1,
                value: vec![0x81, 0x01],
            },
            IpcMessage::RestoreDhtProvider {
                key: [70; 32],
                peer_id: DeviceIdentity::generate().unwrap().peer_id(),
                addresses: vec![
                    "/ip4/127.0.0.1/tcp/4001".into(),
                    "/ip4/127.0.0.1/udp/4001/quic-v1".into(),
                ],
                expires_at_ms: u64::MAX - 1,
            },
            IpcMessage::DhtProviderObserved {
                key: [71; 32],
                peer_id: DeviceIdentity::generate().unwrap().peer_id(),
                addresses: vec!["/ip4/192.168.1.4/tcp/4001".into()],
                expires_at_ms: u64::MAX - 1,
            },
            IpcMessage::PublishMailboxRecord {
                operation_id: [63; 16],
                record: asl_net::mailbox::MailboxRecord {
                    recipient_id: [64; 32],
                    sender_id: [65; 32],
                    topic_id: [66; 32],
                    mailbox_id: [67; 32],
                    shard_id: [68; 32],
                    epoch: 1,
                    shard_index: 0,
                    shard_count: 1,
                    expires_at_ms: u64::MAX - 1,
                    ciphertext: vec![69; 16],
                }
                .encode()
                .unwrap(),
            },
            IpcMessage::GossipSubscribe {
                operation_id: [51; 16],
                key: [52; 32],
            },
            IpcMessage::GossipUnsubscribe {
                operation_id: [53; 16],
                key: [54; 32],
            },
            IpcMessage::GossipPublish {
                operation_id: [55; 16],
                key: [56; 32],
                payload: vec![57; 32],
            },
            IpcMessage::GossipReceived {
                key: [58; 32],
                propagation_source: DeviceIdentity::generate().unwrap().peer_id(),
                message_id: [59; 32],
                payload: vec![60; 32],
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
                | IpcMessage::ReachabilityChanged { .. }
                | IpcMessage::RouteChanged { .. }
                | IpcMessage::DiscoveryCandidate { .. }
                | IpcMessage::DhtRecordCandidate { .. }
                | IpcMessage::DhtProviders { .. }
                | IpcMessage::DhtProviderObserved { .. }
                | IpcMessage::PairingInviteRequested { .. }
                | IpcMessage::PairingExchangeReceived { .. }
                | IpcMessage::ControlRequested { .. }
                | IpcMessage::ControlReceived { .. }
                | IpcMessage::BulkRequested { .. }
                | IpcMessage::BulkReceived { .. }
                | IpcMessage::GroupRequested { .. }
                | IpcMessage::GroupReceived { .. }
                | IpcMessage::GossipReceived { .. }
                | IpcMessage::RequestFailed { .. }
                | IpcMessage::NetworkError { .. } => (IpcRole::Net, IpcRole::Core),
                IpcMessage::Shutdown
                | IpcMessage::Ping { .. }
                | IpcMessage::Listen { .. }
                | IpcMessage::Dial { .. }
                | IpcMessage::CloseConnection { .. }
                | IpcMessage::SendControl { .. }
                | IpcMessage::ReplyControl { .. }
                | IpcMessage::ReplyDirect { .. }
                | IpcMessage::SendBulk { .. }
                | IpcMessage::ReplyBulk { .. }
                | IpcMessage::SendGroup { .. }
                | IpcMessage::ReplyGroup { .. }
                | IpcMessage::SetAddressPolicy { .. }
                | IpcMessage::FindProviders { .. }
                | IpcMessage::LookupDhtRecord { .. }
                | IpcMessage::RestoreDhtRecord { .. }
                | IpcMessage::RestoreDhtProvider { .. }
                | IpcMessage::PublishMailboxRecord { .. }
                | IpcMessage::StartProviding { .. }
                | IpcMessage::StopProviding { .. }
                | IpcMessage::PrepareProfile { .. }
                | IpcMessage::PublishProfile { .. }
                | IpcMessage::CancelProfile { .. }
                | IpcMessage::LookupProfile { .. }
                | IpcMessage::DecideDhtRecord { .. }
                | IpcMessage::GossipSubscribe { .. }
                | IpcMessage::GossipUnsubscribe { .. }
                | IpcMessage::GossipPublish { .. } => (IpcRole::Core, IpcRole::Net),
                IpcMessage::ReserveRelay { .. } | IpcMessage::DialViaRelays { .. } => {
                    (IpcRole::Core, IpcRole::Net)
                }
                IpcMessage::RunTask { .. } => (IpcRole::Core, IpcRole::Worker),
                IpcMessage::RunExtractorTask { .. } => (IpcRole::Core, IpcRole::Extractor),
                IpcMessage::ExtractorResult { .. } => (IpcRole::Extractor, IpcRole::Core),
                IpcMessage::TaskResult { .. } | IpcMessage::TaskStarted { .. } => {
                    (IpcRole::Worker, IpcRole::Core)
                }
                IpcMessage::TaskContinue { .. } => (IpcRole::Core, IpcRole::Worker),
                IpcMessage::PeerAuthenticated { .. }
                | IpcMessage::PeerDisconnected { .. }
                | IpcMessage::IdentityProofRequested { .. }
                | IpcMessage::IdentityProofReceived { .. } => (IpcRole::Net, IpcRole::Core),
                IpcMessage::RequestIdentityProof { .. }
                | IpcMessage::ReplyIdentityProof { .. }
                | IpcMessage::RequestPairing { .. }
                | IpcMessage::ReplyPairing { .. }
                | IpcMessage::PrepareDirectory { .. }
                | IpcMessage::PublishDirectory { .. }
                | IpcMessage::CancelDirectory { .. }
                | IpcMessage::PrepareContactPolicy { .. }
                | IpcMessage::PublishContactPolicy { .. }
                | IpcMessage::CancelContactPolicy { .. } => (IpcRole::Core, IpcRole::Net),
            };
            let bytes = encode_frame(sender, receiver, 7, &message)
                .unwrap_or_else(|error| panic!("failed to encode {message:?}: {error:?}"));
            let decoded = decode_frame(&bytes, sender, receiver, 7)
                .unwrap_or_else(|error| panic!("failed to decode {message:?}: {error:?}"));
            assert_eq!(decoded.message, message);
            assert_eq!(decoded.sequence, 7);
            let mut stream = Vec::new();
            FrameWriter::new(&mut stream, sender, receiver)
                .send(&message)
                .unwrap();
            assert_eq!(
                FrameReader::new(stream.as_slice(), sender, receiver)
                    .receive()
                    .unwrap()
                    .message,
                message
            );
        }
    }

    #[test]
    fn group_ipc_is_role_bound_and_keeps_attempt_handles_separate() {
        use asl_types::{
            ids::{Hash32, Id128},
            protocol::{GroupBody, GroupMembership, MAX_GROUP_PAYLOAD_BYTES},
        };

        let connection_id = [1; 16];
        let response_id = [2; 16];
        let request_handle = [3; 16];
        let deadline_ms = 1_800_000_000_000;
        let request = GroupPacket {
            message_id: Id128([4; 16]),
            group_id: Hash32([4; 32]),
            epoch: 5,
            body: GroupBody::Application(vec![6; MAX_GROUP_PAYLOAD_BYTES]),
        };
        let response = GroupPacket {
            body: GroupBody::Membership(GroupMembership::Receipt),
            ..request.clone()
        };
        let cases = [
            (
                IpcRole::Core,
                IpcRole::Net,
                IpcMessage::SendGroup {
                    connection_id,
                    request_handle,
                    deadline_ms,
                    request: request.clone(),
                },
            ),
            (
                IpcRole::Core,
                IpcRole::Net,
                IpcMessage::ReplyGroup {
                    connection_id,
                    response_id,
                    response: response.clone(),
                },
            ),
            (
                IpcRole::Net,
                IpcRole::Core,
                IpcMessage::GroupRequested {
                    connection_id,
                    response_id,
                    deadline_ms,
                    request: request.clone(),
                },
            ),
            (
                IpcRole::Net,
                IpcRole::Core,
                IpcMessage::GroupReceived {
                    connection_id,
                    request_handle,
                    response,
                },
            ),
            (
                IpcRole::Net,
                IpcRole::Core,
                IpcMessage::RequestFailed {
                    connection_id,
                    request_id: request_handle,
                    protocol: NetworkProtocol::Group,
                    code: NetworkErrorCode::TimedOut,
                },
            ),
        ];
        for (sender, receiver, message) in cases {
            let mut bytes = encode_frame(sender, receiver, 1, &message).unwrap();
            assert_eq!(
                decode_frame(&bytes, sender, receiver, 1).unwrap().message,
                message
            );
            let mut invalid = message.clone();
            if let IpcMessage::SendGroup { deadline_ms, .. }
            | IpcMessage::GroupRequested { deadline_ms, .. } = &mut invalid
            {
                *deadline_ms = 0;
                assert!(encode_frame(sender, receiver, 1, &invalid).is_err());
                let mut zero_deadline = bytes.clone();
                zero_deadline[HEADER_BYTES + 32..HEADER_BYTES + 40].fill(0);
                assert!(decode_frame(&zero_deadline, sender, receiver, 1).is_err());
            }
            assert!(encode_frame(receiver, sender, 1, &message).is_err());
            bytes[6] = receiver as u8;
            assert!(decode_frame(&bytes, receiver, sender, 1).is_err());
        }

        assert!(
            encode_frame(
                IpcRole::Core,
                IpcRole::Net,
                1,
                &IpcMessage::SendGroup {
                    connection_id,
                    request_handle,
                    deadline_ms,
                    request: GroupPacket {
                        body: GroupBody::Application(vec![6; MAX_GROUP_PAYLOAD_BYTES + 1]),
                        ..request.clone()
                    },
                },
            )
            .is_err()
        );

        let mut bytes = encode_frame(
            IpcRole::Core,
            IpcRole::Net,
            1,
            &IpcMessage::SendGroup {
                connection_id,
                request_handle,
                deadline_ms,
                request,
            },
        )
        .unwrap();
        let oversized_body = (32 + 8 + 4 + MAX_EXTENDED_FRAME_BYTES + 1) as u32;
        bytes[16..20].copy_from_slice(&oversized_body.to_be_bytes());
        let mut reader = FrameReader::new(
            Cursor::new(&bytes[..HEADER_BYTES]),
            IpcRole::Core,
            IpcRole::Net,
        );
        assert!(matches!(reader.receive(), Err(AslError::InvalidMessage)));
    }

    #[test]
    fn extractor_ipc_is_role_bound_and_payloads_are_bounded() {
        let task = IpcMessage::RunExtractorTask {
            task_id: [1; 16],
            operation: ExtractorOperation::Avatar,
            payload: vec![0; MAX_IPC_EXTRACTOR_INPUT_BYTES],
        };
        let frame = encode_frame(IpcRole::Core, IpcRole::Extractor, 1, &task).unwrap();
        assert_eq!(
            decode_frame(&frame, IpcRole::Core, IpcRole::Extractor, 1)
                .unwrap()
                .message,
            task
        );
        assert!(
            encode_frame(
                IpcRole::Core,
                IpcRole::Extractor,
                1,
                &IpcMessage::RunExtractorTask {
                    task_id: [1; 16],
                    operation: ExtractorOperation::Avatar,
                    payload: vec![0; MAX_IPC_EXTRACTOR_INPUT_BYTES + 1],
                }
            )
            .is_err()
        );

        let result = IpcMessage::ExtractorResult {
            task_id: [1; 16],
            status: ExtractorStatus::Rejected,
            payload: Vec::new(),
        };
        assert!(encode_frame(IpcRole::Worker, IpcRole::Core, 1, &result).is_err());
        assert!(
            encode_frame(
                IpcRole::Extractor,
                IpcRole::Core,
                1,
                &IpcMessage::ExtractorResult {
                    task_id: [1; 16],
                    status: ExtractorStatus::Rejected,
                    payload: vec![1],
                },
            )
            .is_err()
        );
    }

    #[test]
    fn net_startup_prelude_round_trips_identity_and_flag_before_the_first_frame() {
        let identity = DeviceIdentity::generate().unwrap();
        let first_command = IpcMessage::Shutdown;
        let frame = encode_frame(IpcRole::Core, IpcRole::Net, 1, &first_command).unwrap();
        for enabled in [false, true] {
            let mut bytes = Vec::new();
            let traversal = TraversalConfig::default();
            write_net_startup_prelude(&mut bytes, &identity, enabled, traversal).unwrap();
            bytes.extend_from_slice(&frame);
            let mut stream = Cursor::new(bytes);

            let (received, loopback_groups, received_traversal) =
                read_net_startup_prelude(&mut stream).unwrap();
            assert_eq!(received.peer_id(), identity.peer_id());
            assert_eq!(loopback_groups, enabled);
            assert_eq!(received_traversal, traversal);
            let mut reader = FrameReader::new(stream, IpcRole::Core, IpcRole::Net);
            assert_eq!(reader.receive().unwrap().message, first_command);
        }
    }

    #[test]
    fn malformed_or_oversized_device_identity_preludes_are_rejected_before_body_read() {
        struct HeaderOnly {
            bytes: Cursor<Vec<u8>>,
            body_read: bool,
        }

        impl Read for HeaderOnly {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                if self.bytes.position() >= NET_STARTUP_PRELUDE_HEADER_BYTES as u64 {
                    self.body_read = true;
                }
                self.bytes.read(buffer)
            }
        }

        for (magic, version, length, flag, config_length) in [
            (
                *b"NOPE",
                NET_STARTUP_PRELUDE_VERSION,
                32_u32,
                0,
                NET_STARTUP_TRAVERSAL_BYTES as u16,
            ),
            (NET_STARTUP_PRELUDE_MAGIC, 1_u16, 32, 0, 0),
            (
                NET_STARTUP_PRELUDE_MAGIC,
                NET_STARTUP_PRELUDE_VERSION,
                0,
                0,
                NET_STARTUP_TRAVERSAL_BYTES as u16,
            ),
            (
                NET_STARTUP_PRELUDE_MAGIC,
                NET_STARTUP_PRELUDE_VERSION,
                (MAX_DEVICE_IDENTITY_PRELUDE_BYTES + 1) as u32,
                0,
                NET_STARTUP_TRAVERSAL_BYTES as u16,
            ),
            (
                NET_STARTUP_PRELUDE_MAGIC,
                NET_STARTUP_PRELUDE_VERSION,
                32,
                2,
                NET_STARTUP_TRAVERSAL_BYTES as u16,
            ),
            (
                NET_STARTUP_PRELUDE_MAGIC,
                NET_STARTUP_PRELUDE_VERSION,
                32,
                0,
                0,
            ),
        ] {
            let mut header = Vec::new();
            header.extend_from_slice(&magic);
            header.extend_from_slice(&version.to_be_bytes());
            header.extend_from_slice(&length.to_be_bytes());
            if version == NET_STARTUP_PRELUDE_VERSION {
                header.push(flag);
                header.extend_from_slice(&config_length.to_be_bytes());
            }
            let mut reader = HeaderOnly {
                bytes: Cursor::new(header),
                body_read: false,
            };

            let result = read_net_startup_prelude(&mut reader);
            if version == NET_STARTUP_PRELUDE_VERSION {
                assert!(matches!(result, Err(AslError::InvalidMessage)));
            } else {
                assert!(matches!(result, Err(AslError::IncompatibleVersion)));
            }
            assert!(!reader.body_read);
        }
    }

    #[test]
    fn invalid_or_truncated_device_key_payloads_are_rejected() {
        for (length, payload) in [(1_u32, &[0xff][..]), (2, &[0x08][..])] {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&NET_STARTUP_PRELUDE_MAGIC);
            bytes.extend_from_slice(&NET_STARTUP_PRELUDE_VERSION.to_be_bytes());
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes.push(0);
            bytes.extend_from_slice(&(NET_STARTUP_TRAVERSAL_BYTES as u16).to_be_bytes());
            bytes.extend_from_slice(&encode_traversal_config(TraversalConfig::default()));
            bytes.extend_from_slice(payload);
            assert!(read_net_startup_prelude(&mut Cursor::new(bytes)).is_err());
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
