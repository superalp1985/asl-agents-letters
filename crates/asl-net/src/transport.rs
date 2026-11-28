//! Authenticated transports with policy-filtered IP endpoints.

use std::{
    collections::{BTreeSet, HashMap, HashSet, VecDeque},
    convert::Infallible,
    hash::{Hash, Hasher},
    io,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::{Arc, Weak},
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::address_policy::{
    AddressPolicy, allows_ip, allows_listen_ip, validate_multiaddr, validate_transport_address,
};
use crate::dht::{DhtAudience, MAX_DHT_PROVIDER_ADDRESSES, MAX_DHT_VALUE_BYTES};
use crate::relay::{
    RelayEndpoint, parse_relay_endpoint, parse_relay_listen_multiaddr, parse_relay_route,
    relay_route_address,
};
mod behaviour;
mod gossip;
mod mailbox;
mod profile_publication;
mod requests;
use behaviour::{AslBehaviour, BehaviourEvent, DiscoveryEvent};
pub use gossip::{GossipMessage, GossipTopic, MAX_GOSSIP_PAYLOAD_BYTES, MAX_GOSSIP_SUBSCRIPTIONS};
use requests::Requests;

use asl_types::ids::PeerId;
use asl_types::protocol::{
    GroupEnvelope, GroupPacket, IdentityProof, IdentityProofRequest, PairingExchange,
    PairingInvite, WireFrame,
};
use asl_types::record::decode_record;
use libp2p::{
    Multiaddr, Swarm, SwarmBuilder,
    core::{
        ConnectedPoint, Endpoint,
        transport::{ListenerId, PortUse},
    },
    futures::StreamExt,
    identity::Keypair,
    kad::{self, ProviderRecord, RecordKey, store::RecordStore},
    mdns,
    multiaddr::Protocol,
    noise,
    request_response::{self, InboundRequestId, OutboundRequestId, ResponseChannel},
    swarm::{
        ConnectionDenied, ConnectionId, DialError, FromSwarm, NetworkBehaviour, SwarmEvent,
        ToSwarm,
        dial_opts::{DialOpts, PeerCondition},
        dummy,
    },
    tcp, yamux,
};
use rand::{TryRng, rngs::SysRng};

use crate::codec::{
    BULK_PROTOCOL, BulkCodec, BulkRequest, BulkResponse, CONTROL_PROTOCOL, ControlCodec,
    GROUP_PROTOCOL, GroupStreamCodec, IDENTITY_PROOF_PROTOCOL, IdentityProofCodec,
    PAIRING_PROTOCOL, PairingCodec, TimedGroupEnvelope,
};

const MAX_LISTENERS: usize = 16;
const MAX_PENDING_INBOUND: usize = 8;
const MAX_PENDING_OUTBOUND: usize = 8;
const MAX_CONNECTIONS: usize = 16;
const MAX_PENDING_DISCOVERY_DIALS: usize = 8;
const MAX_DISCOVERY_CANDIDATES: usize = 128;
const MAX_PENDING_DISCOVERY_OBSERVATIONS: usize = 256;
const MAX_PENDING_DHT_RECORDS: usize = 32;
const MAX_PENDING_DHT_PROVIDER_LOOKUPS: usize = 24;
const MAX_DHT_PROVIDER_CANDIDATES: usize = 20;
const DHT_CANDIDATE_LIFETIME: Duration = Duration::from_secs(10);
const DHT_QUERY_TIMEOUT: Duration = Duration::from_secs(8);
const DHT_RECORD_RESTORE_TTL: Duration = Duration::from_secs(30 * 60);
const DHT_PROVIDER_RESTORE_TTL: Duration = Duration::from_secs(60 * 60);
const ABSOLUTE_MAX_RELAY_ENDPOINTS: u16 = 32;
const ABSOLUTE_MAX_RELAY_ROUTES_PER_DIAL: u16 = 16;
const ABSOLUTE_MAX_PENDING_ROUTES: u16 = 64;
const ABSOLUTE_MAX_RELAY_RESERVATION_RETRIES: u16 = 1_024;
const ABSOLUTE_MAX_AUTONAT_PEER_ADDRESSES: u16 = 64;
const ABSOLUTE_MAX_AUTONAT_CONFIDENCE: u8 = 10;
const MAX_TRAVERSAL_TIMEOUT_MS: u64 = 24 * 60 * 60 * 1_000;
pub const MAX_REACHABILITY_ADDRESS_BYTES: usize = 512;
const MAX_PENDING_RESPONSES: usize = MAX_CONNECTIONS * 4 * 2;
const MAX_PENDING_REQUESTS: usize = MAX_PENDING_RESPONSES;
const MAX_PROTOCOL_STREAMS_PER_PEER: usize = 2;
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const PAIRING_REQUEST_TIMEOUT: Duration = Duration::from_secs(3 * 60);
const RELAY_RETRY_MAX_SHIFT: u32 = 6;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraversalConfig {
    pub connection_timeout_ms: u64,
    pub idle_connection_timeout_ms: u64,
    pub hole_punch_timeout_ms: u64,
    pub identify_interval_ms: u64,
    pub autonat_boot_delay_ms: u64,
    pub autonat_retry_interval_ms: u64,
    pub autonat_refresh_interval_ms: u64,
    pub autonat_request_timeout_ms: u64,
    pub relay_retry_base_ms: u64,
    pub relay_retry_max_ms: u64,
    pub max_relay_endpoints: u16,
    pub max_relay_routes_per_dial: u16,
    pub max_pending_routes: u16,
    pub max_relay_reservation_retries: u16,
    pub autonat_max_peer_addresses: u16,
    pub autonat_confidence_max: u8,
}

impl TraversalConfig {
    pub fn validate(self) -> io::Result<Self> {
        let durations = [
            self.connection_timeout_ms,
            self.idle_connection_timeout_ms,
            self.hole_punch_timeout_ms,
            self.identify_interval_ms,
            self.autonat_boot_delay_ms,
            self.autonat_retry_interval_ms,
            self.autonat_refresh_interval_ms,
            self.autonat_request_timeout_ms,
            self.relay_retry_base_ms,
            self.relay_retry_max_ms,
        ];
        if durations
            .into_iter()
            .any(|value| value == 0 || value > MAX_TRAVERSAL_TIMEOUT_MS)
            || self.idle_connection_timeout_ms < self.connection_timeout_ms
            || self.hole_punch_timeout_ms < self.connection_timeout_ms
            || self.autonat_refresh_interval_ms < self.autonat_retry_interval_ms
            || self.relay_retry_max_ms < self.relay_retry_base_ms
            || !(1..=ABSOLUTE_MAX_RELAY_ENDPOINTS).contains(&self.max_relay_endpoints)
            || !(1..=ABSOLUTE_MAX_RELAY_ROUTES_PER_DIAL).contains(&self.max_relay_routes_per_dial)
            || self.max_relay_routes_per_dial > self.max_relay_endpoints
            || !(1..=ABSOLUTE_MAX_PENDING_ROUTES).contains(&self.max_pending_routes)
            || !(1..=ABSOLUTE_MAX_RELAY_RESERVATION_RETRIES)
                .contains(&self.max_relay_reservation_retries)
            || !(1..=ABSOLUTE_MAX_AUTONAT_PEER_ADDRESSES).contains(&self.autonat_max_peer_addresses)
            || !(1..=ABSOLUTE_MAX_AUTONAT_CONFIDENCE).contains(&self.autonat_confidence_max)
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(self)
    }

    fn connection_timeout(self) -> Duration {
        Duration::from_millis(self.connection_timeout_ms)
    }

    fn idle_connection_timeout(self) -> Duration {
        Duration::from_millis(self.idle_connection_timeout_ms)
    }

    fn hole_punch_timeout(self) -> Duration {
        Duration::from_millis(self.hole_punch_timeout_ms)
    }

    fn identify_interval(self) -> Duration {
        Duration::from_millis(self.identify_interval_ms)
    }

    fn autonat_boot_delay(self) -> Duration {
        Duration::from_millis(self.autonat_boot_delay_ms)
    }

    fn autonat_retry_interval(self) -> Duration {
        Duration::from_millis(self.autonat_retry_interval_ms)
    }

    fn autonat_refresh_interval(self) -> Duration {
        Duration::from_millis(self.autonat_refresh_interval_ms)
    }

    fn autonat_request_timeout(self) -> Duration {
        Duration::from_millis(self.autonat_request_timeout_ms)
    }

    fn relay_retry_base(self) -> Duration {
        Duration::from_millis(self.relay_retry_base_ms)
    }

    fn relay_retry_max(self) -> Duration {
        Duration::from_millis(self.relay_retry_max_ms)
    }
}

impl Default for TraversalConfig {
    fn default() -> Self {
        Self {
            connection_timeout_ms: 5_000,
            idle_connection_timeout_ms: 30_000,
            hole_punch_timeout_ms: 20_000,
            identify_interval_ms: 5 * 60 * 1_000,
            autonat_boot_delay_ms: 15_000,
            autonat_retry_interval_ms: 90_000,
            autonat_refresh_interval_ms: 15 * 60 * 1_000,
            autonat_request_timeout_ms: 30_000,
            relay_retry_base_ms: 1_000,
            relay_retry_max_ms: 60_000,
            max_relay_endpoints: 8,
            max_relay_routes_per_dial: 3,
            max_pending_routes: 8,
            max_relay_reservation_retries: 32,
            autonat_max_peer_addresses: 20,
            autonat_confidence_max: 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TransportKind {
    Tcp,
    Quic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DiscoveryCandidateState {
    Discovered = 1,
    Expired = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DhtLookupStatus {
    Completed = 1,
    Failed = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ReachabilityState {
    Unknown = 1,
    Private = 2,
    Public = 3,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReachabilityStatus {
    pub state: ReachabilityState,
    pub confidence: u8,
    pub public_address: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RouteState {
    DirectDialing = 1,
    RelayDialing = 2,
    HolePunching = 3,
    Direct = 4,
    HolePunched = 5,
    Relayed = 6,
    Failed = 7,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RouteFailure {
    DirectUnavailable = 1,
    RelayUnavailable = 2,
    HolePunchFailed = 3,
    TimedOut = 4,
    PeerIdentityMismatch = 5,
    Disconnected = 6,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteStatus {
    pub peer_id: PeerId,
    pub state: RouteState,
    pub relay_peer_id: Option<PeerId>,
    pub direct_attempts: u8,
    pub relay_attempts: u8,
    pub failure: Option<RouteFailure>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhtProviderCandidate {
    pub peer_id: PeerId,
    pub endpoint: Option<(TransportKind, SocketAddr)>,
    pub relay_route_available: bool,
}

/// Parses a direct bootstrap endpoint without inventing a default network.
///
/// The multiaddr must contain exactly one IP transport and one canonical
/// libp2p peer ID. The caller supplies the local address policy so a
/// loopback-only profile cannot accidentally dial a public seed.
pub fn parse_bootstrap_multiaddr(
    value: &str,
    policy: AddressPolicy,
) -> io::Result<(PeerId, TransportKind, SocketAddr)> {
    if value.is_empty() || value.len() > 512 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let address = Multiaddr::from_str(value).map_err(|_| io::ErrorKind::InvalidInput)?;
    let endpoint = parse_relay_endpoint(&address)?;
    validate_multiaddr(policy, &endpoint.peer_id, &endpoint.address)
        .map_err(|_| io::ErrorKind::PermissionDenied)?;
    let peer_id =
        PeerId::from_bytes(endpoint.peer_id.to_bytes()).map_err(|_| io::ErrorKind::InvalidInput)?;
    Ok((peer_id, endpoint.transport, endpoint.socket))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DialFailure {
    PeerIdentityMismatch,
    Busy,
    Transport,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryCandidate {
    pub peer_id: PeerId,
    pub kind: TransportKind,
    pub address: SocketAddr,
    pub state: DiscoveryCandidateState,
}

/// Opaque, process-local handle. A reconnect gets a new handle even for the same device.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LocalConnectionId(ConnectionId);

/// A device identity observed only after libp2p authenticates the connection.
#[derive(Debug)]
pub struct AuthenticatedPeer {
    peer: PeerId,
    connection_id: LocalConnectionId,
    lifetime: Weak<()>,
}

impl PartialEq for AuthenticatedPeer {
    fn eq(&self, other: &Self) -> bool {
        self.connection_id == other.connection_id
            && self.peer == other.peer
            && Weak::ptr_eq(&self.lifetime, &other.lifetime)
    }
}

impl Eq for AuthenticatedPeer {}

impl AuthenticatedPeer {
    pub fn peer_id(&self) -> &PeerId {
        &self.peer
    }

    pub fn connection_id(&self) -> LocalConnectionId {
        self.connection_id
    }

    /// False after the transport processes this connection's close or is dropped.
    pub fn is_live(&self) -> bool {
        self.lifetime.strong_count() != 0
    }
}

#[derive(Clone, Debug)]
pub struct RequestToken(LocalConnectionId, u64, Weak<()>);

impl PartialEq for RequestToken {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0 && self.1 == other.1 && Weak::ptr_eq(&self.2, &other.2)
    }
}

impl Eq for RequestToken {}

impl RequestToken {
    pub(super) fn new(connection: &AuthenticatedPeer, id: u64) -> Self {
        Self(connection.connection_id, id, connection.lifetime.clone())
    }

    pub fn belongs_to(&self, connection: &AuthenticatedPeer) -> bool {
        self.0 == connection.connection_id && Weak::ptr_eq(&self.2, &connection.lifetime)
    }
}

#[derive(Clone, Debug)]
pub struct ResponseToken(LocalConnectionId, u64, Weak<()>);

impl PartialEq for ResponseToken {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0 && self.1 == other.1 && Weak::ptr_eq(&self.2, &other.2)
    }
}

impl Eq for ResponseToken {}

impl Hash for ResponseToken {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
        self.1.hash(state);
        self.2.as_ptr().hash(state);
    }
}

impl ResponseToken {
    pub(super) fn new(connection: &AuthenticatedPeer, id: u64) -> Self {
        Self(connection.connection_id, id, connection.lifetime.clone())
    }

    pub(super) fn belongs_to(&self, connection: &AuthenticatedPeer) -> bool {
        self.0 == connection.connection_id && Weak::ptr_eq(&self.2, &connection.lifetime)
    }
}

#[derive(Debug)]
pub enum TransportEvent {
    Listening(TransportKind, SocketAddr),
    ReachabilityChanged(ReachabilityStatus),
    RouteChanged(RouteStatus),
    RelayReserved {
        relay_peer_id: libp2p::PeerId,
        address: Multiaddr,
    },
    RelayUnavailable {
        relay_peer_id: libp2p::PeerId,
    },
    DiscoveryCandidate(DiscoveryCandidate),
    DhtProviders {
        lookup_id: [u8; 16],
        status: DhtLookupStatus,
        providers: Vec<DhtProviderCandidate>,
    },
    DhtProviderObserved {
        key: [u8; 32],
        provider: PeerId,
        addresses: Vec<String>,
        expires_in: Duration,
    },
    DhtRecordCandidate {
        candidate_id: [u8; 16],
        key: [u8; 32],
        value: Vec<u8>,
    },
    ProfilePublicationProgress {
        operation_id: [u8; 16],
        succeeded: bool,
    },
    MailboxRecordPut {
        query_id: MailboxPutQuery,
        succeeded: bool,
    },
    InboundRejected,
    DialFailed {
        peer_id: PeerId,
        failure: DialFailure,
    },
    /// Authenticated device key only; no agent identity, certificate or grant is implied.
    Connected {
        connection: AuthenticatedPeer,
    },
    /// Core must verify the ASL identity/session before forwarding this frame.
    ControlRequest {
        connection: AuthenticatedPeer,
        request: WireFrame,
        response: ResponseToken,
    },
    ControlResponse {
        connection: AuthenticatedPeer,
        request: RequestToken,
        response: WireFrame,
    },
    IdentityProofRequest {
        connection: AuthenticatedPeer,
        request: IdentityProofRequest,
        response: ResponseToken,
    },
    PairingInviteRequest {
        connection: AuthenticatedPeer,
        invite: PairingInvite,
        response: ResponseToken,
    },
    PairingExchangeResponse {
        connection: AuthenticatedPeer,
        request: RequestToken,
        invite: PairingInvite,
        exchange: PairingExchange,
    },
    IdentityProofResponse {
        connection: AuthenticatedPeer,
        request: RequestToken,
        response: IdentityProof,
    },
    BulkRequest {
        connection: AuthenticatedPeer,
        request: BulkRequest,
        response: ResponseToken,
    },
    BulkResponse {
        connection: AuthenticatedPeer,
        request: RequestToken,
        response: BulkResponse,
    },
    GroupRequest {
        connection: AuthenticatedPeer,
        request: GroupPacket,
        response: ResponseToken,
        deadline: Instant,
    },
    GroupResponse {
        connection: AuthenticatedPeer,
        request: RequestToken,
        response: GroupPacket,
    },
    GossipMessage(GossipMessage),
    RequestFailed {
        connection_id: LocalConnectionId,
        request: RequestToken,
    },
    Disconnected {
        connection_id: LocalConnectionId,
        peer: PeerId,
    },
}

pub type MailboxPutQuery = libp2p::kad::QueryId;

/// Driven by polling `next_event` in a Tokio runtime with I/O and time enabled.
/// Construction opens no sockets. Dropping the adapter shuts down its transports.
pub struct LocalTransport {
    live: HashMap<LocalConnectionId, Arc<()>>,
    swarm: Swarm<AslBehaviour>,
    listeners: HashSet<ListenerId>,
    requests: Requests,
    address_policy: AddressPolicy,
    policy_configured: bool,
    network_started: bool,
    pending_discovery_dials: HashSet<libp2p::PeerId>,
    discovery_candidates: HashSet<(libp2p::PeerId, TransportKind, SocketAddr)>,
    pending_discovery_observations: VecDeque<DiscoveryCandidate>,
    pending_transport_events: VecDeque<TransportEvent>,
    traversal: TraversalConfig,
    reachability: ReachabilityStatus,
    routes: HashMap<libp2p::PeerId, RouteAttempt>,
    connection_routes: HashMap<ConnectionId, EstablishedRoute>,
    relay_endpoints: HashMap<libp2p::PeerId, RelayEndpoint>,
    relay_listeners: HashMap<ListenerId, libp2p::PeerId>,
    relay_retries: HashMap<libp2p::PeerId, RelayRetry>,
    reserved_relays: HashSet<libp2p::PeerId>,
    pending_dht_records: HashMap<[u8; 16], (kad::Record, tokio::time::Instant)>,
    pending_dht_provider_lookups: HashMap<kad::QueryId, PendingDhtProviderLookup>,
    pending_mailbox_puts: HashMap<kad::QueryId, RecordKey>,
    profile_publication: Option<profile_publication::Publication>,
    gossip_subscriptions: HashSet<GossipTopic>,
}

struct PendingDhtProviderLookup {
    lookup_id: [u8; 16],
    key: RecordKey,
    providers: HashSet<libp2p::PeerId>,
}

struct RelayRetry {
    attempts: u32,
    retry_at: Option<tokio::time::Instant>,
}

struct RouteAttempt {
    state: RouteState,
    relay_peer_id: Option<libp2p::PeerId>,
    direct_attempts: u8,
    relay_attempts: u8,
    direct_dial: Option<ConnectionId>,
    relay_dial: Option<ConnectionId>,
    deadline: Option<tokio::time::Instant>,
    pending_failure: DialFailure,
}

#[derive(Clone, Copy)]
enum EstablishedRoute {
    Direct {
        peer: libp2p::PeerId,
    },
    Relayed {
        peer: libp2p::PeerId,
        relay_peer_id: Option<libp2p::PeerId>,
    },
}

impl LocalTransport {
    pub fn new(identity: Keypair) -> io::Result<Self> {
        Self::new_with_config(identity, TraversalConfig::default())
    }

    pub fn new_with_config(identity: Keypair, traversal: TraversalConfig) -> io::Result<Self> {
        Self::build(identity, false, traversal)
    }

    /// Enables the MLS group adapter. The caller still needs to
    /// authorize each group operation against an admitted ASL session.
    pub fn new_with_groups(identity: Keypair) -> io::Result<Self> {
        Self::new_with_groups_config(identity, TraversalConfig::default())
    }

    pub fn new_with_groups_config(
        identity: Keypair,
        traversal: TraversalConfig,
    ) -> io::Result<Self> {
        Self::build(identity, true, traversal)
    }

    /// Backward-compatible name for the group-enabled constructor.
    pub fn new_with_loopback_groups(identity: Keypair) -> io::Result<Self> {
        Self::new_with_groups(identity)
    }

    fn build(
        identity: Keypair,
        loopback_groups: bool,
        traversal: TraversalConfig,
    ) -> io::Result<Self> {
        let traversal = traversal.validate()?;
        let local_peer_id = identity.public().to_peer_id();
        let behaviour_traversal = traversal;
        let swarm = SwarmBuilder::with_existing_identity(identity)
            .with_tokio()
            .with_tcp(tcp::Config::default(), noise::Config::new, || {
                yamux::Config::default()
            })
            .map_err(|_| io::Error::other("cannot configure authenticated TCP"))?
            .with_quic_config(|mut config| {
                config.handshake_timeout = traversal.connection_timeout();
                config.max_concurrent_stream_limit = 8;
                config.max_stream_data = 16 * 1024;
                config.max_connection_data = 16 * 1024;
                config
            })
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .map_err(|_| io::Error::other("cannot configure relay client"))?
            .with_behaviour(move |key, relay| {
                AslBehaviour::new(
                    local_peer_id,
                    key.public(),
                    relay,
                    loopback_groups,
                    behaviour_traversal,
                )
            })
            .expect("infallible behaviour constructor")
            .with_swarm_config(|config| {
                config
                    .with_max_negotiating_inbound_streams(4)
                    .with_idle_connection_timeout(traversal.idle_connection_timeout())
            })
            .with_connection_timeout(traversal.connection_timeout())
            .build();
        let reachability = ReachabilityStatus {
            state: ReachabilityState::Unknown,
            confidence: 0,
            public_address: None,
        };
        Ok(Self {
            live: HashMap::new(),
            swarm,
            listeners: HashSet::new(),
            requests: Requests::new(),
            address_policy: AddressPolicy::LoopbackOnly,
            policy_configured: false,
            network_started: false,
            pending_discovery_dials: HashSet::new(),
            discovery_candidates: HashSet::new(),
            pending_discovery_observations: VecDeque::new(),
            pending_transport_events: VecDeque::new(),
            traversal,
            reachability,
            routes: HashMap::new(),
            connection_routes: HashMap::new(),
            relay_endpoints: HashMap::new(),
            relay_listeners: HashMap::new(),
            relay_retries: HashMap::new(),
            reserved_relays: HashSet::new(),
            pending_dht_records: HashMap::new(),
            pending_dht_provider_lookups: HashMap::new(),
            pending_mailbox_puts: HashMap::new(),
            profile_publication: None,
            gossip_subscriptions: HashSet::new(),
        })
    }

    /// Port zero requests an ephemeral port; `Listening` reports each bound endpoint.
    pub fn listen(&mut self, kind: TransportKind, addr: SocketAddr) -> io::Result<()> {
        if !allows_listen_ip(self.address_policy, addr.ip()) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        if addr.ip().is_unspecified() {
            return self.listen_on_policy_interfaces(kind, addr.port());
        }
        self.validate_socket_scope(addr)?;
        require_runtime()?;
        self.reserve_listener_capacity(1)?;
        let endpoint = socket_endpoint(kind, addr)?;
        let id = self
            .swarm
            .listen_on(endpoint)
            .map_err(|_| io::Error::other("cannot bind network listener"))?;
        self.listeners.insert(id);
        self.network_started = true;
        Ok(())
    }

    /// Bind every current interface allowed by policy. Wildcard listeners are never
    /// handed to libp2p, so mDNS advertises concrete interface addresses only.
    pub fn listen_on_policy_interfaces(
        &mut self,
        kind: TransportKind,
        port: u16,
    ) -> io::Result<()> {
        let mut addresses = BTreeSet::new();
        for interface in if_addrs::get_if_addrs()? {
            let ip = interface.ip();
            if ip.is_unspecified()
                || !allows_ip(self.address_policy, ip)
                || matches!(ip, IpAddr::V6(address) if address.is_unicast_link_local())
            {
                continue;
            }
            addresses.insert(SocketAddr::new(ip, port));
        }
        if addresses.is_empty() {
            return Err(io::ErrorKind::AddrNotAvailable.into());
        }
        self.reserve_listener_capacity(addresses.len())?;
        require_runtime()?;

        let mut created = Vec::with_capacity(addresses.len());
        for address in addresses {
            let endpoint = socket_endpoint(kind, address)?;
            match self.swarm.listen_on(endpoint) {
                Ok(id) => created.push(id),
                Err(_) => {
                    for id in created {
                        let _ = self.swarm.remove_listener(id);
                        self.listeners.remove(&id);
                    }
                    return Err(io::Error::other("cannot bind policy-approved interface"));
                }
            }
        }
        self.listeners.extend(created);
        self.network_started = true;
        Ok(())
    }

    pub fn set_address_policy(&mut self, policy: AddressPolicy) -> io::Result<()> {
        if self.policy_configured
            || self.network_started
            || !self.listeners.is_empty()
            || !self.live.is_empty()
        {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if policy == self.address_policy {
            self.policy_configured = true;
            return Ok(());
        }
        if policy.includes_lan() {
            require_runtime()?;
        }
        self.swarm.behaviour_mut().set_address_policy(policy)?;
        self.address_policy = policy;
        self.policy_configured = true;
        Ok(())
    }

    /// Start one handshake to exactly this address and expected device.
    pub fn dial(
        &mut self,
        kind: TransportKind,
        addr: SocketAddr,
        expected: &PeerId,
    ) -> io::Result<()> {
        if !allows_ip(self.address_policy, addr.ip()) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        self.validate_socket_scope(addr)?;
        let endpoint = socket_endpoint(kind, addr)?;
        let peer = libp2p::PeerId::from_bytes(expected.as_bytes())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        if addr.port() == 0 || peer == *self.swarm.local_peer_id() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        require_runtime()?;
        self.start_direct_route(peer, endpoint)
    }

    pub fn reserve_relay(&mut self, address: &Multiaddr) -> io::Result<libp2p::PeerId> {
        let endpoint = parse_relay_endpoint(address)?;
        if endpoint.peer_id == *self.swarm.local_peer_id()
            || (self.address_policy != AddressPolicy::RelayOnly
                && !allows_ip(self.address_policy, endpoint.socket.ip()))
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        if let Some(existing) = self.relay_endpoints.get(&endpoint.peer_id) {
            if existing != &endpoint {
                return Err(io::ErrorKind::AlreadyExists.into());
            }
            if self
                .relay_listeners
                .values()
                .any(|peer_id| *peer_id == endpoint.peer_id)
            {
                return Ok(endpoint.peer_id);
            }
        }
        if !self.relay_endpoints.contains_key(&endpoint.peer_id)
            && self.relay_endpoints.len() >= usize::from(self.traversal.max_relay_endpoints)
        {
            return Err(io::Error::other("relay endpoint limit reached"));
        }
        if self.listeners.len() >= MAX_LISTENERS {
            return Err(io::Error::other("network listener limit reached"));
        }
        require_runtime()?;
        let listener = self
            .swarm
            .listen_on(endpoint.address.clone().with(Protocol::P2pCircuit))
            .map_err(|_| io::Error::other("cannot reserve relay circuit"))?;
        if let Err(error) = self
            .swarm
            .behaviour_mut()
            .allow_relay_endpoint(endpoint.clone())
        {
            self.swarm.remove_listener(listener);
            return Err(error);
        }
        self.listeners.insert(listener);
        self.relay_listeners.insert(listener, endpoint.peer_id);
        self.relay_endpoints
            .insert(endpoint.peer_id, endpoint.clone());
        self.relay_retries
            .entry(endpoint.peer_id)
            .and_modify(|retry| {
                retry.attempts = 0;
                retry.retry_at = None;
            });
        self.network_started = true;
        Ok(endpoint.peer_id)
    }

    pub fn is_relay_reserved(&self, relay_peer_id: &libp2p::PeerId) -> bool {
        self.reserved_relays.contains(relay_peer_id)
    }

    pub fn reachability_status(&self) -> &ReachabilityStatus {
        &self.reachability
    }

    pub fn route_status(&self, peer: &PeerId) -> io::Result<Option<RouteStatus>> {
        let peer =
            libp2p::PeerId::from_bytes(peer.as_bytes()).map_err(|_| io::ErrorKind::InvalidInput)?;
        if !self.routes.contains_key(&peer) {
            return Ok(None);
        }
        let TransportEvent::RouteChanged(status) = self.route_event(peer, None)? else {
            unreachable!("route_event only creates route status events");
        };
        Ok(Some(status))
    }

    pub fn dial_via_relays(&mut self, expected: &PeerId) -> io::Result<()> {
        let peer = libp2p::PeerId::from_bytes(expected.as_bytes())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        if peer == *self.swarm.local_peer_id() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        require_runtime()?;
        self.start_relay_route(peer, DialFailure::Transport, false)
    }

    pub fn add_dht_peer(&mut self, peer: &PeerId, address: &Multiaddr) -> io::Result<()> {
        let peer =
            libp2p::PeerId::from_bytes(peer.as_bytes()).map_err(|_| io::ErrorKind::InvalidInput)?;
        validate_multiaddr(self.address_policy, &peer, address)
            .map_err(|_| io::ErrorKind::PermissionDenied)?;
        self.swarm
            .behaviour_mut()
            .dht
            .add_address(&peer, address.clone());
        self.network_started = true;
        Ok(())
    }

    /// Rehydrates a previously verified signed record into the local Kademlia
    /// store without treating it as a fresh network response.
    pub fn restore_dht_record(&mut self, value: Vec<u8>, expires_at_ms: u64) -> io::Result<()> {
        let signed = decode_record(&value).map_err(|_| io::ErrorKind::InvalidData)?;
        let key = crate::dht::record_key_for_payload(&signed.record.payload)
            .map_err(|_| io::ErrorKind::InvalidData)?;
        let remaining_ms = expires_at_ms
            .checked_sub(unix_time_ms()?)
            .ok_or(io::ErrorKind::TimedOut)?;
        if remaining_ms == 0 {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let mut record = kad::Record::new(key, value);
        record.expires =
            Some(Instant::now() + Duration::from_millis(remaining_ms).min(DHT_RECORD_RESTORE_TTL));
        self.swarm
            .behaviour_mut()
            .dht
            .store_mut()
            .put(record)
            .map_err(|_| io::Error::other("DHT restore capacity reached"))
    }

    pub fn restore_dht_provider(
        &mut self,
        key: [u8; 32],
        provider: &PeerId,
        addresses: &[String],
        expires_at_ms: u64,
    ) -> io::Result<()> {
        let remaining_ms = expires_at_ms
            .checked_sub(unix_time_ms()?)
            .ok_or(io::ErrorKind::TimedOut)?;
        if remaining_ms == 0 {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let provider = libp2p::PeerId::from_bytes(provider.as_bytes())
            .map_err(|_| io::ErrorKind::InvalidInput)?;
        let addresses = addresses
            .iter()
            .take(MAX_DHT_PROVIDER_ADDRESSES)
            .filter_map(|address| {
                let address = address.parse::<Multiaddr>().ok()?;
                validate_multiaddr(self.address_policy, &provider, &address)
                    .ok()
                    .map(|_| address)
            })
            .collect();
        let record = ProviderRecord {
            key: RecordKey::new(&key),
            provider,
            addresses,
            expires: Some(
                Instant::now() + Duration::from_millis(remaining_ms).min(DHT_PROVIDER_RESTORE_TTL),
            ),
        };
        self.swarm
            .behaviour_mut()
            .dht
            .store_mut()
            .add_provider(record)
            .map_err(|_| io::Error::other("DHT provider restore capacity reached"))
    }

    pub fn start_providing(
        &mut self,
        key: RecordKey,
        audience: DhtAudience,
    ) -> io::Result<kad::QueryId> {
        if !audience.allows_public_advertisement() {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        if key.as_ref().len() != 32 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.swarm
            .behaviour_mut()
            .dht
            .start_providing(key)
            .map_err(|_| io::Error::other("DHT provider capacity reached"))
    }

    pub fn stop_providing(&mut self, key: RecordKey) -> io::Result<()> {
        if key.as_ref().len() != 32 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.swarm.behaviour_mut().dht.stop_providing(&key);
        Ok(())
    }

    pub fn get_providers(&mut self, key: RecordKey) -> io::Result<kad::QueryId> {
        if key.as_ref().len() != 32 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(self.swarm.behaviour_mut().dht.get_providers(key))
    }

    pub fn find_providers(
        &mut self,
        key: [u8; 32],
        lookup_id: [u8; 16],
    ) -> io::Result<kad::QueryId> {
        if lookup_id == [0; 16] {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        if self.pending_dht_provider_lookups.len() >= MAX_PENDING_DHT_PROVIDER_LOOKUPS {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if self
            .pending_dht_provider_lookups
            .values()
            .any(|lookup| lookup.lookup_id == lookup_id)
        {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        let key = RecordKey::new(&key);
        let query_id = self.swarm.behaviour_mut().dht.get_providers(key.clone());
        self.pending_dht_provider_lookups.insert(
            query_id,
            PendingDhtProviderLookup {
                lookup_id,
                key,
                providers: HashSet::new(),
            },
        );
        Ok(query_id)
    }

    pub fn get_record(&mut self, key: RecordKey) -> io::Result<kad::QueryId> {
        if key.as_ref().len() != 32 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(self.swarm.behaviour_mut().dht.get_record(key))
    }

    pub fn decide_dht_record(&mut self, candidate_id: [u8; 16], accept: bool) -> io::Result<()> {
        let (mut record, expires_at) = self
            .pending_dht_records
            .remove(&candidate_id)
            .ok_or(io::ErrorKind::NotFound)?;
        if expires_at <= tokio::time::Instant::now() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        if !accept {
            return Ok(());
        }
        record.expires = Some(Instant::now() + Duration::from_secs(30 * 60));
        self.swarm
            .behaviour_mut()
            .dht
            .store_mut()
            .put(record)
            .map_err(|_| io::Error::other("DHT record capacity reached"))
    }

    /// Close only the authenticated connection represented by this handle.
    pub fn close_connection(&mut self, connection: &AuthenticatedPeer) -> io::Result<()> {
        self.require_live(connection)?;
        self.requests.close_connection(connection.connection_id);
        if self.swarm.close_connection(connection.connection_id.0) {
            Ok(())
        } else {
            Err(io::ErrorKind::NotConnected.into())
        }
    }

    /// Failed inbound handshakes are reported without stopping the listener.
    pub async fn next_event(&mut self) -> io::Result<TransportEvent> {
        require_runtime()?;
        if let Some(event) = self.requests.pop_event() {
            return Ok(event);
        }
        if let Some(event) = self.pending_transport_events.pop_front() {
            return Ok(event);
        }
        loop {
            let now = tokio::time::Instant::now();
            self.pending_dht_records
                .retain(|_, (_, expires)| *expires > now);
            self.advance_due_routes(now)?;
            if let Some(event) = self.pending_transport_events.pop_front() {
                return Ok(event);
            }
            if let Some(candidate) = self.pending_discovery_observations.pop_front() {
                return Ok(TransportEvent::DiscoveryCandidate(candidate));
            }
            self.start_due_relay_retries();
            let deadline = [
                self.next_relay_retry_deadline(),
                self.next_pending_dht_deadline(),
                self.next_route_deadline(),
            ]
            .into_iter()
            .flatten()
            .min();
            let event = if let Some(deadline) = deadline {
                tokio::select! {
                    event = self.swarm.select_next_some() => event,
                    _ = tokio::time::sleep_until(deadline) => continue,
                }
            } else {
                self.swarm.select_next_some().await
            };
            match event {
                SwarmEvent::NewListenAddr {
                    listener_id,
                    address,
                } => {
                    if self.relay_listeners.contains_key(&listener_id) {
                        continue;
                    }
                    let (kind, addr) =
                        bound_endpoint(&address).ok_or(io::ErrorKind::InvalidData)?;
                    return Ok(TransportEvent::Listening(kind, addr));
                }
                SwarmEvent::ConnectionEstablished {
                    peer_id,
                    connection_id,
                    endpoint,
                    ..
                } => {
                    if self.relay_endpoints.contains_key(&peer_id) {
                        continue;
                    }
                    self.pending_discovery_dials.remove(&peer_id);
                    self.observe_established_route(peer_id, connection_id, &endpoint)?;
                    let peer = device_peer(peer_id)?;
                    let connection_id = LocalConnectionId(connection_id);
                    let owner = Arc::new(());
                    let lifetime = Arc::downgrade(&owner);
                    self.live.insert(connection_id, owner);
                    return Ok(TransportEvent::Connected {
                        connection: AuthenticatedPeer {
                            peer,
                            connection_id,
                            lifetime,
                        },
                    });
                }
                SwarmEvent::ConnectionClosed {
                    peer_id,
                    connection_id,
                    num_established,
                    ..
                } => {
                    if self.relay_endpoints.contains_key(&peer_id) {
                        if num_established == 0 && self.fail_relay_peer(peer_id) {
                            return Ok(TransportEvent::RelayUnavailable {
                                relay_peer_id: peer_id,
                            });
                        }
                        continue;
                    }
                    self.observe_closed_route(peer_id, connection_id, num_established)?;
                    let connection_id = LocalConnectionId(connection_id);
                    self.live.remove(&connection_id);
                    self.requests.close_connection(connection_id);
                    return Ok(TransportEvent::Disconnected {
                        connection_id,
                        peer: device_peer(peer_id)?,
                    });
                }
                SwarmEvent::Behaviour(BehaviourEvent::Control(event)) => {
                    if let Some(event) = self.handle_control(event)? {
                        return Ok(event);
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::IdentityProof(event)) => {
                    if let Some(event) = self.handle_identity_proof(event)? {
                        return Ok(event);
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Pairing(event)) => {
                    if let Some(event) = self.handle_pairing(event)? {
                        return Ok(event);
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Bulk(event)) => {
                    if let Some(event) = self.handle_bulk(event)? {
                        return Ok(event);
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Group(event)) => {
                    if let Some(event) = self.handle_group(event) {
                        return Ok(event);
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Gossip(event)) => {
                    if let Some(event) = self.handle_gossip(event) {
                        return Ok(event);
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Autonat(event)) => {
                    if let Some(event) = self.handle_autonat(event)? {
                        return Ok(event);
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Dcutr(event)) => {
                    return self.handle_dcutr(event);
                }
                SwarmEvent::Behaviour(BehaviourEvent::Identify) => {}
                SwarmEvent::Behaviour(BehaviourEvent::Discovery(DiscoveryEvent::Mdns(event))) => {
                    self.handle_discovery(event)?;
                }
                SwarmEvent::Behaviour(BehaviourEvent::Kad(event)) => {
                    if let Some(event) = self.handle_dht(event)? {
                        return Ok(event);
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Relay(
                    libp2p::relay::client::Event::ReservationReqAccepted {
                        relay_peer_id,
                        renewal: false,
                        ..
                    },
                )) => {
                    self.reserved_relays.insert(relay_peer_id);
                    self.relay_retries.remove(&relay_peer_id);
                    if let Some(endpoint) = self.relay_endpoints.get(&relay_peer_id) {
                        let address = endpoint
                            .address
                            .clone()
                            .with(Protocol::P2pCircuit)
                            .with(Protocol::P2p(*self.swarm.local_peer_id()));
                        return Ok(TransportEvent::RelayReserved {
                            relay_peer_id,
                            address,
                        });
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Relay(
                    libp2p::relay::client::Event::ReservationReqAccepted { .. },
                )) => {}
                SwarmEvent::Behaviour(BehaviourEvent::Relay(_)) => {}
                SwarmEvent::Behaviour(BehaviourEvent::Admission(never)) => match never {},
                SwarmEvent::ExpiredListenAddr { listener_id, .. } => {
                    if let Some(relay_peer_id) = self.fail_relay_listener(listener_id, false) {
                        return Ok(TransportEvent::RelayUnavailable { relay_peer_id });
                    }
                }
                SwarmEvent::ListenerClosed { listener_id, .. } => {
                    let was_known = self.listeners.remove(&listener_id);
                    if let Some(relay_peer_id) = self.fail_relay_listener(listener_id, true) {
                        return Ok(TransportEvent::RelayUnavailable { relay_peer_id });
                    }
                    if !was_known {
                        continue;
                    }
                    return Err(io::Error::other("network listener closed"));
                }
                SwarmEvent::ListenerError { listener_id, .. } => {
                    let was_known = self.listeners.remove(&listener_id);
                    if let Some(relay_peer_id) = self.fail_relay_listener(listener_id, true) {
                        return Ok(TransportEvent::RelayUnavailable { relay_peer_id });
                    }
                    if !was_known {
                        continue;
                    }
                    return Err(io::Error::other("network listener error"));
                }
                SwarmEvent::IncomingConnectionError { .. } => {
                    return Ok(TransportEvent::InboundRejected);
                }
                SwarmEvent::OutgoingConnectionError {
                    peer_id,
                    connection_id,
                    error,
                } => {
                    if let Some(relay_peer_id) = peer_id
                        && self.relay_endpoints.contains_key(&relay_peer_id)
                        && !self.swarm.is_connected(&relay_peer_id)
                    {
                        if self.fail_relay_peer(relay_peer_id) {
                            return Ok(TransportEvent::RelayUnavailable { relay_peer_id });
                        }
                        if self.relay_retries.contains_key(&relay_peer_id) {
                            continue;
                        }
                    }
                    if let Some(peer_id) = peer_id
                        && self.handle_route_dial_failure(peer_id, connection_id, &error)?
                    {
                        if let Some(event) = self.pending_transport_events.pop_front() {
                            return Ok(event);
                        }
                        continue;
                    }
                    let was_discovery = match peer_id {
                        Some(peer_id) => self.pending_discovery_dials.remove(&peer_id),
                        None => {
                            let had_discovery_dials = !self.pending_discovery_dials.is_empty();
                            self.pending_discovery_dials.clear();
                            had_discovery_dials
                        }
                    };
                    if was_discovery {
                        continue;
                    }
                    if let Some(peer_id) = peer_id {
                        return Ok(TransportEvent::DialFailed {
                            peer_id: device_peer(peer_id)?,
                            failure: classify_dial_failure(&error),
                        });
                    }
                    return Err(dial_error(error));
                }
                _ => {}
            }
        }
    }

    fn start_direct_route(&mut self, peer: libp2p::PeerId, address: Multiaddr) -> io::Result<()> {
        self.reserve_route_capacity(&peer)?;
        if self.swarm.is_connected(&peer) {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        let opts = DialOpts::peer_id(peer)
            .condition(PeerCondition::DisconnectedAndNotDialing)
            .addresses(vec![address])
            .build();
        let connection_id = opts.connection_id();
        let direct_attempts = self
            .routes
            .get(&peer)
            .map_or(1, |route| route.direct_attempts.saturating_add(1));
        self.routes.insert(
            peer,
            RouteAttempt {
                state: RouteState::DirectDialing,
                relay_peer_id: None,
                direct_attempts,
                relay_attempts: 0,
                direct_dial: Some(connection_id),
                relay_dial: None,
                deadline: Some(tokio::time::Instant::now() + self.traversal.connection_timeout()),
                pending_failure: DialFailure::Transport,
            },
        );
        match self.swarm.dial(opts) {
            Ok(()) => {
                self.network_started = true;
                self.queue_route_status(peer)?;
                Ok(())
            }
            Err(error) => {
                let failure = classify_dial_failure(&error);
                if self.start_relay_route(peer, failure, true).is_ok() {
                    return Ok(());
                }
                self.mark_route_failed(peer, route_failure_for_dial(failure))?;
                Err(dial_error(error))
            }
        }
    }

    fn start_relay_route(
        &mut self,
        peer: libp2p::PeerId,
        pending_failure: DialFailure,
        override_pending: bool,
    ) -> io::Result<()> {
        match self.routes.get(&peer).map(|route| route.state) {
            Some(RouteState::DirectDialing | RouteState::Failed) => {}
            Some(
                RouteState::RelayDialing
                | RouteState::HolePunching
                | RouteState::Direct
                | RouteState::HolePunched
                | RouteState::Relayed,
            ) => return Err(io::ErrorKind::WouldBlock.into()),
            None => self.reserve_route_capacity(&peer)?,
        }
        if self.swarm.is_connected(&peer) && !override_pending {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        let addresses = self.relay_route_addresses(&peer)?;
        if addresses.is_empty() {
            return Err(io::ErrorKind::NotConnected.into());
        }
        let relay_peer_id = (addresses.len() == 1)
            .then(|| {
                parse_relay_route(&addresses[0])
                    .ok()
                    .map(|route| route.endpoint.peer_id)
            })
            .flatten();
        let opts = if override_pending {
            DialOpts::peer_id(peer)
                .condition(PeerCondition::Always)
                .addresses(addresses)
                .build()
        } else {
            DialOpts::peer_id(peer)
                .condition(PeerCondition::DisconnectedAndNotDialing)
                .addresses(addresses)
                .build()
        };
        let connection_id = opts.connection_id();
        let previous = self.routes.remove(&peer);
        let route = RouteAttempt {
            state: RouteState::RelayDialing,
            relay_peer_id,
            direct_attempts: previous.as_ref().map_or(0, |route| route.direct_attempts),
            relay_attempts: previous
                .as_ref()
                .map_or(1, |route| route.relay_attempts.saturating_add(1)),
            direct_dial: previous.and_then(|route| route.direct_dial),
            relay_dial: Some(connection_id),
            deadline: Some(tokio::time::Instant::now() + self.traversal.connection_timeout()),
            pending_failure,
        };
        self.routes.insert(peer, route);
        if let Err(error) = self.swarm.dial(opts) {
            self.mark_route_failed(peer, RouteFailure::RelayUnavailable)?;
            return Err(dial_error(error));
        }
        self.network_started = true;
        Ok(())
    }

    fn reserve_route_capacity(&self, peer: &libp2p::PeerId) -> io::Result<()> {
        let already_pending = self.routes.get(peer).is_some_and(|route| {
            matches!(
                route.state,
                RouteState::DirectDialing | RouteState::RelayDialing | RouteState::HolePunching
            )
        });
        if already_pending {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let pending = self
            .routes
            .values()
            .filter(|route| {
                matches!(
                    route.state,
                    RouteState::DirectDialing | RouteState::RelayDialing | RouteState::HolePunching
                )
            })
            .count();
        if pending >= usize::from(self.traversal.max_pending_routes) {
            return Err(io::Error::other("route attempt limit reached"));
        }
        Ok(())
    }

    fn handle_route_dial_failure(
        &mut self,
        peer: libp2p::PeerId,
        connection_id: ConnectionId,
        error: &DialError,
    ) -> io::Result<bool> {
        let Some(route) = self.routes.get(&peer) else {
            return Ok(false);
        };
        let state = route.state;
        let direct_dial = route.direct_dial;
        let relay_dial = route.relay_dial;
        let pending_failure = route.pending_failure;

        if state == RouteState::DirectDialing && direct_dial == Some(connection_id) {
            let failure = classify_dial_failure(error);
            if let Some(route) = self.routes.get_mut(&peer) {
                route.direct_dial = None;
                route.pending_failure = failure;
            }
            if self.start_relay_route(peer, failure, true).is_err() {
                self.mark_route_failed(peer, route_failure_for_dial(failure))?;
                self.queue_dial_failure(peer, failure)?;
            }
            return Ok(true);
        }
        if state == RouteState::RelayDialing && relay_dial == Some(connection_id) {
            let relay_failure = classify_dial_failure(error);
            let final_failure = if pending_failure == DialFailure::PeerIdentityMismatch {
                pending_failure
            } else {
                relay_failure
            };
            self.mark_route_failed(peer, RouteFailure::RelayUnavailable)?;
            self.queue_dial_failure(peer, final_failure)?;
            return Ok(true);
        }
        if state == RouteState::RelayDialing && direct_dial == Some(connection_id) {
            if let Some(route) = self.routes.get_mut(&peer) {
                route.direct_dial = None;
            }
            return Ok(true);
        }
        if matches!(state, RouteState::Direct | RouteState::HolePunched)
            && (direct_dial == Some(connection_id) || relay_dial == Some(connection_id))
        {
            if let Some(route) = self.routes.get_mut(&peer) {
                if direct_dial == Some(connection_id) {
                    route.direct_dial = None;
                }
                if relay_dial == Some(connection_id) {
                    route.relay_dial = None;
                }
            }
            return Ok(true);
        }
        Ok(matches!(
            state,
            RouteState::HolePunching
                | RouteState::HolePunched
                | RouteState::Direct
                | RouteState::Relayed
                | RouteState::Failed
        ))
    }

    fn observe_established_route(
        &mut self,
        peer: libp2p::PeerId,
        connection_id: ConnectionId,
        endpoint: &ConnectedPoint,
    ) -> io::Result<()> {
        let relay_peer_id = relay_peer_from_endpoint(endpoint);
        let established = if endpoint.is_relayed() {
            EstablishedRoute::Relayed {
                peer,
                relay_peer_id,
            }
        } else {
            EstablishedRoute::Direct { peer }
        };
        self.connection_routes.insert(connection_id, established);

        let has_direct = self.peer_has_direct_connection(peer);
        let has_relay = self.peer_has_relay_connection(peer);
        let route = self.routes.entry(peer).or_insert(RouteAttempt {
            state: RouteState::Direct,
            relay_peer_id: None,
            direct_attempts: 0,
            relay_attempts: 0,
            direct_dial: None,
            relay_dial: None,
            deadline: None,
            pending_failure: DialFailure::Transport,
        });
        route.direct_dial = None;
        if endpoint.is_relayed() {
            route.relay_dial = None;
            route.relay_peer_id = relay_peer_id;
            route.state = if has_direct {
                RouteState::Direct
            } else {
                RouteState::HolePunching
            };
            route.deadline = (!has_direct)
                .then_some(tokio::time::Instant::now() + self.traversal.hole_punch_timeout());
        } else if matches!(route.state, RouteState::HolePunching) && has_relay {
            route.deadline =
                Some(tokio::time::Instant::now() + self.traversal.hole_punch_timeout());
        } else {
            route.state = if matches!(route.state, RouteState::Relayed) {
                RouteState::HolePunched
            } else {
                RouteState::Direct
            };
            route.deadline = None;
        }
        Ok(())
    }

    fn observe_closed_route(
        &mut self,
        peer: libp2p::PeerId,
        connection_id: ConnectionId,
        _num_established: u32,
    ) -> io::Result<()> {
        self.connection_routes.remove(&connection_id);
        let has_direct = self.peer_has_direct_connection(peer);
        let relay_connection = self.peer_relay_connection(peer);
        let has_relay = relay_connection.is_some();
        let relay_peer_id = relay_connection.flatten();
        let Some(route) = self.routes.get_mut(&peer) else {
            return Ok(());
        };
        if has_direct {
            if route.state != RouteState::HolePunching {
                route.state = RouteState::Direct;
                route.deadline = None;
            }
        } else if has_relay {
            route.state = RouteState::Relayed;
            route.relay_peer_id = relay_peer_id;
            route.deadline = None;
        } else {
            route.state = RouteState::Failed;
            route.deadline = None;
        }
        Ok(())
    }

    fn handle_autonat(
        &mut self,
        event: libp2p::autonat::Event,
    ) -> io::Result<Option<TransportEvent>> {
        let libp2p::autonat::Event::StatusChanged { new, .. } = event else {
            return Ok(None);
        };
        let (state, public_address) = match new {
            libp2p::autonat::NatStatus::Unknown => (ReachabilityState::Unknown, None),
            libp2p::autonat::NatStatus::Private => (ReachabilityState::Private, None),
            libp2p::autonat::NatStatus::Public(address) => {
                let bytes = address.to_vec();
                (
                    ReachabilityState::Public,
                    (bytes.len() <= MAX_REACHABILITY_ADDRESS_BYTES).then_some(bytes),
                )
            }
        };
        let status = ReachabilityStatus {
            state,
            confidence: u8::try_from(self.swarm.behaviour().autonat.confidence())
                .unwrap_or(u8::MAX),
            public_address,
        };
        if status == self.reachability {
            return Ok(None);
        }
        self.reachability = status.clone();
        Ok(Some(TransportEvent::ReachabilityChanged(status)))
    }

    fn handle_dcutr(&mut self, event: libp2p::dcutr::Event) -> io::Result<TransportEvent> {
        let peer = event.remote_peer_id;
        let has_direct = self.peer_has_direct_connection(peer);
        let has_relay = self.peer_has_relay_connection(peer);
        let route = self.routes.entry(peer).or_insert(RouteAttempt {
            state: RouteState::HolePunching,
            relay_peer_id: None,
            direct_attempts: 0,
            relay_attempts: 0,
            direct_dial: None,
            relay_dial: None,
            deadline: None,
            pending_failure: DialFailure::Transport,
        });
        let failure = if event.result.is_ok() || has_direct {
            route.state = RouteState::HolePunched;
            None
        } else if has_relay {
            route.state = RouteState::Relayed;
            Some(RouteFailure::HolePunchFailed)
        } else {
            route.state = RouteState::Failed;
            Some(RouteFailure::HolePunchFailed)
        };
        route.deadline = None;
        self.route_event(peer, failure)
    }

    fn next_route_deadline(&self) -> Option<tokio::time::Instant> {
        self.routes
            .values()
            .filter_map(|route| route.deadline)
            .min()
    }

    fn advance_due_routes(&mut self, now: tokio::time::Instant) -> io::Result<()> {
        let due = self
            .routes
            .iter()
            .filter_map(|(peer, route)| route.deadline.is_some_and(|at| at <= now).then_some(*peer))
            .collect::<Vec<_>>();
        for peer in due {
            let Some(state) = self.routes.get(&peer).map(|route| route.state) else {
                continue;
            };
            match state {
                RouteState::DirectDialing => {
                    if let Some(route) = self.routes.get_mut(&peer) {
                        route.pending_failure = DialFailure::Transport;
                    }
                    if self
                        .start_relay_route(peer, DialFailure::Transport, true)
                        .is_err()
                    {
                        self.mark_route_failed(peer, RouteFailure::TimedOut)?;
                        self.queue_dial_failure(peer, DialFailure::Transport)?;
                    }
                }
                RouteState::RelayDialing => {
                    self.mark_route_failed(peer, RouteFailure::TimedOut)?;
                    self.queue_dial_failure(peer, DialFailure::Transport)?;
                }
                RouteState::HolePunching => {
                    if self.peer_has_direct_connection(peer) {
                        if let Some(route) = self.routes.get_mut(&peer) {
                            route.state = RouteState::HolePunched;
                            route.deadline = None;
                        }
                        self.queue_route_status(peer)?;
                    } else if self.peer_has_relay_connection(peer) {
                        if let Some(route) = self.routes.get_mut(&peer) {
                            route.state = RouteState::Relayed;
                            route.deadline = None;
                        }
                        self.queue_route_status_with_failure(peer, Some(RouteFailure::TimedOut))?;
                    } else {
                        self.mark_route_failed(peer, RouteFailure::TimedOut)?;
                        self.queue_dial_failure(peer, DialFailure::Transport)?;
                    }
                }
                _ => {
                    if let Some(route) = self.routes.get_mut(&peer) {
                        route.deadline = None;
                    }
                }
            }
        }
        Ok(())
    }

    fn peer_has_direct_connection(&self, peer: libp2p::PeerId) -> bool {
        self.connection_routes.values().any(|route| {
            matches!(route, EstablishedRoute::Direct { peer: route_peer } if *route_peer == peer)
        })
    }

    fn peer_has_relay_connection(&self, peer: libp2p::PeerId) -> bool {
        self.peer_relay_connection(peer).is_some()
    }

    fn peer_relay_connection(&self, peer: libp2p::PeerId) -> Option<Option<libp2p::PeerId>> {
        self.connection_routes
            .values()
            .find_map(|route| match route {
                EstablishedRoute::Relayed {
                    peer: route_peer,
                    relay_peer_id,
                } if *route_peer == peer => Some(*relay_peer_id),
                _ => None,
            })
    }

    fn mark_route_failed(&mut self, peer: libp2p::PeerId, failure: RouteFailure) -> io::Result<()> {
        if let Some(route) = self.routes.get_mut(&peer) {
            route.state = RouteState::Failed;
            route.deadline = None;
            route.direct_dial = None;
            route.relay_dial = None;
        }
        self.queue_route_status_with_failure(peer, Some(failure))
    }

    fn queue_dial_failure(&mut self, peer: libp2p::PeerId, failure: DialFailure) -> io::Result<()> {
        self.pending_transport_events
            .push_back(TransportEvent::DialFailed {
                peer_id: device_peer(peer)?,
                failure,
            });
        Ok(())
    }

    fn queue_route_status(&mut self, peer: libp2p::PeerId) -> io::Result<()> {
        self.queue_route_status_with_failure(peer, None)
    }

    fn queue_route_status_with_failure(
        &mut self,
        peer: libp2p::PeerId,
        failure: Option<RouteFailure>,
    ) -> io::Result<()> {
        let event = self.route_event(peer, failure)?;
        self.pending_transport_events.push_back(event);
        Ok(())
    }

    fn route_event(
        &self,
        peer: libp2p::PeerId,
        failure: Option<RouteFailure>,
    ) -> io::Result<TransportEvent> {
        let route = self.routes.get(&peer).ok_or(io::ErrorKind::NotFound)?;
        Ok(TransportEvent::RouteChanged(RouteStatus {
            peer_id: device_peer(peer)?,
            state: route.state,
            relay_peer_id: route.relay_peer_id.map(device_peer).transpose()?,
            direct_attempts: route.direct_attempts,
            relay_attempts: route.relay_attempts,
            failure,
        }))
    }

    fn relay_route_addresses(&self, target: &libp2p::PeerId) -> io::Result<Vec<Multiaddr>> {
        let mut relays = self
            .relay_endpoints
            .iter()
            .filter(|(relay_peer_id, _)| {
                self.reserved_relays.contains(relay_peer_id)
                    && !self.relay_retries.contains_key(relay_peer_id)
            })
            .collect::<Vec<_>>();
        relays.sort_by_key(|(peer, _)| peer.to_bytes());
        relays
            .into_iter()
            .take(usize::from(self.traversal.max_relay_routes_per_dial))
            .map(|(_, relay)| relay_route_address(&relay.address, target))
            .collect()
    }

    fn next_relay_retry_deadline(&self) -> Option<tokio::time::Instant> {
        self.relay_retries
            .values()
            .filter_map(|retry| retry.retry_at)
            .min()
    }

    fn start_due_relay_retries(&mut self) {
        let now = tokio::time::Instant::now();
        let due = self
            .relay_retries
            .iter()
            .filter_map(|(peer, retry)| {
                retry
                    .retry_at
                    .is_some_and(|deadline| deadline <= now)
                    .then_some(*peer)
            })
            .collect::<Vec<_>>();

        for relay_peer_id in due {
            if let Some(retry) = self.relay_retries.get_mut(&relay_peer_id) {
                retry.retry_at = None;
            }
            let Some(endpoint) = self.relay_endpoints.get(&relay_peer_id) else {
                self.relay_retries.remove(&relay_peer_id);
                continue;
            };
            match self
                .swarm
                .listen_on(endpoint.address.clone().with(Protocol::P2pCircuit))
            {
                Ok(listener) => {
                    self.listeners.insert(listener);
                    self.relay_listeners.insert(listener, relay_peer_id);
                    self.network_started = true;
                }
                Err(_) => self.schedule_relay_retry(relay_peer_id),
            }
        }
    }

    fn fail_relay_listener(
        &mut self,
        listener_id: ListenerId,
        already_closed: bool,
    ) -> Option<libp2p::PeerId> {
        let relay_peer_id = self.relay_listeners.remove(&listener_id)?;
        self.listeners.remove(&listener_id);
        if !already_closed {
            self.swarm.remove_listener(listener_id);
        }
        self.reserved_relays.remove(&relay_peer_id);
        self.schedule_relay_retry(relay_peer_id);
        Some(relay_peer_id)
    }

    fn fail_relay_peer(&mut self, relay_peer_id: libp2p::PeerId) -> bool {
        let listeners = self
            .relay_listeners
            .iter()
            .filter_map(|(listener, peer)| (*peer == relay_peer_id).then_some(*listener))
            .collect::<Vec<_>>();
        for listener in &listeners {
            self.relay_listeners.remove(listener);
            self.listeners.remove(listener);
            self.swarm.remove_listener(*listener);
        }

        let was_active = self.reserved_relays.remove(&relay_peer_id) || !listeners.is_empty();
        if was_active {
            self.schedule_relay_retry(relay_peer_id);
        }
        was_active
    }

    fn schedule_relay_retry(&mut self, relay_peer_id: libp2p::PeerId) {
        let retry = self
            .relay_retries
            .entry(relay_peer_id)
            .or_insert(RelayRetry {
                attempts: 0,
                retry_at: None,
            });
        retry.attempts = retry.attempts.saturating_add(1);
        retry.retry_at = (retry.attempts
            <= u32::from(self.traversal.max_relay_reservation_retries))
        .then(|| {
            tokio::time::Instant::now()
                + relay_retry_delay(
                    retry.attempts,
                    self.traversal.relay_retry_base(),
                    self.traversal.relay_retry_max(),
                )
        });
    }

    fn validate_socket_scope(&self, address: SocketAddr) -> io::Result<()> {
        if matches!(address, SocketAddr::V6(value) if value.scope_id() != 0 || value.flowinfo() != 0)
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(())
    }

    fn reserve_listener_capacity(&self, requested: usize) -> io::Result<()> {
        if self.listeners.len().saturating_add(requested) > MAX_LISTENERS {
            return Err(io::Error::other("listener limit reached"));
        }
        Ok(())
    }

    fn handle_discovery(&mut self, event: mdns::Event) -> io::Result<()> {
        match event {
            mdns::Event::Discovered(peers) => {
                for (peer_id, address) in peers {
                    let Some(address) = policy_approved_discovery_address(
                        self.address_policy,
                        self.swarm.local_peer_id(),
                        peer_id,
                        address,
                    ) else {
                        continue;
                    };
                    let Some((kind, socket)) = bound_endpoint(&address) else {
                        continue;
                    };
                    self.swarm
                        .behaviour_mut()
                        .dht
                        .add_address(&peer_id, address.clone());
                    let candidate_key = (peer_id, kind, socket);
                    if !self.discovery_candidates.contains(&candidate_key)
                        && self.discovery_candidates.len() < MAX_DISCOVERY_CANDIDATES
                    {
                        self.discovery_candidates.insert(candidate_key);
                        if self.pending_discovery_observations.len()
                            < MAX_PENDING_DISCOVERY_OBSERVATIONS
                        {
                            self.pending_discovery_observations
                                .push_back(DiscoveryCandidate {
                                    peer_id: device_peer(peer_id)?,
                                    kind,
                                    address: socket,
                                    state: DiscoveryCandidateState::Discovered,
                                });
                        }
                    }

                    if self.swarm.is_connected(&peer_id)
                        || self.pending_discovery_dials.contains(&peer_id)
                        || self.pending_discovery_dials.len() >= MAX_PENDING_DISCOVERY_DIALS
                    {
                        continue;
                    }
                    if self
                        .swarm
                        .dial(
                            DialOpts::peer_id(peer_id)
                                .condition(PeerCondition::DisconnectedAndNotDialing)
                                .addresses(vec![address])
                                .build(),
                        )
                        .is_ok()
                    {
                        self.pending_discovery_dials.insert(peer_id);
                        self.network_started = true;
                    }
                }
            }
            mdns::Event::Expired(peers) => {
                for (peer_id, address) in peers {
                    let Some(address) = policy_approved_discovery_address(
                        self.address_policy,
                        self.swarm.local_peer_id(),
                        peer_id,
                        address,
                    ) else {
                        continue;
                    };
                    let Some((kind, socket)) = bound_endpoint(&address) else {
                        continue;
                    };
                    if self.discovery_candidates.remove(&(peer_id, kind, socket))
                        && self.pending_discovery_observations.len()
                            < MAX_PENDING_DISCOVERY_OBSERVATIONS
                    {
                        self.pending_discovery_observations
                            .push_back(DiscoveryCandidate {
                                peer_id: device_peer(peer_id)?,
                                kind,
                                address: socket,
                                state: DiscoveryCandidateState::Expired,
                            });
                    }
                }
            }
        }
        Ok(())
    }

    fn handle_dht(&mut self, event: kad::Event) -> io::Result<Option<TransportEvent>> {
        if let Some(progress) = self.handle_mailbox_put_progress(&event) {
            return Ok(Some(progress));
        }
        if let Some(progress) = self.handle_profile_publication_progress(&event) {
            return Ok(Some(progress));
        }
        if let kad::Event::OutboundQueryProgressed {
            id,
            result: kad::QueryResult::GetProviders(result),
            step,
            ..
        } = &event
        {
            return self.handle_provider_lookup_progress(*id, result, step.last);
        }

        let record = match event {
            kad::Event::InboundRequest {
                request:
                    kad::InboundRequest::AddProvider {
                        record: Some(mut record),
                    },
            } => {
                if record.key.as_ref().len() != 32 || record.provider == *self.swarm.local_peer_id()
                {
                    return Ok(None);
                }
                let key: [u8; 32] = record.key.as_ref().try_into().unwrap();
                let provider = record.provider;
                let mut addresses = Vec::new();
                for address in record.addresses {
                    if addresses.len() == MAX_DHT_PROVIDER_ADDRESSES {
                        break;
                    }
                    if validate_multiaddr(self.address_policy, &record.provider, &address).is_ok() {
                        addresses.push(address);
                    }
                }
                record.addresses = addresses;
                let store = self.swarm.behaviour_mut().dht.store_mut();
                if store.add_provider(record).is_err() {
                    return Ok(None);
                }
                let Some(stored) = store
                    .providers(&RecordKey::new(&key))
                    .into_iter()
                    .find(|record| record.provider == provider)
                else {
                    return Ok(None);
                };
                let expires_in = stored
                    .expires
                    .unwrap_or_else(|| Instant::now() + DHT_PROVIDER_RESTORE_TTL)
                    .saturating_duration_since(Instant::now());
                if expires_in.is_zero() {
                    return Ok(None);
                }
                return Ok(Some(TransportEvent::DhtProviderObserved {
                    key,
                    provider: device_peer(provider)?,
                    addresses: stored
                        .addresses
                        .into_iter()
                        .map(|address| address.to_string())
                        .collect(),
                    expires_in,
                }));
            }
            kad::Event::InboundRequest {
                request:
                    kad::InboundRequest::PutRecord {
                        record: Some(record),
                        ..
                    },
            } => record,
            kad::Event::OutboundQueryProgressed {
                result: kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(peer_record))),
                ..
            } => peer_record.record,
            _ => return Ok(None),
        };

        if record.key.as_ref().len() != 32
            || record.value.is_empty()
            || record.value.len() > MAX_DHT_VALUE_BYTES
            || self.pending_dht_records.len() >= MAX_PENDING_DHT_RECORDS
        {
            return Ok(None);
        }

        let key: [u8; 32] = record.key.as_ref().try_into().unwrap();
        let mut candidate_id = [0; 16];
        for _ in 0..8 {
            SysRng
                .try_fill_bytes(&mut candidate_id)
                .map_err(|_| io::Error::other("cannot allocate DHT request handle"))?;
            if candidate_id != [0; 16] && !self.pending_dht_records.contains_key(&candidate_id) {
                self.pending_dht_records.insert(
                    candidate_id,
                    (
                        record.clone(),
                        tokio::time::Instant::now() + DHT_CANDIDATE_LIFETIME,
                    ),
                );
                return Ok(Some(TransportEvent::DhtRecordCandidate {
                    candidate_id,
                    key,
                    value: record.value,
                }));
            }
        }
        Ok(None)
    }

    fn handle_provider_lookup_progress(
        &mut self,
        query_id: kad::QueryId,
        result: &kad::GetProvidersResult,
        is_last: bool,
    ) -> io::Result<Option<TransportEvent>> {
        match result {
            Ok(kad::GetProvidersOk::FoundProviders { providers, .. }) => {
                if let Some(lookup) = self.pending_dht_provider_lookups.get_mut(&query_id) {
                    for provider in providers {
                        if lookup.providers.len() >= MAX_DHT_PROVIDER_CANDIDATES {
                            break;
                        }
                        lookup.providers.insert(*provider);
                    }
                }
                if !is_last {
                    return Ok(None);
                }
                self.finish_provider_lookup(query_id, DhtLookupStatus::Completed)
            }
            Ok(kad::GetProvidersOk::FinishedWithNoAdditionalRecord { .. }) => {
                self.finish_provider_lookup(query_id, DhtLookupStatus::Completed)
            }
            Err(_) => self.finish_provider_lookup(query_id, DhtLookupStatus::Failed),
        }
    }

    fn finish_provider_lookup(
        &mut self,
        query_id: kad::QueryId,
        status: DhtLookupStatus,
    ) -> io::Result<Option<TransportEvent>> {
        let Some(lookup) = self.pending_dht_provider_lookups.remove(&query_id) else {
            return Ok(None);
        };
        let local_peer = *self.swarm.local_peer_id();
        let mut peers = lookup.providers.into_iter().collect::<Vec<_>>();
        peers.retain(|peer| *peer != local_peer);
        peers.sort_by_key(|peer| peer.to_bytes());

        let providers = peers
            .into_iter()
            .take(MAX_DHT_PROVIDER_CANDIDATES)
            .map(|peer| {
                let endpoint = self.provider_endpoint(&lookup.key, peer);
                let relay_route_available = self
                    .relay_route_addresses(&peer)
                    .is_ok_and(|addresses| !addresses.is_empty());
                Ok(DhtProviderCandidate {
                    peer_id: device_peer(peer)?,
                    endpoint,
                    relay_route_available,
                })
            })
            .collect::<io::Result<Vec<_>>>()?;

        Ok(Some(TransportEvent::DhtProviders {
            lookup_id: lookup.lookup_id,
            status,
            providers,
        }))
    }

    fn provider_endpoint(
        &mut self,
        key: &RecordKey,
        peer: libp2p::PeerId,
    ) -> Option<(TransportKind, SocketAddr)> {
        let mut addresses = self
            .swarm
            .behaviour_mut()
            .dht
            .store_mut()
            .providers(key)
            .into_iter()
            .find(|record| record.provider == peer)
            .map(|record| record.addresses)
            .unwrap_or_default();
        addresses.extend(
            self.swarm
                .behaviour_mut()
                .dht
                .kbuckets()
                .find_map(|bucket| {
                    bucket
                        .iter()
                        .find(|entry| entry.node.key.preimage() == &peer)
                        .map(|entry| entry.node.value.iter().cloned().collect::<Vec<_>>())
                })
                .unwrap_or_default(),
        );
        select_provider_endpoint(self.address_policy, &peer, addresses)
    }

    fn next_pending_dht_deadline(&self) -> Option<tokio::time::Instant> {
        self.pending_dht_records
            .values()
            .map(|(_, deadline)| *deadline)
            .min()
    }
}

fn unix_time_ms() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| io::Error::other("system clock is before UNIX epoch"))
        .and_then(|elapsed| {
            u64::try_from(elapsed.as_millis())
                .map_err(|_| io::Error::other("system clock overflow"))
        })
}

fn select_provider_endpoint(
    policy: AddressPolicy,
    peer: &libp2p::PeerId,
    addresses: impl IntoIterator<Item = Multiaddr>,
) -> Option<(TransportKind, SocketAddr)> {
    addresses.into_iter().find_map(|address| {
        validate_multiaddr(policy, peer, &address).ok()?;
        bound_endpoint(&address)
    })
}

fn policy_approved_discovery_address(
    policy: AddressPolicy,
    local_peer: &libp2p::PeerId,
    peer: libp2p::PeerId,
    address: Multiaddr,
) -> Option<Multiaddr> {
    if peer == *local_peer || validate_multiaddr(policy, &peer, &address).is_err() {
        return None;
    }
    Some(if matches!(address.iter().last(), Some(Protocol::P2p(_))) {
        address
    } else {
        address.with(Protocol::P2p(peer))
    })
}

fn require_runtime() -> io::Result<()> {
    tokio::runtime::Handle::try_current()
        .map(|_| ())
        .map_err(|_| io::Error::other("transport requires a Tokio runtime"))
}

fn device_peer(peer: libp2p::PeerId) -> io::Result<PeerId> {
    PeerId::from_bytes(peer.to_bytes()).map_err(|_| io::ErrorKind::InvalidData.into())
}

fn dial_error(error: DialError) -> io::Error {
    match error {
        DialError::WrongPeerId { .. } => io::ErrorKind::PermissionDenied,
        DialError::DialPeerConditionFalse(_) | DialError::Denied { .. } => {
            io::ErrorKind::WouldBlock
        }
        _ => io::ErrorKind::ConnectionAborted,
    }
    .into()
}

fn classify_dial_failure(error: &DialError) -> DialFailure {
    match error {
        DialError::WrongPeerId { .. } => DialFailure::PeerIdentityMismatch,
        DialError::DialPeerConditionFalse(_) | DialError::Denied { .. } => DialFailure::Busy,
        _ => DialFailure::Transport,
    }
}

fn route_failure_for_dial(failure: DialFailure) -> RouteFailure {
    match failure {
        DialFailure::PeerIdentityMismatch => RouteFailure::PeerIdentityMismatch,
        DialFailure::Busy | DialFailure::Transport => RouteFailure::DirectUnavailable,
    }
}

fn relay_peer_from_endpoint(endpoint: &ConnectedPoint) -> Option<libp2p::PeerId> {
    let address = match endpoint {
        ConnectedPoint::Dialer { address, .. } => address,
        ConnectedPoint::Listener { local_addr, .. } => local_addr,
    };
    parse_relay_route(address)
        .ok()
        .map(|route| route.endpoint.peer_id)
}

fn relay_retry_delay(attempts: u32, base: Duration, maximum: Duration) -> Duration {
    let shift = attempts.saturating_sub(1).min(RELAY_RETRY_MAX_SHIFT);
    base.saturating_mul(1u32 << shift).min(maximum)
}

pub(crate) fn socket_endpoint(kind: TransportKind, addr: SocketAddr) -> io::Result<Multiaddr> {
    let ip = Multiaddr::from(addr.ip());
    Ok(match kind {
        TransportKind::Tcp => ip.with(Protocol::Tcp(addr.port())),
        TransportKind::Quic => ip.with(Protocol::Udp(addr.port())).with(Protocol::QuicV1),
    })
}

fn bound_endpoint(addr: &Multiaddr) -> Option<(TransportKind, SocketAddr)> {
    let mut parts = addr.iter();
    let ip = match parts.next()? {
        Protocol::Ip4(ip) => IpAddr::V4(ip),
        Protocol::Ip6(ip) => IpAddr::V6(ip),
        _ => return None,
    };
    let (kind, port) = match parts.next()? {
        Protocol::Tcp(port) => (TransportKind::Tcp, port),
        Protocol::Udp(port) if parts.next() == Some(Protocol::QuicV1) => {
            (TransportKind::Quic, port)
        }
        _ => return None,
    };
    if port == 0 {
        return None;
    }
    match parts.next() {
        Some(Protocol::P2p(_)) if parts.next().is_none() => {}
        None => {}
        _ => return None,
    }
    (ip.is_unspecified() || !ip.is_multicast()).then_some((kind, SocketAddr::new(ip, port)))
}

fn valid_inbound_endpoint(policy: AddressPolicy, address: &Multiaddr, local: bool) -> bool {
    let Some((_, socket)) = bound_endpoint(address) else {
        return false;
    };
    if local {
        allows_listen_ip(policy, socket.ip())
    } else {
        validate_transport_address(policy, address).is_ok()
    }
}

// Keep only live identities. Each pending handshake owns its own reservation,
// even if an inbound and an outbound handshake involve the same peer.
struct Admission {
    local_peer_id: libp2p::PeerId,
    established: HashSet<libp2p::PeerId>,
    pending_outgoing: HashSet<ConnectionId>,
    pending_incoming: HashSet<ConnectionId>,
    policy: AddressPolicy,
    max_outbound_addresses: usize,
    relay_endpoints: HashMap<libp2p::PeerId, RelayEndpoint>,
}

impl Admission {
    fn new(
        local_peer_id: libp2p::PeerId,
        policy: AddressPolicy,
        max_outbound_addresses: usize,
    ) -> Self {
        Self {
            local_peer_id,
            established: HashSet::new(),
            pending_outgoing: HashSet::new(),
            pending_incoming: HashSet::new(),
            policy,
            max_outbound_addresses,
            relay_endpoints: HashMap::new(),
        }
    }

    fn allow_relay_endpoint(&mut self, endpoint: RelayEndpoint) -> io::Result<()> {
        if endpoint.peer_id == self.local_peer_id
            || (self.policy != AddressPolicy::RelayOnly
                && !allows_ip(self.policy, endpoint.socket.ip()))
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        match self.relay_endpoints.get(&endpoint.peer_id) {
            Some(existing) if existing == &endpoint => Ok(()),
            Some(_) => Err(io::ErrorKind::AlreadyExists.into()),
            None => {
                self.relay_endpoints.insert(endpoint.peer_id, endpoint);
                Ok(())
            }
        }
    }

    fn matches_relay_route(
        &self,
        expected_peer: Option<libp2p::PeerId>,
        address: &Multiaddr,
    ) -> bool {
        let Ok(route) = parse_relay_route(address) else {
            return false;
        };
        let target_matches = match expected_peer {
            Some(expected) => route.target_peer_id == Some(expected),
            None => route.target_peer_id.is_some(),
        };
        target_matches && self.matches_configured_relay(&route.endpoint)
    }

    fn allows_outbound_address(&self, expected_peer: libp2p::PeerId, address: &Multiaddr) -> bool {
        self.matches_relay_endpoint(expected_peer, address)
            || validate_multiaddr(self.policy, &expected_peer, address).is_ok()
            || self.matches_relay_route(Some(expected_peer), address)
    }

    fn allows_inbound_connection(
        &self,
        expected_peer: Option<libp2p::PeerId>,
        local_address: &Multiaddr,
        remote_address: &Multiaddr,
    ) -> bool {
        if valid_inbound_endpoint(self.policy, local_address, true)
            && valid_inbound_endpoint(self.policy, remote_address, false)
        {
            return true;
        }

        let Ok(route) = parse_relay_route(local_address) else {
            return false;
        };
        let target_matches = route
            .target_peer_id
            .is_none_or(|target| target == self.local_peer_id);
        let mut remote_parts = remote_address.iter();
        let source_matches = matches!(
            remote_parts.next(),
            Some(Protocol::P2p(source))
                if remote_parts.next().is_none()
                    && expected_peer.map_or(source != self.local_peer_id, |peer| source == peer)
        );
        target_matches && source_matches && self.matches_configured_relay(&route.endpoint)
    }

    fn matches_relay_endpoint(&self, expected_peer: libp2p::PeerId, address: &Multiaddr) -> bool {
        let Some(endpoint) = self.relay_endpoints.get(&expected_peer) else {
            return false;
        };
        let mut socket_address = address.clone();
        match socket_address.iter().last() {
            Some(Protocol::P2p(peer)) if peer == expected_peer => {
                socket_address.pop();
            }
            Some(Protocol::P2p(_)) => return false,
            _ => {}
        }
        parse_relay_listen_multiaddr(&socket_address.to_string()).is_ok_and(
            |(transport, socket)| endpoint.transport == transport && endpoint.socket == socket,
        )
    }

    fn matches_configured_relay(&self, candidate: &RelayEndpoint) -> bool {
        self.relay_endpoints
            .get(&candidate.peer_id)
            .is_some_and(|endpoint| {
                endpoint.transport == candidate.transport
                    && endpoint.socket == candidate.socket
                    && (self.policy == AddressPolicy::RelayOnly
                        || allows_ip(self.policy, endpoint.socket.ip()))
            })
    }

    fn at_capacity(&self) -> bool {
        self.established.len() + self.pending_outgoing.len() + self.pending_incoming.len()
            >= MAX_CONNECTIONS
    }

    fn admit(&self, peer: libp2p::PeerId) -> Result<dummy::ConnectionHandler, ConnectionDenied> {
        if self.at_capacity() || self.established.contains(&peer) {
            return Err(ConnectionDenied::new("connection limit reached"));
        }
        Ok(dummy::ConnectionHandler)
    }
}

impl NetworkBehaviour for Admission {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = Infallible;

    fn handle_pending_inbound_connection(
        &mut self,
        id: ConnectionId,
        local: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        if self.pending_incoming.len() >= MAX_PENDING_INBOUND || self.at_capacity() {
            return Err(ConnectionDenied::new("inbound limit reached"));
        }
        if !self.allows_inbound_connection(None, local, remote) {
            return Err(ConnectionDenied::new("inbound address denied by policy"));
        }
        self.pending_incoming.insert(id);
        Ok(())
    }

    fn handle_pending_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: Option<libp2p::PeerId>,
        addresses: &[Multiaddr],
        _: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        if self.pending_outgoing.len() >= MAX_PENDING_OUTBOUND || self.at_capacity() {
            return Err(ConnectionDenied::new("outbound limit reached"));
        }
        let Some(peer) = peer else {
            return Err(ConnectionDenied::new(
                "dial requires one policy-approved IP endpoint and peer",
            ));
        };
        if addresses.is_empty()
            || addresses.len() > self.max_outbound_addresses
            || !addresses
                .iter()
                .all(|address| self.allows_outbound_address(peer, address))
        {
            return Err(ConnectionDenied::new(
                "dial requires one policy-approved IP endpoint and peer",
            ));
        }
        self.pending_outgoing.insert(id);
        Ok(Vec::new())
    }

    fn handle_established_inbound_connection(
        &mut self,
        id: ConnectionId,
        peer: libp2p::PeerId,
        local: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<Self::ConnectionHandler, ConnectionDenied> {
        self.pending_incoming.remove(&id);
        if !self.allows_inbound_connection(Some(peer), local, remote) {
            return Err(ConnectionDenied::new("inbound address denied by policy"));
        }
        self.admit(peer)
    }

    fn handle_established_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: libp2p::PeerId,
        addr: &Multiaddr,
        _: Endpoint,
        _: PortUse,
    ) -> Result<Self::ConnectionHandler, ConnectionDenied> {
        self.pending_outgoing.remove(&id);
        if !self.allows_outbound_address(peer, addr) {
            return Err(ConnectionDenied::new("outbound address denied by policy"));
        }
        self.admit(peer)
    }

    fn on_swarm_event(&mut self, event: FromSwarm<'_>) {
        match event {
            FromSwarm::ListenFailure(failure) => {
                self.pending_incoming.remove(&failure.connection_id);
            }
            FromSwarm::DialFailure(failure) => {
                self.pending_outgoing.remove(&failure.connection_id);
            }
            FromSwarm::ConnectionEstablished(established) => {
                self.established.insert(established.peer_id);
            }
            FromSwarm::ConnectionClosed(closed) => {
                self.established.remove(&closed.peer_id);
            }
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        _: libp2p::PeerId,
        _: ConnectionId,
        event: Infallible,
    ) {
        match event {}
    }

    fn poll(&mut self, _: &mut Context<'_>) -> Poll<ToSwarm<Infallible, Infallible>> {
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::{
        core::ConnectedPoint,
        swarm::behaviour::{ConnectionEstablished, DialFailure},
    };
    use std::net::SocketAddrV4;

    fn peer() -> libp2p::PeerId {
        Keypair::generate_ed25519().public().to_peer_id()
    }

    fn endpoint() -> Multiaddr {
        socket_endpoint(
            TransportKind::Tcp,
            SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 1).into(),
        )
        .unwrap()
    }

    #[test]
    fn selecting_the_default_policy_locks_out_later_scope_changes() {
        let mut transport = LocalTransport::new(Keypair::generate_ed25519()).unwrap();
        transport
            .set_address_policy(AddressPolicy::LoopbackOnly)
            .unwrap();

        assert_eq!(
            transport
                .set_address_policy(AddressPolicy::Hybrid)
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[tokio::test]
    async fn group_transport_can_enable_public_addresses() {
        let mut transport =
            LocalTransport::new_with_loopback_groups(Keypair::generate_ed25519()).unwrap();
        transport.set_address_policy(AddressPolicy::Hybrid).unwrap();
    }

    #[test]
    fn relay_retry_delay_grows_exponentially_and_is_bounded() {
        let config = TraversalConfig::default();
        let delay = |attempts| {
            relay_retry_delay(
                attempts,
                config.relay_retry_base(),
                config.relay_retry_max(),
            )
        };
        assert_eq!(delay(1), Duration::from_secs(1));
        assert_eq!(delay(2), Duration::from_secs(2));
        assert_eq!(delay(7), Duration::from_secs(60));
        assert_eq!(delay(u32::MAX), config.relay_retry_max());
    }

    #[test]
    fn relay_routes_skip_endpoints_in_backoff() {
        let target_peer = peer();
        let failed_peer = peer();
        let available_peer = peer();
        let failed_endpoint =
            parse_relay_endpoint(&endpoint().with(Protocol::P2p(failed_peer))).unwrap();
        let available_endpoint =
            parse_relay_endpoint(&endpoint().with(Protocol::P2p(available_peer))).unwrap();
        let mut transport = LocalTransport::new(Keypair::generate_ed25519()).unwrap();
        transport
            .relay_endpoints
            .insert(failed_peer, failed_endpoint);
        transport
            .relay_endpoints
            .insert(available_peer, available_endpoint.clone());
        transport.reserved_relays.insert(available_peer);
        transport.relay_retries.insert(
            failed_peer,
            RelayRetry {
                attempts: 1,
                retry_at: Some(tokio::time::Instant::now() + Duration::from_secs(1)),
            },
        );

        assert_eq!(
            transport.relay_route_addresses(&target_peer).unwrap(),
            vec![relay_route_address(&available_endpoint.address, &target_peer).unwrap()]
        );
    }

    #[test]
    fn relay_only_policy_rejects_direct_endpoints() {
        let local_peer = peer();
        let direct = endpoint().with(Protocol::P2p(peer()));
        let mut admission = Admission::new(
            local_peer,
            AddressPolicy::RelayOnly,
            usize::from(TraversalConfig::default().autonat_max_peer_addresses),
        );
        assert!(
            admission
                .handle_pending_outbound_connection(
                    ConnectionId::new_unchecked(1),
                    Some(peer()),
                    std::slice::from_ref(&direct),
                    Endpoint::Dialer,
                )
                .is_err()
        );
        assert!(!valid_inbound_endpoint(
            AddressPolicy::RelayOnly,
            &endpoint(),
            false
        ));

        let relay_peer = peer();
        let relay_address = endpoint().with(Protocol::P2p(relay_peer));
        let relay_endpoint = parse_relay_endpoint(&relay_address).unwrap();
        admission.allow_relay_endpoint(relay_endpoint).unwrap();
        assert!(admission.allows_outbound_address(relay_peer, &endpoint()));

        let target_peer = peer();
        let route = relay_route_address(&relay_address, &target_peer).unwrap();
        assert!(admission.allows_outbound_address(target_peer, &route));

        let local_route = relay_address.with(Protocol::P2pCircuit);
        let remote_address = Multiaddr::empty().with(Protocol::P2p(target_peer));
        let pending = ConnectionId::new_unchecked(10);
        assert!(
            admission
                .handle_pending_inbound_connection(pending, &local_route, &remote_address,)
                .is_ok()
        );
        assert!(
            admission
                .handle_established_inbound_connection(
                    pending,
                    target_peer,
                    &local_route,
                    &remote_address,
                )
                .is_ok()
        );

        let pending = ConnectionId::new_unchecked(11);
        assert!(
            admission
                .handle_pending_inbound_connection(pending, &local_route, &remote_address,)
                .is_ok()
        );
        assert!(
            admission
                .handle_established_inbound_connection(
                    pending,
                    peer(),
                    &local_route,
                    &remote_address,
                )
                .is_err()
        );
    }

    #[tokio::test]
    async fn public_provider_advertising_is_the_only_allowed_scope() {
        let mut transport = LocalTransport::new(Keypair::generate_ed25519()).unwrap();
        let key = crate::dht::content_key(asl_types::ids::Hash32([8; 32]));

        for audience in [
            DhtAudience::Contacts,
            DhtAudience::Peers,
            DhtAudience::Group,
        ] {
            assert_eq!(
                transport
                    .start_providing(key.clone(), audience)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
        }
        assert!(transport.start_providing(key, DhtAudience::Public).is_ok());
    }

    #[test]
    fn inbound_endpoints_obey_local_and_remote_address_scopes() {
        let lan_listener =
            socket_endpoint(TransportKind::Tcp, "192.168.1.2:4001".parse().unwrap()).unwrap();
        let wildcard_listener =
            socket_endpoint(TransportKind::Tcp, "0.0.0.0:4001".parse().unwrap()).unwrap();
        let lan_peer =
            socket_endpoint(TransportKind::Tcp, "10.0.0.4:4002".parse().unwrap()).unwrap();
        let public_peer =
            socket_endpoint(TransportKind::Tcp, "8.8.8.8:4002".parse().unwrap()).unwrap();

        assert!(valid_inbound_endpoint(
            AddressPolicy::LanOnly,
            &lan_listener,
            true
        ));
        assert!(valid_inbound_endpoint(
            AddressPolicy::LanOnly,
            &wildcard_listener,
            true
        ));
        assert!(valid_inbound_endpoint(
            AddressPolicy::LanOnly,
            &lan_peer,
            false
        ));
        assert!(!valid_inbound_endpoint(
            AddressPolicy::LanOnly,
            &public_peer,
            false
        ));
        assert!(valid_inbound_endpoint(
            AddressPolicy::InternetOnly,
            &public_peer,
            false
        ));
        assert!(!valid_inbound_endpoint(
            AddressPolicy::InternetOnly,
            &lan_peer,
            false
        ));
    }

    #[test]
    fn discovery_filters_scope_identity_and_self_before_dialing() {
        let local = peer();
        let remote = peer();
        let lan_addr: Multiaddr = "/ip4/192.168.1.10/tcp/4001".parse().unwrap();
        let public_addr: Multiaddr = "/ip4/8.8.8.8/tcp/4001".parse().unwrap();
        let wrong_peer: Multiaddr = format!("/ip4/192.168.1.10/tcp/4001/p2p/{local}")
            .parse()
            .unwrap();

        let accepted =
            policy_approved_discovery_address(AddressPolicy::LanOnly, &local, remote, lan_addr)
                .unwrap();
        assert_eq!(accepted.iter().last(), Some(Protocol::P2p(remote)));
        assert!(
            policy_approved_discovery_address(AddressPolicy::LanOnly, &local, remote, public_addr)
                .is_none()
        );
        assert!(
            policy_approved_discovery_address(AddressPolicy::LanOnly, &local, remote, wrong_peer)
                .is_none()
        );
        assert!(
            policy_approved_discovery_address(AddressPolicy::LanOnly, &local, local, accepted)
                .is_none()
        );
    }

    #[test]
    fn provider_endpoints_are_selected_only_with_matching_peer_and_policy_scope() {
        let remote = peer();
        let private: Multiaddr = format!("/ip4/192.168.1.10/tcp/4001/p2p/{remote}")
            .parse()
            .unwrap();
        let public: Multiaddr = format!("/ip4/8.8.8.8/udp/4002/quic-v1/p2p/{remote}")
            .parse()
            .unwrap();
        let wrong_peer: Multiaddr = format!("/ip4/192.168.1.10/tcp/4001/p2p/{}", peer())
            .parse()
            .unwrap();

        assert_eq!(
            select_provider_endpoint(
                AddressPolicy::LanOnly,
                &remote,
                [public.clone(), private.clone()]
            ),
            Some((TransportKind::Tcp, "192.168.1.10:4001".parse().unwrap()))
        );
        assert_eq!(
            select_provider_endpoint(AddressPolicy::InternetOnly, &remote, [public]),
            Some((TransportKind::Quic, "8.8.8.8:4002".parse().unwrap()))
        );
        assert_eq!(
            select_provider_endpoint(AddressPolicy::LanOnly, &remote, [wrong_peer]),
            None
        );
    }

    #[test]
    fn provider_restore_reinserts_only_policy_valid_addresses() {
        let provider = peer();
        let key = [19; 32];
        let mut transport = LocalTransport::new(Keypair::generate_ed25519()).unwrap();
        transport
            .set_address_policy(AddressPolicy::LoopbackOnly)
            .unwrap();
        let provider_id =
            asl_types::ids::PeerId::from_bytes(provider.to_bytes()).expect("canonical peer id");
        let expires_at_ms = unix_time_ms().unwrap() + 60_000;

        transport
            .restore_dht_provider(
                key,
                &provider_id,
                &[
                    "/ip4/127.0.0.1/tcp/4001".into(),
                    "/ip4/8.8.8.8/tcp/4001".into(),
                ],
                expires_at_ms,
            )
            .unwrap();

        let providers = transport
            .swarm
            .behaviour_mut()
            .dht
            .store_mut()
            .providers(&RecordKey::new(&key));
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].provider, provider);
        assert_eq!(
            providers[0].addresses,
            vec!["/ip4/127.0.0.1/tcp/4001".parse().unwrap()]
        );
    }

    #[test]
    fn accepted_inbound_provider_emits_a_persistence_observation() {
        let provider = peer();
        let key = [23; 32];
        let mut transport = LocalTransport::new(Keypair::generate_ed25519()).unwrap();
        transport
            .set_address_policy(AddressPolicy::LoopbackOnly)
            .unwrap();
        let event = kad::Event::InboundRequest {
            request: kad::InboundRequest::AddProvider {
                record: Some(ProviderRecord {
                    key: RecordKey::new(&key),
                    provider,
                    addresses: vec![
                        "/ip4/127.0.0.1/tcp/4001".parse().unwrap(),
                        "/ip4/8.8.8.8/tcp/4001".parse().unwrap(),
                    ],
                    expires: Some(Instant::now() + Duration::from_secs(30)),
                }),
            },
        };

        let Some(TransportEvent::DhtProviderObserved {
            key: observed_key,
            provider: observed_provider,
            addresses,
            expires_in,
        }) = transport.handle_dht(event).unwrap()
        else {
            panic!("expected a validated provider observation");
        };
        assert_eq!(observed_key, key);
        assert_eq!(observed_provider.as_bytes(), provider.to_bytes().as_slice());
        assert_eq!(addresses, vec!["/ip4/127.0.0.1/tcp/4001".to_string()]);
        assert!(expires_in <= Duration::from_secs(30));
    }

    #[tokio::test]
    async fn discovery_candidate_observation_tracks_expiration_without_authenticating_peer() {
        let local_key = Keypair::generate_ed25519();
        let remote_peer = peer();
        let address: Multiaddr = "/ip4/192.168.1.10/tcp/4001".parse().unwrap();
        let mut transport = LocalTransport::new(local_key).unwrap();
        transport
            .set_address_policy(AddressPolicy::LanOnly)
            .unwrap();

        transport
            .handle_discovery(mdns::Event::Discovered(vec![(
                remote_peer,
                address.clone(),
            )]))
            .unwrap();

        let TransportEvent::DiscoveryCandidate(candidate) = transport.next_event().await.unwrap()
        else {
            panic!("expected an mDNS candidate observation");
        };
        assert_eq!(
            candidate,
            DiscoveryCandidate {
                peer_id: device_peer(remote_peer).unwrap(),
                kind: TransportKind::Tcp,
                address: "192.168.1.10:4001".parse().unwrap(),
                state: DiscoveryCandidateState::Discovered,
            }
        );
        assert!(transport.live.is_empty());

        transport
            .handle_discovery(mdns::Event::Expired(vec![(remote_peer, address)]))
            .unwrap();

        let TransportEvent::DiscoveryCandidate(candidate) = transport.next_event().await.unwrap()
        else {
            panic!("expected an mDNS expiry observation");
        };
        assert_eq!(
            candidate,
            DiscoveryCandidate {
                peer_id: device_peer(remote_peer).unwrap(),
                kind: TransportKind::Tcp,
                address: "192.168.1.10:4001".parse().unwrap(),
                state: DiscoveryCandidateState::Expired,
            }
        );
    }

    #[test]
    fn connection_handles_include_their_transport_lifetime_identity() {
        let peer = device_peer(peer()).unwrap();
        let first_owner = Arc::new(());
        let second_owner = Arc::new(());
        let first = AuthenticatedPeer {
            peer: peer.clone(),
            connection_id: LocalConnectionId(ConnectionId::new_unchecked(1)),
            lifetime: Arc::downgrade(&first_owner),
        };
        let same_connection = AuthenticatedPeer {
            peer: peer.clone(),
            connection_id: LocalConnectionId(ConnectionId::new_unchecked(1)),
            lifetime: Arc::downgrade(&first_owner),
        };
        let other_swarm = AuthenticatedPeer {
            peer,
            connection_id: LocalConnectionId(ConnectionId::new_unchecked(1)),
            lifetime: Arc::downgrade(&second_owner),
        };

        assert_eq!(first, same_connection);
        assert_ne!(first, other_swarm);
        assert_ne!(
            RequestToken::new(&first, 1),
            RequestToken::new(&other_swarm, 1)
        );
        assert_ne!(
            ResponseToken::new(&first, 1),
            ResponseToken::new(&other_swarm, 1)
        );
    }

    fn record_established(
        admission: &mut Admission,
        connection_id: ConnectionId,
        peer_id: libp2p::PeerId,
        addr: &Multiaddr,
    ) {
        admission.on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
            peer_id,
            connection_id,
            endpoint: &ConnectedPoint::Listener {
                local_addr: addr.clone(),
                send_back_addr: addr.clone(),
            },
            failed_addresses: &[],
            other_established: 0,
        }));
    }

    #[test]
    fn inbound_connection_does_not_release_a_pending_dial_for_the_same_peer() {
        let mut admission = Admission::new(
            peer(),
            AddressPolicy::LoopbackOnly,
            usize::from(TraversalConfig::default().autonat_max_peer_addresses),
        );
        let peer = peer();
        let addr = endpoint();
        let inbound = ConnectionId::new_unchecked(1);
        let outbound = ConnectionId::new_unchecked(2);
        admission
            .handle_pending_outbound_connection(
                outbound,
                Some(peer),
                std::slice::from_ref(&addr),
                Endpoint::Dialer,
            )
            .unwrap();
        admission
            .handle_pending_inbound_connection(inbound, &addr, &addr)
            .unwrap();
        admission
            .handle_established_inbound_connection(inbound, peer, &addr, &addr)
            .unwrap();
        record_established(&mut admission, inbound, peer, &addr);

        assert!(admission.pending_outgoing.contains(&outbound));
        admission.on_swarm_event(FromSwarm::DialFailure(DialFailure {
            peer_id: Some(peer),
            connection_id: ConnectionId::new_unchecked(3),
            error: &DialError::DialPeerConditionFalse(PeerCondition::DisconnectedAndNotDialing),
        }));
        assert!(admission.pending_outgoing.contains(&outbound));
        assert!(
            admission
                .handle_established_outbound_connection(
                    outbound,
                    peer,
                    &addr,
                    Endpoint::Dialer,
                    PortUse::Reuse,
                )
                .is_err()
        );
        assert!(admission.pending_outgoing.is_empty());
        assert!(admission.established.contains(&peer));
    }

    #[test]
    fn inbound_outbound_and_established_share_one_connection_budget() {
        let mut admission = Admission::new(
            peer(),
            AddressPolicy::LoopbackOnly,
            usize::from(TraversalConfig::default().autonat_max_peer_addresses),
        );
        let addr = endpoint();
        let mut incoming = 1..;
        let mut outgoing = MAX_CONNECTIONS + 1..;
        let reserve_inbound = |state: &mut Admission, n| {
            state.handle_pending_inbound_connection(ConnectionId::new_unchecked(n), &addr, &addr)
        };
        let reserve_outbound = |state: &mut Admission, n| {
            state.handle_pending_outbound_connection(
                ConnectionId::new_unchecked(n),
                Some(peer()),
                std::slice::from_ref(&addr),
                Endpoint::Dialer,
            )
        };

        for _ in 0..MAX_PENDING_INBOUND {
            reserve_inbound(&mut admission, incoming.next().unwrap()).unwrap();
        }
        assert!(reserve_inbound(&mut admission, incoming.next().unwrap()).is_err());
        for _ in 0..MAX_PENDING_OUTBOUND {
            reserve_outbound(&mut admission, outgoing.next().unwrap()).unwrap();
        }
        assert!(reserve_outbound(&mut admission, outgoing.next().unwrap()).is_err());

        let inbound = ConnectionId::new_unchecked(1);
        let connected_peer = peer();
        admission
            .handle_established_inbound_connection(inbound, connected_peer, &addr, &addr)
            .unwrap();
        record_established(&mut admission, inbound, connected_peer, &addr);
        assert!(reserve_inbound(&mut admission, incoming.next().unwrap()).is_err());

        admission.on_swarm_event(FromSwarm::DialFailure(DialFailure {
            peer_id: None,
            connection_id: ConnectionId::new_unchecked(MAX_CONNECTIONS + 1),
            error: &DialError::NoAddresses,
        }));
        reserve_inbound(&mut admission, incoming.next().unwrap()).unwrap();
        assert!(reserve_outbound(&mut admission, outgoing.next().unwrap()).is_err());
    }
}
