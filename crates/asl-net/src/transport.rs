//! Authenticated transports with policy-filtered IP endpoints.

use std::{
    collections::{BTreeSet, HashMap, HashSet, VecDeque},
    convert::Infallible,
    hash::{Hash, Hasher},
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Weak},
    task::{Context, Poll},
    time::Duration,
};

use crate::address_policy::{
    AddressPolicy, allows_ip, allows_listen_ip, validate_multiaddr, validate_transport_address,
};
use crate::relay::{
    RelayEndpoint, parse_relay_endpoint, parse_relay_listen_multiaddr, parse_relay_route,
    relay_route_address,
};
mod behaviour;
mod requests;
use behaviour::{AslBehaviour, BehaviourEvent, DiscoveryEvent};
use requests::Requests;

use asl_types::ids::PeerId;
use asl_types::protocol::{IdentityProof, IdentityProofRequest, WireFrame};
use libp2p::{
    Multiaddr, Swarm, SwarmBuilder,
    core::{
        Endpoint,
        transport::{ListenerId, PortUse},
    },
    futures::StreamExt,
    identity::Keypair,
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

use crate::codec::{
    BULK_PROTOCOL, BulkCodec, BulkRequest, BulkResponse, CONTROL_PROTOCOL, ControlCodec,
    IDENTITY_PROOF_PROTOCOL, IdentityProofCodec,
};

const MAX_LISTENERS: usize = 16;
const MAX_PENDING_INBOUND: usize = 8;
const MAX_PENDING_OUTBOUND: usize = 8;
const MAX_CONNECTIONS: usize = 16;
const MAX_PENDING_DISCOVERY_DIALS: usize = 8;
const MAX_RELAY_ENDPOINTS: usize = 8;
const MAX_PENDING_RESPONSES: usize = MAX_CONNECTIONS * 3 * 2;
const MAX_PENDING_REQUESTS: usize = MAX_PENDING_RESPONSES;
const MAX_PROTOCOL_STREAMS_PER_PEER: usize = 2;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const RELAY_RETRY_BASE: Duration = Duration::from_secs(1);
const RELAY_RETRY_MAX: Duration = Duration::from_secs(60);
const RELAY_RETRY_MAX_SHIFT: u32 = 6;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportKind {
    Tcp,
    Quic,
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
    RelayReserved {
        relay_peer_id: libp2p::PeerId,
        address: Multiaddr,
    },
    RelayUnavailable {
        relay_peer_id: libp2p::PeerId,
    },
    InboundRejected,
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
    RequestFailed {
        connection_id: LocalConnectionId,
        request: RequestToken,
    },
    Disconnected {
        connection_id: LocalConnectionId,
        peer: PeerId,
    },
}

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
    relay_endpoints: HashMap<libp2p::PeerId, RelayEndpoint>,
    relay_listeners: HashMap<ListenerId, libp2p::PeerId>,
    relay_retries: HashMap<libp2p::PeerId, RelayRetry>,
    reserved_relays: HashSet<libp2p::PeerId>,
}

struct RelayRetry {
    attempts: u32,
    retry_at: Option<tokio::time::Instant>,
}

impl LocalTransport {
    pub fn new(identity: Keypair) -> io::Result<Self> {
        let local_peer_id = identity.public().to_peer_id();
        let swarm = SwarmBuilder::with_existing_identity(identity)
            .with_tokio()
            .with_tcp(tcp::Config::default(), noise::Config::new, || {
                yamux::Config::default()
            })
            .map_err(|_| io::Error::other("cannot configure authenticated TCP"))?
            .with_quic_config(|mut config| {
                config.handshake_timeout = HANDSHAKE_TIMEOUT;
                config.max_concurrent_stream_limit = 1;
                config.max_stream_data = 16 * 1024;
                config.max_connection_data = 16 * 1024;
                config
            })
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .map_err(|_| io::Error::other("cannot configure relay client"))?
            .with_behaviour(|_, relay| AslBehaviour::new(local_peer_id, relay))
            .expect("infallible behaviour constructor")
            .with_swarm_config(|config| {
                config
                    .with_max_negotiating_inbound_streams(1)
                    .with_idle_connection_timeout(IDLE_TIMEOUT)
            })
            .with_connection_timeout(HANDSHAKE_TIMEOUT)
            .build();
        Ok(Self {
            live: HashMap::new(),
            swarm,
            listeners: HashSet::new(),
            requests: Requests::new(),
            address_policy: AddressPolicy::LoopbackOnly,
            policy_configured: false,
            network_started: false,
            pending_discovery_dials: HashSet::new(),
            relay_endpoints: HashMap::new(),
            relay_listeners: HashMap::new(),
            relay_retries: HashMap::new(),
            reserved_relays: HashSet::new(),
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
        self.swarm
            .dial(
                DialOpts::peer_id(peer)
                    .condition(PeerCondition::DisconnectedAndNotDialing)
                    .addresses(vec![endpoint])
                    .build(),
            )
            .map_err(dial_error)?;
        self.network_started = true;
        Ok(())
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
            && self.relay_endpoints.len() >= MAX_RELAY_ENDPOINTS
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
            .and_modify(|retry| retry.retry_at = None);
        self.network_started = true;
        Ok(endpoint.peer_id)
    }

    pub fn is_relay_reserved(&self, relay_peer_id: &libp2p::PeerId) -> bool {
        self.reserved_relays.contains(relay_peer_id)
    }

    pub fn dial_via_relays(&mut self, expected: &PeerId) -> io::Result<()> {
        let peer = libp2p::PeerId::from_bytes(expected.as_bytes())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        if peer == *self.swarm.local_peer_id() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let addresses = self.relay_route_addresses(&peer)?;
        if addresses.is_empty() {
            return Err(io::ErrorKind::NotConnected.into());
        }
        require_runtime()?;
        self.swarm
            .dial(
                DialOpts::peer_id(peer)
                    .condition(PeerCondition::DisconnectedAndNotDialing)
                    .addresses(addresses)
                    .build(),
            )
            .map_err(dial_error)?;
        self.network_started = true;
        Ok(())
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
        loop {
            self.start_due_relay_retries();
            let event = if let Some(deadline) = self.next_relay_retry_deadline() {
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
                    ..
                } => {
                    if self.relay_endpoints.contains_key(&peer_id) {
                        continue;
                    }
                    self.pending_discovery_dials.remove(&peer_id);
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
                SwarmEvent::Behaviour(BehaviourEvent::Bulk(event)) => {
                    if let Some(event) = self.handle_bulk(event)? {
                        return Ok(event);
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Discovery(DiscoveryEvent::Mdns(event))) => {
                    self.handle_discovery(event);
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
                SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
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
                    return Err(dial_error(error));
                }
                _ => {}
            }
        }
    }

    fn relay_route_addresses(&self, target: &libp2p::PeerId) -> io::Result<Vec<Multiaddr>> {
        self.relay_endpoints
            .iter()
            .filter(|(relay_peer_id, _)| !self.relay_retries.contains_key(relay_peer_id))
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
        retry.retry_at = Some(tokio::time::Instant::now() + relay_retry_delay(retry.attempts));
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

    fn handle_discovery(&mut self, event: mdns::Event) {
        let mdns::Event::Discovered(peers) = event else {
            return;
        };

        for (peer_id, address) in peers {
            if self.swarm.is_connected(&peer_id)
                || self.pending_discovery_dials.contains(&peer_id)
                || self.pending_discovery_dials.len() >= MAX_PENDING_DISCOVERY_DIALS
            {
                continue;
            }

            let Some(address) = policy_approved_discovery_address(
                self.address_policy,
                self.swarm.local_peer_id(),
                peer_id,
                address,
            ) else {
                continue;
            };
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

fn relay_retry_delay(attempts: u32) -> Duration {
    let shift = attempts.saturating_sub(1).min(RELAY_RETRY_MAX_SHIFT);
    RELAY_RETRY_BASE
        .saturating_mul(1u32 << shift)
        .min(RELAY_RETRY_MAX)
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
    relay_endpoints: HashMap<libp2p::PeerId, RelayEndpoint>,
}

impl Admission {
    fn new(local_peer_id: libp2p::PeerId, policy: AddressPolicy) -> Self {
        Self {
            local_peer_id,
            established: HashSet::new(),
            pending_outgoing: HashSet::new(),
            pending_incoming: HashSet::new(),
            policy,
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
            || addresses.len() > MAX_RELAY_ENDPOINTS
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

    #[test]
    fn relay_retry_delay_grows_exponentially_and_is_bounded() {
        assert_eq!(relay_retry_delay(1), Duration::from_secs(1));
        assert_eq!(relay_retry_delay(2), Duration::from_secs(2));
        assert_eq!(relay_retry_delay(7), Duration::from_secs(60));
        assert_eq!(relay_retry_delay(u32::MAX), RELAY_RETRY_MAX);
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
        let mut admission = Admission::new(local_peer, AddressPolicy::RelayOnly);
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
        let mut admission = Admission::new(peer(), AddressPolicy::LoopbackOnly);
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
        let mut admission = Admission::new(peer(), AddressPolicy::LoopbackOnly);
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
