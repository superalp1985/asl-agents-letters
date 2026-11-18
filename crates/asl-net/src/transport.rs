//! Explicit loopback endpoints only, pending the T16 address policy.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    convert::Infallible,
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Weak},
    task::{Context, Poll},
    time::Duration,
};

mod behaviour;
mod requests;
use behaviour::{AslBehaviour, BehaviourEvent};
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

const MAX_LISTENERS: usize = 4;
const MAX_PENDING_INBOUND: usize = 8;
const MAX_PENDING_OUTBOUND: usize = 8;
const MAX_CONNECTIONS: usize = 16;
const MAX_PENDING_RESPONSES: usize = MAX_CONNECTIONS * 3 * 2;
const MAX_PENDING_REQUESTS: usize = MAX_PENDING_RESPONSES;
const MAX_PROTOCOL_STREAMS_PER_PEER: usize = 2;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

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
        self.connection_id == other.connection_id && self.peer == other.peer
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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RequestToken(u64);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ResponseToken(LocalConnectionId, u64);

#[derive(Debug)]
pub enum TransportEvent {
    Listening(TransportKind, SocketAddr),
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
}

impl LocalTransport {
    pub fn new(identity: Keypair) -> io::Result<Self> {
        let behaviour = AslBehaviour::new();
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
            .with_behaviour(|_| behaviour)
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
        })
    }

    /// Port zero requests an ephemeral port; `Listening` reports the bound endpoint.
    pub fn listen(&mut self, kind: TransportKind, addr: SocketAddr) -> io::Result<()> {
        let endpoint = loopback_endpoint(kind, addr)?;
        if self.listeners.len() >= MAX_LISTENERS {
            return Err(io::Error::other("listener limit reached"));
        }
        require_runtime()?;
        let id = self
            .swarm
            .listen_on(endpoint)
            .map_err(|_| io::Error::other("cannot bind loopback endpoint"))?;
        self.listeners.insert(id);
        Ok(())
    }

    /// Start one handshake to exactly this address and expected device.
    pub fn dial(
        &mut self,
        kind: TransportKind,
        addr: SocketAddr,
        expected: &PeerId,
    ) -> io::Result<()> {
        let endpoint = loopback_endpoint(kind, addr)?;
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
            .map_err(dial_error)
    }

    /// Failed inbound handshakes are reported without stopping the listener.
    pub async fn next_event(&mut self) -> io::Result<TransportEvent> {
        require_runtime()?;
        if let Some(event) = self.requests.pop_event() {
            return Ok(event);
        }
        loop {
            match self.swarm.select_next_some().await {
                SwarmEvent::NewListenAddr { address, .. } => {
                    let (kind, addr) =
                        bound_endpoint(&address).ok_or(io::ErrorKind::InvalidData)?;
                    return Ok(TransportEvent::Listening(kind, addr));
                }
                SwarmEvent::ConnectionEstablished {
                    peer_id,
                    connection_id,
                    ..
                } => {
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
                    ..
                } => {
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
                SwarmEvent::Behaviour(BehaviourEvent::Admission(never)) => match never {},
                SwarmEvent::ListenerClosed { listener_id, .. } => {
                    self.listeners.remove(&listener_id);
                    return Err(io::Error::other("loopback listener closed"));
                }
                SwarmEvent::ListenerError { .. } => {
                    return Err(io::Error::other("loopback listener error"));
                }
                SwarmEvent::IncomingConnectionError { .. } => {
                    return Ok(TransportEvent::InboundRejected);
                }
                SwarmEvent::OutgoingConnectionError { error, .. } => {
                    return Err(dial_error(error));
                }
                _ => {}
            }
        }
    }
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

fn loopback_endpoint(kind: TransportKind, addr: SocketAddr) -> io::Result<Multiaddr> {
    if !addr.ip().is_loopback() {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    // IP multiaddrs cannot represent either of these IPv6 socket fields.
    if matches!(addr, SocketAddr::V6(v6) if v6.scope_id() != 0 || v6.flowinfo() != 0) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
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
    (ip.is_loopback() && port != 0 && parts.next().is_none())
        .then_some((kind, SocketAddr::new(ip, port)))
}

// Keep only live identities. Each pending handshake owns its own reservation,
// even if an inbound and an outbound handshake involve the same peer.
#[derive(Default)]
struct Admission {
    established: HashSet<libp2p::PeerId>,
    pending_outgoing: HashSet<ConnectionId>,
    pending_incoming: HashSet<ConnectionId>,
}

impl Admission {
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
        if bound_endpoint(local).is_none() || bound_endpoint(remote).is_none() {
            return Err(ConnectionDenied::new("not a loopback connection"));
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
        if peer.is_none() || !matches!(addresses, [addr] if bound_endpoint(addr).is_some()) {
            return Err(ConnectionDenied::new(
                "dial requires one loopback endpoint and peer",
            ));
        }
        self.pending_outgoing.insert(id);
        Ok(Vec::new())
    }

    fn handle_established_inbound_connection(
        &mut self,
        id: ConnectionId,
        peer: libp2p::PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<Self::ConnectionHandler, ConnectionDenied> {
        self.pending_incoming.remove(&id);
        self.admit(peer)
    }

    fn handle_established_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: libp2p::PeerId,
        _: &Multiaddr,
        _: Endpoint,
        _: PortUse,
    ) -> Result<Self::ConnectionHandler, ConnectionDenied> {
        self.pending_outgoing.remove(&id);
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
        loopback_endpoint(
            TransportKind::Tcp,
            SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 1).into(),
        )
        .unwrap()
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
        let mut admission = Admission::default();
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
        let mut admission = Admission::default();
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
