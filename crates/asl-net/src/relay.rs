use std::{io, net::SocketAddr, str::FromStr, time::Duration};

use libp2p::{
    Multiaddr, SwarmBuilder,
    futures::StreamExt,
    identity::{Keypair, PeerId},
    noise, relay,
    swarm::{NetworkBehaviour, Swarm, SwarmEvent},
    tcp, yamux,
};

use crate::transport::{TransportKind, socket_endpoint};

const MAX_RELAY_LISTENERS: usize = 16;
pub const MAX_RELAY_ENDPOINT_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayServerLimits {
    pub max_reservations: usize,
    pub max_reservations_per_peer: usize,
    pub reservation_duration: Duration,
    pub max_circuits: usize,
    pub max_circuits_per_peer: usize,
    pub max_circuit_duration: Duration,
    pub max_circuit_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayEndpoint {
    pub peer_id: PeerId,
    pub address: Multiaddr,
    pub transport: TransportKind,
    pub socket: SocketAddr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayRoute {
    pub endpoint: RelayEndpoint,
    pub target_peer_id: Option<PeerId>,
}

impl Default for RelayServerLimits {
    fn default() -> Self {
        Self {
            max_reservations: 128,
            max_reservations_per_peer: 4,
            reservation_duration: Duration::from_secs(60 * 60),
            max_circuits: 64,
            max_circuits_per_peer: 4,
            max_circuit_duration: Duration::from_secs(5 * 60),
            max_circuit_bytes: 128 * 1024 * 1024,
        }
    }
}

impl RelayServerLimits {
    pub fn validate(self) -> io::Result<Self> {
        if self.max_reservations == 0
            || self.max_reservations_per_peer == 0
            || self.max_reservations_per_peer > self.max_reservations
            || self.reservation_duration.is_zero()
            || self.reservation_duration.as_secs() > u32::MAX as u64
            || self.max_circuits == 0
            || self.max_circuits_per_peer == 0
            || self.max_circuits_per_peer > self.max_circuits
            || self.max_circuit_duration.is_zero()
            || self.max_circuit_duration.as_secs() > u32::MAX as u64
            || self.max_circuit_bytes == 0
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(self)
    }

    fn into_libp2p_config(self) -> io::Result<relay::Config> {
        let limits = self.validate()?;
        Ok(relay::Config {
            max_reservations: limits.max_reservations,
            max_reservations_per_peer: limits.max_reservations_per_peer,
            reservation_duration: limits.reservation_duration,
            max_circuits: limits.max_circuits,
            max_circuits_per_peer: limits.max_circuits_per_peer,
            max_circuit_duration: limits.max_circuit_duration,
            max_circuit_bytes: limits.max_circuit_bytes,
            ..relay::Config::default()
        })
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "relay::Event")]
struct RelayServerBehaviour {
    relay: relay::Behaviour,
}

pub struct RelayServer {
    swarm: Swarm<RelayServerBehaviour>,
    listeners: usize,
}

impl RelayServer {
    pub fn new(identity: Keypair, limits: RelayServerLimits) -> io::Result<Self> {
        let relay_config = limits.into_libp2p_config()?;
        let peer_id = identity.public().to_peer_id();
        let swarm = SwarmBuilder::with_existing_identity(identity)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(io::Error::other)?
            .with_quic()
            .with_behaviour(|_| RelayServerBehaviour {
                relay: relay::Behaviour::new(peer_id, relay_config),
            })
            .map_err(io::Error::other)?
            .build();
        Ok(Self {
            swarm,
            listeners: 0,
        })
    }

    pub fn peer_id(&self) -> PeerId {
        self.swarm.local_peer_id().to_owned()
    }

    pub fn listen(&mut self, kind: TransportKind, address: SocketAddr) -> io::Result<()> {
        if self.listeners >= MAX_RELAY_LISTENERS {
            return Err(io::Error::other("relay listener limit reached"));
        }
        let endpoint = socket_endpoint(kind, address)?;
        self.swarm
            .listen_on(endpoint)
            .map_err(|_| io::Error::other("cannot bind relay listener"))?;
        self.listeners += 1;
        Ok(())
    }

    pub fn add_external_address(
        &mut self,
        kind: TransportKind,
        address: SocketAddr,
    ) -> io::Result<()> {
        if address.port() == 0
            || address.ip().is_unspecified()
            || address.ip().is_multicast()
            || matches!(address.ip(), std::net::IpAddr::V4(ip) if ip.is_broadcast())
            || matches!(address.ip(), std::net::IpAddr::V6(ip) if ip.is_unicast_link_local())
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.swarm
            .add_external_address(socket_endpoint(kind, address)?);
        Ok(())
    }

    pub async fn next_event(&mut self) -> io::Result<Multiaddr> {
        loop {
            match self.swarm.select_next_some().await {
                SwarmEvent::NewListenAddr { mut address, .. } => {
                    if matches!(
                        address.iter().last(),
                        Some(libp2p::multiaddr::Protocol::P2p(peer_id))
                            if peer_id == self.peer_id()
                    ) {
                        address.pop();
                    }
                    if let Ok((kind, socket)) = parse_relay_listen_multiaddr(&address.to_string())
                        && !socket.ip().is_unspecified()
                    {
                        self.add_external_address(kind, socket)?;
                    }
                    return Ok(address);
                }
                SwarmEvent::ListenerError { .. } | SwarmEvent::ListenerClosed { .. } => {
                    return Err(io::Error::other("relay listener stopped"));
                }
                SwarmEvent::Behaviour(_) => {}
                _ => {}
            }
        }
    }

    pub async fn run(mut self) -> io::Result<()> {
        loop {
            self.next_event().await?;
        }
    }
}

pub fn relay_multiaddr(
    relay_peer_id: &PeerId,
    target_peer_id: &PeerId,
    address: SocketAddr,
    kind: TransportKind,
) -> io::Result<Multiaddr> {
    let mut multiaddr = socket_endpoint(kind, address)?;
    multiaddr.push(libp2p::multiaddr::Protocol::P2p(relay_peer_id.to_owned()));
    multiaddr.push(libp2p::multiaddr::Protocol::P2pCircuit);
    multiaddr.push(libp2p::multiaddr::Protocol::P2p(target_peer_id.to_owned()));
    Ok(multiaddr)
}

pub fn parse_relay_endpoint(address: &Multiaddr) -> io::Result<RelayEndpoint> {
    let mut parts = address.iter();
    let ip: std::net::IpAddr = match parts.next() {
        Some(libp2p::multiaddr::Protocol::Ip4(ip)) => ip.into(),
        Some(libp2p::multiaddr::Protocol::Ip6(ip)) => ip.into(),
        _ => return Err(io::ErrorKind::InvalidInput.into()),
    };
    let (transport, port) = match parts.next() {
        Some(libp2p::multiaddr::Protocol::Tcp(port)) => (TransportKind::Tcp, port),
        Some(libp2p::multiaddr::Protocol::Udp(port))
            if parts.next() == Some(libp2p::multiaddr::Protocol::QuicV1) =>
        {
            (TransportKind::Quic, port)
        }
        _ => return Err(io::ErrorKind::InvalidInput.into()),
    };
    let peer_id = match parts.next() {
        Some(libp2p::multiaddr::Protocol::P2p(peer_id)) if parts.next().is_none() => peer_id,
        _ => return Err(io::ErrorKind::InvalidInput.into()),
    };
    if port == 0
        || ip.is_unspecified()
        || ip.is_multicast()
        || matches!(ip, std::net::IpAddr::V4(address) if address.is_broadcast())
        || matches!(ip, std::net::IpAddr::V6(address) if address.is_unicast_link_local())
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }

    Ok(RelayEndpoint {
        peer_id,
        address: socket_endpoint(transport, SocketAddr::new(ip, port))?
            .with(libp2p::multiaddr::Protocol::P2p(peer_id)),
        transport,
        socket: SocketAddr::new(ip, port),
    })
}

pub fn parse_relay_route(address: &Multiaddr) -> io::Result<RelayRoute> {
    let mut parts = address.iter();
    let ip: std::net::IpAddr = match parts.next() {
        Some(libp2p::multiaddr::Protocol::Ip4(ip)) => ip.into(),
        Some(libp2p::multiaddr::Protocol::Ip6(ip)) => ip.into(),
        _ => return Err(io::ErrorKind::InvalidInput.into()),
    };
    let (transport, port) = match parts.next() {
        Some(libp2p::multiaddr::Protocol::Tcp(port)) => (TransportKind::Tcp, port),
        Some(libp2p::multiaddr::Protocol::Udp(port))
            if parts.next() == Some(libp2p::multiaddr::Protocol::QuicV1) =>
        {
            (TransportKind::Quic, port)
        }
        _ => return Err(io::ErrorKind::InvalidInput.into()),
    };
    let peer_id = match parts.next() {
        Some(libp2p::multiaddr::Protocol::P2p(peer_id)) => peer_id,
        _ => return Err(io::ErrorKind::InvalidInput.into()),
    };
    if parts.next() != Some(libp2p::multiaddr::Protocol::P2pCircuit) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let target_peer_id = match parts.next() {
        Some(libp2p::multiaddr::Protocol::P2p(peer_id)) if parts.next().is_none() => Some(peer_id),
        None => None,
        _ => return Err(io::ErrorKind::InvalidInput.into()),
    };
    if port == 0
        || ip.is_multicast()
        || matches!(ip, std::net::IpAddr::V4(address) if address.is_broadcast())
        || matches!(ip, std::net::IpAddr::V6(address) if address.is_unicast_link_local())
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }

    Ok(RelayRoute {
        endpoint: RelayEndpoint {
            peer_id,
            address: socket_endpoint(transport, SocketAddr::new(ip, port))?
                .with(libp2p::multiaddr::Protocol::P2p(peer_id)),
            transport,
            socket: SocketAddr::new(ip, port),
        },
        target_peer_id,
    })
}

pub fn relay_route_address(endpoint: &Multiaddr, target_peer_id: &PeerId) -> io::Result<Multiaddr> {
    let endpoint = parse_relay_endpoint(endpoint)?;
    Ok(endpoint
        .address
        .with(libp2p::multiaddr::Protocol::P2pCircuit)
        .with(libp2p::multiaddr::Protocol::P2p(*target_peer_id)))
}

pub fn relay_endpoint_config(value: &str) -> io::Result<Vec<u8>> {
    if value.len() > MAX_RELAY_ENDPOINT_BYTES {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let address = Multiaddr::from_str(value).map_err(|_| io::ErrorKind::InvalidInput)?;
    parse_relay_endpoint(&address)?;
    Ok(address.to_vec())
}

pub fn parse_relay_endpoint_bytes(bytes: Vec<u8>) -> io::Result<Multiaddr> {
    if bytes.is_empty() || bytes.len() > MAX_RELAY_ENDPOINT_BYTES {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let address = Multiaddr::try_from(bytes).map_err(|_| io::ErrorKind::InvalidInput)?;
    parse_relay_endpoint(&address)?;
    Ok(address)
}

pub fn parse_relay_listen_multiaddr(value: &str) -> io::Result<(TransportKind, SocketAddr)> {
    let address = Multiaddr::from_str(value).map_err(|_| io::ErrorKind::InvalidInput)?;
    let mut parts = address.iter();
    let ip: std::net::IpAddr = match parts.next() {
        Some(libp2p::multiaddr::Protocol::Ip4(ip)) => ip.into(),
        Some(libp2p::multiaddr::Protocol::Ip6(ip)) => ip.into(),
        _ => return Err(io::ErrorKind::InvalidInput.into()),
    };
    let (kind, port) = match parts.next() {
        Some(libp2p::multiaddr::Protocol::Tcp(port)) if parts.next().is_none() => {
            (TransportKind::Tcp, port)
        }
        Some(libp2p::multiaddr::Protocol::Udp(port))
            if parts.next() == Some(libp2p::multiaddr::Protocol::QuicV1)
                && parts.next().is_none() =>
        {
            (TransportKind::Quic, port)
        }
        _ => return Err(io::ErrorKind::InvalidInput.into()),
    };
    if port == 0
        || ip.is_multicast()
        || matches!(ip, std::net::IpAddr::V4(address) if address.is_broadcast())
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    if matches!(ip, std::net::IpAddr::V6(address) if address.is_unicast_link_local()) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok((kind, SocketAddr::new(ip, port)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_limits_reject_unbounded_or_inconsistent_values() {
        let mut limits = RelayServerLimits::default();
        assert!(limits.validate().is_ok());

        limits.max_circuits = 0;
        assert!(limits.validate().is_err());

        limits = RelayServerLimits::default();
        limits.max_circuits_per_peer = limits.max_circuits + 1;
        assert!(limits.validate().is_err());

        limits = RelayServerLimits::default();
        limits.max_circuit_duration = Duration::from_secs(u32::MAX as u64 + 1);
        assert!(limits.validate().is_err());

        limits = RelayServerLimits::default();
        limits.reservation_duration = Duration::from_secs(u32::MAX as u64 + 1);
        assert!(limits.validate().is_err());

        limits = RelayServerLimits::default();
        limits.max_circuit_bytes = 0;
        assert!(limits.validate().is_err());
    }

    #[test]
    fn relay_server_identity_is_the_routing_peer_id() {
        let key = Keypair::generate_ed25519();
        let expected = key.public().to_peer_id();
        let server = RelayServer::new(key, RelayServerLimits::default()).unwrap();
        assert_eq!(server.peer_id(), expected);
    }

    #[tokio::test]
    async fn relay_server_binds_a_tcp_listener() {
        let key = Keypair::generate_ed25519();
        let mut server = RelayServer::new(key, RelayServerLimits::default()).unwrap();
        server
            .listen(
                TransportKind::Tcp,
                SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), 0),
            )
            .unwrap();

        let event = tokio::time::timeout(Duration::from_secs(5), server.swarm.select_next_some())
            .await
            .unwrap();
        let SwarmEvent::NewListenAddr { address, .. } = event else {
            panic!("expected relay listener address, got {event:?}");
        };
        assert!(address.iter().any(|protocol| {
            matches!(protocol, libp2p::multiaddr::Protocol::Tcp(port) if port != 0)
        }));
    }

    #[test]
    fn relay_multiaddr_places_circuit_after_transport_and_peer() {
        let relay_peer_id = Keypair::generate_ed25519().public().to_peer_id();
        let target_peer_id = Keypair::generate_ed25519().public().to_peer_id();
        let address = relay_multiaddr(
            &relay_peer_id,
            &target_peer_id,
            SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 4_001)),
            TransportKind::Tcp,
        )
        .unwrap();
        assert_eq!(
            address.to_string(),
            format!("/ip4/127.0.0.1/tcp/4001/p2p/{relay_peer_id}/p2p-circuit/p2p/{target_peer_id}")
        );
    }

    #[test]
    fn relay_endpoint_and_route_parsers_require_exact_peer_bound_ip_paths() {
        let relay_peer_id = Keypair::generate_ed25519().public().to_peer_id();
        let target_peer_id = Keypair::generate_ed25519().public().to_peer_id();
        let endpoint: Multiaddr = format!("/ip4/127.0.0.1/tcp/4001/p2p/{relay_peer_id}")
            .parse()
            .unwrap();
        let parsed = parse_relay_endpoint(&endpoint).unwrap();
        assert_eq!(parsed.peer_id, relay_peer_id);
        assert_eq!(parsed.transport, TransportKind::Tcp);
        assert_eq!(parsed.socket, SocketAddr::from(([127, 0, 0, 1], 4_001)));

        let route = relay_route_address(&endpoint, &target_peer_id).unwrap();
        let parsed_route = parse_relay_route(&route).unwrap();
        assert_eq!(parsed_route.endpoint, parsed);
        assert_eq!(parsed_route.target_peer_id, Some(target_peer_id));

        for invalid in [
            format!("/dns4/relay.example/tcp/4001/p2p/{relay_peer_id}"),
            format!("/ip4/127.0.0.1/tcp/4001/p2p/{relay_peer_id}/ws"),
            format!("/ip4/127.0.0.1/udp/4001/quic-v1/p2p/{relay_peer_id}/p2p-circuit"),
            format!("/ip6/fe80::1/tcp/4001/p2p/{relay_peer_id}"),
        ] {
            let address: Multiaddr = invalid.parse().unwrap();
            assert!(parse_relay_endpoint(&address).is_err(), "{address}");
        }
    }

    #[test]
    fn relay_listener_parser_accepts_only_tcp_or_quic_ip_endpoints() {
        assert_eq!(
            parse_relay_listen_multiaddr("/ip4/0.0.0.0/tcp/4001").unwrap(),
            (
                TransportKind::Tcp,
                SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 4_001)
            )
        );
        assert_eq!(
            parse_relay_listen_multiaddr("/ip6/::/udp/4001/quic-v1").unwrap(),
            (
                TransportKind::Quic,
                SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), 4_001)
            )
        );
        for invalid in [
            "/dns4/relay.example/tcp/4001",
            "/ip4/0.0.0.0/tcp/4001/ws",
            "/ip4/0.0.0.0/tcp/0",
            "/ip6/fe80::1/tcp/4001",
            "/ip4/224.0.0.1/tcp/4001",
            "/ip4/255.255.255.255/tcp/4001",
        ] {
            assert!(parse_relay_listen_multiaddr(invalid).is_err(), "{invalid}");
        }
    }
}
