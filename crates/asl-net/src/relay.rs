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

    pub async fn run(mut self) -> io::Result<()> {
        loop {
            match self.swarm.select_next_some().await {
                SwarmEvent::ListenerError { .. } | SwarmEvent::ListenerClosed { .. } => {
                    return Err(io::Error::other("relay listener stopped"));
                }
                SwarmEvent::Behaviour(_) => {}
                _ => {}
            }
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
