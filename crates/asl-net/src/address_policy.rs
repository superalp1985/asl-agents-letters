use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use libp2p::{Multiaddr, PeerId, multiaddr::Protocol};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressPolicy {
    LoopbackOnly,
    LanOnly,
    InternetOnly,
    Hybrid,
    RelayOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressClass {
    Loopback,
    Private,
    LinkLocal,
    Public,
    Reserved,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressError {
    UnsupportedAddress,
    UnsupportedTransport,
    PeerMismatch,
    ScopeDenied,
}

pub fn classify_ip(address: IpAddr) -> AddressClass {
    if address.is_loopback() {
        return AddressClass::Loopback;
    }
    if address.is_unspecified() || address.is_multicast() {
        return AddressClass::Reserved;
    }
    if is_link_local(address) {
        return AddressClass::LinkLocal;
    }
    if is_private(address) {
        return AddressClass::Private;
    }
    if is_global(address) {
        return AddressClass::Public;
    }
    AddressClass::Reserved
}

pub fn allows_ip(policy: AddressPolicy, address: IpAddr) -> bool {
    policy.allows(classify_ip(address))
}

pub fn allows_listen_ip(policy: AddressPolicy, address: IpAddr) -> bool {
    if address.is_unspecified() {
        return matches!(
            policy,
            AddressPolicy::LanOnly | AddressPolicy::InternetOnly | AddressPolicy::Hybrid
        );
    }
    allows_ip(policy, address)
}

pub fn validate_multiaddr(
    policy: AddressPolicy,
    expected_peer: &PeerId,
    address: &Multiaddr,
) -> Result<SocketAddr, AddressError> {
    let (ip, port, peer) = parse_transport_address(address)?;
    if peer.is_some_and(|peer| peer != *expected_peer) {
        return Err(AddressError::PeerMismatch);
    }
    validate_scope(policy, ip, port)
}

pub fn validate_transport_address(
    policy: AddressPolicy,
    address: &Multiaddr,
) -> Result<SocketAddr, AddressError> {
    let (ip, port, _) = parse_transport_address(address)?;
    validate_scope(policy, ip, port)
}

fn parse_transport_address(
    address: &Multiaddr,
) -> Result<(IpAddr, u16, Option<PeerId>), AddressError> {
    let mut parts = address.iter();
    let ip = match parts.next() {
        Some(Protocol::Ip4(address)) => IpAddr::V4(address),
        Some(Protocol::Ip6(address)) => IpAddr::V6(address),
        _ => return Err(AddressError::UnsupportedAddress),
    };

    let port = match parts.next() {
        Some(Protocol::Tcp(port)) => port,
        Some(Protocol::Udp(port)) if parts.next() == Some(Protocol::QuicV1) => port,
        _ => return Err(AddressError::UnsupportedTransport),
    };
    if port == 0 {
        return Err(AddressError::UnsupportedAddress);
    }

    let peer = match parts.next() {
        Some(Protocol::P2p(peer)) if parts.next().is_none() => Some(peer),
        None => None,
        _ => return Err(AddressError::UnsupportedAddress),
    };

    Ok((ip, port, peer))
}

fn validate_scope(
    policy: AddressPolicy,
    ip: IpAddr,
    port: u16,
) -> Result<SocketAddr, AddressError> {
    if !allows_ip(policy, ip) {
        return Err(AddressError::ScopeDenied);
    }

    Ok(SocketAddr::new(ip, port))
}

impl AddressPolicy {
    fn allows(self, class: AddressClass) -> bool {
        match self {
            Self::LoopbackOnly => class == AddressClass::Loopback,
            Self::LanOnly => matches!(class, AddressClass::Private | AddressClass::LinkLocal),
            Self::InternetOnly => class == AddressClass::Public,
            Self::Hybrid => matches!(
                class,
                AddressClass::Private | AddressClass::LinkLocal | AddressClass::Public
            ),
            Self::RelayOnly => false,
        }
    }

    pub(crate) fn includes_lan(self) -> bool {
        matches!(self, Self::LanOnly | Self::Hybrid)
    }
}

fn is_private(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_private(),
        IpAddr::V6(address) => address.is_unique_local(),
    }
}

fn is_link_local(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_link_local(),
        IpAddr::V6(address) => address.is_unicast_link_local(),
    }
}

fn is_global(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_global_v4(address),
        IpAddr::V6(address) => is_global_v6(address),
    }
}

fn is_global_v4(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    let value = u32::from(address);
    let in_range = |network: Ipv4Addr, prefix: u32| {
        let mask = u32::MAX << (32 - prefix);
        value & mask == u32::from(network) & mask
    };

    if address == Ipv4Addr::new(192, 0, 0, 9) || address == Ipv4Addr::new(192, 0, 0, 10) {
        return true;
    }

    !address.is_private()
        && !address.is_loopback()
        && !address.is_link_local()
        && !address.is_broadcast()
        && octets[0] != 0
        && !(octets[0] == 100 && octets[1] & 0b1100_0000 == 0b0100_0000)
        && !in_range(Ipv4Addr::new(192, 0, 0, 0), 24)
        && !in_range(Ipv4Addr::new(192, 0, 2, 0), 24)
        && !in_range(Ipv4Addr::new(192, 88, 99, 0), 24)
        && !in_range(Ipv4Addr::new(198, 18, 0, 0), 15)
        && !in_range(Ipv4Addr::new(198, 51, 100, 0), 24)
        && !in_range(Ipv4Addr::new(203, 0, 113, 0), 24)
        && !(octets[0] & 0xf0 == 0xf0)
}

fn is_global_v6(address: Ipv6Addr) -> bool {
    let value = u128::from(address);
    let in_range = |network: u128, prefix: u32| {
        let mask = u128::MAX << (128 - prefix);
        value & mask == network & mask
    };

    let segments = address.segments();
    let in_protocol_assignments = segments[0] == 0x2001 && segments[1] < 0x0200;
    let globally_reachable_assignment = value == 0x2001_0001_0000_0000_0000_0000_0000_0001
        || value == 0x2001_0001_0000_0000_0000_0000_0000_0002
        || in_range(0x2001_0003_0000_0000_0000_0000_0000_0000, 32)
        || in_range(0x2001_0004_0112_0000_0000_0000_0000_0000, 48)
        || in_range(0x2001_0020_0000_0000_0000_0000_0000_0000, 28);

    !(in_range(0, 96)
        || in_range(0x0000_0000_0000_0000_0000_ffff_0000_0000, 96)
        || in_range(0x0064_ff9b_0001_0000_0000_0000_0000_0000, 48)
        || in_range(0x0100_0000_0000_0000_0000_0000_0000_0000, 64)
        || (in_protocol_assignments && !globally_reachable_assignment)
        || in_range(0x2001_0db8_0000_0000_0000_0000_0000_0000, 32)
        || in_range(0xfc00_0000_0000_0000_0000_0000_0000_0000, 7)
        || in_range(0xfe80_0000_0000_0000_0000_0000_0000_0000, 10)
        || in_range(0xff00_0000_0000_0000_0000_0000_0000_0000, 8))
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;

    #[test]
    fn classifies_loopback_lan_link_local_public_and_reserved_ranges() {
        let cases = [
            (IpAddr::V4(Ipv4Addr::LOCALHOST), AddressClass::Loopback),
            (
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                AddressClass::Private,
            ),
            (
                IpAddr::V4(Ipv4Addr::new(169, 254, 1, 10)),
                AddressClass::LinkLocal,
            ),
            (IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), AddressClass::Public),
            (
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                AddressClass::Reserved,
            ),
            (
                IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
                AddressClass::Reserved,
            ),
            (
                IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)),
                AddressClass::Reserved,
            ),
            (
                IpAddr::V4(Ipv4Addr::new(192, 0, 0, 9)),
                AddressClass::Public,
            ),
            (IpAddr::V6(Ipv6Addr::LOCALHOST), AddressClass::Loopback),
            (
                IpAddr::V6("fc00::1".parse().unwrap()),
                AddressClass::Private,
            ),
            (
                IpAddr::V6("fe80::1".parse().unwrap()),
                AddressClass::LinkLocal,
            ),
            (
                IpAddr::V6("2001:4860:4860::8888".parse().unwrap()),
                AddressClass::Public,
            ),
            (
                IpAddr::V6("2001:db8::1".parse().unwrap()),
                AddressClass::Reserved,
            ),
            (
                IpAddr::V6("::ffff:192.0.2.1".parse().unwrap()),
                AddressClass::Reserved,
            ),
        ];

        for (address, expected) in cases {
            assert_eq!(classify_ip(address), expected, "{address}");
        }
    }

    #[test]
    fn validates_supported_multiaddrs_against_scope_and_authenticated_peer() {
        let expected = Keypair::generate_ed25519().public().to_peer_id();
        let other = Keypair::generate_ed25519().public().to_peer_id();
        let address: Multiaddr = format!("/ip4/192.168.1.10/tcp/4001/p2p/{expected}")
            .parse()
            .unwrap();

        assert_eq!(
            validate_multiaddr(AddressPolicy::LanOnly, &expected, &address).unwrap(),
            SocketAddr::from(([192, 168, 1, 10], 4001))
        );
        assert_eq!(
            validate_multiaddr(AddressPolicy::InternetOnly, &expected, &address),
            Err(AddressError::ScopeDenied)
        );

        let wrong_peer: Multiaddr = format!("/ip4/192.168.1.10/tcp/4001/p2p/{other}")
            .parse()
            .unwrap();
        assert_eq!(
            validate_multiaddr(AddressPolicy::LanOnly, &expected, &wrong_peer),
            Err(AddressError::PeerMismatch)
        );
    }

    #[test]
    fn rejects_non_ip_dns_unsupported_protocol_and_zero_port_addresses() {
        let expected = Keypair::generate_ed25519().public().to_peer_id();
        for value in [
            "/dns4/node.example/tcp/4001",
            "/ip4/192.168.1.10/tcp/4001/ws",
            "/ip4/192.168.1.10/udp/4001",
            "/ip4/192.168.1.10/tcp/0",
        ] {
            let address: Multiaddr = value.parse().unwrap();
            assert!(validate_multiaddr(AddressPolicy::Hybrid, &expected, &address).is_err());
        }
    }

    #[test]
    fn address_profiles_separate_loopback_lan_and_public_routes() {
        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let private = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let public = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(allows_ip(AddressPolicy::LoopbackOnly, loopback));
        assert!(!allows_ip(AddressPolicy::LanOnly, loopback));
        assert!(allows_ip(AddressPolicy::LanOnly, private));
        assert!(!allows_ip(AddressPolicy::InternetOnly, private));
        assert!(allows_ip(AddressPolicy::InternetOnly, public));
        assert!(allows_ip(AddressPolicy::Hybrid, private));
        assert!(allows_ip(AddressPolicy::Hybrid, public));
        assert!(!allows_listen_ip(
            AddressPolicy::LoopbackOnly,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        ));
        assert!(allows_listen_ip(
            AddressPolicy::LanOnly,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        ));
    }
}
