use std::{io, net::SocketAddr, time::Duration};

use asl_net::{
    address_policy::AddressPolicy,
    relay::RelayServer,
    transport::{LocalTransport, TransportEvent, TransportKind},
};
use libp2p::{Multiaddr, identity::Keypair, multiaddr::Protocol};

async fn next_reserved(transport: &mut LocalTransport, expected: libp2p::PeerId) -> Multiaddr {
    loop {
        match transport.next_event().await.unwrap() {
            TransportEvent::RelayReserved {
                relay_peer_id,
                address,
            } if relay_peer_id == expected => return address,
            TransportEvent::InboundRejected
            | TransportEvent::Listening(_, _)
            | TransportEvent::RelayReserved { .. } => {}
            TransportEvent::RelayUnavailable { relay_peer_id } => {
                panic!("relay became unavailable: {relay_peer_id}");
            }
            event => panic!("unexpected relay reservation event: {event:?}"),
        }
    }
}

async fn next_connected(
    transport: &mut LocalTransport,
    expected: libp2p::PeerId,
) -> io::Result<()> {
    loop {
        match transport.next_event().await? {
            TransportEvent::Connected { connection }
                if connection.peer_id().as_bytes() == expected.to_bytes().as_slice() =>
            {
                return Ok(());
            }
            TransportEvent::InboundRejected
            | TransportEvent::Listening(_, _)
            | TransportEvent::RelayReserved { .. } => {}
            TransportEvent::RelayUnavailable { relay_peer_id } => {
                panic!("relay became unavailable: {relay_peer_id}");
            }
            TransportEvent::Connected { .. }
            | TransportEvent::Disconnected { .. }
            | TransportEvent::ControlRequest { .. }
            | TransportEvent::ControlResponse { .. }
            | TransportEvent::IdentityProofRequest { .. }
            | TransportEvent::IdentityProofResponse { .. }
            | TransportEvent::BulkRequest { .. }
            | TransportEvent::BulkResponse { .. }
            | TransportEvent::RequestFailed { .. } => {}
        }
    }
}

#[tokio::test]
async fn two_clients_establish_an_authenticated_connection_through_relay_v2() {
    let relay_key = Keypair::generate_ed25519();
    let relay_peer_id = relay_key.public().to_peer_id();
    let mut relay = RelayServer::new(relay_key, Default::default()).unwrap();
    relay
        .listen(
            TransportKind::Tcp,
            SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), 0),
        )
        .unwrap();
    let address = tokio::time::timeout(Duration::from_secs(5), relay.next_event())
        .await
        .unwrap()
        .unwrap();
    let relay_address = match address.iter().last() {
        Some(Protocol::P2p(peer_id)) if peer_id == relay_peer_id => address,
        Some(Protocol::P2p(_)) => panic!("relay listener announced a different peer id"),
        _ => address.with(Protocol::P2p(relay_peer_id)),
    };
    let relay_task = tokio::spawn(relay.run());

    let requester_key = Keypair::generate_ed25519();
    let requester_peer_id = requester_key.public().to_peer_id();
    let responder_key = Keypair::generate_ed25519();
    let responder_peer_id = responder_key.public().to_peer_id();
    let mut requester = LocalTransport::new(requester_key).unwrap();
    let mut responder = LocalTransport::new(responder_key).unwrap();
    requester
        .set_address_policy(AddressPolicy::RelayOnly)
        .unwrap();
    responder
        .set_address_policy(AddressPolicy::RelayOnly)
        .unwrap();
    requester.reserve_relay(&relay_address).unwrap();
    responder.reserve_relay(&relay_address).unwrap();

    let (requester_reservation, responder_reservation) =
        tokio::time::timeout(Duration::from_secs(15), async {
            tokio::join!(
                next_reserved(&mut requester, relay_peer_id),
                next_reserved(&mut responder, relay_peer_id)
            )
        })
        .await
        .unwrap();
    assert!(requester_reservation.to_string().contains("/p2p-circuit"));
    assert!(responder_reservation.to_string().contains("/p2p-circuit"));

    requester
        .dial_via_relays(&asl_types::ids::PeerId::from_bytes(responder_peer_id.to_bytes()).unwrap())
        .unwrap();

    tokio::time::timeout(Duration::from_secs(15), async {
        tokio::join!(
            next_connected(&mut requester, responder_peer_id),
            next_connected(&mut responder, requester_peer_id)
        )
    })
    .await
    .unwrap()
    .0
    .unwrap();

    relay_task.abort();
}
