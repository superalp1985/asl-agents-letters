use std::{
    collections::HashSet,
    io,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use asl_net::{
    address_policy::AddressPolicy,
    codec::{BulkOperation, BulkRequest, BulkResponse, BulkStatus},
    relay::RelayServer,
    transport::{AuthenticatedPeer, LocalTransport, TransportEvent, TransportKind},
};
use asl_types::ids::{Hash32, Id128};
use libp2p::{Multiaddr, identity::Keypair, multiaddr::Protocol};

async fn start_relay(
    key: &Keypair,
    bind_address: SocketAddr,
) -> (tokio::task::JoinHandle<io::Result<()>>, Multiaddr) {
    let relay_peer_id = key.public().to_peer_id();
    let mut relay = RelayServer::new(key.clone(), Default::default()).unwrap();
    relay.listen(TransportKind::Tcp, bind_address).unwrap();
    let address = tokio::time::timeout(Duration::from_secs(5), relay.next_event())
        .await
        .unwrap()
        .unwrap();
    let address = match address.iter().last() {
        Some(Protocol::P2p(peer_id)) if peer_id == relay_peer_id => address,
        Some(Protocol::P2p(_)) => panic!("relay listener announced a different peer id"),
        _ => address.with(Protocol::P2p(relay_peer_id)),
    };
    (tokio::spawn(relay.run()), address)
}

fn socket_address(address: &Multiaddr) -> SocketAddr {
    let mut parts = address.iter();
    let ip = match parts.next().unwrap() {
        Protocol::Ip4(ip) => IpAddr::V4(ip),
        Protocol::Ip6(ip) => IpAddr::V6(ip),
        _ => panic!("relay address is not an IP endpoint"),
    };
    let port = match parts.next().unwrap() {
        Protocol::Tcp(port) => port,
        _ => panic!("relay address is not a TCP endpoint"),
    };
    SocketAddr::new(ip, port)
}

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

async fn next_reservation_after_recovery(
    transport: &mut LocalTransport,
    expected: libp2p::PeerId,
) -> Multiaddr {
    loop {
        match transport.next_event().await.unwrap() {
            TransportEvent::RelayReserved {
                relay_peer_id,
                address,
            } if relay_peer_id == expected => return address,
            TransportEvent::InboundRejected
            | TransportEvent::Listening(_, _)
            | TransportEvent::RelayReserved { .. }
            | TransportEvent::RelayUnavailable { .. }
            | TransportEvent::DiscoveryCandidate(_)
            | TransportEvent::DhtRecordCandidate { .. }
            | TransportEvent::DhtProviders { .. }
            | TransportEvent::ProfilePublicationProgress { .. }
            | TransportEvent::PairingInviteRequest { .. }
            | TransportEvent::PairingExchangeResponse { .. }
            | TransportEvent::DialFailed { .. } => {}
            event => panic!("unexpected relay event during recovery: {event:?}"),
        }
    }
}

async fn next_reservations(transport: &mut LocalTransport, expected: &[libp2p::PeerId]) {
    let expected = expected.iter().copied().collect::<HashSet<_>>();
    let mut reserved = HashSet::new();
    while reserved.len() < expected.len() {
        match transport.next_event().await.unwrap() {
            TransportEvent::RelayReserved { relay_peer_id, .. }
                if expected.contains(&relay_peer_id) =>
            {
                reserved.insert(relay_peer_id);
            }
            TransportEvent::RelayUnavailable { relay_peer_id } => {
                panic!("relay became unavailable before reservation: {relay_peer_id}");
            }
            TransportEvent::InboundRejected
            | TransportEvent::Listening(_, _)
            | TransportEvent::RelayReserved { .. } => {}
            event => panic!("unexpected relay event: {event:?}"),
        }
    }
}

async fn next_unavailable(transport: &mut LocalTransport, expected: libp2p::PeerId) {
    loop {
        if matches!(
            transport.next_event().await.unwrap(),
            TransportEvent::RelayUnavailable { relay_peer_id } if relay_peer_id == expected
        ) {
            return;
        }
    }
}

async fn next_from_either(
    first: &mut LocalTransport,
    second: &mut LocalTransport,
    predicate: impl Fn(&TransportEvent) -> bool,
) -> TransportEvent {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let event = tokio::select! {
                event = first.next_event() => event.unwrap(),
                event = second.next_event() => event.unwrap(),
            };
            if predicate(&event) {
                return event;
            }
        }
    })
    .await
    .unwrap()
}

async fn next_connected(
    transport: &mut LocalTransport,
    expected: libp2p::PeerId,
) -> io::Result<AuthenticatedPeer> {
    loop {
        match transport.next_event().await? {
            TransportEvent::Connected { connection }
                if connection.peer_id().as_bytes() == expected.to_bytes().as_slice() =>
            {
                return Ok(connection);
            }
            TransportEvent::InboundRejected
            | TransportEvent::Listening(_, _)
            | TransportEvent::RelayReserved { .. }
            | TransportEvent::RelayUnavailable { .. }
            | TransportEvent::DiscoveryCandidate(_)
            | TransportEvent::DhtRecordCandidate { .. }
            | TransportEvent::DhtProviders { .. }
            | TransportEvent::ProfilePublicationProgress { .. }
            | TransportEvent::PairingInviteRequest { .. }
            | TransportEvent::PairingExchangeResponse { .. }
            | TransportEvent::DialFailed { .. } => {}
            TransportEvent::Connected { .. }
            | TransportEvent::Disconnected { .. }
            | TransportEvent::ControlRequest { .. }
            | TransportEvent::ControlResponse { .. }
            | TransportEvent::IdentityProofRequest { .. }
            | TransportEvent::IdentityProofResponse { .. }
            | TransportEvent::BulkRequest { .. }
            | TransportEvent::BulkResponse { .. }
            | TransportEvent::GroupRequest { .. }
            | TransportEvent::GroupResponse { .. }
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

#[tokio::test]
async fn relay_carries_multiple_bulk_chunks_between_authenticated_peers() {
    let relay_key = Keypair::generate_ed25519();
    let relay_peer_id = relay_key.public().to_peer_id();
    let (relay_task, relay_address) = start_relay(&relay_key, "127.0.0.1:0".parse().unwrap()).await;
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

    tokio::time::timeout(Duration::from_secs(15), async {
        tokio::join!(
            next_reserved(&mut requester, relay_peer_id),
            next_reserved(&mut responder, relay_peer_id)
        )
    })
    .await
    .unwrap();
    requester
        .dial_via_relays(&asl_types::ids::PeerId::from_bytes(responder_peer_id.to_bytes()).unwrap())
        .unwrap();
    let (requester_connection, responder_connection) =
        tokio::time::timeout(Duration::from_secs(15), async {
            tokio::join!(
                next_connected(&mut requester, responder_peer_id),
                next_connected(&mut responder, requester_peer_id)
            )
        })
        .await
        .unwrap();
    let requester_connection = requester_connection.unwrap();
    let responder_connection = responder_connection.unwrap();

    for chunk_index in 0..4u32 {
        let request_id = Id128([chunk_index as u8 + 1; 16]);
        let request = BulkRequest {
            operation: BulkOperation::Chunk,
            request_id,
            content_id: Hash32([18; 32]),
            lease_id: Hash32([19; 32]),
            chunk_index,
        };
        let request_token = requester
            .send_bulk_request(&requester_connection, request.clone())
            .unwrap();
        let (received_request, response_token) =
            match next_from_either(&mut responder, &mut requester, |event| {
                matches!(event, TransportEvent::BulkRequest { .. })
            })
            .await
            {
                TransportEvent::BulkRequest {
                    request, response, ..
                } => (request, response),
                _ => unreachable!(),
            };
        assert_eq!(received_request, request);

        let payload = vec![chunk_index as u8; 128 * 1024];
        responder
            .send_bulk_response(
                &responder_connection,
                &response_token,
                BulkResponse {
                    request_id,
                    status: BulkStatus::Success,
                    payload: payload.clone(),
                },
            )
            .unwrap();
        match next_from_either(&mut requester, &mut responder, |event| {
            matches!(event, TransportEvent::BulkResponse { .. })
        })
        .await
        {
            TransportEvent::BulkResponse {
                request, response, ..
            } => {
                assert_eq!(request, request_token);
                assert_eq!(response.request_id, request_id);
                assert_eq!(response.status, BulkStatus::Success);
                assert_eq!(response.payload, payload);
            }
            _ => unreachable!(),
        }
    }

    relay_task.abort();
}

#[tokio::test]
async fn client_re_reserves_automatically_after_relay_restarts() {
    let relay_key = Keypair::generate_ed25519();
    let relay_peer_id = relay_key.public().to_peer_id();
    let (relay_task, relay_address) = start_relay(&relay_key, "127.0.0.1:0".parse().unwrap()).await;
    let bind_address = socket_address(&relay_address);

    let client_key = Keypair::generate_ed25519();
    let mut client = LocalTransport::new(client_key).unwrap();
    client.set_address_policy(AddressPolicy::RelayOnly).unwrap();
    client.reserve_relay(&relay_address).unwrap();
    tokio::time::timeout(
        Duration::from_secs(10),
        next_reserved(&mut client, relay_peer_id),
    )
    .await
    .unwrap();
    assert!(client.is_relay_reserved(&relay_peer_id));

    relay_task.abort();
    let _ = relay_task.await;
    tokio::time::timeout(
        Duration::from_secs(10),
        next_unavailable(&mut client, relay_peer_id),
    )
    .await
    .unwrap();
    assert!(!client.is_relay_reserved(&relay_peer_id));

    tokio::time::timeout(
        Duration::from_secs(8),
        next_unavailable(&mut client, relay_peer_id),
    )
    .await
    .unwrap();

    let (relay_task, restarted_address) = start_relay(&relay_key, bind_address).await;
    assert_eq!(restarted_address, relay_address);
    let reservation = tokio::time::timeout(
        Duration::from_secs(15),
        next_reservation_after_recovery(&mut client, relay_peer_id),
    )
    .await
    .unwrap();
    assert!(reservation.to_string().contains("/p2p-circuit"));
    assert!(client.is_relay_reserved(&relay_peer_id));
    relay_task.abort();
}

#[tokio::test]
async fn clients_use_the_remaining_relay_when_another_relay_is_offline() {
    let failed_key = Keypair::generate_ed25519();
    let failed_peer_id = failed_key.public().to_peer_id();
    let (failed_task, failed_address) =
        start_relay(&failed_key, "127.0.0.1:0".parse().unwrap()).await;
    let active_key = Keypair::generate_ed25519();
    let active_peer_id = active_key.public().to_peer_id();
    let (active_task, active_address) =
        start_relay(&active_key, "127.0.0.1:0".parse().unwrap()).await;

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
    for transport in [&mut requester, &mut responder] {
        transport.reserve_relay(&failed_address).unwrap();
        transport.reserve_relay(&active_address).unwrap();
    }

    let expected_relays = [failed_peer_id, active_peer_id];
    tokio::time::timeout(Duration::from_secs(15), async {
        tokio::join!(
            next_reservations(&mut requester, &expected_relays),
            next_reservations(&mut responder, &expected_relays)
        )
    })
    .await
    .unwrap();

    failed_task.abort();
    let _ = failed_task.await;
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            next_unavailable(&mut requester, failed_peer_id),
            next_unavailable(&mut responder, failed_peer_id)
        )
    })
    .await
    .unwrap();

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

    active_task.abort();
}
