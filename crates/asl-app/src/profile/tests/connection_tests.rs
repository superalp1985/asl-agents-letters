use super::*;
use crate::profile::DeviceSession;
use asl_net::transport::{LocalTransport, TransportEvent, TransportKind};
use asl_types::protocol::{Feature, Hello};
use libp2p_identity::Keypair;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;
use tokio::time::timeout;

fn hello(cert: &DeviceCertificate) -> Hello {
    Hello {
        message_id: Id128([1; 16]),
        agent_id: cert.agent_id,
        peer_id: cert.peer_id.clone(),
        device_certificate: cert.clone(),
        major: 1,
        minor: 0,
        features: vec![Feature::Query],
    }
}

async fn listen(device_key: Keypair) -> (LocalTransport, std::net::SocketAddr) {
    let mut listener = LocalTransport::new(device_key).unwrap();
    listener
        .listen(
            TransportKind::Tcp,
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into(),
        )
        .unwrap();
    let endpoint = match timeout(Duration::from_secs(5), listener.next_event())
        .await
        .unwrap()
        .unwrap()
    {
        TransportEvent::Listening(TransportKind::Tcp, endpoint) => endpoint,
        event => panic!("unexpected listener event: {event:?}"),
    };
    (listener, endpoint)
}

async fn connect(
    dialer: &mut LocalTransport,
    listener: &mut LocalTransport,
    endpoint: std::net::SocketAddr,
    peer: &PeerId,
) -> DeviceSession {
    dialer.dial(TransportKind::Tcp, endpoint, peer).unwrap();
    let (dialer_event, listener_event) = timeout(Duration::from_secs(5), async {
        tokio::join!(dialer.next_event(), listener.next_event())
    })
    .await
    .unwrap();
    let TransportEvent::Connected { connection } = dialer_event.unwrap() else {
        panic!("dialer did not produce an authenticated connection");
    };
    assert_eq!(connection.peer_id(), peer);
    assert!(matches!(
        listener_event.unwrap(),
        TransportEvent::Connected { .. }
    ));

    DeviceSession::from_transport(connection)
}

#[tokio::test]
async fn authenticated_connection_admits_its_bound_device_certificate() {
    let root = AgentIdentity::generate().unwrap();
    let device_key = Keypair::generate_ed25519();
    let peer = PeerId::from_bytes(device_key.public().to_peer_id().to_bytes()).unwrap();
    let cert = certificate(&root, &peer, 1);
    let d = directory(&root, 7, vec![cert.clone()], vec![]);
    let signed = signed_directory(&root, &d, 1);
    let mut resolver = directory_resolver(&root, &d);
    let mut history = RecordHistory::new(root.agent_id(), 32).unwrap();
    let (mut listener, endpoint) = listen(device_key.clone()).await;
    let mut dialer = LocalTransport::new(Keypair::generate_ed25519()).unwrap();

    let mut session = connect(&mut dialer, &mut listener, endpoint, &peer).await;
    let old_connection = session.connection_id().unwrap();
    session
        .accept_hello(&hello(&cert), &signed, &mut history, &mut resolver, NOW)
        .unwrap();
    assert_eq!(
        session.current_agent(&history, &mut resolver, NOW).unwrap(),
        root.agent_id()
    );

    drop(listener);
    assert!(matches!(
        timeout(Duration::from_secs(5), dialer.next_event())
            .await
            .unwrap()
            .unwrap(),
        TransportEvent::Disconnected { .. }
    ));
    assert!(session.current_agent(&history, &mut resolver, NOW).is_err());

    let (mut listener, endpoint) = listen(device_key).await;
    let mut next = connect(&mut dialer, &mut listener, endpoint, &peer).await;
    assert_ne!(next.connection_id(), Some(old_connection));
    assert!(next.current_agent(&history, &mut resolver, NOW).is_err());
    drop(dialer);
    assert!(
        next.accept_hello(&hello(&cert), &signed, &mut history, &mut resolver, NOW)
            .is_err()
    );
}

#[test]
fn connected_is_not_verified_and_a_second_hello_closes_the_session() {
    let root = AgentIdentity::generate().unwrap();
    let p = peers(1).pop().unwrap();
    let c = certificate(&root, &p, 1);
    let d = directory(&root, 7, vec![c.clone()], vec![]);
    let mut r = directory_resolver(&root, &d);
    let mut history = RecordHistory::new(root.agent_id(), 32).unwrap();
    let signed = signed_directory(&root, &d, 1);
    let mut session = DeviceSession::from_test_peer(p);
    assert!(session.current_agent(&history, &mut r, NOW).is_err());
    session
        .accept_hello(&hello(&c), &signed, &mut history, &mut r, NOW)
        .unwrap();
    assert_eq!(
        session.current_agent(&history, &mut r, NOW).unwrap(),
        root.agent_id()
    );
    assert!(
        session
            .accept_hello(&hello(&c), &signed, &mut history, &mut r, NOW)
            .is_err()
    );
    assert!(session.current_agent(&history, &mut r, NOW).is_err());
}

#[test]
fn a_valid_signed_certificate_must_be_for_this_connection_and_in_its_directory() {
    let root = AgentIdentity::generate().unwrap();
    let devices = peers(2);
    let old = certificate(&root, &devices[0], 1);
    let new = certificate(&root, &devices[0], 2);
    let d = directory(&root, 7, vec![new.clone()], vec![1]);
    let signed = signed_directory(&root, &d, 1);
    let mut history = RecordHistory::new(root.agent_id(), 32).unwrap();
    let mut r = directory_resolver(&root, &d);
    for (peer, claim) in [
        (&devices[1], hello(&new)),
        (&devices[0], hello(&old)),
        (
            &devices[0],
            Hello {
                agent_id: AgentId([9; 32]),
                ..hello(&new)
            },
        ),
    ] {
        let mut session = DeviceSession::from_test_peer(peer.clone());
        assert!(
            session
                .accept_hello(&claim, &signed, &mut history, &mut r, NOW)
                .is_err()
        );
        assert!(session.current_agent(&history, &mut r, NOW).is_err());
    }
}

#[test]
fn chain_rotation_expiry_or_history_advance_require_a_new_handshake() {
    let root = AgentIdentity::generate().unwrap();
    let p = peers(1).pop().unwrap();
    let c = certificate(&root, &p, 1);
    let d = directory(&root, 7, vec![c.clone()], vec![]);
    for case in 0..6 {
        let mut r = directory_resolver(&root, &d);
        let mut history = RecordHistory::new(root.agent_id(), 32).unwrap();
        let mut session = DeviceSession::from_test_peer(p.clone());
        session
            .accept_hello(
                &hello(&c),
                &signed_directory(&root, &d, 1),
                &mut history,
                &mut r,
                NOW,
            )
            .unwrap();
        let mut now = NOW;
        match case {
            0 => r.resolution = IdentityResolution::Limited(LimitedReason::Revoked),
            1 => r = directory_resolver(&root, &directory(&root, 8, vec![c.clone()], vec![])),
            2 => now += LIFETIME,
            3 => {
                history
                    .accept(&signed_directory(&root, &d, 2), NOW, &mut r)
                    .unwrap();
            }
            4 => now -= 1,
            _ => session.close(),
        }
        assert!(session.current_agent(&history, &mut r, now).is_err());
        let mut fresh = directory_resolver(&root, &d);
        assert!(session.current_agent(&history, &mut fresh, NOW).is_err());
    }
}
