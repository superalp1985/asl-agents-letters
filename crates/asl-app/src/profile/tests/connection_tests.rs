use super::*;
#[cfg(windows)]
use crate::chain::{
    DurableIdentityResolver, DurableResolverConfigV1, IdentityProofV1,
    test_support::{TestChainDatabase, bootstrapped, consensus_config},
};
#[cfg(windows)]
use crate::network::{NetworkCommand, NetworkEvent};
use crate::profile::DeviceSession;
#[cfg(windows)]
use crate::profile::{
    AdmittedNetworkEvent, CoreAdmission, DeviceAdmissionError, serve_local_identity_proof,
};
use asl_net::transport::{LocalTransport, TransportEvent, TransportKind};
use asl_types::protocol::{Feature, Hello, WireFrame};
use libp2p_identity::Keypair;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;
use tokio::time::timeout;

#[cfg(windows)]
mod group_rooms;

#[cfg(windows)]
fn durable_directory_resolver(
    root: &AgentIdentity,
    directory: &DeviceDirectory,
) -> (TestChainDatabase, DurableIdentityResolver, IdentityProofV1) {
    let commitment = device_directory_commitment(directory).unwrap();
    let mut values = [[0; 32]; 3];
    values[0][12..].copy_from_slice(&root.controller_address());
    values[1] = commitment.0;
    values[2][23] = 1;
    values[2][24..].copy_from_slice(&directory.registry_sequence.to_be_bytes());
    let (deployment, finalized, proof) = proof_fixture_for_agent(values, 8, root.agent_id());
    let database = TestChainDatabase::new();
    let config = DurableResolverConfigV1 {
        consensus: consensus_config(),
        deployment,
        max_cache_age_secs: 120,
        cache_capacity: 8,
    };
    let mut resolver = DurableIdentityResolver::create(
        database.open(),
        config,
        bootstrapped().with_test_execution(finalized),
        BOOTSTRAP_TIME,
    )
    .unwrap();
    resolver
        .accept_proof(root.agent_id(), &proof, BOOTSTRAP_TIME)
        .unwrap();
    (database, resolver, proof)
}

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
) -> (DeviceSession, asl_net::transport::AuthenticatedPeer) {
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
    let TransportEvent::Connected {
        connection: listener_connection,
    } = listener_event.unwrap()
    else {
        panic!("listener did not produce an authenticated connection");
    };

    (
        DeviceSession::from_transport(connection),
        listener_connection,
    )
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

    let (mut session, _) = connect(&mut dialer, &mut listener, endpoint, &peer).await;
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
    let (mut next, _) = connect(&mut dialer, &mut listener, endpoint, &peer).await;
    assert_ne!(next.connection_id(), Some(old_connection));
    assert!(next.current_agent(&history, &mut resolver, NOW).is_err());
    drop(dialer);
    assert!(
        next.accept_hello(&hello(&cert), &signed, &mut history, &mut resolver, NOW)
            .is_err()
    );
}

#[cfg(windows)]
#[tokio::test]
async fn network_hello_verifies_the_proof_and_directory_before_admission() {
    let root = AgentIdentity::generate().unwrap();
    let device = Keypair::generate_ed25519();
    let peer = PeerId::from_bytes(device.public().to_peer_id().to_bytes()).unwrap();
    let cert = certificate(&root, &peer, 1);
    let directory = directory(&root, 7, vec![cert.clone()], vec![]);
    let signed = signed_directory(&root, &directory, 1);
    let mut values = [[0; 32]; 3];
    values[0][12..].copy_from_slice(&root.controller_address());
    values[1] = device_directory_commitment(&directory).unwrap().0;
    values[2][23] = 1;
    values[2][24..].copy_from_slice(&7_u64.to_be_bytes());
    let (deployment, finalized, proof) = proof_fixture_for_agent(values, 8, root.agent_id());
    let config = DurableResolverConfigV1 {
        consensus: consensus_config(),
        deployment,
        max_cache_age_secs: 120,
        cache_capacity: 2,
    };
    let create_resolver = |db: &TestChainDatabase| {
        DurableIdentityResolver::create(
            db.open(),
            config.clone(),
            bootstrapped().with_test_execution(finalized.clone()),
            BOOTSTRAP_TIME,
        )
        .unwrap()
    };
    let serving_db = TestChainDatabase::new();
    let mut serving = create_resolver(&serving_db);
    serving
        .accept_proof(root.agent_id(), &proof, BOOTSTRAP_TIME)
        .unwrap();
    let remote_hello = hello(&cert);

    for case in 0..3 {
        let receiving_db = TestChainDatabase::new();
        let mut resolver = create_resolver(&receiving_db);
        let mut history = RecordHistory::new(root.agent_id(), 32).unwrap();
        let (mut listener, address) = listen(device.clone()).await;
        let dialer_key = Keypair::generate_ed25519();
        let dialer_peer = PeerId::from_bytes(dialer_key.public().to_peer_id().to_bytes()).unwrap();
        let dialer_identity = AgentIdentity::generate().unwrap();
        let dialer_certificate = certificate(&dialer_identity, &dialer_peer, 1);
        let dialer_hello = hello(&dialer_certificate);
        let mut dialer = LocalTransport::new(dialer_key).unwrap();
        let (mut session, listener_connection) =
            connect(&mut dialer, &mut listener, address, &peer).await;
        let hello_token = listener
            .send_control_request(
                &listener_connection,
                asl_types::protocol::WireFrame::Hello(remote_hello.clone()),
            )
            .unwrap();
        let event = timeout(Duration::from_secs(5), async {
            tokio::select! {
                event = dialer.next_event() => event.unwrap(),
                event = listener.next_event() => panic!("unexpected listener event: {event:?}"),
            }
        })
        .await
        .unwrap();
        let TransportEvent::ControlRequest {
            connection: dialer_connection,
            request: asl_types::protocol::WireFrame::Hello(received_hello),
            response: hello_response_token,
        } = event
        else {
            panic!("unexpected request event: {event:?}");
        };
        let sent = session
            .begin_network_hello(received_hello, &mut dialer, &resolver, NOW)
            .unwrap();
        assert!(session.current_agent(&history, &mut resolver, NOW).is_err());
        let (connection, request, response_token) = timeout(Duration::from_secs(5), async {
            tokio::select! {
                event = listener.next_event() => match event.unwrap() {
                    TransportEvent::IdentityProofRequest { connection, request, response } => (connection, request, response),
                    event => panic!("unexpected request event: {event:?}"),
                },
                event = dialer.next_event() => panic!("unexpected outbound event: {event:?}"),
            }
        }).await.unwrap();
        assert_eq!(request.checkpoint_hash.0, finalized.block_hash());
        assert_eq!(request.agent_id, root.agent_id());
        let mut wrong = request.clone();
        wrong.checkpoint_hash.0[0] ^= 1;
        assert!(
            serve_local_identity_proof(&remote_hello, &signed, &wrong, &mut serving, NOW)
                .unwrap()
                .is_none()
        );
        wrong = request.clone();
        wrong.agent_id.0[0] ^= 1;
        assert!(
            serve_local_identity_proof(&remote_hello, &signed, &wrong, &mut serving, NOW)
                .unwrap()
                .is_none()
        );
        assert!(
            serve_local_identity_proof(
                &remote_hello,
                &signed,
                &request,
                &mut serving,
                NOW + 121_000
            )
            .unwrap()
            .is_none()
        );
        let mut response =
            serve_local_identity_proof(&remote_hello, &signed, &request, &mut serving, NOW)
                .unwrap()
                .unwrap();
        match case {
            1 => response.state_root.0[0] ^= 1,
            2 => *response.signed_directory.last_mut().unwrap() ^= 1,
            _ => {}
        }
        listener
            .send_identity_proof_response(&connection, &response_token, response)
            .unwrap();
        let (connection, received, proof) = timeout(Duration::from_secs(5), async {
            tokio::select! {
                event = dialer.next_event() => match event.unwrap() {
                    TransportEvent::IdentityProofResponse { connection, request, response } => (connection, request, response),
                    event => panic!("unexpected response event: {event:?}"),
                },
                event = listener.next_event() => panic!("unexpected listener event: {event:?}"),
            }
        }).await.unwrap();
        assert_eq!(received, sent);
        let result = session.finish_network_hello(
            &connection,
            received,
            &proof,
            &mut history,
            &mut resolver,
            NOW,
        );
        match case {
            0 => {
                result.unwrap();
                assert_eq!(
                    session.current_agent(&history, &mut resolver, NOW).unwrap(),
                    root.agent_id()
                );
                dialer
                    .send_control_response(
                        &dialer_connection,
                        &hello_response_token,
                        asl_types::protocol::WireFrame::Hello(dialer_hello),
                    )
                    .unwrap();
                let event = timeout(Duration::from_secs(5), async {
                    tokio::select! {
                        event = listener.next_event() => event.unwrap(),
                        event = dialer.next_event() => panic!("unexpected dialer event: {event:?}"),
                    }
                })
                .await
                .unwrap();
                assert!(
                    matches!(event, TransportEvent::ControlResponse { request, .. } if request == hello_token)
                );
                assert!(
                    session
                        .current_agent(&history, &mut resolver, NOW + 121_000)
                        .is_err()
                );
            }
            1 => assert!(matches!(result, Err(DeviceAdmissionError::Chain(_)))),
            _ => assert!(matches!(result, Err(DeviceAdmissionError::Session(_)))),
        }
        assert!(session.current_agent(&history, &mut resolver, NOW).is_err());
    }
}

#[cfg(windows)]
#[test]
fn ipc_device_session_binds_the_pending_proof_to_the_local_connection_handle() {
    use crate::chain::identity_proof_to_wire;

    let root = AgentIdentity::generate().unwrap();
    let device = Keypair::generate_ed25519();
    let peer = PeerId::from_bytes(device.public().to_peer_id().to_bytes()).unwrap();
    let cert = certificate(&root, &peer, 1);
    let directory = directory(&root, 7, vec![cert.clone()], vec![]);
    let signed = signed_directory(&root, &directory, 1);
    let mut values = [[0; 32]; 3];
    values[0][12..].copy_from_slice(&root.controller_address());
    values[1] = device_directory_commitment(&directory).unwrap().0;
    values[2][23] = 1;
    values[2][24..].copy_from_slice(&7_u64.to_be_bytes());
    let (deployment, finalized, proof) = proof_fixture_for_agent(values, 8, root.agent_id());
    let config = DurableResolverConfigV1 {
        consensus: consensus_config(),
        deployment,
        max_cache_age_secs: 120,
        cache_capacity: 2,
    };
    let database = TestChainDatabase::new();
    let mut resolver = DurableIdentityResolver::create(
        database.open(),
        config,
        bootstrapped().with_test_execution(finalized),
        BOOTSTRAP_TIME,
    )
    .unwrap();
    resolver
        .accept_proof(root.agent_id(), &proof, BOOTSTRAP_TIME)
        .unwrap();
    let mut history = RecordHistory::new(root.agent_id(), 32).unwrap();
    let connection_id = [71; 16];
    let mut session = DeviceSession::from_ipc_connection(connection_id, peer);
    let request = session
        .begin_network_hello_ipc(hello(&cert), &resolver, NOW)
        .unwrap();
    assert_eq!(request.agent_id, root.agent_id());
    assert_eq!(request.checkpoint_hash.0, proof.block_hash);
    assert_eq!(session.ipc_connection_id(), Some(connection_id));

    let wire = identity_proof_to_wire(&request, proof.clone(), signed.clone());
    let mut wrong_connection = DeviceSession::from_ipc_connection([72; 16], cert.peer_id.clone());
    let wrong_request = wrong_connection
        .begin_network_hello_ipc(hello(&cert), &resolver, NOW)
        .unwrap();
    let wrong_wire = identity_proof_to_wire(&wrong_request, proof.clone(), signed.clone());
    assert!(
        wrong_connection
            .finish_network_hello_ipc(connection_id, &wrong_wire, &mut history, &mut resolver, NOW,)
            .is_err()
    );
    assert!(
        wrong_connection
            .finish_network_hello_ipc([72; 16], &wrong_wire, &mut history, &mut resolver, NOW,)
            .is_err()
    );

    session
        .finish_network_hello_ipc(connection_id, &wire, &mut history, &mut resolver, NOW)
        .unwrap();
    assert_eq!(
        session.current_agent(&history, &mut resolver, NOW).unwrap(),
        root.agent_id()
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

#[cfg(windows)]
#[test]
fn core_admission_only_emits_application_events_after_proof_verification() {
    use asl_types::protocol::{Ack, IdentityProofRequest};

    let local_root = AgentIdentity::generate().unwrap();
    let local_device = DeviceIdentity::generate().unwrap();
    let remote_device = DeviceIdentity::generate().unwrap();
    let local_cert = certificate(&local_root, &local_device.peer_id(), 1);
    let remote_cert = certificate(&local_root, &remote_device.peer_id(), 2);
    let room = Hash32([72; 32]);
    let (_, remote_leaf) = super::super::group_credential::issue_group_credential(
        &local_root,
        room,
        &remote_cert,
        NOW,
    )
    .unwrap();
    let (_, different_device_leaf) =
        super::super::group_credential::issue_group_credential(&local_root, room, &local_cert, NOW)
            .unwrap();
    let local_directory = directory(
        &local_root,
        7,
        vec![local_cert.clone(), remote_cert.clone()],
        vec![],
    );
    let local_signed = signed_directory(&local_root, &local_directory, 1);
    let (local_database, local_resolver, _) =
        durable_directory_resolver(&local_root, &local_directory);
    let mut admission = CoreAdmission::for_local_identity(
        &local_root,
        local_device.peer_id(),
        local_signed.clone(),
        local_resolver,
        NOW,
    )
    .unwrap();

    let (_remote_database, mut remote_resolver, _) =
        durable_directory_resolver(&local_root, &local_directory);
    let remote_hello = hello(&remote_cert);

    let unlisted_device = DeviceIdentity::generate().unwrap();
    let (_unlisted_database, unlisted_resolver, _) =
        durable_directory_resolver(&local_root, &local_directory);
    assert!(
        CoreAdmission::for_local_identity(
            &local_root,
            unlisted_device.peer_id(),
            local_signed.clone(),
            unlisted_resolver,
            NOW,
        )
        .is_err(),
        "the local network device must be listed in the signed registry directory"
    );

    let (_refresh_database, refresh_resolver, refresh_proof) =
        durable_directory_resolver(&local_root, &local_directory);
    assert!(
        admission
            .refresh_local_identity(refresh_resolver.light_client().clone(), &refresh_proof, NOW,)
            .unwrap()
    );
    let mut invalid_refresh_proof = refresh_proof.clone();
    invalid_refresh_proof.storage[0].value[31] ^= 1;
    assert!(
        admission
            .refresh_local_identity(
                refresh_resolver.light_client().clone(),
                &invalid_refresh_proof,
                NOW,
            )
            .is_err()
    );

    let rejected_connection = [82; 16];
    admission.handle_event(
        NetworkEvent::TransportConnected {
            connection_id: rejected_connection,
            peer_id: remote_device.peer_id(),
        },
        NOW,
    );
    let rejected = admission.handle_event(
        NetworkEvent::UnverifiedControlRequest {
            connection_id: rejected_connection,
            response_id: [83; 16],
            request: WireFrame::Ack(Ack {
                message_id: Id128([84; 16]),
                received_id: Id128([85; 16]),
            }),
        },
        NOW,
    );
    assert!(rejected.events.is_empty());
    assert_eq!(
        rejected.commands,
        vec![NetworkCommand::CloseConnection {
            connection_id: rejected_connection
        }]
    );

    let failed_connection = [80; 16];
    let started = admission.handle_event(
        NetworkEvent::TransportConnected {
            connection_id: failed_connection,
            peer_id: remote_device.peer_id(),
        },
        NOW,
    );
    let hello_request_id = started
        .commands
        .iter()
        .find_map(|command| match command {
            NetworkCommand::SendControl {
                request_id,
                request: WireFrame::Hello(_),
                ..
            } => Some(*request_id),
            _ => None,
        })
        .unwrap();
    let failed = admission.handle_event(
        NetworkEvent::RequestFailed {
            connection_id: failed_connection,
            request_id: hello_request_id,
            protocol: crate::ipc::NetworkProtocol::Control,
            code: crate::ipc::NetworkErrorCode::TimedOut,
        },
        NOW,
    );
    assert!(failed.events.is_empty());
    assert_eq!(
        failed.commands,
        vec![NetworkCommand::CloseConnection {
            connection_id: failed_connection,
        }]
    );

    let connection_id = [86; 16];
    let connected = admission.handle_event(
        NetworkEvent::TransportConnected {
            connection_id,
            peer_id: remote_device.peer_id(),
        },
        NOW,
    );
    assert!(matches!(
        connected.commands.as_slice(),
        [NetworkCommand::SendControl {
            request: WireFrame::Hello(_),
            ..
        }]
    ));
    assert!(
        admission
            .authorize_control_command(
                connection_id,
                [87; 16],
                WireFrame::Ack(Ack {
                    message_id: Id128([88; 16]),
                    received_id: Id128([89; 16]),
                }),
                NOW,
            )
            .is_err(),
        "outbound application traffic must remain behind the identity gate"
    );

    let hello_batch = admission.handle_event(
        NetworkEvent::UnverifiedControlRequest {
            connection_id,
            response_id: [90; 16],
            request: WireFrame::Hello(remote_hello.clone()),
        },
        NOW,
    );
    assert!(hello_batch.events.is_empty());
    assert_eq!(hello_batch.commands.len(), 2);
    let proof_request = hello_batch
        .commands
        .iter()
        .find_map(|command| match command {
            NetworkCommand::RequestIdentityProof { request, .. } => Some(request.clone()),
            _ => None,
        })
        .unwrap();
    assert!(hello_batch.commands.iter().any(|command| matches!(
        command,
        NetworkCommand::ReplyControl {
            response: WireFrame::Hello(_),
            ..
        }
    )));
    assert!(
        admission
            .handle_event(
                NetworkEvent::IdentityProofRequested {
                    connection_id,
                    response_id: [91; 16],
                    request: IdentityProofRequest {
                        request_id: Id128([92; 16]),
                        agent_id: local_root.agent_id(),
                        checkpoint_hash: proof_request.checkpoint_hash,
                    },
                },
                NOW,
            )
            .commands
            .iter()
            .any(|command| matches!(command, NetworkCommand::ReplyIdentityProof { .. }))
    );
    let remote_proof = serve_local_identity_proof(
        &remote_hello,
        &local_signed,
        &proof_request,
        &mut remote_resolver,
        NOW,
    )
    .unwrap()
    .unwrap();
    admission.exhaust_proof_budget_for_test();
    let queued = admission.handle_event(
        NetworkEvent::IdentityProofReceived {
            connection_id,
            proof: remote_proof,
        },
        NOW,
    );
    assert!(queued.events.is_empty());
    assert!(
        admission
            .verify_admitted_group_leaf(connection_id, room, &remote_leaf, NOW)
            .is_err()
    );
    assert!(
        admission
            .authorize_control_command(
                connection_id,
                [102; 16],
                WireFrame::Ack(Ack {
                    message_id: Id128([103; 16]),
                    received_id: Id128([104; 16]),
                }),
                NOW,
            )
            .is_err(),
        "a proof waiting for the CPU budget must not admit application traffic"
    );
    std::thread::sleep(Duration::from_millis(510));
    let admitted = admission.poll(NOW);
    admission
        .verify_admitted_group_leaf(connection_id, room, &remote_leaf, NOW)
        .unwrap();
    assert!(
        admission
            .verify_admitted_group_leaf(connection_id, room, &different_device_leaf, NOW)
            .is_err(),
        "a sibling device's leaf is not valid for this authenticated connection"
    );
    assert_eq!(
        admitted.events,
        vec![AdmittedNetworkEvent::PeerAdmitted {
            connection_id,
            peer_id: remote_device.peer_id(),
            agent_id: local_root.agent_id(),
        }]
    );
    assert!(
        admission
            .authorize_control_command(
                connection_id,
                [93; 16],
                WireFrame::Ack(Ack {
                    message_id: Id128([94; 16]),
                    received_id: Id128([95; 16]),
                }),
                NOW,
            )
            .is_ok()
    );

    let control = WireFrame::Ack(Ack {
        message_id: Id128([96; 16]),
        received_id: Id128([97; 16]),
    });
    let delivered = admission.handle_event(
        NetworkEvent::UnverifiedControlRequest {
            connection_id,
            response_id: [98; 16],
            request: control.clone(),
        },
        NOW,
    );
    assert_eq!(
        delivered.events,
        vec![AdmittedNetworkEvent::ControlRequest {
            connection_id,
            agent_id: local_root.agent_id(),
            response_id: [98; 16],
            request: control,
        }]
    );
    assert_eq!(
        admission.close_all().commands,
        vec![NetworkCommand::CloseConnection { connection_id }]
    );
    assert!(
        admission
            .authorize_control_command(
                connection_id,
                [99; 16],
                WireFrame::Ack(Ack {
                    message_id: Id128([100; 16]),
                    received_id: Id128([101; 16]),
                }),
                NOW,
            )
            .is_err()
    );
    drop(admission);
    drop(local_database);
}

#[cfg(windows)]
#[test]
fn only_a_matched_fetch_manifest_registers_its_admitted_device() {
    use crate::{supervisor::Supervisor, transfer::TransferService};
    use asl_net::codec::{BulkOperation, BulkRequest, BulkResponse, BulkStatus};
    use asl_types::{
        manifest::{Manifest, content_id, encode_manifest},
        protocol::{FetchGrant, FetchRequest},
    };

    let root = AgentIdentity::generate().unwrap();
    let keys = Keypair::generate_ed25519().public();
    let peer = PeerId::from_bytes(keys.to_peer_id().to_bytes()).unwrap();
    let device = certificate(&root, &peer, 2);
    let local_peer = DeviceIdentity::generate().unwrap().peer_id();
    let dir = directory(
        &root,
        7,
        vec![certificate(&root, &local_peer, 1), device.clone()],
        vec![],
    );
    let signed = signed_directory(&root, &dir, 1);
    let (db, resolver, proof) = durable_directory_resolver(&root, &dir);
    let mut admission =
        CoreAdmission::for_local_identity(&root, local_peer, signed.clone(), resolver, NOW)
            .unwrap();
    let connection_id = [51; 16];
    admission.handle_event(
        NetworkEvent::TransportConnected {
            connection_id,
            peer_id: peer.clone(),
        },
        NOW,
    );
    let batch = admission.handle_event(
        NetworkEvent::UnverifiedControlRequest {
            connection_id,
            response_id: [52; 16],
            request: WireFrame::Hello(hello(&device)),
        },
        NOW,
    );
    let request = batch
        .commands
        .iter()
        .find_map(|command| match command {
            NetworkCommand::RequestIdentityProof { request, .. } => Some(request),
            _ => None,
        })
        .unwrap();
    let proof = crate::chain::identity_proof_to_wire(request, proof, signed);
    let batch = admission.handle_event(
        NetworkEvent::IdentityProofReceived {
            connection_id,
            proof,
        },
        NOW,
    );
    assert!(matches!(
        batch.events.as_slice(),
        [AdmittedNetworkEvent::PeerAdmitted { .. }]
    ));

    let sql = rusqlite::Connection::open(&db.path).unwrap();
    let counts = || {
        sql.query_row(
            "SELECT (SELECT count(*) FROM device_identities), (SELECT count(*) FROM peers)",
            [],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
        )
        .unwrap()
    };
    assert_eq!(counts(), (0, 0));
    let mut transfers = TransferService::open(&db.path).unwrap();
    let hash = *blake3::hash(b"x").as_bytes();
    let payload = encode_manifest(&Manifest {
        file_size: 1,
        file_hash: hash,
        chunk_hashes: vec![hash],
    })
    .unwrap();
    let fetch = FetchRequest {
        message_id: Id128([53; 16]),
        root_task_id: Id128([54; 16]),
        content_id: Hash32(content_id(&payload)),
    };
    let control_id = [55; 16];
    let grant = FetchGrant {
        message_id: Id128([56; 16]),
        content_id: fetch.content_id,
        lease_id: Hash32([57; 32]),
        file_size: 1,
        expires_at_ms: NOW + 5_000,
    };
    let requester = admission
        .direct_requester(connection_id, root.agent_id())
        .unwrap();
    let request_manifest = |admission: &mut CoreAdmission, transfers: &mut TransferService| {
        let mut bulk_id = None;
        let event = AdmittedNetworkEvent::ControlResponse {
            connection_id,
            agent_id: root.agent_id(),
            request_id: control_id,
            response: WireFrame::FetchGrant(grant.clone()),
        };
        assert!(
            Supervisor::route_transfer_with(Some(admission), transfers, event, NOW, |command| {
                let NetworkCommand::SendBulk { request, .. } = command else {
                    panic!("expected manifest request")
                };
                assert_eq!(request.operation, BulkOperation::Manifest);
                bulk_id = Some(request.request_id);
                Ok(true)
            })
            .unwrap()
            .is_none()
        );
        bulk_id
    };
    let deliver = |admission: &mut CoreAdmission,
                   transfers: &mut TransferService,
                   id: Id128,
                   bytes: &[u8]| {
        let batch = admission.handle_event(
            NetworkEvent::UnverifiedBulkResponse {
                connection_id,
                request_id: id.0,
                response: BulkResponse {
                    request_id: id,
                    status: BulkStatus::Success,
                    payload: bytes.to_vec(),
                },
            },
            NOW,
        );
        let event = batch.events.into_iter().next().unwrap();
        Supervisor::route_transfer_with(Some(admission), transfers, event, NOW, |_| {
            panic!("unexpected send")
        })
        .unwrap()
    };
    assert!(request_manifest(&mut admission, &mut transfers).is_none());
    let raw_id = Id128([58; 16]);
    assert!(deliver(&mut admission, &mut transfers, raw_id, &payload).is_none());
    transfers
        .authorize_bulk_request(
            &mut admission,
            connection_id,
            BulkRequest {
                operation: BulkOperation::Manifest,
                request_id: raw_id,
                content_id: fetch.content_id,
                lease_id: grant.lease_id,
                chunk_index: 0,
            },
            NOW,
        )
        .unwrap();
    assert!(matches!(
        deliver(&mut admission, &mut transfers, raw_id, &payload),
        Some(AdmittedNetworkEvent::BulkTransferResponse(_))
    ));
    assert_eq!(counts(), (0, 0));

    let fetch_once =
        |admission: &mut CoreAdmission, transfers: &mut TransferService, bytes: &[u8]| {
            transfers
                .expect_fetch_response(connection_id, &requester, control_id, &fetch, NOW)
                .unwrap();
            let id = request_manifest(admission, transfers).unwrap();
            let event = deliver(admission, transfers, id, bytes);
            assert!(deliver(admission, transfers, id, bytes).is_none());
            event
        };
    assert!(fetch_once(&mut admission, &mut transfers, &[0]).is_none());
    assert_eq!(counts(), (0, 0));
    sql.execute("UPDATE identity_registry_states SET sequence=8", [])
        .unwrap();
    assert!(fetch_once(&mut admission, &mut transfers, &payload).is_none());
    assert_eq!(counts(), (0, 0));
    sql.execute("UPDATE identity_registry_states SET sequence=7", [])
        .unwrap();

    // Historical, genuinely signed certificates cannot be displaced by a download.
    let other_key = Keypair::generate_ed25519().public();
    let other_peer = PeerId::from_bytes(other_key.to_peer_id().to_bytes()).unwrap();
    let key_hex = |key: libp2p_identity::PublicKey| {
        alloy_primitives::hex::encode(key.try_into_ed25519().unwrap().to_bytes())
    };
    for (existing, existing_key) in [
        (certificate(&root, &other_peer, device.serial), &other_key),
        (certificate(&root, &peer, device.serial + 1), &keys),
        (
            root.issue_device_certificate(peer.clone(), device.serial, NOW, device.expires_at_ms)
                .unwrap(),
            &keys,
        ),
    ] {
        let cbor = existing.to_canonical_cbor().unwrap();
        sql.execute(
            "INSERT INTO device_identities(peer_id,agent_id,public_key_hex,certificate_cbor,
                certificate_serial,certificate_expires_ms,created_at_ms) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            rusqlite::params![bs58::encode(existing.peer_id.as_bytes()).into_string(),
                bs58::encode(existing.agent_id.0).into_string(), key_hex(existing_key.clone()),
                cbor, existing.serial as i64, existing.expires_at_ms as i64, NOW as i64],
        ).unwrap();
        assert!(fetch_once(&mut admission, &mut transfers, &payload).is_none());
        assert_eq!(counts(), (1, 0));
        assert_eq!(
            sql.execute(
                "DELETE FROM device_identities WHERE certificate_cbor=?1",
                [&cbor]
            )
            .unwrap(),
            1
        );
    }
    for _ in 0..2 {
        assert!(
            matches!(fetch_once(&mut admission, &mut transfers, &payload),
            Some(AdmittedNetworkEvent::FetchManifestReceived(m)) if m.peer_id == peer && m.root_task_id == fetch.root_task_id)
        );
        assert_eq!(counts(), (1, 1));
    }
    let row = sql
        .query_row(
            "SELECT p.peer_id,p.agent_id,d.public_key_hex,d.certificate_cbor
        FROM peers p JOIN device_identities d USING(peer_id,agent_id)",
            [],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(
        row,
        (
            keys.to_peer_id().to_base58(),
            bs58::encode(root.agent_id().0).into_string(),
            key_hex(keys),
            device.to_canonical_cbor().unwrap()
        )
    );
    assert!(db.open().authorized_contacts().unwrap().is_empty());
    let elevations: i64 = sql
        .query_row(
            "SELECT (SELECT count(*) FROM paired_contacts)
        + (SELECT count(*) FROM preferred_peers) + (SELECT count(*) FROM trust_events)
        + (SELECT count(*) FROM contribution_events)",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(elevations, 0);

    sql.execute(
        "UPDATE device_identities SET revoked_at_ms=?1",
        [NOW as i64],
    )
    .unwrap();
    assert!(fetch_once(&mut admission, &mut transfers, &payload).is_none());
    let revoked: i64 = sql
        .query_row("SELECT revoked_at_ms FROM device_identities", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(revoked, NOW as i64);
}

#[cfg(windows)]
#[test]
fn dht_records_are_cached_only_after_key_signature_and_chain_admission() {
    let root = AgentIdentity::generate().unwrap();
    let local_device = DeviceIdentity::generate().unwrap();
    let cert = certificate(&root, &local_device.peer_id(), 1);
    let directory = directory(&root, 7, vec![cert], vec![]);
    let signed_directory = signed_directory(&root, &directory, 1);
    let (database, resolver, _) = durable_directory_resolver(&root, &directory);
    let mut admission = CoreAdmission::for_local_identity(
        &root,
        local_device.peer_id(),
        signed_directory,
        resolver,
        NOW,
    )
    .unwrap();

    let bytes = sign_record(
        &root,
        RecordPayload::Profile(Profile {
            agent_id: root.agent_id(),
            sequence: 1,
            capabilities: vec![ConceptRef::RUST],
            avatar: None,
        }),
        1,
        NOW,
        LIFETIME,
    )
    .unwrap();
    let key = asl_net::dht::identity_record_key(root.agent_id(), RecordKind::Profile).unwrap();
    let valid = admission.handle_event(
        NetworkEvent::DhtRecordCandidate {
            candidate_id: [120; 16],
            key: key.as_ref().try_into().unwrap(),
            value: bytes.clone(),
        },
        NOW,
    );
    assert_eq!(
        valid.commands,
        vec![NetworkCommand::DecideDhtRecord {
            candidate_id: [120; 16],
            accept: true,
        }]
    );
    assert!(matches!(
        valid.events.as_slice(),
        [AdmittedNetworkEvent::DhtRecordAvailable {
            agent_id,
            kind: RecordKind::Profile,
            sequence: 1,
            record,
        }] if *agent_id == root.agent_id() && record == &bytes
    ));

    let mut invalid_signature = asl_types::record::decode_record(&bytes).unwrap();
    invalid_signature.signature.0[0] ^= 1;
    let invalid_signature = asl_types::record::encode_record(&invalid_signature).unwrap();
    let rejected = admission.handle_event(
        NetworkEvent::DhtRecordCandidate {
            candidate_id: [121; 16],
            key: key.as_ref().try_into().unwrap(),
            value: invalid_signature,
        },
        NOW,
    );
    assert_eq!(
        rejected.commands,
        vec![NetworkCommand::DecideDhtRecord {
            candidate_id: [121; 16],
            accept: false,
        }]
    );
    assert!(rejected.events.is_empty());

    let wrong_key = admission.handle_event(
        NetworkEvent::DhtRecordCandidate {
            candidate_id: [122; 16],
            key: [0; 32],
            value: bytes,
        },
        NOW,
    );
    assert_eq!(
        wrong_key.commands,
        vec![NetworkCommand::DecideDhtRecord {
            candidate_id: [122; 16],
            accept: false,
        }]
    );
    assert!(wrong_key.events.is_empty());
    drop(database);
}
