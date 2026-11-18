use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use asl_net::{
    codec::{BulkOperation, BulkRequest, BulkResponse, BulkStatus},
    transport::{LocalTransport, TransportEvent, TransportKind},
};
use asl_types::{
    ids::{AgentId, Hash32, Id128, PeerId},
    protocol::{AccountProof, Ack, IdentityProof, IdentityProofRequest, StorageProof, WireFrame},
};
use libp2p::identity::Keypair;

const DEADLINE: Duration = Duration::from_secs(10);

fn peer_id(identity: &Keypair) -> PeerId {
    PeerId::from_bytes(identity.public().to_peer_id().to_bytes()).unwrap()
}

async fn next_matching(
    transport: &mut LocalTransport,
    predicate: impl Fn(&TransportEvent) -> bool,
) -> TransportEvent {
    tokio::time::timeout(DEADLINE, async {
        loop {
            let event = transport.next_event().await.unwrap();
            if predicate(&event) {
                return event;
            }
        }
    })
    .await
    .expect("network event deadline")
}

async fn next_from_either(
    listener: &mut LocalTransport,
    dialer: &mut LocalTransport,
    predicate: impl Fn(&TransportEvent) -> bool,
) -> TransportEvent {
    tokio::time::timeout(DEADLINE, async {
        loop {
            let event = tokio::select! {
                event = listener.next_event() => event.unwrap(),
                event = dialer.next_event() => event.unwrap(),
            };
            if predicate(&event) {
                return event;
            }
        }
    })
    .await
    .expect("network event deadline")
}

#[tokio::test]
async fn control_identity_and_bulk_requests_use_the_authenticated_connection() {
    for kind in [TransportKind::Tcp, TransportKind::Quic] {
        let listener_key = Keypair::generate_ed25519();
        let listener_peer = peer_id(&listener_key);
        let mut listener = LocalTransport::new(listener_key).unwrap();
        listener
            .listen(kind, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .unwrap();
        let endpoint = match next_matching(&mut listener, |event| {
            matches!(event, TransportEvent::Listening(_, _))
        })
        .await
        {
            TransportEvent::Listening(_, endpoint) => endpoint,
            _ => unreachable!(),
        };

        let dialer_key = Keypair::generate_ed25519();
        let dialer_peer = peer_id(&dialer_key);
        let mut dialer = LocalTransport::new(dialer_key).unwrap();
        dialer.dial(kind, endpoint, &listener_peer).unwrap();
        let (listener_event, dialer_event) = tokio::join!(
            next_matching(&mut listener, |event| matches!(
                event,
                TransportEvent::Connected { .. }
            )),
            next_matching(&mut dialer, |event| matches!(
                event,
                TransportEvent::Connected { .. }
            )),
        );
        let TransportEvent::Connected {
            connection: listener_connection,
        } = listener_event
        else {
            unreachable!()
        };
        let TransportEvent::Connected {
            connection: dialer_connection,
        } = dialer_event
        else {
            unreachable!()
        };
        assert_eq!(listener_connection.peer_id(), &dialer_peer);
        assert_eq!(dialer_connection.peer_id(), &listener_peer);

        let mut alternate_dialer = LocalTransport::new(Keypair::generate_ed25519()).unwrap();
        alternate_dialer
            .dial(kind, endpoint, &listener_peer)
            .unwrap();
        let (alternate_listener_event, alternate_dialer_event) = tokio::join!(
            next_matching(&mut listener, |event| matches!(
                event,
                TransportEvent::Connected { .. }
            )),
            next_matching(&mut alternate_dialer, |event| matches!(
                event,
                TransportEvent::Connected { .. }
            )),
        );
        let TransportEvent::Connected {
            connection: alternate_connection,
        } = alternate_listener_event
        else {
            unreachable!()
        };
        assert!(matches!(
            alternate_dialer_event,
            TransportEvent::Connected { .. }
        ));

        let identity_request = IdentityProofRequest {
            request_id: Id128([1; 16]),
            agent_id: AgentId([2; 32]),
            checkpoint_hash: Hash32([3; 32]),
        };
        let identity_token = dialer
            .send_identity_proof_request(&dialer_connection, identity_request.clone())
            .unwrap();
        let identity_response_token = match next_from_either(&mut listener, &mut dialer, |event| {
            matches!(event, TransportEvent::IdentityProofRequest { .. })
        })
        .await
        {
            TransportEvent::IdentityProofRequest {
                connection,
                request,
                response,
            } => {
                assert_eq!(
                    connection.connection_id(),
                    listener_connection.connection_id()
                );
                assert_eq!(request, identity_request);
                response
            }
            _ => unreachable!(),
        };
        let identity_response = IdentityProof {
            request_id: identity_request.request_id,
            agent_id: identity_request.agent_id,
            finalized_height: 42,
            block_hash: identity_request.checkpoint_hash,
            state_root: Hash32([4; 32]),
            account: AccountProof {
                nonce: 0,
                balance: [0; 32],
                storage_root: [5; 32],
                code_hash: [6; 32],
                nodes: vec![vec![7; 8]],
            },
            storage_proofs: (0..3)
                .map(|slot| StorageProof {
                    slot: [slot + 8; 32],
                    value: [slot + 11; 32],
                    nodes: vec![vec![12; 8]],
                })
                .collect(),
            signed_directory: vec![13; 32],
        };
        assert_eq!(
            listener
                .send_identity_proof_response(
                    &alternate_connection,
                    &identity_response_token,
                    identity_response.clone(),
                )
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        let mut wrong_identity_response = identity_response.clone();
        wrong_identity_response.agent_id = AgentId([99; 32]);
        assert!(
            listener
                .send_identity_proof_response(
                    &listener_connection,
                    &identity_response_token,
                    wrong_identity_response,
                )
                .is_err()
        );
        listener
            .send_identity_proof_response(
                &listener_connection,
                &identity_response_token,
                identity_response,
            )
            .unwrap();
        match next_from_either(&mut listener, &mut dialer, |event| {
            matches!(event, TransportEvent::IdentityProofResponse { .. })
        })
        .await
        {
            TransportEvent::IdentityProofResponse {
                connection,
                request,
                response,
            } => {
                assert_eq!(
                    connection.connection_id(),
                    dialer_connection.connection_id()
                );
                assert_eq!(request, identity_token);
                assert_eq!(response.request_id, identity_request.request_id);
                assert_eq!(response.agent_id, identity_request.agent_id);
            }
            _ => unreachable!(),
        }

        let control_request = WireFrame::Ack(Ack {
            message_id: Id128([14; 16]),
            received_id: Id128([15; 16]),
        });
        let control_token = dialer
            .send_control_request(&dialer_connection, control_request.clone())
            .unwrap();
        let control_response_token = match next_from_either(&mut listener, &mut dialer, |event| {
            matches!(event, TransportEvent::ControlRequest { .. })
        })
        .await
        {
            TransportEvent::ControlRequest {
                connection,
                request,
                response,
            } => {
                assert_eq!(
                    connection.connection_id(),
                    listener_connection.connection_id()
                );
                assert_eq!(request, control_request);
                response
            }
            _ => unreachable!(),
        };
        let control_response = WireFrame::Ack(Ack {
            message_id: Id128([16; 16]),
            received_id: Id128([14; 16]),
        });
        listener
            .send_control_response(
                &listener_connection,
                &control_response_token,
                control_response.clone(),
            )
            .unwrap();
        match next_from_either(&mut listener, &mut dialer, |event| {
            matches!(event, TransportEvent::ControlResponse { .. })
        })
        .await
        {
            TransportEvent::ControlResponse {
                connection,
                request,
                response,
            } => {
                assert_eq!(
                    connection.connection_id(),
                    dialer_connection.connection_id()
                );
                assert_eq!(request, control_token);
                assert_eq!(response, control_response);
            }
            _ => unreachable!(),
        }

        let bulk_request = BulkRequest {
            operation: BulkOperation::Manifest,
            request_id: Id128([17; 16]),
            content_id: Hash32([18; 32]),
            lease_id: Hash32([19; 32]),
            chunk_index: 0,
        };
        let bulk_token = dialer
            .send_bulk_request(&dialer_connection, bulk_request.clone())
            .unwrap();
        let bulk_response_token = match next_from_either(&mut listener, &mut dialer, |event| {
            matches!(event, TransportEvent::BulkRequest { .. })
        })
        .await
        {
            TransportEvent::BulkRequest {
                connection,
                request,
                response,
            } => {
                assert_eq!(
                    connection.connection_id(),
                    listener_connection.connection_id()
                );
                assert_eq!(request, bulk_request);
                response
            }
            _ => unreachable!(),
        };
        listener
            .send_bulk_response(
                &listener_connection,
                &bulk_response_token,
                BulkResponse {
                    request_id: bulk_request.request_id,
                    status: BulkStatus::NotFound,
                    payload: Vec::new(),
                },
            )
            .unwrap();
        match next_from_either(&mut listener, &mut dialer, |event| {
            matches!(event, TransportEvent::BulkResponse { .. })
        })
        .await
        {
            TransportEvent::BulkResponse {
                connection,
                request,
                response,
            } => {
                assert_eq!(
                    connection.connection_id(),
                    dialer_connection.connection_id()
                );
                assert_eq!(request, bulk_token);
                assert_eq!(response.request_id, bulk_request.request_id);
            }
            _ => unreachable!(),
        }
    }
}
