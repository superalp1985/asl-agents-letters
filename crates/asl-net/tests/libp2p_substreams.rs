use std::time::Duration;

use asl_net::codec::{
    BULK_PROTOCOL, BulkCodec, BulkOperation, BulkRequest, BulkResponse, BulkStatus,
    CONTROL_PROTOCOL, ControlCodec, IDENTITY_PROOF_PROTOCOL, IdentityProofCodec,
};
use asl_net::transport::TransportKind;
use asl_types::{
    manifest::{CHUNK_SIZE, Manifest, content_id, decode_manifest, encode_manifest},
    protocol::{Ack, IdentityProof, IdentityProofRequest, WireFrame},
};
use libp2p::{
    Multiaddr, Swarm, SwarmBuilder,
    futures::StreamExt,
    identity::Keypair,
    noise,
    request_response::{self, Codec, Event, Message, ProtocolSupport},
    swarm::SwarmEvent,
    tcp, yamux,
};

const DEADLINE: Duration = Duration::from_secs(10);

fn swarm<C>(
    identity: Keypair,
    codec: C,
    protocol: C::Protocol,
) -> Swarm<request_response::Behaviour<C>>
where
    C: Codec + Default + Clone + Send + 'static,
    C::Protocol: Send + 'static,
{
    let behaviour = request_response::Behaviour::with_codec(
        codec,
        [(protocol, ProtocolSupport::Full)],
        request_response::Config::default()
            .with_request_timeout(DEADLINE)
            .with_max_concurrent_streams(2),
    );
    SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .unwrap()
        .with_quic_config(|mut config| {
            config.handshake_timeout = DEADLINE;
            config.max_concurrent_stream_limit = 2;
            config.max_stream_data = 16 * 1024;
            config.max_connection_data = 16 * 1024;
            config
        })
        .with_behaviour(|_| behaviour)
        .unwrap()
        .with_swarm_config(|config| config.with_max_negotiating_inbound_streams(1))
        .with_connection_timeout(DEADLINE)
        .build()
}

fn endpoint(kind: TransportKind, port: u16) -> Multiaddr {
    let tcp = format!("/ip4/127.0.0.1/tcp/{port}");
    let quic = format!("/ip4/127.0.0.1/udp/{port}/quic-v1");
    match kind {
        TransportKind::Tcp => tcp.parse().unwrap(),
        TransportKind::Quic => quic.parse().unwrap(),
    }
}

async fn listening<C: Codec + Default + Clone + Send + 'static>(
    swarm: &mut Swarm<request_response::Behaviour<C>>,
) -> Multiaddr {
    loop {
        if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
            return address;
        }
    }
}

#[tokio::test]
async fn control_codec_runs_over_tcp_and_quic_request_response_substreams() {
    for kind in [TransportKind::Tcp, TransportKind::Quic] {
        let mut listener = swarm(Keypair::generate_ed25519(), ControlCodec, CONTROL_PROTOCOL);
        listener.listen_on(endpoint(kind, 0)).unwrap();
        let address = tokio::time::timeout(DEADLINE, listening(&mut listener))
            .await
            .unwrap();
        let listener_peer = *listener.local_peer_id();

        let mut dialer = swarm(Keypair::generate_ed25519(), ControlCodec, CONTROL_PROTOCOL);
        let dialer_peer = *dialer.local_peer_id();
        dialer.dial(address).unwrap();
        // Use the independent fixed bytes so the network test covers a real
        // expression on each transport without relying on local JSON syntax.
        let expression = include_str!("../../../schemas/vectors/expression-letter-v1.hex")
            .split_ascii_whitespace()
            .map(|byte| u8::from_str_radix(byte, 16).unwrap())
            .collect::<Vec<_>>();
        let request = asl_types::protocol::decode_control(&expression).unwrap();
        let WireFrame::Expression(letter) = &request else {
            panic!("expected expression");
        };
        let response = WireFrame::Ack(Ack {
            message_id: [3; 16].into(),
            received_id: letter.message_id,
        });
        let mut request_id = None;
        let mut received_request = false;
        let mut received_response = false;

        tokio::time::timeout(DEADLINE, async {
            while !received_response {
                tokio::select! {
                    event = listener.select_next_some() => {
                        if let SwarmEvent::Behaviour(Event::Message {
                            peer,
                            message: Message::Request { request: incoming, channel, .. },
                            ..
                        }) = event {
                            assert_eq!(peer, dialer_peer);
                            assert_eq!(incoming, request);
                            listener.behaviour_mut().send_response(channel, response.clone()).unwrap();
                            received_request = true;
                        }
                    }
                    event = dialer.select_next_some() => {
                        match event {
                            SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == listener_peer => {
                                request_id = Some(dialer.behaviour_mut().send_request(&listener_peer, request.clone()));
                            }
                            SwarmEvent::Behaviour(Event::Message {
                                peer,
                                message: Message::Response { request_id: response_id, response: incoming },
                                ..
                            }) => {
                                assert_eq!(peer, listener_peer);
                                assert_eq!(Some(response_id), request_id);
                                assert_eq!(incoming, response);
                                received_response = true;
                            }
                            SwarmEvent::Behaviour(Event::OutboundFailure { error, .. }) => panic!("control request failed: {error}"),
                            _ => {}
                        }
                    }
                }
            }
        })
        .await
        .unwrap();
        assert!(received_request);
    }
}

#[tokio::test]
async fn identity_proof_codec_runs_over_tcp_and_quic_request_response_substreams() {
    for kind in [TransportKind::Tcp, TransportKind::Quic] {
        let mut listener = swarm(
            Keypair::generate_ed25519(),
            IdentityProofCodec,
            IDENTITY_PROOF_PROTOCOL,
        );
        listener.listen_on(endpoint(kind, 0)).unwrap();
        let address = tokio::time::timeout(DEADLINE, listening(&mut listener))
            .await
            .unwrap();
        let listener_peer = *listener.local_peer_id();
        let mut dialer = swarm(
            Keypair::generate_ed25519(),
            IdentityProofCodec,
            IDENTITY_PROOF_PROTOCOL,
        );
        let dialer_peer = *dialer.local_peer_id();
        dialer.dial(address).unwrap();

        let request = IdentityProofRequest {
            request_id: [1; 16].into(),
            agent_id: [2; 32].into(),
            checkpoint_hash: [3; 32].into(),
        };
        let response = IdentityProof {
            request_id: request.request_id,
            agent_id: request.agent_id,
            finalized_height: 123,
            block_hash: [4; 32].into(),
            state_root: [5; 32].into(),
            account: asl_types::protocol::AccountProof {
                nonce: 1,
                balance: [6; 32],
                storage_root: [7; 32],
                code_hash: [8; 32],
                nodes: vec![vec![9; 8]],
            },
            storage_proofs: (0_u8..3)
                .map(|slot| asl_types::protocol::StorageProof {
                    slot: [slot + 10; 32],
                    value: [slot + 20; 32],
                    nodes: vec![vec![11; 8]],
                })
                .collect(),
            signed_directory: vec![12; 256],
        };
        let mut request_id = None;
        let mut received_request = false;
        let mut received_response = false;

        tokio::time::timeout(DEADLINE, async {
            while !received_response {
                tokio::select! {
                    event = listener.select_next_some() => {
                        if let SwarmEvent::Behaviour(Event::Message {
                            peer,
                            message: Message::Request { request: incoming, channel, .. },
                            ..
                        }) = event {
                            assert_eq!(peer, dialer_peer);
                            assert_eq!(incoming, request);
                            listener.behaviour_mut().send_response(channel, response.clone()).unwrap();
                            received_request = true;
                        }
                    }
                    event = dialer.select_next_some() => {
                        match event {
                            SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == listener_peer => {
                                request_id = Some(dialer.behaviour_mut().send_request(&listener_peer, request.clone()));
                            }
                            SwarmEvent::Behaviour(Event::Message {
                                peer,
                                message: Message::Response { request_id: response_id, response: incoming },
                                ..
                            }) => {
                                assert_eq!(peer, listener_peer);
                                assert_eq!(Some(response_id), request_id);
                                assert_eq!(incoming, response);
                                received_response = true;
                            }
                            SwarmEvent::Behaviour(Event::OutboundFailure { error, .. }) => panic!("identity proof request failed: {error}"),
                            _ => {}
                        }
                    }
                }
            }
        })
        .await
        .unwrap();
        assert!(received_request);
    }
}

#[tokio::test]
async fn largest_encoded_manifest_traverses_tcp_and_quic_substreams() {
    let manifest = Manifest {
        file_size: u64::from(CHUNK_SIZE) * 65_536,
        file_hash: [4; 32],
        chunk_hashes: vec![[5; 32]; 65_536],
    };
    let encoded = encode_manifest(&manifest).unwrap();
    assert_eq!(encoded.len(), 2_097_210);
    let expected_id = content_id(&encoded);
    for kind in [TransportKind::Tcp, TransportKind::Quic] {
        let mut listener = swarm(Keypair::generate_ed25519(), BulkCodec, BULK_PROTOCOL);
        listener.listen_on(endpoint(kind, 0)).unwrap();
        let address = tokio::time::timeout(DEADLINE, listening(&mut listener))
            .await
            .unwrap();
        let listener_peer = *listener.local_peer_id();
        let mut dialer = swarm(Keypair::generate_ed25519(), BulkCodec, BULK_PROTOCOL);
        let dialer_peer = *dialer.local_peer_id();
        dialer.dial(address).unwrap();

        let request = BulkRequest {
            operation: BulkOperation::Manifest,
            request_id: [1; 16].into(),
            content_id: expected_id.into(),
            lease_id: [3; 32].into(),
            chunk_index: 0,
        };
        let response = BulkResponse {
            request_id: request.request_id,
            status: BulkStatus::Success,
            payload: encoded.clone(),
        };
        let mut request_id = None;
        let mut received_request = false;
        let mut received_response = false;

        tokio::time::timeout(DEADLINE, async {
            while !received_response {
                tokio::select! {
                    event = listener.select_next_some() => {
                        if let SwarmEvent::Behaviour(Event::Message {
                            peer,
                            message: Message::Request { request: incoming, channel, .. },
                            ..
                        }) = event {
                            assert_eq!(peer, dialer_peer);
                            assert_eq!(incoming, request);
                            listener.behaviour_mut().send_response(channel, response.clone()).unwrap();
                            received_request = true;
                        }
                    }
                    event = dialer.select_next_some() => {
                        match event {
                            SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == listener_peer => {
                                request_id = Some(dialer.behaviour_mut().send_request(&listener_peer, request.clone()));
                            }
                            SwarmEvent::Behaviour(Event::Message {
                                peer,
                                message: Message::Response { request_id: response_id, response: incoming },
                                ..
                            }) => {
                                assert_eq!(peer, listener_peer);
                                assert_eq!(Some(response_id), request_id);
                                assert_eq!(incoming.request_id, request.request_id);
                                assert_eq!(incoming.status, BulkStatus::Success);
                                assert_eq!(decode_manifest(&incoming.payload, expected_id).unwrap(), manifest);
                                received_response = true;
                            }
                            SwarmEvent::Behaviour(Event::OutboundFailure { error, .. }) => panic!("bulk request failed: {error}"),
                            _ => {}
                        }
                    }
                }
            }
        })
        .await
        .unwrap();
        assert!(received_request);
    }
}
