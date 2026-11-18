use std::time::Duration;

use asl_net::codec::{CONTROL_PROTOCOL, ControlCodec, IDENTITY_PROOF_PROTOCOL, IdentityProofCodec};
use asl_net::transport::TransportKind;
use asl_types::protocol::{Ack, IdentityProof, IdentityProofRequest, WireFrame};
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
        let request = WireFrame::Ack(Ack {
            message_id: [1; 16].into(),
            received_id: [2; 16].into(),
        });
        let response = WireFrame::Ack(Ack {
            message_id: [3; 16].into(),
            received_id: [4; 16].into(),
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
            account_proof: vec![vec![6; 8]],
            storage_proofs: vec![],
            controller_address: [7; 20],
            state_commitment: [8; 32].into(),
            sequence: 9,
            revoked: false,
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
