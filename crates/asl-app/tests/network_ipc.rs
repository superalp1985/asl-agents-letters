use asl_app::ipc::{
    IpcMessage, IpcRole, MAX_IPC_BULK_PAYLOAD_BYTES, MAX_IPC_IDENTITY_PROOF_FRAME_BYTES,
    NetworkErrorCode, NetworkProtocol, decode_frame, encode_frame,
};
use asl_net::{
    codec::{BulkOperation, BulkRequest, BulkResponse, BulkStatus},
    transport::TransportKind,
};
use asl_types::{
    ids::{AgentId, Hash32, Id128, PeerId},
    protocol::{AccountProof, IdentityProof, IdentityProofRequest, StorageProof},
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn peer_id() -> PeerId {
    let keypair = libp2p_identity::Keypair::generate_ed25519();
    PeerId::from_bytes(keypair.public().to_peer_id().to_bytes()).unwrap()
}

fn proof_request() -> IdentityProofRequest {
    IdentityProofRequest {
        request_id: Id128([7; 16]),
        agent_id: AgentId([8; 32]),
        checkpoint_hash: Hash32([9; 32]),
    }
}

fn identity_proof() -> IdentityProof {
    IdentityProof {
        request_id: Id128([7; 16]),
        agent_id: AgentId([8; 32]),
        finalized_height: 123,
        block_hash: Hash32([9; 32]),
        state_root: Hash32([10; 32]),
        account: AccountProof {
            nonce: 1,
            balance: [11; 32],
            storage_root: [12; 32],
            code_hash: [13; 32],
            nodes: vec![vec![14, 15]],
        },
        storage_proofs: (0..3)
            .map(|slot| StorageProof {
                slot: [slot + 16; 32],
                value: [slot + 20; 32],
                nodes: vec![vec![24, 25]],
            })
            .collect(),
        signed_directory: vec![26; 128],
    }
}

#[test]
fn authenticated_peer_and_identity_proof_messages_round_trip_in_their_roles() {
    let messages = [
        (
            IpcRole::Net,
            IpcRole::Core,
            IpcMessage::PeerAuthenticated {
                connection_id: [1; 16],
                peer_id: peer_id(),
            },
        ),
        (
            IpcRole::Net,
            IpcRole::Core,
            IpcMessage::PeerDisconnected {
                connection_id: [2; 16],
            },
        ),
        (
            IpcRole::Net,
            IpcRole::Core,
            IpcMessage::IdentityProofRequested {
                connection_id: [3; 16],
                response_id: [4; 16],
                request: proof_request(),
            },
        ),
        (
            IpcRole::Net,
            IpcRole::Core,
            IpcMessage::IdentityProofReceived {
                connection_id: [5; 16],
                proof: identity_proof(),
            },
        ),
        (
            IpcRole::Core,
            IpcRole::Net,
            IpcMessage::RequestIdentityProof {
                connection_id: [6; 16],
                request: proof_request(),
            },
        ),
        (
            IpcRole::Core,
            IpcRole::Net,
            IpcMessage::ReplyIdentityProof {
                connection_id: [7; 16],
                response_id: [8; 16],
                proof: identity_proof(),
            },
        ),
    ];

    for (sender, receiver, message) in messages {
        let bytes = encode_frame(sender, receiver, 1, &message).unwrap();
        let decoded = decode_frame(&bytes, sender, receiver, 1).unwrap();
        assert_eq!(decoded.message, message);
    }
}

#[test]
fn identity_proof_ipc_messages_reject_wrong_roles_and_malformed_peer_ids() {
    let connected = IpcMessage::PeerAuthenticated {
        connection_id: [1; 16],
        peer_id: peer_id(),
    };
    assert!(encode_frame(IpcRole::Core, IpcRole::Net, 1, &connected).is_err());
    assert!(encode_frame(IpcRole::Worker, IpcRole::Core, 1, &connected).is_err());

    let request = IpcMessage::RequestIdentityProof {
        connection_id: [2; 16],
        request: proof_request(),
    };
    assert!(encode_frame(IpcRole::Net, IpcRole::Core, 1, &request).is_err());

    let mut bytes = encode_frame(IpcRole::Net, IpcRole::Core, 1, &connected).unwrap();
    let peer_id_start = 20 + 16 + 2;
    bytes[peer_id_start] = 0xff;
    assert!(decode_frame(&bytes, IpcRole::Net, IpcRole::Core, 1).is_err());
}

#[test]
fn identity_proof_ipc_messages_reject_invalid_nested_protocol_frames() {
    let mut bytes = encode_frame(
        IpcRole::Net,
        IpcRole::Core,
        1,
        &IpcMessage::IdentityProofReceived {
            connection_id: [5; 16],
            proof: identity_proof(),
        },
    )
    .unwrap();
    let nested_frame_start = 20 + 16 + 4;
    bytes[nested_frame_start] = 0xff;
    assert!(decode_frame(&bytes, IpcRole::Net, IpcRole::Core, 1).is_err());
}

#[test]
fn a_valid_identity_request_cannot_be_decoded_as_a_proof() {
    let mut bytes = encode_frame(
        IpcRole::Core,
        IpcRole::Net,
        1,
        &IpcMessage::RequestIdentityProof {
            connection_id: [5; 16],
            request: proof_request(),
        },
    )
    .unwrap();
    bytes[6] = IpcRole::Net as u8;
    bytes[7] = 13; // IdentityProofReceived has the same envelope as RequestIdentityProof.
    assert!(decode_frame(&bytes, IpcRole::Net, IpcRole::Core, 1).is_err());
}

#[test]
fn identity_proof_ipc_messages_reject_frames_over_the_protocol_limit() {
    let body_length = 16 + 4 + MAX_IPC_IDENTITY_PROOF_FRAME_BYTES + 1;
    let mut bytes = vec![0; 20 + body_length];
    bytes[..4].copy_from_slice(b"ASLI");
    bytes[4..6].copy_from_slice(&1_u16.to_be_bytes());
    bytes[6] = IpcRole::Net as u8;
    bytes[7] = 13;
    bytes[8..16].copy_from_slice(&1_u64.to_be_bytes());
    bytes[16..20].copy_from_slice(&(body_length as u32).to_be_bytes());
    bytes[20 + 16..20 + 20]
        .copy_from_slice(&((MAX_IPC_IDENTITY_PROOF_FRAME_BYTES + 1) as u32).to_be_bytes());

    assert!(decode_frame(&bytes, IpcRole::Net, IpcRole::Core, 1).is_err());
}

#[test]
fn net_driver_commands_and_events_round_trip_with_fixed_roles() {
    let peer = peer_id();
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4001);
    let control = asl_types::protocol::WireFrame::Ack(asl_types::protocol::Ack {
        message_id: Id128([31; 16]),
        received_id: Id128([32; 16]),
    });
    let bulk_request = BulkRequest {
        operation: BulkOperation::Chunk,
        request_id: Id128([33; 16]),
        content_id: Hash32([34; 32]),
        lease_id: Hash32([35; 32]),
        chunk_index: 7,
    };
    let messages = [
        (
            IpcRole::Core,
            IpcRole::Net,
            IpcMessage::Listen {
                operation_id: [36; 16],
                kind: TransportKind::Tcp,
                address,
            },
        ),
        (
            IpcRole::Core,
            IpcRole::Net,
            IpcMessage::Dial {
                operation_id: [37; 16],
                kind: TransportKind::Quic,
                address,
                peer_id: peer,
            },
        ),
        (
            IpcRole::Core,
            IpcRole::Net,
            IpcMessage::CloseConnection {
                connection_id: [49; 16],
            },
        ),
        (
            IpcRole::Net,
            IpcRole::Core,
            IpcMessage::OperationAccepted {
                operation_id: [36; 16],
            },
        ),
        (
            IpcRole::Net,
            IpcRole::Core,
            IpcMessage::OperationFailed {
                operation_id: [37; 16],
                code: NetworkErrorCode::Transport,
            },
        ),
        (
            IpcRole::Net,
            IpcRole::Core,
            IpcMessage::Listening {
                kind: TransportKind::Tcp,
                address,
            },
        ),
        (
            IpcRole::Net,
            IpcRole::Core,
            IpcMessage::ControlRequested {
                connection_id: [38; 16],
                response_id: [39; 16],
                request: control.clone(),
            },
        ),
        (
            IpcRole::Net,
            IpcRole::Core,
            IpcMessage::ControlReceived {
                connection_id: [38; 16],
                request_id: [40; 16],
                response: control.clone(),
            },
        ),
        (
            IpcRole::Core,
            IpcRole::Net,
            IpcMessage::SendControl {
                connection_id: [38; 16],
                request_id: [40; 16],
                request: control.clone(),
            },
        ),
        (
            IpcRole::Core,
            IpcRole::Net,
            IpcMessage::ReplyControl {
                connection_id: [38; 16],
                response_id: [39; 16],
                response: control,
            },
        ),
        (
            IpcRole::Net,
            IpcRole::Core,
            IpcMessage::BulkRequested {
                connection_id: [41; 16],
                response_id: [42; 16],
                request: bulk_request.clone(),
            },
        ),
        (
            IpcRole::Net,
            IpcRole::Core,
            IpcMessage::BulkReceived {
                connection_id: [41; 16],
                response: BulkResponse {
                    request_id: bulk_request.request_id,
                    status: BulkStatus::Success,
                    payload: vec![43; 64],
                },
            },
        ),
        (
            IpcRole::Core,
            IpcRole::Net,
            IpcMessage::SendBulk {
                connection_id: [41; 16],
                request: bulk_request,
            },
        ),
        (
            IpcRole::Net,
            IpcRole::Core,
            IpcMessage::RequestFailed {
                connection_id: [44; 16],
                request_id: [45; 16],
                protocol: NetworkProtocol::Bulk,
                code: NetworkErrorCode::TimedOut,
            },
        ),
        (
            IpcRole::Net,
            IpcRole::Core,
            IpcMessage::NetworkError {
                code: NetworkErrorCode::Capacity,
            },
        ),
    ];

    for (sender, receiver, message) in messages {
        let bytes = encode_frame(sender, receiver, 1, &message).unwrap();
        assert_eq!(
            decode_frame(&bytes, sender, receiver, 1).unwrap().message,
            message
        );
    }
}

#[test]
fn net_driver_ipc_rejects_wrong_roles_and_non_control_payloads() {
    let request = IpcMessage::SendControl {
        connection_id: [51; 16],
        request_id: [52; 16],
        request: asl_types::protocol::WireFrame::IdentityProofRequest(proof_request()),
    };
    assert!(encode_frame(IpcRole::Core, IpcRole::Net, 1, &request).is_err());

    let reply = IpcMessage::ReplyBulk {
        connection_id: [53; 16],
        response_id: [54; 16],
        response: BulkResponse {
            request_id: Id128([55; 16]),
            status: BulkStatus::Success,
            payload: vec![56; MAX_IPC_BULK_PAYLOAD_BYTES + 1],
        },
    };
    assert!(encode_frame(IpcRole::Core, IpcRole::Net, 1, &reply).is_err());

    let peer_event = IpcMessage::PeerDisconnected {
        connection_id: [57; 16],
    };
    assert!(encode_frame(IpcRole::Core, IpcRole::Net, 1, &peer_event).is_err());

    let close = IpcMessage::CloseConnection {
        connection_id: [58; 16],
    };
    assert!(encode_frame(IpcRole::Net, IpcRole::Core, 1, &close).is_err());
}
