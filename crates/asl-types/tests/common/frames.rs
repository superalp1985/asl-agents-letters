use std::str::FromStr;

use asl_types::{
    error::ErrorCode,
    ids::{AgentId, Hash32, Id128, PeerId, Signature65},
    protocol::{
        AccountProof, Ack, Answer, AnswerStatus, Claim, ConceptRef, Constraint, ConstraintOperator,
        DeviceCertificate, Feature, FetchGrant, FetchRequest, GroupEnvelope, GroupOperation, Hello,
        IdentityProof, IdentityProofRequest, Intent, MediaKind, Offer, PairingExchange,
        PairingInvite, Profile, ProtocolError, Query, ResultShape, ResultStatus, StorageProof,
        TypedValue, WireFrame,
    },
};

fn peer_id() -> PeerId {
    let peer =
        libp2p_identity::PeerId::from_str("12D3KooWRNw2pJC9748Fmq4WNV27HoSTcX3r37132FLkQMrbKAiC")
            .unwrap();
    PeerId::from_bytes(peer.to_bytes()).unwrap()
}

fn concept(id: u32) -> ConceptRef {
    ConceptRef {
        vocabulary_id: 1,
        concept_id: id,
    }
}

pub fn sample_frames() -> Vec<WireFrame> {
    let agent = AgentId([7; 32]);
    let peer = peer_id();
    let id = Id128([1; 16]);
    let hash = Hash32([2; 32]);
    let certificate = DeviceCertificate {
        agent_id: agent,
        peer_id: peer.clone(),
        serial: 1,
        issued_at_ms: 100,
        expires_at_ms: 200,
        signature: Signature65([3; 65]),
    };

    vec![
        WireFrame::Hello(Hello {
            message_id: id,
            agent_id: agent,
            peer_id: peer.clone(),
            device_certificate: certificate,
            major: 1,
            minor: 0,
            features: vec![Feature::Query, Feature::Blob],
        }),
        WireFrame::Query(Query {
            message_id: id,
            root_task_id: Id128([4; 16]),
            created_at_ms: 100,
            expires_at_ms: 200,
            intent_id: Intent::FindEvidence,
            topics: vec![concept(100), concept(101)],
            constraints: vec![
                Constraint {
                    predicate: concept(206),
                    operator: ConstraintOperator::NotEqual,
                    value: TypedValue::Integer(42),
                },
                Constraint {
                    predicate: concept(207),
                    operator: ConstraintOperator::Equal,
                    value: TypedValue::Hash(hash),
                },
                Constraint {
                    predicate: concept(208),
                    operator: ConstraintOperator::Equal,
                    value: TypedValue::Agent(agent),
                },
                Constraint {
                    predicate: concept(203),
                    operator: ConstraintOperator::Equal,
                    value: TypedValue::Concepts(vec![concept(100), concept(101)]),
                },
            ],
            result_shape: ResultShape::Claims,
            budget: 10,
        }),
        WireFrame::Answer(Answer {
            message_id: id,
            root_task_id: Id128([4; 16]),
            created_at_ms: 100,
            expires_at_ms: 200,
            status: AnswerStatus::Answered,
            claims: vec![Claim {
                subject: TypedValue::Agent(agent),
                predicate: concept(208),
                object: TypedValue::Hash(hash),
                evidence: Some(hash),
            }],
            evidence_ids: vec![Id128([5; 16])],
            result_status: ResultStatus::Partial,
        }),
        WireFrame::Offer(Offer {
            message_id: id,
            root_task_id: Id128([4; 16]),
            content_id: hash,
            file_size: 1_048_576,
            media_kind: MediaKind::Image,
            concepts: vec![concept(100), concept(101)],
            expires_at_ms: 200,
        }),
        WireFrame::FetchRequest(FetchRequest {
            message_id: id,
            root_task_id: Id128([4; 16]),
            content_id: hash,
        }),
        WireFrame::FetchGrant(FetchGrant {
            message_id: id,
            content_id: hash,
            lease_id: Hash32([6; 32]),
            expires_at_ms: 200,
            file_size: 1_048_576,
        }),
        WireFrame::Error(ProtocolError {
            message_id: id,
            code: ErrorCode::NotFound,
        }),
        WireFrame::Ack(Ack {
            message_id: id,
            received_id: Id128([8; 16]),
        }),
        WireFrame::Profile(Profile {
            agent_id: agent,
            sequence: 7,
            capabilities: vec![concept(1), concept(100)],
            avatar: Some(hash),
        }),
        WireFrame::IdentityProofRequest(IdentityProofRequest {
            request_id: id,
            agent_id: agent,
            checkpoint_hash: hash,
        }),
        WireFrame::IdentityProof(IdentityProof {
            request_id: id,
            agent_id: agent,
            finalized_height: 123,
            block_hash: hash,
            state_root: Hash32([9; 32]),
            account: AccountProof {
                nonce: 1,
                balance: [10; 32],
                storage_root: [11; 32],
                code_hash: [12; 32],
                nodes: vec![vec![1, 2, 3]],
            },
            storage_proofs: (0_u8..3)
                .map(|slot| StorageProof {
                    slot: [slot + 5; 32],
                    value: [slot + 8; 32],
                    nodes: vec![vec![4, 5, 6]],
                })
                .collect(),
            signed_directory: vec![13; 256],
        }),
        WireFrame::PairingInvite(PairingInvite {
            invite_id: id,
            inviter: agent,
            target: AgentId([12; 32]),
            expires_at_ms: 200,
            token: vec![13; 16],
            signature: Signature65([14; 65]),
        }),
        WireFrame::PairingExchange(PairingExchange {
            exchange_id: id,
            agent_id: agent,
            peer_id: peer,
            attempt: 1,
            payload: vec![15; 64],
            transcript_hash: hash,
        }),
        WireFrame::GroupEnvelope(GroupEnvelope {
            message_id: id,
            group_id: hash,
            epoch: 2,
            operation: GroupOperation::Application,
            ciphertext: vec![16; 128],
        }),
    ]
}
