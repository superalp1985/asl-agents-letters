use asl_agent::{CONVERSATION_WINDOW_MS, Conversation, InboundDecision, MAX_SEMANTIC_MESSAGES};
use asl_types::{
    ids::{Hash32, PeerId},
    protocol::{
        Ack, Answer, AnswerStatus, FetchGrant, Intent, Query, ResultShape, ResultStatus, WireFrame,
    },
};
use libp2p_identity::Keypair;

fn peer(seed: u8) -> PeerId {
    let key = Keypair::ed25519_from_bytes([seed; 32]).unwrap();
    PeerId::from_bytes(key.public().to_peer_id().to_bytes()).unwrap()
}

fn query(message: u8, root: u8, now_ms: u64) -> Query {
    Query {
        message_id: [message; 16].into(),
        root_task_id: [root; 16].into(),
        created_at_ms: now_ms,
        expires_at_ms: now_ms + 10_000,
        intent_id: Intent::FindEvidence,
        topics: vec![],
        constraints: vec![],
        result_shape: ResultShape::Claims,
        budget: 3,
    }
}

fn answer(message: u8, root: u8, now_ms: u64) -> WireFrame {
    WireFrame::Answer(Answer {
        message_id: [message; 16].into(),
        root_task_id: [root; 16].into(),
        created_at_ms: now_ms,
        expires_at_ms: now_ms + CONVERSATION_WINDOW_MS,
        status: AnswerStatus::NoMatch,
        claims: vec![],
        evidence_ids: vec![],
        result_status: ResultStatus::Complete,
    })
}

#[test]
fn conversation_enforces_semantic_budget_and_retry_window() {
    let now = 1_000;
    let remote = peer(1);
    let mut conversation = Conversation::new();
    let task_id = conversation
        .start_query(remote, query(1, 9, now), now)
        .unwrap();
    assert_eq!(conversation.outbox_count(), 1);
    assert_eq!(conversation.due_deliveries(now).len(), 1);

    for (failure_at, expected_attempts) in [(1_000, 1), (2_000, 2), (12_000, 3)] {
        let message_id = [1; 16].into();
        let retry = conversation
            .mark_failed(message_id, failure_at)
            .unwrap()
            .unwrap();
        assert_eq!(retry.attempts, expected_attempts);
    }
    assert!(
        conversation
            .mark_failed([1; 16].into(), 72_000)
            .unwrap()
            .is_none()
    );
    assert_eq!(conversation.outbox_count(), 0);

    for message in 2..=6 {
        conversation
            .queue_outbound(&task_id, answer(message, 9, now), now + 1)
            .unwrap();
    }
    assert_eq!(conversation.outbox_count(), 5);
    assert!(matches!(
        conversation.queue_outbound(&task_id, answer(7, 9, now), now + 1),
        Err(asl_types::error::AslError::QuotaExceeded)
    ));
    assert_eq!(MAX_SEMANTIC_MESSAGES, 6);
}

#[test]
fn inbound_query_is_created_once_and_non_conversation_frames_are_ignored() {
    let now = 1_000;
    let remote = peer(2);
    let mut conversation = Conversation::new();
    let incoming = WireFrame::Query(query(4, 11, now));

    let first = conversation
        .accept_incoming(remote.clone(), incoming.clone(), now + 1)
        .unwrap();
    assert!(matches!(first, InboundDecision::Deliver { .. }));
    assert_eq!(conversation.task_count(), 1);
    assert_eq!(
        conversation
            .accept_incoming(remote.clone(), incoming, now + 2)
            .unwrap(),
        InboundDecision::Duplicate
    );

    assert_eq!(
        conversation
            .accept_incoming(
                remote,
                WireFrame::FetchGrant(FetchGrant {
                    message_id: [5; 16].into(),
                    content_id: Hash32([6; 32]),
                    lease_id: Hash32([7; 32]),
                    expires_at_ms: now + 60_000,
                    file_size: 10,
                }),
                now + 3,
            )
            .unwrap(),
        InboundDecision::Ignored
    );
    assert_eq!(conversation.outbox_count(), 0);
}

#[test]
fn answers_do_not_create_unknown_tasks_and_ack_does_not_consume_semantic_budget() {
    let now = 1_000;
    let remote = peer(3);
    let mut conversation = Conversation::new();
    assert!(matches!(
        conversation
            .accept_incoming(remote.clone(), answer(8, 99, now), now + 1)
            .unwrap_err(),
        asl_types::error::AslError::NotFound
    ));

    let task_id = conversation
        .start_query(remote.clone(), query(9, 12, now), now)
        .unwrap();
    let answer_frame = answer(10, 12, now);
    conversation
        .queue_outbound(&task_id, answer_frame.clone(), now + 1)
        .unwrap();
    let ack = WireFrame::Ack(Ack {
        message_id: [11; 16].into(),
        received_id: [10; 16].into(),
    });
    conversation
        .queue_outbound(&task_id, ack.clone(), now + 1)
        .unwrap();
    assert_eq!(conversation.outbox_count(), 3);
    conversation.mark_delivered([10; 16].into()).unwrap();
    let inbound_ack = WireFrame::Ack(Ack {
        message_id: [12; 16].into(),
        received_id: [10; 16].into(),
    });
    assert!(matches!(
        conversation
            .accept_incoming(remote, inbound_ack, now + 2)
            .unwrap(),
        InboundDecision::Deliver { .. }
    ));
}
