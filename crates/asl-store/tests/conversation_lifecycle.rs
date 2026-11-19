use std::path::Path;

use asl_store::{
    conversation::{ConversationTaskSpec, MessageInsert, OutboxFailure, TaskDirection},
    open_store,
};
use asl_types::{
    error::AslError,
    ids::{AgentId, Id128, PeerId},
    protocol::{Answer, AnswerStatus, Intent, Query, ResultShape, ResultStatus, WireFrame},
    task::TaskId,
};
use libp2p_identity::Keypair;
use rusqlite::Connection;

fn agent_text(agent: AgentId) -> String {
    bs58::encode(agent.as_bytes()).into_string()
}

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
        expires_at_ms: now_ms + 600_000,
        status: AnswerStatus::NoMatch,
        claims: vec![],
        evidence_ids: vec![],
        result_status: ResultStatus::Complete,
    })
}

fn seed_peer(path: &Path, agent: AgentId, peer: &PeerId) {
    let db = Connection::open(path).unwrap();
    db.pragma_update(None, "foreign_keys", "ON").unwrap();
    let agent_text = agent_text(agent);
    let peer_text = bs58::encode(peer.as_bytes()).into_string();
    db.execute("INSERT INTO agents(agent_id) VALUES (?1)", [&agent_text])
        .unwrap();
    db.execute(
        "INSERT INTO device_identities(
            peer_id,agent_id,public_key_hex,certificate_cbor,certificate_serial,
            certificate_expires_ms,created_at_ms
         ) VALUES (?1,?2,?3,X'',1,?4,0)",
        rusqlite::params![peer_text, agent_text, "00".repeat(32), 10_000_000_i64],
    )
    .unwrap();
    db.execute(
        "INSERT INTO peers(peer_id,agent_id) VALUES (?1,?2)",
        rusqlite::params![peer_text, agent_text],
    )
    .unwrap();
}

#[test]
fn sqlite_conversation_survives_reopen_and_bounds_outbox() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("asl.sqlite3");
    let agent = AgentId([1; 32]);
    let remote = peer(7);
    let now = 1_000_i64;
    let root = TaskId(Id128([9; 16]));
    let initial = query(1, 9, now as u64);

    let mut store = open_store(&path).unwrap();
    seed_peer(&path, agent, &remote);
    store
        .create_conversation_task(ConversationTaskSpec {
            task_id: root.clone(),
            agent_id: agent,
            peer_id: &remote,
            direction: TaskDirection::Outgoing,
            query: Some(&initial),
            created_at_ms: now,
            expires_at_ms: now + 600_000,
        })
        .unwrap();
    assert_eq!(
        store
            .enqueue_outgoing_message(
                &root,
                &remote,
                &WireFrame::Query(initial.clone()),
                now,
                now + 10_000,
            )
            .unwrap(),
        MessageInsert::Inserted
    );
    assert_eq!(
        store
            .enqueue_outgoing_message(
                &root,
                &remote,
                &WireFrame::Query(initial),
                now,
                now + 10_000,
            )
            .unwrap(),
        MessageInsert::Duplicate
    );
    assert_eq!(store.due_outbox(now, 10).unwrap().len(), 1);
    assert!(matches!(
        store.mark_outbox_failed(Id128([1; 16]), now).unwrap(),
        OutboxFailure::Rescheduled { attempts: 1, .. }
    ));
    assert!(store.due_outbox(now, 10).unwrap().is_empty());

    for message in 2..=6 {
        assert_eq!(
            store
                .enqueue_outgoing_message(
                    &root,
                    &remote,
                    &answer(message, 9, now as u64),
                    now + 1,
                    now + 600_000,
                )
                .unwrap(),
            MessageInsert::Inserted
        );
    }
    assert!(matches!(
        store
            .enqueue_outgoing_message(
                &root,
                &remote,
                &answer(7, 9, now as u64),
                now + 1,
                now + 600_000,
            )
            .unwrap_err(),
        AslError::QuotaExceeded
    ));

    assert!(
        store
            .claim_processed_request(agent, Id128([4; 16]), now, now + 600_000)
            .unwrap()
    );
    assert!(
        !store
            .claim_processed_request(agent, Id128([4; 16]), now + 1, now + 600_000)
            .unwrap()
    );
    drop(store);

    let mut reopened = open_store(&path).unwrap();
    assert!(
        !reopened
            .claim_processed_request(agent, Id128([4; 16]), now + 2, now + 600_000)
            .unwrap()
    );
    assert_eq!(reopened.due_outbox(now + 2, 64).unwrap().len(), 5);
}

#[test]
fn sqlite_does_not_create_tasks_for_answers_or_store_fetch_grants_in_outbox() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("asl.sqlite3");
    let agent = AgentId([2; 32]);
    let remote = peer(8);
    let mut store = open_store(&path).unwrap();
    seed_peer(&path, agent, &remote);

    let unknown = TaskId(Id128([3; 16]));
    assert!(matches!(
        store
            .store_incoming_message(&unknown, &remote, &answer(1, 3, 1_000), 1_000, 601_000,)
            .unwrap_err(),
        AslError::NotFound
    ));

    let grant = WireFrame::FetchGrant(asl_types::protocol::FetchGrant {
        message_id: [2; 16].into(),
        content_id: [3; 32].into(),
        lease_id: [4; 32].into(),
        expires_at_ms: 60_000,
        file_size: 32,
    });
    assert!(matches!(
        store
            .enqueue_outgoing_message(&unknown, &remote, &grant, 1_000, 60_000,)
            .unwrap_err(),
        AslError::InvalidMessage
    ));
}
