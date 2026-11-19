use asl_agent::{
    InboundQueryDecision, MAX_QUERY_PEERS, OutgoingTask, QueryAction, QueryRouter, QueryScope,
};
use asl_types::{
    ids::PeerId,
    protocol::{Intent, Query, ResultShape},
    task::TaskId,
};
use libp2p_identity::Keypair;

fn peer(seed: u8) -> PeerId {
    let key = Keypair::ed25519_from_bytes([seed; 32]).unwrap();
    PeerId::from_bytes(key.public().to_peer_id().to_bytes()).unwrap()
}

fn task(scope: QueryScope) -> OutgoingTask {
    OutgoingTask::new(
        1_000,
        Intent::FindEvidence,
        vec![asl_types::protocol::ConceptRef::RUST],
        Vec::new(),
        ResultShape::Claims,
        3,
        scope,
    )
}

#[test]
fn contacts_only_tasks_do_not_leak_concepts_to_dht() {
    let mut router = QueryRouter::with_contacts([peer(1), peer(2)]);
    let task_id = router.start_query(task(QueryScope::ContactsOnly)).unwrap();
    let actions = router.next_actions(&task_id, 1_001);

    let peers: Vec<_> = actions
        .iter()
        .filter_map(|action| match action {
            QueryAction::Contact { peer_id, .. } => Some(peer_id.clone()),
            QueryAction::DhtLookup { .. } => None,
        })
        .collect();
    assert_eq!(peers.len(), 2);
    for peer_id in peers {
        router.complete_peer(&task_id, &peer_id, 1_002).unwrap();
    }
    assert!(router.next_actions(&task_id, 1_003).is_empty());
}

#[test]
fn direct_query_candidates_are_bounded_even_when_dht_returns_more() {
    let mut router = QueryRouter::new();
    let task_id = router.start_query(task(QueryScope::Public)).unwrap();
    let QueryAction::DhtLookup { concept, .. } = router.next_actions(&task_id, 1_001)[0] else {
        panic!("public task must start with a DHT lookup without contacts");
    };
    router
        .record_dht_result(&task_id, concept, (1..=32).map(peer), 1_002)
        .unwrap();
    let direct = router.next_actions(&task_id, 1_003);
    assert_eq!(direct.len(), MAX_QUERY_PEERS);
}

#[test]
fn inbound_ring_replays_are_local_only_and_not_forwarded() {
    let mut a = QueryRouter::new();
    let mut b = QueryRouter::new();
    let mut c = QueryRouter::new();
    let query = Query {
        message_id: [9; 16].into(),
        root_task_id: [8; 16].into(),
        created_at_ms: 1_000,
        expires_at_ms: 2_000,
        intent_id: Intent::FindEvidence,
        topics: vec![asl_types::protocol::ConceptRef::RUST],
        constraints: Vec::new(),
        result_shape: ResultShape::Claims,
        budget: 3,
    };

    assert!(matches!(
        a.accept_incoming(peer(1), query.clone(), 1_001),
        Ok(InboundQueryDecision::ExecuteLocally { .. })
    ));
    assert!(matches!(
        b.accept_incoming(peer(2), query.clone(), 1_001),
        Ok(InboundQueryDecision::ExecuteLocally { .. })
    ));
    assert!(matches!(
        c.accept_incoming(peer(3), query.clone(), 1_001),
        Ok(InboundQueryDecision::ExecuteLocally { .. })
    ));
    assert_eq!(
        a.accept_incoming(peer(1), query, 1_002).unwrap(),
        InboundQueryDecision::Duplicate
    );
    let task_id = TaskId([8; 16].into());
    assert!(a.next_actions(&task_id, 1_003).is_empty());
    assert!(b.next_actions(&task_id, 1_003).is_empty());
    assert!(c.next_actions(&task_id, 1_003).is_empty());
}
