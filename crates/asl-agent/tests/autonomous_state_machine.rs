use std::collections::HashSet;

use asl_agent::runner::{InboundMode, InboundRunner, InboundWork, Ingress, ResourceMatch};
use asl_policy::{
    AccessOperation, AccessRequest, Audience, AuthenticatedDevice, GrantPolicy, ModelPolicy,
    PolicyEngine, PolicyService, PolicySnapshot, Principal, ResourceOrigin, ResourcePolicy,
    ScopedPolicy,
};
use asl_types::{
    error::ErrorCode,
    ids::{AgentId, Hash32, Id128, PeerId},
    protocol::{
        Ack, AnswerStatus, ConceptRef, Intent, MediaKind, Query, ResultShape, ResultStatus,
        WireFrame,
    },
    task::{GrantId, ResourceKey},
};

const NOW: u64 = 10_000;
const AGENT: AgentId = AgentId([1; 32]);
const CONTENT: Hash32 = Hash32([2; 32]);
const GRANT: GrantId = GrantId(Id128([3; 16]));
const RESOURCE: ResourceKey = ResourceKey(Id128([4; 16]));

fn peer(seed: u8) -> PeerId {
    let key = libp2p_identity::Keypair::ed25519_from_bytes([seed; 32]).unwrap();
    PeerId::from_bytes(key.public().to_peer_id().to_bytes()).unwrap()
}

fn query(message: u8, root: u8, shape: ResultShape) -> WireFrame {
    WireFrame::Query(Query {
        message_id: [message; 16].into(),
        root_task_id: [root; 16].into(),
        created_at_ms: NOW,
        expires_at_ms: NOW + 10_000,
        intent_id: Intent::FindEvidence,
        topics: vec![ConceptRef::RUST],
        constraints: vec![],
        result_shape: shape,
        budget: 6,
    })
}

fn work(ingress: Ingress) -> InboundWork {
    let Ingress::Work(work) = ingress else {
        panic!("expected local work, got {ingress:?}");
    };
    *work
}

fn answering_runner() -> InboundRunner {
    let mut runner = InboundRunner::default();
    runner.set_mode(InboundMode::Answer);
    runner
}

fn policy(peers: &[PeerId]) -> PolicyEngine {
    let mut snapshot = PolicySnapshot::default();
    for peer in peers {
        snapshot.devices.insert(
            peer.clone(),
            AuthenticatedDevice {
                agent_id: AGENT,
                active: true,
                chain_valid_until_ms: NOW + 60_000,
                certificate_valid_until_ms: NOW + 60_000,
            },
        );
    }
    snapshot.grants.insert(
        GRANT,
        GrantPolicy {
            epoch: 1,
            active: true,
            audience: Audience::Peers(HashSet::from([AGENT])),
            model_policy: ModelPolicy::Never,
            extensions: HashSet::from([".md".into()]),
            max_snapshot_bytes: 64,
            allowed_operations: HashSet::from([AccessOperation::ReadMetadata]),
            allow_derived_disclosure: false,
        },
    );
    snapshot.resources.insert(
        RESOURCE,
        ResourcePolicy {
            content_id: CONTENT,
            grant_id: GRANT,
            grant_epoch: 1,
            active: true,
            snapshot_ready: true,
            file_size: 64,
            extension: ".md".into(),
            retention_until_ms: None,
            origin: ResourceOrigin::Local,
        },
    );
    PolicyEngine::new(snapshot, 5_000).unwrap()
}

fn hit(policy: &ScopedPolicy<'_>) -> ResourceMatch {
    let permit = policy
        .authorize(
            &AccessRequest {
                grant_id: GRANT,
                resource_key: RESOURCE,
                principal: Principal::Agent(AGENT),
                operation: AccessOperation::ReadMetadata,
            },
            NOW,
        )
        .unwrap();
    ResourceMatch::new(permit, vec![ConceptRef::RUST], 64, MediaKind::Document).unwrap()
}

#[test]
fn browse_only_never_schedules_work_and_ack_does_not_create_a_task() {
    let peer = peer(1);
    let mut runner = InboundRunner::default();
    assert!(matches!(
        runner
            .receive(AGENT, peer.clone(), query(1, 2, ResultShape::Claims), NOW)
            .unwrap(),
        Ingress::Ignored
    ));
    runner.set_mode(InboundMode::BrowseOnly);
    assert!(matches!(
        runner
            .receive(AGENT, peer.clone(), query(1, 2, ResultShape::Claims), NOW)
            .unwrap(),
        Ingress::Observed
    ));
    runner.set_mode(InboundMode::Answer);
    let ack = WireFrame::Ack(Ack {
        message_id: [3; 16].into(),
        received_id: [1; 16].into(),
    });
    assert!(matches!(
        runner.receive(AGENT, peer, ack, NOW).unwrap(),
        Ingress::Observed
    ));
}

#[test]
fn deterministic_fallback_preserves_the_request_shape_without_model_access() {
    let peer = peer(2);
    let engine = policy(std::slice::from_ref(&peer));
    let policy = engine.for_peer(peer.clone());
    let mut runner = answering_runner();
    for (message, shape) in [(1, ResultShape::Claims), (2, ResultShape::Resources)] {
        let task = work(
            runner
                .receive(AGENT, peer.clone(), query(message, 10, shape), NOW)
                .unwrap(),
        );
        let reply = runner
            .finish_without_model(task, Some(hit(&policy)), &policy, NOW)
            .unwrap()
            .unwrap();
        assert_eq!(reply.model_status, ErrorCode::ModelUnavailable);
        match (shape, runner.take_reply(reply, &policy, NOW).unwrap()) {
            (ResultShape::Claims, WireFrame::Answer(answer)) => {
                assert_eq!(answer.status, AnswerStatus::Answered);
                assert_eq!(answer.result_status, ResultStatus::Unverified);
                assert_eq!(answer.claims[0].evidence, Some(CONTENT));
            }
            (ResultShape::Resources, WireFrame::Offer(offer)) => {
                assert_eq!(offer.content_id, CONTENT);
                assert_eq!(offer.file_size, 64);
            }
            (_, actual) => panic!("wrong reply: {actual:?}"),
        }
    }
}

#[test]
fn duplicate_queries_and_a_fourth_round_do_not_get_more_work() {
    let peer = peer(3);
    let engine = policy(std::slice::from_ref(&peer));
    let policy = engine.for_peer(peer.clone());
    let mut runner = answering_runner();
    for message in 1..=3 {
        let frame = query(message, 10, ResultShape::Claims);
        let task = work(
            runner
                .receive(AGENT, peer.clone(), frame.clone(), NOW)
                .unwrap(),
        );
        assert!(
            runner
                .finish_without_model(task, None, &policy, NOW)
                .unwrap()
                .is_some()
        );
        assert!(matches!(
            runner.receive(AGENT, peer.clone(), frame, NOW).unwrap(),
            Ingress::Duplicate
        ));
    }
    assert!(matches!(
        runner
            .receive(AGENT, peer, query(4, 10, ResultShape::Claims), NOW)
            .unwrap(),
        Ingress::Busy
    ));
}

#[test]
fn independent_devices_of_one_agent_share_one_pending_slot() {
    let first = peer(4);
    let second = peer(5);
    let mut runner = answering_runner();
    let task = work(
        runner
            .receive(AGENT, first.clone(), query(1, 10, ResultShape::Claims), NOW)
            .unwrap(),
    );
    assert!(matches!(
        runner
            .receive(
                AGENT,
                second.clone(),
                query(2, 11, ResultShape::Claims),
                NOW
            )
            .unwrap(),
        Ingress::Busy
    ));
    runner.disconnect(&first);
    let engine = policy(&[first.clone(), second.clone()]);
    assert!(
        runner
            .finish_without_model(task, None, &engine.for_peer(first), NOW)
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        runner
            .receive(AGENT, second, query(3, 12, ResultShape::Claims), NOW)
            .unwrap(),
        Ingress::Work(_)
    ));
}

#[test]
fn another_devices_permit_cannot_back_a_reply_and_revocation_blocks_send() {
    let first = peer(6);
    let other = peer(7);
    let engine = policy(&[first.clone(), other.clone()]);
    let policy = engine.for_peer(first.clone());
    let mut runner = answering_runner();
    let task = work(
        runner
            .receive(AGENT, first.clone(), query(1, 10, ResultShape::Claims), NOW)
            .unwrap(),
    );
    let wrong = hit(&engine.for_peer(other));
    let reply = runner
        .finish_without_model(task, Some(wrong), &policy, NOW)
        .unwrap()
        .unwrap();
    let WireFrame::Answer(answer) = runner.take_reply(reply, &policy, NOW).unwrap() else {
        panic!("expected no-match answer");
    };
    assert_eq!(answer.status, AnswerStatus::NoMatch);
    assert!(answer.claims.is_empty());

    let task = work(
        runner
            .receive(AGENT, first, query(2, 10, ResultShape::Resources), NOW)
            .unwrap(),
    );
    let reply = runner
        .finish_without_model(task, Some(hit(&policy)), &policy, NOW)
        .unwrap()
        .unwrap();
    engine.revoke(GRANT, 1).unwrap();
    assert!(runner.take_reply(reply, &policy, NOW + 1).is_none());
}

#[test]
fn expired_tasks_and_prior_authorization_mode_do_not_emit_replies() {
    let peer = peer(8);
    let engine = policy(std::slice::from_ref(&peer));
    let policy = engine.for_peer(peer.clone());
    let mut runner = answering_runner();
    let old = work(
        runner
            .receive(AGENT, peer.clone(), query(1, 10, ResultShape::Claims), NOW)
            .unwrap(),
    );
    let reply = runner
        .finish_without_model(old, None, &policy, NOW)
        .unwrap()
        .unwrap();
    runner.set_mode(InboundMode::BrowseOnly);
    runner.set_mode(InboundMode::Answer);
    assert!(runner.take_reply(reply, &policy, NOW + 1).is_none());

    let task = work(
        runner
            .receive(AGENT, peer, query(2, 10, ResultShape::Claims), NOW)
            .unwrap(),
    );
    assert!(
        runner
            .finish_without_model(task, None, &policy, NOW + 10_000)
            .unwrap()
            .is_none()
    );
}
