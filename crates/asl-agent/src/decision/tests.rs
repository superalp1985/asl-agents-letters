use std::{
    collections::HashSet,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use asl_policy::{
    AccessRequest, Audience, AuthenticatedDevice, GrantPolicy, ModelPolicy, PolicyEngine,
    PolicySnapshot, ProviderPolicy, ResourceOrigin, ResourcePolicy,
};
use asl_types::{
    ids::{AgentId, Hash32, Id128, PeerId},
    protocol::{Answer, AnswerStatus, Intent, ResultShape, ResultStatus, decode_control},
    task::GrantId,
};
use serde_json::{Value, json};

use super::*;
use crate::gateway::{AuthorizedPrompt, ModelText};

const NOW: u64 = 10_000;
const CONTENT: Hash32 = Hash32([3; 32]);
const ANSWER: &str = r#"{"v":1,"action":"answer","claims":[{"subject":{"kind":"content"},"predicate":[1,203],"object":{"kind":"concepts","value":[[1,101]]},"evidence":1}]}"#;
const MORE: &str = r#"{"v":1,"action":"request_more","terms":[[1,101]]}"#;

struct Fixture {
    engine: PolicyEngine,
    peer: PeerId,
    grant: GrantId,
    resource: ResourceKey,
    provider: ProviderId,
    local_task: TaskId,
}

impl Fixture {
    fn new() -> Self {
        let grant = GrantId(Id128([1; 16]));
        let resource = ResourceKey(Id128([2; 16]));
        let local_task = TaskId(Id128([4; 16]));
        let provider = ProviderId("test-model".into());
        let peer = PeerId::from_bytes(
            libp2p_identity::Keypair::ed25519_from_bytes([7; 32])
                .unwrap()
                .public()
                .to_peer_id()
                .to_bytes(),
        )
        .unwrap();
        let mut snapshot = PolicySnapshot::default();
        snapshot.grants.insert(
            grant.clone(),
            GrantPolicy {
                epoch: 1,
                active: true,
                audience: Audience::Public,
                model_policy: ModelPolicy::LocalOnly(HashSet::from([provider.clone()])),
                extensions: HashSet::from([".md".into()]),
                max_snapshot_bytes: 1024,
                allowed_operations: HashSet::from([
                    AccessOperation::ReadChunk,
                    AccessOperation::ModelInput,
                ]),
                allow_derived_disclosure: false,
            },
        );
        snapshot.resources.insert(
            resource.clone(),
            ResourcePolicy {
                content_id: CONTENT,
                grant_id: grant.clone(),
                grant_epoch: 1,
                active: true,
                snapshot_ready: true,
                file_size: 16,
                extension: ".md".into(),
                retention_until_ms: None,
                origin: ResourceOrigin::Local,
            },
        );
        snapshot.providers.insert(
            provider.clone(),
            ProviderPolicy {
                authorized: true,
                local: true,
            },
        );
        snapshot.devices.insert(
            peer.clone(),
            AuthenticatedDevice {
                agent_id: AgentId([7; 32]),
                active: true,
                chain_valid_until_ms: NOW + 20_000,
                certificate_valid_until_ms: NOW + 20_000,
            },
        );
        snapshot.local_tasks.insert(local_task.clone());
        Self {
            engine: PolicyEngine::new(snapshot, 5_000).unwrap(),
            peer,
            grant,
            resource,
            provider,
            local_task,
        }
    }

    fn context(&self, direction: Direction, snippet: &str) -> DecisionContext {
        let authorize = |policy: &dyn PolicyService, principal, operation| {
            policy
                .authorize(
                    &AccessRequest {
                        grant_id: self.grant.clone(),
                        resource_key: self.resource.clone(),
                        principal,
                        operation,
                    },
                    NOW,
                )
                .unwrap()
        };
        let read = match direction {
            Direction::Incoming => authorize(
                &self.engine.for_peer(self.peer.clone()),
                Principal::Agent(AgentId([7; 32])),
                AccessOperation::ReadChunk,
            ),
            Direction::Outgoing => authorize(
                &self.engine,
                Principal::LocalTask(self.local_task.clone()),
                AccessOperation::ReadChunk,
            ),
        };
        let model = authorize(
            &self.engine,
            Principal::ModelProvider(self.provider.clone()),
            AccessOperation::ModelInput,
        );
        DecisionContext::new(
            Query {
                message_id: Id128([5; 16]),
                root_task_id: self.local_task.0,
                created_at_ms: NOW,
                expires_at_ms: NOW + 10_000,
                intent_id: Intent::FindEvidence,
                topics: vec![ConceptRef::RUST],
                constraints: vec![],
                result_shape: ResultShape::Claims,
                budget: 6,
            },
            direction,
            vec![CandidateEvidence::new(snippet.into(), read, model).unwrap()],
        )
        .unwrap()
    }

    fn validate(
        &self,
        context: &DecisionContext,
        text: &str,
        now: u64,
    ) -> Result<ValidatedDecision, ErrorCode> {
        let peer = self.engine.for_peer(self.peer.clone());
        let read_policy: &(dyn PolicyService + Sync) = match context.direction {
            Direction::Incoming => &peer,
            Direction::Outgoing => &self.engine,
        };
        validate_decision(
            text,
            context,
            &self.provider,
            read_policy,
            &self.engine,
            now,
        )
    }
}

#[test]
fn answer_resolves_only_bound_evidence_into_the_existing_wire_type() {
    let fixture = Fixture::new();
    let context = fixture.context(Direction::Incoming, "A Rust reference");
    let ValidatedDecision::Answer(claims) = fixture.validate(&context, ANSWER, NOW).unwrap() else {
        panic!("expected a typed answer");
    };
    assert_eq!(claims[0].source(), &fixture.resource);
    assert_eq!(claims[0].claim().subject, TypedValue::Hash(CONTENT));
    assert_eq!(claims[0].claim().evidence, Some(CONTENT));
    assert_eq!(
        claims[0].claim().object,
        TypedValue::Concepts(vec![ConceptRef::RUST])
    );

    let frame = WireFrame::Answer(Answer {
        message_id: Id128([11; 16]),
        root_task_id: context.query.root_task_id,
        created_at_ms: NOW,
        expires_at_ms: NOW + 10_000,
        status: AnswerStatus::Answered,
        claims: vec![claims[0].claim().clone()],
        evidence_ids: vec![],
        result_status: ResultStatus::Unverified,
    });
    let encoded = encode_control(&frame).unwrap();
    assert_eq!(decode_control(&encoded).unwrap(), frame);
    assert!(!encoded.windows(4).any(|bytes| bytes == b"Rust"));
}

#[test]
fn one_bad_claim_invalidates_the_entire_decision() {
    let fixture = Fixture::new();
    let context = fixture.context(Direction::Outgoing, "evidence");
    let claim = serde_json::from_str::<Value>(ANSWER).unwrap()["claims"][0].clone();
    for (field, value) in [
        ("evidence", json!(2)),
        ("subject", json!({"kind":"content","path":"local.txt"})),
        ("subject", json!({"kind":"constraint","index":1})),
        (
            "object",
            json!({"kind":"concepts","value":[[1,101],[1,101]]}),
        ),
        ("object", json!({"kind":"concepts","value":[[1,999]]})),
        ("object", json!({"kind":"integer","value":32})),
        (
            "object",
            json!({"kind":"concepts","value":vec![[1,101]; 65]}),
        ),
        ("object", json!({"kind":"text","value":"free text"})),
        ("predicate", json!([1, 209])),
    ] {
        let mut bad = claim.clone();
        bad[field] = value;
        let response = json!({"v":1,"action":"answer","claims":[claim,bad]}).to_string();
        assert_eq!(
            fixture.validate(&context, &response, NOW),
            Err(ErrorCode::ModelInvalid),
            "{field}"
        );
    }
    let response = json!({"v":1,"action":"answer","claims":vec![claim; 33]}).to_string();
    assert_eq!(
        fixture.validate(&context, &response, NOW),
        Err(ErrorCode::ModelInvalid)
    );
}

#[test]
fn rejects_duplicate_keys_missing_fields_and_prose() {
    let fixture = Fixture::new();
    let context = fixture.context(Direction::Outgoing, "evidence");
    for response in [
        r#"{"v":1,"v":1,"action":"decline","reason":"no_match"}"#,
        r#"{"v":1,"action":"decline","action":"decline","reason":"no_match"}"#,
        r#"{"v":1,"action":"decline","reason":"no_match","text":"prose"}"#,
        r#"{"v":1,"action":"decline","reason":"supported"}"#,
        r#"{"v":1,"action":"decline"}"#,
        r#"{"v":0,"action":"decline","reason":"no_match"}"#,
        r#"{"v":1,"action":"request_more","terms":[[1,200]]}"#,
        r#"{"v":1,"action":"request_more","terms":[[1,101],[1,101]]}"#,
        r#"{"v":1,"action":"answer","claims":[{"subject":{"kind":"content","kind":"content"},"predicate":[1,200],"object":{"kind":"null"},"evidence":1}]}"#,
        r#"{"v":1,"action":"answer","claims":[{"subject":{"kind":"content"},"predicate":[1,200],"object":{"kind":"null"},"evidence":1,"evidence":1}]}"#,
        "```json\n{\"v\":1,\"action\":\"decline\",\"reason\":\"no_match\"}\n```",
    ] {
        assert_eq!(
            fixture.validate(&context, response, NOW),
            Err(ErrorCode::ModelInvalid),
            "{response}"
        );
    }
}

#[test]
fn request_more_never_propagates_an_incoming_query() {
    let fixture = Fixture::new();
    let incoming = fixture.context(Direction::Incoming, "evidence");
    let outgoing = fixture.context(Direction::Outgoing, "evidence");
    assert_eq!(
        fixture.validate(&incoming, MORE, NOW),
        Ok(ValidatedDecision::Decline(
            DeclineReason::InsufficientEvidence
        ))
    );
    assert_eq!(
        fixture.validate(&outgoing, MORE, NOW),
        Ok(ValidatedDecision::RequestMore(vec![ConceptRef::RUST]))
    );
    assert_eq!(
        fixture.validate(
            &outgoing,
            r#"{"v":1,"action":"decline","reason":"no_match"}"#,
            NOW
        ),
        Ok(ValidatedDecision::Decline(DeclineReason::NoMatch))
    );
}

#[test]
fn current_audience_and_model_permits_are_required() {
    let fixture = Fixture::new();
    let context = fixture.context(Direction::Incoming, "evidence");
    assert_eq!(
        validate_decision(
            ANSWER,
            &context,
            &fixture.provider,
            &fixture.engine,
            &fixture.engine,
            NOW
        ),
        Err(ErrorCode::PolicyDenied),
    );
    assert_eq!(
        fixture.validate(&context, ANSWER, NOW + 5_000),
        Err(ErrorCode::PolicyDenied)
    );
    assert_eq!(
        fixture.validate(&context, ANSWER, NOW + 10_000),
        Err(ErrorCode::Timeout)
    );
    fixture.engine.revoke(fixture.grant.clone(), 1).unwrap();
    assert_eq!(
        fixture.validate(&context, ANSWER, NOW),
        Err(ErrorCode::PolicyDenied)
    );
}

struct ScriptedGateway<'a> {
    replies: [&'static str; 2],
    prompts: Mutex<Vec<Value>>,
    after_reply: &'a (dyn Fn() + Sync),
}

impl ModelGateway for ScriptedGateway<'_> {
    async fn complete(
        &self,
        _: &ProviderId,
        prompt: AuthorizedPrompt,
        _: &(dyn PolicyService + Sync),
        _: u64,
    ) -> Result<ModelText, ModelGatewayError> {
        let mut prompts = self.prompts.lock().unwrap();
        let response = self.replies[prompts.len()];
        prompts.push(serde_json::from_str(prompt.content()).unwrap());
        (self.after_reply)();
        Ok(ModelText::new(response.into()))
    }
}

#[tokio::test]
async fn invalid_response_is_repaired_once_without_replaying_provider_text() {
    let fixture = Fixture::new();
    let context = fixture.context(Direction::Outgoing, "A quoted \"line\"\nsecond line");
    for (second, valid) in [(MORE, true), ("another invalid result", false)] {
        let gateway = ScriptedGateway {
            replies: ["UNTRUSTED_PROVIDER_REPLY", second],
            prompts: Mutex::new(Vec::new()),
            after_reply: &|| {},
        };
        let result = decide(
            &gateway,
            &context,
            &fixture.provider,
            &fixture.engine,
            &fixture.engine,
            || NOW,
        )
        .await;
        if valid {
            assert_eq!(
                result,
                Ok(ValidatedDecision::RequestMore(vec![ConceptRef::RUST]))
            );
        } else {
            assert_eq!(result, Err(ErrorCode::ModelInvalid));
        }
        let prompts = gateway.prompts.into_inner().unwrap();
        assert_eq!(prompts.len(), 2);
        assert_eq!(
            prompts[0]["candidates"][0]["excerpt"],
            "A quoted \"line\"\nsecond line"
        );
        assert_eq!(prompts[0]["candidates"], prompts[1]["candidates"]);
        assert_eq!(prompts[0]["query"], prompts[1]["query"]);
        assert_eq!(prompts[0]["repair"], 0);
        assert_eq!(prompts[1]["repair"], 1);
        assert!(!prompts[1].to_string().contains("UNTRUSTED_PROVIDER_REPLY"));
    }
}

#[tokio::test]
async fn revoked_or_expired_context_is_not_repaired_or_accepted() {
    for revoke in [true, false] {
        let fixture = Fixture::new();
        let context = fixture.context(Direction::Outgoing, "evidence");
        let time = AtomicU64::new(NOW);
        let after_reply = || {
            if revoke {
                fixture.engine.revoke(fixture.grant.clone(), 1).unwrap();
            } else {
                time.store(NOW + 10_000, Ordering::Relaxed);
            }
        };
        let gateway = ScriptedGateway {
            replies: [if revoke { "invalid" } else { ANSWER }, ANSWER],
            prompts: Mutex::new(Vec::new()),
            after_reply: &after_reply,
        };
        let result = decide(
            &gateway,
            &context,
            &fixture.provider,
            &fixture.engine,
            &fixture.engine,
            || time.load(Ordering::Relaxed),
        )
        .await;
        assert_eq!(
            result,
            Err(if revoke {
                ErrorCode::PolicyDenied
            } else {
                ErrorCode::Timeout
            })
        );
        assert_eq!(gateway.prompts.into_inner().unwrap().len(), 1);
    }
}
