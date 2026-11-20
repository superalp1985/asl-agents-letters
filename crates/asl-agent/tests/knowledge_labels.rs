#![cfg(windows)]

use std::{collections::HashSet, fs, path::Path};

use asl_agent::{
    decision::{
        CandidateEvidence, DecisionContext, Direction, ValidatedDecision, validate_decision,
    },
    knowledge::KnowledgeRepository,
};
use asl_policy::{
    AccessOperation, AccessRequest, Audience, GrantPolicy, ModelPolicy, PolicyEngine,
    PolicyService, PolicySnapshot, Principal, ProviderPolicy, ResourceOrigin, ResourcePolicy,
};
use asl_store::resources::SnapshotBroker;
use asl_types::{
    ids::{Hash32, Id128},
    protocol::{ConceptRef, Intent, Query, ResultShape},
    task::TaskId,
};
use rusqlite::Connection;

const NOW: u64 = 10_000;

#[test]
fn derived_visibility_is_the_intersection_of_every_source() {
    assert!(derive_case(Audience::Public));
    assert!(!derive_case(Audience::Contacts));
}

fn derive_case(second_audience: Audience) -> bool {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    fs::create_dir_all(home.join("state")).unwrap();
    fs::create_dir_all(home.join("derived")).unwrap();
    let mut broker = SnapshotBroker::open(&home).unwrap();
    let mut grants = Vec::new();
    let mut keys = Vec::new();
    for index in 0..2 {
        let source = temp.path().join(format!("source-{index}"));
        fs::create_dir(&source).unwrap();
        fs::write(source.join("facts.md"), format!("source {index}")).unwrap();
        let audience = if index == 0 {
            Audience::Public
        } else {
            second_audience.clone()
        };
        let grant = broker
            .authorize_directory_with_derivation(
                &source,
                &["md".into()],
                &audience,
                1024,
                audience == Audience::Public,
            )
            .unwrap();
        keys.push(broker.import_source(&grant, Path::new("facts.md")).unwrap());
        grants.push(grant);
    }
    let write_grant = broker
        .authorize_derived_directory(&home.join("derived"), 64 * 1024)
        .unwrap();

    let task_id = TaskId(Id128([4; 16]));
    let provider = asl_types::task::ProviderId("local-test".into());
    let mut snapshot = PolicySnapshot::default();
    snapshot.local_tasks.insert(task_id.clone());
    snapshot.providers.insert(
        provider.clone(),
        ProviderPolicy {
            authorized: true,
            local: true,
        },
    );
    let db = Connection::open(home.join("state/asl.sqlite3")).unwrap();
    for (index, (key, grant_id)) in keys.iter().zip(&grants).enumerate() {
        let (content, size): (String, i64) = db
            .query_row(
                "SELECT content_id,s.file_size FROM resources r
                 JOIN snapshots s USING(content_id) WHERE r.resource_key=?1",
                [hex::encode(key.0.0)],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let audience = if index == 0 {
            Audience::Public
        } else {
            second_audience.clone()
        };
        snapshot.grants.insert(
            grant_id.clone(),
            GrantPolicy {
                epoch: 1,
                active: true,
                audience,
                model_policy: ModelPolicy::LocalOnly(HashSet::from([provider.clone()])),
                extensions: HashSet::from([".md".into()]),
                max_snapshot_bytes: 1024,
                allowed_operations: HashSet::from([
                    AccessOperation::ReadChunk,
                    AccessOperation::ModelInput,
                    AccessOperation::WriteDerived,
                    AccessOperation::PublishRecord,
                ]),
                allow_derived_disclosure: index == 0 || second_audience == Audience::Public,
            },
        );
        snapshot.resources.insert(
            key.clone(),
            ResourcePolicy {
                content_id: Hash32(hex::decode(content).unwrap().try_into().unwrap()),
                grant_id: grant_id.clone(),
                grant_epoch: 1,
                active: true,
                snapshot_ready: true,
                file_size: u64::try_from(size).unwrap(),
                extension: ".md".into(),
                retention_until_ms: None,
                origin: ResourceOrigin::Local,
            },
        );
    }
    drop(db);
    let policy = PolicyEngine::new(snapshot, 5_000).unwrap();
    let mut candidates = Vec::new();
    for (key, grant_id) in keys.iter().zip(&grants) {
        let read = policy
            .authorize(
                &AccessRequest {
                    grant_id: grant_id.clone(),
                    resource_key: key.clone(),
                    principal: Principal::LocalTask(task_id.clone()),
                    operation: AccessOperation::ReadChunk,
                },
                NOW,
            )
            .unwrap();
        let model = policy
            .authorize(
                &AccessRequest {
                    grant_id: grant_id.clone(),
                    resource_key: key.clone(),
                    principal: Principal::ModelProvider(provider.clone()),
                    operation: AccessOperation::ModelInput,
                },
                NOW,
            )
            .unwrap();
        candidates.push(CandidateEvidence::new("source-backed facts".into(), read, model).unwrap());
    }
    let context = DecisionContext::new(
        Query {
            message_id: Id128([5; 16]),
            root_task_id: task_id.0,
            created_at_ms: NOW,
            expires_at_ms: NOW + 10_000,
            intent_id: Intent::FindEvidence,
            topics: vec![ConceptRef::RUST],
            constraints: vec![],
            result_shape: ResultShape::Claims,
            budget: 6,
        },
        Direction::Outgoing,
        candidates,
    )
    .unwrap();
    let response = r#"{"v":1,"action":"answer","claims":[
        {"subject":{"kind":"content"},"predicate":[1,203],"object":{"kind":"concepts","value":[[1,101]]},"evidence":1},
        {"subject":{"kind":"content"},"predicate":[1,203],"object":{"kind":"concepts","value":[[1,101]]},"evidence":2}
    ]}"#;
    let decision = validate_decision(response, &context, &provider, &policy, &policy, NOW).unwrap();
    assert!(matches!(decision, ValidatedDecision::Answer(_)));

    let result = KnowledgeRepository::save_answer(
        &mut broker,
        &decision,
        write_grant,
        &task_id,
        &policy,
        NOW,
    )
    .unwrap()
    .unwrap();
    let verify_db = Connection::open(home.join("state/asl.sqlite3")).unwrap();
    let persisted_label: String = verify_db
        .query_row(
            "SELECT label_json FROM resources WHERE resource_key=?1",
            [hex::encode(result.resource_key.0.0)],
            |row| row.get(0),
        )
        .unwrap();
    let label: serde_json::Value = serde_json::from_str(&persisted_label).unwrap();
    assert_eq!(
        label.get("kind").and_then(serde_json::Value::as_str),
        Some(if result.published {
            "public"
        } else {
            "private"
        })
    );
    assert_eq!(
        label
            .get("disclosure_allowed")
            .and_then(serde_json::Value::as_bool),
        Some(result.published)
    );
    let record = fs::read(
        home.join("derived")
            .join(format!("{}.json", hex::encode(result.resource_key.0.0))),
    )
    .unwrap();
    let record: serde_json::Value = serde_json::from_slice(&record).unwrap();
    assert_eq!(
        record
            .get("verification")
            .and_then(serde_json::Value::as_str),
        Some("derived_unverified")
    );
    broker.revoke_directory(&grants[0]).unwrap();
    let active: i64 = verify_db
        .query_row(
            "SELECT active FROM resources WHERE resource_key=?1",
            [hex::encode(result.resource_key.0.0)],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(active, 0);
    let indexed: i64 = verify_db
        .query_row(
            "SELECT count(*) FROM resource_fts WHERE resource_key=?1",
            [hex::encode(result.resource_key.0.0)],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(indexed, 0);
    result.published
}
