use asl_store::{open_store, semantic_context::SemanticContextCandidateInsert};
use asl_types::{
    ids::{AgentId, Hash32, Signature65},
    protocol::{
        Expression, SemanticConceptDefinition, SemanticConformanceVector, SemanticContextBundle,
        SemanticContextRef, SignedSemanticContextBundle,
    },
};
use rusqlite::Connection;
use serde_json::json;

fn context(authority: AgentId, namespace: u32, revision: u16) -> SemanticContextBundle {
    SemanticContextBundle {
        authority,
        namespace,
        revision,
        kernel_revision: 1,
        dependencies: Vec::new(),
        concepts: vec![SemanticConceptDefinition {
            concept_id: 7,
            arity: 1,
            definition: Expression::from_json(&json!([
                "meaning_is",
                [
                    "concept",
                    authority
                        .0
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>(),
                    namespace,
                    revision,
                    7
                ],
                1,
                ["op", "gt", ["var", 0], ["int", "0"]]
            ]))
            .unwrap(),
        }],
        vectors: vec![SemanticConformanceVector {
            concept_id: 7,
            case_id: 1,
            inputs: vec![Expression::from_json(&json!(["int", "2"])).unwrap()],
            expected: Expression::from_json(&json!(["bool", true])).unwrap(),
        }],
    }
}

fn signed(bundle: SemanticContextBundle) -> Vec<u8> {
    SignedSemanticContextBundle {
        bundle,
        signature: Signature65([0x44; 65]),
    }
    .encode()
    .unwrap()
}

#[test]
fn context_cache_is_immutable_idempotent_and_survives_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("asl.sqlite3");
    let bundle = context(AgentId([0x11; 32]), 4, 1);
    let reference = bundle.context_ref().unwrap();
    let bytes = signed(bundle);
    {
        let mut store = open_store(&path).unwrap();
        assert_eq!(
            store.put_semantic_context_candidate(&bytes, 10).unwrap(),
            (reference, SemanticContextCandidateInsert::Inserted)
        );
        assert_eq!(
            store.put_semantic_context_candidate(&bytes, 11).unwrap(),
            (reference, SemanticContextCandidateInsert::AlreadyPresent)
        );
    }
    let mut store = open_store(&path).unwrap();
    assert_eq!(
        store
            .semantic_context_candidate(reference)
            .unwrap()
            .as_deref(),
        Some(bytes.as_slice())
    );
    let other_digest = SemanticContextRef {
        digest: Hash32([0x99; 32]),
        ..reference
    };
    assert!(
        store
            .semantic_context_candidate(other_digest)
            .unwrap()
            .is_none()
    );
    assert!(store.remove_semantic_context_candidate(reference).unwrap());
    assert!(
        store
            .semantic_context_candidate(reference)
            .unwrap()
            .is_none()
    );
    assert!(!store.remove_semantic_context_candidate(reference).unwrap());
}

#[test]
fn conflicting_bytes_cannot_replace_an_immutable_namespace_revision() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("asl.sqlite3");
    let authority = AgentId([0x11; 32]);
    let mut store = open_store(&path).unwrap();
    let first = signed(context(authority, 4, 1));
    store.put_semantic_context_candidate(&first, 10).unwrap();
    let mut changed = context(authority, 4, 1);
    changed.concepts[0].definition = Expression::from_json(&json!([
        "meaning_is",
        [
            "concept",
            "1111111111111111111111111111111111111111111111111111111111111111",
            4,
            1,
            7
        ],
        1,
        ["op", "ge", ["var", 0], ["int", "0"]]
    ]))
    .unwrap();
    let conflicting = signed(changed);
    assert_ne!(first, conflicting);
    assert!(
        store
            .put_semantic_context_candidate(&conflicting, 11)
            .is_err()
    );
    assert_eq!(
        store
            .semantic_context_candidate(
                SignedSemanticContextBundle::decode(&first)
                    .unwrap()
                    .bundle
                    .context_ref()
                    .unwrap()
            )
            .unwrap(),
        Some(first)
    );
}

#[test]
fn context_cache_enforces_a_per_profile_entry_limit() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("asl.sqlite3");
    let authority = AgentId([0x11; 32]);
    let mut store = open_store(&path).unwrap();
    for namespace in 0..256 {
        let bytes = signed(context(authority, namespace, 1));
        store.put_semantic_context_candidate(&bytes, 10).unwrap();
    }
    let overflow = signed(context(authority, 256, 1));
    assert!(matches!(
        store.put_semantic_context_candidate(&overflow, 10),
        Err(asl_types::error::AslError::QuotaExceeded)
    ));
}

#[test]
fn schema_v32_upgrades_additively_without_creating_share_or_inbox_grants() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("asl.sqlite3");
    let store = open_store(&path).unwrap();
    store.set_setting("test.preserved", "\"yes\"", 10).unwrap();
    drop(store);

    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "DROP TABLE semantic_context_candidates;
             DROP TABLE semantic_context_resources;
             DROP TABLE conversation_attachment_refs;
             DROP TABLE conversation_act_events;
             DROP TABLE conversation_budget_grants;
             DROP TABLE mailbox_shards;
             DROP TABLE mailbox_slots;
             DROP TABLE gossip_topic_state;
             DROP TABLE local_capacity_measurements;
             DROP TABLE group_access_members;
             DROP TABLE group_access_policies;
             DELETE FROM schema_migrations WHERE version>32;",
        )
        .unwrap();
    drop(connection);

    let store = open_store(&path).unwrap();
    assert_eq!(store.schema_version(), 36);
    assert_eq!(
        store.get_setting("test.preserved").unwrap().as_deref(),
        Some("\"yes\"")
    );
    let database = Connection::open(&path).unwrap();
    let (candidates, grants, inbox): (i64, i64, i64) = database
        .query_row(
            "SELECT (SELECT COUNT(*) FROM semantic_context_candidates),
                    (SELECT COUNT(*) FROM grants),
                    (SELECT COUNT(*) FROM write_grants WHERE kind='inbox')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!((candidates, grants, inbox), (0, 0, 0));
}
