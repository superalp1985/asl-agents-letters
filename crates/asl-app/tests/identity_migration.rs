#![cfg(windows)]

use std::{
    fs,
    time::{SystemTime, UNIX_EPOCH},
};

use age::secrecy::SecretString;
use asl_app::{
    identity::{AgentIdentity, DeviceIdentity},
    migration::{Selection, export, import_new},
    paths::AppPaths,
};
use asl_store::{
    act_history::{ActDirection, ActHistoryRecord},
    dashboard::Dashboard,
    evidence::{TrustDimension, TrustOutcome},
    open_store,
};
use asl_types::{
    ids::{AgentId, Hash32},
    protocol::{ConceptRef, Intent, Query, ResultShape},
};
use rusqlite::Connection;

#[test]
fn encrypted_migration_preserves_selected_data_with_a_fresh_device() {
    let fixture = tempfile::Builder::new()
        .prefix("asl-migration-")
        .tempdir()
        .unwrap();
    let origin = AppPaths::open(&fixture.path().join("origin")).unwrap();
    let root = AgentIdentity::generate().unwrap();
    root.save_protected_new(&origin.agent_root_key()).unwrap();
    let original_device = DeviceIdentity::generate().unwrap();
    original_device
        .save_protected_new(&origin.device_key())
        .unwrap();
    let path = origin.state().join("asl.sqlite3");
    let mut store = open_store(&path).unwrap();
    store.set_network_pause_requested(true).unwrap();
    let database = Connection::open(&path).unwrap();
    let contact = AgentId([1; 32]);
    database
        .execute(
            "INSERT INTO agents(agent_id) VALUES (?1)",
            [bs58::encode(contact.as_bytes()).into_string()],
        )
        .unwrap();
    database.execute(
        "INSERT INTO contact_bindings VALUES (?1,'previous-device','bound',1), (?2,NULL,'revoked',1)",
        rusqlite::params![[1u8; 32], [2u8; 32]],
    ).unwrap();
    drop(database);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let retained_until_ms = now + 7 * 24 * 60 * 60 * 1000;
    store
        .record_trust_observation(
            contact,
            None,
            TrustDimension::Integrity,
            TrustOutcome::Negative,
            Hash32([5; 32]),
            now,
        )
        .unwrap();
    store
        .record_direct_inbound_observation(
            contact,
            &original_device.peer_id(),
            &Query {
                message_id: [3; 16].into(),
                root_task_id: [4; 16].into(),
                created_at_ms: now,
                expires_at_ms: retained_until_ms,
                intent_id: Intent::LocateResource,
                topics: vec![ConceptRef::RUST],
                constraints: vec![],
                result_shape: ResultShape::Resources,
                budget: 1,
            },
            now as i64,
        )
        .unwrap();
    store
        .record_act_history(ActHistoryRecord {
            conversation_id: "00112233445566778899aabbccddeeff",
            message_id: [6; 16].into(),
            mls_epoch: 2,
            direction: ActDirection::In,
            act_kind: 1,
            reply_to: None,
            causal_root: [7; 16].into(),
            body: Some("migrated act preview"),
            now_ms: now,
            expires_at_ms: retained_until_ms,
        })
        .unwrap();
    drop(store);
    let export_path = fixture.path().join("export");
    fs::create_dir(&export_path).unwrap();
    let bundle = export_path.join("identity.age");
    let passphrase = || SecretString::from("a generated migration passphrase");
    export(
        &origin,
        &bundle,
        passphrase(),
        Selection {
            contacts: true,
            trust: true,
            history: true,
        },
    )
    .unwrap();
    assert!(
        fs::read(&bundle)
            .unwrap()
            .starts_with(b"age-encryption.org/v1\n")
    );

    let target = fixture.path().join("target");
    assert!(import_new(&bundle, &target, "wrong passphrase".into()).is_err());
    assert!(!target.exists());
    let imported = import_new(&bundle, &target, passphrase()).unwrap();
    assert_eq!(imported.agent_id, root.agent_id());
    assert_ne!(imported.peer_id, original_device.peer_id());
    let target_paths = AppPaths::open_existing(&target).unwrap();
    assert_eq!(
        AgentIdentity::load_protected(&target_paths.agent_root_key())
            .unwrap()
            .agent_id(),
        root.agent_id()
    );
    assert_eq!(
        DeviceIdentity::load_protected(&target_paths.device_key())
            .unwrap()
            .peer_id(),
        imported.peer_id
    );
    assert!(!target_paths.signed_device_directory().exists());
    let target_database = target_paths.state().join("asl.sqlite3");
    let view = Dashboard::load(&target_database).unwrap();
    assert_eq!(view.contact_bindings.len(), 2);
    assert!(
        view.contact_bindings
            .iter()
            .all(|row| row.peer_id.is_none() && !row.authorized)
    );
    assert!(
        view.contact_bindings
            .iter()
            .any(|row| row.state == "revoked")
    );
    assert!(view.access.is_empty());
    assert!(!view.network_pause_requested);
    assert_eq!(view.trust.len(), 1);
    assert_eq!(view.trust[0].integrity, [0, 1]);
    assert_eq!(view.direct_observations.len(), 1);
    assert_eq!(view.direct_observations[0].observed_at_ms, now as i64);
    assert_eq!(view.direct_observations[0].topic_ids, vec![(1, 101)]);
    assert!(view.activity.iter().any(|row| {
        row.direction.as_deref() == Some("in")
            && row.preview.as_deref() == Some("migrated act preview")
    }));
    assert!(import_new(&bundle, &target, passphrase()).is_err());
}
