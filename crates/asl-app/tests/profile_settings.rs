#![cfg(windows)]

use std::process::Command;

use asl_app::{identity::AgentIdentity, paths::AppPaths};
use asl_store::open_store;

#[test]
fn profile_signing_cli_requires_reviewed_identity_and_never_claims_publication() {
    let home =
        std::env::temp_dir().join(format!("asl profile {}", libp2p_identity::PeerId::random()));
    let paths = AppPaths::open(&home).unwrap();
    let mut store = open_store(&paths.state().join("asl.sqlite3")).unwrap();
    let identity = AgentIdentity::load_or_create_protected(&paths.agent_root_key()).unwrap();
    let agent = bs58::encode(identity.agent_id().as_bytes()).into_string();
    let cli = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_asl-core"))
            .arg("--profile")
            .args(args)
            .env("ASL_HOME", &home)
            .output()
            .unwrap()
    };
    let status = || {
        let output = cli(&["status"]);
        assert!(output.status.success(), "{:?}", output.stderr);
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    assert!(status()["approval"].is_null());
    assert!(!cli(&["lookup", &agent]).status.success());
    let lookup_target = bs58::encode([9; 32]).into_string();
    let lookup = cli(&["lookup", &lookup_target]);
    assert!(lookup.status.success(), "{:?}", lookup.stderr);
    let report: serde_json::Value = serde_json::from_slice(&lookup.stdout).unwrap();
    assert_eq!(report["state"], "queued");
    assert_eq!(report["target"], lookup_target);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&cli(&["lookup-status"]).stdout).unwrap(),
        report
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&cli(&["received"]).stdout).unwrap(),
        serde_json::json!([])
    );
    assert!(
        !cli(&["approve-local-signing", "wrong-id", "101"])
            .status
            .success()
    );
    assert!(
        !cli(&["approve-local-signing", &agent, "free text"])
            .status
            .success()
    );
    assert!(
        cli(&["approve-local-signing", &agent, "104", "101"])
            .status
            .success()
    );
    let approved = status();
    assert_eq!(
        approved["approval"]["topics"],
        serde_json::json!([101, 104])
    );
    assert!(approved["last_candidate"].is_null());
    assert_eq!(approved["approval"]["publish"], false);
    assert!(
        !cli(&["approve-publication", "wrong-id", "101"])
            .status
            .success()
    );
    assert!(
        cli(&["approve-publication", &agent, "101"])
            .status
            .success()
    );
    let public = status();
    assert_eq!(public["approval"]["publish"], true);
    assert!(public["last_publication"].is_null());
    let approval = store
        .current_public_profile(identity.agent_id())
        .unwrap()
        .unwrap();
    let handoff = asl_store::public_profile::ProfileHandoff {
        operation: [3; 16],
        net_pid: std::process::id(),
    };
    assert!(store.reserve_profile_handoff(&approval, handoff).unwrap());
    let revoked = cli(&["revoke"]);
    assert!(revoked.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&revoked.stdout).unwrap()["status"],
        "pending_network_drain"
    );
    assert_eq!(status()["change_pending"], true);
    store.finish_profile_handoff(handoff.operation).unwrap();
    assert_eq!(status()["change_pending"], false);
    assert!(status()["approval"].is_null());

    drop(store);
    std::fs::remove_dir_all(home).unwrap();
}
