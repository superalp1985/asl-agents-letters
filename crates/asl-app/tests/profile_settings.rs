#![cfg(windows)]

use std::process::Command;

use asl_app::{identity::AgentIdentity, paths::AppPaths};
use asl_store::open_store;

#[test]
fn profile_signing_cli_requires_reviewed_identity_and_never_claims_publication() {
    let home =
        std::env::temp_dir().join(format!("asl profile {}", libp2p_identity::PeerId::random()));
    let paths = AppPaths::open(&home).unwrap();
    let store = open_store(&paths.state().join("asl.sqlite3")).unwrap();
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
    assert!(cli(&["revoke"]).status.success());
    assert!(status()["approval"].is_null());

    drop(store);
    std::fs::remove_dir_all(home).unwrap();
}
