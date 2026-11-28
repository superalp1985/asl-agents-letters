#![cfg(windows)]

use std::{fs, path::PathBuf, process::Command};

use asl_app::paths::AppPaths;
use asl_store::{network_privacy::NetworkRuntimeState, open_store};
use rusqlite::Connection;
use serde_json::{Value, json};

struct Fixture(PathBuf);

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn diagnostics_cli_exports_only_the_local_summary_and_never_replaces_an_output() {
    let root = Fixture(
        std::env::temp_dir().join(format!("asl-diagnostics-{:032x}", rand::random::<u128>())),
    );
    let profile = root.0.join("private-profile-path");
    let paths = AppPaths::open(&profile).unwrap();
    let database = paths.state().join("asl.sqlite3");
    let store = open_store(&database).unwrap();
    store
        .report_network_state(NetworkRuntimeState::Paused, true, 2, 0)
        .unwrap();
    let settings = Connection::open(&database).unwrap();
    settings
        .execute_batch(
            "INSERT INTO agents(agent_id) VALUES ('sensitive-agent-id');
             INSERT INTO providers
             VALUES ('sample','https://example.invalid/private-endpoint','private-model',
                     'private-credential', 'remote',1,1000);
             INSERT INTO tasks(task_id,direction,local_task_text,audience_json,state,created_at_ms,expires_at_ms)
             VALUES (printf('%032x',1),'local','private-task-text','{}','done',0,1);",
        )
        .unwrap();
    drop(settings);
    fs::write(paths.agent_root_key(), b"private-key-placeholder").unwrap();
    fs::write(paths.logs().join("sample.log"), b"private-log-message").unwrap();

    let cli = |destination: &std::path::Path| {
        Command::new(env!("CARGO_BIN_EXE_asl-core"))
            .arg("--diagnostics")
            .arg(destination)
            .env("ASL_HOME", &profile)
            .output()
            .unwrap()
    };
    assert!(!cli(&paths.state().join("report.json")).status.success());
    let export = root.0.join("export");
    fs::create_dir(&export).unwrap();
    let destination = export.join("local report.json");
    let result = cli(&destination);
    assert!(result.status.success(), "{:?}", result.stderr);
    let body = fs::read(&destination).unwrap();
    let report: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        report,
        json!({
            "format_version": 1,
            "app_version": env!("CARGO_PKG_VERSION"),
            "schema_version": store.schema_version(),
            "last_network_report": {
                "runtime": "paused",
                "relay_only": true,
                "configured_relays": 2,
                "reserved_relays": 0,
                "listening_endpoints": 0,
                "reachability": "unreported",
                "reachability_confidence": 0,
                "public_entry": false,
                "direct_routes": 0,
                "hole_punched_routes": 0,
                "relayed_routes": 0,
                "negotiating_routes": 0,
                "failed_routes": 0,
                "last_route_failure": null,
                "observed_at_ms": report["last_network_report"]["observed_at_ms"]
            },
            "counts": {
                "known_agents": 1,
                "active_share_grants": 0,
                "active_inbox_grants": 0,
                "completed_downloads": 0,
                "failed_downloads": 0
            }
        })
    );
    assert!(report["last_network_report"]["observed_at_ms"].is_i64());
    assert!(!cli(&destination).status.success());
    assert_eq!(fs::read(&destination).unwrap(), body);
    assert_eq!(fs::read_dir(export).unwrap().count(), 1);
}
