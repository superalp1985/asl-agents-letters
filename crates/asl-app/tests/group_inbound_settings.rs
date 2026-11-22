#![cfg(windows)]

use std::process::Command;

use asl_app::paths::AppPaths;
use asl_store::{dashboard::Dashboard, open_store};

#[test]
fn group_switches_edit_only_the_requested_setting_in_the_selected_home() {
    let root = std::env::temp_dir().join(format!(
        "asl group settings {}",
        libp2p_identity::PeerId::random()
    ));
    std::fs::create_dir(&root).unwrap();
    let database = AppPaths::open(&root).unwrap().state().join("asl.sqlite3");
    drop(open_store(&database).unwrap());

    let policy = || Dashboard::load(&database).unwrap().group_inbound;
    let change = |field, value| {
        Command::new(env!("CARGO_BIN_EXE_asl-core"))
            .args(["--group-inbound", field, value])
            .env("ASL_HOME", &root)
            .output()
            .unwrap()
            .status
            .success()
    };
    assert!(policy().browse_enabled);
    assert!(!policy().answer_enabled);
    assert!(change("answer", "on"));
    assert!(change("browse", "off"));
    assert!(!change("answer", "maybe"));
    assert!(!policy().browse_enabled);
    assert!(policy().answer_enabled);
    assert!(change("answer", "off"));
    assert!(!policy().answer_enabled);
    std::fs::remove_dir_all(root).unwrap();
}
