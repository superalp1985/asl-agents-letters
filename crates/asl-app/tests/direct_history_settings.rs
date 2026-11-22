#![cfg(windows)]

use std::process::Command;

use asl_app::paths::AppPaths;
use asl_store::{dashboard::Dashboard, open_store};

#[test]
fn core_updates_the_selected_profiles_history_without_changing_inbound_permissions() {
    let profile =
        std::env::temp_dir().join(format!("asl history {}", libp2p_identity::PeerId::random()));
    let database = AppPaths::open(&profile)
        .unwrap()
        .state()
        .join("asl.sqlite3");
    drop(open_store(&database).unwrap());
    let dashboard = || Dashboard::load(&database).unwrap();
    let change = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_asl-core"))
            .args(args)
            .env("ASL_HOME", &profile)
            .output()
            .unwrap()
            .status
            .success()
    };
    assert_eq!(dashboard().direct_observation_days, 7);
    assert!(change(&["--direct-inbound", "browse"]));
    assert!(change(&["--retention", "direct", "0"]));
    assert!(!change(&["--retention", "direct", "8"]));
    assert_eq!(dashboard().direct_observation_days, 0);
    assert_eq!(dashboard().direct_inbound_mode, "browse");
    assert!(change(&["--retention", "direct", "3"]));
    assert_eq!(dashboard().direct_observation_days, 3);
    assert_eq!(dashboard().group_observation_days, 7);
    assert!(change(&["--group-inbound", "answer", "on"]));
    assert!(!change(&["--retention", "group", "8"]));
    assert!(change(&["--retention", "group", "0"]));
    let data = dashboard();
    assert_eq!(data.group_observation_days, 0);
    assert_eq!(data.direct_observation_days, 3);
    assert!(data.group_inbound.answer_enabled);
    assert!(data.group_inbound.browse_enabled);
    std::fs::remove_dir_all(profile).unwrap();
}
