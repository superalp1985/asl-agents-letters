#![cfg(windows)]

use std::{fs, process::Command};

use asl_app::{
    network_settings::{NetworkAddressScopeV1, NetworkSettingsV1},
    paths::AppPaths,
};
use asl_store::{dashboard::Dashboard, open_store};

#[test]
fn local_command_changes_next_start_only_and_keeps_the_configured_addresses() {
    let root = std::env::temp_dir().join(format!(
        "asl network privacy {}",
        libp2p_identity::PeerId::random()
    ));
    let paths = AppPaths::open(&root).unwrap();
    let database = paths.state().join("asl.sqlite3");
    drop(open_store(&database).unwrap());
    let change = |mode| {
        Command::new(env!("CARGO_BIN_EXE_asl-core"))
            .args(["--network", "relay-only", mode])
            .env("ASL_HOME", &root)
            .output()
            .unwrap()
            .status
            .success()
    };
    assert!(!change("on"));

    let config = paths.network_settings_configuration();
    let peer = libp2p_identity::PeerId::random();
    let base = NetworkSettingsV1 {
        address_scope: NetworkAddressScopeV1::Hybrid,
        listen_on_interfaces: true,
        relay_addresses: vec![format!("/ip4/127.0.0.1/tcp/40667/p2p/{peer}")],
        ..NetworkSettingsV1::default()
    };
    let original = serde_json::to_vec_pretty(&base).unwrap();
    fs::write(&config, &original).unwrap();
    assert!(change("on"));
    assert!(!change("maybe"));
    let dashboard = Dashboard::load(&database).unwrap();
    assert!(dashboard.force_relay_only);
    assert!(dashboard.network_report.is_none());
    let next = NetworkSettingsV1::load(&config)
        .unwrap()
        .with_relay_only_override(dashboard.force_relay_only)
        .unwrap();
    assert_eq!(next.address_scope, NetworkAddressScopeV1::RelayOnly);
    assert!(!next.listen_on_interfaces);
    assert_eq!(next.relay_addresses, base.relay_addresses);

    fs::remove_file(&config).unwrap();
    assert!(
        NetworkSettingsV1::load(&config)
            .unwrap()
            .with_relay_only_override(dashboard.force_relay_only)
            .is_err()
    );
    assert!(change("off"));
    assert!(!Dashboard::load(&database).unwrap().force_relay_only);
    fs::write(&config, &original).unwrap();
    assert!(change("on"));
    assert!(change("off"));
    assert_eq!(fs::read(&config).unwrap(), original);
    assert_eq!(
        NetworkSettingsV1::load(&config)
            .unwrap()
            .with_relay_only_override(false)
            .unwrap(),
        base
    );
    let pause = |mode| {
        Command::new(env!("CARGO_BIN_EXE_asl-core"))
            .args(["--network", "pause", mode])
            .env("ASL_HOME", &root)
            .output()
            .unwrap()
            .status
            .success()
    };
    assert!(pause("on"));
    assert!(!pause("maybe"));
    let dashboard = Dashboard::load(&database).unwrap();
    assert!(dashboard.network_pause_requested);
    assert!(dashboard.network_report.is_none());
    assert!(pause("off"));
    assert!(!Dashboard::load(&database).unwrap().network_pause_requested);
    assert_eq!(fs::read(&config).unwrap(), original);
    fs::remove_dir_all(root).unwrap();
}
