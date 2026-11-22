#![cfg(windows)]

use std::{process::Command, time::SystemTime};

use asl_app::{
    chain::{
        ChainEndpointV1, ChainHttpConfigV1, CheckpointV1, ConsensusConfigV1,
        DurableResolverConfigV1, ForkV1, ForksV1, RegistryDeploymentV1,
    },
    network_identity::NetworkIdentityConfigurationV1,
    paths::AppPaths,
};
use asl_store::{
    chain::{ChainBundle, ChainStateRow},
    open_store,
};

#[test]
fn core_cli_stages_and_cancels_only_a_reviewed_checkpoint() {
    let home = std::env::temp_dir().join(format!(
        "asl checkpoint cli {}",
        libp2p_identity::PeerId::random()
    ));
    let paths = AppPaths::open(&home).unwrap();
    let store_path = paths.state().join("asl.sqlite3");
    let mut store = open_store(&store_path).unwrap();
    let cli = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_asl-core"))
            .arg("--checkpoint")
            .args(args)
            .env("ASL_HOME", &home)
            .output()
            .unwrap()
    };
    let status = || {
        let result = cli(&["status"]);
        assert!(result.status.success(), "{:?}", result.stderr);
        serde_json::from_slice::<serde_json::Value>(&result.stdout).unwrap()
    };
    assert!(status().is_null());
    let now = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs();
    let checkpoint = CheckpointV1 {
        beacon_root: [3; 32],
        slot: 10,
    };
    let deployment = RegistryDeploymentV1 {
        version: 1,
        chain_id: 7,
        address: [4; 20],
        runtime_code_hash: [5; 32],
    };
    let fork = ForkV1 {
        epoch: 0,
        version: [0; 4],
    };
    let endpoint = ChainEndpointV1 {
        url: "https://example.invalid".into(),
        allow_loopback_http: false,
    };
    let config = NetworkIdentityConfigurationV1 {
        version: 1,
        resolver: DurableResolverConfigV1 {
            deployment,
            max_cache_age_secs: 600,
            cache_capacity: 8,
            consensus: ConsensusConfigV1 {
                version: 1,
                chain_id: 7,
                genesis_time_secs: now - 1_200,
                genesis_validators_root: [1; 32],
                seconds_per_slot: 12,
                forks: ForksV1 {
                    genesis: fork,
                    altair: fork,
                    bellatrix: fork,
                    capella: fork,
                    deneb: fork,
                    electra: fork,
                    fulu: fork,
                    gloas: fork,
                },
                checkpoint,
                max_checkpoint_age_secs: 3600,
                max_finality_age_secs: 600,
            },
        },
        http: ChainHttpConfigV1 {
            version: 1,
            beacon_endpoints: vec![endpoint.clone()],
            execution_endpoints: vec![endpoint],
            request_timeout_ms: 100,
            max_committee_updates: 1,
            max_sync_requests: 2,
        },
    };
    let config_path = paths.network_identity_configuration();
    let bytes = serde_json::to_vec(&config).unwrap();
    std::fs::write(&config_path, &bytes).unwrap();
    // CLI only records local intent. Startup must authenticate the snapshot.
    store
        .save_chain_bundle(
            &ChainBundle {
                state: ChainStateRow {
                    chain_id: 7,
                    registry_address: deployment.address,
                    registry_code_hash: deployment.runtime_code_hash,
                    finalized_height: 1,
                    finalized_block_hash: [6; 32],
                    execution_state_root: [7; 32],
                    checkpoint_hash: checkpoint.beacon_root,
                    verified_header_state: vec![1],
                    updated_at_ms: now * 1000,
                },
                observations: vec![],
                proofs: vec![],
            },
            None,
        )
        .unwrap();
    drop(store);

    let initial = status();
    let context = initial["context"].as_str().unwrap();
    let root = alloy_primitives::hex::encode_prefixed([8; 32]);
    assert!(
        !cli(&["stage", "stale-context", "90", &root])
            .status
            .success()
    );
    assert!(!cli(&["stage", context, "10", &root]).status.success());
    assert!(cli(&["stage", context, "90", &root]).status.success());
    let staged = status();
    assert_eq!(staged["pending"]["slot"], 90);
    assert_eq!(staged["current"]["slot"], 10);
    assert!(cli(&["cancel"]).status.success());
    assert!(status()["pending"].is_null());
    assert_eq!(std::fs::read(config_path).unwrap(), bytes);
    std::fs::remove_dir_all(home).unwrap();
}
