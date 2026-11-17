use super::*;
use crate::chain::test_support::{
    BOOTSTRAP, BOOTSTRAP_TIME, FINALITY, FINALITY_NOW, bootstrapped, consensus_config, synced,
};

#[test]
fn verifies_historical_mainnet_checkpoint_and_bls_finality_updates() {
    let client = synced();
    let finalized = client.finalized(FINALITY_NOW).unwrap();
    assert_eq!(finalized.block_number(), 17_923_026);
    assert_eq!(finalized.beacon_slot(), 7_109_344);
    assert_eq!(
        B256::from(finalized.state_root()),
        alloy_primitives::b256!("226f5ff47ab3725b5a4a3afc74b1e79e4aa3a29704561eccce590e58900baec3")
    );
    assert_eq!(
        B256::from(finalized.block_hash()),
        alloy_primitives::b256!("bc8499537876e5406c7a65e25f99063f1cd85a17014a3aa5ade38271b1fbf64f")
    );
}

#[test]
fn rejects_wrong_checkpoint_root_slot_and_stale_or_future_checkpoint() {
    let config = consensus_config();
    let mut wrong_root = config.clone();
    wrong_root.checkpoint.beacon_root = [9; 32];
    let mut wrong_slot = config.clone();
    wrong_slot.checkpoint.slot += 1;
    for wrong in [wrong_root, wrong_slot] {
        assert!(matches!(
            EthereumLightClient::bootstrap(wrong, BOOTSTRAP, BOOTSTRAP_TIME + 12),
            Err(ChainError::InvalidCheckpoint)
        ));
    }
    assert!(matches!(
        EthereumLightClient::bootstrap(
            config.clone(),
            BOOTSTRAP,
            BOOTSTRAP_TIME + config.max_checkpoint_age_secs + 1
        ),
        Err(ChainError::ExpiredCheckpoint)
    ));
    assert!(matches!(
        EthereumLightClient::bootstrap(config, BOOTSTRAP, BOOTSTRAP_TIME - 1),
        Err(ChainError::ClockBeforeState)
    ));
}

#[test]
fn expired_finality_cannot_be_refreshed_by_replaying_a_bootstrap() {
    let client =
        EthereumLightClient::bootstrap(consensus_config(), BOOTSTRAP, FINALITY_NOW).unwrap();
    assert_eq!(
        client.finalized(FINALITY_NOW),
        Err(ChainError::StaleFinality)
    );
    let client = bootstrapped();
    assert!(client.finalized(BOOTSTRAP_TIME + 1800).is_ok());
    assert_eq!(
        client.finalized(BOOTSTRAP_TIME + 1801),
        Err(ChainError::StaleFinality)
    );
}

#[test]
fn invalid_rpc_data_cannot_replace_or_fault_verified_finality() {
    let mut client = synced();
    let before = client.finalized(FINALITY_NOW).unwrap();
    let mut response: serde_json::Value = serde_json::from_slice(FINALITY).unwrap();
    response["data"]["finalized_header"]["execution"]["state_root"] =
        serde_json::Value::String(format!("0x{}", "99".repeat(32)));
    assert_eq!(
        client.apply_finality_json(&serde_json::to_vec(&response).unwrap(), FINALITY_NOW),
        Err(ChainError::InvalidConsensusData)
    );
    assert_eq!(client.finalized(FINALITY_NOW).unwrap(), before);
    assert!(client.apply_finality_json(b"{}", FINALITY_NOW).is_err());
    assert!(client.apply_update_json(FINALITY, FINALITY_NOW).is_err());
    assert_eq!(client.finalized(FINALITY_NOW).unwrap(), before);
}

#[test]
fn bad_signatures_and_oversized_responses_cannot_advance_finality() {
    let mut client = bootstrapped();
    let mut response: serde_json::Value = serde_json::from_slice(FINALITY).unwrap();
    response["data"]["sync_aggregate"]["sync_committee_signature"] =
        serde_json::Value::String(format!("0x{}", "00".repeat(96)));
    assert!(
        client
            .apply_finality_json(&serde_json::to_vec(&response).unwrap(), FINALITY_NOW)
            .is_err()
    );
    assert!(
        client
            .apply_update_json(&vec![b' '; MAX_CONSENSUS_RESPONSE_BYTES + 1], FINALITY_NOW)
            .is_err()
    );
    assert_eq!(
        client.finalized(BOOTSTRAP_TIME).unwrap().beacon_slot(),
        7_069_376
    );
}

#[test]
fn optimistic_reorganization_does_not_update_identity_state() {
    let mut client = bootstrapped();
    let before = client.finalized(BOOTSTRAP_TIME).unwrap();
    let mut candidate = client.store.clone();
    candidate.optimistic_header = LightClientHeader::default();
    client.commit_verified_store(candidate).unwrap();
    assert_eq!(client.finalized(BOOTSTRAP_TIME).unwrap(), before);
}

#[test]
fn conflicting_verified_finality_disables_identity_resolution() {
    let mut client = bootstrapped();
    let mut candidate = client.store.clone();
    if let LightClientHeader::Capella(header) = &mut candidate.finalized_header {
        header.beacon.body_root = B256::ZERO;
    } else {
        panic!("fixture should be capella");
    }
    assert_eq!(
        client.commit_verified_store(candidate),
        Err(ChainError::ConflictingFinality)
    );
    assert_eq!(
        client.finalized(BOOTSTRAP_TIME),
        Err(ChainError::ConflictingFinality)
    );
}

#[test]
fn public_update_path_detects_same_slot_finality_conflict_before_helios_discards_it() {
    let mut client = synced();
    // Model a previously accepted conflicting head, then feed an unmodified,
    // genuinely signed Mainnet finality response through the public API.
    if let LightClientHeader::Capella(header) = &mut client.store.finalized_header {
        header.beacon.body_root = B256::ZERO;
    } else {
        panic!("fixture should be capella");
    }
    assert_eq!(
        client.apply_finality_json(FINALITY, FINALITY_NOW),
        Err(ChainError::ConflictingFinality)
    );
    assert_eq!(
        client.finalized(FINALITY_NOW),
        Err(ChainError::ConflictingFinality)
    );
}

#[test]
fn weak_subjectivity_expiry_requires_a_new_trusted_checkpoint() {
    let mut client = bootstrapped();
    let now = BOOTSTRAP_TIME + consensus_config().max_checkpoint_age_secs + 1;
    assert_eq!(
        client.apply_finality_json(FINALITY, now),
        Err(ChainError::ExpiredCheckpoint)
    );
}

#[test]
fn gloas_execution_root_requires_a_hash_bound_full_header() {
    use helios_consensus_core::types::LightClientHeaderGloas;
    let mut client = bootstrapped();
    let execution = Header {
        number: 17_883_334,
        timestamp: BOOTSTRAP_TIME + 12,
        state_root: B256::repeat_byte(4),
        ..Default::default()
    };
    // This unit test starts after consensus verification, exercising only the
    // adapter's Gloas execution-header binding, not a synthetic BLS signature.
    let mut candidate = client.store.clone();
    let mut beacon = candidate.finalized_header.beacon().clone();
    beacon.slot += 1;
    candidate.finalized_header = LightClientHeader::Gloas(LightClientHeaderGloas {
        beacon,
        execution_block_hash: execution.hash_slow(),
        ..Default::default()
    });
    client.commit_verified_store(candidate).unwrap();
    assert_eq!(
        client.finalized(BOOTSTRAP_TIME + 12),
        Err(ChainError::ExecutionHeaderRequired)
    );
    let wrong = alloy_rlp::encode(Header::default());
    assert_eq!(
        client.supply_execution_header(&wrong, BOOTSTRAP_TIME + 12),
        Err(ChainError::InvalidExecutionHeader)
    );
    client
        .supply_execution_header(&alloy_rlp::encode(execution), BOOTSTRAP_TIME + 12)
        .unwrap();
    assert_eq!(
        client.finalized(BOOTSTRAP_TIME + 12).unwrap().state_root(),
        [4; 32]
    );
}
