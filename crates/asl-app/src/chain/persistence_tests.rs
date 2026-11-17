use super::*;
use crate::chain::test_support::{
    BOOTSTRAP_TIME, FINALITY, FINALITY_NOW, TestChainDatabase, UPDATES, bootstrapped,
    consensus_config, proof_fixture, proof_fixture_for_agent, registry_values, synced,
};

pub(super) fn config() -> DurableResolverConfigV1 {
    let (deployment, _, _) = proof_fixture(registry_values(9, 1, 1), 8);
    DurableResolverConfigV1 {
        consensus: consensus_config(),
        deployment,
        max_cache_age_secs: 120,
        cache_capacity: 2,
    }
}

fn synthetic(
    database: &TestChainDatabase,
    sequence: u64,
    status: u8,
) -> (DurableIdentityResolver, IdentityProofV1) {
    let (_, finalized, proof) = proof_fixture(registry_values(9, sequence, status), 8);
    let client = bootstrapped().with_test_execution(finalized);
    let resolver =
        DurableIdentityResolver::create(database.open(), config(), client, BOOTSTRAP_TIME).unwrap();
    (resolver, proof)
}

#[test]
fn finalized_consensus_roundtrips_and_can_resume_from_stale_finality() {
    let database = TestChainDatabase::new();
    let durable =
        DurableIdentityResolver::create(database.open(), config(), bootstrapped(), BOOTSTRAP_TIME)
            .unwrap();
    drop(durable);
    let mut restored =
        DurableIdentityResolver::restore(database.open(), config(), FINALITY_NOW).unwrap();
    assert_eq!(
        restored.light_client().finalized(FINALITY_NOW),
        Err(ChainError::StaleFinality)
    );
    let updates: Vec<Value> = serde_json::from_slice(UPDATES).unwrap();
    for update in updates {
        restored
            .apply_update_json(&serde_json::to_vec(&update).unwrap(), FINALITY_NOW)
            .unwrap();
    }
    restored
        .apply_finality_json(FINALITY, FINALITY_NOW)
        .unwrap();
    let expected = synced().finalized(FINALITY_NOW).unwrap();
    assert_eq!(
        restored.light_client().finalized(FINALITY_NOW).unwrap(),
        expected
    );
    drop(restored);
    let restored =
        DurableIdentityResolver::restore(database.open(), config(), FINALITY_NOW).unwrap();
    assert_eq!(
        restored.light_client().finalized(FINALITY_NOW).unwrap(),
        expected
    );
}

use serde_json::Value;

#[test]
fn positive_proof_is_reverified_after_restart_without_renewing_expiry() {
    let database = TestChainDatabase::new();
    let (mut durable, proof) = synthetic(&database, 1, 1);
    durable
        .accept_proof(proof.agent_id, &proof, BOOTSTRAP_TIME)
        .unwrap();
    assert!(matches!(
        durable.resolve(proof.agent_id, BOOTSTRAP_TIME),
        IdentityResolution::Verified(_)
    ));
    drop(durable);
    let mut restored =
        DurableIdentityResolver::restore(database.open(), config(), BOOTSTRAP_TIME + 120).unwrap();
    assert!(matches!(
        restored.resolve(proof.agent_id, BOOTSTRAP_TIME + 120),
        IdentityResolution::Verified(_)
    ));
    drop(restored);
    let mut expired =
        DurableIdentityResolver::restore(database.open(), config(), BOOTSTRAP_TIME + 121).unwrap();
    assert!(!matches!(
        expired.resolve(proof.agent_id, BOOTSTRAP_TIME + 121),
        IdentityResolution::Verified(_)
    ));
    assert_eq!(expired.bundle.observations.len(), 1);
}

#[test]
fn invalid_proof_leaves_the_complete_committed_bundle_unchanged() {
    let database = TestChainDatabase::new();
    let (mut durable, mut proof) = synthetic(&database, 1, 1);
    durable
        .accept_proof(proof.agent_id, &proof, BOOTSTRAP_TIME)
        .unwrap();
    let before = durable.bundle.clone();
    proof.storage[0].value[31] ^= 1;
    assert!(
        durable
            .accept_proof(proof.agent_id, &proof, BOOTSTRAP_TIME + 1)
            .is_err()
    );
    assert_eq!(durable.bundle, before);
    assert_eq!(
        database.open().load_chain_bundle(1).unwrap().unwrap(),
        before
    );
}

#[test]
fn snapshot_proof_and_observation_tampering_all_fail_closed() {
    for statement in [
        "UPDATE chain_state_cache SET verified_header_state = zeroblob(length(verified_header_state))",
        "UPDATE identity_proof_cache SET proof_cbor = X'80'",
        "UPDATE identity_registry_states SET sequence = sequence + 1",
        "DELETE FROM identity_registry_states",
    ] {
        let database = TestChainDatabase::new();
        let (mut durable, proof) = synthetic(&database, 1, 1);
        durable
            .accept_proof(proof.agent_id, &proof, BOOTSTRAP_TIME)
            .unwrap();
        drop(durable);
        let connection = rusqlite::Connection::open(&database.path).unwrap();
        connection.execute_batch(statement).unwrap();
        drop(connection);
        assert!(
            matches!(
                DurableIdentityResolver::restore(database.open(), config(), BOOTSTRAP_TIME),
                Err(ChainError::InvalidLocalState)
            ),
            "{statement}"
        );
    }
}

#[test]
fn changed_trust_configuration_expired_checkpoint_and_clock_rollback_are_rejected() {
    let database = TestChainDatabase::new();
    let (durable, _) = synthetic(&database, 1, 1);
    drop(durable);
    let mut changed = config();
    changed.consensus.genesis_validators_root[0] ^= 1;
    assert!(matches!(
        DurableIdentityResolver::restore(database.open(), changed, BOOTSTRAP_TIME),
        Err(ChainError::InvalidLocalState)
    ));
    let mut changed = config();
    changed.deployment.address[0] ^= 1;
    assert!(DurableIdentityResolver::restore(database.open(), changed, BOOTSTRAP_TIME).is_err());
    assert!(matches!(
        DurableIdentityResolver::restore(database.open(), config(), BOOTSTRAP_TIME - 1),
        Err(ChainError::InvalidLocalState)
    ));
    assert!(matches!(
        DurableIdentityResolver::restore(
            database.open(),
            config(),
            BOOTSTRAP_TIME + config().consensus.max_checkpoint_age_secs + 1
        ),
        Err(ChainError::ExpiredCheckpoint)
    ));
    assert!(matches!(
        DurableIdentityResolver::create(database.open(), config(), bootstrapped(), BOOTSTRAP_TIME),
        Err(ChainError::InvalidLocalState)
    ));
}

#[test]
fn revoked_observation_survives_proof_eviction_expiry_and_restart() {
    let database = TestChainDatabase::new();
    let (mut durable, proof) = synthetic(&database, 2, 2);
    durable
        .accept_proof(proof.agent_id, &proof, BOOTSTRAP_TIME)
        .unwrap();
    let mut bundle = durable.bundle.clone();
    bundle.proofs.clear();
    durable
        .commit(durable.resolver.clone(), bundle, BOOTSTRAP_TIME + 121)
        .unwrap();
    drop(durable);
    let mut restored =
        DurableIdentityResolver::restore(database.open(), config(), BOOTSTRAP_TIME + 121).unwrap();
    assert!(restored.bundle.proofs.is_empty());
    assert_eq!(
        restored.resolve(proof.agent_id, BOOTSTRAP_TIME + 121),
        IdentityResolution::Limited(LimitedReason::Revoked)
    );
    // Isolate the durable monotonicity check with a separately verified,
    // synthetic newer head, rather than pretending to forge a BLS update.
    let (_, mut finalized, mut active) = proof_fixture(registry_values(9, 3, 1), 8);
    finalized.block_number += 1;
    finalized.timestamp_secs += 121;
    active.block_number = finalized.block_number;
    *restored.resolver.light_client_mut() = bootstrapped().with_test_execution(finalized);
    assert_eq!(
        restored.accept_proof(active.agent_id, &active, BOOTSTRAP_TIME + 121),
        Err(ChainError::Rollback)
    );
}

#[test]
fn sequence_highwater_survives_proof_eviction_and_restart() {
    let database = TestChainDatabase::new();
    let (mut durable, proof) = synthetic(&database, 2, 1);
    durable
        .accept_proof(proof.agent_id, &proof, BOOTSTRAP_TIME)
        .unwrap();
    let mut bundle = durable.bundle.clone();
    bundle.proofs.clear();
    durable
        .commit(durable.resolver.clone(), bundle, BOOTSTRAP_TIME + 1)
        .unwrap();
    drop(durable);
    let mut restored =
        DurableIdentityResolver::restore(database.open(), config(), BOOTSTRAP_TIME + 1).unwrap();
    let (_, mut finalized, mut older) = proof_fixture(registry_values(9, 1, 1), 8);
    finalized.block_number += 1;
    finalized.timestamp_secs += 1;
    older.block_number = finalized.block_number;
    *restored.resolver.light_client_mut() = bootstrapped().with_test_execution(finalized);
    assert_eq!(
        restored.accept_proof(older.agent_id, &older, BOOTSTRAP_TIME + 1),
        Err(ChainError::Rollback)
    );
}

#[test]
fn failed_durable_commit_disables_previously_cached_positive_identity() {
    let database = TestChainDatabase::new();
    let (mut durable, proof) = synthetic(&database, 1, 1);
    durable
        .accept_proof(proof.agent_id, &proof, BOOTSTRAP_TIME)
        .unwrap();
    let connection = rusqlite::Connection::open(&database.path).unwrap();
    connection.execute_batch(
        "CREATE TRIGGER reject_chain_save BEFORE UPDATE ON chain_state_cache BEGIN SELECT RAISE(ABORT, 'test write failure'); END;"
    ).unwrap();
    assert_eq!(
        durable.accept_proof(proof.agent_id, &proof, BOOTSTRAP_TIME + 1),
        Err(ChainError::StorageUnavailable)
    );
    assert_eq!(
        durable.resolve(proof.agent_id, BOOTSTRAP_TIME + 1),
        IdentityResolution::Limited(LimitedReason::ChainUnavailable)
    );
    drop(connection);
    drop(durable);
    let mut restored =
        DurableIdentityResolver::restore(database.open(), config(), BOOTSTRAP_TIME + 1).unwrap();
    assert!(matches!(
        restored.resolve(proof.agent_id, BOOTSTRAP_TIME + 1),
        IdentityResolution::Verified(_)
    ));
}

#[test]
fn concurrent_core_cannot_overwrite_a_newer_sealed_snapshot() {
    let database = TestChainDatabase::new();
    let (mut first, proof) = synthetic(&database, 1, 1);
    let mut stale =
        DurableIdentityResolver::restore(database.open(), config(), BOOTSTRAP_TIME).unwrap();
    first
        .accept_proof(proof.agent_id, &proof, BOOTSTRAP_TIME)
        .unwrap();
    assert_eq!(
        stale.accept_proof(proof.agent_id, &proof, BOOTSTRAP_TIME + 1),
        Err(ChainError::StorageUnavailable)
    );
    assert_eq!(
        stale.resolve(proof.agent_id, BOOTSTRAP_TIME + 1),
        IdentityResolution::Limited(LimitedReason::ChainUnavailable)
    );
}

#[test]
fn authenticated_finality_conflict_is_saved_and_blocks_restart() {
    let database = TestChainDatabase::new();
    // Start after acceptance of a conflicting header, then use the genuinely
    // signed historical finality response through the public update API.
    let mut durable = DurableIdentityResolver::create(
        database.open(),
        config(),
        synced().with_test_beacon_conflict(),
        FINALITY_NOW,
    )
    .unwrap();
    assert_eq!(
        durable.apply_finality_json(FINALITY, FINALITY_NOW),
        Err(ChainError::ConflictingFinality)
    );
    drop(durable);
    assert!(matches!(
        DurableIdentityResolver::restore(database.open(), config(), FINALITY_NOW),
        Err(ChainError::ConflictingFinality)
    ));
}

#[test]
fn recovery_rechecks_mpt_even_inside_an_authentic_local_snapshot() {
    let database = TestChainDatabase::new();
    let (mut durable, proof) = synthetic(&database, 1, 1);
    durable
        .accept_proof(proof.agent_id, &proof, BOOTSTRAP_TIME)
        .unwrap();
    let mut candidate = durable.bundle.clone();
    let mut saved: SavedProof = decode(&candidate.proofs[0].proof_cbor).unwrap();
    saved.proof.storage[0].value[31] ^= 1;
    candidate.proofs[0].proof_cbor = encode(&saved).unwrap();
    let plaintext = unprotect_secret(&candidate.state.verified_header_state).unwrap();
    let mut snapshot: LocalSnapshot = decode(&plaintext).unwrap();
    snapshot.rows_hash = rows_hash(&candidate).unwrap();
    candidate.state.verified_header_state = protect_secret(&encode(&snapshot).unwrap()).unwrap();
    durable
        .store
        .save_chain_bundle(
            &candidate,
            Some(&durable.bundle.state.verified_header_state),
        )
        .unwrap();
    drop(durable);
    assert!(matches!(
        DurableIdentityResolver::restore(database.open(), config(), BOOTSTRAP_TIME),
        Err(ChainError::InvalidProof)
    ));
}

#[test]
fn recovery_uses_current_time_for_ttl_and_restores_lru_separately() {
    let database = TestChainDatabase::new();
    let (_, earlier, earlier_proof) =
        proof_fixture_for_agent(registry_values(9, 1, 1), 8, AgentId([2; 32]));
    let mut durable = DurableIdentityResolver::create(
        database.open(),
        config(),
        bootstrapped().with_test_execution(earlier),
        BOOTSTRAP_TIME,
    )
    .unwrap();
    durable
        .accept_proof(earlier_proof.agent_id, &earlier_proof, BOOTSTRAP_TIME)
        .unwrap();
    let (_, mut later, mut later_proof) =
        proof_fixture_for_agent(registry_values(9, 1, 1), 8, AgentId([1; 32]));
    later.timestamp_secs += 12;
    later.beacon_slot += 1;
    later.block_number += 1;
    later_proof.block_number = later.block_number;
    *durable.resolver.light_client_mut() = bootstrapped().with_test_execution(later);
    durable
        .accept_proof(later_proof.agent_id, &later_proof, BOOTSTRAP_TIME + 12)
        .unwrap();
    drop(durable);
    let mut restored =
        DurableIdentityResolver::restore(database.open(), config(), BOOTSTRAP_TIME + 24).unwrap();
    assert!(matches!(
        restored.resolve(later_proof.agent_id, BOOTSTRAP_TIME + 24),
        IdentityResolution::Verified(_)
    ));
    assert!(matches!(
        restored.resolve(earlier_proof.agent_id, BOOTSTRAP_TIME + 24),
        IdentityResolution::Verified(_)
    ));
}

#[test]
fn unregistered_identity_churn_never_creates_persistent_agent_rows() {
    let database = TestChainDatabase::new();
    let (_, finalized, _) = proof_fixture([[0; 32]; 3], 8);
    let mut durable = DurableIdentityResolver::create(
        database.open(),
        config(),
        bootstrapped().with_test_execution(finalized),
        BOOTSTRAP_TIME,
    )
    .unwrap();
    for index in 1..=16 {
        let agent = AgentId([index; 32]);
        let (_, _, proof) = proof_fixture_for_agent([[0; 32]; 3], 8, agent);
        durable.accept_proof(agent, &proof, BOOTSTRAP_TIME).unwrap();
        assert_eq!(
            durable.resolve(agent, BOOTSTRAP_TIME),
            IdentityResolution::Limited(LimitedReason::Unregistered)
        );
    }
    assert!(durable.bundle.proofs.is_empty());
    assert!(durable.bundle.observations.is_empty());
    drop(durable);
    let connection = rusqlite::Connection::open(&database.path).unwrap();
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM agents", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);
    drop(connection);
    let mut restored =
        DurableIdentityResolver::restore(database.open(), config(), BOOTSTRAP_TIME).unwrap();
    assert_eq!(
        restored.resolve(AgentId([16; 32]), BOOTSTRAP_TIME),
        IdentityResolution::Limited(LimitedReason::Unknown)
    );
}
