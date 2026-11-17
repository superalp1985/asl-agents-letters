//! Renewal state-machine tests with real SQLite, local seals, and synthetic MPT
//! proofs. Synthetic heads/checkpoints start after consensus validation; these
//! transitions do not establish BLS or weak-subjectivity interoperability.

use super::*;
use crate::chain::{
    CheckpointV1,
    test_support::{
        BOOTSTRAP_TIME, FINALITY, FINALITY_NOW, TestChainDatabase, bootstrapped,
        proof_fixture_for_agent, registry_values, synced,
    },
};

const ACTIVE: AgentId = AgentId([1; 32]);
const REVOKED: AgentId = AgentId([2; 32]);

fn revoked_values() -> [[u8; 32]; 3] {
    let mut values = registry_values(3, 11, 2);
    values[1] = [24; 32];
    values
}

fn synthetic_proof(
    agent: AgentId,
    values: [[u8; 32]; 3],
    now_secs: u64,
    height_delta: u64,
) -> (FinalizedExecution, IdentityProofV1) {
    let (_, mut head, mut proof) = proof_fixture_for_agent(values, 8, agent);
    head.beacon_slot = tests::config().consensus.current_slot(now_secs).unwrap();
    head.block_number += height_delta;
    head.block_hash = [6 + height_delta as u8; 32];
    head.timestamp_secs = now_secs;
    proof.block_number = head.block_number;
    proof.block_hash = head.block_hash;
    (head, proof)
}

fn seeded(
    database: &TestChainDatabase,
) -> (DurableIdentityResolver, IdentityProofV1, IdentityProofV1) {
    let (head, active) = synthetic_proof(ACTIVE, registry_values(9, 7, 1), BOOTSTRAP_TIME, 0);
    let mut durable = DurableIdentityResolver::create(
        database.open(),
        tests::config(),
        bootstrapped().with_test_execution(head),
        BOOTSTRAP_TIME,
    )
    .unwrap();
    durable
        .accept_proof(ACTIVE, &active, BOOTSTRAP_TIME)
        .unwrap();
    let (head, revoked) = synthetic_proof(REVOKED, revoked_values(), BOOTSTRAP_TIME + 24, 2);
    *durable.resolver.light_client_mut() = bootstrapped().with_test_execution(head);
    durable
        .accept_proof(REVOKED, &revoked, BOOTSTRAP_TIME + 24)
        .unwrap();
    assert_eq!(durable.bundle.observations.len(), 2);
    assert_eq!(durable.bundle.proofs.len(), 2);
    (durable, active, revoked)
}

fn expired_now() -> u64 {
    BOOTSTRAP_TIME + 2 * tests::config().consensus.max_checkpoint_age_secs + 120
}

fn replacement_with_proof(
    agent: AgentId,
    values: [[u8; 32]; 3],
    now_secs: u64,
) -> (EthereumLightClient, IdentityProofV1) {
    let (head, proof) = synthetic_proof(agent, values, now_secs, 100);
    let checkpoint = CheckpointV1 {
        beacon_root: [85; 32],
        slot: head.beacon_slot,
    };
    (
        bootstrapped()
            .with_test_checkpoint(checkpoint)
            .with_test_execution(head),
        proof,
    )
}

fn replacement(now_secs: u64) -> EthereumLightClient {
    replacement_with_proof(ACTIVE, registry_values(9, 7, 1), now_secs).0
}

fn renewed_config(client: &EthereumLightClient) -> DurableResolverConfigV1 {
    let mut config = tests::config();
    config.consensus.checkpoint = client.config().checkpoint;
    config
}

fn persisted(database: &TestChainDatabase) -> ChainBundle {
    database.open().load_chain_bundle(1).unwrap().unwrap()
}

fn assert_rejected_without_write(
    database: &TestChainDatabase,
    previous_config: DurableResolverConfigV1,
    client: EthereumLightClient,
    now_secs: u64,
    expected: ChainError,
) {
    let before = persisted(database);
    let error = DurableIdentityResolver::renew_checkpoint(
        database.open(),
        previous_config,
        client,
        now_secs,
    )
    .err();
    assert_eq!(error, Some(expected));
    assert_eq!(persisted(database), before);
}

#[test]
fn expired_checkpoint_renews_with_observations_intact_and_all_proofs_cleared() {
    let database = TestChainDatabase::new();
    let (mut old, _, _) = seeded(&database);
    let before = persisted(&database);
    let now = expired_now();
    assert!(matches!(
        DurableIdentityResolver::restore(database.open(), tests::config(), now),
        Err(ChainError::ExpiredCheckpoint)
    ));
    assert_eq!(
        old.light_client().finalized(now),
        Err(ChainError::ExpiredCheckpoint)
    );
    assert_eq!(
        old.resolve(ACTIVE, now),
        IdentityResolution::Limited(LimitedReason::ChainUnavailable)
    );
    drop(old);

    let client = replacement(now);
    let expected_head = client.finalized(now).unwrap();
    let config = renewed_config(&client);
    let mut renewed =
        DurableIdentityResolver::renew_checkpoint(database.open(), tests::config(), client, now)
            .unwrap();
    assert_eq!(renewed.bundle.observations, before.observations);
    assert!(renewed.bundle.proofs.is_empty());
    assert_eq!(renewed.config, config);
    assert_eq!(
        renewed.light_client().finalized(now).unwrap(),
        expected_head
    );
    assert_eq!(
        renewed.bundle.state.checkpoint_hash,
        config.consensus.checkpoint.beacon_root
    );
    assert_eq!(renewed.bundle.state.updated_at_ms, now * 1000);
    assert_ne!(
        renewed.bundle.state.verified_header_state,
        before.state.verified_header_state
    );
    assert_eq!(persisted(&database), renewed.bundle);
    assert_eq!(
        renewed.resolve(ACTIVE, now),
        IdentityResolution::Limited(LimitedReason::Unknown)
    );
    assert_eq!(
        renewed.resolve(REVOKED, now),
        IdentityResolution::Limited(LimitedReason::Revoked)
    );
    drop(renewed);

    assert!(matches!(
        DurableIdentityResolver::restore(database.open(), tests::config(), now),
        Err(ChainError::InvalidLocalState)
    ));
    let mut restored = DurableIdentityResolver::restore(database.open(), config, now).unwrap();
    assert_eq!(restored.bundle.observations, before.observations);
    assert!(restored.bundle.proofs.is_empty());
    assert_eq!(
        restored.light_client().finalized(now).unwrap(),
        expected_head
    );
    assert_eq!(
        restored.resolve(ACTIVE, now),
        IdentityResolution::Limited(LimitedReason::Unknown)
    );
    assert_eq!(
        restored.resolve(REVOKED, now),
        IdentityResolution::Limited(LimitedReason::Revoked)
    );
}

#[test]
fn renewal_clears_still_live_proofs_instead_of_only_expired_proofs() {
    let database = TestChainDatabase::new();
    let (old, _, _) = seeded(&database);
    let now = BOOTSTRAP_TIME + 36;
    let before = persisted(&database);
    assert!(
        before
            .proofs
            .iter()
            .all(|row| row.expires_at_ms > now * 1000)
    );
    drop(old);
    let mut renewed = DurableIdentityResolver::renew_checkpoint(
        database.open(),
        tests::config(),
        replacement(now),
        now,
    )
    .unwrap();
    assert_eq!(renewed.bundle.observations, before.observations);
    assert!(renewed.bundle.proofs.is_empty());
    assert!(persisted(&database).proofs.is_empty());
    assert_eq!(
        renewed.resolve(ACTIVE, now),
        IdentityResolution::Limited(LimitedReason::Unknown)
    );
}

#[test]
fn renewal_requires_a_fresh_proof_to_promote_an_active_identity() {
    let database = TestChainDatabase::new();
    let (old, old_proof, _) = seeded(&database);
    drop(old);
    let now = expired_now();
    let (client, proof) = replacement_with_proof(ACTIVE, registry_values(9, 8, 1), now);
    let config = renewed_config(&client);
    let mut renewed =
        DurableIdentityResolver::renew_checkpoint(database.open(), tests::config(), client, now)
            .unwrap();
    assert_eq!(
        renewed.resolve(ACTIVE, now),
        IdentityResolution::Limited(LimitedReason::Unknown)
    );
    let before = persisted(&database);
    assert_eq!(
        renewed.accept_proof(ACTIVE, &old_proof, now),
        Err(ChainError::WrongContext)
    );
    assert_eq!(persisted(&database), before);
    renewed.accept_proof(ACTIVE, &proof, now).unwrap();
    assert!(matches!(
        renewed.resolve(ACTIVE, now),
        IdentityResolution::Verified(identity) if identity.state().sequence == 8
    ));
    assert_eq!(
        renewed.resolve(REVOKED, now),
        IdentityResolution::Limited(LimitedReason::Revoked)
    );
    drop(renewed);
    let mut restored =
        DurableIdentityResolver::restore(database.open(), config.clone(), now + 120).unwrap();
    assert!(matches!(
        restored.resolve(ACTIVE, now + 120),
        IdentityResolution::Verified(_)
    ));
    drop(restored);
    let mut expired = DurableIdentityResolver::restore(database.open(), config, now + 121).unwrap();
    assert!(!matches!(
        expired.resolve(ACTIVE, now + 121),
        IdentityResolution::Verified(_)
    ));
}

#[test]
fn retained_observations_reject_fresh_sequence_state_and_revocation_rollbacks() {
    let mut changed_controller = registry_values(10, 7, 1);
    changed_controller[1] = [42; 32];
    let mut changed_commitment = registry_values(9, 7, 1);
    changed_commitment[1] = [43; 32];
    for (label, agent, values) in [
        ("lower sequence", ACTIVE, registry_values(9, 6, 1)),
        ("same-sequence controller", ACTIVE, changed_controller),
        ("same-sequence commitment", ACTIVE, changed_commitment),
        ("revocation reversal", REVOKED, registry_values(3, 12, 1)),
    ] {
        let database = TestChainDatabase::new();
        let (old, _, _) = seeded(&database);
        drop(old);
        let now = expired_now();
        let (client, proof) = replacement_with_proof(agent, values, now);
        let config = renewed_config(&client);
        let renewed = DurableIdentityResolver::renew_checkpoint(
            database.open(),
            tests::config(),
            client,
            now,
        )
        .unwrap();
        drop(renewed);
        let mut restored = DurableIdentityResolver::restore(database.open(), config, now).unwrap();
        let before = persisted(&database);
        assert_eq!(
            restored.accept_proof(agent, &proof, now),
            Err(ChainError::Rollback),
            "{label}"
        );
        assert_eq!(restored.bundle, before, "{label}");
        assert_eq!(persisted(&database), before, "{label}");
        assert_eq!(
            restored.resolve(ACTIVE, now),
            IdentityResolution::Limited(LimitedReason::Unknown),
            "{label}"
        );
        assert_eq!(
            restored.resolve(REVOKED, now),
            IdentityResolution::Limited(LimitedReason::Revoked),
            "{label}"
        );
    }
}

#[test]
fn missing_previous_snapshot_is_not_silently_created_by_renewal() {
    let database = TestChainDatabase::new();
    assert!(database.open().load_chain_bundle(1).unwrap().is_none());
    assert!(matches!(
        DurableIdentityResolver::renew_checkpoint(
            database.open(),
            tests::config(),
            replacement(expired_now()),
            expired_now()
        ),
        Err(ChainError::InvalidLocalState)
    ));
    assert!(database.open().load_chain_bundle(1).unwrap().is_none());
}

#[test]
fn expired_prior_snapshot_and_row_tampering_cannot_be_bypassed_by_renewal() {
    for statement in [
        "UPDATE chain_state_cache SET verified_header_state = zeroblob(length(verified_header_state))",
        "UPDATE identity_proof_cache SET proof_cbor = X'80'",
        "UPDATE identity_registry_states SET sequence = sequence + 1",
        "UPDATE identity_registry_states SET controller_address = zeroblob(20)",
        "UPDATE identity_registry_states SET state_commitment = zeroblob(32)",
        "UPDATE identity_registry_states SET verified_at_ms = verified_at_ms + 1",
        "DELETE FROM identity_registry_states",
        "UPDATE chain_state_cache SET checkpoint_hash = zeroblob(32)",
        "UPDATE chain_state_cache SET execution_state_root = zeroblob(32)",
    ] {
        let database = TestChainDatabase::new();
        let (old, _, _) = seeded(&database);
        drop(old);
        let connection = rusqlite::Connection::open(&database.path).unwrap();
        connection.execute_batch(statement).unwrap();
        drop(connection);
        assert_rejected_without_write(
            &database,
            tests::config(),
            replacement(expired_now()),
            expired_now(),
            ChainError::InvalidLocalState,
        );
    }
}

fn reseal_snapshot(database: &TestChainDatabase, change: impl FnOnce(&mut LocalSnapshot)) {
    let mut bundle = persisted(database);
    let previous = bundle.state.verified_header_state.clone();
    let plaintext = unprotect_secret(&previous).unwrap();
    let mut snapshot: LocalSnapshot = decode(&plaintext).unwrap();
    change(&mut snapshot);
    bundle.state.verified_header_state = protect_secret(&encode(&snapshot).unwrap()).unwrap();
    database
        .open()
        .save_chain_bundle(&bundle, Some(&previous))
        .unwrap();
}

#[test]
fn authenticated_but_invalid_prior_metadata_is_rejected() {
    for change in 0..4 {
        let database = TestChainDatabase::new();
        let (old, _, _) = seeded(&database);
        let mut mismatched_head = old.light_client().observed_execution().unwrap().clone();
        mismatched_head.block_number += 1;
        drop(old);
        reseal_snapshot(&database, |snapshot| match change {
            0 => snapshot.domain = "different local domain".to_owned(),
            1 => snapshot.consensus_json = b"{}".to_vec(),
            2 => {
                snapshot.consensus_json = bootstrapped()
                    .with_test_execution(mismatched_head)
                    .local_state()
                    .unwrap();
            }
            3 => snapshot.config.consensus.genesis_validators_root[0] ^= 1,
            _ => unreachable!(),
        });
        assert_rejected_without_write(
            &database,
            tests::config(),
            replacement(expired_now()),
            expired_now(),
            ChainError::InvalidLocalState,
        );
    }
}

type ConfigMutation = (&'static str, fn(&mut DurableResolverConfigV1));

fn immutable_config_mutations() -> Vec<ConfigMutation> {
    vec![
        ("consensus version", |c| c.consensus.version += 1),
        ("chain ID", |c| c.consensus.chain_id += 1),
        ("genesis time", |c| c.consensus.genesis_time_secs -= 1),
        ("genesis root", |c| {
            c.consensus.genesis_validators_root[0] ^= 1
        }),
        ("slot duration", |c| c.consensus.seconds_per_slot += 1),
        ("genesis fork epoch", |c| {
            c.consensus.forks.genesis.epoch += 1
        }),
        ("genesis fork version", |c| {
            c.consensus.forks.genesis.version[0] ^= 1
        }),
        ("altair epoch", |c| c.consensus.forks.altair.epoch += 1),
        ("altair version", |c| {
            c.consensus.forks.altair.version[0] ^= 1
        }),
        ("bellatrix epoch", |c| {
            c.consensus.forks.bellatrix.epoch += 1
        }),
        ("bellatrix version", |c| {
            c.consensus.forks.bellatrix.version[0] ^= 1
        }),
        ("capella epoch", |c| c.consensus.forks.capella.epoch += 1),
        ("capella version", |c| {
            c.consensus.forks.capella.version[0] ^= 1
        }),
        ("deneb epoch", |c| c.consensus.forks.deneb.epoch += 1),
        ("deneb version", |c| c.consensus.forks.deneb.version[0] ^= 1),
        ("electra epoch", |c| c.consensus.forks.electra.epoch += 1),
        ("electra version", |c| {
            c.consensus.forks.electra.version[0] ^= 1
        }),
        ("fulu epoch", |c| c.consensus.forks.fulu.epoch += 1),
        ("fulu version", |c| c.consensus.forks.fulu.version[0] ^= 1),
        ("gloas epoch", |c| c.consensus.forks.gloas.epoch -= 1),
        ("gloas version", |c| c.consensus.forks.gloas.version[0] ^= 1),
        ("checkpoint age", |c| {
            c.consensus.max_checkpoint_age_secs -= 12
        }),
        ("finality age", |c| c.consensus.max_finality_age_secs -= 12),
        ("deployment version", |c| c.deployment.version += 1),
        ("deployment chain", |c| c.deployment.chain_id += 1),
        ("registry address", |c| c.deployment.address[0] ^= 1),
        ("registry code hash", |c| {
            c.deployment.runtime_code_hash[0] ^= 1
        }),
        ("cache age", |c| c.max_cache_age_secs += 1),
        ("cache capacity", |c| c.cache_capacity += 1),
    ]
}

#[test]
fn renewal_authenticates_the_exact_previous_configuration_in_every_family() {
    let database = TestChainDatabase::new();
    let (old, _, _) = seeded(&database);
    drop(old);
    let now = expired_now();
    for (label, mutate) in immutable_config_mutations() {
        let mut changed = tests::config();
        mutate(&mut changed);
        assert_ne!(changed, tests::config(), "{label}");
        assert_rejected_without_write(
            &database,
            changed,
            replacement(now),
            now,
            ChainError::InvalidLocalState,
        );
    }
    for change_root in [false, true] {
        let mut changed = tests::config();
        if change_root {
            changed.consensus.checkpoint.beacon_root[0] ^= 1;
        } else {
            changed.consensus.checkpoint.slot += 1;
        }
        assert_rejected_without_write(
            &database,
            changed,
            replacement(now),
            now,
            ChainError::InvalidLocalState,
        );
    }
}

#[test]
fn replacement_consensus_may_change_only_the_checkpoint() {
    let database = TestChainDatabase::new();
    let (old, _, _) = seeded(&database);
    drop(old);
    let now = expired_now();
    let client = replacement(now);
    let base = renewed_config(&client);
    let bytes = client.local_state().unwrap();
    for (label, mutate) in immutable_config_mutations() {
        let mut changed = base.clone();
        mutate(&mut changed);
        if changed.consensus == base.consensus || changed.consensus.version != 1 {
            continue;
        }
        // Decode only synthetic post-consensus state under the alternative
        // configuration. This does not bootstrap an alternative real network.
        let decode_time = changed
            .consensus
            .slot_time(base.consensus.checkpoint.slot)
            .unwrap();
        let changed_client =
            EthereumLightClient::from_local_state(changed.consensus, &bytes, decode_time)
                .unwrap_or_else(|error| panic!("{label}: {error}"));
        assert_rejected_without_write(
            &database,
            tests::config(),
            changed_client,
            now,
            ChainError::InvalidConfiguration,
        );
    }
}

#[test]
fn anchor_must_exceed_both_the_previous_checkpoint_and_saved_beacon_head() {
    let database = TestChainDatabase::new();
    let (old, _, _) = seeded(&database);
    drop(old);
    let previous_slot = tests::config().consensus.checkpoint.slot;
    let now = BOOTSTRAP_TIME + 36;
    for slot in [
        previous_slot - 1,
        previous_slot,
        previous_slot + 1,
        previous_slot + 2,
    ] {
        let client = replacement(now).with_test_checkpoint(CheckpointV1 {
            beacon_root: [85; 32],
            slot,
        });
        assert_rejected_without_write(
            &database,
            tests::config(),
            client,
            now,
            ChainError::Rollback,
        );
    }
}

#[test]
fn stale_future_and_expired_replacements_do_not_replace_the_old_database() {
    let database = TestChainDatabase::new();
    let (old, _, _) = seeded(&database);
    drop(old);
    let config = tests::config();
    let now = expired_now();
    for (label, slot_age, execution_time, expected) in [
        (
            "stale beacon",
            config.consensus.max_finality_age_secs + 12,
            now,
            ChainError::StaleFinality,
        ),
        (
            "stale execution",
            0,
            now - config.consensus.max_finality_age_secs - 1,
            ChainError::StaleFinality,
        ),
        ("future execution", 0, now + 1, ChainError::ClockBeforeState),
        (
            "expired checkpoint",
            config.consensus.max_checkpoint_age_secs + 12,
            now,
            ChainError::ExpiredCheckpoint,
        ),
    ] {
        let mut head = replacement(now).observed_execution().unwrap().clone();
        head.beacon_slot -= slot_age / config.consensus.seconds_per_slot;
        head.timestamp_secs = execution_time;
        let client = replacement(now)
            .with_test_checkpoint(CheckpointV1 {
                beacon_root: [85; 32],
                slot: head.beacon_slot,
            })
            .with_test_execution(head);
        assert_eq!(client.finalized(now), Err(expected), "{label}");
        assert_rejected_without_write(&database, config.clone(), client, now, expected);
    }
    let mut future = replacement(now).observed_execution().unwrap().clone();
    future.beacon_slot += 1;
    let client = replacement(now)
        .with_test_checkpoint(CheckpointV1 {
            beacon_root: [85; 32],
            slot: future.beacon_slot,
        })
        .with_test_execution(future);
    assert_rejected_without_write(&database, config, client, now, ChainError::ClockBeforeState);
}

#[test]
fn gloas_replacement_requires_the_hash_bound_execution_header() {
    let database = TestChainDatabase::new();
    let (old, _, _) = seeded(&database);
    drop(old);
    let now = expired_now();
    let execution = alloy_consensus::Header {
        number: 17_883_434,
        timestamp: now + 12,
        state_root: alloy_primitives::B256::repeat_byte(4),
        ..Default::default()
    };
    let client = replacement(now).with_test_gloas_execution(&execution);
    assert_eq!(
        client.finalized(now + 12),
        Err(ChainError::ExecutionHeaderRequired)
    );
    assert_rejected_without_write(
        &database,
        tests::config(),
        client.clone(),
        now + 12,
        ChainError::ExecutionHeaderRequired,
    );
    let mut bound = client;
    bound
        .supply_execution_header(&alloy_rlp::encode(&execution), now + 12)
        .unwrap();
    let config = renewed_config(&bound);
    let renewed = DurableIdentityResolver::renew_checkpoint(
        database.open(),
        tests::config(),
        bound,
        now + 12,
    )
    .unwrap();
    assert_eq!(
        renewed
            .light_client()
            .finalized(now + 12)
            .unwrap()
            .state_root(),
        [4; 32]
    );
    drop(renewed);
    assert!(DurableIdentityResolver::restore(database.open(), config, now + 12).is_ok());
}

#[test]
fn expired_old_gloas_snapshot_retains_its_saved_header_and_timestamp_floor() {
    let database = TestChainDatabase::new();
    let (mut old, _, _) = seeded(&database);
    let execution = alloy_consensus::Header {
        number: 17_883_336,
        timestamp: BOOTSTRAP_TIME + 36,
        state_root: alloy_primitives::B256::repeat_byte(4),
        ..Default::default()
    };
    let header_rlp = alloy_rlp::encode(&execution);
    *old.resolver.light_client_mut() = old
        .light_client()
        .clone()
        .with_test_gloas_execution(&execution);
    old.supply_execution_header(&header_rlp, BOOTSTRAP_TIME + 36)
        .unwrap();
    let before = persisted(&database);

    // A fresh replacement with a lower execution timestamp isolates this check
    // from expiry/freshness rejection before exercising expired recovery below.
    let mut earlier = replacement(BOOTSTRAP_TIME + 48)
        .observed_execution()
        .unwrap()
        .clone();
    earlier.timestamp_secs = BOOTSTRAP_TIME + 35;
    let earlier_client = replacement(BOOTSTRAP_TIME + 48).with_test_execution(earlier);
    assert!(earlier_client.finalized(BOOTSTRAP_TIME + 48).is_ok());
    assert_rejected_without_write(
        &database,
        tests::config(),
        earlier_client,
        BOOTSTRAP_TIME + 48,
        ChainError::Rollback,
    );

    let now = expired_now();
    let (_, snapshot) = authenticated_snapshot(&database.open(), &tests::config(), now).unwrap();
    let (slot, floor) = EthereumLightClient::checkpoint_renewal_floor(
        tests::config().consensus,
        &snapshot.consensus_json,
    )
    .unwrap();
    assert_eq!(slot, 7_069_379);
    let floor = floor.expect("the saved hash-bound Gloas header supplies the historical floor");
    assert_eq!(floor.block_number(), 17_883_336);
    assert_eq!(floor.block_hash(), execution.hash_slow().0);
    assert_eq!(floor.state_root(), [4; 32]);
    assert_eq!(floor.timestamp_secs(), BOOTSTRAP_TIME + 36);
    assert!(matches!(
        DurableIdentityResolver::restore(database.open(), tests::config(), now),
        Err(ChainError::ExpiredCheckpoint)
    ));
    assert!(matches!(
        EthereumLightClient::from_local_state(
            tests::config().consensus,
            &snapshot.consensus_json,
            now
        ),
        Err(ChainError::ExpiredCheckpoint)
    ));
    assert_eq!(
        old.supply_execution_header(&header_rlp, now),
        Err(ChainError::ExpiredCheckpoint)
    );
    assert_eq!(persisted(&database), before);
    drop(old);

    let client = replacement(now);
    let config = renewed_config(&client);
    let renewed =
        DurableIdentityResolver::renew_checkpoint(database.open(), tests::config(), client, now)
            .unwrap();
    assert_eq!(renewed.bundle.observations, before.observations);
    assert!(renewed.bundle.proofs.is_empty());
    drop(renewed);
    let mut restored = DurableIdentityResolver::restore(database.open(), config, now).unwrap();
    assert_eq!(
        restored.resolve(ACTIVE, now),
        IdentityResolution::Limited(LimitedReason::Unknown)
    );
    assert_eq!(
        restored.resolve(REVOKED, now),
        IdentityResolution::Limited(LimitedReason::Revoked)
    );
}

#[test]
fn old_gloas_without_a_projection_uses_the_persisted_execution_floors() {
    let database = TestChainDatabase::new();
    let (mut old, _, _) = seeded(&database);
    let execution = alloy_consensus::Header {
        number: 17_883_336,
        timestamp: BOOTSTRAP_TIME + 36,
        state_root: alloy_primitives::B256::repeat_byte(4),
        ..Default::default()
    };
    // Model the already-verified Gloas transition awaiting its full execution
    // header. commit must retain the last projected execution database rows.
    let pending = make_resolver(
        &tests::config(),
        old.light_client()
            .clone()
            .with_test_gloas_execution(&execution),
    )
    .unwrap();
    old.commit(pending, old.bundle.clone(), BOOTSTRAP_TIME + 36)
        .unwrap();
    assert!(old.light_client().observed_execution().is_none());
    let before = persisted(&database);
    assert_eq!(before.state.finalized_height, 17_883_335);
    drop(old);

    let now = expired_now();
    let (_, snapshot) = authenticated_snapshot(&database.open(), &tests::config(), now).unwrap();
    let (slot, floor) = EthereumLightClient::checkpoint_renewal_floor(
        tests::config().consensus,
        &snapshot.consensus_json,
    )
    .unwrap();
    assert_eq!(slot, 7_069_379);
    assert!(floor.is_none());
    assert!(matches!(
        DurableIdentityResolver::restore(database.open(), tests::config(), now),
        Err(ChainError::ExpiredCheckpoint)
    ));

    for change in 0..3 {
        let mut head = replacement(now).observed_execution().unwrap().clone();
        head.block_number = before.state.finalized_height;
        head.block_hash = before.state.finalized_block_hash;
        head.state_root = before.state.execution_state_root;
        match change {
            0 => head.block_number -= 1,
            1 => head.block_hash[0] ^= 1,
            2 => head.state_root[0] ^= 1,
            _ => unreachable!(),
        }
        assert_rejected_without_write(
            &database,
            tests::config(),
            replacement(now).with_test_execution(head),
            now,
            ChainError::Rollback,
        );
    }

    let mut same_execution = replacement(now).observed_execution().unwrap().clone();
    same_execution.block_number = before.state.finalized_height;
    same_execution.block_hash = before.state.finalized_block_hash;
    same_execution.state_root = before.state.execution_state_root;
    let client = replacement(now).with_test_execution(same_execution);
    let config = renewed_config(&client);
    let renewed =
        DurableIdentityResolver::renew_checkpoint(database.open(), tests::config(), client, now)
            .unwrap();
    assert_eq!(
        renewed.bundle.state.finalized_height,
        before.state.finalized_height
    );
    assert_eq!(renewed.bundle.observations, before.observations);
    assert!(renewed.bundle.proofs.is_empty());
    drop(renewed);
    let restored = DurableIdentityResolver::restore(database.open(), config, now).unwrap();
    assert_eq!(restored.bundle, persisted(&database));
}

#[test]
fn execution_height_hash_root_and_timestamp_floors_survive_renewal() {
    let database = TestChainDatabase::new();
    let (old, _, _) = seeded(&database);
    let previous_head = old.light_client().observed_execution().unwrap().clone();
    drop(old);
    let now = BOOTSTRAP_TIME + 36;
    for change in 0..4 {
        let mut head = replacement(now).observed_execution().unwrap().clone();
        match change {
            0 => head.block_number = previous_head.block_number - 1,
            1 => {
                head.block_number = previous_head.block_number;
                head.state_root = previous_head.state_root;
                head.block_hash = previous_head.block_hash;
                head.block_hash[0] ^= 1;
            }
            2 => {
                head.block_number = previous_head.block_number;
                head.block_hash = previous_head.block_hash;
                head.state_root = previous_head.state_root;
                head.state_root[0] ^= 1;
            }
            3 => head.timestamp_secs = previous_head.timestamp_secs - 1,
            _ => unreachable!(),
        }
        let client = replacement(now).with_test_execution(head);
        assert!(client.finalized(now).is_ok());
        assert_rejected_without_write(
            &database,
            tests::config(),
            client,
            now,
            ChainError::Rollback,
        );
    }
}

#[test]
fn identical_execution_at_a_strictly_newer_anchor_is_allowed() {
    let database = TestChainDatabase::new();
    let (old, _, _) = seeded(&database);
    let mut head = old.light_client().observed_execution().unwrap().clone();
    let before = persisted(&database);
    drop(old);
    let now = BOOTSTRAP_TIME + 36;
    head.beacon_slot = tests::config().consensus.current_slot(now).unwrap();
    let renewed = DurableIdentityResolver::renew_checkpoint(
        database.open(),
        tests::config(),
        replacement(now).with_test_execution(head),
        now,
    )
    .unwrap();
    assert_eq!(
        renewed.bundle.state.finalized_height,
        before.state.finalized_height
    );
    assert_eq!(
        renewed.bundle.state.finalized_block_hash,
        before.state.finalized_block_hash
    );
    assert_eq!(
        renewed.bundle.state.execution_state_root,
        before.state.execution_state_root
    );
    assert_eq!(renewed.bundle.observations, before.observations);
    assert!(renewed.bundle.proofs.is_empty());
}

#[test]
fn renewal_rejects_local_clock_rollback_before_the_saved_write() {
    let database = TestChainDatabase::new();
    let (old, _, _) = seeded(&database);
    drop(old);
    assert_rejected_without_write(
        &database,
        tests::config(),
        replacement(BOOTSTRAP_TIME + 36),
        BOOTSTRAP_TIME + 23,
        ChainError::InvalidLocalState,
    );
}

#[test]
fn saved_finality_conflict_remains_locked_even_after_expiry_and_renewal() {
    let database = TestChainDatabase::new();
    let mut old = DurableIdentityResolver::create(
        database.open(),
        tests::config(),
        synced().with_test_beacon_conflict(),
        FINALITY_NOW,
    )
    .unwrap();
    assert_eq!(
        old.apply_finality_json(FINALITY, FINALITY_NOW),
        Err(ChainError::ConflictingFinality)
    );
    drop(old);
    assert_rejected_without_write(
        &database,
        tests::config(),
        replacement(expired_now()),
        expired_now(),
        ChainError::ConflictingFinality,
    );
    assert!(matches!(
        DurableIdentityResolver::restore(database.open(), tests::config(), expired_now()),
        Err(ChainError::ConflictingFinality)
    ));
}

#[test]
fn late_sql_failure_rolls_back_the_new_seal_observations_and_proof_deletion() {
    let database = TestChainDatabase::new();
    let (old, _, _) = seeded(&database);
    drop(old);
    let before = persisted(&database);
    let connection = rusqlite::Connection::open(&database.path).unwrap();
    // save_chain_bundle has already written the header and observations before
    // deleting proofs. Abort after that deletion to exercise transaction rollback.
    connection
        .execute_batch(
            "CREATE TRIGGER reject_renewal_delete AFTER DELETE ON identity_proof_cache
             BEGIN SELECT RAISE(ABORT, 'synthetic late renewal failure'); END;",
        )
        .unwrap();
    assert_rejected_without_write(
        &database,
        tests::config(),
        replacement(expired_now()),
        expired_now(),
        ChainError::StorageUnavailable,
    );
    assert_eq!(persisted(&database), before);
    assert!(
        DurableIdentityResolver::restore(database.open(), tests::config(), BOOTSTRAP_TIME + 36)
            .is_ok()
    );
    connection
        .execute_batch("DROP TRIGGER reject_renewal_delete")
        .unwrap();
    drop(connection);
    let renewed = DurableIdentityResolver::renew_checkpoint(
        database.open(),
        tests::config(),
        replacement(expired_now()),
        expired_now(),
    )
    .unwrap();
    assert_eq!(renewed.bundle.observations, before.observations);
    assert!(renewed.bundle.proofs.is_empty());
}

#[test]
fn unreadable_storage_does_not_rebuild_or_replace_the_saved_snapshot() {
    let database = TestChainDatabase::new();
    let (old, _, _) = seeded(&database);
    drop(old);
    let before = persisted(&database);
    let connection = rusqlite::Connection::open(&database.path).unwrap();
    connection
        .execute_batch("ALTER TABLE identity_proof_cache RENAME TO unavailable_proofs")
        .unwrap();
    assert!(matches!(
        DurableIdentityResolver::renew_checkpoint(
            database.open(),
            tests::config(),
            replacement(expired_now()),
            expired_now()
        ),
        Err(ChainError::StorageUnavailable)
    ));
    connection
        .execute_batch("ALTER TABLE unavailable_proofs RENAME TO identity_proof_cache")
        .unwrap();
    drop(connection);
    assert_eq!(persisted(&database), before);
}

#[test]
fn stale_pre_renewal_writer_cannot_overwrite_the_renewed_snapshot() {
    let database = TestChainDatabase::new();
    let (mut stale, _, revoked) = seeded(&database);
    let now = BOOTSTRAP_TIME + 36;
    let client = replacement(now);
    let config = renewed_config(&client);
    let renewed =
        DurableIdentityResolver::renew_checkpoint(database.open(), tests::config(), client, now)
            .unwrap();
    let committed = persisted(&database);
    assert_eq!(
        stale.accept_proof(REVOKED, &revoked, now),
        Err(ChainError::StorageUnavailable)
    );
    assert_eq!(
        stale.resolve(ACTIVE, now),
        IdentityResolution::Limited(LimitedReason::ChainUnavailable)
    );
    assert_eq!(persisted(&database), committed);
    assert_rejected_without_write(
        &database,
        tests::config(),
        replacement(now + 12),
        now + 12,
        ChainError::InvalidLocalState,
    );
    drop(stale);
    drop(renewed);
    let restored = DurableIdentityResolver::restore(database.open(), config, now).unwrap();
    assert_eq!(restored.bundle, committed);
}
