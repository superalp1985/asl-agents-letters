use std::{
    ffi::OsString,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use super::*;
use crate::open_store;

static NEXT_DATABASE_ID: AtomicU64 = AtomicU64::new(1);

struct TestDatabase(PathBuf);

impl TestDatabase {
    fn new() -> Self {
        let directory = std::env::var_os("ASL_TEST_FIXTURE_BASE")
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::temp_dir().join("asl-test-fs"))
            .join("asl-store");
        fs::create_dir_all(&directory).unwrap();
        let id = NEXT_DATABASE_ID.fetch_add(1, Ordering::Relaxed);
        Self(directory.join(format!("chain-{}-{id}.sqlite3", std::process::id())))
    }

    fn open(&self) -> Store {
        open_store(&self.0).unwrap()
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
        for suffix in ["-wal", "-shm"] {
            let mut sidecar = OsString::from(self.0.as_os_str());
            sidecar.push(suffix);
            let _ = fs::remove_file(PathBuf::from(sidecar));
        }
    }
}

fn agent(index: u64) -> AgentId {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&index.to_be_bytes());
    AgentId(bytes)
}

fn observation(index: u64, chain_id: u64) -> IdentityObservationRow {
    IdentityObservationRow {
        agent_id: agent(index),
        chain_id,
        controller_address: [3; 20],
        state_commitment: [4; 32],
        sequence: 2,
        status: ObservationStatus::Active,
        finalized_height: 90,
        storage_proof_hash: [5; 32],
        verified_at_ms: 1_000,
    }
}

fn proof(index: u64, chain_id: u64) -> IdentityProofRow {
    IdentityProofRow {
        agent_id: agent(index),
        chain_id,
        finalized_height: 90,
        proof_cbor: vec![0xa1, 0x00, 0x01],
        expires_at_ms: 2_000,
        last_used_ms: 1_000,
    }
}

fn bundle(chain_id: u64) -> ChainBundle {
    ChainBundle {
        state: ChainStateRow {
            chain_id,
            registry_address: [1; 20],
            registry_code_hash: [2; 32],
            finalized_height: 100,
            finalized_block_hash: [6; 32],
            execution_state_root: [7; 32],
            checkpoint_hash: [8; 32],
            verified_header_state: vec![9, 10, 11],
            updated_at_ms: 1_000,
        },
        observations: vec![observation(1, chain_id)],
        proofs: vec![proof(1, chain_id)],
    }
}

fn advance(previous: &ChainBundle) -> ChainBundle {
    let mut next = previous.clone();
    next.state.finalized_height += 10;
    next.state.finalized_block_hash[0] ^= 1;
    next.state.execution_state_root[0] ^= 1;
    next.state.verified_header_state.push(12);
    next.state.updated_at_ms += 1;
    next
}

fn assert_unchanged(store: &Store, expected: &ChainBundle) {
    assert_eq!(
        store.load_chain_bundle(expected.state.chain_id).unwrap(),
        Some(expected.clone())
    );
}

#[test]
fn records_have_the_required_value_and_serialization_traits() {
    fn assert_traits<T>()
    where
        T: Clone + std::fmt::Debug + Eq + PartialEq + Serialize + for<'de> Deserialize<'de>,
    {
    }
    assert_traits::<ChainStateRow>();
    assert_traits::<IdentityObservationRow>();
    assert_traits::<ObservationStatus>();
    assert_traits::<IdentityProofRow>();
    assert_traits::<ChainBundle>();
}

#[test]
fn roundtrips_real_file_after_reopen_with_canonical_ids_and_sorted_rows() {
    let database = TestDatabase::new();
    let mut expected = bundle(1);
    expected.observations = [u64::MAX, 0, 1, 256]
        .map(|index| observation(index, 1))
        .to_vec();
    expected.proofs = [u64::MAX, 0, 1, 256].map(|index| proof(index, 1)).to_vec();
    expected.observations[0].status = ObservationStatus::Revoked;
    {
        let mut store = database.open();
        assert_eq!(store.load_chain_bundle(1).unwrap(), None);
        store.save_chain_bundle(&expected, None).unwrap();
        let stored: String = store
            .connection
            .query_row(
                "SELECT agent_id FROM identity_registry_states WHERE status = 'revoked'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored, agent_text(agent(u64::MAX)));
    }
    expected
        .observations
        .sort_by_key(|observation| agent_text(observation.agent_id));
    expected
        .proofs
        .sort_by_key(|proof| agent_text(proof.agent_id));
    let store = database.open();
    assert_unchanged(&store, &expected);
    let mut check = store
        .connection
        .prepare("PRAGMA foreign_key_check")
        .unwrap();
    assert!(!check.exists([]).unwrap());
}

#[test]
fn cas_requires_first_create_then_exact_previous_state_and_rejects_stale_writers() {
    let database = TestDatabase::new();
    let mut first = database.open();
    let mut second = database.open();
    let initial = bundle(1);
    assert!(
        first
            .save_chain_bundle(&initial, Some(&initial.state.verified_header_state))
            .is_err()
    );
    assert_eq!(first.load_chain_bundle(1).unwrap(), None);
    first.save_chain_bundle(&initial, None).unwrap();
    let second_view = second.load_chain_bundle(1).unwrap().unwrap();
    let next = advance(&initial);
    assert!(first.save_chain_bundle(&next, None).is_err());
    assert!(first.save_chain_bundle(&next, Some(&[])).is_err());
    first
        .save_chain_bundle(&next, Some(&initial.state.verified_header_state))
        .unwrap();
    assert!(
        second
            .save_chain_bundle(
                &advance(&second_view),
                Some(&second_view.state.verified_header_state)
            )
            .is_err()
    );
    assert_unchanged(&second, &next);
}

#[test]
fn empty_header_state_still_distinguishes_creation_from_cas_update() {
    let database = TestDatabase::new();
    let mut store = database.open();
    let mut initial = bundle(1);
    initial.state.verified_header_state.clear();
    assert!(store.save_chain_bundle(&initial, Some(&[])).is_err());
    store.save_chain_bundle(&initial, None).unwrap();
    let next = advance(&initial);
    assert!(store.save_chain_bundle(&next, None).is_err());
    store.save_chain_bundle(&next, Some(&[])).unwrap();
    assert_unchanged(&store, &next);
}

#[test]
fn rejects_registry_changes_height_rollback_and_same_height_finality_conflicts() {
    let database = TestDatabase::new();
    let mut store = database.open();
    let initial = bundle(1);
    store.save_chain_bundle(&initial, None).unwrap();
    let mutations: [fn(&mut ChainBundle); 5] = [
        |bundle| bundle.state.registry_address[0] ^= 1,
        |bundle| bundle.state.registry_code_hash[0] ^= 1,
        |bundle| bundle.state.finalized_height -= 1,
        |bundle| bundle.state.finalized_block_hash[0] ^= 1,
        |bundle| bundle.state.execution_state_root[0] ^= 1,
    ];
    for mutate in mutations {
        let mut invalid = initial.clone();
        mutate(&mut invalid);
        assert!(
            store
                .save_chain_bundle(&invalid, Some(&initial.state.verified_header_state))
                .is_err()
        );
        assert_unchanged(&store, &initial);
    }
    let mut same_height = initial.clone();
    same_height.state.verified_header_state.push(1);
    same_height.state.checkpoint_hash[0] ^= 1;
    store
        .save_chain_bundle(&same_height, Some(&initial.state.verified_header_state))
        .unwrap();
    assert_unchanged(&store, &same_height);
}

#[test]
fn rejects_observation_removal_sequence_height_rollback_and_same_sequence_changes() {
    let database = TestDatabase::new();
    let mut store = database.open();
    let initial = bundle(1);
    store.save_chain_bundle(&initial, None).unwrap();
    let mutations: [fn(&mut ChainBundle); 6] = [
        |bundle| {
            bundle.observations.clear();
            bundle.proofs.clear();
        },
        |bundle| bundle.observations[0].sequence -= 1,
        |bundle| bundle.observations[0].finalized_height -= 1,
        |bundle| bundle.observations[0].controller_address[0] ^= 1,
        |bundle| bundle.observations[0].state_commitment[0] ^= 1,
        |bundle| bundle.observations[0].status = ObservationStatus::Revoked,
    ];
    for mutate in mutations {
        let mut invalid = advance(&initial);
        mutate(&mut invalid);
        assert!(
            store
                .save_chain_bundle(&invalid, Some(&initial.state.verified_header_state))
                .is_err()
        );
        assert_unchanged(&store, &initial);
    }
}

#[test]
fn accepts_monotonic_updates_and_never_reverses_revocation_after_cache_eviction() {
    let database = TestDatabase::new();
    let initial = bundle(1);
    let mut revoked = advance(&initial);
    revoked.observations[0].sequence += 1;
    revoked.observations[0].status = ObservationStatus::Revoked;
    revoked.observations[0].controller_address[0] ^= 1;
    revoked.observations[0].state_commitment[0] ^= 1;
    revoked.observations[0].finalized_height = 105;
    revoked.proofs.clear();
    {
        let mut store = database.open();
        store.save_chain_bundle(&initial, None).unwrap();
        store
            .save_chain_bundle(&revoked, Some(&initial.state.verified_header_state))
            .unwrap();
    }
    let mut store = database.open();
    let mut reversed = advance(&revoked);
    reversed.observations[0].sequence += 1;
    reversed.observations[0].status = ObservationStatus::Active;
    reversed.observations[0].finalized_height = 115;
    assert!(
        store
            .save_chain_bundle(&reversed, Some(&revoked.state.verified_header_state))
            .is_err()
    );
    assert_unchanged(&store, &revoked);
}

#[test]
fn permits_old_observations_without_proofs_and_refreshing_same_sequence_evidence() {
    let database = TestDatabase::new();
    let mut store = database.open();
    let initial = bundle(1);
    store.save_chain_bundle(&initial, None).unwrap();
    let mut next = advance(&initial);
    next.proofs.clear();
    next.observations.push(observation(2, 1));
    store
        .save_chain_bundle(&next, Some(&initial.state.verified_header_state))
        .unwrap();
    let mut refreshed = advance(&next);
    refreshed.observations[0].finalized_height = 115;
    refreshed.observations[0].storage_proof_hash[0] ^= 1;
    refreshed.observations[0].verified_at_ms += 10;
    store
        .save_chain_bundle(&refreshed, Some(&next.state.verified_header_state))
        .unwrap();
    assert_unchanged(&store, &refreshed);
}

#[test]
fn replaces_only_target_chain_proofs_and_rejects_agent_reassignment_across_chains() {
    let database = TestDatabase::new();
    let mut store = database.open();
    let first = bundle(1);
    let mut second = bundle(2);
    second.observations = vec![observation(2, 2)];
    second.proofs = vec![proof(2, 2)];
    store.save_chain_bundle(&first, None).unwrap();
    store.save_chain_bundle(&second, None).unwrap();
    let mut next = advance(&first);
    next.proofs.clear();
    store
        .save_chain_bundle(&next, Some(&first.state.verified_header_state))
        .unwrap();
    assert_unchanged(&store, &second);
    assert_unchanged(&store, &next);
    let mut collision = advance(&second);
    collision.observations.push(observation(1, 2));
    collision.proofs.push(proof(1, 2));
    assert!(
        store
            .save_chain_bundle(&collision, Some(&second.state.verified_header_state))
            .is_err()
    );
    assert_unchanged(&store, &second);
    assert_unchanged(&store, &next);
}

#[test]
fn rejects_invalid_observation_and_proof_context_duplicates_and_future_heights() {
    let database = TestDatabase::new();
    let mut store = database.open();
    let mutations: [fn(&mut ChainBundle); 7] = [
        |bundle| bundle.observations[0].chain_id = 2,
        |bundle| bundle.observations[0].sequence = 0,
        |bundle| bundle.observations[0].finalized_height = 101,
        |bundle| bundle.observations.push(bundle.observations[0].clone()),
        |bundle| bundle.proofs[0].chain_id = 2,
        |bundle| bundle.proofs[0].finalized_height = 101,
        |bundle| bundle.proofs.push(bundle.proofs[0].clone()),
    ];
    for mutate in mutations {
        let mut invalid = bundle(1);
        mutate(&mut invalid);
        assert!(store.save_chain_bundle(&invalid, None).is_err());
        assert_eq!(store.load_chain_bundle(1).unwrap(), None);
        let agents: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM agents", [], |row| row.get(0))
            .unwrap();
        assert_eq!(agents, 0);
    }
}

#[test]
fn proof_bytes_are_opaque_and_empty_blobs_are_valid_storage_values() {
    let database = TestDatabase::new();
    let mut store = database.open();
    let mut initial = bundle(1);
    initial.state.verified_header_state.clear();
    initial.proofs[0].proof_cbor.clear();
    store.save_chain_bundle(&initial, None).unwrap();
    assert_unchanged(&store, &initial);
    let mut next = advance(&initial);
    next.proofs[0].proof_cbor = vec![0xff, 0xff, 0xff];
    store
        .save_chain_bundle(&next, Some(&initial.state.verified_header_state))
        .unwrap();
    assert_unchanged(&store, &next);
}

#[test]
fn accepts_proof_only_negative_cache_records_with_default_agents() {
    let database = TestDatabase::new();
    let mut store = database.open();
    let mut negative = bundle(1);
    negative.observations.clear();
    store.save_chain_bundle(&negative, None).unwrap();
    assert_unchanged(&store, &negative);
    let identity_state: String = store
        .connection
        .query_row(
            "SELECT identity_state FROM agents WHERE agent_id = ?1",
            [agent_text(agent(1))],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(identity_state, "pending_anchor");
    let contacts: i64 = store
        .connection
        .query_row("SELECT COUNT(*) FROM authorized_contacts", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(contacts, 0);
}

#[test]
fn rejects_proof_only_records_for_agents_observed_on_another_chain() {
    let database = TestDatabase::new();
    let mut store = database.open();
    let mut first = bundle(1);
    first.proofs.clear();
    store.save_chain_bundle(&first, None).unwrap();
    let mut foreign = bundle(2);
    foreign.observations.clear();
    assert!(store.save_chain_bundle(&foreign, None).is_err());
    assert_eq!(store.load_chain_bundle(2).unwrap(), None);
    assert_unchanged(&store, &first);

    foreign.proofs[0].agent_id = agent(2);
    store.save_chain_bundle(&foreign, None).unwrap();
    store
        .connection
        .execute(
            "UPDATE identity_proof_cache SET agent_id = ?1 WHERE chain_id = 2",
            [agent_text(agent(1))],
        )
        .unwrap();
    assert!(store.load_chain_bundle(2).is_err());
}

#[test]
fn rejects_observations_for_agents_with_proofs_on_another_chain() {
    let database = TestDatabase::new();
    let mut store = database.open();
    let mut first = bundle(1);
    first.observations.clear();
    store.save_chain_bundle(&first, None).unwrap();
    let mut foreign = bundle(2);
    foreign.proofs.clear();
    assert!(store.save_chain_bundle(&foreign, None).is_err());
    assert_eq!(store.load_chain_bundle(2).unwrap(), None);
    assert_unchanged(&store, &first);
}

#[test]
fn rolls_back_chain_agents_observations_and_proof_replacement_on_late_sql_failure() {
    let database = TestDatabase::new();
    let mut store = database.open();
    let initial = bundle(1);
    store.save_chain_bundle(&initial, None).unwrap();
    store
        .connection
        .execute_batch(
            "CREATE TRIGGER fail_proof BEFORE INSERT ON identity_proof_cache
             BEGIN SELECT RAISE(ABORT, 'injected proof write failure'); END;",
        )
        .unwrap();
    let mut next = advance(&initial);
    next.observations[0].sequence += 1;
    next.observations.push(observation(2, 1));
    next.proofs = vec![proof(2, 1)];
    assert!(
        store
            .save_chain_bundle(&next, Some(&initial.state.verified_header_state))
            .is_err()
    );
    assert_unchanged(&store, &initial);
    let inserted: bool = store
        .connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM agents WHERE agent_id = ?1)",
            [agent_text(agent(2))],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!inserted);
}

#[test]
fn foreign_key_failure_rolls_back_initial_creation_and_default_agents() {
    let database = TestDatabase::new();
    let mut store = database.open();
    store
        .connection
        .execute_batch(
            "CREATE TRIGGER fail_foreign_key AFTER INSERT ON identity_proof_cache
             BEGIN
                INSERT INTO authorized_contacts(agent_id, authorized_at_ms, authorization_revision)
                VALUES ('missing-agent', 0, 1);
             END;",
        )
        .unwrap();
    assert!(store.save_chain_bundle(&bundle(1), None).is_err());
    assert_eq!(store.load_chain_bundle(1).unwrap(), None);
    let agents: i64 = store
        .connection
        .query_row("SELECT COUNT(*) FROM agents", [], |row| row.get(0))
        .unwrap();
    assert_eq!(agents, 0);
    let contacts: i64 = store
        .connection
        .query_row("SELECT COUNT(*) FROM authorized_contacts", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(contacts, 0);
}

#[test]
fn checks_every_u64_database_conversion_and_accepts_i64_maximum() {
    let database = TestDatabase::new();
    let mut store = database.open();
    let mutations: [fn(&mut ChainBundle); 11] = [
        |bundle| bundle.state.chain_id = u64::MAX,
        |bundle| bundle.state.finalized_height = u64::MAX,
        |bundle| bundle.state.updated_at_ms = u64::MAX,
        |bundle| bundle.observations[0].chain_id = u64::MAX,
        |bundle| bundle.observations[0].sequence = u64::MAX,
        |bundle| bundle.observations[0].finalized_height = u64::MAX,
        |bundle| bundle.observations[0].verified_at_ms = u64::MAX,
        |bundle| bundle.proofs[0].chain_id = u64::MAX,
        |bundle| bundle.proofs[0].finalized_height = u64::MAX,
        |bundle| bundle.proofs[0].expires_at_ms = u64::MAX,
        |bundle| bundle.proofs[0].last_used_ms = u64::MAX,
    ];
    for mutate in mutations {
        let mut invalid = bundle(1);
        mutate(&mut invalid);
        assert!(store.save_chain_bundle(&invalid, None).is_err());
        assert_eq!(store.load_chain_bundle(1).unwrap(), None);
    }
    assert!(store.load_chain_bundle(u64::MAX).is_err());
    assert!(store.load_chain_bundle(0).is_err());
    let mut zero_chain = bundle(1);
    zero_chain.state.chain_id = 0;
    assert!(store.save_chain_bundle(&zero_chain, None).is_err());

    let maximum = i64::MAX as u64;
    let mut valid = bundle(maximum);
    valid.state.finalized_height = maximum;
    valid.state.updated_at_ms = maximum;
    valid.observations[0].sequence = maximum;
    valid.observations[0].finalized_height = maximum;
    valid.observations[0].verified_at_ms = maximum;
    valid.proofs[0].finalized_height = maximum;
    valid.proofs[0].expires_at_ms = maximum;
    valid.proofs[0].last_used_ms = maximum;
    store.save_chain_bundle(&valid, None).unwrap();
    assert_unchanged(&store, &valid);
}

#[test]
fn rejects_save_quotas_without_creating_partial_records() {
    let database = TestDatabase::new();
    let mut store = database.open();
    let mut invalid = bundle(1);
    invalid.observations = vec![observation(1, 1); MAX_CHAIN_OBSERVATIONS + 1];
    assert!(store.save_chain_bundle(&invalid, None).is_err());
    invalid = bundle(1);
    invalid.proofs = vec![proof(1, 1); MAX_CHAIN_PROOFS + 1];
    assert!(store.save_chain_bundle(&invalid, None).is_err());
    invalid = bundle(1);
    invalid.proofs[0].proof_cbor = vec![0; MAX_CHAIN_PROOF_BYTES + 1];
    assert!(store.save_chain_bundle(&invalid, None).is_err());
    invalid = bundle(1);
    invalid.state.verified_header_state = vec![0; MAX_CHAIN_SNAPSHOT_BYTES + 1];
    assert!(store.save_chain_bundle(&invalid, None).is_err());
    assert!(
        store
            .save_chain_bundle(&bundle(1), Some(&vec![0; MAX_CHAIN_SNAPSHOT_BYTES + 1]))
            .is_err()
    );
    assert_eq!(store.load_chain_bundle(1).unwrap(), None);
}

#[test]
fn accepts_exact_observation_limit() {
    let database = TestDatabase::new();
    let mut store = database.open();
    let mut maximum = bundle(1);
    maximum.proofs.clear();
    maximum.observations = (0..MAX_CHAIN_OBSERVATIONS)
        .map(|index| observation(index as u64, 1))
        .collect();
    store.save_chain_bundle(&maximum, None).unwrap();
    maximum
        .observations
        .sort_by_key(|observation| agent_text(observation.agent_id));
    assert_unchanged(&store, &maximum);
}

#[test]
fn accepts_exact_proof_snapshot_and_total_cache_byte_limits() {
    let database = TestDatabase::new();
    let mut store = database.open();
    let mut maximum = bundle(1);
    maximum.state.verified_header_state = vec![42; MAX_CHAIN_SNAPSHOT_BYTES];
    maximum.observations = (0..MAX_CHAIN_PROOFS)
        .map(|index| observation(index as u64, 1))
        .collect();
    maximum.proofs = (0..MAX_CHAIN_PROOFS)
        .map(|index| {
            let mut proof = proof(index as u64, 1);
            proof.proof_cbor = vec![42; MAX_CHAIN_PROOF_BYTES];
            proof
        })
        .collect();
    assert_eq!(
        maximum
            .proofs
            .iter()
            .map(|proof| proof.proof_cbor.len())
            .sum::<usize>(),
        MAX_CHAIN_CACHE_BYTES
    );
    store.save_chain_bundle(&maximum, None).unwrap();
    drop(store);
    maximum
        .observations
        .sort_by_key(|observation| agent_text(observation.agent_id));
    maximum
        .proofs
        .sort_by_key(|proof| agent_text(proof.agent_id));
    assert_unchanged(&database.open(), &maximum);
}

#[test]
fn proof_cache_quotas_apply_across_chains_and_failed_replacement_preserves_both() {
    let database = TestDatabase::new();
    let mut store = database.open();
    let mut first = bundle(1);
    first.observations.clear();
    first.proofs = (0..MAX_CHAIN_PROOFS)
        .map(|index| proof(index as u64, 1))
        .collect();
    store.save_chain_bundle(&first, None).unwrap();
    first.proofs.sort_by_key(|proof| agent_text(proof.agent_id));
    let mut second = bundle(2);
    second.observations = vec![observation(1_000, 2)];
    second.proofs = vec![proof(1_000, 2)];
    assert!(store.save_chain_bundle(&second, None).is_err());
    assert_eq!(store.load_chain_bundle(2).unwrap(), None);
    assert_unchanged(&store, &first);

    let mut smaller = advance(&first);
    smaller.proofs.pop();
    store
        .save_chain_bundle(&smaller, Some(&first.state.verified_header_state))
        .unwrap();
    store.save_chain_bundle(&second, None).unwrap();
    let mut too_large = advance(&smaller);
    too_large.proofs = first.proofs;
    assert!(
        store
            .save_chain_bundle(&too_large, Some(&smaller.state.verified_header_state))
            .is_err()
    );
    assert_unchanged(&store, &smaller);
    assert_unchanged(&store, &second);
}

#[test]
fn load_checks_global_cache_count_before_loading_one_chain() {
    let database = TestDatabase::new();
    let mut store = database.open();
    let mut first = bundle(1);
    first.observations.clear();
    first.proofs = (0..MAX_CHAIN_PROOFS)
        .map(|index| proof(index as u64, 1))
        .collect();
    store.save_chain_bundle(&first, None).unwrap();
    let mut second = bundle(2);
    second.observations.clear();
    second.proofs.clear();
    store.save_chain_bundle(&second, None).unwrap();
    let agent_id = agent_text(agent(1_000));
    store
        .connection
        .execute("INSERT INTO agents(agent_id) VALUES (?1)", [&agent_id])
        .unwrap();
    store
        .connection
        .execute(
            "INSERT INTO identity_proof_cache(
                agent_id, chain_id, finalized_height, proof_cbor, expires_at_ms, last_used_ms
             ) VALUES (?1, 2, 0, X'', 0, 0)",
            [&agent_id],
        )
        .unwrap();
    assert!(store.load_chain_bundle(1).is_err());
    assert!(store.load_chain_bundle(2).is_err());
}

#[test]
fn load_rejects_database_row_count_quotas_before_collecting_rows() {
    for (table, count) in [
        ("identity_registry_states", MAX_CHAIN_OBSERVATIONS + 1),
        ("identity_proof_cache", MAX_CHAIN_PROOFS + 1),
    ] {
        let database = TestDatabase::new();
        let mut store = database.open();
        let mut initial = bundle(1);
        initial.observations.clear();
        initial.proofs.clear();
        store.save_chain_bundle(&initial, None).unwrap();
        store
            .connection
            .execute(
                "WITH RECURSIVE ids(n) AS (
                    SELECT 1 UNION ALL SELECT n + 1 FROM ids WHERE n < ?1
                 ) INSERT INTO agents(agent_id) SELECT printf('quota-%05d', n) FROM ids",
                [count as i64],
            )
            .unwrap();
        let sql = if table == "identity_registry_states" {
            "INSERT INTO identity_registry_states(
                agent_id, chain_id, controller_address, state_commitment, sequence,
                status, finalized_height, storage_proof_hash, verified_at_ms
             ) SELECT agent_id, 1, zeroblob(20), zeroblob(32), 1, 'active', 0, zeroblob(32), 0
               FROM agents"
        } else {
            "INSERT INTO identity_proof_cache(
                agent_id, chain_id, finalized_height, proof_cbor, expires_at_ms, last_used_ms
             ) SELECT agent_id, 1, 0, X'', 0, 0 FROM agents"
        };
        store.connection.execute_batch(sql).unwrap();
        assert!(store.load_chain_bundle(1).is_err(), "{table}");
    }
}

#[test]
fn load_rejects_oversized_database_blobs_even_when_checks_were_bypassed() {
    for (sql, size) in [
        (
            "UPDATE chain_state_cache SET verified_header_state = zeroblob(?1)",
            MAX_CHAIN_SNAPSHOT_BYTES + 1,
        ),
        (
            "UPDATE identity_proof_cache SET proof_cbor = zeroblob(?1)",
            MAX_CHAIN_PROOF_BYTES + 1,
        ),
    ] {
        let database = TestDatabase::new();
        let mut store = database.open();
        store.save_chain_bundle(&bundle(1), None).unwrap();
        store
            .connection
            .pragma_update(None, "ignore_check_constraints", true)
            .unwrap();
        store.connection.execute(sql, [size as i64]).unwrap();
        assert!(store.load_chain_bundle(1).is_err());
    }
}

#[test]
fn load_rejects_negative_database_integers_and_invalid_status_or_fixed_blob() {
    for sql in [
        "UPDATE chain_state_cache SET updated_at_ms = -1",
        "UPDATE chain_state_cache SET finalized_height = -1",
        "UPDATE identity_registry_states SET sequence = -1",
        "UPDATE identity_registry_states SET sequence = 0",
        "UPDATE identity_registry_states SET finalized_height = -1",
        "UPDATE identity_registry_states SET verified_at_ms = -1",
        "UPDATE identity_registry_states SET status = 'unknown'",
        "UPDATE identity_registry_states SET controller_address = X''",
        "UPDATE identity_proof_cache SET finalized_height = -1",
        "UPDATE identity_proof_cache SET expires_at_ms = -1",
        "UPDATE identity_proof_cache SET last_used_ms = -1",
    ] {
        let database = TestDatabase::new();
        let mut store = database.open();
        store.save_chain_bundle(&bundle(1), None).unwrap();
        store
            .connection
            .pragma_update(None, "ignore_check_constraints", true)
            .unwrap();
        store.connection.execute_batch(sql).unwrap();
        assert!(store.load_chain_bundle(1).is_err(), "{sql}");
    }
}

#[test]
fn load_rejects_malformed_agent_text_in_observations_and_proofs() {
    let invalid_ids = [
        String::new(),
        "0OIl".to_owned(),
        bs58::encode([1; 31]).into_string(),
        bs58::encode([1; 33]).into_string(),
        format!(" {}", agent_text(agent(1))),
        "1".repeat(45),
        "x".repeat(1_024),
    ];
    for table in ["identity_registry_states", "identity_proof_cache"] {
        let database = TestDatabase::new();
        let mut store = database.open();
        let initial = bundle(1);
        store.save_chain_bundle(&initial, None).unwrap();
        for invalid in &invalid_ids {
            store
                .connection
                .execute("INSERT INTO agents(agent_id) VALUES (?1)", [invalid])
                .unwrap();
            let sql = format!("UPDATE {table} SET agent_id = ?1");
            store.connection.execute(&sql, [invalid]).unwrap();
            assert!(store.load_chain_bundle(1).is_err(), "{table}: {invalid}");
            store
                .connection
                .execute(&sql, [agent_text(agent(1))])
                .unwrap();
        }
        assert_unchanged(&store, &initial);
    }
}

#[test]
fn load_rejects_future_database_heights() {
    for sql in [
        "UPDATE identity_registry_states SET finalized_height = 101",
        "UPDATE identity_proof_cache SET finalized_height = 101",
    ] {
        let database = TestDatabase::new();
        let mut store = database.open();
        store.save_chain_bundle(&bundle(1), None).unwrap();
        store.connection.execute_batch(sql).unwrap();
        assert!(store.load_chain_bundle(1).is_err(), "{sql}");
    }
}

#[test]
fn creates_only_default_agents_and_preserves_existing_metadata_and_authorization() {
    let database = TestDatabase::new();
    let mut store = database.open();
    let existing = agent_text(agent(1));
    store
        .connection
        .execute(
            "INSERT INTO agents(
                agent_id, handle_code, profile_cbor, profile_sequence,
                profile_expires_ms, first_seen_ms, identity_state
             ) VALUES (?1, 'local-handle', X'0102', 5, 5000, 50, 'stale')",
            [&existing],
        )
        .unwrap();
    store
        .connection
        .execute(
            "INSERT INTO authorized_contacts(agent_id, authorized_at_ms, authorization_revision)
             VALUES (?1, 10, 1)",
            [&existing],
        )
        .unwrap();
    let mut initial = bundle(1);
    initial.observations.push(observation(2, 1));
    initial.proofs.push(proof(2, 1));
    store.save_chain_bundle(&initial, None).unwrap();
    let preserved: (String, Vec<u8>, i64, i64, i64, String) = store
        .connection
        .query_row(
            "SELECT handle_code, profile_cbor, profile_sequence, profile_expires_ms,
                first_seen_ms, identity_state FROM agents WHERE agent_id = ?1",
            [&existing],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(
        preserved,
        (
            "local-handle".to_owned(),
            vec![1, 2],
            5,
            5_000,
            50,
            "stale".to_owned()
        )
    );
    let defaults: (Option<String>, Vec<u8>, i64, i64, i64, String) = store
        .connection
        .query_row(
            "SELECT handle_code, profile_cbor, profile_sequence, profile_expires_ms,
                first_seen_ms, identity_state FROM agents WHERE agent_id = ?1",
            [agent_text(agent(2))],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(
        defaults,
        (None, vec![], 0, 0, 0, "pending_anchor".to_owned())
    );
    let counts: (i64, i64, i64, i64, i64, i64) = store
        .connection
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM authorized_contacts),
                (SELECT COUNT(*) FROM preferred_peers),
                (SELECT COUNT(*) FROM grants),
                (SELECT COUNT(*) FROM grant_agents),
                (SELECT COUNT(*) FROM providers),
                (SELECT COUNT(*) FROM peers)",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(counts, (1, 0, 0, 0, 0, 0));
    assert_eq!(store.policy_revision().unwrap(), 1);
}
