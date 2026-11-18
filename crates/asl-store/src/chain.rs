//! Durable chain snapshots, identity high-water marks, and bounded proof caches.
//!
//! These records must come from the caller's proof verifier. This repository
//! enforces storage consistency and compare-and-swap, not cryptographic validity.

use std::collections::BTreeMap;

use asl_types::{error::AslError, ids::AgentId};
use rusqlite::{Connection, OptionalExtension, Row, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

use crate::{Store, database_error};

pub const MAX_CHAIN_OBSERVATIONS: usize = 10_000;
pub const MAX_CHAIN_PROOFS: usize = 128;
pub const MAX_CHAIN_PROOF_BYTES: usize = 262_144;
pub const MAX_CHAIN_CACHE_BYTES: usize = 33_554_432;
pub const MAX_CHAIN_SNAPSHOT_BYTES: usize = 1_048_576;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChainStateRow {
    pub chain_id: u64,
    pub registry_address: [u8; 20],
    pub registry_code_hash: [u8; 32],
    pub finalized_height: u64,
    pub finalized_block_hash: [u8; 32],
    pub execution_state_root: [u8; 32],
    pub checkpoint_hash: [u8; 32],
    pub verified_header_state: Vec<u8>,
    pub updated_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ObservationStatus {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IdentityObservationRow {
    pub agent_id: AgentId,
    pub chain_id: u64,
    pub controller_address: [u8; 20],
    pub state_commitment: [u8; 32],
    pub sequence: u64,
    pub status: ObservationStatus,
    pub finalized_height: u64,
    pub storage_proof_hash: [u8; 32],
    pub verified_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IdentityProofRow {
    pub agent_id: AgentId,
    pub chain_id: u64,
    pub finalized_height: u64,
    pub proof_cbor: Vec<u8>,
    pub expires_at_ms: u64,
    pub last_used_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChainBundle {
    pub state: ChainStateRow,
    pub observations: Vec<IdentityObservationRow>,
    pub proofs: Vec<IdentityProofRow>,
}

impl Store {
    /// Loads a consistent snapshot, with rows ordered by canonical AgentId text.
    pub fn load_chain_bundle(&self, chain_id: u64) -> Result<Option<ChainBundle>, AslError> {
        let chain_id = chain_integer(chain_id)?;
        let transaction = self
            .connection
            .unchecked_transaction()
            .map_err(database_error)?;
        let bundle = load_bundle(&transaction, chain_id)?;
        transaction.commit().map_err(database_error)?;
        Ok(bundle)
    }

    /// Saves a complete bundle atomically. `None` permits only initial creation;
    /// otherwise the previous opaque header state must match exactly.
    ///
    /// All observations are durable high-water marks and must be retained even
    /// when the caller evicts their proofs. Invalid records, stale writers, and
    /// invariant violations return `AslError::InvalidDatabase`.
    pub fn save_chain_bundle(
        &mut self,
        bundle: &ChainBundle,
        expected_state: Option<&[u8]>,
    ) -> Result<(), AslError> {
        let observations = validate_bundle(bundle)?;
        if expected_state.is_some_and(|state| state.len() > MAX_CHAIN_SNAPSHOT_BYTES) {
            return Err(AslError::InvalidDatabase);
        }
        let chain_id = chain_integer(bundle.state.chain_id)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;

        let previous = load_bundle(&transaction, chain_id)?;
        match (previous.as_ref(), expected_state) {
            (None, None) => {}
            (Some(previous), Some(expected))
                if previous.state.verified_header_state == expected =>
            {
                validate_update(bundle, previous, &observations)?;
            }
            _ => return Err(AslError::InvalidDatabase),
        }

        // A changed registry sequence can retire a device even when the Agent
        // stays active. Cache touches do not change authorization facts.
        let changed_authority = previous.as_ref().is_some_and(|old| {
            old.state.checkpoint_hash != bundle.state.checkpoint_hash
                || old.observations.iter().any(|prior| {
                    observations
                        .get(&prior.agent_id.0)
                        .is_none_or(|new| new.sequence != prior.sequence)
                })
        });
        if changed_authority {
            transaction
                .execute(
                    "UPDATE policy_state SET revision=revision+1 WHERE singleton=1",
                    [],
                )
                .map_err(database_error)?;
        }

        let state = &bundle.state;
        transaction
            .execute(
                "INSERT INTO chain_state_cache(
                    chain_id, registry_address, registry_code_hash, finalized_height,
                    finalized_block_hash, execution_state_root, checkpoint_hash,
                    verified_header_state, updated_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(chain_id) DO UPDATE SET
                    registry_address = excluded.registry_address,
                    registry_code_hash = excluded.registry_code_hash,
                    finalized_height = excluded.finalized_height,
                    finalized_block_hash = excluded.finalized_block_hash,
                    execution_state_root = excluded.execution_state_root,
                    checkpoint_hash = excluded.checkpoint_hash,
                    verified_header_state = excluded.verified_header_state,
                    updated_at_ms = excluded.updated_at_ms",
                params![
                    chain_id,
                    &state.registry_address,
                    &state.registry_code_hash,
                    db_integer(state.finalized_height)?,
                    &state.finalized_block_hash,
                    &state.execution_state_root,
                    &state.checkpoint_hash,
                    &state.verified_header_state,
                    db_integer(state.updated_at_ms)?,
                ],
            )
            .map_err(database_error)?;

        {
            let mut insert_agent = transaction
                .prepare(
                    "INSERT INTO agents(agent_id) VALUES (?1)
                     ON CONFLICT(agent_id) DO NOTHING",
                )
                .map_err(database_error)?;
            let mut proof_chain = transaction
                .prepare("SELECT chain_id FROM identity_proof_cache WHERE agent_id = ?1")
                .map_err(database_error)?;
            let mut upsert_observation = transaction
                .prepare(
                    "INSERT INTO identity_registry_states(
                        agent_id, chain_id, controller_address, state_commitment,
                        sequence, status, finalized_height, storage_proof_hash, verified_at_ms
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                     ON CONFLICT(agent_id) DO UPDATE SET
                        controller_address = excluded.controller_address,
                        state_commitment = excluded.state_commitment,
                        sequence = excluded.sequence,
                        status = excluded.status,
                        finalized_height = excluded.finalized_height,
                        storage_proof_hash = excluded.storage_proof_hash,
                        verified_at_ms = excluded.verified_at_ms
                     WHERE identity_registry_states.chain_id = excluded.chain_id",
                )
                .map_err(database_error)?;
            for observation in &bundle.observations {
                let agent_id = agent_text(observation.agent_id);
                let cached_chain = proof_chain
                    .query_row([&agent_id], |row| row.get::<_, i64>(0))
                    .optional()
                    .map_err(database_error)?;
                if cached_chain.is_some_and(|cached| cached != chain_id) {
                    return Err(AslError::InvalidDatabase);
                }
                insert_agent.execute([&agent_id]).map_err(database_error)?;
                let changed = upsert_observation
                    .execute(params![
                        &agent_id,
                        chain_id,
                        &observation.controller_address,
                        &observation.state_commitment,
                        db_integer(observation.sequence)?,
                        match observation.status {
                            ObservationStatus::Active => "active",
                            ObservationStatus::Revoked => "revoked",
                        },
                        db_integer(observation.finalized_height)?,
                        &observation.storage_proof_hash,
                        db_integer(observation.verified_at_ms)?,
                    ])
                    .map_err(database_error)?;
                if changed != 1 {
                    return Err(AslError::InvalidDatabase);
                }
            }
        }

        transaction
            .execute(
                "DELETE FROM identity_proof_cache WHERE chain_id = ?1",
                [chain_id],
            )
            .map_err(database_error)?;
        let (other_proofs, other_bytes) = proof_cache_usage(&transaction)?;
        let new_bytes = bundle.proofs.iter().try_fold(0_usize, |total, proof| {
            total
                .checked_add(proof.proof_cbor.len())
                .ok_or(AslError::InvalidDatabase)
        })?;
        if other_proofs
            .checked_add(bundle.proofs.len())
            .is_none_or(|count| count > MAX_CHAIN_PROOFS)
            || other_bytes
                .checked_add(new_bytes)
                .is_none_or(|bytes| bytes > MAX_CHAIN_CACHE_BYTES)
        {
            return Err(AslError::InvalidDatabase);
        }
        {
            let mut insert_agent = transaction
                .prepare(
                    "INSERT INTO agents(agent_id) VALUES (?1)
                     ON CONFLICT(agent_id) DO NOTHING",
                )
                .map_err(database_error)?;
            let mut observation_chain = transaction
                .prepare("SELECT chain_id FROM identity_registry_states WHERE agent_id = ?1")
                .map_err(database_error)?;
            let mut insert_proof = transaction
                .prepare(
                    "INSERT INTO identity_proof_cache(
                        agent_id, chain_id, finalized_height, proof_cbor, expires_at_ms, last_used_ms
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                )
                .map_err(database_error)?;
            for proof in &bundle.proofs {
                let agent_id = agent_text(proof.agent_id);
                let observed_chain = observation_chain
                    .query_row([&agent_id], |row| row.get::<_, i64>(0))
                    .optional()
                    .map_err(database_error)?;
                if observed_chain.is_some_and(|observed| observed != chain_id) {
                    return Err(AslError::InvalidDatabase);
                }
                insert_agent.execute([&agent_id]).map_err(database_error)?;
                insert_proof
                    .execute(params![
                        agent_id,
                        chain_id,
                        db_integer(proof.finalized_height)?,
                        &proof.proof_cbor,
                        db_integer(proof.expires_at_ms)?,
                        db_integer(proof.last_used_ms)?,
                    ])
                    .map_err(database_error)?;
            }
        }
        transaction.commit().map_err(database_error)
    }
}

type Observations<'a> = BTreeMap<[u8; 32], &'a IdentityObservationRow>;

fn validate_bundle(bundle: &ChainBundle) -> Result<Observations<'_>, AslError> {
    let state = &bundle.state;
    chain_integer(state.chain_id)?;
    db_integer(state.finalized_height)?;
    db_integer(state.updated_at_ms)?;
    if state.verified_header_state.len() > MAX_CHAIN_SNAPSHOT_BYTES
        || bundle.observations.len() > MAX_CHAIN_OBSERVATIONS
        || bundle.proofs.len() > MAX_CHAIN_PROOFS
    {
        return Err(AslError::InvalidDatabase);
    }

    let mut observations = BTreeMap::new();
    for observation in &bundle.observations {
        chain_integer(observation.chain_id)?;
        db_integer(observation.sequence)?;
        db_integer(observation.finalized_height)?;
        db_integer(observation.verified_at_ms)?;
        if observation.chain_id != state.chain_id
            || observation.sequence == 0
            || observation.finalized_height > state.finalized_height
            || observations
                .insert(observation.agent_id.0, observation)
                .is_some()
        {
            return Err(AslError::InvalidDatabase);
        }
    }

    let mut proof_agents = BTreeMap::new();
    let mut cache_bytes = 0_usize;
    for proof in &bundle.proofs {
        chain_integer(proof.chain_id)?;
        db_integer(proof.finalized_height)?;
        db_integer(proof.expires_at_ms)?;
        db_integer(proof.last_used_ms)?;
        cache_bytes = cache_bytes
            .checked_add(proof.proof_cbor.len())
            .ok_or(AslError::InvalidDatabase)?;
        if proof.chain_id != state.chain_id
            || proof.finalized_height > state.finalized_height
            || proof_agents.insert(proof.agent_id.0, ()).is_some()
            || proof.proof_cbor.len() > MAX_CHAIN_PROOF_BYTES
            || cache_bytes > MAX_CHAIN_CACHE_BYTES
        {
            return Err(AslError::InvalidDatabase);
        }
    }
    Ok(observations)
}

fn validate_update(
    bundle: &ChainBundle,
    previous: &ChainBundle,
    observations: &Observations<'_>,
) -> Result<(), AslError> {
    let state = &bundle.state;
    let old = &previous.state;
    if state.registry_address != old.registry_address
        || state.registry_code_hash != old.registry_code_hash
        || state.finalized_height < old.finalized_height
        || (state.finalized_height == old.finalized_height
            && (state.finalized_block_hash != old.finalized_block_hash
                || state.execution_state_root != old.execution_state_root))
    {
        return Err(AslError::InvalidDatabase);
    }
    for old in &previous.observations {
        let observation = observations
            .get(&old.agent_id.0)
            .ok_or(AslError::InvalidDatabase)?;
        if observation.sequence < old.sequence
            || observation.finalized_height < old.finalized_height
            || (observation.sequence == old.sequence
                && (observation.controller_address != old.controller_address
                    || observation.state_commitment != old.state_commitment
                    || observation.status != old.status))
            || (old.status == ObservationStatus::Revoked
                && observation.status != ObservationStatus::Revoked)
        {
            return Err(AslError::InvalidDatabase);
        }
    }
    Ok(())
}

fn load_bundle(connection: &Connection, chain_id: i64) -> Result<Option<ChainBundle>, AslError> {
    // Inspect only lengths/counts before copying any database BLOBs or collecting rows.
    let (snapshot_bytes, observation_count, proof_count) = connection
        .query_row(
            "SELECT
                (SELECT length(verified_header_state) FROM chain_state_cache WHERE chain_id = ?1),
                (SELECT COUNT(*) FROM identity_registry_states WHERE chain_id = ?1),
                (SELECT COUNT(*) FROM identity_proof_cache WHERE chain_id = ?1)",
            [chain_id],
            |row| {
                Ok((
                    row.get::<_, Option<i64>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .map_err(database_error)?;
    let observation_count = bounded_size(observation_count, MAX_CHAIN_OBSERVATIONS)?;
    let proof_count = bounded_size(proof_count, MAX_CHAIN_PROOFS)?;
    proof_cache_usage(connection)?;
    let Some(snapshot_bytes) = snapshot_bytes else {
        return if observation_count == 0 && proof_count == 0 {
            Ok(None)
        } else {
            Err(AslError::InvalidDatabase)
        };
    };
    bounded_size(snapshot_bytes, MAX_CHAIN_SNAPSHOT_BYTES)?;

    let state = connection
        .query_row(
            "SELECT chain_id, registry_address, registry_code_hash, finalized_height,
                finalized_block_hash, execution_state_root, checkpoint_hash,
                verified_header_state, updated_at_ms
             FROM chain_state_cache WHERE chain_id = ?1",
            [chain_id],
            |row| Ok(read_state(row)),
        )
        .map_err(database_error)??;
    let mut observations = Vec::with_capacity(observation_count);
    let mut statement = connection
        .prepare(
            "SELECT agent_id, chain_id, controller_address, state_commitment, sequence,
                status, finalized_height, storage_proof_hash, verified_at_ms
             FROM identity_registry_states WHERE chain_id = ?1 ORDER BY agent_id",
        )
        .map_err(database_error)?;
    let mut rows = statement.query([chain_id]).map_err(database_error)?;
    while let Some(row) = rows.next().map_err(database_error)? {
        if observations.len() >= observation_count {
            return Err(AslError::InvalidDatabase);
        }
        observations.push(read_observation(row)?);
    }
    let mut proofs = Vec::with_capacity(proof_count);
    let mut statement = connection
        .prepare(
            "SELECT proof.agent_id, proof.chain_id, proof.finalized_height, proof.proof_cbor,
                proof.expires_at_ms, proof.last_used_ms, observation.chain_id
             FROM identity_proof_cache AS proof
             LEFT JOIN identity_registry_states AS observation ON observation.agent_id = proof.agent_id
             WHERE proof.chain_id = ?1 ORDER BY proof.agent_id",
        )
        .map_err(database_error)?;
    let mut rows = statement.query([chain_id]).map_err(database_error)?;
    while let Some(row) = rows.next().map_err(database_error)? {
        if proofs.len() >= proof_count {
            return Err(AslError::InvalidDatabase);
        }
        proofs.push(read_proof(row)?);
    }
    let bundle = ChainBundle {
        state,
        observations,
        proofs,
    };
    validate_bundle(&bundle)?;
    Ok(Some(bundle))
}

fn proof_cache_usage(connection: &Connection) -> Result<(usize, usize), AslError> {
    let (count, bytes, largest) = connection
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(length(proof_cbor)), 0),
                COALESCE(MAX(length(proof_cbor)), 0) FROM identity_proof_cache",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .map_err(database_error)?;
    bounded_size(largest, MAX_CHAIN_PROOF_BYTES)?;
    Ok((
        bounded_size(count, MAX_CHAIN_PROOFS)?,
        bounded_size(bytes, MAX_CHAIN_CACHE_BYTES)?,
    ))
}

fn read_state(row: &Row<'_>) -> Result<ChainStateRow, AslError> {
    Ok(ChainStateRow {
        chain_id: read_integer(row, 0)?,
        registry_address: read_fixed(row, 1)?,
        registry_code_hash: read_fixed(row, 2)?,
        finalized_height: read_integer(row, 3)?,
        finalized_block_hash: read_fixed(row, 4)?,
        execution_state_root: read_fixed(row, 5)?,
        checkpoint_hash: read_fixed(row, 6)?,
        verified_header_state: read_blob(row, 7, MAX_CHAIN_SNAPSHOT_BYTES)?,
        updated_at_ms: read_integer(row, 8)?,
    })
}

fn read_observation(row: &Row<'_>) -> Result<IdentityObservationRow, AslError> {
    let status = match row
        .get_ref(5)
        .map_err(database_error)?
        .as_str()
        .map_err(|_| AslError::InvalidDatabase)?
    {
        "active" => ObservationStatus::Active,
        "revoked" => ObservationStatus::Revoked,
        _ => return Err(AslError::InvalidDatabase),
    };
    Ok(IdentityObservationRow {
        agent_id: read_agent(row, 0)?,
        chain_id: read_integer(row, 1)?,
        controller_address: read_fixed(row, 2)?,
        state_commitment: read_fixed(row, 3)?,
        sequence: read_integer(row, 4)?,
        status,
        finalized_height: read_integer(row, 6)?,
        storage_proof_hash: read_fixed(row, 7)?,
        verified_at_ms: read_integer(row, 8)?,
    })
}

fn read_proof(row: &Row<'_>) -> Result<IdentityProofRow, AslError> {
    let chain_id = read_integer(row, 1)?;
    let observed_chain = row.get::<_, Option<i64>>(6).map_err(database_error)?;
    if observed_chain.is_some_and(|observed| u64::try_from(observed).ok() != Some(chain_id)) {
        return Err(AslError::InvalidDatabase);
    }
    Ok(IdentityProofRow {
        agent_id: read_agent(row, 0)?,
        chain_id,
        finalized_height: read_integer(row, 2)?,
        proof_cbor: read_blob(row, 3, MAX_CHAIN_PROOF_BYTES)?,
        expires_at_ms: read_integer(row, 4)?,
        last_used_ms: read_integer(row, 5)?,
    })
}

fn db_integer(value: u64) -> Result<i64, AslError> {
    i64::try_from(value).map_err(|_| AslError::InvalidDatabase)
}

fn chain_integer(value: u64) -> Result<i64, AslError> {
    if value == 0 {
        return Err(AslError::InvalidDatabase);
    }
    db_integer(value)
}

fn bounded_size(value: i64, limit: usize) -> Result<usize, AslError> {
    usize::try_from(value)
        .ok()
        .filter(|value| *value <= limit)
        .ok_or(AslError::InvalidDatabase)
}

fn read_integer(row: &Row<'_>, index: usize) -> Result<u64, AslError> {
    let value = row.get::<_, i64>(index).map_err(database_error)?;
    u64::try_from(value).map_err(|_| AslError::InvalidDatabase)
}

fn read_fixed<const N: usize>(row: &Row<'_>, index: usize) -> Result<[u8; N], AslError> {
    row.get_ref(index)
        .map_err(database_error)?
        .as_blob()
        .map_err(|_| AslError::InvalidDatabase)?
        .try_into()
        .map_err(|_| AslError::InvalidDatabase)
}

fn read_blob(row: &Row<'_>, index: usize, limit: usize) -> Result<Vec<u8>, AslError> {
    let blob = row
        .get_ref(index)
        .map_err(database_error)?
        .as_blob()
        .map_err(|_| AslError::InvalidDatabase)?;
    if blob.len() > limit {
        return Err(AslError::InvalidDatabase);
    }
    Ok(blob.to_vec())
}

pub(crate) fn agent_text(agent: AgentId) -> String {
    bs58::encode(agent.as_bytes()).into_string()
}

fn read_agent(row: &Row<'_>, index: usize) -> Result<AgentId, AslError> {
    let text = row
        .get_ref(index)
        .map_err(database_error)?
        .as_str()
        .map_err(|_| AslError::InvalidDatabase)?;
    if !(32..=44).contains(&text.len()) {
        return Err(AslError::InvalidDatabase);
    }
    let mut bytes = [0_u8; 32];
    let length = bs58::decode(text)
        .onto(&mut bytes)
        .map_err(|_| AslError::InvalidDatabase)?;
    let agent = AgentId(bytes);
    if length != bytes.len() || agent_text(agent) != text {
        return Err(AslError::InvalidDatabase);
    }
    Ok(agent)
}

#[cfg(test)]
#[path = "chain_tests.rs"]
mod tests;
