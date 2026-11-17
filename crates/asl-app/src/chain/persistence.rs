use asl_policy::{protect_secret, unprotect_secret};
use asl_store::{
    Store,
    chain::{
        ChainBundle, ChainStateRow, IdentityObservationRow, IdentityProofRow,
        MAX_CHAIN_OBSERVATIONS, MAX_CHAIN_PROOF_BYTES, MAX_CHAIN_SNAPSHOT_BYTES, ObservationStatus,
    },
};
use asl_types::ids::AgentId;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use super::{
    ChainError, ConsensusConfigV1, EthereumIdentityResolver, EthereumLightClient,
    EthereumProofVerifier, FinalizedExecution, IdentityProofV1, IdentityProofVerifier,
    IdentityResolution, IdentityResolver, LimitedReason, RegistryDeploymentV1, RegistryStatus,
    VerifiedIdentity,
};

const SNAPSHOT_DOMAIN: &str = "ASL-LOCAL-CHAIN-1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DurableResolverConfigV1 {
    pub consensus: ConsensusConfigV1,
    pub deployment: RegistryDeploymentV1,
    pub max_cache_age_secs: u64,
    pub cache_capacity: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalSnapshot {
    domain: String,
    config: DurableResolverConfigV1,
    consensus_json: Vec<u8>,
    rows_hash: [u8; 32],
}

// This representation is accepted only inside an authenticated local snapshot.
// FinalizedExecution deliberately does not implement Deserialize.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedExecution {
    chain_id: u64,
    beacon_slot: u64,
    block_number: u64,
    block_hash: [u8; 32],
    state_root: [u8; 32],
    timestamp_secs: u64,
}

impl SavedExecution {
    fn capture(state: &FinalizedExecution) -> Self {
        Self {
            chain_id: state.chain_id(),
            beacon_slot: state.beacon_slot(),
            block_number: state.block_number(),
            block_hash: state.block_hash(),
            state_root: state.state_root(),
            timestamp_secs: state.timestamp_secs(),
        }
    }

    fn authenticated_state(self) -> FinalizedExecution {
        FinalizedExecution {
            chain_id: self.chain_id,
            beacon_slot: self.beacon_slot,
            block_number: self.block_number,
            block_hash: self.block_hash,
            state_root: self.state_root,
            timestamp_secs: self.timestamp_secs,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedProof {
    finalized: SavedExecution,
    proof: IdentityProofV1,
}

pub struct DurableIdentityResolver {
    store: Store,
    config: DurableResolverConfigV1,
    resolver: EthereumIdentityResolver,
    bundle: ChainBundle,
    storage_healthy: bool,
}

impl DurableIdentityResolver {
    pub fn create(
        store: Store,
        config: DurableResolverConfigV1,
        light_client: EthereumLightClient,
        now_secs: u64,
    ) -> Result<Self, ChainError> {
        if light_client.config() != &config.consensus
            || store
                .load_chain_bundle(config.consensus.chain_id)
                .map_err(|_| ChainError::StorageUnavailable)?
                .is_some()
        {
            return Err(ChainError::InvalidLocalState);
        }
        let finalized = match light_client.finalized(now_secs) {
            Ok(finalized) => finalized,
            Err(ChainError::StaleFinality) => light_client
                .observed_execution()
                .cloned()
                .ok_or(ChainError::ExecutionHeaderRequired)?,
            Err(error) => return Err(error),
        };
        let resolver = make_resolver(&config, light_client)?;
        let bundle = ChainBundle {
            state: ChainStateRow {
                chain_id: finalized.chain_id(),
                registry_address: config.deployment.address,
                registry_code_hash: config.deployment.runtime_code_hash,
                finalized_height: finalized.block_number(),
                finalized_block_hash: finalized.block_hash(),
                execution_state_root: finalized.state_root(),
                checkpoint_hash: config.consensus.checkpoint.beacon_root,
                verified_header_state: Vec::new(),
                updated_at_ms: millis(now_secs)?,
            },
            observations: Vec::new(),
            proofs: Vec::new(),
        };
        let mut durable = Self {
            store,
            config,
            resolver: resolver.clone(),
            bundle: bundle.clone(),
            storage_healthy: true,
        };
        durable.commit(resolver, bundle, now_secs)?;
        Ok(durable)
    }

    pub fn restore(
        store: Store,
        config: DurableResolverConfigV1,
        now_secs: u64,
    ) -> Result<Self, ChainError> {
        let mut bundle = store
            .load_chain_bundle(config.consensus.chain_id)
            .map_err(|_| ChainError::StorageUnavailable)?
            .ok_or(ChainError::InvalidLocalState)?;
        normalize(&mut bundle);
        let plaintext = unprotect_secret(&bundle.state.verified_header_state)
            .map_err(|_| ChainError::InvalidLocalState)?;
        if plaintext.len() > MAX_CHAIN_SNAPSHOT_BYTES {
            return Err(ChainError::InvalidLocalState);
        }
        let saved: LocalSnapshot = decode(&plaintext)?;
        if saved.domain != SNAPSHOT_DOMAIN
            || saved.config != config
            || saved.rows_hash != rows_hash(&bundle)?
            || bundle.state.updated_at_ms > millis(now_secs)?
            || bundle.state.registry_address != config.deployment.address
            || bundle.state.registry_code_hash != config.deployment.runtime_code_hash
            || bundle.state.checkpoint_hash != config.consensus.checkpoint.beacon_root
        {
            return Err(ChainError::InvalidLocalState);
        }
        let client = EthereumLightClient::from_local_state(
            config.consensus.clone(),
            &saved.consensus_json,
            now_secs,
        )?;
        if let Some(finalized) = client.observed_execution()
            && (finalized.block_number() != bundle.state.finalized_height
                || finalized.block_hash() != bundle.state.finalized_block_hash
                || finalized.state_root() != bundle.state.execution_state_root)
        {
            return Err(ChainError::InvalidLocalState);
        }
        let mut resolver = make_resolver(&config, client)?;
        let verifier = EthereumProofVerifier::new(config.deployment)?;
        for row in &bundle.proofs {
            if row.expires_at_ms < millis(now_secs)? {
                continue;
            }
            let saved: SavedProof = decode(&row.proof_cbor)?;
            let finalized = saved.finalized.authenticated_state();
            if finalized.chain_id() != config.consensus.chain_id
                || finalized.block_number() != row.finalized_height
                || finalized.block_number() > bundle.state.finalized_height
                || finalized.timestamp_secs() > now_secs
                || finalized
                    .timestamp_secs()
                    .checked_add(config.max_cache_age_secs)
                    .and_then(|time| time.checked_mul(1000))
                    != Some(row.expires_at_ms)
                || row.last_used_ms > millis(now_secs)?
            {
                return Err(ChainError::InvalidLocalState);
            }
            let identity = verifier.verify(&finalized, row.agent_id, &saved.proof)?;
            check_observation(&bundle, &identity)?;
            resolver.restore_verified(identity, row.last_used_ms / 1000, now_secs)?;
        }
        Ok(Self {
            store,
            config,
            resolver,
            bundle,
            storage_healthy: true,
        })
    }

    pub fn light_client(&self) -> &EthereumLightClient {
        self.resolver.light_client()
    }

    pub fn deployment(&self) -> RegistryDeploymentV1 {
        self.config.deployment
    }

    pub fn apply_update_json(&mut self, bytes: &[u8], now_secs: u64) -> Result<(), ChainError> {
        self.update_consensus(now_secs, |client| client.apply_update_json(bytes, now_secs))
    }

    pub fn apply_finality_json(&mut self, bytes: &[u8], now_secs: u64) -> Result<(), ChainError> {
        self.update_consensus(now_secs, |client| {
            client.apply_finality_json(bytes, now_secs)
        })
    }

    pub fn supply_execution_header(&mut self, rlp: &[u8], now_secs: u64) -> Result<(), ChainError> {
        self.update_consensus(now_secs, |client| {
            client.supply_execution_header(rlp, now_secs)
        })
    }

    pub fn accept_proof(
        &mut self,
        expected_agent: AgentId,
        proof: &IdentityProofV1,
        now_secs: u64,
    ) -> Result<(), ChainError> {
        self.ensure_storage()?;
        let identity = self
            .resolver
            .verify_fresh_proof(expected_agent, proof, now_secs)?;
        check_observation(&self.bundle, &identity)?;
        let mut candidate = self.resolver.clone();
        candidate.cache_verified(identity.clone(), now_secs)?;
        if identity.state().status == RegistryStatus::Unregistered {
            // Negative results expire in memory. Persisting arbitrary absent
            // AgentIds would create permanent parent rows for a transient cache.
            self.resolver = candidate;
            return Ok(());
        }
        let mut bundle = self.bundle.clone();
        bundle.proofs.retain(|row| {
            row.expires_at_ms >= now_secs.saturating_mul(1000) && row.agent_id != expected_agent
        });
        let encoded = encode(&SavedProof {
            finalized: SavedExecution::capture(identity.finalized()),
            proof: proof.clone(),
        })?;
        if encoded.len() <= MAX_CHAIN_PROOF_BYTES {
            if bundle.proofs.len() >= self.config.cache_capacity {
                let index = bundle
                    .proofs
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, row)| (row.last_used_ms, row.agent_id.0))
                    .map(|(index, _)| index)
                    .ok_or(ChainError::CacheFull)?;
                bundle.proofs.remove(index);
            }
            bundle.proofs.push(IdentityProofRow {
                agent_id: expected_agent,
                chain_id: identity.deployment().chain_id,
                finalized_height: identity.finalized().block_number(),
                proof_cbor: encoded.clone(),
                expires_at_ms: millis(
                    identity
                        .finalized()
                        .timestamp_secs()
                        .checked_add(self.config.max_cache_age_secs)
                        .ok_or(ChainError::InvalidLocalState)?,
                )?,
                last_used_ms: millis(now_secs)?,
            });
        }
        if identity.state().status != RegistryStatus::Unregistered {
            let observation = IdentityObservationRow {
                agent_id: expected_agent,
                chain_id: identity.deployment().chain_id,
                controller_address: identity.state().controller,
                state_commitment: identity.state().state_commitment,
                sequence: identity.state().sequence,
                status: if identity.state().status == RegistryStatus::Revoked {
                    ObservationStatus::Revoked
                } else {
                    ObservationStatus::Active
                },
                finalized_height: identity.finalized().block_number(),
                storage_proof_hash: *blake3::hash(&encoded).as_bytes(),
                verified_at_ms: millis(now_secs)?,
            };
            if let Some(row) = bundle
                .observations
                .iter_mut()
                .find(|row| row.agent_id == expected_agent)
            {
                *row = observation;
            } else {
                if bundle.observations.len() >= MAX_CHAIN_OBSERVATIONS {
                    return Err(ChainError::ObservationLimit);
                }
                bundle.observations.push(observation);
            }
        }
        self.commit(candidate, bundle, now_secs)
    }

    fn update_consensus(
        &mut self,
        now_secs: u64,
        update: impl FnOnce(&mut EthereumLightClient) -> Result<(), ChainError>,
    ) -> Result<(), ChainError> {
        self.ensure_storage()?;
        let mut candidate = self.resolver.clone();
        let result = update(candidate.light_client_mut());
        if result.is_ok() || result == Err(ChainError::ConflictingFinality) {
            self.commit(candidate, self.bundle.clone(), now_secs)?;
        }
        result
    }

    fn commit(
        &mut self,
        candidate: EthereumIdentityResolver,
        bundle: ChainBundle,
        now_secs: u64,
    ) -> Result<(), ChainError> {
        let result = self.commit_inner(candidate, bundle, now_secs);
        if result.is_err() {
            self.storage_healthy = false;
        }
        result
    }

    fn commit_inner(
        &mut self,
        candidate: EthereumIdentityResolver,
        mut bundle: ChainBundle,
        now_secs: u64,
    ) -> Result<(), ChainError> {
        let now_ms = millis(now_secs)?;
        if now_ms < bundle.state.updated_at_ms {
            return Err(ChainError::ClockBeforeState);
        }
        if let Some(finalized) = candidate.light_client().observed_execution() {
            bundle.state.finalized_height = finalized.block_number();
            bundle.state.finalized_block_hash = finalized.block_hash();
            bundle.state.execution_state_root = finalized.state_root();
        }
        bundle.state.updated_at_ms = now_ms;
        bundle.proofs.retain(|row| row.expires_at_ms >= now_ms);
        normalize(&mut bundle);
        let plaintext = encode(&LocalSnapshot {
            domain: SNAPSHOT_DOMAIN.to_owned(),
            config: self.config.clone(),
            consensus_json: candidate.light_client().local_state()?,
            rows_hash: rows_hash(&bundle)?,
        })?;
        if plaintext.len() > MAX_CHAIN_SNAPSHOT_BYTES {
            return Err(ChainError::InvalidLocalState);
        }
        let sealed = protect_secret(&plaintext).map_err(|_| ChainError::StorageUnavailable)?;
        if sealed.len() > MAX_CHAIN_SNAPSHOT_BYTES {
            return Err(ChainError::InvalidLocalState);
        }
        bundle.state.verified_header_state = sealed;
        let previous = &self.bundle.state.verified_header_state;
        let expected = (!previous.is_empty()).then_some(previous.as_slice());
        if self.store.save_chain_bundle(&bundle, expected).is_err() {
            self.storage_healthy = false;
            return Err(ChainError::StorageUnavailable);
        }
        self.bundle = bundle;
        self.resolver = candidate;
        Ok(())
    }

    fn ensure_storage(&self) -> Result<(), ChainError> {
        if !self.storage_healthy {
            return Err(ChainError::StorageUnavailable);
        }
        Ok(())
    }
}

impl IdentityResolver for DurableIdentityResolver {
    fn interface_version(&self) -> u16 {
        self.resolver.interface_version()
    }

    fn resolve(&mut self, agent: AgentId, now_secs: u64) -> IdentityResolution {
        if self
            .bundle
            .observations
            .iter()
            .any(|row| row.agent_id == agent && row.status == ObservationStatus::Revoked)
        {
            return IdentityResolution::Limited(LimitedReason::Revoked);
        }
        if !self.storage_healthy {
            return IdentityResolution::Limited(LimitedReason::ChainUnavailable);
        }
        if let Some(row) = self
            .bundle
            .proofs
            .iter_mut()
            .find(|row| row.agent_id == agent)
        {
            row.last_used_ms = now_secs.saturating_mul(1000);
        }
        self.resolver.resolve(agent, now_secs)
    }
}

fn make_resolver(
    config: &DurableResolverConfigV1,
    client: EthereumLightClient,
) -> Result<EthereumIdentityResolver, ChainError> {
    EthereumIdentityResolver::new(
        client,
        EthereumProofVerifier::new(config.deployment)?,
        config.max_cache_age_secs,
        config.cache_capacity,
    )
}

fn check_observation(bundle: &ChainBundle, identity: &VerifiedIdentity) -> Result<(), ChainError> {
    let Some(row) = bundle
        .observations
        .iter()
        .find(|row| row.agent_id == identity.agent_id())
    else {
        return Ok(());
    };
    let state = identity.state();
    if identity.finalized().block_number() < row.finalized_height
        || state.sequence < row.sequence
        || (state.sequence == row.sequence
            && (state.controller != row.controller_address
                || state.state_commitment != row.state_commitment
                || (state.status == RegistryStatus::Revoked)
                    != (row.status == ObservationStatus::Revoked)))
        || (row.status == ObservationStatus::Revoked && state.status != RegistryStatus::Revoked)
    {
        return Err(ChainError::Rollback);
    }
    Ok(())
}

fn normalize(bundle: &mut ChainBundle) {
    bundle.observations.sort_by_key(|row| row.agent_id.0);
    bundle.proofs.sort_by_key(|row| row.agent_id.0);
}

fn rows_hash(bundle: &ChainBundle) -> Result<[u8; 32], ChainError> {
    let mut state = bundle.state.clone();
    state.verified_header_state.clear();
    let mut hash = blake3::Hasher::new();
    hash.update(SNAPSHOT_DOMAIN.as_bytes());
    let mut append = |bytes: Vec<u8>| {
        hash.update(&(bytes.len() as u64).to_be_bytes());
        hash.update(&bytes);
    };
    append(encode(&state)?);
    for row in &bundle.observations {
        append(encode(row)?);
    }
    for row in &bundle.proofs {
        append(encode(row)?);
    }
    Ok(*hash.finalize().as_bytes())
}

fn encode(value: &impl Serialize) -> Result<Vec<u8>, ChainError> {
    cbor2::to_canonical_vec(value).map_err(|_| ChainError::InvalidLocalState)
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ChainError> {
    cbor2::validate_slice(bytes).map_err(|_| ChainError::InvalidLocalState)?;
    cbor2::from_slice(bytes).map_err(|_| ChainError::InvalidLocalState)
}

fn millis(seconds: u64) -> Result<u64, ChainError> {
    seconds
        .checked_mul(1000)
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or(ChainError::InvalidLocalState)
}

#[cfg(all(test, windows))]
#[path = "persistence_tests.rs"]
mod tests;
