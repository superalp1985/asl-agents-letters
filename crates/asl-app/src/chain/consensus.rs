use alloy_consensus::Header;
use alloy_primitives::B256;
use alloy_rlp::Decodable;
use helios_consensus_core::{
    apply_bootstrap, apply_finality_update, apply_update,
    consensus_spec::{ConsensusSpec, MainnetConsensusSpec},
    get_bits,
    types::{Bootstrap, FinalityUpdate, Fork, Forks, LightClientHeader, LightClientStore, Update},
    verify_bootstrap, verify_finality_update, verify_update,
};
use serde::Deserialize;

use super::{ChainError, ConsensusConfigV1, FinalizedExecution, ForkV1};

const MAX_CONSENSUS_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_EXECUTION_HEADER_BYTES: usize = 4096;

#[derive(Deserialize)]
struct BeaconResponse<T> {
    data: T,
}

pub struct EthereumLightClient {
    config: ConsensusConfigV1,
    forks: Forks,
    store: LightClientStore<MainnetConsensusSpec>,
    execution: Option<FinalizedExecution>,
    conflicting_finality: bool,
}

impl EthereumLightClient {
    pub fn bootstrap(
        config: ConsensusConfigV1,
        response_json: &[u8],
        now_secs: u64,
    ) -> Result<Self, ChainError> {
        config.validate()?;
        check_age(
            now_secs,
            config.slot_time(config.checkpoint.slot)?,
            config.max_checkpoint_age_secs,
            ChainError::ExpiredCheckpoint,
        )?;
        let forks = configured_forks(&config);
        let bootstrap: Bootstrap<MainnetConsensusSpec> = decode_response(response_json)?;
        if bootstrap.header().beacon().slot != config.checkpoint.slot {
            return Err(ChainError::InvalidCheckpoint);
        }
        verify_bootstrap(
            &bootstrap,
            B256::from(config.checkpoint.beacon_root),
            &forks,
        )
        .map_err(|_| ChainError::InvalidCheckpoint)?;
        let mut store = LightClientStore::default();
        apply_bootstrap(&mut store, &bootstrap);
        let execution = execution_from_payload(config.chain_id, &store.finalized_header)?;
        Ok(Self {
            config,
            forks,
            store,
            execution,
            conflicting_finality: false,
        })
    }

    pub fn chain_id(&self) -> u64 {
        self.config.chain_id
    }

    pub fn max_finality_age_secs(&self) -> u64 {
        self.config.max_finality_age_secs
    }

    pub fn finalized(&self, now_secs: u64) -> Result<FinalizedExecution, ChainError> {
        self.check_checkpoint_lifetime(now_secs)?;
        check_age(
            now_secs,
            self.config
                .slot_time(self.store.finalized_header.beacon().slot)?,
            self.config.max_finality_age_secs,
            ChainError::StaleFinality,
        )?;
        let execution = self
            .execution
            .as_ref()
            .ok_or(ChainError::ExecutionHeaderRequired)?;
        check_age(
            now_secs,
            execution.timestamp_secs,
            self.config.max_finality_age_secs,
            ChainError::StaleFinality,
        )?;
        Ok(execution.clone())
    }

    pub fn apply_update_json(
        &mut self,
        response_json: &[u8],
        now_secs: u64,
    ) -> Result<(), ChainError> {
        self.check_checkpoint_lifetime(now_secs)?;
        let update: Update<MainnetConsensusSpec> = decode_response(response_json)?;
        verify_update(
            &update,
            self.config.current_slot(now_secs)?,
            &self.store,
            B256::from(self.config.genesis_validators_root),
            &self.forks,
        )
        .map_err(|_| ChainError::InvalidConsensusData)?;
        self.check_verified_finality(
            &update.finalized_header(),
            get_bits::<MainnetConsensusSpec>(&update.sync_aggregate().sync_committee_bits),
        )?;
        let mut candidate = self.store.clone();
        apply_update(&mut candidate, &update);
        self.commit_verified_store(candidate)
    }

    pub fn apply_finality_json(
        &mut self,
        response_json: &[u8],
        now_secs: u64,
    ) -> Result<(), ChainError> {
        self.check_checkpoint_lifetime(now_secs)?;
        let update: FinalityUpdate<MainnetConsensusSpec> = decode_response(response_json)?;
        verify_finality_update(
            &update,
            self.config.current_slot(now_secs)?,
            &self.store,
            B256::from(self.config.genesis_validators_root),
            &self.forks,
        )
        .map_err(|_| ChainError::InvalidConsensusData)?;
        self.check_verified_finality(
            &update.finalized_header(),
            get_bits::<MainnetConsensusSpec>(&update.sync_aggregate().sync_committee_bits),
        )?;
        let mut candidate = self.store.clone();
        apply_finality_update(&mut candidate, &update);
        self.commit_verified_store(candidate)
    }

    // Gloas commits an execution block hash instead of its state-root payload.
    // Alloy checks the full header against that verified hash before use.
    pub fn supply_execution_header(&mut self, rlp: &[u8], now_secs: u64) -> Result<(), ChainError> {
        self.check_checkpoint_lifetime(now_secs)?;
        if rlp.len() > MAX_EXECUTION_HEADER_BYTES {
            return Err(ChainError::InvalidExecutionHeader);
        }
        let mut remaining = rlp;
        let header =
            Header::decode(&mut remaining).map_err(|_| ChainError::InvalidExecutionHeader)?;
        if !remaining.is_empty()
            || header.hash_slow() != execution_hash(&self.store.finalized_header)?
        {
            return Err(ChainError::InvalidExecutionHeader);
        }
        let candidate = FinalizedExecution {
            chain_id: self.config.chain_id,
            beacon_slot: self.store.finalized_header.beacon().slot,
            block_number: header.number,
            block_hash: header.hash_slow().0,
            state_root: header.state_root.0,
            timestamp_secs: header.timestamp,
        };
        if let Some(previous) = &self.execution
            && previous != &candidate
        {
            return Err(ChainError::InvalidExecutionHeader);
        }
        self.execution = Some(candidate);
        Ok(())
    }

    fn check_checkpoint_lifetime(&self, now_secs: u64) -> Result<(), ChainError> {
        if self.conflicting_finality {
            return Err(ChainError::ConflictingFinality);
        }
        check_age(
            now_secs,
            self.config
                .slot_time(self.store.finalized_header.beacon().slot)?,
            self.config.max_checkpoint_age_secs,
            ChainError::ExpiredCheckpoint,
        )
    }

    fn check_verified_finality(
        &mut self,
        header: &LightClientHeader,
        participants: u64,
    ) -> Result<(), ChainError> {
        // Helios ignores same-slot finalized headers when applying an update.
        // Detect an authenticated supermajority conflict before that information
        // is discarded. Unverified responses must never reach this check.
        if participants * 3 >= MainnetConsensusSpec::sync_committee_size() * 2
            && header.beacon().slot == self.store.finalized_header.beacon().slot
            && header.beacon() != self.store.finalized_header.beacon()
        {
            self.conflicting_finality = true;
            return Err(ChainError::ConflictingFinality);
        }
        Ok(())
    }

    fn commit_verified_store(
        &mut self,
        candidate: LightClientStore<MainnetConsensusSpec>,
    ) -> Result<(), ChainError> {
        let previous_header = &self.store.finalized_header;
        let next_header = &candidate.finalized_header;
        if next_header.beacon().slot < previous_header.beacon().slot {
            return Err(ChainError::Rollback);
        }
        if next_header.beacon().slot == previous_header.beacon().slot
            && next_header.beacon() != previous_header.beacon()
        {
            self.conflicting_finality = true;
            return Err(ChainError::ConflictingFinality);
        }
        let mut execution = execution_from_payload(self.config.chain_id, next_header)?;
        if execution.is_none()
            && let Some(previous) = &self.execution
            && B256::from(previous.block_hash) == execution_hash(next_header)?
        {
            let mut retained = previous.clone();
            retained.beacon_slot = next_header.beacon().slot;
            execution = Some(retained);
        }
        if let (Some(previous), Some(next)) = (&self.execution, &execution)
            && (next.block_number < previous.block_number
                || (next.block_number == previous.block_number
                    && (next.block_hash != previous.block_hash
                        || next.state_root != previous.state_root)))
        {
            self.conflicting_finality = true;
            return Err(ChainError::ConflictingFinality);
        }
        self.store = candidate;
        self.execution = execution;
        Ok(())
    }
}

fn execution_from_payload(
    chain_id: u64,
    header: &LightClientHeader,
) -> Result<Option<FinalizedExecution>, ChainError> {
    if matches!(header, LightClientHeader::Gloas(_)) {
        return Ok(None);
    }
    let execution = header
        .execution()
        .map_err(|_| ChainError::ExecutionHeaderRequired)?;
    Ok(Some(FinalizedExecution {
        chain_id,
        beacon_slot: header.beacon().slot,
        block_number: *execution.block_number(),
        block_hash: execution.block_hash().0,
        state_root: execution.state_root().0,
        timestamp_secs: *execution.timestamp(),
    }))
}

fn execution_hash(header: &LightClientHeader) -> Result<B256, ChainError> {
    match header {
        LightClientHeader::Gloas(header) => Ok(header.execution_block_hash),
        _ => header
            .execution()
            .map(|execution| *execution.block_hash())
            .map_err(|_| ChainError::ExecutionHeaderRequired),
    }
}

fn decode_response<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, ChainError> {
    if bytes.len() > MAX_CONSENSUS_RESPONSE_BYTES {
        return Err(ChainError::InvalidConsensusData);
    }
    serde_json::from_slice::<BeaconResponse<T>>(bytes)
        .map(|response| response.data)
        .map_err(|_| ChainError::InvalidConsensusData)
}

fn check_age(
    now_secs: u64,
    timestamp_secs: u64,
    max_age_secs: u64,
    stale: ChainError,
) -> Result<(), ChainError> {
    let age = now_secs
        .checked_sub(timestamp_secs)
        .ok_or(ChainError::ClockBeforeState)?;
    if age > max_age_secs {
        return Err(stale);
    }
    Ok(())
}

fn configured_forks(config: &ConsensusConfigV1) -> Forks {
    fn convert(fork: ForkV1) -> Fork {
        Fork {
            epoch: fork.epoch,
            fork_version: fork.version.into(),
        }
    }
    let forks = &config.forks;
    Forks {
        genesis: convert(forks.genesis),
        altair: convert(forks.altair),
        bellatrix: convert(forks.bellatrix),
        capella: convert(forks.capella),
        deneb: convert(forks.deneb),
        electra: convert(forks.electra),
        fulu: convert(forks.fulu),
        gloas: convert(forks.gloas),
    }
}

#[cfg(test)]
#[path = "consensus_tests.rs"]
mod tests;
