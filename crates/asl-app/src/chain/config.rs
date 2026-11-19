use super::ChainError;
use serde::{Deserialize, Serialize};

pub const INTERFACE_VERSION: u16 = 1;
pub const MAX_CHECKPOINT_AGE_SECS: u64 = 14 * 24 * 60 * 60;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryDeploymentV1 {
    pub version: u16,
    pub chain_id: u64,
    pub address: [u8; 20],
    pub runtime_code_hash: [u8; 32],
}

impl RegistryDeploymentV1 {
    pub(super) fn validate(&self) -> Result<(), ChainError> {
        if self.version != INTERFACE_VERSION
            || self.chain_id == 0
            || self.address == [0; 20]
            || self.runtime_code_hash == [0; 32]
        {
            return Err(ChainError::InvalidConfiguration);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointV1 {
    pub beacon_root: [u8; 32],
    pub slot: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForkV1 {
    pub epoch: u64,
    pub version: [u8; 4],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForksV1 {
    pub genesis: ForkV1,
    pub altair: ForkV1,
    pub bellatrix: ForkV1,
    pub capella: ForkV1,
    pub deneb: ForkV1,
    pub electra: ForkV1,
    pub fulu: ForkV1,
    pub gloas: ForkV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsensusConfigV1 {
    pub version: u16,
    pub chain_id: u64,
    pub genesis_time_secs: u64,
    pub genesis_validators_root: [u8; 32],
    pub seconds_per_slot: u64,
    pub forks: ForksV1,
    pub checkpoint: CheckpointV1,
    pub max_checkpoint_age_secs: u64,
    pub max_finality_age_secs: u64,
}

impl ConsensusConfigV1 {
    pub(super) fn validate(&self) -> Result<(), ChainError> {
        if self.version != INTERFACE_VERSION
            || self.chain_id == 0
            || self.genesis_validators_root == [0; 32]
            || self.checkpoint.beacon_root == [0; 32]
            || self.seconds_per_slot == 0
            || self.max_checkpoint_age_secs == 0
            || self.max_checkpoint_age_secs > MAX_CHECKPOINT_AGE_SECS
            || self.max_finality_age_secs == 0
            || self.max_finality_age_secs > self.max_checkpoint_age_secs
        {
            return Err(ChainError::InvalidConfiguration);
        }
        Ok(())
    }

    pub(super) fn slot_time(&self, slot: u64) -> Result<u64, ChainError> {
        slot.checked_mul(self.seconds_per_slot)
            .and_then(|elapsed| self.genesis_time_secs.checked_add(elapsed))
            .ok_or(ChainError::InvalidConfiguration)
    }

    pub(super) fn current_slot(&self, now_secs: u64) -> Result<u64, ChainError> {
        now_secs
            .checked_sub(self.genesis_time_secs)
            .map(|elapsed| elapsed / self.seconds_per_slot)
            .ok_or(ChainError::ClockBeforeState)
    }
}
