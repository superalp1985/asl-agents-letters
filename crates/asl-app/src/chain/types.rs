use std::fmt;

use asl_types::ids::AgentId;

use super::RegistryDeploymentV1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChainError {
    InvalidConfiguration,
    InvalidConsensusData,
    InvalidCheckpoint,
    ExpiredCheckpoint,
    ClockBeforeState,
    StaleFinality,
    ConflictingFinality,
    ExecutionHeaderRequired,
    InvalidExecutionHeader,
    InvalidProof,
    ProofTooLarge,
    WrongContext,
    WrongCodeHash,
    InvalidRegistryState,
    Rollback,
    CacheFull,
}

impl fmt::Display for ChainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidConfiguration => "invalid chain configuration",
            Self::InvalidConsensusData => "invalid consensus data",
            Self::InvalidCheckpoint => "checkpoint verification failed",
            Self::ExpiredCheckpoint => "trusted checkpoint has expired",
            Self::ClockBeforeState => "local time precedes verified state",
            Self::StaleFinality => "finalized state is stale",
            Self::ConflictingFinality => "conflicting finalized state",
            Self::ExecutionHeaderRequired => "finalized execution header is required",
            Self::InvalidExecutionHeader => "execution header does not match finalized block",
            Self::InvalidProof => "state proof verification failed",
            Self::ProofTooLarge => "state proof exceeds protocol limits",
            Self::WrongContext => "proof does not match the requested finalized state",
            Self::WrongCodeHash => "registry code hash does not match the deployment",
            Self::InvalidRegistryState => "invalid registry storage state",
            Self::Rollback => "identity state would roll back",
            Self::CacheFull => "verified identity cache is full",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ChainError {}

// Only the consensus adapter can construct a trusted execution state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizedExecution {
    pub(super) chain_id: u64,
    pub(super) beacon_slot: u64,
    pub(super) block_number: u64,
    pub(super) block_hash: [u8; 32],
    pub(super) state_root: [u8; 32],
    pub(super) timestamp_secs: u64,
}

impl FinalizedExecution {
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn beacon_slot(&self) -> u64 {
        self.beacon_slot
    }

    pub fn block_number(&self) -> u64 {
        self.block_number
    }

    pub fn block_hash(&self) -> [u8; 32] {
        self.block_hash
    }

    pub fn state_root(&self) -> [u8; 32] {
        self.state_root
    }

    pub fn timestamp_secs(&self) -> u64 {
        self.timestamp_secs
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountProofV1 {
    pub nonce: u64,
    pub balance: [u8; 32],
    pub storage_root: [u8; 32],
    pub code_hash: [u8; 32],
    pub nodes: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageProofV1 {
    pub slot: [u8; 32],
    pub value: [u8; 32],
    pub nodes: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityProofV1 {
    pub version: u16,
    pub agent_id: AgentId,
    pub chain_id: u64,
    pub registry_address: [u8; 20],
    pub block_number: u64,
    pub block_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub account: AccountProofV1,
    pub storage: Vec<StorageProofV1>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryStatus {
    Unregistered,
    Active,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryStateV1 {
    pub controller: [u8; 20],
    pub state_commitment: [u8; 32],
    pub sequence: u64,
    pub status: RegistryStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedIdentity {
    pub(super) agent_id: AgentId,
    pub(super) deployment: RegistryDeploymentV1,
    pub(super) finalized: FinalizedExecution,
    pub(super) state: RegistryStateV1,
}

impl VerifiedIdentity {
    pub fn agent_id(&self) -> AgentId {
        self.agent_id
    }

    pub fn deployment(&self) -> RegistryDeploymentV1 {
        self.deployment
    }

    pub fn finalized(&self) -> &FinalizedExecution {
        &self.finalized
    }

    pub fn state(&self) -> RegistryStateV1 {
        self.state
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LimitedReason {
    Unknown,
    StaleProof,
    ChainUnavailable,
    Unregistered,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentityResolution {
    Verified(Box<VerifiedIdentity>),
    Limited(LimitedReason),
}
