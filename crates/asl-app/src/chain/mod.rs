mod config;
mod consensus;
mod proof;
mod resolver;
mod types;

#[cfg(test)]
mod test_support;

pub use config::{CheckpointV1, ConsensusConfigV1, ForkV1, ForksV1, RegistryDeploymentV1};
pub use consensus::EthereumLightClient;
pub use proof::{EthereumProofVerifier, IdentityProofVerifier, registry_slots};
pub use resolver::{EthereumIdentityResolver, IdentityResolver};
pub use types::{
    AccountProofV1, ChainError, FinalizedExecution, IdentityProofV1, IdentityResolution,
    LimitedReason, RegistryStateV1, RegistryStatus, StorageProofV1, VerifiedIdentity,
};
