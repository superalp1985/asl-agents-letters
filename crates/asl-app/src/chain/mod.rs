mod config;
mod consensus;
mod http;
mod persistence;
mod proof;
mod resolver;
mod types;

#[cfg(test)]
pub(crate) mod test_support;

pub use config::{CheckpointV1, ConsensusConfigV1, ForkV1, ForksV1, RegistryDeploymentV1};
pub use consensus::EthereumLightClient;
pub use http::{ChainEndpointV1, ChainHttpClient, ChainHttpConfigV1, ChainSyncReport};
pub use persistence::{DurableIdentityResolver, DurableResolverConfigV1};
pub use proof::{EthereumProofVerifier, IdentityProofVerifier, registry_slots};
pub use resolver::{EthereumIdentityResolver, IdentityResolver};
pub use types::{
    AccountProofV1, ChainError, FinalizedExecution, IdentityProofV1, IdentityResolution,
    LimitedReason, RegistryStateV1, RegistryStatus, StorageProofV1, VerifiedIdentity,
};
