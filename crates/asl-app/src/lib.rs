pub mod act_history_export;
#[cfg(windows)]
mod agent_mail;
pub mod avatar;
pub mod capacity;
pub mod chain;
mod chain_refresh;
pub mod checkpoint_access;
pub mod contact_invite;
#[cfg(windows)]
pub mod contact_policy_sync;
#[cfg(not(windows))]
pub mod contact_policy_sync {
    use asl_store::Store;
    use asl_types::error::AslError;

    use crate::identity::AgentIdentity;

    #[derive(Clone, Debug)]
    pub struct PreparedPublication {
        pub record: Vec<u8>,
        pub revision: u64,
        pub expires_at_ms: u64,
        pub next_attempt_ms: u64,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum ImportOutcome {
        Applied(u64),
        KeptLocal(u64),
    }

    pub fn due(
        _identity: &AgentIdentity,
        _store: &Store,
        _now_ms: u64,
    ) -> Result<Option<PreparedPublication>, AslError> {
        Err(AslError::SandboxUnavailable)
    }

    pub fn prepare(
        _identity: &AgentIdentity,
        _store: &Store,
        _now_ms: u64,
    ) -> Result<PreparedPublication, AslError> {
        Err(AslError::SandboxUnavailable)
    }

    pub fn note_attempt(_store: &Store, _now_ms: u64) -> Result<(), AslError> {
        Err(AslError::SandboxUnavailable)
    }

    pub fn note_success(_store: &Store, _now_ms: u64) -> Result<(), AslError> {
        Err(AslError::SandboxUnavailable)
    }

    pub fn note_failure(_store: &Store, _now_ms: u64) -> Result<(), AslError> {
        Err(AslError::SandboxUnavailable)
    }

    pub fn note_success_for_revision(
        _store: &Store,
        _revision: u64,
        _now_ms: u64,
    ) -> Result<bool, AslError> {
        Err(AslError::SandboxUnavailable)
    }

    pub fn note_failure_for_revision(
        _store: &Store,
        _revision: u64,
        _now_ms: u64,
    ) -> Result<bool, AslError> {
        Err(AslError::SandboxUnavailable)
    }

    pub fn export(
        _identity: &AgentIdentity,
        _store: &Store,
        _now_ms: u64,
    ) -> Result<Vec<u8>, AslError> {
        Err(AslError::SandboxUnavailable)
    }

    pub fn import(
        _identity: &AgentIdentity,
        _store: &Store,
        _bytes: &[u8],
        _now_ms: u64,
    ) -> Result<ImportOutcome, AslError> {
        Err(AslError::SandboxUnavailable)
    }
}
pub mod diagnostics;
mod direct_inbound;
mod direct_outbound;
mod documents;
pub mod downloads;
pub mod identity;
pub mod identity_onboarding;
pub mod identity_registration;
pub mod infrastructure;
pub mod ipc;
pub mod libraries;
#[cfg(windows)]
pub mod mcp;
#[cfg(windows)]
pub mod migration;
pub mod model_endpoint_access;
pub mod network;
pub mod network_identity;
pub mod network_settings;
pub mod pairing;
pub mod paths;
pub mod profile;
pub mod profile_setup;
pub mod providers;
pub mod semantic_context;
pub mod supervisor;
mod transfer;
pub mod update;

pub use direct_outbound::{
    OutgoingQueryEvent, OutgoingQueryPort, OutgoingQueryRuntime, OutgoingQueryTicket,
    outgoing_query_channel,
};
pub use transfer::{
    CorruptFetchManifest, FetchManifestDetails, MatchedBulkResponse, VerifiedFetchManifest,
};
