use std::collections::{HashMap, HashSet};

use asl_types::{
    ids::{AgentId, Hash32, PeerId},
    task::{GrantId, GroupId, ProviderId, ResourceKey, TaskId},
};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AccessOperation {
    Search,
    ReadMetadata,
    ReadChunk,
    PublishRecord,
    ModelInput,
    /// Authorizes reuse of sources; the caller must separately authorize its destination write grant.
    WriteDerived,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Principal {
    Agent(AgentId),
    LocalTask(TaskId),
    ModelProvider(ProviderId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessRequest {
    pub grant_id: GrantId,
    pub resource_key: ResourceKey,
    pub principal: Principal,
    pub operation: AccessOperation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyRevision(pub u64);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Audience {
    Public,
    Contacts,
    Peers(HashSet<AgentId>),
    Group(GroupId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelPolicy {
    Never,
    LocalOnly(HashSet<ProviderId>),
    Providers(HashSet<ProviderId>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantPolicy {
    pub epoch: u64,
    pub active: bool,
    pub audience: Audience,
    pub model_policy: ModelPolicy,
    pub extensions: HashSet<String>,
    pub max_snapshot_bytes: u64,
    pub allowed_operations: HashSet<AccessOperation>,
    pub allow_derived_disclosure: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResourceOrigin {
    Local,
    Remote {
        reuse_allowed: bool,
    },
    Derived {
        sources: Vec<ResourceKey>,
        disclosure_allowed: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourcePolicy {
    pub content_id: Hash32,
    pub grant_id: GrantId,
    pub grant_epoch: u64,
    pub active: bool,
    pub snapshot_ready: bool,
    pub file_size: u64,
    pub extension: String,
    pub retention_until_ms: Option<u64>,
    pub origin: ResourceOrigin,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedDevice {
    pub agent_id: AgentId,
    pub active: bool,
    pub chain_valid_until_ms: u64,
    pub certificate_valid_until_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderPolicy {
    pub authorized: bool,
    pub local: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupPolicy {
    pub active: bool,
    pub membership_epoch: u64,
    pub members: HashSet<PeerId>,
}

/// Verified local broker facts, never authority supplied by a wire message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicySnapshot {
    pub revision: PolicyRevision,
    pub grants: HashMap<GrantId, GrantPolicy>,
    pub resources: HashMap<ResourceKey, ResourcePolicy>,
    pub devices: HashMap<PeerId, AuthenticatedDevice>,
    pub contacts: HashSet<AgentId>,
    pub providers: HashMap<ProviderId, ProviderPolicy>,
    pub groups: HashMap<GroupId, GroupPolicy>,
    pub local_tasks: HashSet<TaskId>,
}

impl Default for PolicySnapshot {
    fn default() -> Self {
        Self {
            revision: PolicyRevision(1),
            grants: HashMap::new(),
            resources: HashMap::new(),
            devices: HashMap::new(),
            contacts: HashSet::new(),
            providers: HashMap::new(),
            groups: HashMap::new(),
            local_tasks: HashSet::new(),
        }
    }
}
