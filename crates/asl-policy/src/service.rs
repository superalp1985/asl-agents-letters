use std::{collections::HashMap, sync::RwLock};

use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId},
    task::{GrantId, GroupId, ResourceKey},
};
use rand::{TryRng, rngs::SysRng};

use crate::{
    audience::{MAX_TIME_MS, Scope},
    labels::{Evaluation, evaluate},
    types::{AccessOperation, AccessRequest, PolicyRevision, PolicySnapshot, ResourcePolicy},
};

pub trait PolicyService {
    fn authorize(&self, request: &AccessRequest, now_ms: u64) -> Result<Permit, AslError>;
    fn revalidate(&self, permit: &Permit, now_ms: u64) -> Result<(), AslError>;
    fn revoke(&self, grant: GrantId, expected_epoch: u64) -> Result<PolicyRevision, AslError>;
}

/// An in-memory capability. Only its issuing engine and original scope can validate it.
#[derive(Clone, Debug)]
pub struct Permit {
    permit_id: Id128,
    issuer: Id128,
    scope: Scope,
    request: AccessRequest,
    grant_epoch: u64,
    policy_revision: PolicyRevision,
    content_id: Hash32,
    issued_at_ms: u64,
    expires_at_ms: u64,
    dependencies: HashMap<ResourceKey, ResourcePolicy>,
    requester_agent_id: Option<AgentId>,
    group_binding: Option<(GroupId, u64)>,
}

impl Permit {
    pub fn permit_id(&self) -> Id128 {
        self.permit_id
    }

    pub fn grant_id(&self) -> &GrantId {
        &self.request.grant_id
    }

    pub fn grant_epoch(&self) -> u64 {
        self.grant_epoch
    }

    pub fn policy_revision(&self) -> PolicyRevision {
        self.policy_revision
    }

    pub fn requester_agent_id(&self) -> Option<AgentId> {
        self.requester_agent_id
    }

    pub fn authenticated_device_peer_id(&self) -> Option<&PeerId> {
        self.scope.peer()
    }

    pub fn content_id(&self) -> Hash32 {
        self.content_id
    }

    pub fn operation(&self) -> AccessOperation {
        self.request.operation
    }

    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    pub fn group_binding(&self) -> Option<(GroupId, u64)> {
        self.group_binding.clone()
    }
}

pub struct PolicyEngine {
    state: RwLock<PolicySnapshot>,
    issuer: Id128,
    permit_lifetime_ms: u64,
}

impl PolicyEngine {
    pub fn new(snapshot: PolicySnapshot, permit_lifetime_ms: u64) -> Result<Self, AslError> {
        if !(1..=60_000).contains(&permit_lifetime_ms) {
            return Err(AslError::InvalidPolicyState);
        }
        validate_snapshot(&snapshot)?;
        Ok(Self {
            state: RwLock::new(snapshot),
            issuer: random_id()?,
            permit_lifetime_ms,
        })
    }

    pub fn snapshot(&self) -> Result<PolicySnapshot, AslError> {
        self.state
            .read()
            .map(|snapshot| snapshot.clone())
            .map_err(|_| AslError::InvalidPolicyState)
    }

    /// Replaces broker facts atomically; grant and group histories must retain their tombstones.
    pub fn replace_snapshot(
        &self,
        expected: PolicyRevision,
        next: PolicySnapshot,
    ) -> Result<PolicyRevision, AslError> {
        let mut current = self
            .state
            .write()
            .map_err(|_| AslError::InvalidPolicyState)?;
        if current.revision != expected {
            return Err(AslError::PolicyVersionConflict);
        }
        let next_revision = increment(current.revision.0)?;
        if next.revision != PolicyRevision(next_revision) {
            return Err(AslError::PolicyVersionConflict);
        }
        validate_snapshot(&next)?;
        for (id, previous) in &current.grants {
            let replacement = next.grants.get(id).ok_or(AslError::InvalidPolicyState)?;
            if !previous.active && replacement.active {
                return Err(AslError::GrantRevoked);
            }
            if replacement.epoch < previous.epoch
                || (replacement != previous && replacement.epoch == previous.epoch)
            {
                return Err(AslError::InvalidPolicyState);
            }
        }
        for (id, previous) in &current.groups {
            let replacement = next.groups.get(id).ok_or(AslError::InvalidPolicyState)?;
            if replacement.membership_epoch < previous.membership_epoch
                || (replacement != previous
                    && replacement.membership_epoch == previous.membership_epoch)
            {
                return Err(AslError::InvalidPolicyState);
            }
        }
        let revision = next.revision;
        *current = next;
        Ok(revision)
    }

    pub fn for_peer(&self, peer: PeerId) -> ScopedPolicy<'_> {
        ScopedPolicy {
            engine: self,
            scope: Scope::Peer(peer),
        }
    }

    pub fn for_group(&self, peer: PeerId, group: GroupId) -> ScopedPolicy<'_> {
        ScopedPolicy {
            engine: self,
            scope: Scope::Group { peer, group },
        }
    }

    fn authorize_in(
        &self,
        scope: &Scope,
        request: &AccessRequest,
        now_ms: u64,
    ) -> Result<Permit, AslError> {
        let snapshot = self.state.read().map_err(|_| AslError::NotFound)?;
        let evaluation = evaluate(&snapshot, scope, request, now_ms)?;
        let expires_at_ms = now_ms
            .checked_add(self.permit_lifetime_ms)
            .filter(|until| *until <= MAX_TIME_MS)
            .ok_or(AslError::NotFound)?
            .min(evaluation.valid_until_ms);
        let resource = snapshot
            .resources
            .get(&request.resource_key)
            .ok_or(AslError::NotFound)?;
        Ok(Permit {
            permit_id: random_id().map_err(|_| AslError::NotFound)?,
            issuer: self.issuer,
            scope: scope.clone(),
            request: request.clone(),
            grant_epoch: resource.grant_epoch,
            policy_revision: snapshot.revision,
            content_id: resource.content_id,
            issued_at_ms: now_ms,
            expires_at_ms,
            dependencies: evaluation.resources,
            requester_agent_id: evaluation.requester,
            group_binding: evaluation.group_binding,
        })
    }

    fn revalidate_in(&self, scope: &Scope, permit: &Permit, now_ms: u64) -> Result<(), AslError> {
        if permit.issuer != self.issuer
            || &permit.scope != scope
            || now_ms > MAX_TIME_MS
            || now_ms < permit.issued_at_ms
            || now_ms >= permit.expires_at_ms
        {
            return Err(AslError::NotFound);
        }
        let snapshot = self.state.read().map_err(|_| AslError::NotFound)?;
        let Evaluation {
            resources,
            requester,
            group_binding,
            ..
        } = evaluate(&snapshot, scope, &permit.request, now_ms)?;
        if resources != permit.dependencies
            || requester != permit.requester_agent_id
            || group_binding != permit.group_binding
        {
            return Err(AslError::NotFound);
        }
        Ok(())
    }
}

impl PolicyService for PolicyEngine {
    fn authorize(&self, request: &AccessRequest, now_ms: u64) -> Result<Permit, AslError> {
        self.authorize_in(&Scope::Local, request, now_ms)
    }

    fn revalidate(&self, permit: &Permit, now_ms: u64) -> Result<(), AslError> {
        self.revalidate_in(&Scope::Local, permit, now_ms)
    }

    /// Updates memory only; persistence, audit and cancellation fences belong to the caller.
    fn revoke(&self, grant: GrantId, expected_epoch: u64) -> Result<PolicyRevision, AslError> {
        let mut snapshot = self
            .state
            .write()
            .map_err(|_| AslError::InvalidPolicyState)?;
        let current = snapshot.grants.get(&grant).ok_or(AslError::NotFound)?;
        if current.epoch != expected_epoch {
            return Err(AslError::PolicyVersionConflict);
        }
        if !current.active {
            return Err(AslError::GrantRevoked);
        }
        let epoch = increment(current.epoch)?;
        let revision = PolicyRevision(increment(snapshot.revision.0)?);
        let current = snapshot
            .grants
            .get_mut(&grant)
            .ok_or(AslError::InvalidPolicyState)?;
        current.active = false;
        current.epoch = epoch;
        snapshot.revision = revision;
        Ok(revision)
    }
}

pub struct ScopedPolicy<'a> {
    engine: &'a PolicyEngine,
    scope: Scope,
}

impl PolicyService for ScopedPolicy<'_> {
    fn authorize(&self, request: &AccessRequest, now_ms: u64) -> Result<Permit, AslError> {
        self.engine.authorize_in(&self.scope, request, now_ms)
    }

    fn revalidate(&self, permit: &Permit, now_ms: u64) -> Result<(), AslError> {
        self.engine.revalidate_in(&self.scope, permit, now_ms)
    }

    fn revoke(&self, _grant: GrantId, _expected_epoch: u64) -> Result<PolicyRevision, AslError> {
        // A recipient scope is never local policy administration authority.
        Err(AslError::NotFound)
    }
}

fn validate_snapshot(snapshot: &PolicySnapshot) -> Result<(), AslError> {
    if snapshot.revision.0 == 0
        || snapshot.grants.values().any(|grant| grant.epoch == 0)
        || snapshot
            .resources
            .values()
            .any(|resource| resource.grant_epoch == 0)
        || snapshot
            .groups
            .values()
            .any(|group| group.membership_epoch == 0)
    {
        return Err(AslError::InvalidPolicyState);
    }
    Ok(())
}

fn increment(value: u64) -> Result<u64, AslError> {
    value.checked_add(1).ok_or(AslError::InvalidPolicyState)
}

fn random_id() -> Result<Id128, AslError> {
    let mut bytes = [0; 16];
    SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| AslError::InvalidPolicyState)?;
    Ok(Id128(bytes))
}
