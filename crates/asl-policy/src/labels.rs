use std::collections::{HashMap, HashSet};

use asl_types::{
    error::AslError,
    ids::AgentId,
    task::{GroupId, ResourceKey},
};

use crate::{
    audience::{AccessContext, MAX_TIME_MS, Scope},
    types::{AccessOperation, AccessRequest, PolicySnapshot, ResourceOrigin, ResourcePolicy},
};

const MAX_FILE_SIZE: u64 = 68_719_476_736;
const MAX_DIRECT_SOURCES: usize = 8;
const MAX_PROVENANCE_DEPTH: usize = 4;
const MAX_LEAF_REFERENCES: usize = 32;

pub(crate) struct Evaluation {
    pub(crate) resources: HashMap<ResourceKey, ResourcePolicy>,
    pub(crate) requester: Option<AgentId>,
    pub(crate) group_binding: Option<(GroupId, u64)>,
    pub(crate) valid_until_ms: u64,
}

pub(crate) fn evaluate(
    snapshot: &PolicySnapshot,
    scope: &Scope,
    request: &AccessRequest,
    now_ms: u64,
) -> Result<Evaluation, AslError> {
    let context = AccessContext::new(snapshot, scope, request, now_ms)?;
    let root = snapshot
        .resources
        .get(&request.resource_key)
        .ok_or(AslError::NotFound)?;
    if root.grant_id != request.grant_id {
        return Err(AslError::NotFound);
    }
    let mut walker = Provenance {
        snapshot,
        context: &context,
        now_ms,
        path: HashSet::new(),
        resources: HashMap::new(),
        leaves: 0,
        valid_until_ms: context.valid_until_ms,
    };
    walker.visit(&request.resource_key, 0)?;
    Ok(Evaluation {
        resources: walker.resources,
        requester: context.requester,
        group_binding: context.group_binding.clone(),
        valid_until_ms: walker.valid_until_ms,
    })
}

struct Provenance<'a, 'b> {
    snapshot: &'a PolicySnapshot,
    context: &'a AccessContext<'b>,
    now_ms: u64,
    path: HashSet<ResourceKey>,
    resources: HashMap<ResourceKey, ResourcePolicy>,
    leaves: usize,
    valid_until_ms: u64,
}

impl Provenance<'_, '_> {
    fn visit(&mut self, key: &ResourceKey, depth: usize) -> Result<(), AslError> {
        if depth > MAX_PROVENANCE_DEPTH || !self.path.insert(key.clone()) {
            return Err(AslError::NotFound);
        }
        let resource = self.snapshot.resources.get(key).ok_or(AslError::NotFound)?;
        let grant = self
            .snapshot
            .grants
            .get(&resource.grant_id)
            .ok_or(AslError::NotFound)?;
        if !resource.active
            || !resource.snapshot_ready
            || !grant.active
            || grant.epoch == 0
            || resource.grant_epoch != grant.epoch
            || resource.file_size > grant.max_snapshot_bytes
            || resource.file_size > MAX_FILE_SIZE
            || !canonical_extension(&resource.extension)
            || !grant.extensions.contains(&resource.extension)
            || !grant
                .allowed_operations
                .contains(&self.context.request.operation)
        {
            return Err(AslError::NotFound);
        }
        if let Some(until) = resource.retention_until_ms {
            if until > MAX_TIME_MS || self.now_ms >= until {
                return Err(AslError::NotFound);
            }
            self.valid_until_ms = self.valid_until_ms.min(until);
        }
        self.context.check_grant(self.snapshot, grant)?;
        if self.context.discloses() && depth > 0 && !grant.allow_derived_disclosure {
            return Err(AslError::NotFound);
        }
        match &resource.origin {
            ResourceOrigin::Derived {
                sources,
                disclosure_allowed,
            } => {
                if sources.is_empty()
                    || sources.len() > MAX_DIRECT_SOURCES
                    || (self.context.discloses() && !disclosure_allowed)
                {
                    return Err(AslError::NotFound);
                }
                // Traverse each occurrence: shared DAG branches still consume the leaf budget.
                for source in sources {
                    self.visit(source, depth + 1)?;
                }
            }
            ResourceOrigin::Local | ResourceOrigin::Remote { .. } => {
                if matches!(
                    resource.origin,
                    ResourceOrigin::Remote {
                        reuse_allowed: false
                    }
                ) && (self.context.request.operation == AccessOperation::WriteDerived
                    || (self.context.discloses() && depth > 0))
                {
                    return Err(AslError::NotFound);
                }
                self.leaves += 1;
                if self.leaves > MAX_LEAF_REFERENCES {
                    return Err(AslError::NotFound);
                }
            }
        }
        self.resources.insert(key.clone(), resource.clone());
        self.path.remove(key);
        Ok(())
    }
}

fn canonical_extension(extension: &str) -> bool {
    extension.strip_prefix('.').is_some_and(|suffix| {
        !suffix.is_empty()
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    })
}
