use asl_types::{
    error::AslError,
    ids::{AgentId, PeerId},
    task::GroupId,
};

use crate::types::{
    AccessOperation, AccessRequest, Audience, GrantPolicy, ModelPolicy, PolicySnapshot, Principal,
};

pub(crate) const MAX_TIME_MS: u64 = i64::MAX as u64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Scope {
    Local,
    Peer(PeerId),
    Group { peer: PeerId, group: GroupId },
}

impl Scope {
    pub(crate) fn peer(&self) -> Option<&PeerId> {
        match self {
            Self::Local => None,
            Self::Peer(peer) | Self::Group { peer, .. } => Some(peer),
        }
    }
}

pub(crate) struct AccessContext<'a> {
    pub(crate) scope: &'a Scope,
    pub(crate) request: &'a AccessRequest,
    pub(crate) requester: Option<AgentId>,
    pub(crate) group_binding: Option<(GroupId, u64)>,
    pub(crate) valid_until_ms: u64,
}

impl<'a> AccessContext<'a> {
    pub(crate) fn new(
        snapshot: &PolicySnapshot,
        scope: &'a Scope,
        request: &'a AccessRequest,
        now_ms: u64,
    ) -> Result<Self, AslError> {
        if now_ms > MAX_TIME_MS {
            return Err(AslError::NotFound);
        }
        let mut context = Self {
            scope,
            request,
            requester: None,
            group_binding: None,
            valid_until_ms: MAX_TIME_MS,
        };
        if let Some(peer) = scope.peer() {
            let device = snapshot.devices.get(peer).ok_or(AslError::NotFound)?;
            if !device.active
                || device.chain_valid_until_ms > MAX_TIME_MS
                || device.certificate_valid_until_ms > MAX_TIME_MS
                || now_ms >= device.chain_valid_until_ms
                || now_ms >= device.certificate_valid_until_ms
            {
                return Err(AslError::NotFound);
            }
            context.requester = Some(device.agent_id);
            context.valid_until_ms = device
                .chain_valid_until_ms
                .min(device.certificate_valid_until_ms);
        }
        if let Scope::Group { peer, group } = scope {
            let policy = snapshot.groups.get(group).ok_or(AslError::NotFound)?;
            if !policy.active || policy.membership_epoch == 0 || !policy.members.contains(peer) {
                return Err(AslError::NotFound);
            }
            context.group_binding = Some((group.clone(), policy.membership_epoch));
        }
        let valid_principal = match &request.principal {
            Principal::Agent(agent) => {
                context.requester == Some(*agent)
                    && !matches!(
                        request.operation,
                        AccessOperation::ModelInput | AccessOperation::PublishRecord
                    )
            }
            Principal::LocalTask(task) => {
                matches!(scope, Scope::Local)
                    && snapshot.local_tasks.contains(task)
                    && request.operation != AccessOperation::ModelInput
            }
            Principal::ModelProvider(provider) => {
                request.operation == AccessOperation::ModelInput
                    && snapshot
                        .providers
                        .get(provider)
                        .is_some_and(|policy| policy.authorized)
            }
        };
        if !valid_principal {
            return Err(AslError::NotFound);
        }
        Ok(context)
    }

    pub(crate) fn discloses(&self) -> bool {
        self.requester.is_some() || self.request.operation == AccessOperation::PublishRecord
    }

    pub(crate) fn check_grant(
        &self,
        snapshot: &PolicySnapshot,
        grant: &GrantPolicy,
    ) -> Result<(), AslError> {
        if self.request.operation == AccessOperation::PublishRecord
            && grant.audience != Audience::Public
        {
            return Err(AslError::NotFound);
        }
        if let Some(agent) = self.requester {
            let allowed = match &grant.audience {
                Audience::Public => true,
                Audience::Contacts => snapshot.contacts.contains(&agent),
                Audience::Peers(agents) => agents.contains(&agent),
                Audience::Group(group) => {
                    matches!(self.scope, Scope::Group { group: scoped, .. } if scoped == group)
                }
            };
            if !allowed {
                return Err(AslError::NotFound);
            }
        }
        if let Principal::ModelProvider(provider) = &self.request.principal {
            let allowed = match &grant.model_policy {
                ModelPolicy::Never => false,
                ModelPolicy::Providers(providers) => providers.contains(provider),
                ModelPolicy::LocalOnly(providers) => {
                    providers.contains(provider)
                        && snapshot
                            .providers
                            .get(provider)
                            .is_some_and(|policy| policy.authorized && policy.local)
                }
            };
            if !allowed {
                return Err(AslError::NotFound);
            }
        }
        Ok(())
    }
}
