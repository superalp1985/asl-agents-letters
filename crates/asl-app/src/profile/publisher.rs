use asl_policy::{AccessOperation, AccessRequest, PolicyService, Principal};
use asl_types::{
    error::AslError,
    protocol::{ConceptRef, Profile},
    record::RecordPayload,
    task::{GrantId, ResourceKey, TaskId},
};

use crate::{
    chain::{IdentityResolution, IdentityResolver, RegistryStatus},
    identity::AgentIdentity,
};

use super::sign_record;

const RENEWAL_MS: u64 = 5 * 60 * 1_000;
const PROFILE_LIFETIME_MS: u64 = 30 * 60 * 1_000;

#[derive(Clone, Debug)]
pub struct AvatarReference {
    pub grant_id: GrantId,
    pub resource_key: ResourceKey,
}

#[derive(Clone, Debug)]
pub struct ProfileConfiguration {
    pub capabilities: Vec<ConceptRef>,
    pub avatar: Option<AvatarReference>,
}

/// Produces publication candidates for the later network adapter. This is not
/// a background network publisher; withdrawal cannot erase remote copies.
pub struct ProfilePublisher<'a> {
    identity: &'a AgentIdentity,
    configuration: Option<ProfileConfiguration>,
    next_sequence: Option<u64>,
    next_renewal_ms: Option<u64>,
    last_poll_ms: Option<u64>,
}

impl<'a> ProfilePublisher<'a> {
    pub fn new(identity: &'a AgentIdentity, first_sequence: u64) -> Self {
        Self {
            identity,
            configuration: None,
            next_sequence: Some(first_sequence),
            next_renewal_ms: None,
            last_poll_ms: None,
        }
    }

    /// Called only for explicit local publication authorization.
    pub fn configure(&mut self, configuration: ProfileConfiguration) {
        self.configuration = Some(configuration);
        self.next_renewal_ms = None;
    }

    pub fn withdraw(&mut self) {
        self.configuration = None;
        self.next_renewal_ms = None;
    }

    pub fn poll_record(
        &mut self,
        now_ms: u64,
        task: TaskId,
        policy: &dyn PolicyService,
        resolver: &mut dyn IdentityResolver,
    ) -> Result<Option<Vec<u8>>, AslError> {
        if self.last_poll_ms.is_some_and(|previous| now_ms < previous) {
            return Err(AslError::ExpiredMessage);
        }
        self.last_poll_ms = Some(now_ms);
        let Some(configuration) = &self.configuration else {
            return Ok(None);
        };
        if self.next_renewal_ms.is_some_and(|due| now_ms < due) {
            return Ok(None);
        }
        if resolver.interface_version() != 1 {
            return Err(AslError::InvalidIdentity);
        }
        let IdentityResolution::Verified(identity) =
            resolver.resolve(self.identity.agent_id(), now_ms / 1_000)
        else {
            return Err(AslError::InvalidIdentity);
        };
        if identity.agent_id() != self.identity.agent_id()
            || identity.state().status != RegistryStatus::Active
            || identity.state().controller != self.identity.controller_address()
        {
            return Err(AslError::InvalidIdentity);
        }
        let sequence = self.next_sequence.ok_or(AslError::PolicyVersionConflict)?;
        let permit = configuration
            .avatar
            .as_ref()
            .map(|avatar| {
                policy.authorize(
                    &AccessRequest {
                        grant_id: avatar.grant_id.clone(),
                        resource_key: avatar.resource_key.clone(),
                        principal: Principal::LocalTask(task),
                        operation: AccessOperation::PublishRecord,
                    },
                    now_ms,
                )
            })
            .transpose()?;
        let bytes = sign_record(
            self.identity,
            RecordPayload::Profile(Profile {
                agent_id: self.identity.agent_id(),
                sequence,
                capabilities: configuration.capabilities.clone(),
                avatar: permit.as_ref().map(|permit| permit.content_id()),
            }),
            sequence,
            now_ms,
            PROFILE_LIFETIME_MS,
        )?;
        if let Some(permit) = &permit {
            policy.revalidate(permit, now_ms)?;
        }
        self.next_renewal_ms = Some(
            now_ms
                .checked_add(RENEWAL_MS)
                .ok_or(AslError::InvalidMessage)?,
        );
        self.next_sequence = sequence.checked_add(1);
        Ok(Some(bytes))
    }
}
