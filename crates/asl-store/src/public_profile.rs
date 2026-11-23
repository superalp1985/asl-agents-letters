//! Local profile signing and separate explicit DHT disclosure permission.

use asl_policy::{
    AccessOperation, Audience, GrantPolicy, ModelPolicy, PolicyRevision, PolicySnapshot,
    ResourceOrigin, ResourcePolicy,
};
use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32},
    manifest::{Manifest, content_id, encode_manifest},
    protocol::{ConceptRef, Profile},
    record::{RecordPayload, SignedRecord, decode_record},
    task::TaskId,
};
use rusqlite::{Connection, TransactionBehavior};
use serde::{Deserialize, Serialize};

use crate::{
    Store,
    avatar_publication::{AvatarGrant, MAX_IMAGE_BYTES, current_grant},
    current_time_ms, database_error,
    network_privacy::network_pause_requested,
    read_setting, write_setting,
};

const KEY: &str = "identity.profile_signing_v1";
pub const PROFILE_RENEWAL_MS: u64 = 5 * 60 * 1_000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSigningApproval {
    pub agent_id: AgentId,
    pub topics: Vec<u32>,
    #[serde(default)]
    pub publish: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    avatar: Option<AvatarGrant>,
    revision: u64,
}

impl ProfileSigningApproval {
    pub fn avatar(&self) -> Option<&AvatarGrant> {
        self.avatar.as_ref()
    }
}

pub fn profile_topic(concept_id: u32) -> ConceptRef {
    ConceptRef {
        vocabulary_id: 1,
        concept_id,
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProfileCandidateStatus {
    pub sequence: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Default, Serialize)]
pub struct ProfileSigningStatus {
    pub approval: Option<ProfileSigningApproval>,
    pub change_pending: bool,
    pub last_candidate: Option<ProfileCandidateStatus>,
    pub last_publication: Option<ProfilePublicationResult>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfilePublicationResult {
    Submitted,
    DhtAcknowledged,
    NoAcknowledgment,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct State {
    revision: u64,
    approval: Option<ProfileSigningApproval>,
    candidate: Option<ProfileCandidateStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    candidate_digest: Option<Hash32>,
    #[serde(default)]
    publication: Option<ProfilePublicationResult>,
    #[serde(default)]
    handoff: Option<ProfileHandoff>,
    #[serde(default)]
    change: Option<ApprovalChange>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProfileHandoff {
    pub operation: [u8; 16],
    pub net_pid: u32,
}

#[derive(Deserialize, Serialize)]
struct ApprovalChange {
    next: Option<ProfileSigningApproval>,
}

impl State {
    fn selected_approval(&self) -> Option<&ProfileSigningApproval> {
        self.change
            .as_ref()
            .map_or(self.approval.as_ref(), |change| change.next.as_ref())
    }

    fn next_revision(&self) -> Result<u64, AslError> {
        self.revision
            .checked_add(1)
            .ok_or(AslError::PolicyVersionConflict)
    }

    fn revise(&mut self, revision: u64, next: Option<ProfileSigningApproval>) {
        self.revision = revision;
        self.candidate = None;
        self.candidate_digest = None;
        self.publication = None;
        if self.handoff.is_some() {
            self.change = Some(ApprovalChange { next });
        } else {
            self.change = None;
            self.approval = next;
        }
    }

    fn matches(
        &self,
        db: &Connection,
        approval: &ProfileSigningApproval,
    ) -> Result<bool, AslError> {
        Ok(self.change.is_none()
            && self.approval.as_ref() == Some(approval)
            && avatar_is_current(db, approval)?)
    }
}

/// Call inside the transaction that changes the avatar grant. Never adopt a
/// new grant here, including when a topic approval is waiting on cancellation.
pub(crate) fn avatar_changed(db: &Connection, agent: AgentId) -> Result<(), AslError> {
    let mut state = read(db)?;
    let mut next = state.selected_approval().cloned();
    if !state.approval.as_ref().is_some_and(|a| a.agent_id == agent)
        && !next.as_ref().is_some_and(|a| a.agent_id == agent)
    {
        return Ok(());
    }
    let revision = state.next_revision()?;
    if let Some(approval) = next.as_mut().filter(|a| a.agent_id == agent) {
        approval.revision = revision;
        if !avatar_is_current(db, approval)? {
            approval.avatar = None;
        }
    }
    state.revise(revision, next);
    write(db, &state)
}

/// Finish explicit avatar confirmation against the selected public approval.
/// Call inside the write transaction that establishes the grant.
pub(crate) fn approve_profile_avatar(db: &Connection, grant: &AvatarGrant) -> Result<(), AslError> {
    if current_grant(db, grant.agent_id)?.as_ref() != Some(grant) {
        return Err(AslError::PolicyVersionConflict);
    }
    let mut state = read(db)?;
    let Some(mut next) = state
        .selected_approval()
        .filter(|a| a.agent_id == grant.agent_id && a.publish)
        .cloned()
    else {
        return Ok(());
    };
    if next.avatar.as_ref() == Some(grant) {
        return Ok(());
    }
    let revision = state.next_revision()?;
    next.revision = revision;
    next.avatar = Some(grant.clone());
    state.revise(revision, Some(next));
    write(db, &state)
}

fn avatar_is_current(db: &Connection, approval: &ProfileSigningApproval) -> Result<bool, AslError> {
    match approval.avatar() {
        None => Ok(true),
        Some(grant) => Ok(approval.publish
            && grant.agent_id == approval.agent_id
            && current_grant(db, approval.agent_id)?.as_ref() == Some(grant)),
    }
}

impl Store {
    pub fn set_profile_signing_approval(
        &mut self,
        agent_id: AgentId,
        topics: Vec<u32>,
    ) -> Result<(), AslError> {
        self.update_profile_signing_approval(Some((agent_id, validate_topics(topics)?, false)))
    }

    pub fn approve_profile_publication(
        &mut self,
        agent_id: AgentId,
        topics: Vec<u32>,
    ) -> Result<(), AslError> {
        self.update_profile_signing_approval(Some((agent_id, validate_topics(topics)?, true)))
    }

    pub fn revoke_profile_signing_approval(&mut self) -> Result<(), AslError> {
        self.update_profile_signing_approval(None)
    }

    fn update_profile_signing_approval(
        &mut self,
        selection: Option<(AgentId, Vec<u32>, bool)>,
    ) -> Result<(), AslError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let mut state = read(&tx)?;
        let revision = state.next_revision()?;
        let next = if let Some((agent_id, topics, publish)) = selection {
            let avatar = if publish {
                current_grant(&tx, agent_id)?
            } else {
                None
            };
            Some(ProfileSigningApproval {
                agent_id,
                topics,
                publish,
                avatar,
                revision,
            })
        } else {
            None
        };
        state.revise(revision, next);
        write(&tx, &state)?;
        tx.commit().map_err(database_error)
    }

    pub fn profile_signing_status(&self) -> Result<ProfileSigningStatus, AslError> {
        profile_signing_status(&self.connection)
    }

    pub fn current_public_profile(
        &self,
        agent: AgentId,
    ) -> Result<Option<ProfileSigningApproval>, AslError> {
        let tx = self
            .connection
            .unchecked_transaction()
            .map_err(database_error)?;
        let state = read(&tx)?;
        if let Some(approval) = state
            .approval
            .filter(|_| state.change.is_none())
            .filter(|approval| approval.publish && approval.agent_id == agent)
            && avatar_is_current(&tx, &approval)?
        {
            return Ok(Some(approval));
        }
        Ok(None)
    }

    /// Project only the approved, app-managed artifact into PublishRecord
    /// policy. It has no corresponding directory or search permission.
    pub fn profile_signing_policy(
        &self,
        approval: &ProfileSigningApproval,
        task: TaskId,
    ) -> Result<PolicySnapshot, AslError> {
        let mut policy = PolicySnapshot {
            revision: PolicyRevision(approval.revision),
            ..PolicySnapshot::default()
        };
        let Some(grant) = approval.avatar() else {
            return Ok(policy);
        };
        let tx = self
            .connection
            .unchecked_transaction()
            .map_err(database_error)?;
        if !read(&tx)?.matches(&tx, approval)? {
            return Err(AslError::PolicyVersionConflict);
        }
        let image: Vec<u8> = tx
            .query_row(
                "SELECT image FROM local_avatar_selection WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        let extension = if image.starts_with(b"\x89PNG\r\n\x1a\n") {
            ".png"
        } else if image.starts_with(b"RIFF") && image.get(8..12) == Some(&b"WEBP"[..]) {
            ".webp"
        } else {
            return Err(AslError::InvalidDatabase);
        };
        if image.len() > MAX_IMAGE_BYTES {
            return Err(AslError::InvalidDatabase);
        }
        let manifest = Manifest::from_bytes(&image).map_err(|_| AslError::InvalidDatabase)?;
        let encoded = encode_manifest(&manifest).map_err(|_| AslError::InvalidDatabase)?;
        if content_id(&encoded) != grant.content_id.0 {
            return Err(AslError::InvalidDatabase);
        }
        policy.local_tasks.insert(task);
        policy.grants.insert(
            grant.grant_id.clone(),
            GrantPolicy {
                epoch: grant.epoch,
                active: true,
                audience: Audience::Public,
                model_policy: ModelPolicy::Never,
                extensions: [extension.into()].into(),
                max_snapshot_bytes: MAX_IMAGE_BYTES as u64,
                allowed_operations: [AccessOperation::PublishRecord].into(),
                allow_derived_disclosure: false,
            },
        );
        policy.resources.insert(
            grant.resource_key.clone(),
            ResourcePolicy {
                content_id: grant.content_id,
                grant_id: grant.grant_id.clone(),
                grant_epoch: grant.epoch,
                active: true,
                snapshot_ready: true,
                file_size: image.len() as u64,
                extension: extension.into(),
                retention_until_ms: None,
                origin: ResourceOrigin::Local,
            },
        );
        Ok(policy)
    }

    pub fn profile_handoff(&self) -> Result<Option<ProfileHandoff>, AslError> {
        Ok(read(&self.connection)?.handoff)
    }

    /// Commit before releasing any signed bytes to IPC. A concurrent edit
    /// cannot complete until Net has consumed or discarded this operation.
    pub fn reserve_profile_handoff(
        &mut self,
        approval: &ProfileSigningApproval,
        handoff: ProfileHandoff,
    ) -> Result<bool, AslError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let mut state = read(&tx)?;
        if !approval.publish
            || state.handoff.is_some()
            || !state.matches(&tx, approval)?
            || network_pause_requested(&tx)?
        {
            return Ok(false);
        }
        state.handoff = Some(handoff);
        write(&tx, &state)?;
        tx.commit().map_err(database_error)?;
        Ok(true)
    }

    /// Release a handoff after matching cancellation or confirmed process exit.
    pub fn finish_profile_handoff(&mut self, operation: [u8; 16]) -> Result<(), AslError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let mut state = read(&tx)?;
        if state.handoff.is_some_and(|h| h.operation == operation) {
            state.handoff = None;
            if let Some(change) = state.change.take() {
                state.approval = change.next;
            }
            write(&tx, &state)?;
        }
        tx.commit().map_err(database_error)
    }

    /// A PUT receipt may finish only a still-current operation. A pending
    /// change instead waits for the matching cancel receipt or Net exit.
    pub fn acknowledge_profile_handoff(
        &mut self,
        approval: &ProfileSigningApproval,
        operation: [u8; 16],
        outcome: ProfilePublicationResult,
    ) -> Result<bool, AslError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let mut state = read(&tx)?;
        if !state.handoff.is_some_and(|h| h.operation == operation)
            || !approval.publish
            || !state.matches(&tx, approval)?
            || network_pause_requested(&tx)?
        {
            return Ok(false);
        }
        state.handoff = None;
        state.publication = Some(outcome);
        write(&tx, &state)?;
        tx.commit().map_err(database_error)?;
        Ok(true)
    }

    /// Order a nonblocking, unsigned Net prepare against revocation and pause.
    pub fn with_current_public_profile(
        &mut self,
        approval: &ProfileSigningApproval,
        enqueue: impl FnOnce() -> Result<bool, AslError>,
    ) -> Result<bool, AslError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let state = read(&tx)?;
        if !approval.publish
            || state.handoff.is_some()
            || !state.matches(&tx, approval)?
            || network_pause_requested(&tx)?
        {
            return Ok(false);
        }
        enqueue()
    }

    /// Signed bytes may only be queued for the reserved operation, under the
    /// same write lock used by avatar and profile changes.
    pub fn with_current_profile_handoff(
        &mut self,
        approval: &ProfileSigningApproval,
        operation: [u8; 16],
        bytes: Vec<u8>,
        enqueue: impl FnOnce(Vec<u8>) -> Result<bool, AslError>,
    ) -> Result<bool, AslError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let state = read(&tx)?;
        if !state.handoff.is_some_and(|h| h.operation == operation)
            || !approval.publish
            || !state.matches(&tx, approval)?
            || network_pause_requested(&tx)?
        {
            return Ok(false);
        }
        check_candidate(approval, &decode_record(&bytes)?)?;
        if state.candidate_digest != Some(Hash32(*blake3::hash(&bytes).as_bytes())) {
            return Ok(false);
        }
        enqueue(bytes)
    }

    pub fn observe_profile_publication(
        &mut self,
        approval: &ProfileSigningApproval,
        outcome: ProfilePublicationResult,
    ) -> Result<(), AslError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let mut state = read(&tx)?;
        if approval.publish && state.matches(&tx, approval)? {
            state.publication = Some(outcome);
            write(&tx, &state)?;
        }
        tx.commit().map_err(database_error)
    }

    pub fn profile_signing_due(
        &self,
        agent_id: AgentId,
        now_ms: u64,
    ) -> Result<Option<ProfileSigningApproval>, AslError> {
        let state = read(&self.connection)?;
        Ok(state.approval.filter(|approval| {
            !approval.publish
                && approval.agent_id == agent_id
                && state.candidate.is_none_or(|record| {
                    now_ms.saturating_sub(record.issued_at_ms) >= PROFILE_RENEWAL_MS
                })
        }))
    }

    /// Commit a local observation of the actual candidate, only while the
    /// exact approval is still current. No candidate bytes are exported.
    pub fn observe_profile_candidate(
        &mut self,
        approval: &ProfileSigningApproval,
        bytes: &[u8],
    ) -> Result<bool, AslError> {
        let signed = decode_record(bytes)?;
        check_candidate(approval, &signed)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let mut state = read(&tx)?;
        if !state.matches(&tx, approval)? {
            return Ok(false);
        }
        state.candidate = Some(ProfileCandidateStatus {
            sequence: signed.record.sequence,
            issued_at_ms: signed.record.issued_at_ms,
            expires_at_ms: signed.record.expires_at_ms,
        });
        state.candidate_digest = Some(Hash32(*blake3::hash(bytes).as_bytes()));
        write(&tx, &state)?;
        tx.commit().map_err(database_error)?;
        Ok(true)
    }
}

fn check_candidate(
    approval: &ProfileSigningApproval,
    signed: &SignedRecord,
) -> Result<(), AslError> {
    let RecordPayload::Profile(Profile {
        agent_id,
        avatar,
        capabilities,
        ..
    }) = &signed.record.payload
    else {
        return Err(AslError::InvalidMessage);
    };
    if *agent_id != approval.agent_id
        || *avatar != approval.avatar().map(|grant| grant.content_id)
        || !capabilities
            .iter()
            .copied()
            .eq(approval.topics.iter().copied().map(profile_topic))
    {
        return Err(AslError::PolicyDenied);
    }
    Ok(())
}

pub(crate) fn profile_signing_status(db: &Connection) -> Result<ProfileSigningStatus, AslError> {
    let state = read(db)?;
    Ok(ProfileSigningStatus {
        change_pending: state.change.is_some(),
        approval: state.change.map_or(state.approval, |change| change.next),
        last_candidate: state.candidate,
        last_publication: state.publication,
    })
}

fn validate_topics(mut topics: Vec<u32>) -> Result<Vec<u32>, AslError> {
    if topics.is_empty() || topics.iter().any(|id| !profile_topic(*id).is_topic()) {
        return Err(AslError::InvalidMessage);
    }
    topics.sort_unstable();
    if topics.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(AslError::InvalidMessage);
    }
    Ok(topics)
}

fn read(db: &Connection) -> Result<State, AslError> {
    read_setting(db, KEY)?
        .map(|value| serde_json::from_str(&value).map_err(|_| AslError::InvalidDatabase))
        .transpose()
        .map(Option::unwrap_or_default)
}

fn write(db: &Connection, state: &State) -> Result<(), AslError> {
    let value = serde_json::to_string(state).map_err(|_| AslError::InvalidDatabase)?;
    write_setting(db, KEY, &value, current_time_ms())
}

#[cfg(test)]
mod tests {
    use super::*;
    use asl_policy::{AccessRequest, PolicyEngine, PolicyService, Principal};
    use asl_types::{
        ids::{Id128, Signature65},
        record::{UnsignedRecord, encode_record},
    };

    use crate::{
        dashboard::{Dashboard, LocalIdentityProjection},
        open_store,
    };

    fn select_avatar(store: &mut Store, agent: AgentId) -> String {
        let png = hex::decode(concat!(
            "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489",
            "0000000d49444154789c636000020000050001a5f645400000000049454e44ae426082"
        ))
        .unwrap();
        store
            .set_local_identity_projection(&LocalIdentityProjection {
                agent_id: bs58::encode(agent.0).into_string(),
                peer_id: String::new(),
                network_state: "pending_anchor".into(),
                binding_code: String::new(),
            })
            .unwrap();
        store.replace_sanitized_avatar(Some(&png)).unwrap();
        store.avatar_review().unwrap().unwrap().token.unwrap()
    }

    fn candidate(agent: AgentId, sequence: u64, avatar: Option<Hash32>) -> Vec<u8> {
        encode_record(&SignedRecord {
            record: UnsignedRecord {
                payload: RecordPayload::Profile(Profile {
                    agent_id: agent,
                    sequence,
                    capabilities: vec![profile_topic(101)],
                    avatar,
                }),
                sequence,
                issued_at_ms: 1_000,
                expires_at_ms: 61_000,
            },
            signature: Signature65([1; 65]),
        })
        .unwrap()
    }

    #[test]
    fn profile_avatar_approvals_compose_in_either_order() {
        for avatar_first in [true, false] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("asl.sqlite3");
            let mut store = open_store(&path).unwrap();
            let agent = AgentId([7; 32]);
            let reviewed = select_avatar(&mut store, agent);
            if avatar_first {
                store.approve_avatar_reference(agent, &reviewed).unwrap();
                assert!(store.current_public_profile(agent).unwrap().is_none());
                store.approve_profile_publication(agent, vec![101]).unwrap();
            } else {
                store.approve_profile_publication(agent, vec![101]).unwrap();
                let old = store.current_public_profile(agent).unwrap().unwrap();
                assert!(old.avatar().is_none());
                store.approve_avatar_reference(agent, &reviewed).unwrap();
                assert!(
                    !store
                        .with_current_public_profile(&old, || panic!("old approval"))
                        .unwrap()
                );
            }
            let grant = current_grant(&store.connection, agent).unwrap().unwrap();
            drop(store);
            let mut store = open_store(&path).unwrap();
            let approval = store.current_public_profile(agent).unwrap().unwrap();
            assert_eq!(approval.avatar(), Some(&grant));

            let task = TaskId(Id128([2; 16]));
            let snapshot = store
                .profile_signing_policy(&approval, task.clone())
                .unwrap();
            let policy = PolicyEngine::new(snapshot, 10_000).unwrap();
            let mut request = AccessRequest {
                grant_id: grant.grant_id,
                resource_key: grant.resource_key,
                principal: Principal::LocalTask(task),
                operation: AccessOperation::PublishRecord,
            };
            let permit = policy.authorize(&request, 1_000).unwrap();
            assert_eq!(permit.content_id(), grant.content_id);
            request.operation = AccessOperation::ReadChunk;
            assert!(policy.authorize(&request, 1_000).is_err());

            let other = AgentId([8; 32]);
            store.approve_profile_publication(other, vec![101]).unwrap();
            assert!(
                store
                    .current_public_profile(other)
                    .unwrap()
                    .unwrap()
                    .avatar()
                    .is_none()
            );
            store
                .set_profile_signing_approval(agent, vec![101])
                .unwrap();
            assert!(
                store
                    .profile_signing_due(agent, 1_000)
                    .unwrap()
                    .unwrap()
                    .avatar()
                    .is_none()
            );
        }
    }

    #[test]
    fn profile_avatar_replacement_fences_old_handoff_and_preserves_pending_topics() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("asl.sqlite3");
        let mut store = open_store(&path).unwrap();
        let agent = AgentId([7; 32]);
        let reviewed = select_avatar(&mut store, agent);
        store.approve_avatar_reference(agent, &reviewed).unwrap();
        store.approve_profile_publication(agent, vec![101]).unwrap();
        let old = store.current_public_profile(agent).unwrap().unwrap();
        let avatar = Some(old.avatar().unwrap().content_id);
        let bytes = candidate(agent, 1, avatar);
        let handoff = ProfileHandoff {
            operation: [3; 16],
            net_pid: std::process::id(),
        };
        assert!(matches!(
            store.observe_profile_candidate(&old, &candidate(agent, 1, Some(Hash32([9; 32])))),
            Err(AslError::PolicyDenied)
        ));
        assert!(store.observe_profile_candidate(&old, &bytes).unwrap());
        assert!(store.reserve_profile_handoff(&old, handoff).unwrap());
        assert!(
            !store
                .with_current_profile_handoff(&old, [4; 16], bytes.clone(), |_| panic!(
                    "wrong operation"
                ))
                .unwrap()
        );
        assert!(
            !store
                .with_current_profile_handoff(
                    &old,
                    handoff.operation,
                    candidate(agent, 2, avatar),
                    |_| { panic!("unobserved signature") }
                )
                .unwrap()
        );
        assert!(
            store
                .with_current_profile_handoff(&old, handoff.operation, bytes.clone(), |value| Ok(
                    value == bytes
                ))
                .unwrap()
        );

        let mut cli = open_store(&path).unwrap();
        cli.approve_profile_publication(agent, vec![104]).unwrap();
        let replacement = select_avatar(&mut cli, agent);
        assert_ne!(reviewed, replacement);
        let status = cli.profile_signing_status().unwrap();
        assert!(status.change_pending && status.last_candidate.is_none());
        let next = status.approval.unwrap();
        assert_eq!(next.topics, [104]);
        assert!(next.avatar().is_none());
        assert!(
            !store
                .with_current_profile_handoff(&old, handoff.operation, bytes, |_| panic!(
                    "revoked enqueue"
                ))
                .unwrap()
        );
        assert!(
            !store
                .acknowledge_profile_handoff(
                    &old,
                    handoff.operation,
                    ProfilePublicationResult::DhtAcknowledged
                )
                .unwrap()
        );
        assert_eq!(store.profile_handoff().unwrap(), Some(handoff));
        store.finish_profile_handoff(handoff.operation).unwrap();
        assert_eq!(store.current_public_profile(agent).unwrap(), Some(next));
    }

    #[test]
    fn profile_avatar_withdrawal_preserves_a_pending_full_revocation() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = open_store(&directory.path().join("asl.sqlite3")).unwrap();
        let agent = AgentId([7; 32]);
        let reviewed = select_avatar(&mut store, agent);
        store.approve_avatar_reference(agent, &reviewed).unwrap();
        store.approve_profile_publication(agent, vec![101]).unwrap();
        let approval = store.current_public_profile(agent).unwrap().unwrap();
        let handoff = ProfileHandoff {
            operation: [3; 16],
            net_pid: std::process::id(),
        };
        assert!(store.reserve_profile_handoff(&approval, handoff).unwrap());
        store.revoke_profile_signing_approval().unwrap();
        store.withdraw_avatar_reference().unwrap();
        let status = store.profile_signing_status().unwrap();
        assert!(status.change_pending && status.approval.is_none());
        assert_eq!(store.profile_handoff().unwrap(), Some(handoff));
        store.finish_profile_handoff(handoff.operation).unwrap();
        assert!(store.current_public_profile(agent).unwrap().is_none());
    }

    #[test]
    fn profile_change_survives_reopen_and_only_finishes_the_matching_handoff() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("asl.sqlite3");
        let mut cli = open_store(&path).unwrap();
        let agent = AgentId([7; 32]);
        let handoff = ProfileHandoff {
            operation: [3; 16],
            net_pid: std::process::id(),
        };
        cli.approve_profile_publication(agent, vec![101]).unwrap();
        let old = cli.current_public_profile(agent).unwrap().unwrap();
        assert!(cli.reserve_profile_handoff(&old, handoff).unwrap());
        cli.revoke_profile_signing_approval().unwrap();
        cli.approve_profile_publication(agent, vec![104]).unwrap();
        drop(cli);
        let mut cli = open_store(&path).unwrap();
        assert_eq!(cli.profile_handoff().unwrap(), Some(handoff));
        assert!(cli.current_public_profile(agent).unwrap().is_none());
        assert!(
            !cli.with_current_public_profile(&old, || panic!("stale write"))
                .unwrap()
        );
        cli.finish_profile_handoff([1; 16]).unwrap();
        assert!(cli.profile_signing_status().unwrap().change_pending);
        cli.finish_profile_handoff(handoff.operation).unwrap();
        let new = cli.current_public_profile(agent).unwrap().unwrap();
        assert_eq!(new.topics, [104]);
        assert_ne!(old.revision, new.revision);
        assert!(!cli.profile_signing_status().unwrap().change_pending);
    }

    #[test]
    fn profile_publication_fences_reapproval_revocation_and_pause() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("asl.sqlite3");
        let mut store = open_store(&path).unwrap();
        let mut cli = open_store(&path).unwrap();
        let agent = AgentId([7; 32]);
        cli.set_profile_signing_approval(agent, vec![101]).unwrap();
        assert!(store.current_public_profile(agent).unwrap().is_none());
        cli.approve_profile_publication(agent, vec![101]).unwrap();
        let approval = store.current_public_profile(agent).unwrap().unwrap();
        assert!(
            store
                .with_current_public_profile(&approval, || Ok(true))
                .unwrap()
        );
        cli.set_network_pause_requested(true).unwrap();
        assert!(
            !store
                .with_current_public_profile(&approval, || panic!("paused enqueue"))
                .unwrap()
        );
        cli.set_network_pause_requested(false).unwrap();
        cli.revoke_profile_signing_approval().unwrap();
        cli.approve_profile_publication(agent, vec![101]).unwrap();
        assert!(
            !store
                .with_current_public_profile(&approval, || panic!("stale enqueue"))
                .unwrap()
        );
        store
            .observe_profile_publication(&approval, ProfilePublicationResult::DhtAcknowledged)
            .unwrap();
        assert!(
            store
                .profile_signing_status()
                .unwrap()
                .last_publication
                .is_none()
        );
    }

    #[test]
    fn profile_signing_settings_and_cursor_survive_reopen_without_inheriting_identity() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("asl.sqlite3");
        let owner = AgentId([1; 32]);
        let new_owner = AgentId([2; 32]);
        let mut store = open_store(&path).unwrap();
        assert!(store.profile_signing_status().unwrap().approval.is_none());
        for invalid in [vec![], vec![1], vec![101, 101], vec![999]] {
            assert!(store.set_profile_signing_approval(owner, invalid).is_err());
        }
        store
            .set_profile_signing_approval(owner, vec![109, 101])
            .unwrap();
        assert_eq!(store.reserve_profile_sequence(owner).unwrap(), 0);
        assert_eq!(
            store.reserve_device_directory_sequence(owner, 41).unwrap(),
            41
        );
        drop(store);

        let mut store = open_store(&path).unwrap();
        let status = Dashboard::load(&path).unwrap().profile_signing;
        let approval = status.approval.unwrap();
        assert_eq!(approval.agent_id, owner);
        assert_eq!(approval.topics, [101, 109]);
        assert!(store.profile_signing_due(new_owner, 42).unwrap().is_none());
        assert_eq!(store.reserve_profile_sequence(owner).unwrap(), 1);
        store.revoke_profile_signing_approval().unwrap();
        assert!(
            Dashboard::load(&path)
                .unwrap()
                .profile_signing
                .approval
                .is_none()
        );
        assert_eq!(store.reserve_profile_sequence(owner).unwrap(), 2);
    }
}
