use std::collections::{HashMap, HashSet};

use asl_policy::{
    AccessOperation, AccessRequest, Audience, AuthenticatedDevice, GrantPolicy, GroupPolicy,
    ModelPolicy, PolicyEngine, PolicyRevision, PolicyService, PolicySnapshot, Principal,
    ProviderPolicy, ResourceOrigin, ResourcePolicy,
};
use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId},
    task::{GrantId, GroupId, ProviderId, ResourceKey, TaskId},
};

const NOW: u64 = 1_000_000;
const LIFETIME: u64 = 60_000;

fn grant(index: u8) -> GrantId {
    GrantId(Id128([index; 16]))
}

fn key(index: u8) -> ResourceKey {
    ResourceKey(Id128([index; 16]))
}

fn agent(index: u8) -> AgentId {
    AgentId([index; 32])
}

fn peer(index: u8) -> PeerId {
    let mut bytes = vec![0, 36, 8, 1, 18, 32];
    bytes.extend_from_slice(&[index; 32]);
    PeerId::from_bytes(bytes).unwrap()
}

fn group() -> GroupId {
    GroupId(Id128([5; 16]))
}

fn task() -> TaskId {
    TaskId(Id128([9; 16]))
}

fn provider(local: bool) -> ProviderId {
    ProviderId(if local { "local" } else { "cloud" }.into())
}

fn all_operations() -> HashSet<AccessOperation> {
    use AccessOperation::*;
    HashSet::from([
        Search,
        ReadMetadata,
        ReadChunk,
        PublishRecord,
        ModelInput,
        WriteDerived,
    ])
}

fn snapshot() -> PolicySnapshot {
    let mut state = PolicySnapshot::default();
    state.grants.insert(
        grant(1),
        GrantPolicy {
            epoch: 1,
            active: true,
            audience: Audience::Public,
            model_policy: ModelPolicy::Providers(HashSet::from([provider(false), provider(true)])),
            extensions: HashSet::from([".md".into()]),
            max_snapshot_bytes: 1_048_576,
            allowed_operations: all_operations(),
            allow_derived_disclosure: true,
        },
    );
    state.resources.insert(
        key(1),
        ResourcePolicy {
            content_id: Hash32([1; 32]),
            grant_id: grant(1),
            grant_epoch: 1,
            active: true,
            snapshot_ready: true,
            file_size: 100,
            extension: ".md".into(),
            retention_until_ms: Some(NOW + 120_000),
            origin: ResourceOrigin::Local,
        },
    );
    for index in 1..=2 {
        state.devices.insert(
            peer(index),
            AuthenticatedDevice {
                agent_id: agent(index),
                active: true,
                chain_valid_until_ms: NOW + 120_000,
                certificate_valid_until_ms: NOW + 120_000,
            },
        );
    }
    for local in [false, true] {
        state.providers.insert(
            provider(local),
            ProviderPolicy {
                authorized: true,
                local,
            },
        );
    }
    state.local_tasks.insert(task());
    state.groups.insert(
        group(),
        GroupPolicy {
            active: true,
            membership_epoch: 1,
            members: HashSet::from([peer(1)]),
        },
    );
    state
}

fn request(principal: Principal, operation: AccessOperation) -> AccessRequest {
    AccessRequest {
        grant_id: grant(1),
        resource_key: key(1),
        principal,
        operation,
    }
}

fn read() -> AccessRequest {
    request(Principal::Agent(agent(1)), AccessOperation::ReadChunk)
}

fn local(operation: AccessOperation) -> AccessRequest {
    request(Principal::LocalTask(task()), operation)
}

fn model(local: bool) -> AccessRequest {
    request(
        Principal::ModelProvider(provider(local)),
        AccessOperation::ModelInput,
    )
}

fn engine(state: PolicySnapshot) -> PolicyEngine {
    PolicyEngine::new(state, LIFETIME).unwrap()
}

fn denied<T>(result: Result<T, AslError>) {
    assert!(matches!(result, Err(AslError::NotFound)));
}

fn replace(engine: &PolicyEngine, edit: impl FnOnce(&mut PolicySnapshot)) {
    let mut next = engine.snapshot().unwrap();
    let previous = next.revision;
    next.revision = PolicyRevision(previous.0 + 1);
    edit(&mut next);
    engine.replace_snapshot(previous, next).unwrap();
}

fn add_resource(state: &mut PolicySnapshot, index: u8) {
    let mut source = state.resources[&key(1)].clone();
    source.grant_id = grant(index);
    source.content_id = Hash32([index; 32]);
    state
        .grants
        .insert(grant(index), state.grants[&grant(1)].clone());
    state.resources.insert(key(index), source);
}

fn derived() -> PolicySnapshot {
    let mut state = snapshot();
    add_resource(&mut state, 2);
    add_resource(&mut state, 3);
    state.resources.get_mut(&key(3)).unwrap().origin = ResourceOrigin::Derived {
        sources: vec![key(1), key(2)],
        disclosure_allowed: true,
    };
    state
}

fn derived_request(principal: Principal, operation: AccessOperation) -> AccessRequest {
    AccessRequest {
        grant_id: grant(3),
        resource_key: key(3),
        principal,
        operation,
    }
}

#[test]
fn public_permission_binds_the_authenticated_agent_device_content_and_time() {
    let engine = engine(snapshot());
    let scoped = engine.for_peer(peer(1));
    let permit = scoped.authorize(&read(), NOW).unwrap();
    assert_eq!(permit.grant_id(), &grant(1));
    assert_eq!(permit.grant_epoch(), 1);
    assert_eq!(permit.policy_revision(), PolicyRevision(1));
    assert_eq!(permit.requester_agent_id(), Some(agent(1)));
    assert_eq!(permit.authenticated_device_peer_id(), Some(&peer(1)));
    assert_eq!(permit.content_id(), Hash32([1; 32]));
    assert_eq!(permit.operation(), AccessOperation::ReadChunk);
    assert_eq!(permit.expires_at_ms(), NOW + LIFETIME);
    assert!(permit.group_binding().is_none());
    assert!(scoped.revalidate(&permit, NOW + 1).is_ok());
    denied(engine.authorize(&read(), NOW));
    denied(engine.for_peer(peer(2)).authorize(&read(), NOW));
}

#[test]
fn unknown_inactive_and_stale_identity_facts_never_authorize_public_data() {
    for variant in 0..4 {
        let mut state = snapshot();
        match variant {
            0 => {
                state.devices.remove(&peer(1));
            }
            1 => state.devices.get_mut(&peer(1)).unwrap().active = false,
            2 => {
                state
                    .devices
                    .get_mut(&peer(1))
                    .unwrap()
                    .chain_valid_until_ms = NOW
            }
            _ => {
                state
                    .devices
                    .get_mut(&peer(1))
                    .unwrap()
                    .certificate_valid_until_ms = NOW
            }
        }
        denied(engine(state).for_peer(peer(1)).authorize(&read(), NOW));
    }
}

#[test]
fn contacts_are_explicit_stable_agent_ids_and_apply_to_each_certified_device() {
    let mut state = snapshot();
    state.grants.get_mut(&grant(1)).unwrap().audience = Audience::Contacts;
    denied(
        engine(state.clone())
            .for_peer(peer(1))
            .authorize(&read(), NOW),
    );
    state.contacts.insert(agent(1));
    let device = state.devices[&peer(1)].clone();
    state.devices.insert(peer(3), device);
    let engine = engine(state);
    assert!(engine.for_peer(peer(1)).authorize(&read(), NOW).is_ok());
    assert!(engine.for_peer(peer(3)).authorize(&read(), NOW).is_ok());
    denied(engine.for_peer(peer(2)).authorize(
        &request(Principal::Agent(agent(2)), AccessOperation::ReadChunk),
        NOW,
    ));
}

#[test]
fn explicitly_named_peers_do_not_authorize_other_verified_agents() {
    let mut state = snapshot();
    state.grants.get_mut(&grant(1)).unwrap().audience = Audience::Peers(HashSet::from([agent(1)]));
    let engine = engine(state);
    assert!(engine.for_peer(peer(1)).authorize(&read(), NOW).is_ok());
    denied(engine.for_peer(peer(2)).authorize(
        &request(Principal::Agent(agent(2)), AccessOperation::ReadChunk),
        NOW,
    ));
}

#[test]
fn missing_denied_revoked_and_inactive_resources_have_one_external_error() {
    for variant in 0..10 {
        let mut state = snapshot();
        match variant {
            0 => {
                state.resources.remove(&key(1));
            }
            1 => {
                state.grants.remove(&grant(1));
            }
            2 => state.grants.get_mut(&grant(1)).unwrap().active = false,
            3 => state.resources.get_mut(&key(1)).unwrap().active = false,
            4 => state.resources.get_mut(&key(1)).unwrap().snapshot_ready = false,
            5 => state.resources.get_mut(&key(1)).unwrap().grant_epoch = 2,
            6 => state.resources.get_mut(&key(1)).unwrap().extension = ".exe".into(),
            7 => state.resources.get_mut(&key(1)).unwrap().file_size = 1_048_577,
            8 => state.resources.get_mut(&key(1)).unwrap().retention_until_ms = Some(NOW),
            _ => {
                state
                    .grants
                    .get_mut(&grant(1))
                    .unwrap()
                    .allowed_operations
                    .clear();
            }
        }
        denied(engine(state).for_peer(peer(1)).authorize(&read(), NOW));
    }
}

#[test]
fn identical_content_in_another_grant_is_not_a_permission_alias() {
    let mut state = snapshot();
    add_resource(&mut state, 2);
    state.resources.get_mut(&key(2)).unwrap().content_id = Hash32([1; 32]);
    state.grants.get_mut(&grant(2)).unwrap().audience = Audience::Contacts;
    let engine = engine(state);
    assert!(engine.for_peer(peer(1)).authorize(&read(), NOW).is_ok());
    let mut other = read();
    other.grant_id = grant(2);
    other.resource_key = key(2);
    denied(engine.for_peer(peer(1)).authorize(&other, NOW));
    other.grant_id = grant(1);
    denied(engine.for_peer(peer(1)).authorize(&other, NOW));
}

#[test]
fn group_permission_requires_current_device_membership_and_explicit_group_scope() {
    let mut state = snapshot();
    state.grants.get_mut(&grant(1)).unwrap().audience = Audience::Group(group());
    let engine = engine(state);
    let scoped = engine.for_group(peer(1), group());
    let permit = scoped.authorize(&read(), NOW).unwrap();
    assert_eq!(permit.group_binding(), Some((group(), 1)));
    denied(engine.for_peer(peer(1)).authorize(&read(), NOW));
    denied(engine.for_group(peer(2), group()).authorize(
        &request(Principal::Agent(agent(2)), AccessOperation::ReadChunk),
        NOW,
    ));
    replace(&engine, |next| {
        next.groups.get_mut(&group()).unwrap().membership_epoch += 1;
    });
    denied(scoped.revalidate(&permit, NOW + 1));
    assert!(scoped.authorize(&read(), NOW + 1).is_ok());
}

#[test]
fn removed_or_unsynchronized_groups_cannot_read_new_content() {
    for remove in [false, true] {
        let mut state = snapshot();
        state.grants.get_mut(&grant(1)).unwrap().audience = Audience::Group(group());
        if remove {
            state.groups.get_mut(&group()).unwrap().members.clear();
        } else {
            state.groups.get_mut(&group()).unwrap().active = false;
        }
        denied(
            engine(state)
                .for_group(peer(1), group())
                .authorize(&read(), NOW),
        );
    }
}

#[test]
fn group_membership_changes_require_a_new_epoch_and_epochs_cannot_move_backwards() {
    let engine = engine(snapshot());
    let before = engine.snapshot().unwrap();
    let mut unversioned = before.clone();
    unversioned.revision = PolicyRevision(2);
    unversioned
        .groups
        .get_mut(&group())
        .unwrap()
        .members
        .insert(peer(2));
    assert!(
        engine
            .replace_snapshot(PolicyRevision(1), unversioned)
            .is_err()
    );
    assert_eq!(engine.snapshot().unwrap(), before);
    replace(&engine, |next| {
        let policy = next.groups.get_mut(&group()).unwrap();
        policy.members.insert(peer(2));
        policy.membership_epoch += 1;
    });
    let mut rollback = engine.snapshot().unwrap();
    rollback.revision = PolicyRevision(3);
    rollback.groups.get_mut(&group()).unwrap().membership_epoch = 1;
    assert!(
        engine
            .replace_snapshot(PolicyRevision(2), rollback)
            .is_err()
    );
}

#[test]
fn local_tasks_need_an_existing_task_and_cannot_impersonate_remote_principals() {
    let mut state = snapshot();
    state.grants.get_mut(&grant(1)).unwrap().audience = Audience::Contacts;
    let engine = engine(state);
    assert!(
        engine
            .authorize(&local(AccessOperation::Search), NOW)
            .is_ok()
    );
    denied(
        engine
            .for_peer(peer(1))
            .authorize(&local(AccessOperation::Search), NOW),
    );
    replace(&engine, |next| next.local_tasks.clear());
    denied(engine.authorize(&local(AccessOperation::Search), NOW));
}

#[test]
fn model_never_and_unauthorized_providers_are_absolute() {
    for never in [false, true] {
        let mut state = snapshot();
        if never {
            state.grants.get_mut(&grant(1)).unwrap().model_policy = ModelPolicy::Never;
        } else {
            state
                .providers
                .get_mut(&provider(false))
                .unwrap()
                .authorized = false;
        }
        denied(engine(state).authorize(&model(false), NOW));
    }
}

#[test]
fn local_only_requires_both_an_explicit_provider_and_local_location() {
    let mut state = snapshot();
    state.grants.get_mut(&grant(1)).unwrap().model_policy =
        ModelPolicy::LocalOnly(HashSet::from([provider(false), provider(true)]));
    let engine = engine(state);
    assert!(engine.authorize(&model(true), NOW).is_ok());
    denied(engine.authorize(&model(false), NOW));
    replace(&engine, |next| {
        next.providers.get_mut(&provider(true)).unwrap().local = false;
    });
    denied(engine.authorize(&model(true), NOW));
}

#[test]
fn an_authorized_local_provider_still_needs_the_grants_explicit_allowlist() {
    let mut state = snapshot();
    state.grants.get_mut(&grant(1)).unwrap().model_policy = ModelPolicy::LocalOnly(HashSet::new());
    denied(engine(state).authorize(&model(true), NOW));
}

#[test]
fn provider_ids_and_operations_are_not_interchangeable_with_agents() {
    let engine = engine(snapshot());
    denied(engine.authorize(
        &request(
            Principal::ModelProvider(provider(true)),
            AccessOperation::ReadChunk,
        ),
        NOW,
    ));
    denied(engine.for_peer(peer(1)).authorize(
        &request(Principal::Agent(agent(1)), AccessOperation::ModelInput),
        NOW,
    ));
    denied(engine.authorize(
        &request(Principal::LocalTask(task()), AccessOperation::ModelInput),
        NOW,
    ));
}

#[test]
fn recipient_scoped_model_input_requires_the_recipient_to_have_source_permission() {
    let mut state = snapshot();
    state.grants.get_mut(&grant(1)).unwrap().audience = Audience::Contacts;
    let engine = engine(state);
    assert!(engine.authorize(&model(false), NOW).is_ok());
    denied(engine.for_peer(peer(1)).authorize(&model(false), NOW));
    replace(&engine, |next| {
        next.contacts.insert(agent(1));
    });
    assert!(
        engine
            .for_peer(peer(1))
            .authorize(&model(false), NOW)
            .is_ok()
    );
}

#[test]
fn model_permits_cannot_cross_scope_and_stop_when_the_provider_is_revoked() {
    let engine = engine(snapshot());
    let scoped = engine.for_peer(peer(1));
    let local = engine.authorize(&model(false), NOW).unwrap();
    let remote = scoped.authorize(&model(false), NOW).unwrap();
    denied(scoped.revalidate(&local, NOW + 1));
    denied(engine.revalidate(&remote, NOW + 1));
    replace(&engine, |next| {
        next.providers.get_mut(&provider(false)).unwrap().authorized = false;
    });
    denied(engine.revalidate(&local, NOW + 1));
    denied(scoped.revalidate(&remote, NOW + 1));
}

#[test]
fn contact_removal_invalidates_reply_model_permits_but_preserves_local_model_permission() {
    let mut state = snapshot();
    state.grants.get_mut(&grant(1)).unwrap().audience = Audience::Contacts;
    state.contacts.insert(agent(1));
    let engine = engine(state);
    let scoped = engine.for_peer(peer(1));
    let local = engine.authorize(&model(false), NOW).unwrap();
    let reply = scoped.authorize(&model(false), NOW).unwrap();
    replace(&engine, |next| next.contacts.clear());
    denied(scoped.revalidate(&reply, NOW + 1));
    assert!(engine.revalidate(&local, NOW + 1).is_ok());
}

#[test]
fn derived_disclosure_is_the_intersection_of_all_source_audiences() {
    let mut state = derived();
    state.grants.get_mut(&grant(1)).unwrap().audience = Audience::Contacts;
    state.grants.get_mut(&grant(2)).unwrap().audience =
        Audience::Peers(HashSet::from([agent(1), agent(2)]));
    state.contacts.insert(agent(1));
    let engine = engine(state);
    let request = derived_request(Principal::Agent(agent(1)), AccessOperation::ReadChunk);
    assert!(engine.for_peer(peer(1)).authorize(&request, NOW).is_ok());
    denied(engine.for_peer(peer(2)).authorize(
        &derived_request(Principal::Agent(agent(2)), AccessOperation::ReadChunk),
        NOW,
    ));
    replace(&engine, |next| next.contacts.clear());
    denied(engine.for_peer(peer(1)).authorize(&request, NOW));
}

#[test]
fn model_intersection_requires_the_same_provider_for_every_source() {
    let mut state = derived();
    state.grants.get_mut(&grant(1)).unwrap().model_policy =
        ModelPolicy::Providers(HashSet::from([provider(false)]));
    state.grants.get_mut(&grant(2)).unwrap().model_policy =
        ModelPolicy::Providers(HashSet::from([provider(true)]));
    let engine = engine(state);
    for local in [false, true] {
        denied(engine.authorize(
            &derived_request(
                Principal::ModelProvider(provider(local)),
                AccessOperation::ModelInput,
            ),
            NOW,
        ));
    }
}

#[test]
fn private_derived_material_can_be_browsed_locally_without_becoming_shareable() {
    let mut state = derived();
    let ResourceOrigin::Derived {
        disclosure_allowed, ..
    } = &mut state.resources.get_mut(&key(3)).unwrap().origin
    else {
        unreachable!();
    };
    *disclosure_allowed = false;
    let engine = engine(state);
    assert!(
        engine
            .authorize(
                &derived_request(Principal::LocalTask(task()), AccessOperation::Search),
                NOW,
            )
            .is_ok()
    );
    denied(engine.for_peer(peer(1)).authorize(
        &derived_request(Principal::Agent(agent(1)), AccessOperation::ReadChunk),
        NOW,
    ));
}

#[test]
fn remote_source_reuse_and_source_derived_disclosure_need_explicit_permission() {
    for remote in [false, true] {
        let mut state = derived();
        if remote {
            state.resources.get_mut(&key(1)).unwrap().origin = ResourceOrigin::Remote {
                reuse_allowed: false,
            };
        } else {
            state
                .grants
                .get_mut(&grant(1))
                .unwrap()
                .allow_derived_disclosure = false;
        }
        denied(engine(state).for_peer(peer(1)).authorize(
            &derived_request(Principal::Agent(agent(1)), AccessOperation::ReadChunk),
            NOW,
        ));
    }
}

#[test]
fn source_derivation_rules_do_not_disable_authorized_original_file_browsing() {
    let mut state = snapshot();
    state
        .grants
        .get_mut(&grant(1))
        .unwrap()
        .allow_derived_disclosure = false;
    assert!(
        engine(state.clone())
            .for_peer(peer(1))
            .authorize(&read(), NOW)
            .is_ok()
    );
    state.resources.get_mut(&key(1)).unwrap().origin = ResourceOrigin::Remote {
        reuse_allowed: false,
    };
    let engine = engine(state);
    assert!(
        engine
            .authorize(&local(AccessOperation::ReadChunk), NOW)
            .is_ok()
    );
    denied(engine.authorize(&local(AccessOperation::WriteDerived), NOW));
}

#[test]
fn publication_requires_public_sources_and_a_local_task() {
    let state = derived();
    let request = derived_request(Principal::LocalTask(task()), AccessOperation::PublishRecord);
    let engine = engine(state);
    assert!(engine.authorize(&request, NOW).is_ok());
    denied(engine.for_peer(peer(1)).authorize(
        &derived_request(Principal::Agent(agent(1)), AccessOperation::PublishRecord),
        NOW,
    ));
    replace(&engine, |next| {
        let source = next.grants.get_mut(&grant(2)).unwrap();
        source.audience = Audience::Contacts;
        source.epoch += 1;
        next.resources.get_mut(&key(2)).unwrap().grant_epoch += 1;
        next.contacts.insert(agent(1));
    });
    denied(engine.authorize(&request, NOW));
}

#[test]
fn a_denied_or_replaced_source_invalidates_an_existing_derived_permit() {
    for content_change in [false, true] {
        let engine = engine(derived());
        let scoped = engine.for_peer(peer(1));
        let request = derived_request(Principal::Agent(agent(1)), AccessOperation::ReadChunk);
        let permit = scoped.authorize(&request, NOW).unwrap();
        replace(&engine, |next| {
            let source = next.resources.get_mut(&key(1)).unwrap();
            if content_change {
                source.content_id = Hash32([99; 32]);
            } else {
                source.active = false;
            }
        });
        denied(scoped.revalidate(&permit, NOW + 1));
    }
}

#[test]
fn epoch_changes_in_any_source_invalidate_old_permits_without_blocking_new_ones() {
    let engine = engine(derived());
    let scoped = engine.for_peer(peer(1));
    let request = derived_request(Principal::Agent(agent(1)), AccessOperation::ReadChunk);
    let permit = scoped.authorize(&request, NOW).unwrap();
    replace(&engine, |next| {
        next.grants.get_mut(&grant(1)).unwrap().epoch += 1;
        next.resources.get_mut(&key(1)).unwrap().grant_epoch += 1;
    });
    denied(scoped.revalidate(&permit, NOW + 1));
    assert!(scoped.authorize(&request, NOW + 1).is_ok());
}

#[test]
fn unrelated_revisions_do_not_cancel_a_valid_permit() {
    let engine = engine(snapshot());
    let scoped = engine.for_peer(peer(1));
    let permit = scoped.authorize(&read(), NOW).unwrap();
    replace(&engine, |next| {
        next.contacts.insert(agent(2));
    });
    assert!(scoped.revalidate(&permit, NOW + 1).is_ok());
    assert_eq!(permit.policy_revision(), PolicyRevision(1));
}

#[test]
fn contact_or_device_revocation_stops_existing_permits() {
    for contact in [false, true] {
        let mut state = snapshot();
        state.grants.get_mut(&grant(1)).unwrap().audience = Audience::Contacts;
        state.contacts.insert(agent(1));
        let engine = engine(state);
        let scoped = engine.for_peer(peer(1));
        let permit = scoped.authorize(&read(), NOW).unwrap();
        replace(&engine, |next| {
            if contact {
                next.contacts.clear();
            } else {
                next.devices.get_mut(&peer(1)).unwrap().active = false;
            }
        });
        denied(scoped.revalidate(&permit, NOW + 1));
    }
}

#[test]
fn permits_expire_without_renewal_and_cannot_cross_instances_or_scopes() {
    let state = snapshot();
    let first = engine(state.clone());
    let scoped = first.for_peer(peer(1));
    let permit = scoped.authorize(&read(), NOW).unwrap();
    denied(scoped.revalidate(&permit, NOW - 1));
    denied(scoped.revalidate(&permit, NOW + LIFETIME));
    denied(first.for_peer(peer(2)).revalidate(&permit, NOW + 1));
    denied(first.revalidate(&permit, NOW + 1));
    denied(engine(state).for_peer(peer(1)).revalidate(&permit, NOW + 1));
}

#[test]
fn permit_lifetime_cannot_outlive_its_shortest_source_or_identity_deadline() {
    for certificate in [false, true] {
        let mut state = snapshot();
        if certificate {
            state
                .devices
                .get_mut(&peer(1))
                .unwrap()
                .certificate_valid_until_ms = NOW + 50;
        } else {
            state.resources.get_mut(&key(1)).unwrap().retention_until_ms = Some(NOW + 50);
        }
        let engine = engine(state);
        let scoped = engine.for_peer(peer(1));
        let permit = scoped.authorize(&read(), NOW).unwrap();
        assert_eq!(permit.expires_at_ms(), NOW + 50);
        denied(scoped.revalidate(&permit, NOW + 50));
    }
}

#[test]
fn revoke_is_versioned_and_cannot_reactivate_an_existing_grant_id() {
    let engine = engine(snapshot());
    let scoped = engine.for_peer(peer(1));
    let permit = scoped.authorize(&read(), NOW).unwrap();
    assert!(engine.revoke(grant(1), 2).is_err());
    assert_eq!(engine.revoke(grant(1), 1).unwrap(), PolicyRevision(2));
    denied(scoped.revalidate(&permit, NOW + 1));
    denied(scoped.authorize(&read(), NOW + 1));
    let mut next = engine.snapshot().unwrap();
    next.revision = PolicyRevision(3);
    let revoked = next.grants.get_mut(&grant(1)).unwrap();
    revoked.active = true;
    revoked.epoch += 1;
    assert!(engine.replace_snapshot(PolicyRevision(2), next).is_err());
    assert_eq!(engine.snapshot().unwrap().revision, PolicyRevision(2));
}

#[test]
fn stale_snapshot_or_unversioned_grant_changes_are_rejected_atomically() {
    let engine = engine(snapshot());
    let before = engine.snapshot().unwrap();
    let mut changed = before.clone();
    changed.revision = PolicyRevision(2);
    changed.grants.get_mut(&grant(1)).unwrap().audience = Audience::Contacts;
    assert!(engine.replace_snapshot(PolicyRevision(1), changed).is_err());
    assert_eq!(engine.snapshot().unwrap(), before);
    replace(&engine, |_| {});
    let mut stale = before;
    stale.revision = PolicyRevision(2);
    assert!(engine.replace_snapshot(PolicyRevision(1), stale).is_err());
}

#[test]
fn protocol_file_limit_cannot_be_raised_by_an_overly_broad_local_grant() {
    let mut state = snapshot();
    state.grants.get_mut(&grant(1)).unwrap().max_snapshot_bytes = 68_719_476_737;
    state.resources.get_mut(&key(1)).unwrap().file_size = 68_719_476_736;
    assert!(
        engine(state.clone())
            .for_peer(peer(1))
            .authorize(&read(), NOW)
            .is_ok()
    );
    state.resources.get_mut(&key(1)).unwrap().file_size += 1;
    denied(engine(state).for_peer(peer(1)).authorize(&read(), NOW));
}

fn derivation_chain(depth: u8) -> (PolicySnapshot, AccessRequest) {
    let mut state = snapshot();
    let mut previous = key(1);
    for level in 1..=depth {
        let index = 100 + level;
        add_resource(&mut state, index);
        state.resources.get_mut(&key(index)).unwrap().origin = ResourceOrigin::Derived {
            sources: vec![previous],
            disclosure_allowed: true,
        };
        previous = key(index);
    }
    let request = AccessRequest {
        grant_id: grant(100 + depth),
        resource_key: previous,
        principal: Principal::Agent(agent(1)),
        operation: AccessOperation::ReadChunk,
    };
    (state, request)
}

#[test]
fn provenance_depth_four_is_valid_and_depth_five_is_private() {
    let (state, request) = derivation_chain(4);
    assert!(
        engine(state)
            .for_peer(peer(1))
            .authorize(&request, NOW)
            .is_ok()
    );
    let (state, request) = derivation_chain(5);
    denied(engine(state).for_peer(peer(1)).authorize(&request, NOW));
}

#[test]
fn provenance_cycles_missing_sources_and_too_many_direct_sources_are_private() {
    for variant in 0..4 {
        let mut state = derived();
        let sources = match variant {
            0 => vec![key(3)],
            1 => vec![key(77)],
            2 => vec![],
            _ => (10..19)
                .map(|index| {
                    add_resource(&mut state, index);
                    key(index)
                })
                .collect(),
        };
        state.resources.get_mut(&key(3)).unwrap().origin = ResourceOrigin::Derived {
            sources,
            disclosure_allowed: true,
        };
        denied(engine(state).for_peer(peer(1)).authorize(
            &derived_request(Principal::Agent(agent(1)), AccessOperation::ReadChunk),
            NOW,
        ));
    }
}

fn expanded_sources(count: u8) -> (PolicySnapshot, AccessRequest) {
    let mut state = snapshot();
    let mut branches: HashMap<u8, Vec<ResourceKey>> = HashMap::new();
    for index in 0..count {
        let leaf = index + 10;
        add_resource(&mut state, leaf);
        branches.entry(index / 8).or_default().push(key(leaf));
    }
    let mut roots = Vec::new();
    for (branch, sources) in branches {
        let index = 100 + branch;
        add_resource(&mut state, index);
        state.resources.get_mut(&key(index)).unwrap().origin = ResourceOrigin::Derived {
            sources,
            disclosure_allowed: true,
        };
        roots.push(key(index));
    }
    add_resource(&mut state, 200);
    state.resources.get_mut(&key(200)).unwrap().origin = ResourceOrigin::Derived {
        sources: roots,
        disclosure_allowed: true,
    };
    (
        state,
        AccessRequest {
            grant_id: grant(200),
            resource_key: key(200),
            principal: Principal::Agent(agent(1)),
            operation: AccessOperation::ReadChunk,
        },
    )
}

#[test]
fn thirty_two_expanded_sources_are_valid_but_thirty_three_are_private() {
    let (state, request) = expanded_sources(32);
    assert!(
        engine(state)
            .for_peer(peer(1))
            .authorize(&request, NOW)
            .is_ok()
    );
    let (state, request) = expanded_sources(33);
    denied(engine(state).for_peer(peer(1)).authorize(&request, NOW));
}

#[test]
fn repeated_sources_still_consume_the_expanded_reference_budget() {
    for count in [32, 33] {
        let (mut state, request) = expanded_sources(count);
        for index in 100..105 {
            if let Some(ResourcePolicy {
                origin: ResourceOrigin::Derived { sources, .. },
                ..
            }) = state.resources.get_mut(&key(index))
            {
                *sources = (0..sources.len())
                    .map(|index| key(10 + index as u8))
                    .collect();
            }
        }
        let engine = engine(state);
        let result = engine.for_peer(peer(1)).authorize(&request, NOW);
        if count == 32 {
            assert!(result.is_ok());
        } else {
            denied(result);
        }
    }
}
