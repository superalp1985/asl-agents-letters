use std::collections::{HashMap, HashSet};

use asl_policy::{
    AccessOperation, AccessRequest, Audience, AuthenticatedDevice, GrantPolicy, LeaseManager,
    MAX_ACTIVE_LEASES_PER_PEER, ModelPolicy, PolicyEngine, PolicyRevision, PolicyService,
    PolicySnapshot, Principal, ResourceOrigin, ResourcePolicy, issue_fetch_grant,
    validate_fetch_grant,
};
use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId},
    protocol::FetchRequest,
    task::{GrantId, ResourceKey},
};

const NOW: u64 = 1_000_000;

fn agent() -> AgentId {
    AgentId([1; 32])
}

fn peer() -> PeerId {
    let mut bytes = vec![0, 36, 8, 1, 18, 32];
    bytes.extend_from_slice(&[1; 32]);
    PeerId::from_bytes(bytes).unwrap()
}

fn grant() -> GrantId {
    GrantId(Id128([2; 16]))
}

fn resource() -> ResourceKey {
    ResourceKey(Id128([3; 16]))
}

fn snapshot() -> PolicySnapshot {
    PolicySnapshot {
        revision: PolicyRevision(1),
        grants: HashMap::from([(
            grant(),
            GrantPolicy {
                epoch: 1,
                active: true,
                audience: Audience::Contacts,
                model_policy: ModelPolicy::Never,
                extensions: HashSet::from([".md".into()]),
                max_snapshot_bytes: 1_048_576,
                allowed_operations: HashSet::from([AccessOperation::ReadChunk]),
                allow_derived_disclosure: false,
            },
        )]),
        resources: HashMap::from([(
            resource(),
            ResourcePolicy {
                content_id: Hash32([4; 32]),
                grant_id: grant(),
                grant_epoch: 1,
                active: true,
                snapshot_ready: true,
                file_size: 100,
                extension: ".md".into(),
                retention_until_ms: None,
                origin: ResourceOrigin::Local,
            },
        )]),
        devices: HashMap::from([(
            peer(),
            AuthenticatedDevice {
                agent_id: agent(),
                active: true,
                chain_valid_until_ms: NOW + 120_000,
                certificate_valid_until_ms: NOW + 120_000,
            },
        )]),
        contacts: HashSet::from([agent()]),
        ..PolicySnapshot::default()
    }
}

fn request() -> AccessRequest {
    AccessRequest {
        grant_id: grant(),
        resource_key: resource(),
        principal: Principal::Agent(agent()),
        operation: AccessOperation::ReadChunk,
    }
}

#[test]
fn lease_binds_peer_content_and_expires_in_memory() {
    let engine = PolicyEngine::new(snapshot(), 60_000).unwrap();
    let scope = engine.for_peer(peer());
    let permit = scope.authorize(&request(), NOW).unwrap();
    let leases = LeaseManager::new();
    let grant = leases.issue(&scope, &permit, 100, NOW).unwrap();

    assert_eq!(leases.active_count().unwrap(), 1);
    assert_eq!(
        leases
            .validate(&scope, grant.lease_id, &peer(), grant.content_id, NOW)
            .unwrap()
            .file_size,
        100
    );
    assert!(matches!(
        leases.validate(&scope, grant.lease_id, &other_peer(), grant.content_id, NOW),
        Err(AslError::NotFound)
    ));
    assert!(matches!(
        leases.validate(&scope, grant.lease_id, &peer(), Hash32([9; 32]), NOW),
        Err(AslError::NotFound)
    ));
    assert!(matches!(
        leases.validate(
            &scope,
            grant.lease_id,
            &peer(),
            grant.content_id,
            grant.expires_at_ms
        ),
        Err(AslError::NotFound)
    ));
    assert!(matches!(
        LeaseManager::new().validate(&scope, grant.lease_id, &peer(), grant.content_id, NOW),
        Err(AslError::NotFound)
    ));
}

#[test]
fn fetch_grant_is_bound_to_the_authenticated_peer_and_requested_content() {
    let engine = PolicyEngine::new(snapshot(), 60_000).unwrap();
    let scope = engine.for_peer(peer());
    let permit = scope.authorize(&request(), NOW).unwrap();
    let leases = LeaseManager::new();
    let request = FetchRequest {
        message_id: [5; 16].into(),
        root_task_id: [6; 16].into(),
        content_id: Hash32([4; 32]),
        logical_group_id: None,
        source_room_id: None,
    };
    let grant = issue_fetch_grant(&scope, &leases, &peer(), &request, &permit, 100, NOW).unwrap();
    assert_eq!(
        validate_fetch_grant(&scope, &leases, &peer(), &grant, NOW)
            .unwrap()
            .content_id,
        request.content_id
    );
    let wrong_content = FetchRequest {
        content_id: Hash32([8; 32]),
        ..request
    };
    assert!(matches!(
        issue_fetch_grant(&scope, &leases, &peer(), &wrong_content, &permit, 100, NOW),
        Err(AslError::NotFound)
    ));
}

#[test]
fn contact_revocation_revalidates_before_chunk_access() {
    let engine = PolicyEngine::new(snapshot(), 60_000).unwrap();
    let leases = LeaseManager::new();
    let grant = {
        let scope = engine.for_peer(peer());
        let permit = scope.authorize(&request(), NOW).unwrap();
        leases.issue(&scope, &permit, 100, NOW).unwrap()
    };

    let mut next = engine.snapshot().unwrap();
    next.revision = PolicyRevision(2);
    next.contacts.clear();
    engine.replace_snapshot(PolicyRevision(1), next).unwrap();

    let scope = engine.for_peer(peer());
    assert!(matches!(
        leases.validate(&scope, grant.lease_id, &peer(), grant.content_id, NOW + 1),
        Err(AslError::NotFound)
    ));
}

#[test]
fn unrelated_policy_revision_keeps_a_valid_lease_usable() {
    let mut state = snapshot();
    let unrelated_grant = GrantId(Id128([8; 16]));
    state.grants.insert(
        unrelated_grant.clone(),
        GrantPolicy {
            epoch: 1,
            active: true,
            audience: Audience::Public,
            model_policy: ModelPolicy::Never,
            extensions: HashSet::new(),
            max_snapshot_bytes: 1,
            allowed_operations: HashSet::from([AccessOperation::ReadChunk]),
            allow_derived_disclosure: false,
        },
    );
    let engine = PolicyEngine::new(state, 60_000).unwrap();
    let leases = LeaseManager::new();
    let grant = {
        let scope = engine.for_peer(peer());
        let permit = scope.authorize(&request(), NOW).unwrap();
        leases.issue(&scope, &permit, 100, NOW).unwrap()
    };

    let mut next = engine.snapshot().unwrap();
    next.revision = PolicyRevision(2);
    next.grants.get_mut(&unrelated_grant).unwrap().epoch = 2;
    engine.replace_snapshot(PolicyRevision(1), next).unwrap();

    let scope = engine.for_peer(peer());
    assert!(
        leases
            .validate(&scope, grant.lease_id, &peer(), grant.content_id, NOW + 1)
            .is_ok()
    );
}

#[test]
fn lease_capacity_is_fair_per_authenticated_peer_and_releasable() {
    let mut state = snapshot();
    let second_agent = AgentId([7; 32]);
    let second_peer = peer_with_byte(7);
    state.devices.insert(
        second_peer.clone(),
        AuthenticatedDevice {
            agent_id: second_agent,
            active: true,
            chain_valid_until_ms: NOW + 120_000,
            certificate_valid_until_ms: NOW + 120_000,
        },
    );
    state.contacts.insert(second_agent);
    let engine = PolicyEngine::new(state, 60_000).unwrap();
    let leases = LeaseManager::new();
    let first_scope = engine.for_peer(peer());
    let first_permit = first_scope.authorize(&request(), NOW).unwrap();

    let mut lease_ids = Vec::new();
    for _ in 0..MAX_ACTIVE_LEASES_PER_PEER {
        lease_ids.push(
            leases
                .issue(&first_scope, &first_permit, 100, NOW)
                .unwrap()
                .lease_id,
        );
    }
    assert!(matches!(
        leases.issue(&first_scope, &first_permit, 100, NOW),
        Err(AslError::QuotaExceeded)
    ));

    let second_scope = engine.for_peer(second_peer.clone());
    let second_request = AccessRequest {
        principal: Principal::Agent(second_agent),
        ..request()
    };
    let second_permit = second_scope.authorize(&second_request, NOW).unwrap();
    leases
        .issue(&second_scope, &second_permit, 100, NOW)
        .unwrap();

    leases.release(lease_ids[0], &peer()).unwrap();
    leases.issue(&first_scope, &first_permit, 100, NOW).unwrap();
    leases.release(lease_ids[1], &second_peer).unwrap();
    assert_eq!(
        leases.active_count().unwrap(),
        MAX_ACTIVE_LEASES_PER_PEER + 1
    );
}

fn other_peer() -> PeerId {
    let mut bytes = vec![0, 36, 8, 1, 18, 32];
    bytes.extend_from_slice(&[2; 32]);
    PeerId::from_bytes(bytes).unwrap()
}

fn peer_with_byte(byte: u8) -> PeerId {
    let mut bytes = vec![0, 36, 8, 1, 18, 32];
    bytes.extend_from_slice(&[byte; 32]);
    PeerId::from_bytes(bytes).unwrap()
}
