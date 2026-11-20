use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128},
    task::GroupId,
};

use super::{
    MlsIncomingInvite, MlsJoinKey, MlsJoinedRoom, MlsMemberEvidence, PendingMlsRoom,
    recovery_tests::register_evidence, tests,
};

#[test]
fn inbound_join_requires_local_approval_and_consumes_only_with_the_room_transaction() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("invite.sqlite3");
    let mut store = crate::open_store(&path).unwrap();
    let inviter = tests::test_peer(1);
    let recipient = tests::test_peer(2);
    let unknown = tests::test_peer(3);
    let other_inviter = tests::test_peer(4);
    let recipient_agent = AgentId([2; 32]);
    let inviter_evidence = register_evidence(&store, AgentId([1; 32]), &inviter, 105_000);
    let recipient_evidence = register_evidence(&store, recipient_agent, &recipient, 105_000);
    tests::register_agent_peer(&store, AgentId([4; 32]), &other_inviter, 1);
    let invite = MlsIncomingInvite {
        id: Id128([7; 16]),
        wire_id: Hash32([8; 32]),
        base_epoch: 9,
        inviter: AgentId([1; 32]),
        inviter_device: inviter.clone(),
        recipient: recipient_agent,
        recipient_device: recipient.clone(),
        expires_at_ms: 105_000,
    };
    let key = MlsJoinKey {
        request_id: Id128([11; 16]),
        package_ref: Hash32([12; 32]),
    };
    let local_id = GroupId(Id128([13; 16]));
    let join = |members, key, revision| MlsJoinedRoom {
        invite: &invite,
        key,
        room: PendingMlsRoom {
            local_id: &local_id,
            wire_id: invite.wire_id,
            creator: &inviter,
            local_name: "Group",
            mls_epoch: 10,
            sealed_snapshot: b"opaque room state",
        },
        members,
        chain_id: 1,
        expected_policy_revision: revision,
    };
    let mut obsolete = register_evidence(&store, AgentId([3; 32]), &unknown, 105_000);
    obsolete.registry_sequence += 1;
    let bad_roster = [
        MlsMemberEvidence {
            certificate: inviter_evidence.certificate.clone(),
            ..inviter_evidence
        },
        MlsMemberEvidence {
            certificate: recipient_evidence.certificate.clone(),
            ..recipient_evidence
        },
        obsolete,
    ];
    let members = [inviter_evidence, recipient_evidence];

    assert!(store.receive_mls_invite(&invite, 100_000).unwrap());
    assert!(!store.receive_mls_invite(&invite, 100_000).unwrap());
    let competing = MlsIncomingInvite {
        id: Id128([10; 16]),
        inviter: AgentId([4; 32]),
        inviter_device: other_inviter,
        ..invite.clone()
    };
    let competing_key = MlsJoinKey {
        request_id: Id128([14; 16]),
        package_ref: Hash32([15; 32]),
    };
    assert!(store.receive_mls_invite(&competing, 100_000).unwrap());
    assert!(
        store
            .pending_mls_join_package(&invite, 100_001)
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .finish_mls_join(join(&members, key, 1), 100_001)
            .is_err()
    );
    let other_device = MlsIncomingInvite {
        recipient_device: unknown.clone(),
        ..invite.clone()
    };
    assert!(
        !store
            .save_mls_join_package(&other_device, key, b"pending", 100_001)
            .unwrap()
    );
    assert!(
        store
            .save_mls_join_package(&invite, key, b"pending", 100_001)
            .unwrap()
    );
    assert!(
        !store
            .save_mls_join_package(&invite, key, b"replacement", 100_002)
            .unwrap()
    );
    assert!(
        !store
            .save_mls_join_package(&competing, competing_key, b"alternate join", 100_002)
            .unwrap()
    );
    drop(store);

    let mut store = crate::open_store(&path).unwrap();
    let recovered = store
        .recover_mls_joins(recipient_agent, &recipient, 100_002)
        .unwrap();
    assert_eq!(recovered.as_slice(), std::slice::from_ref(&invite));
    assert!(
        store
            .recover_mls_joins(AgentId([1; 32]), &recipient, 100_002)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store
            .pending_mls_join_package(&recovered[0], 100_002)
            .unwrap(),
        Some((key, b"pending".to_vec())),
    );
    assert!(
        store
            .pending_mls_join_package(&other_device, 100_002)
            .unwrap()
            .is_none()
    );
    let wrong_key = MlsJoinKey {
        package_ref: Hash32([3; 32]),
        ..key
    };
    assert!(
        store
            .finish_mls_join(join(&members, wrong_key, 1), 100_003)
            .is_err()
    );
    assert!(matches!(
        store.finish_mls_join(join(&members, key, 2), 100_003),
        Err(AslError::PolicyVersionConflict)
    ));
    assert!(matches!(
        store.finish_mls_join(join(&bad_roster, key, 1), 100_004),
        Err(AslError::InvalidDeviceCertificate)
    ));
    assert!(store.mls_room_snapshot(invite.wire_id).unwrap().is_none());
    assert!(
        store
            .pending_mls_join_package(&invite, 100_004)
            .unwrap()
            .is_some()
    );

    let version = store
        .finish_mls_join(join(&members, key, 1), 100_005)
        .unwrap();
    assert!(
        store
            .finish_mls_join(join(&members, key, 1), 100_006)
            .is_err()
    );
    assert!(
        store
            .pending_mls_join_package(&invite, 100_006)
            .unwrap()
            .is_none()
    );
    let room = store.mls_room_snapshot(invite.wire_id).unwrap().unwrap();
    assert_eq!(room.version, version);
    assert_eq!(room.version.policy_revision, 1);
    assert_eq!(room.version.mls_epoch, 10);
    let (state, roster): (String, i64) = store.connection.query_row(
        "SELECT state,(SELECT count(*) FROM group_members WHERE state='active') FROM asl_groups",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    ).unwrap();
    assert_eq!((state.as_str(), roster), ("needs_sync", 2));
    let open: i64 = store
        .connection
        .query_row(
            "SELECT count(*) FROM mls_incoming_invites WHERE state<>'closed'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(open, 0);
}

#[test]
fn inbound_invites_bound_prompts_across_devices_and_restarts() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("budget.sqlite3");
    let mut store = crate::open_store(&path).unwrap();
    let recipient = tests::test_peer(100);
    let inviter = tests::test_peer(101);
    let other_device = tests::test_peer(102);
    let recipient_agent = AgentId([100; 32]);
    tests::register_peer(&store, &inviter, 1);
    tests::register_peer(&store, &other_device, 2);
    tests::register_agent_peer(&store, recipient_agent, &recipient, 1);
    let invite = MlsIncomingInvite {
        id: Id128([1; 16]),
        wire_id: Hash32([2; 32]),
        base_epoch: 0,
        inviter: AgentId([1; 32]),
        inviter_device: inviter,
        recipient: recipient_agent,
        recipient_device: recipient,
        expires_at_ms: 100_010,
    };
    assert!(store.receive_mls_invite(&invite, 100_000).unwrap());
    assert!(store.reject_mls_invite(&invite, 100_001).unwrap());
    assert!(!store.reject_mls_invite(&invite, 100_001).unwrap());
    drop(store);
    let mut store = crate::open_store(&path).unwrap();
    let changed = MlsIncomingInvite {
        inviter_device: other_device,
        id: Id128([4; 16]),
        ..invite.clone()
    };
    assert!(!store.receive_mls_invite(&changed, 100_002).unwrap());
    assert!(
        !store
            .save_mls_join_package(
                &invite,
                MlsJoinKey {
                    request_id: Id128([5; 16]),
                    package_ref: Hash32([6; 32])
                },
                b"opaque",
                100_002
            )
            .unwrap()
    );
}

#[test]
fn invite_prompt_slots_expire_without_releasing_the_hourly_budget() {
    let root = tempfile::tempdir().unwrap();
    let mut store = crate::open_store(&root.path().join("slots.sqlite3")).unwrap();
    let recipient = tests::test_peer(100);
    let recipient_agent = AgentId([100; 32]);
    tests::register_agent_peer(&store, recipient_agent, &recipient, 1);
    let devices: Vec<_> = (1..=21).map(tests::test_peer).collect();
    for (index, device) in devices.iter().enumerate() {
        tests::register_agent_peer(&store, AgentId([index as u8 + 1; 32]), device, 1);
    }
    let invite = |index: usize, now: u64| MlsIncomingInvite {
        id: Id128([index as u8 + 1; 16]),
        wire_id: Hash32([2; 32]),
        base_epoch: 0,
        inviter: AgentId([index as u8 + 1; 32]),
        inviter_device: devices[index].clone(),
        recipient: recipient_agent,
        recipient_device: recipient.clone(),
        expires_at_ms: now + 1000,
    };
    let start = 100_000;
    for index in 0..5 {
        assert!(
            store
                .receive_mls_invite(&invite(index, start), start)
                .unwrap()
        );
    }
    let key = MlsJoinKey {
        request_id: Id128([99; 16]),
        package_ref: Hash32([99; 32]),
    };
    assert!(
        store
            .save_mls_join_package(&invite(0, start), key, b"sealed", start)
            .unwrap()
    );
    assert!(!store.receive_mls_invite(&invite(5, start), start).unwrap());
    for index in 5..20 {
        let now = start + 1000 * ((index / 5) as u64);
        assert!(store.receive_mls_invite(&invite(index, now), now).unwrap());
    }
    let expired: (String, Option<Vec<u8>>) = store
        .connection
        .query_row(
            "SELECT state,sealed_package FROM mls_incoming_invites WHERE invite_id=?1",
            [invite(0, start).id.as_bytes()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(expired, ("closed".to_owned(), None));
    assert!(
        store
            .pending_mls_join_package(&invite(0, start), start)
            .unwrap()
            .is_none()
    );
    let now = start + 4_000;
    assert!(!store.receive_mls_invite(&invite(20, now), now).unwrap());
    let later = start + 3_600_000;
    assert!(store.receive_mls_invite(&invite(20, later), later).unwrap());
}
