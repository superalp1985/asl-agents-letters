use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128},
    task::GroupId,
};
use rusqlite::params;

use super::{
    MlsEpochBindings, MlsIncomingInvite, MlsInviteEndpoints, MlsJoinKey, MlsJoinedRoom,
    MlsJournalEntry, MlsJournalKind, MlsMemberEvidence, MlsRoomUpdate, PendingMlsRoom, RoomVersion,
    recovery_tests::register_evidence, tests, transition::peer_text,
};
use crate::Store;

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
            .finish_mls_join(join(&members, key, 1), || Ok(100_001))
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
    assert!(!store.reject_mls_invite(&invite, 100_002).unwrap());
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
            .finish_mls_join(join(&members, wrong_key, 1), || Ok(100_003))
            .is_err()
    );
    assert!(matches!(
        store.finish_mls_join(join(&members, key, 2), || Ok(100_003)),
        Err(AslError::PolicyVersionConflict)
    ));
    assert!(matches!(
        store.finish_mls_join(join(&bad_roster, key, 1), || Ok(100_004)),
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
        .finish_mls_join(join(&members, key, 1), || Ok(100_005))
        .unwrap();
    assert!(
        store
            .finish_mls_join(join(&members, key, 1), || Ok(100_006))
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
fn pending_invites_list_only_live_prompts_for_the_exact_local_device() {
    let root = tempfile::tempdir().unwrap();
    let mut store = crate::open_store(&root.path().join("pending.sqlite3")).unwrap();
    let recipient = tests::test_peer(100);
    let recipient_agent = AgentId([100; 32]);
    tests::register_agent_peer(&store, recipient_agent, &recipient, 1);
    let start = 100_000;
    let end = start + 1_000;
    let invites: [_; 5] = std::array::from_fn(|index| {
        let seed = index as u8 + 1;
        let inviter = AgentId([seed; 32]);
        let inviter_device = tests::test_peer(seed);
        tests::register_agent_peer(&store, inviter, &inviter_device, 1);
        let invite = MlsIncomingInvite {
            id: Id128([seed; 16]),
            wire_id: Hash32([seed; 32]),
            base_epoch: 0,
            inviter,
            inviter_device,
            recipient: recipient_agent,
            recipient_device: recipient.clone(),
            expires_at_ms: if index == 2 { end } else { end + 1 },
        };
        assert!(store.receive_mls_invite(&invite, start).unwrap());
        invite
    });
    let [pending, approved, _, closed, joined] = &invites;
    assert!(
        store
            .save_mls_join_package(
                approved,
                MlsJoinKey {
                    request_id: Id128([11; 16]),
                    package_ref: Hash32([12; 32]),
                },
                b"sealed",
                start,
            )
            .unwrap()
    );
    assert!(store.reject_mls_invite(closed, start).unwrap());
    store
        .stage_mls_room(PendingMlsRoom {
            local_id: &GroupId(Id128([13; 16])),
            wire_id: joined.wire_id,
            creator: &joined.inviter_device,
            local_name: "Existing room",
            mls_epoch: 0,
            sealed_snapshot: b"sealed",
        })
        .unwrap();

    assert_eq!(
        store
            .list_pending_mls_invites(recipient_agent, &recipient, end)
            .unwrap(),
        std::slice::from_ref(pending),
    );
    assert!(
        store
            .list_pending_mls_invites(approved.inviter, &recipient, end)
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .list_pending_mls_invites(recipient_agent, &approved.inviter_device, end)
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .list_pending_mls_invites(recipient_agent, &recipient, start - 1)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store
            .recover_mls_joins(recipient_agent, &recipient, end)
            .unwrap(),
        std::slice::from_ref(approved),
    );
    use super::invite_review::{Choice, Outcome};
    let review = store
        .local_group_invitations(recipient_agent, &recipient, start)
        .unwrap();
    let tag = &review.iter().find(|r| r.id == approved.id).unwrap().tag;
    assert!(
        store
            .queue_group_decision(recipient_agent, &recipient, tag, Choice::Approve, start)
            .is_err()
    );
    store
        .queue_group_decision(recipient_agent, &recipient, tag, Choice::Retry, start)
        .unwrap();
    let request = store
        .claim_group_decision(recipient_agent, &recipient, start)
        .unwrap()
        .unwrap();
    assert!(
        store
            .claim_group_decision(recipient_agent, &recipient, start)
            .unwrap()
            .is_none()
    );
    store
        .finish_group_decision(&request, Outcome::JoinQueued, start)
        .unwrap();
    let tag = &review.iter().find(|r| r.id == pending.id).unwrap().tag;
    store
        .queue_group_decision(recipient_agent, &recipient, tag, Choice::Reject, start)
        .unwrap();
    assert!(
        store
            .claim_group_decision(recipient_agent, &approved.inviter_device, start)
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .claim_group_decision(recipient_agent, &recipient, start)
            .unwrap()
            .is_none()
    );
}

#[test]
fn inbound_invites_bound_prompts_across_devices_and_restarts_without_registering_limited_devices() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("budget.sqlite3");
    let mut store = crate::open_store(&path).unwrap();
    let recipient = tests::test_peer(100);
    let inviter = tests::test_peer(101);
    let other_device = tests::test_peer(102);
    let recipient_agent = AgentId([100; 32]);
    let inviter_agent = AgentId([1; 32]);
    let inviter_evidence = register_evidence(&store, inviter_agent, &inviter, 105_000);
    let recipient_evidence = register_evidence(&store, recipient_agent, &recipient, 105_000);
    let invite = MlsIncomingInvite {
        id: Id128([1; 16]),
        wire_id: Hash32([2; 32]),
        base_epoch: 0,
        inviter: inviter_agent,
        inviter_device: inviter,
        recipient: recipient_agent,
        recipient_device: recipient,
        expires_at_ms: 100_010,
    };
    assert!(
        store
            .receive_verified_mls_invite(
                &invite,
                MlsInviteEndpoints {
                    inviter: &inviter_evidence,
                    recipient: &recipient_evidence,
                    chain_id: 1,
                },
                100_000,
            )
            .unwrap()
    );
    assert!(store.reject_mls_invite(&invite, 100_001).unwrap());
    assert!(!store.reject_mls_invite(&invite, 100_001).unwrap());
    drop(store);
    let mut store = crate::open_store(&path).unwrap();
    let mut other_evidence = inviter_evidence;
    other_evidence.certificate.peer_id = other_device.clone();
    other_evidence.certificate.serial = 2;
    other_evidence.device_key = libp2p_identity::Keypair::ed25519_from_bytes([102; 32])
        .unwrap()
        .public()
        .try_into_ed25519()
        .unwrap()
        .to_bytes();
    let changed = MlsIncomingInvite {
        inviter_device: other_device.clone(),
        id: Id128([4; 16]),
        ..invite.clone()
    };
    assert!(
        !store
            .receive_verified_mls_invite(
                &changed,
                MlsInviteEndpoints {
                    inviter: &other_evidence,
                    recipient: &recipient_evidence,
                    chain_id: 1,
                },
                100_002,
            )
            .unwrap()
    );
    let registered: bool = store
        .connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM device_identities WHERE peer_id=?1)
                 OR EXISTS(SELECT 1 FROM peers WHERE peer_id=?1)",
            [bs58::encode(other_device.as_bytes()).into_string()],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!registered);
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
    assert_eq!(
        store
            .list_pending_mls_invites(recipient_agent, &recipient, start)
            .unwrap(),
        (0..5).map(|index| invite(index, start)).collect::<Vec<_>>(),
    );
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

const REJOIN_NOW: u64 = 100_000;
const REJOIN_END: u64 = 105_000;
const REJOIN_ROOM: GroupId = GroupId(Id128([20; 16]));
const REJOIN_KEY: MlsJoinKey = MlsJoinKey {
    request_id: Id128([21; 16]),
    package_ref: Hash32([22; 32]),
};

fn rejoin_fixture(store: &Store) -> (MlsIncomingInvite, [MlsMemberEvidence; 2]) {
    let creator = register_evidence(store, AgentId([1; 32]), &tests::test_peer(1), REJOIN_END);
    let recipient = register_evidence(store, AgentId([2; 32]), &tests::test_peer(2), REJOIN_END);
    let invite = MlsIncomingInvite {
        id: Id128([23; 16]),
        wire_id: Hash32([24; 32]),
        base_epoch: 8,
        inviter: creator.certificate.agent_id,
        inviter_device: creator.certificate.peer_id.clone(),
        recipient: recipient.certificate.agent_id,
        recipient_device: recipient.certificate.peer_id.clone(),
        expires_at_ms: REJOIN_END,
    };
    (invite, [creator, recipient])
}

fn rejoin_candidate<'a>(
    invite: &'a MlsIncomingInvite,
    members: &'a [MlsMemberEvidence],
) -> MlsJoinedRoom<'a> {
    MlsJoinedRoom {
        invite,
        key: REJOIN_KEY,
        room: PendingMlsRoom {
            local_id: &REJOIN_ROOM,
            wire_id: invite.wire_id,
            creator: &invite.inviter_device,
            local_name: "Do not replace the original label",
            mls_epoch: invite.base_epoch + 1,
            sealed_snapshot: b"fresh state",
        },
        members,
        chain_id: 1,
        expected_policy_revision: 1,
    }
}

fn stage_rejoin_room(store: &mut Store, invite: &MlsIncomingInvite) -> RoomVersion {
    store
        .stage_mls_room(PendingMlsRoom {
            local_id: &REJOIN_ROOM,
            wire_id: invite.wire_id,
            creator: &invite.inviter_device,
            local_name: "Original label",
            mls_epoch: 5,
            sealed_snapshot: b"old state",
        })
        .unwrap();
    store
        .mls_room_snapshot(invite.wire_id)
        .unwrap()
        .unwrap()
        .version
}

#[test]
fn rejoin_replaces_only_the_paused_branch_and_preserves_replay_markers() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("rejoin.sqlite3");
    let mut store = crate::open_store(&path).unwrap();
    let (invite, members) = rejoin_fixture(&store);
    let old_member = tests::test_peer(3);
    let same_agent_other_device = tests::test_peer(4);
    tests::register_agent_peer(&store, AgentId([3; 32]), &old_member, 1);
    tests::register_agent_peer(&store, invite.inviter, &same_agent_other_device, 2);
    let initial = stage_rejoin_room(&mut store, &invite);
    let old_members = [invite.inviter_device.clone(), old_member.clone()];
    let projected = store
        .commit_mls_room_candidate(MlsRoomUpdate {
            local_id: &REJOIN_ROOM,
            wire_id: invite.wire_id,
            expected: initial,
            mls_epoch: 5,
            sealed_snapshot: b"old projection",
            members: &old_members,
            event: None,
        })
        .unwrap();
    let expected = store
        .commit_mls_room_candidate(MlsRoomUpdate {
            local_id: &REJOIN_ROOM,
            wire_id: invite.wire_id,
            expected: projected,
            mls_epoch: 6,
            sealed_snapshot: b"old head",
            members: &old_members,
            event: Some(MlsJournalEntry {
                sender: &invite.inviter_device,
                kind: MlsJournalKind::SyncCommit(MlsEpochBindings {
                    base: Hash32([25; 32]),
                    next: Hash32([26; 32]),
                }),
                ciphertext: b"old commit",
            }),
        })
        .unwrap();
    let old_package = Hash32([27; 32]);
    store
        .connection
        .execute(
            "INSERT INTO mls_outgoing_invites
                (invite_id,wire_group_id,base_epoch,creator_peer_id,recipient_agent_id,
                 recipient_peer_id,created_at_ms,expires_at_ms,request_id,package_ref,welcome)
             VALUES (?1,?2,5,?3,?4,?5,100000,105000,?6,?7,X'01')",
            params![
                Id128([28; 16]).as_bytes(),
                invite.wire_id.as_bytes(),
                peer_text(&invite.inviter_device),
                bs58::encode([3; 32]).into_string(),
                peer_text(&old_member),
                Id128([29; 16]).as_bytes(),
                old_package.as_bytes(),
            ],
        )
        .unwrap();
    store
        .connection
        .execute(
            "INSERT INTO mls_consumed_key_packages VALUES (?1,105000)",
            [old_package.as_bytes()],
        )
        .unwrap();

    for denied in [
        MlsIncomingInvite {
            base_epoch: 6,
            ..invite.clone()
        },
        MlsIncomingInvite {
            inviter_device: same_agent_other_device,
            ..invite.clone()
        },
    ] {
        assert!(!store.receive_mls_invite(&denied, REJOIN_NOW).unwrap());
    }
    store
        .connection
        .execute("UPDATE asl_groups SET state='active'", [])
        .unwrap();
    assert!(!store.receive_mls_invite(&invite, REJOIN_NOW).unwrap());
    store
        .connection
        .execute("UPDATE asl_groups SET state='needs_sync'", [])
        .unwrap();

    assert!(store.receive_mls_invite(&invite, REJOIN_NOW).unwrap());
    assert_eq!(
        store
            .list_pending_mls_invites(invite.recipient, &invite.recipient_device, REJOIN_NOW)
            .unwrap(),
        std::slice::from_ref(&invite),
    );
    let candidate = || rejoin_candidate(&invite, &members);
    assert!(
        store
            .finish_mls_rejoin(candidate(), expected, || Ok(REJOIN_NOW))
            .is_err()
    );
    assert!(
        store
            .save_mls_join_package(&invite, REJOIN_KEY, b"approved rejoin", REJOIN_NOW)
            .unwrap()
    );
    drop(store);

    let mut store = crate::open_store(&path).unwrap();
    assert_eq!(
        store
            .recover_mls_joins(invite.recipient, &invite.recipient_device, REJOIN_NOW)
            .unwrap(),
        std::slice::from_ref(&invite),
    );
    assert!(
        store
            .finish_mls_join(candidate(), || Ok(REJOIN_NOW))
            .is_err()
    );
    for stale in [
        RoomVersion {
            revision: expected.revision - 1,
            ..expected
        },
        RoomVersion {
            mls_epoch: expected.mls_epoch - 1,
            ..expected
        },
        RoomVersion {
            membership_epoch: expected.membership_epoch + 1,
            ..expected
        },
        RoomVersion {
            policy_revision: expected.policy_revision + 1,
            ..expected
        },
    ] {
        assert!(matches!(
            store.finish_mls_rejoin(candidate(), stale, || Ok(REJOIN_NOW)),
            Err(AslError::PolicyVersionConflict)
        ));
    }
    let wrong_id = GroupId(Id128([30; 16]));
    let mut wrong_room = candidate();
    wrong_room.room.local_id = &wrong_id;
    assert!(
        store
            .finish_mls_rejoin(wrong_room, expected, || Ok(REJOIN_NOW))
            .is_err()
    );
    store
        .connection
        .execute_batch(
            "CREATE TRIGGER fail_rejoin_projection BEFORE INSERT ON group_members
         BEGIN SELECT RAISE(ABORT, 'test rollback'); END;",
        )
        .unwrap();
    assert!(
        store
            .finish_mls_rejoin(candidate(), expected, || Ok(REJOIN_NOW))
            .is_err()
    );
    assert_eq!(
        store.pending_mls_join_package(&invite, REJOIN_NOW).unwrap(),
        Some((REJOIN_KEY, b"approved rejoin".to_vec()))
    );
    let history_counts = |store: &Store| {
        store
            .connection
            .query_row(
                "SELECT (SELECT count(*) FROM mls_sync_log),
                    (SELECT count(*) FROM group_events),
                    (SELECT count(*) FROM mls_outgoing_invites WHERE welcome IS NOT NULL),
                    (SELECT count(*) FROM mls_consumed_key_packages)",
                [],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, i64>(3)?,
                    ))
                },
            )
            .unwrap()
    };
    assert_eq!(history_counts(&store), (1, 1, 1, 1));
    let unchanged = store
        .mls_room_for_reconciliation(invite.wire_id)
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.snapshot.version, expected);
    assert_eq!(unchanged.snapshot.sealed_snapshot, b"old head");
    assert_eq!(unchanged.members.len(), 2);
    assert!(unchanged.members.contains(&old_member));
    store
        .connection
        .execute_batch("DROP TRIGGER fail_rejoin_projection")
        .unwrap();

    let mut times = [REJOIN_NOW, invite.expires_at_ms].into_iter();
    assert!(matches!(
        store.finish_mls_rejoin(candidate(), expected, || Ok(times.next().unwrap())),
        Err(AslError::ExpiredMessage)
    ));
    assert_eq!(
        store
            .mls_room_snapshot(invite.wire_id)
            .unwrap()
            .unwrap()
            .version,
        expected
    );
    assert!(
        store
            .pending_mls_join_package(&invite, REJOIN_NOW)
            .unwrap()
            .is_some()
    );
    let result = store
        .finish_mls_rejoin(candidate(), expected, || Ok(REJOIN_NOW))
        .unwrap();
    assert_eq!(
        result,
        RoomVersion {
            revision: expected.revision + 1,
            mls_epoch: 9,
            ..expected
        }
    );
    assert!(
        store
            .finish_mls_rejoin(candidate(), result, || Ok(REJOIN_NOW))
            .is_err()
    );
    drop(store);
    let mut store = crate::open_store(&path).unwrap();
    let room = store
        .mls_room_for_reconciliation(invite.wire_id)
        .unwrap()
        .unwrap();
    assert_eq!(room.snapshot.local_id, REJOIN_ROOM);
    assert_eq!(room.snapshot.version, result);
    assert_eq!(room.snapshot.sealed_snapshot, b"fresh state");
    assert_eq!(room.creator, invite.inviter_device);
    assert_eq!(room.members.len(), 2);
    assert!(room.members.contains(&invite.recipient_device));
    assert!(!room.members.contains(&old_member));
    assert_eq!(history_counts(&store), (0, 1, 0, 1));
    assert_eq!(
        store.mls_room_progress(invite.wire_id).unwrap(),
        Some(("needs_sync".to_owned(), 9))
    );
    let label: String = store
        .connection
        .query_row("SELECT local_name FROM asl_groups", [], |r| r.get(0))
        .unwrap();
    assert_eq!(label, "Original label");
    let relations: (bool, bool, bool) = store
        .connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM peers WHERE peer_id=?1),
                NOT EXISTS(SELECT 1 FROM pragma_foreign_key_check),
                NOT EXISTS(SELECT 1 FROM grants)",
            [peer_text(&old_member)],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(relations, (true, true, true));
    assert!(
        store
            .pending_mls_join_package(&invite, REJOIN_NOW)
            .unwrap()
            .is_none()
    );
}

#[test]
fn newly_staged_room_does_not_inherit_a_new_room_approval() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("stale-invite.sqlite3");
    let mut store = crate::open_store(&path).unwrap();
    let (invite, members) = rejoin_fixture(&store);
    assert!(store.receive_mls_invite(&invite, REJOIN_NOW).unwrap());
    assert!(
        store
            .save_mls_join_package(
                &invite,
                REJOIN_KEY,
                b"approved for initial join",
                REJOIN_NOW
            )
            .unwrap()
    );
    let expected = stage_rejoin_room(&mut store, &invite);
    drop(store);

    let mut store = crate::open_store(&path).unwrap();
    assert!(
        store
            .recover_mls_joins(invite.recipient, &invite.recipient_device, REJOIN_NOW)
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .finish_mls_rejoin(rejoin_candidate(&invite, &members), expected, || Ok(
                REJOIN_NOW
            ))
            .is_err()
    );
    assert_eq!(
        store
            .mls_room_snapshot(invite.wire_id)
            .unwrap()
            .unwrap()
            .version,
        expected
    );
}
