use std::path::PathBuf;

use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId},
    protocol::{GroupBody, GroupMembership, GroupPacket},
    task::GroupId,
};
use rusqlite::params;

use super::{
    MLS_SYNC_RETENTION_MS, MlsEpochBindings, MlsInviteResponse, MlsJournalEntry, MlsJournalKind,
    MlsMemberEvidence, MlsRemoveAuthority, MlsRoomUpdate, MlsSyncStoredStep, MlsWelcomeRequest,
    PendingMlsRoom, RoomVersion,
    recovery_tests::register_evidence,
    tests::{register_agent_peer, test_peer},
    transition::{commit_candidate, peer_text},
};
use crate::{Store, open_store};

const LOCAL: GroupId = GroupId(Id128([1; 16]));
const WIRE: Hash32 = Hash32([2; 32]);
const INVITE: Id128 = Id128([3; 16]);
const TARGET: AgentId = AgentId([2; 32]);
const NOW: u64 = 1_000;
const EXPIRES: u64 = 2_000;

fn bindings(epoch: u64) -> MlsEpochBindings {
    let binding = |epoch: u64| Hash32(*blake3::hash(&epoch.to_be_bytes()).as_bytes());
    MlsEpochBindings {
        base: binding(epoch),
        next: binding(epoch + 1),
    }
}

struct Fixture {
    path: PathBuf,
    _root: tempfile::TempDir,
    creator: PeerId,
    target: PeerId,
    alternate: PeerId,
}

impl Fixture {
    fn new() -> (Self, Store, RoomVersion) {
        let (fixture, store, base, ()) = Self::with_devices(|store, f| {
            for (peer, agent, serial) in [
                (&f.creator, AgentId([1; 32]), 1),
                (&f.target, TARGET, 1),
                (&f.alternate, TARGET, 2),
            ] {
                register_agent_peer(store, agent, peer, serial);
            }
            store
                .connection
                .execute(
                    "UPDATE device_identities SET certificate_expires_ms=?1",
                    [EXPIRES as i64 + 1],
                )
                .unwrap();
        });
        (fixture, store, base)
    }

    fn with_devices<T>(register: impl FnOnce(&Store, &Self) -> T) -> (Self, Store, RoomVersion, T) {
        let root = tempfile::tempdir().unwrap();
        let fixture = Self {
            path: root.path().join("outgoing.sqlite3"),
            _root: root,
            creator: test_peer(1),
            target: test_peer(2),
            alternate: test_peer(3),
        };
        let mut store = open_store(&fixture.path).unwrap();
        let devices = register(&store, &fixture);
        store
            .stage_mls_room(PendingMlsRoom {
                local_id: &LOCAL,
                wire_id: WIRE,
                creator: &fixture.creator,
                local_name: "Local",
                mls_epoch: 0,
                sealed_snapshot: b"initial",
            })
            .unwrap();
        let initial = store.mls_room_snapshot(WIRE).unwrap().unwrap().version;
        let base = store
            .commit_mls_room_candidate(MlsRoomUpdate {
                local_id: &LOCAL,
                wire_id: WIRE,
                expected: initial,
                mls_epoch: 0,
                sealed_snapshot: b"projected",
                members: std::slice::from_ref(&fixture.creator),
                event: None,
            })
            .unwrap();
        (fixture, store, base, devices)
    }

    fn invite(&self) -> GroupPacket {
        GroupPacket {
            message_id: INVITE,
            group_id: WIRE,
            epoch: 0,
            body: GroupBody::Membership(GroupMembership::Invite {
                agent: TARGET,
                device: self.target.clone(),
                expires_at_ms: EXPIRES,
            }),
        }
    }

    fn request(&self, packet: &GroupPacket) -> GroupPacket {
        GroupPacket {
            message_id: Id128([4; 16]),
            body: GroupBody::Membership(GroupMembership::KeyPackage {
                invite: packet.message_id,
                message: b"test package".to_vec(),
            }),
            ..packet.clone()
        }
    }

    fn authenticate<'a>(&'a self, packet: &'a GroupPacket) -> MlsWelcomeRequest<'a> {
        MlsWelcomeRequest {
            local_creator: &self.creator,
            recipient: TARGET,
            device: &self.target,
            packet,
            package_ref: Hash32([5; 32]),
            package_expires_at_ms: EXPIRES + 1_000,
        }
    }

    fn change<'a>(
        &'a self,
        base: RoomVersion,
        members: &'a [PeerId],
        commit: &'a [u8],
    ) -> MlsRoomUpdate<'a> {
        MlsRoomUpdate {
            local_id: &LOCAL,
            wire_id: WIRE,
            expected: base,
            mls_epoch: base.mls_epoch + 1,
            sealed_snapshot: b"next sealed snapshot",
            members,
            event: Some(MlsJournalEntry {
                sender: &self.creator,
                kind: MlsJournalKind::Commit,
                ciphertext: commit,
            }),
        }
    }

    fn sync_change<'a>(
        &'a self,
        base: RoomVersion,
        members: &'a [PeerId],
        commit: &'a [u8],
    ) -> MlsRoomUpdate<'a> {
        let mut update = self.change(base, members, commit);
        update.event.as_mut().unwrap().kind = MlsJournalKind::SyncCommit(bindings(base.mls_epoch));
        update
    }

    fn remove_target(
        &self,
        store: &mut Store,
        expected: RoomVersion,
        creator: &MlsMemberEvidence,
        now: u64,
    ) -> Result<RoomVersion, AslError> {
        let mut update = self.sync_change(expected, std::slice::from_ref(&self.creator), b"remove");
        update.sealed_snapshot = b"removed snapshot";
        store.commit_verified_mls_remove(
            update,
            MlsRemoveAuthority {
                source: &self.creator,
                committer: &self.creator,
                removed: &self.target,
                survivors: std::slice::from_ref(creator),
                chain_id: 1,
            },
            now,
            || Ok(now),
        )
    }
}

#[test]
fn committed_welcome_survives_restart_and_matches_only_the_original_request() {
    let (f, mut store, base) = Fixture::new();
    let invite = f.invite();
    let packet = f.request(&invite);
    let request = f.authenticate(&packet);
    assert!(store.mls_invite_response(&request, NOW).unwrap().is_none());
    assert!(store.issue_mls_invite(&f.alternate, &invite, NOW).is_err());
    store.issue_mls_invite(&f.creator, &invite, NOW).unwrap();
    assert_eq!(
        store.mls_invite_response(&request, NOW).unwrap(),
        Some(MlsInviteResponse::Pending)
    );
    let wrong_device = MlsWelcomeRequest {
        device: &f.alternate,
        ..request
    };
    assert!(
        store
            .mls_invite_response(&wrong_device, NOW)
            .unwrap()
            .is_none()
    );
    let wrong_agent = MlsWelcomeRequest {
        recipient: AgentId([9; 32]),
        ..request
    };
    assert!(
        store
            .mls_invite_response(&wrong_agent, NOW)
            .unwrap()
            .is_none()
    );
    let wrong_local = MlsWelcomeRequest {
        local_creator: &f.alternate,
        ..request
    };
    assert!(
        store
            .mls_invite_response(&wrong_local, NOW)
            .unwrap()
            .is_none()
    );
    let roster = [f.creator.clone(), f.target.clone()];
    let update = || f.change(base, &roster, b"add commit");
    let added = store
        .commit_mls_invite_welcome(&request, update(), b"one welcome".to_vec(), NOW)
        .unwrap();
    let exact = store.mls_invite_response(&request, NOW).unwrap().unwrap();
    assert_eq!(
        exact,
        MlsInviteResponse::Committed(GroupPacket {
            message_id: packet.message_id,
            group_id: WIRE,
            epoch: 1,
            body: GroupBody::Membership(GroupMembership::Welcome {
                invite: INVITE,
                package_ref: request.package_ref,
                message: b"one welcome".to_vec(),
            }),
        })
    );
    drop(store);

    let mut store = open_store(&f.path).unwrap();
    assert_eq!(
        store.mls_invite_response(&request, NOW).unwrap(),
        Some(exact)
    );
    assert!(
        store
            .commit_mls_invite_welcome(&request, update(), b"another welcome".to_vec(), NOW)
            .is_err()
    );
    let mut other_group = WIRE;
    other_group.0[31] ^= 1;
    for wrong in [
        GroupPacket {
            group_id: other_group,
            ..packet.clone()
        },
        GroupPacket {
            epoch: 1,
            ..packet.clone()
        },
        GroupPacket {
            message_id: Id128([9; 16]),
            ..packet.clone()
        },
        GroupPacket {
            body: GroupBody::Membership(GroupMembership::KeyPackage {
                invite: Id128([9; 16]),
                message: b"test package".to_vec(),
            }),
            ..packet.clone()
        },
    ] {
        assert!(
            store
                .mls_invite_response(&f.authenticate(&wrong), NOW)
                .unwrap()
                .is_none()
        );
    }
    let wrong_package = MlsWelcomeRequest {
        package_ref: Hash32([9; 32]),
        ..request
    };
    assert!(
        store
            .mls_invite_response(&wrong_package, NOW)
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .mls_invite_response(&wrong_device, NOW)
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .mls_invite_response(&request, EXPIRES)
            .unwrap()
            .is_none()
    );
    let room = store.mls_room_snapshot(WIRE).unwrap().unwrap();
    assert_eq!(room.version, added);
    assert_eq!(room.sealed_snapshot, b"next sealed snapshot");
    assert_eq!(store.policy_revision().unwrap(), base.policy_revision);
    assert_eq!(commit_count(&store), 1);
}

#[test]
fn failed_welcome_write_rolls_back_commit_and_can_be_retried() {
    let (f, mut store, base) = Fixture::new();
    let invite = f.invite();
    store.issue_mls_invite(&f.creator, &invite, NOW).unwrap();
    let packet = f.request(&invite);
    let request = f.authenticate(&packet);
    let roster = [f.creator.clone(), f.target.clone()];
    let extra = [f.creator.clone(), f.target.clone(), f.alternate.clone()];
    let update = || f.sync_change(base, &roster, b"add commit");
    let too_large = vec![0; asl_types::protocol::MAX_GROUP_MLS_OBJECT_BYTES + 1];
    assert!(
        store
            .commit_mls_invite_welcome(
                &request,
                f.change(base, &roster, &too_large),
                b"welcome".to_vec(),
                NOW,
            )
            .is_err()
    );
    assert!(
        store
            .commit_mls_invite_welcome(
                &request,
                f.change(base, &extra, b"extra add"),
                b"welcome".to_vec(),
                NOW,
            )
            .is_err()
    );
    store
        .connection
        .execute_batch(
            "CREATE TEMP TRIGGER reject_welcome BEFORE UPDATE OF welcome ON mls_outgoing_invites
         WHEN NEW.welcome IS NOT NULL BEGIN SELECT RAISE(ABORT,'test rollback'); END;",
        )
        .unwrap();
    assert!(
        store
            .commit_mls_invite_welcome(&request, update(), b"welcome".to_vec(), NOW)
            .is_err()
    );
    let room = store.mls_room_snapshot(WIRE).unwrap().unwrap();
    assert_eq!(room.version, base);
    assert_eq!(room.sealed_snapshot, b"projected");
    assert_eq!(commit_count(&store), 0);
    assert_eq!(sync_count(&store), 0);
    assert_eq!(
        store.mls_invite_response(&request, NOW).unwrap(),
        Some(MlsInviteResponse::Pending)
    );
    store
        .connection
        .execute_batch("DROP TRIGGER reject_welcome")
        .unwrap();
    let version = store
        .commit_mls_invite_welcome(&request, update(), b"welcome".to_vec(), NOW)
        .unwrap();
    assert_eq!(commit_count(&store), 1);
    assert_eq!(sync_count(&store), 1);
    drop(store);

    let mut store = open_store(&f.path).unwrap();
    assert_eq!(
        store.mls_sync_step(WIRE, 0, NOW).unwrap(),
        Some(MlsSyncStoredStep {
            local_id: LOCAL,
            base_epoch: 0,
            expires_at_ms: NOW + MLS_SYNC_RETENTION_MS,
            bindings: bindings(0),
            signer: f.creator.clone(),
            commit: b"add commit".to_vec(),
            version,
        }),
    );
    assert!(
        store
            .mls_sync_step(WIRE, 0, NOW + MLS_SYNC_RETENTION_MS - 1)
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .mls_sync_step(WIRE, 0, NOW + MLS_SYNC_RETENTION_MS)
            .unwrap()
            .is_none()
    );
    assert!(store.mls_sync_step(WIRE, 0, NOW - 1).unwrap().is_none());
    store
        .connection
        .execute(
            "UPDATE group_events SET ciphertext=zeroblob(?1)",
            [asl_types::protocol::MAX_GROUP_MLS_OBJECT_BYTES as i64 + 1],
        )
        .unwrap();
    assert!(store.mls_sync_step(WIRE, 0, NOW).unwrap().is_none());
    store
        .prune_mls_expired(NOW + MLS_SYNC_RETENTION_MS)
        .unwrap();
    assert_eq!(sync_count(&store), 0);
    assert_eq!(commit_count(&store), 0);
}

#[test]
fn sync_digest_binds_expiry_and_the_exact_step() {
    let signer = test_peer(1);
    let local_device = test_peer(2);
    let bindings = bindings(0);
    let expiry = NOW + MLS_SYNC_RETENTION_MS;
    let digest = |epoch_and_expiry, commit: &[u8]| {
        bindings.digest(
            &LOCAL,
            WIRE,
            &local_device,
            epoch_and_expiry,
            &signer,
            commit,
        )
    };
    let sealed = digest((0, expiry), b"commit");
    assert_ne!(sealed, digest((0, expiry + 1), b"commit"));
    assert_ne!(sealed, digest((1, expiry), b"commit"));
    assert_ne!(sealed, digest((0, expiry), b"commit\0"));
}

#[test]
fn removed_member_cannot_fetch_an_earlier_welcome_even_after_reentry() {
    let (f, mut store, base) = Fixture::new();
    let invite = f.invite();
    store.issue_mls_invite(&f.creator, &invite, NOW).unwrap();
    let packet = f.request(&invite);
    let request = f.authenticate(&packet);
    let roster = [f.creator.clone(), f.target.clone()];
    let added = store
        .commit_mls_invite_welcome(
            &request,
            f.change(base, &roster, b"add"),
            b"welcome".to_vec(),
            NOW,
        )
        .unwrap();
    store
        .connection
        .execute(
            "UPDATE device_identities SET revoked_at_ms=?2 WHERE peer_id=?1",
            params![peer_text(&f.target), NOW as i64 + 1],
        )
        .unwrap();
    assert!(
        store
            .mls_invite_response(&request, NOW + 1)
            .unwrap()
            .is_none()
    );
    store
        .connection
        .execute(
            "UPDATE device_identities SET revoked_at_ms=NULL WHERE peer_id=?1",
            [peer_text(&f.target)],
        )
        .unwrap();
    let later = store
        .commit_mls_room_candidate(f.change(added, &roster, b"update"))
        .unwrap();
    assert!(matches!(
        store.mls_invite_response(&request, NOW + 1).unwrap(),
        Some(MlsInviteResponse::Committed(_))
    ));
    let removed = store
        .commit_mls_room_candidate(f.change(later, std::slice::from_ref(&f.creator), b"remove"))
        .unwrap();
    store
        .commit_mls_room_candidate(f.change(removed, &roster, b"new admission"))
        .unwrap();
    assert!(
        store
            .mls_invite_response(&request, NOW + 1)
            .unwrap()
            .is_none()
    );
    store.prune_mls_expired(EXPIRES).unwrap();
    assert_eq!(
        store
            .connection
            .query_row("SELECT count(*) FROM mls_outgoing_invites", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

fn room_with_cached_welcome() -> (
    Fixture,
    Store,
    RoomVersion,
    [MlsMemberEvidence; 2],
    GroupPacket,
) {
    let (f, mut store, base, evidence) = Fixture::with_devices(|store, f| {
        [
            register_evidence(store, AgentId([1; 32]), &f.creator, EXPIRES + 1),
            register_evidence(store, TARGET, &f.target, EXPIRES + 1),
        ]
    });
    let invite = f.invite();
    store.issue_mls_invite(&f.creator, &invite, NOW).unwrap();
    let packet = f.request(&invite);
    let roster = [f.creator.clone(), f.target.clone()];
    let added = store
        .commit_mls_invite_welcome(
            &f.authenticate(&packet),
            f.sync_change(base, &roster, b"add"),
            b"welcome".to_vec(),
            NOW,
        )
        .unwrap();
    (f, store, added, evidence, packet)
}

#[test]
fn verified_remove_invalidates_cached_welcome_for_a_revoked_device() {
    let (f, mut store, added, [creator, target], packet) = room_with_cached_welcome();
    let request = f.authenticate(&packet);
    let now = NOW + 1;
    assert!(matches!(
        store.mls_invite_response(&request, now).unwrap(),
        Some(MlsInviteResponse::Committed(_))
    ));
    store.require_mls_member(&target, 1, now).unwrap();
    store
        .connection
        .execute(
            "UPDATE device_identities SET revoked_at_ms=?2 WHERE peer_id=?1",
            params![peer_text(&f.target), now as i64],
        )
        .unwrap();
    assert!(matches!(
        store.require_mls_member(&target, 1, now),
        Err(AslError::InvalidDeviceCertificate)
    ));

    // The replay filter already hides revoked devices, so assert on the cached bytes directly.
    let cached_welcome = |store: &Store| {
        store
            .connection
            .query_row(
                "SELECT welcome FROM mls_outgoing_invites WHERE invite_id=?1",
                [INVITE.as_bytes()],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .unwrap()
    };
    assert_eq!(
        cached_welcome(&store).as_deref(),
        Some(b"welcome".as_slice())
    );
    let removed = f.remove_target(&mut store, added, &creator, now).unwrap();
    assert_eq!(
        removed,
        RoomVersion {
            revision: added.revision + 1,
            mls_epoch: added.mls_epoch + 1,
            membership_epoch: added.membership_epoch + 1,
            ..added
        }
    );
    drop(store);

    let store = open_store(&f.path).unwrap();
    let room = store.mls_room_for_reconciliation(WIRE).unwrap().unwrap();
    assert_eq!(room.snapshot.version, removed);
    assert_eq!(room.snapshot.sealed_snapshot, b"removed snapshot");
    assert_eq!(room.members.as_slice(), std::slice::from_ref(&f.creator));
    let step = store
        .mls_sync_step(WIRE, added.mls_epoch, now)
        .unwrap()
        .unwrap();
    assert_eq!(step.commit, b"remove");
    assert_eq!(step.version, removed);
    assert_eq!(cached_welcome(&store), None);
    assert!(store.mls_invite_response(&request, now).unwrap().is_none());
}

#[test]
fn rejected_verified_remove_retains_cached_welcome_and_room_state() {
    let (f, mut store, added, [mut creator, _], packet) = room_with_cached_welcome();
    let request = f.authenticate(&packet);
    let now = NOW + 1;
    let welcome = store.mls_invite_response(&request, now).unwrap();
    assert!(matches!(welcome, Some(MlsInviteResponse::Committed(_))));
    let assert_unchanged = |store: &Store| {
        assert_eq!(store.mls_invite_response(&request, now).unwrap(), welcome);
        let room = store.mls_room_for_reconciliation(WIRE).unwrap().unwrap();
        assert_eq!(room.snapshot.version, added);
        assert_eq!(room.snapshot.sealed_snapshot, b"next sealed snapshot");
        assert_eq!(room.members.len(), 2);
        assert!(room.members.contains(&f.creator));
        assert!(room.members.contains(&f.target));
        assert_eq!(commit_count(store), 1);
        assert_eq!(sync_count(store), 1);
    };
    let current_sequence = creator.registry_sequence;
    creator.registry_sequence += 1;
    assert!(matches!(
        f.remove_target(&mut store, added, &creator, now),
        Err(AslError::InvalidDeviceCertificate)
    ));
    assert_unchanged(&store);
    creator.registry_sequence = current_sequence;

    let stale = RoomVersion {
        revision: added.revision - 1,
        ..added
    };
    assert!(matches!(
        f.remove_target(&mut store, stale, &creator, now),
        Err(AslError::PolicyVersionConflict)
    ));
    assert_unchanged(&store);

    // Fail the final write, after the journal, projection and Welcome changes.
    store
        .connection
        .execute_batch(
            "CREATE TEMP TRIGGER reject_remove_snapshot BEFORE UPDATE OF sealed_snapshot ON mls_room_states
             BEGIN SELECT RAISE(ABORT,'test remove rollback'); END;",
        )
        .unwrap();
    assert!(matches!(
        f.remove_target(&mut store, added, &creator, now),
        Err(AslError::Io(error)) if error.to_string().contains("test remove rollback")
    ));
    drop(store);
    assert_unchanged(&open_store(&f.path).unwrap());
}

fn commit_count(store: &Store) -> i64 {
    store
        .connection
        .query_row(
            "SELECT count(*) FROM group_events WHERE kind='commit'",
            [],
            |r| r.get(0),
        )
        .unwrap()
}

fn sync_count(store: &Store) -> i64 {
    store
        .connection
        .query_row("SELECT count(*) FROM mls_sync_log", [], |r| r.get(0))
        .unwrap()
}

fn remove_group_transfer_schema_for_legacy_fixture(store: &Store) {
    store
        .connection
        .execute_batch(
            "DROP INDEX upload_consent_lookup;
             ALTER TABLE transfer_consents DROP COLUMN upload_size;
             ALTER TABLE transfer_consents DROP COLUMN upload_filename;
             ALTER TABLE transfer_consents DROP COLUMN target_peer_id;
             DROP INDEX group_download_consent_lookup;
             DROP INDEX group_transfer_epoch_lookup;
             ALTER TABLE transfers DROP COLUMN group_epoch;
             ALTER TABLE transfers DROP COLUMN group_id;",
        )
        .unwrap();
}

fn remove_contact_binding_schema_for_legacy_fixture(store: &Store) {
    crate::avatar_receipts::remove_schema_for_legacy_fixture(store);
    store
        .connection
        .execute_batch(
            "DROP TABLE avatar_reference_grant;
             DROP TABLE local_avatar_selection;
             DROP TABLE contact_binding_actions;
             DROP TABLE contact_binding_candidates;
             DROP TABLE contact_bindings;
             DROP TABLE direct_inbound_observations;
             DROP TABLE observed_remote_profiles;
             ALTER TABLE group_events DROP COLUMN browse_expires_at_ms;
             ALTER TABLE group_events DROP COLUMN browse_kind;
             DELETE FROM settings WHERE key='ui.binding_code_public.v1';",
        )
        .unwrap();
}

#[test]
fn group_browse_retention_zero_and_shortening_leave_the_mls_journal_intact() {
    use crate::{current_time_ms, dashboard::Dashboard};
    let (f, mut store, mut version) = Fixture::new();
    let now = current_time_ms();
    let day = 24 * 60 * 60 * 1000_i64;
    let append = |store: &mut Store, version: RoomVersion, id, at| {
        let tx = store.connection.transaction().unwrap();
        let next = commit_candidate(
            &tx,
            MlsRoomUpdate {
                local_id: &LOCAL,
                wire_id: WIRE,
                expected: version,
                mls_epoch: version.mls_epoch,
                sealed_snapshot: b"updated",
                members: std::slice::from_ref(&f.creator),
                event: Some(MlsJournalEntry {
                    sender: &f.creator,
                    kind: MlsJournalKind::ReceivedApplication(Id128([id; 16]), "expression"),
                    ciphertext: b"received fixture",
                }),
            },
            None,
            at,
        )?;
        tx.commit().unwrap();
        Ok::<_, AslError>(next)
    };
    version = append(&mut store, version, 1, now - 2 * day).unwrap();
    version = append(&mut store, version, 2, now).unwrap();
    let activity_count = || Dashboard::load(&f.path).unwrap().activity.len();
    assert_eq!(activity_count(), 2);

    store.set_group_observation_days(1).unwrap();
    assert_eq!(activity_count(), 1);
    store.set_group_observation_days(7).unwrap();
    version = append(&mut store, version, 3, now + 1).unwrap();
    let deadlines = |store: &Store| {
        store
            .connection
            .prepare(
                "SELECT created_at_ms,expires_at_ms,browse_kind,browse_expires_at_ms,ciphertext
                 FROM group_events ORDER BY created_at_ms",
            )
            .unwrap()
            .query_map([], |row| {
                let created = row.get::<_, i64>(0)?;
                assert_eq!(row.get::<_, i64>(1)?, created + 7 * day);
                assert_eq!(row.get::<_, Vec<u8>>(4)?, b"received fixture");
                Ok((
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                ))
            })
            .unwrap()
            .map(|r| {
                let (kind, deadline) = r.unwrap();
                assert_eq!(kind.as_deref(), deadline.map(|_| "expression"));
                deadline
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        deadlines(&store),
        [None, Some(now + day), Some(now + 1 + 7 * day)]
    );
    assert_eq!(activity_count(), 2);
    store.set_group_observation_days(0).unwrap();
    drop(store);
    let mut store = open_store(&f.path).unwrap();
    assert!(matches!(
        append(&mut store, version, 3, now + 2),
        Err(AslError::PolicyVersionConflict)
    ));
    append(&mut store, version, 4, now + 2).unwrap();
    assert_eq!(deadlines(&store), [None; 4]);
    store.set_group_observation_days(7).unwrap();
    assert_eq!(activity_count(), 0);
}

#[test]
fn upgrading_v20_preserves_which_group_events_were_visible() {
    let (f, store, _) = Fixture::new();
    let peer = peer_text(&f.creator);
    crate::avatar_receipts::remove_schema_for_legacy_fixture(&store);
    store
        .connection
        .execute_batch(
            "ALTER TABLE group_events DROP COLUMN browse_expires_at_ms;
             DROP TABLE avatar_reference_grant;
             DROP TABLE local_avatar_selection;
             DROP TABLE observed_remote_profiles;
             DELETE FROM schema_migrations WHERE version>=21;",
        )
        .unwrap();
    for (id, kind) in [(1, Some("query")), (2, None)] {
        store
            .connection
            .execute(
                "INSERT INTO group_events(event_id,group_id,mls_epoch,sender_peer_id,
                                           kind,ciphertext,created_at_ms,expires_at_ms,browse_kind)
                 VALUES (?1,?2,0,?3,'application',X'01',?4,?5,?6)",
                params![
                    hex::encode([id; 16]),
                    hex::encode(LOCAL.0.0),
                    peer,
                    10,
                    100,
                    kind
                ],
            )
            .unwrap();
    }
    drop(store);
    let store = open_store(&f.path).unwrap();
    let mut rows = store
        .connection
        .prepare("SELECT browse_expires_at_ms FROM group_events ORDER BY event_id")
        .unwrap();
    let deadlines = rows
        .query_map([], |r| r.get::<_, Option<i64>>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(deadlines, [Some(100), None]);
}

#[test]
fn upgrading_v22_preserves_group_activity_and_sync_references() {
    let (f, mut store, base) = Fixture::new();
    crate::avatar_receipts::remove_schema_for_legacy_fixture(&store);
    store
        .connection
        .execute_batch(
            "ALTER TABLE group_events DROP COLUMN browse_expires_at_ms;
             DROP TABLE avatar_reference_grant;
             DROP TABLE local_avatar_selection;
             ALTER TABLE group_events DROP COLUMN browse_kind;
             ALTER TABLE observed_remote_profiles DROP COLUMN avatar_content_id;
             DELETE FROM schema_migrations WHERE version>=23;",
        )
        .unwrap();
    store.connection.execute_batch(crate::SCHEMA_V20).unwrap();
    store.connection.execute_batch(crate::SCHEMA_V21).unwrap();
    let event_id = hex::encode([0xab; 16]);
    let tx = store.connection.transaction().unwrap();
    let members = std::slice::from_ref(&f.creator);
    commit_candidate(
        &tx,
        f.sync_change(base, members, b"commit"),
        None,
        NOW as i64,
    )
    .unwrap();
    tx.execute(
        "INSERT INTO group_events(event_id,group_id,mls_epoch,sender_peer_id,kind,
                                  ciphertext,created_at_ms,expires_at_ms,browse_kind,browse_expires_at_ms)
         VALUES (?1,?2,1,?3,'application',X'01',10,100,'query',50)",
        params![event_id, hex::encode(LOCAL.0.0), peer_text(&f.creator)],
    )
    .unwrap();
    tx.commit().unwrap();
    drop(store);

    let store = open_store(&f.path).unwrap();
    assert_eq!(
        store.mls_sync_step(WIRE, 0, NOW).unwrap().unwrap().commit,
        b"commit"
    );
    assert_eq!(
        store
            .connection
            .query_row(
                "SELECT browse_kind,browse_expires_at_ms FROM group_events WHERE event_id=?1",
                [&event_id],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
            )
            .unwrap(),
        ("query".into(), 50)
    );
    store
        .connection
        .execute(
            "UPDATE group_events SET browse_kind='expression' WHERE event_id=?1",
            [&event_id],
        )
        .unwrap();
    assert!(
        store
            .connection
            .execute(
                "UPDATE group_events SET browse_kind='unknown' WHERE event_id=?1",
                [&event_id]
            )
            .is_err()
    );
}

#[test]
fn upgrading_v13_keeps_the_existing_mls_snapshot() {
    let (f, store, base) = Fixture::new();
    remove_group_transfer_schema_for_legacy_fixture(&store);
    remove_contact_binding_schema_for_legacy_fixture(&store);
    store
        .connection
        .execute_batch(
            "DROP TABLE mls_sync_log;
         DROP TABLE mls_outgoing_invites;
         DROP TABLE mls_consumed_key_packages;
         DELETE FROM schema_migrations WHERE version>=14;",
        )
        .unwrap();
    drop(store);
    let mut upgraded = open_store(&f.path).unwrap();
    let room = upgraded.mls_room_snapshot(WIRE).unwrap().unwrap();
    assert_eq!(room.version, base);
    assert_eq!(room.sealed_snapshot, b"projected");
    upgraded
        .issue_mls_invite(&f.creator, &f.invite(), NOW)
        .unwrap();
}

#[test]
fn upgrading_v14_does_not_backfill_and_a_legacy_gap_cannot_serve_old_steps() {
    let (f, mut store, base) = Fixture::new();
    let members = std::slice::from_ref(&f.creator);
    let version = store
        .commit_mls_room_candidate(f.change(base, members, b"pre-v15 commit"))
        .unwrap();
    remove_group_transfer_schema_for_legacy_fixture(&store);
    remove_contact_binding_schema_for_legacy_fixture(&store);
    store
        .connection
        .execute_batch(
            "DROP TABLE mls_sync_log;
             DELETE FROM schema_migrations WHERE version>=15;",
        )
        .unwrap();
    drop(store);

    let mut store = open_store(&f.path).unwrap();
    assert_eq!(commit_count(&store), 1);
    assert_eq!(sync_count(&store), 0);
    let tx = store.connection.transaction().unwrap();
    let version = commit_candidate(
        &tx,
        f.sync_change(version, members, b"authenticated commit"),
        None,
        NOW as i64,
    )
    .unwrap();
    tx.commit().unwrap();
    assert!(store.mls_sync_step(WIRE, 0, NOW).unwrap().is_none());
    assert!(store.mls_sync_step(WIRE, 1, NOW).unwrap().is_some());

    store
        .commit_mls_room_candidate(f.change(version, members, b"legacy gap"))
        .unwrap();
    assert!(store.mls_sync_step(WIRE, 1, NOW).unwrap().is_none());
    assert!(store.mls_sync_step(WIRE, 2, NOW).unwrap().is_none());
}

#[test]
fn sync_lookup_keeps_only_the_latest_256_base_epochs() {
    let (f, mut store, mut version) = Fixture::new();
    let members = std::slice::from_ref(&f.creator);
    let tx = store.connection.transaction().unwrap();
    for epoch in 0_u64..257 {
        version = commit_candidate(
            &tx,
            f.sync_change(version, members, &epoch.to_be_bytes()),
            None,
            NOW as i64,
        )
        .unwrap();
    }
    tx.commit().unwrap();

    assert_eq!(sync_count(&store), 256);
    assert_eq!(commit_count(&store), 257);
    assert!(store.mls_sync_step(WIRE, 0, NOW).unwrap().is_none());
    assert!(store.mls_sync_step(WIRE, 257, NOW).unwrap().is_none());
    let oldest = store.mls_sync_step(WIRE, 1, NOW).unwrap().unwrap();
    assert_eq!(oldest.commit, 1_u64.to_be_bytes());
    assert_eq!(oldest.version, version);
    assert_eq!(oldest.bindings, bindings(1));
    assert!(store.mls_sync_step(WIRE, 256, NOW).unwrap().is_some());
    assert!(
        store
            .mls_sync_step(Hash32([9; 32]), 1, NOW)
            .unwrap()
            .is_none()
    );

    let verify = |step: &MlsSyncStoredStep| {
        let digest = |bytes: &[u8]| {
            step.bindings.digest(
                &LOCAL,
                WIRE,
                &f.creator,
                (step.base_epoch, NOW + MLS_SYNC_RETENTION_MS),
                &f.creator,
                bytes,
            )
        };
        Ok(digest(&step.commit) == digest(&step.base_epoch.to_be_bytes()))
    };
    let verified = || {
        super::sync_log::read_step(
            &store.connection,
            WIRE,
            1,
            Some(bindings(256).next),
            || Ok(NOW),
            verify,
        )
        .unwrap()
    };
    assert_eq!(verified(), Some(oldest));
    let reads = std::cell::Cell::new(0);
    let visited = std::cell::Cell::new(0);
    let result = super::sync_log::read_step(
        &store.connection,
        WIRE,
        1,
        Some(bindings(256).next),
        || {
            let count = reads.get() + 1;
            reads.set(count);
            if count == 3 {
                Err(AslError::ExpiredMessage)
            } else {
                Ok(NOW)
            }
        },
        |step| {
            visited.set(visited.get() + 1);
            verify(step)
        },
    );
    assert!(matches!(result, Err(AslError::ExpiredMessage)));
    assert_eq!(visited.get(), 1);
    store
        .connection
        .execute(
            "UPDATE group_events SET ciphertext=zeroblob(8) WHERE mls_epoch=256",
            [],
        )
        .unwrap();
    assert!(verified().is_none());

    store
        .connection
        .execute(
            "UPDATE mls_sync_log SET base_binding=zeroblob(32) WHERE base_epoch=2",
            [],
        )
        .unwrap();
    assert!(store.mls_sync_step(WIRE, 1, NOW).unwrap().is_none());
    assert!(store.mls_sync_step(WIRE, 3, NOW).unwrap().is_some());
}

#[test]
fn cleanup_removes_expired_ciphertext_in_batches_and_preserves_the_live_head() {
    let (f, mut store, mut version) = Fixture::new();
    let members = std::slice::from_ref(&f.creator);
    let tx = store.connection.transaction().unwrap();
    for epoch in 0_u64..258 {
        let created = if epoch == 257 { NOW + 1 } else { NOW };
        version = commit_candidate(
            &tx,
            f.sync_change(version, members, &epoch.to_be_bytes()),
            None,
            created as i64,
        )
        .unwrap();
    }
    tx.commit().unwrap();
    let cutoff = NOW + MLS_SYNC_RETENTION_MS;
    store.prune_mls_expired(cutoff).unwrap();
    assert_eq!(commit_count(&store), 2);
    store.prune_mls_expired(cutoff).unwrap();
    assert_eq!(commit_count(&store), 1);
    assert_eq!(sync_count(&store), 1);
    let head = store.mls_sync_step(WIRE, 257, cutoff).unwrap().unwrap();
    assert_eq!(head.version, version);
    assert_eq!(head.expires_at_ms, cutoff + 1);
    assert!(store.mls_sync_step(WIRE, 256, cutoff).unwrap().is_none());
}

#[test]
fn expired_invite_does_not_unconsume_a_key_package() {
    let (f, mut store, base) = Fixture::new();
    let first = f.invite();
    let packet = f.request(&first);
    let request = f.authenticate(&packet);
    store.issue_mls_invite(&f.creator, &first, NOW).unwrap();
    let roster = [f.creator.clone(), f.target.clone()];
    let added = store
        .commit_mls_invite_welcome(
            &request,
            f.change(base, &roster, b"add"),
            b"welcome".to_vec(),
            NOW,
        )
        .unwrap();
    let removed = store
        .commit_mls_room_candidate(f.change(added, std::slice::from_ref(&f.creator), b"remove"))
        .unwrap();
    let second = GroupPacket {
        message_id: Id128([10; 16]),
        epoch: removed.mls_epoch,
        body: GroupBody::Membership(GroupMembership::Invite {
            agent: TARGET,
            device: f.target.clone(),
            expires_at_ms: EXPIRES + 1_000,
        }),
        ..first
    };
    store
        .issue_mls_invite(&f.creator, &second, EXPIRES)
        .unwrap();
    let packet = f.request(&second);
    let reused = f.authenticate(&packet);
    assert!(
        store
            .mls_invite_response(&reused, EXPIRES)
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .commit_mls_invite_welcome(
                &reused,
                f.change(removed, &roster, b"no add"),
                b"welcome".to_vec(),
                EXPIRES,
            )
            .is_err()
    );
    let fresh = MlsWelcomeRequest {
        package_ref: Hash32([11; 32]),
        ..reused
    };
    assert_eq!(
        store.mls_invite_response(&fresh, EXPIRES).unwrap(),
        Some(MlsInviteResponse::Pending)
    );
    store
        .prune_mls_expired(reused.package_expires_at_ms)
        .unwrap();
    let count: u32 = store
        .connection
        .query_row(
            "SELECT count(*) FROM mls_consumed_key_packages",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
}
