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
    MlsRoomUpdate, MlsSyncStoredStep, MlsWelcomeRequest, PendingMlsRoom, RoomVersion,
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
        let root = tempfile::tempdir().unwrap();
        let fixture = Self {
            path: root.path().join("outgoing.sqlite3"),
            _root: root,
            creator: test_peer(1),
            target: test_peer(2),
            alternate: test_peer(3),
        };
        let mut store = open_store(&fixture.path).unwrap();
        for (peer, agent, serial) in [
            (&fixture.creator, AgentId([1; 32]), 1),
            (&fixture.target, TARGET, 1),
            (&fixture.alternate, TARGET, 2),
        ] {
            register_agent_peer(&store, agent, peer, serial);
        }
        store
            .connection
            .execute(
                "UPDATE device_identities SET certificate_expires_ms=?1",
                [EXPIRES as i64 + 1],
            )
            .unwrap();
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
        (fixture, store, base)
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

#[test]
fn upgrading_v13_keeps_the_existing_mls_snapshot() {
    let (f, store, base) = Fixture::new();
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
    store
        .connection
        .execute_batch(
            "DROP TABLE mls_sync_log;
             DELETE FROM schema_migrations WHERE version=15;",
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
