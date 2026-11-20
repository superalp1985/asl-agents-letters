//! Durable MLS state and member projection. A saved room does not authorize
//! access until Core reconciles it with live chain and policy state.

mod invite;
#[cfg(test)]
mod invite_tests;
mod outgoing;
#[cfg(test)]
mod outgoing_tests;
mod recovery;
#[cfg(test)]
mod recovery_tests;
mod sync_authority;
mod sync_log;
mod transition;

pub use invite::{MlsIncomingInvite, MlsInviteEndpoints, MlsJoinKey, MlsJoinedRoom};
pub use outgoing::{MlsInviteResponse, MlsWelcomeRequest};
pub use recovery::{MlsMemberEvidence, MlsRoomRecovery};
pub use sync_authority::{MlsRemoveAuthority, MlsSyncAddAuthority, MlsSyncReadAuthority};
pub use sync_log::{
    MLS_SYNC_MAX_STEPS, MLS_SYNC_RETENTION_MS, MlsEpochBindings, MlsSyncStoredStep,
};
pub use transition::{MlsJournalEntry, MlsJournalKind, MlsRoomUpdate, RoomVersion};

use std::{path::Path, time::Duration};

use asl_types::{
    error::AslError,
    ids::{Hash32, Id128, PeerId},
    task::GroupId,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::{Store, current_time_ms, database_error};

pub const MAX_SEALED_ROOM_BYTES: usize = 2 * 1024 * 1024;

/// The dedicated group writer is used on the Net event pump. Its lock wait
/// must not consume the Core/Net heartbeat budget.
pub fn open_mls_runtime_store(path: &Path) -> Result<Store, AslError> {
    let store = crate::open_store(path)?;
    store
        .connection
        .busy_timeout(Duration::from_millis(25))
        .map_err(database_error)?;
    Ok(store)
}

pub struct PendingMlsRoom<'a> {
    pub local_id: &'a GroupId,
    pub wire_id: Hash32,
    pub creator: &'a PeerId,
    pub local_name: &'a str,
    pub mls_epoch: u64,
    pub sealed_snapshot: &'a [u8],
}

pub struct MlsRoomSnapshot {
    pub local_id: GroupId,
    pub sealed_snapshot: Vec<u8>,
    pub version: RoomVersion,
}

impl Store {
    /// A trusted caller may stage a new room. Do not attach a network
    /// identifier to an existing grant key or activate the room here.
    pub fn stage_mls_room(&mut self, room: PendingMlsRoom<'_>) -> Result<(), AslError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        insert_mls_room(&tx, &room, current_time_ms())?;
        tx.commit().map_err(database_error)
    }

    /// Create a local epoch-zero room and its creator projection together.
    /// The sealed snapshot starts at revision one, and the room stays paused.
    pub fn create_mls_room(
        &mut self,
        room: PendingMlsRoom<'_>,
        creator: &MlsMemberEvidence,
        chain_id: u64,
        expected_policy_revision: u64,
        now_ms: u64,
    ) -> Result<RoomVersion, AslError> {
        if room.mls_epoch != 0 || room.creator != &creator.certificate.peer_id {
            return Err(AslError::InvalidPolicyState);
        }
        let expected = sql_number(expected_policy_revision)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let revision: i64 = tx
            .query_row(
                "SELECT revision FROM policy_state WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if revision != expected {
            return Err(AslError::PolicyVersionConflict);
        }

        creator.register(&tx, chain_id, now_ms)?;
        let now = sql_number(now_ms)?;
        insert_mls_room(&tx, &room, now)?;
        tx.execute(
            "INSERT INTO group_members(group_id,peer_id,role,state,joined_at_ms)
             VALUES (?1,?2,'creator','active',?3)",
            params![
                hex::encode(room.local_id.0.as_bytes()),
                transition::peer_text(room.creator),
                now,
            ],
        )
        .map_err(database_error)?;
        tx.commit().map_err(database_error)?;
        Ok(RoomVersion {
            revision: 1,
            mls_epoch: 0,
            membership_epoch: 1,
            policy_revision: expected_policy_revision,
        })
    }

    /// This is only a storage lookup. Core must authenticate the sealed
    /// contents and reconcile the membership projection before use.
    pub fn mls_room_snapshot(&self, wire_id: Hash32) -> Result<Option<MlsRoomSnapshot>, AslError> {
        Ok(read_mls_room_snapshot(&self.connection, wire_id, false)?.map(|(snapshot, _)| snapshot))
    }

    pub fn mls_room_progress(&self, wire_id: Hash32) -> Result<Option<(String, u64)>, AslError> {
        self.connection
            .query_row(
                "SELECT g.state,g.mls_epoch FROM mls_room_states s
                 JOIN asl_groups g ON g.group_id=s.local_group_id WHERE s.wire_group_id=?1",
                [wire_id.as_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(database_error)?
            .map(|(state, epoch)| Ok((state, unsigned(epoch)?)))
            .transpose()
    }
}

fn read_mls_room_snapshot(
    connection: &Connection,
    wire_id: Hash32,
    paused_only: bool,
) -> Result<Option<(MlsRoomSnapshot, String)>, AslError> {
    connection
        .query_row(
            "SELECT s.local_group_id,s.sealed_snapshot,s.revision,g.mls_epoch,g.membership_epoch,
                    p.revision,g.creator_peer_id
             FROM mls_room_states s JOIN asl_groups g ON g.group_id=s.local_group_id
             CROSS JOIN policy_state p WHERE s.wire_group_id=?1 AND p.singleton=1
               AND (NOT ?2 OR g.state='needs_sync')",
            params![wire_id.as_bytes(), paused_only],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .optional()
        .map_err(database_error)?
        .map(
            |(id, sealed_snapshot, revision, epoch, membership, policy, creator)| {
                let mut bytes = [0; 16];
                hex::decode_to_slice(id, &mut bytes).map_err(|_| AslError::InvalidDatabase)?;
                Ok((
                    MlsRoomSnapshot {
                        local_id: GroupId(Id128(bytes)),
                        sealed_snapshot,
                        version: RoomVersion {
                            revision: unsigned(revision)?,
                            mls_epoch: unsigned(epoch)?,
                            membership_epoch: unsigned(membership)?,
                            policy_revision: unsigned(policy)?,
                        },
                    },
                    creator,
                ))
            },
        )
        .transpose()
}

fn insert_mls_room(
    tx: &rusqlite::Transaction<'_>,
    room: &PendingMlsRoom<'_>,
    now: i64,
) -> Result<(), AslError> {
    if *room.local_id.0.as_bytes() == [0; 16]
        || room.wire_id.0 == [0; 32]
        || !(1..=MAX_SEALED_ROOM_BYTES).contains(&room.sealed_snapshot.len())
    {
        return Err(AslError::InvalidPolicyState);
    }
    let local_id = hex::encode(room.local_id.0.as_bytes());
    let creator = bs58::encode(room.creator.as_bytes()).into_string();
    tx.execute(
        "INSERT INTO asl_groups(group_id,creator_peer_id,local_name,mls_epoch,state,created_at_ms,updated_at_ms)
         VALUES (?1,?2,?3,?4,'needs_sync',?5,?5)",
        params![local_id, creator, room.local_name, sql_number(room.mls_epoch)?, now],
    )
    .map_err(database_error)?;
    tx.execute(
        "INSERT INTO mls_room_states(local_group_id,wire_group_id,sealed_snapshot)
         VALUES (?1,?2,?3)",
        params![local_id, room.wire_id.as_bytes(), room.sealed_snapshot],
    )
    .map_err(database_error)?;
    invite::close_room_invites(tx, room.wire_id)?;
    Ok(())
}

fn sql_number(value: u64) -> Result<i64, AslError> {
    i64::try_from(value).map_err(|_| AslError::InvalidPolicyState)
}

fn unsigned(value: i64) -> Result<u64, AslError> {
    u64::try_from(value).map_err(|_| AslError::InvalidDatabase)
}

#[cfg(test)]
mod tests {
    use super::*;
    use asl_types::ids::AgentId;

    pub(super) fn test_peer(seed: u8) -> PeerId {
        let key = libp2p_identity::Keypair::ed25519_from_bytes([seed; 32]).unwrap();
        PeerId::from_bytes(key.public().to_peer_id().to_bytes()).unwrap()
    }

    pub(super) fn register_peer(store: &Store, peer: &PeerId, serial: i64) {
        register_agent_peer(store, AgentId([1; 32]), peer, serial);
    }

    pub(super) fn register_agent_peer(store: &Store, agent: AgentId, peer: &PeerId, serial: i64) {
        let agent_text = bs58::encode(agent.0).into_string();
        let peer_text = bs58::encode(peer.as_bytes()).into_string();
        store
            .connection
            .execute(
                "INSERT OR IGNORE INTO agents(agent_id) VALUES (?1)",
                [&agent_text],
            )
            .unwrap();
        store
            .connection
            .execute(
                "INSERT INTO device_identities VALUES (?1,?2,printf('%064x',0),X'',?3,1,NULL,0)",
                params![peer_text, agent_text, serial],
            )
            .unwrap();
        store
            .connection
            .execute(
                "INSERT INTO peers(peer_id,agent_id) VALUES (?1,?2)",
                params![peer_text, agent_text],
            )
            .unwrap();
    }

    #[test]
    fn room_mapping_reopens_without_granting_membership_or_rebinding_ids() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("rooms.sqlite3");
        let mut store = crate::open_store(&path).unwrap();
        let peer = test_peer(2);
        register_peer(&store, &peer, 1);
        let first = GroupId(Id128([3; 16]));
        let second = GroupId(Id128([4; 16]));
        let wire_a = Hash32([3; 32]);
        let mut wire_b = wire_a;
        wire_b.0[31] = 4;
        let stage = |store: &mut Store, local_id, wire_id| {
            store.stage_mls_room(PendingMlsRoom {
                local_id,
                wire_id,
                creator: &peer,
                local_name: "Local label",
                mls_epoch: 0,
                sealed_snapshot: b"test opaque snapshot",
            })
        };
        stage(&mut store, &first, wire_a).unwrap();
        assert!(stage(&mut store, &second, wire_a).is_err());
        assert!(stage(&mut store, &first, wire_b).is_err());
        // The failed duplicate wire ID did not leave a room or reserve its key.
        stage(&mut store, &second, wire_b).unwrap();
        drop(store);

        let store = crate::open_store(&path).unwrap();
        for (id, wire) in [(first, wire_a), (second, wire_b)] {
            let entry = store.mls_room_snapshot(wire).unwrap().unwrap();
            assert_eq!(entry.local_id, id);
            assert_eq!(entry.version.revision, 1);
            assert_eq!(entry.sealed_snapshot, b"test opaque snapshot");
        }
        let count = |sql| {
            store
                .connection
                .query_row(sql, [], |r| r.get::<_, u32>(0))
                .unwrap()
        };
        assert_eq!(
            count("SELECT COUNT(*) FROM asl_groups WHERE state='needs_sync'"),
            2
        );
        assert_eq!(count("SELECT COUNT(*) FROM group_members"), 0);
        assert_eq!(store.policy_revision().unwrap(), 1);
    }

    #[test]
    fn paused_room_commits_snapshot_roster_and_authenticated_replay_keys_together() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("rooms.sqlite3");
        let mut store = crate::open_store(&path).unwrap();
        let creator = test_peer(1);
        let member = test_peer(2);
        let unknown = test_peer(3);
        register_peer(&store, &creator, 1);
        register_peer(&store, &member, 2);
        let local_id = GroupId(Id128([4; 16]));
        let wire_id = Hash32([9; 32]);
        store
            .stage_mls_room(PendingMlsRoom {
                local_id: &local_id,
                wire_id,
                creator: &creator,
                local_name: "Paused",
                mls_epoch: 4,
                sealed_snapshot: b"sealed initial",
            })
            .unwrap();
        let base = store.mls_room_snapshot(wire_id).unwrap().unwrap().version;
        let members = [creator.clone(), member.clone()];
        let update = |expected, mls_epoch, members, sealed_snapshot, event| MlsRoomUpdate {
            local_id: &local_id,
            wire_id,
            expected,
            mls_epoch,
            sealed_snapshot,
            members,
            event,
        };
        let initial = store
            .commit_mls_room_candidate(update(base, 4, &members, b"projected", None))
            .unwrap();
        let id = Id128([2; 16]);
        let event = |kind, ciphertext| {
            Some(MlsJournalEntry {
                sender: &creator,
                kind,
                ciphertext,
            })
        };
        let application = store
            .commit_mls_room_candidate(update(
                initial,
                4,
                &members,
                b"new ratchet",
                event(MlsJournalKind::Application(id), b"ciphertext"),
            ))
            .unwrap();
        assert_eq!(application.revision, initial.revision + 1);
        assert_eq!(application.mls_epoch, initial.mls_epoch);
        assert!(matches!(
            store.commit_mls_room_candidate(update(
                application,
                4,
                &members,
                b"replay",
                event(
                    MlsJournalKind::Application(id),
                    b"fresh ciphertext for the same inner ID"
                ),
            )),
            Err(AslError::PolicyVersionConflict)
        ));
        let bogus = [creator.clone(), unknown];
        let remaining = [creator.clone()];
        let commit = || event(MlsJournalKind::Commit, b"commit ciphertext");
        assert!(
            store
                .commit_mls_room_candidate(update(
                    application,
                    5,
                    &bogus,
                    b"invalid roster",
                    commit(),
                ))
                .is_err(),
            "missing peer foreign key must unwind the journal and roster changes"
        );
        let unmodified = store.mls_room_snapshot(wire_id).unwrap().unwrap();
        assert_eq!(unmodified.version, application);
        assert_eq!(unmodified.sealed_snapshot, b"new ratchet");
        let next = store
            .commit_mls_room_candidate(update(application, 5, &remaining, b"new epoch", commit()))
            .unwrap();
        assert!(matches!(
            store
                .commit_mls_room_candidate(update(application, 5, &remaining, b"stale", commit(),)),
            Err(AslError::PolicyVersionConflict)
        ));
        drop(store);

        let store = crate::open_store(&path).unwrap();
        let room = store.mls_room_snapshot(wire_id).unwrap().unwrap();
        assert_eq!(
            room.version,
            RoomVersion {
                revision: 4,
                mls_epoch: 5,
                membership_epoch: 1,
                policy_revision: 1
            }
        );
        assert_eq!(room.version, next);
        assert_eq!(room.sealed_snapshot, b"new epoch");
        let count = |sql| {
            store
                .connection
                .query_row(sql, [], |r| r.get::<_, i64>(0))
                .unwrap()
        };
        assert_eq!(count("SELECT COUNT(*) FROM group_events"), 2);
        assert_eq!(
            count("SELECT COUNT(*) FROM group_members WHERE state='active'"),
            1
        );
        assert_eq!(
            count("SELECT COUNT(*) FROM group_members WHERE state='removed'"),
            1
        );
        assert_eq!(
            count("SELECT COUNT(*) FROM asl_groups WHERE state='active'"),
            0
        );
    }
}
