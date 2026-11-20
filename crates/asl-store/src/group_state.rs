//! Local storage for a room while its MLS state is being established. A saved
//! snapshot is not a membership assertion or a file grant.

use asl_types::{
    error::AslError,
    ids::{Hash32, Id128, PeerId},
    task::GroupId,
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use crate::{Store, current_time_ms, database_error};

pub const MAX_SEALED_ROOM_BYTES: usize = 2 * 1024 * 1024;

pub struct PendingMlsRoom<'a> {
    pub local_id: &'a GroupId,
    pub wire_id: Hash32,
    pub creator: &'a PeerId,
    pub local_name: &'a str,
    pub sealed_snapshot: &'a [u8],
}

pub struct MlsRoomSnapshot {
    pub local_id: GroupId,
    pub sealed_snapshot: Vec<u8>,
    pub revision: u64,
}

impl Store {
    /// A trusted caller may stage a new room. Do not attach a network
    /// identifier to an existing grant key or activate the room here.
    pub fn stage_mls_room(&mut self, room: PendingMlsRoom<'_>) -> Result<(), AslError> {
        if *room.local_id.0.as_bytes() == [0; 16]
            || room.wire_id.0 == [0; 32]
            || room.sealed_snapshot.is_empty()
            || room.sealed_snapshot.len() > MAX_SEALED_ROOM_BYTES
        {
            return Err(AslError::InvalidPolicyState);
        }
        let local_id = hex::encode(room.local_id.0.as_bytes());
        let creator = bs58::encode(room.creator.as_bytes()).into_string();
        let now = current_time_ms();
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        tx.execute(
            "INSERT INTO asl_groups(group_id,creator_peer_id,local_name,state,created_at_ms,updated_at_ms)
             VALUES (?1,?2,?3,'needs_sync',?4,?4)",
            params![local_id, creator, room.local_name, now],
        )
        .map_err(database_error)?;
        tx.execute(
            "INSERT INTO mls_room_states(local_group_id,wire_group_id,sealed_snapshot)
             VALUES (?1,?2,?3)",
            params![local_id, room.wire_id.as_bytes(), room.sealed_snapshot],
        )
        .map_err(database_error)?;
        tx.commit().map_err(database_error)
    }

    /// This is only a storage lookup. Core must authenticate the sealed
    /// contents and reconcile the membership projection before use.
    pub fn mls_room_snapshot(&self, wire_id: Hash32) -> Result<Option<MlsRoomSnapshot>, AslError> {
        self.connection
            .query_row(
                "SELECT local_group_id,sealed_snapshot,revision FROM mls_room_states
                 WHERE wire_group_id=?1",
                [wire_id.as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(database_error)?
            .map(|(id, sealed_snapshot, revision)| {
                let mut bytes = [0; 16];
                hex::decode_to_slice(id, &mut bytes).map_err(|_| AslError::InvalidDatabase)?;
                Ok(MlsRoomSnapshot {
                    local_id: GroupId(Id128(bytes)),
                    sealed_snapshot,
                    revision: u64::try_from(revision).map_err(|_| AslError::InvalidDatabase)?,
                })
            })
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asl_types::ids::AgentId;

    #[test]
    fn room_mapping_reopens_without_granting_membership_or_rebinding_ids() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("rooms.sqlite3");
        let mut store = crate::open_store(&path).unwrap();
        let agent = AgentId([1; 32]);
        let agent_text = bs58::encode(agent.0).into_string();
        let key = libp2p_identity::Keypair::ed25519_from_bytes([2; 32]).unwrap();
        let peer = PeerId::from_bytes(key.public().to_peer_id().to_bytes()).unwrap();
        let peer_text = bs58::encode(peer.as_bytes()).into_string();
        store
            .connection
            .execute("INSERT INTO agents(agent_id) VALUES (?1)", [&agent_text])
            .unwrap();
        store
            .connection
            .execute(
                "INSERT INTO device_identities VALUES (?1,?2,printf('%064x',0),X'',1,1,NULL,0)",
                params![peer_text, agent_text],
            )
            .unwrap();
        store
            .connection
            .execute(
                "INSERT INTO peers(peer_id,agent_id) VALUES (?1,?2)",
                params![peer_text, agent_text],
            )
            .unwrap();
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
            assert_eq!(entry.revision, 1);
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
}
