use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId},
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use super::transition::peer_text;
use crate::{Store, database_error};

pub const GROUP_INVITE_REQUEST_TTL_MS: u64 = 5 * 60 * 1_000;
const GROUP_INVITE_REQUEST_WINDOW_MS: i64 = 60 * 60 * 1_000;
const MAX_PENDING_REQUESTS_PER_GROUP: i64 = 32;
const MAX_REQUESTS_PER_AGENT_HOUR: i64 = 5;
const MAX_REQUESTS_GLOBAL_HOUR: i64 = 64;
const LIST_LIMIT: usize = 100;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupInviteRequest {
    pub request_id: Id128,
    pub wire_id: Hash32,
    pub requester: AgentId,
    pub device: PeerId,
    pub mls_epoch: u64,
    pub expires_at_ms: u64,
    pub created_at_ms: u64,
}

pub struct GroupInviteRequestInput<'a> {
    pub local_creator: &'a PeerId,
    pub wire_id: Hash32,
    pub mls_epoch: u64,
    pub requester: AgentId,
    pub device: &'a PeerId,
    pub expires_at_ms: u64,
    pub now_ms: u64,
}

impl Store {
    /// Records a request only for an active room owned by the local device.
    /// Existing active members produce `None`; this record never grants access.
    pub fn record_group_invite_request(
        &mut self,
        request: GroupInviteRequestInput<'_>,
    ) -> Result<Option<GroupInviteRequest>, AslError> {
        let GroupInviteRequestInput {
            local_creator,
            wire_id,
            mls_epoch,
            requester,
            device,
            expires_at_ms,
            now_ms,
        } = request;
        let now = i64::try_from(now_ms).map_err(|_| AslError::InvalidMessage)?;
        let expires = i64::try_from(expires_at_ms).map_err(|_| AslError::InvalidMessage)?;
        if requester.0 == [0; 32]
            || device == local_creator
            || !(1..=GROUP_INVITE_REQUEST_TTL_MS).contains(&expires_at_ms.saturating_sub(now_ms))
            || mls_epoch > i64::MAX as u64
        {
            return Err(AslError::InvalidMessage);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let owner_matches: bool = tx
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM mls_room_states s JOIN asl_groups g ON g.group_id=s.local_group_id
                    WHERE s.wire_group_id=?1 AND g.creator_peer_id=?2 AND g.state='active'
                      AND g.mls_epoch=?3
                )",
                params![
                    wire_id.as_bytes(),
                    peer_text(local_creator),
                    i64::try_from(mls_epoch).map_err(|_| AslError::InvalidMessage)?
                ],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if !owner_matches {
            return Err(AslError::PolicyDenied);
        }
        prune(&tx, now)?;
        let local_id: String = tx
            .query_row(
                "SELECT local_group_id FROM mls_room_states WHERE wire_group_id=?1",
                [wire_id.as_bytes()],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        let already_member: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM group_members
                 WHERE group_id=?1 AND peer_id=?2 AND state='active')",
                params![local_id, peer_text(device)],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if already_member {
            tx.commit().map_err(database_error)?;
            return Ok(None);
        }
        let agent_text = bs58::encode(requester.as_bytes()).into_string();
        let device_text = peer_text(device);
        if query_request(
            &tx,
            "WHERE r.group_id=?1 AND r.requester_peer_id=?2
               AND r.state IN ('pending','rejected') AND r.expires_at_ms>?3",
            params![local_id, device_text, now],
        )?
        .is_some()
        {
            tx.commit().map_err(database_error)?;
            return Ok(None);
        }
        let pending: i64 = tx
            .query_row(
                "SELECT count(*) FROM group_invite_requests
                 WHERE group_id=?1 AND state='pending' AND expires_at_ms>?2",
                params![local_id, now],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        let per_agent: i64 = tx
            .query_row(
                "SELECT count(*) FROM group_invite_requests
                 WHERE requester_agent_id=?1 AND created_at_ms>?2",
                params![agent_text, now - GROUP_INVITE_REQUEST_WINDOW_MS],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        let global: i64 = tx
            .query_row(
                "SELECT count(*) FROM group_invite_requests WHERE created_at_ms>?1",
                [now - GROUP_INVITE_REQUEST_WINDOW_MS],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if pending >= MAX_PENDING_REQUESTS_PER_GROUP
            || per_agent >= MAX_REQUESTS_PER_AGENT_HOUR
            || global >= MAX_REQUESTS_GLOBAL_HOUR
        {
            return Err(AslError::QuotaExceeded);
        }
        let mut request_bytes = rand::random::<[u8; 16]>();
        if request_bytes == [0; 16] {
            request_bytes[0] = 1;
        }
        let request_id = Id128(request_bytes);
        tx.execute(
            "INSERT INTO group_invite_requests(
                request_id,group_id,requester_agent_id,requester_peer_id,mls_epoch,
                expires_at_ms,created_at_ms,state)
             VALUES (?1,?2,?3,?4,?5,?6,?7,'pending')",
            params![
                hex::encode(request_id.0),
                local_id,
                agent_text,
                device_text,
                i64::try_from(mls_epoch).map_err(|_| AslError::InvalidMessage)?,
                expires,
                now
            ],
        )
        .map_err(database_error)?;
        let request = GroupInviteRequest {
            request_id,
            wire_id,
            requester,
            device: device.clone(),
            mls_epoch,
            expires_at_ms,
            created_at_ms: now_ms,
        };
        tx.commit().map_err(database_error)?;
        Ok(Some(request))
    }

    pub fn list_group_invite_requests(
        &self,
        local_creator: &PeerId,
        now_ms: u64,
        limit: u32,
    ) -> Result<Vec<GroupInviteRequest>, AslError> {
        let now = i64::try_from(now_ms).map_err(|_| AslError::InvalidMessage)?;
        if limit == 0 || limit as usize > LIST_LIMIT {
            return Err(AslError::InvalidMessage);
        }
        let mut statement = self
            .connection
            .prepare(
                "SELECT lower(hex(s.wire_group_id)),r.requester_agent_id,r.requester_peer_id,
                        r.mls_epoch,r.expires_at_ms,r.created_at_ms,r.request_id
                 FROM group_invite_requests r
                 JOIN asl_groups g ON g.group_id=r.group_id
                 JOIN mls_room_states s ON s.local_group_id=g.group_id
                 WHERE g.creator_peer_id=?1 AND g.state='active'
                   AND r.state='pending' AND r.expires_at_ms>?2
                 ORDER BY r.created_at_ms,r.request_id LIMIT ?3",
            )
            .map_err(database_error)?;
        let rows = statement
            .query_map(
                params![peer_text(local_creator), now, i64::from(limit)],
                read_request,
            )
            .map_err(database_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(database_error)?;
        drop(statement);
        Ok(rows)
    }

    pub fn finish_group_invite_request(
        &mut self,
        wire_id: Hash32,
        device: &PeerId,
        approved: bool,
        now_ms: u64,
    ) -> Result<bool, AslError> {
        let now = i64::try_from(now_ms).map_err(|_| AslError::InvalidMessage)?;
        let rejected_until = now.saturating_add(60 * 60 * 1_000);
        let changed = self
            .connection
            .execute(
                "UPDATE group_invite_requests
                 SET state=?3,
                     expires_at_ms=CASE
                       WHEN ?3='rejected' AND expires_at_ms<?4 THEN ?4
                       ELSE expires_at_ms
                     END
                 WHERE state='pending' AND requester_peer_id=?2
                   AND group_id=(SELECT local_group_id FROM mls_room_states
                                 WHERE wire_group_id=?1)",
                params![
                    wire_id.as_bytes(),
                    peer_text(device),
                    if approved { "approved" } else { "rejected" },
                    rejected_until
                ],
            )
            .map_err(database_error)?;
        if changed != 0 {
            self.connection
                .execute(
                    "DELETE FROM group_invite_requests WHERE created_at_ms<=?1",
                    [now - 24 * 60 * 60 * 1_000],
                )
                .map_err(database_error)?;
        }
        Ok(changed != 0)
    }

    pub fn prune_expired_group_invite_requests(&mut self, now_ms: u64) -> Result<usize, AslError> {
        let now = i64::try_from(now_ms).map_err(|_| AslError::InvalidMessage)?;
        let expired = self
            .connection
            .execute(
                "UPDATE group_invite_requests SET state='expired'
                 WHERE state='pending' AND expires_at_ms<=?1",
                [now],
            )
            .map_err(database_error)?;
        self.connection
            .execute(
                "DELETE FROM group_invite_requests WHERE created_at_ms<=?1",
                [now - 24 * 60 * 60 * 1_000],
            )
            .map_err(database_error)?;
        Ok(expired)
    }
}

fn prune(tx: &rusqlite::Transaction<'_>, now: i64) -> Result<(), AslError> {
    tx.execute(
        "UPDATE group_invite_requests SET state='expired'
         WHERE state='pending' AND expires_at_ms<=?1",
        [now],
    )
    .map_err(database_error)?;
    tx.execute(
        "DELETE FROM group_invite_requests WHERE created_at_ms<=?1",
        [now - 24 * 60 * 60 * 1_000],
    )
    .map_err(database_error)?;
    Ok(())
}

fn query_request(
    tx: &rusqlite::Transaction<'_>,
    suffix: &str,
    params: impl rusqlite::Params,
) -> Result<Option<GroupInviteRequest>, AslError> {
    tx.query_row(
        &format!(
            "SELECT lower(hex(s.wire_group_id)),r.requester_agent_id,r.requester_peer_id,
                    r.mls_epoch,r.expires_at_ms,r.created_at_ms,r.request_id
             FROM group_invite_requests r
             JOIN mls_room_states s ON s.local_group_id=r.group_id {suffix}"
        ),
        params,
        read_request,
    )
    .optional()
    .map_err(database_error)
}

fn read_request(row: &rusqlite::Row<'_>) -> rusqlite::Result<GroupInviteRequest> {
    let wire = hex::decode(row.get::<_, String>(0)?)
        .ok()
        .and_then(|value| value.try_into().ok())
        .ok_or(rusqlite::Error::InvalidQuery)?;
    let requester = bs58::decode(row.get::<_, String>(1)?)
        .into_vec()
        .ok()
        .and_then(|value| value.try_into().ok())
        .ok_or(rusqlite::Error::InvalidQuery)?;
    let device = bs58::decode(row.get::<_, String>(2)?)
        .into_vec()
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let request_id = hex::decode(row.get::<_, String>(6)?)
        .ok()
        .and_then(|value| value.try_into().ok())
        .ok_or(rusqlite::Error::InvalidQuery)?;
    Ok(GroupInviteRequest {
        request_id: Id128(request_id),
        wire_id: Hash32(wire),
        requester: AgentId(requester),
        device: PeerId::from_bytes(device).map_err(|_| rusqlite::Error::InvalidQuery)?,
        mls_epoch: u64::try_from(row.get::<_, i64>(3)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        expires_at_ms: u64::try_from(row.get::<_, i64>(4)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        created_at_ms: u64::try_from(row.get::<_, i64>(5)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
    })
}

#[cfg(test)]
mod tests {
    use asl_types::{ids::Id128, task::GroupId};
    use rusqlite::params;

    use super::*;
    use crate::{group_state::PendingMlsRoom, open_store};

    fn peer(seed: u8) -> PeerId {
        let mut bytes = [0; 32];
        bytes[0] = seed;
        let key = libp2p_identity::Keypair::ed25519_from_bytes(bytes).unwrap();
        PeerId::from_bytes(key.public().to_peer_id().to_bytes()).unwrap()
    }

    fn register(store: &Store, agent: AgentId, device: &PeerId) {
        let agent = bs58::encode(agent.as_bytes()).into_string();
        let device = peer_text(device);
        store
            .connection
            .execute(
                "INSERT OR IGNORE INTO agents(agent_id) VALUES (?1)",
                [&agent],
            )
            .unwrap();
        store
            .connection
            .execute(
                "INSERT INTO device_identities VALUES (?1,?2,printf('%064x',0),X'',1,1,NULL,0)",
                params![device, agent],
            )
            .unwrap();
        store
            .connection
            .execute(
                "INSERT INTO peers(peer_id,agent_id) VALUES (?1,?2)",
                params![device, agent],
            )
            .unwrap();
    }

    fn room(store: &mut Store) -> (PeerId, Hash32, GroupId) {
        let owner = peer(1);
        let owner_agent = AgentId([1; 32]);
        register(store, owner_agent, &owner);
        let wire = Hash32([2; 32]);
        let local = GroupId(Id128([3; 16]));
        store
            .stage_mls_room(PendingMlsRoom {
                local_id: &local,
                wire_id: wire,
                creator: &owner,
                local_name: "Invite request",
                mls_epoch: 5,
                sealed_snapshot: b"sealed",
            })
            .unwrap();
        store
            .connection
            .execute("UPDATE asl_groups SET state='active'", [])
            .unwrap();
        (owner, wire, local)
    }

    fn input<'a>(
        local_creator: &'a PeerId,
        wire_id: Hash32,
        mls_epoch: u64,
        requester: AgentId,
        device: &'a PeerId,
        expires_at_ms: u64,
        now_ms: u64,
    ) -> GroupInviteRequestInput<'a> {
        GroupInviteRequestInput {
            local_creator,
            wire_id,
            mls_epoch,
            requester,
            device,
            expires_at_ms,
            now_ms,
        }
    }

    #[test]
    fn records_lists_deduplicates_and_finishes_owner_requests() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = open_store(&directory.path().join("requests.sqlite3")).unwrap();
        let (owner, wire, local) = room(&mut store);
        let requester = AgentId([4; 32]);
        let device = peer(4);
        register(&store, requester, &device);
        let first = store
            .record_group_invite_request(input(
                &owner,
                wire,
                5,
                requester,
                &device,
                10_000 + GROUP_INVITE_REQUEST_TTL_MS,
                10_000,
            ))
            .unwrap()
            .unwrap();
        let duplicate = store
            .record_group_invite_request(input(
                &owner,
                wire,
                5,
                requester,
                &device,
                20_000 + GROUP_INVITE_REQUEST_TTL_MS,
                20_000,
            ))
            .unwrap();
        assert!(duplicate.is_none());
        let listed = store
            .list_group_invite_requests(&owner, 21_000, 10)
            .unwrap();
        assert_eq!(listed, vec![first]);
        assert!(
            store
                .finish_group_invite_request(wire, &device, true, 21_000)
                .unwrap()
        );
        assert!(
            store
                .list_group_invite_requests(&owner, 21_000, 10)
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .mls_room_progress(wire)
                .unwrap()
                .is_some_and(|(state, epoch)| state == "active" && epoch == 5)
        );
        let count: i64 = store
            .connection
            .query_row(
                "SELECT count(*) FROM group_invite_requests WHERE group_id=?1",
                [hex::encode(local.0.0)],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);

        let rejected_requester = AgentId([5; 32]);
        let rejected_device = peer(5);
        register(&store, rejected_requester, &rejected_device);
        let rejected = store
            .record_group_invite_request(input(
                &owner,
                wire,
                5,
                rejected_requester,
                &rejected_device,
                30_000 + GROUP_INVITE_REQUEST_TTL_MS,
                30_000,
            ))
            .unwrap()
            .unwrap();
        assert!(
            store
                .finish_group_invite_request(wire, &rejected_device, false, 30_001)
                .unwrap()
        );
        let state: String = store
            .connection
            .query_row(
                "SELECT state FROM group_invite_requests WHERE request_id=?1",
                [hex::encode(rejected.request_id.0)],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "rejected");
        assert!(
            store
                .record_group_invite_request(input(
                    &owner,
                    wire,
                    5,
                    rejected_requester,
                    &rejected_device,
                    30_002 + GROUP_INVITE_REQUEST_TTL_MS,
                    30_002,
                ))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn rejects_non_owners_members_bad_epochs_and_expiry() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = open_store(&directory.path().join("requests.sqlite3")).unwrap();
        let (owner, wire, local) = room(&mut store);
        let requester = AgentId([4; 32]);
        let device = peer(4);
        register(&store, requester, &device);
        assert!(matches!(
            store.record_group_invite_request(input(
                &peer(9),
                wire,
                5,
                requester,
                &device,
                10_000 + GROUP_INVITE_REQUEST_TTL_MS,
                10_000,
            )),
            Err(AslError::PolicyDenied)
        ));
        assert!(matches!(
            store.record_group_invite_request(input(
                &owner,
                wire,
                4,
                requester,
                &device,
                10_000 + GROUP_INVITE_REQUEST_TTL_MS,
                10_000,
            )),
            Err(AslError::PolicyDenied)
        ));
        assert!(matches!(
            store.record_group_invite_request(input(
                &owner, wire, 5, requester, &device, 10_000, 10_000
            )),
            Err(AslError::InvalidMessage)
        ));
        store
            .connection
            .execute(
                "INSERT INTO group_members(group_id,peer_id,role,state,joined_at_ms)
                 VALUES (?1,?2,'member','active',10000)",
                params![hex::encode(local.0.0), peer_text(&device)],
            )
            .unwrap();
        assert!(
            store
                .record_group_invite_request(input(
                    &owner,
                    wire,
                    5,
                    requester,
                    &device,
                    10_000 + GROUP_INVITE_REQUEST_TTL_MS,
                    10_000,
                ))
                .unwrap()
                .is_none()
        );
    }
}
