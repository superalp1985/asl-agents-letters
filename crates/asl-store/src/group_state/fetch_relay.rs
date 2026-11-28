use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId},
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use super::{sql_number, unsigned};
use crate::{Store, chain::agent_text, database_error};

const MAX_FETCH_RELAYS: usize = 1024;
const MAX_FETCH_RELAYS_PER_SOURCE: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FetchRelay {
    pub request_id: Id128,
    pub logical_root: Hash32,
    pub requester_room: Hash32,
    pub source_room: Hash32,
    pub requester_agent: AgentId,
    pub requester_peer: PeerId,
    pub content_id: Hash32,
    pub expires_at_ms: u64,
}

impl Store {
    #[allow(clippy::too_many_arguments)]
    pub fn record_fetch_relay(
        &mut self,
        request_id: Id128,
        logical_root: Hash32,
        requester_room_id: Hash32,
        source_room_id: Hash32,
        requester_agent: AgentId,
        requester_peer: &PeerId,
        content_id: Hash32,
        now_ms: u64,
        expires_at_ms: u64,
    ) -> Result<(), AslError> {
        if request_id.0 == [0; 16]
            || logical_root.0 == [0; 32]
            || requester_room_id.0 == [0; 32]
            || source_room_id.0 == [0; 32]
            || requester_room_id == source_room_id
            || expires_at_ms <= now_ms
        {
            return Err(AslError::InvalidMessage);
        }
        let requester_agent = agent_text(requester_agent);
        let requester_peer = peer_text(requester_peer);
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        tx.execute(
            "DELETE FROM mls_group_fetch_relays WHERE expires_at_ms<=?1",
            [sql_number(now_ms)?],
        )
        .map_err(database_error)?;
        let existing = tx
            .query_row(
                "SELECT logical_root,requester_room,source_room,requester_agent,
                        requester_peer,content_id,expires_at_ms
                 FROM mls_group_fetch_relays WHERE request_id=?1",
                [request_id.as_bytes()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                },
            )
            .optional()
            .map_err(database_error)?;
        if let Some((
            stored_root,
            stored_requester_room,
            stored_source_room,
            agent,
            peer,
            content,
            expires,
        )) = existing
        {
            if stored_root.as_slice() != logical_root.as_bytes()
                || stored_requester_room.as_slice() != requester_room_id.as_bytes()
                || stored_source_room.as_slice() != source_room_id.as_bytes()
                || agent != requester_agent
                || peer != requester_peer
                || content.as_slice() != content_id.as_bytes()
            {
                return Err(AslError::PolicyVersionConflict);
            }
            let refreshed = unsigned(expires)?.max(expires_at_ms);
            tx.execute(
                "UPDATE mls_group_fetch_relays SET expires_at_ms=?2 WHERE request_id=?1",
                params![request_id.as_bytes(), sql_number(refreshed)?],
            )
            .map_err(database_error)?;
            tx.commit().map_err(database_error)?;
            return Ok(());
        }
        let inserted = tx
            .execute(
                "INSERT INTO mls_group_fetch_relays(
                request_id,logical_root,requester_room,source_room,requester_agent,
                requester_peer,content_id,created_at_ms,expires_at_ms)
             SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9
             WHERE (SELECT count(*) FROM mls_group_fetch_relays)<?10
               AND (SELECT count(*) FROM mls_group_fetch_relays WHERE source_room=?4)<?11",
                params![
                    request_id.as_bytes(),
                    logical_root.as_bytes(),
                    requester_room_id.as_bytes(),
                    source_room_id.as_bytes(),
                    requester_agent,
                    requester_peer,
                    content_id.as_bytes(),
                    sql_number(now_ms)?,
                    sql_number(expires_at_ms)?,
                    i64::try_from(MAX_FETCH_RELAYS).map_err(|_| AslError::InvalidMessage)?,
                    i64::try_from(MAX_FETCH_RELAYS_PER_SOURCE)
                        .map_err(|_| AslError::InvalidMessage)?,
                ],
            )
            .map_err(database_error)?;
        if inserted != 1 {
            return Err(AslError::QuotaExceeded);
        }
        tx.commit().map_err(database_error)
    }

    pub fn fetch_relay(
        &self,
        source_room: Hash32,
        request_id: Id128,
        now_ms: u64,
    ) -> Result<Option<FetchRelay>, AslError> {
        self.connection
            .query_row(
                "SELECT logical_root,requester_room,source_room,requester_agent,
                        requester_peer,content_id,expires_at_ms
                 FROM mls_group_fetch_relays
                 WHERE source_room=?1 AND request_id=?2 AND expires_at_ms>?3",
                params![
                    source_room.as_bytes(),
                    request_id.as_bytes(),
                    sql_number(now_ms)?,
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                },
            )
            .optional()
            .map_err(database_error)?
            .map(
                |(
                    logical_root,
                    requester_room,
                    source_room,
                    requester_agent,
                    requester_peer,
                    content_id,
                    expires_at_ms,
                )| {
                    Ok(FetchRelay {
                        request_id,
                        logical_root: hash32(logical_root)?,
                        requester_room: hash32(requester_room)?,
                        source_room: hash32(source_room)?,
                        requester_agent: crate::chain::decode_agent_text(&requester_agent)
                            .map_err(|_| AslError::InvalidDatabase)?,
                        requester_peer: parse_peer(requester_peer)?,
                        content_id: hash32(content_id)?,
                        expires_at_ms: unsigned(expires_at_ms)?,
                    })
                },
            )
            .transpose()
    }

    pub fn prune_fetch_relays(&self, now_ms: u64) -> Result<usize, AslError> {
        self.connection
            .execute(
                "DELETE FROM mls_group_fetch_relays WHERE expires_at_ms<=?1",
                [sql_number(now_ms)?],
            )
            .map_err(database_error)
    }
}

fn hash32(bytes: Vec<u8>) -> Result<Hash32, AslError> {
    Ok(Hash32(
        bytes.try_into().map_err(|_| AslError::InvalidDatabase)?,
    ))
}

fn peer_text(peer: &PeerId) -> String {
    bs58::encode(peer.as_bytes()).into_string()
}

fn parse_peer(text: String) -> Result<PeerId, AslError> {
    PeerId::from_bytes(
        bs58::decode(text)
            .into_vec()
            .map_err(|_| AslError::InvalidDatabase)?,
    )
    .map_err(|_| AslError::InvalidDatabase)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::open_store;

    fn fixture() -> (tempfile::TempDir, Store, FetchRelay) {
        let home = tempfile::tempdir().unwrap();
        let store = open_store(&home.path().join("state.sqlite3")).unwrap();
        let relay = FetchRelay {
            request_id: Id128([1; 16]),
            logical_root: Hash32([2; 32]),
            requester_room: Hash32([3; 32]),
            source_room: Hash32([4; 32]),
            requester_agent: AgentId([5; 32]),
            requester_peer: super::super::tests::test_peer(6),
            content_id: Hash32([7; 32]),
            expires_at_ms: 200,
        };
        (home, store, relay)
    }

    #[test]
    fn relay_survives_restart_and_is_bound_to_exact_request_and_source_room() {
        let (home, mut store, relay) = fixture();
        store
            .record_fetch_relay(
                relay.request_id,
                relay.logical_root,
                relay.requester_room,
                relay.source_room,
                relay.requester_agent,
                &relay.requester_peer,
                relay.content_id,
                100,
                relay.expires_at_ms,
            )
            .unwrap();
        drop(store);

        let store = open_store(&home.path().join("state.sqlite3")).unwrap();
        assert_eq!(
            store
                .fetch_relay(relay.source_room, relay.request_id, 101)
                .unwrap(),
            Some(relay.clone())
        );
        assert!(
            store
                .fetch_relay(Hash32([9; 32]), relay.request_id, 101)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .fetch_relay(relay.source_room, relay.request_id, relay.expires_at_ms)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn relay_rejects_request_id_reuse_with_different_requester() {
        let (_home, mut store, relay) = fixture();
        store
            .record_fetch_relay(
                relay.request_id,
                relay.logical_root,
                relay.requester_room,
                relay.source_room,
                relay.requester_agent,
                &relay.requester_peer,
                relay.content_id,
                100,
                relay.expires_at_ms,
            )
            .unwrap();
        assert!(matches!(
            store.record_fetch_relay(
                relay.request_id,
                relay.logical_root,
                relay.requester_room,
                relay.source_room,
                relay.requester_agent,
                &super::super::tests::test_peer(8),
                relay.content_id,
                101,
                relay.expires_at_ms,
            ),
            Err(AslError::PolicyVersionConflict)
        ));
    }
}
