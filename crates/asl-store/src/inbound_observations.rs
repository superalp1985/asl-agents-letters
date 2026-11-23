use asl_types::{
    error::AslError,
    ids::{AgentId, PeerId},
    protocol::{Intent, Query, ResultShape},
};
use rusqlite::{Connection, TransactionBehavior, params};

use crate::{
    Store, chain::agent_text, current_time_ms, database_error, read_setting, write_setting,
};

const RETENTION_KEY: &str = "activity.direct_observation_days.v1";
pub(crate) const DAY_MS: i64 = 24 * 60 * 60 * 1_000;
pub const MAX_OBSERVATION_DAYS: u8 = 7;
pub const MAX_DIRECT_INBOUND_OBSERVATIONS: i64 = 200;

pub(crate) fn direct_observation_days(db: &Connection) -> Result<u8, AslError> {
    observation_days(db, RETENTION_KEY)
}

pub(crate) fn observation_days(db: &Connection, key: &str) -> Result<u8, AslError> {
    match read_setting(db, key)? {
        None => Ok(MAX_OBSERVATION_DAYS),
        Some(value) => serde_json::from_str::<u8>(&value)
            .ok()
            .filter(|days| *days <= MAX_OBSERVATION_DAYS)
            .ok_or(AslError::InvalidDatabase),
    }
}

pub struct DirectInboundObservation {
    pub observed_at_ms: i64,
    pub agent_id: String,
    pub peer_id: String,
    pub intent: u8,
    pub topic_ids: Vec<(u16, u32)>,
    pub constraint_count: u8,
    pub result_shape: u8,
}

impl Store {
    pub fn set_direct_observation_days(&mut self, days: u8) -> Result<(), AslError> {
        if days > MAX_OBSERVATION_DAYS {
            return Err(AslError::InvalidMessage);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let now = current_time_ms();
        write_setting(&tx, RETENTION_KEY, &days.to_string(), now)?;
        if days == 0 {
            tx.execute("DELETE FROM direct_inbound_observations", [])
                .map_err(database_error)?;
        } else {
            // Previously shortened lifetimes also apply after the limit is raised.
            tx.execute(
                "UPDATE direct_inbound_observations SET expires_at_ms=observed_at_ms+?1
                 WHERE expires_at_ms-observed_at_ms>?1",
                [i64::from(days) * DAY_MS],
            )
            .map_err(database_error)?;
            delete_expired(&tx, now)?;
        }
        tx.commit().map_err(database_error)
    }

    pub fn record_direct_inbound_observation(
        &mut self,
        agent_id: AgentId,
        peer_id: &PeerId,
        query: &Query,
        now_ms: i64,
    ) -> Result<bool, AslError> {
        if now_ms < 0 || query.topics.len() > 64 || query.constraints.len() > 16 {
            return Err(AslError::InvalidMessage);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let days = direct_observation_days(&transaction)?;
        if days == 0 {
            return Ok(false);
        }
        let expires_at_ms = now_ms
            .checked_add(i64::from(days) * DAY_MS)
            .ok_or(AslError::InvalidMessage)?;
        let topics = query
            .topics
            .iter()
            .map(|topic| (topic.vocabulary_id, topic.concept_id))
            .collect::<Vec<_>>();
        let topics_json = serde_json::to_string(&topics).map_err(|_| AslError::InvalidDatabase)?;
        delete_expired(&transaction, now_ms)?;
        let inserted = transaction
            .execute(
                "INSERT OR IGNORE INTO direct_inbound_observations(
                    agent_id,peer_id,message_id,root_task_id,observed_at_ms,expires_at_ms,
                    intent,result_shape,constraint_count,topics_json
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![
                    agent_text(agent_id),
                    bs58::encode(peer_id.as_bytes()).into_string(),
                    hex::encode(query.message_id.0),
                    hex::encode(query.root_task_id.0),
                    now_ms,
                    expires_at_ms,
                    intent_code(query.intent_id),
                    result_shape_code(query.result_shape),
                    query.constraints.len() as i64,
                    topics_json
                ],
            )
            .map_err(database_error)?;
        transaction
            .execute(
                "DELETE FROM direct_inbound_observations
                 WHERE (agent_id,message_id) NOT IN (
                    SELECT agent_id,message_id FROM direct_inbound_observations
                    ORDER BY observed_at_ms DESC,agent_id,message_id LIMIT ?1
                 )",
                [MAX_DIRECT_INBOUND_OBSERVATIONS],
            )
            .map_err(database_error)?;
        transaction.commit().map_err(database_error)?;
        Ok(inserted == 1)
    }

    pub fn prune_direct_inbound_observations(&mut self, now_ms: i64) -> Result<(), AslError> {
        if now_ms < 0 {
            return Err(AslError::InvalidMessage);
        }
        delete_expired(&self.connection, now_ms)
    }
}

pub(crate) fn delete_expired(db: &Connection, now_ms: i64) -> Result<(), AslError> {
    db.execute(
        "DELETE FROM direct_inbound_observations WHERE expires_at_ms <= ?1",
        [now_ms],
    )
    .map_err(database_error)?;
    Ok(())
}

pub(crate) fn read_recent_direct_inbound_observations(
    database: &Connection,
) -> Result<Vec<DirectInboundObservation>, AslError> {
    let mut statement = database
        .prepare(
            "SELECT observed_at_ms,agent_id,peer_id,intent,result_shape,
                    constraint_count,topics_json
             FROM direct_inbound_observations
             WHERE expires_at_ms > ?1
             ORDER BY observed_at_ms DESC,agent_id,message_id LIMIT ?2",
        )
        .map_err(database_error)?;
    statement
        .query_map(
            params![current_time_ms(), MAX_DIRECT_INBOUND_OBSERVATIONS],
            |row| {
                let topics_json: String = row.get(6)?;
                let topic_ids = serde_json::from_str::<Vec<(u16, u32)>>(&topics_json)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?;
                let intent = row.get::<_, i64>(3)?;
                let result_shape = row.get::<_, i64>(4)?;
                let constraint_count = row.get::<_, i64>(5)?;
                Ok(DirectInboundObservation {
                    observed_at_ms: row.get(0)?,
                    agent_id: row.get(1)?,
                    peer_id: row.get(2)?,
                    intent: u8::try_from(intent)
                        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(3, intent))?,
                    result_shape: u8::try_from(result_shape)
                        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(4, result_shape))?,
                    constraint_count: u8::try_from(constraint_count).map_err(|_| {
                        rusqlite::Error::IntegralValueOutOfRange(5, constraint_count)
                    })?,
                    topic_ids,
                })
            },
        )
        .map_err(database_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(database_error)
}

fn intent_code(intent: Intent) -> i64 {
    match intent {
        Intent::FindEvidence => 1,
        Intent::LocateResource => 2,
        Intent::VerifyClaim => 3,
        Intent::IdentifyAgent => 4,
        Intent::OfferResource => 5,
        Intent::GroupReview => 6,
    }
}

fn result_shape_code(shape: ResultShape) -> i64 {
    match shape {
        ResultShape::Claims => 1,
        ResultShape::Resources => 2,
        ResultShape::Agents => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asl_types::{
        ids::Id128,
        protocol::{ConceptRef, Query},
    };

    fn peer() -> PeerId {
        let key = libp2p_identity::Keypair::ed25519_from_bytes([7; 32]).unwrap();
        PeerId::from_bytes(key.public().to_peer_id().to_bytes()).unwrap()
    }

    fn query(id: u8) -> Query {
        Query {
            message_id: Id128([id; 16]),
            root_task_id: Id128([2; 16]),
            created_at_ms: 1_000,
            expires_at_ms: 10_000,
            intent_id: Intent::LocateResource,
            topics: vec![ConceptRef::RUST],
            constraints: vec![],
            result_shape: ResultShape::Resources,
            budget: 1,
        }
    }

    #[test]
    fn observations_are_structured_deduplicated_and_bounded() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("asl.sqlite3");
        let mut store = crate::open_store(&path).unwrap();
        let agent = AgentId([7; 32]);
        let peer = peer();
        let now = current_time_ms();
        assert!(
            store
                .record_direct_inbound_observation(agent, &peer, &query(1), now)
                .unwrap()
        );
        assert!(
            !store
                .record_direct_inbound_observation(agent, &peer, &query(1), now + 100)
                .unwrap()
        );
        for id in 2..=201 {
            store
                .record_direct_inbound_observation(
                    agent,
                    &peer,
                    &query(id as u8),
                    now + i64::from(id),
                )
                .unwrap();
        }

        let count: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM direct_inbound_observations",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, MAX_DIRECT_INBOUND_OBSERVATIONS);
        drop(store);

        let dashboard = crate::dashboard::Dashboard::load(&path).unwrap();
        assert_eq!(dashboard.direct_observations.len(), 200);
        assert_eq!(dashboard.direct_observations[0].intent, 2);
        assert_eq!(dashboard.direct_observations[0].topic_ids, vec![(1, 101)]);
        assert_eq!(dashboard.direct_observations[0].constraint_count, 0);
        assert_eq!(dashboard.direct_observations[0].result_shape, 2);
    }

    #[test]
    fn shorter_deadlines_apply_to_existing_rows_and_longer_settings_only_to_new_rows() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("asl.sqlite3");
        let mut store = crate::open_store(&path).unwrap();
        let agent = AgentId([9; 32]);
        let peer = peer();
        let now = current_time_ms();
        let record = |store: &mut Store, id, at| {
            store
                .record_direct_inbound_observation(agent, &peer, &query(id), at)
                .unwrap()
        };
        assert!(record(&mut store, 1, now - 2 * DAY_MS));
        assert!(record(&mut store, 2, now));
        store.set_direct_observation_days(1).unwrap();
        store.set_direct_observation_days(7).unwrap();
        assert!(record(&mut store, 3, now));

        let deadlines: Vec<i64> = store
            .connection
            .prepare("SELECT expires_at_ms FROM direct_inbound_observations ORDER BY message_id")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(deadlines, [now + DAY_MS, now + 7 * DAY_MS]);

        store.set_direct_observation_days(0).unwrap();
        drop(store);
        let mut reopened = crate::open_store(&path).unwrap();
        assert!(!record(&mut reopened, 4, now));
        assert!(reopened.set_direct_observation_days(8).is_err());
        let dashboard = crate::dashboard::Dashboard::load(&path).unwrap();
        assert_eq!(dashboard.direct_observation_days, 0);
        assert!(dashboard.direct_observations.is_empty());
        reopened.set_direct_observation_days(2).unwrap();
        assert!(record(&mut reopened, 5, now));
        assert_eq!(
            crate::dashboard::Dashboard::load(&path)
                .unwrap()
                .direct_observations
                .len(),
            1
        );
    }

    #[test]
    fn expired_observations_are_removed_at_startup_cleanup() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = crate::open_store(&temp.path().join("asl.sqlite3")).unwrap();
        let peer = peer();
        store
            .record_direct_inbound_observation(AgentId([8; 32]), &peer, &query(1), 1_000)
            .unwrap();

        store
            .prune_direct_inbound_observations(1_000 + i64::from(MAX_OBSERVATION_DAYS) * DAY_MS)
            .unwrap();

        let count: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM direct_inbound_observations",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }
}
