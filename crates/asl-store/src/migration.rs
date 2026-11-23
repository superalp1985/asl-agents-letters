use asl_types::{
    error::AslError,
    ids::{AgentId, PeerId},
};
use rusqlite::{Row, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

use crate::{Store, chain::agent_text, database_error, inbound_observations::DAY_MS};

const CONTACT_LIMIT: usize = 10_000;
const TRUST_LIMIT: usize = 20_000;
const HISTORY_LIMIT: usize = 200;

#[derive(Clone, Copy, Default)]
pub struct Selection {
    pub contacts: bool,
    pub trust: bool,
    pub history: bool,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PortableRecords {
    contacts: Vec<Contact>,
    trust: Vec<Trust>,
    history: Vec<Observation>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Contact {
    agent: [u8; 32],
    revoked: bool,
    updated_at_ms: i64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Trust {
    agent: [u8; 32],
    id: [u8; 16],
    dedupe: [u8; 32],
    dimension: String,
    outcome: String,
    created_at_ms: i64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    agent: [u8; 32],
    peer: String,
    message: [u8; 16],
    root: [u8; 16],
    observed_at_ms: i64,
    expires_at_ms: i64,
    intent: u8,
    result_shape: u8,
    constraint_count: u8,
    topics: Vec<(u16, u32)>,
}

impl Store {
    pub fn portable_records(
        &mut self,
        selection: Selection,
        now: i64,
    ) -> Result<PortableRecords, AslError> {
        let tx = self.connection.transaction().map_err(database_error)?;
        let mut records = PortableRecords::default();
        if selection.contacts {
            let mut statement = tx.prepare(
                "SELECT agent_id,state,updated_at_ms FROM contact_bindings ORDER BY agent_id LIMIT ?1",
            ).map_err(database_error)?;
            records.contacts = statement
                .query_map([(CONTACT_LIMIT + 1) as i64], |row| {
                    Ok(Contact {
                        agent: row.get(0)?,
                        revoked: row.get::<_, String>(1)? == "revoked",
                        updated_at_ms: row.get(2)?,
                    })
                })
                .map_err(database_error)?
                .collect::<Result<_, _>>()
                .map_err(database_error)?;
        }
        if selection.trust {
            let mut statement = tx
                .prepare(
                    "SELECT agent_id,event_id,dedupe_key,dimension,outcome,created_at_ms
                 FROM trust_events ORDER BY created_at_ms DESC,event_id LIMIT ?1",
                )
                .map_err(database_error)?;
            records.trust = statement
                .query_map([(TRUST_LIMIT + 1) as i64], |row| {
                    Ok(Trust {
                        agent: read_agent(row, 0)?,
                        id: read_hex(row, 1)?,
                        dedupe: read_hex(row, 2)?,
                        dimension: row.get(3)?,
                        outcome: row.get(4)?,
                        created_at_ms: row.get(5)?,
                    })
                })
                .map_err(database_error)?
                .collect::<Result<_, _>>()
                .map_err(database_error)?;
        }
        if selection.history {
            let mut statement = tx
                .prepare(
                    "SELECT agent_id,peer_id,message_id,root_task_id,observed_at_ms,expires_at_ms,
                        intent,result_shape,constraint_count,topics_json
                 FROM direct_inbound_observations WHERE expires_at_ms>?1
                 ORDER BY observed_at_ms DESC,agent_id,message_id LIMIT ?2",
                )
                .map_err(database_error)?;
            records.history = statement
                .query_map(params![now, HISTORY_LIMIT as i64], |row| {
                    Ok(Observation {
                        agent: read_agent(row, 0)?,
                        peer: row.get(1)?,
                        message: read_hex(row, 2)?,
                        root: read_hex(row, 3)?,
                        observed_at_ms: row.get(4)?,
                        expires_at_ms: row.get(5)?,
                        intent: row.get(6)?,
                        result_shape: row.get(7)?,
                        constraint_count: row.get(8)?,
                        topics: serde_json::from_str(&row.get::<_, String>(9)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    })
                })
                .map_err(database_error)?
                .collect::<Result<_, _>>()
                .map_err(database_error)?;
        }
        records.check_limits()?;
        tx.commit().map_err(database_error)?;
        Ok(records)
    }

    /// The app builds the destination in a new, unpublished data directory.
    pub fn restore_portable_records(
        &mut self,
        records: PortableRecords,
        now: i64,
    ) -> Result<(), AslError> {
        records.check_limits()?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        if tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM agents UNION ALL SELECT 1 FROM contact_bindings
              UNION ALL SELECT 1 FROM direct_inbound_observations)",
                [],
                |row| row.get::<_, bool>(0),
            )
            .map_err(database_error)?
        {
            return Err(AslError::InvalidPolicyState);
        }
        for contact in records.contacts {
            if contact.agent == [0; 32] || !(0..=now).contains(&contact.updated_at_ms) {
                return Err(AslError::InvalidMessage);
            }
            tx.execute(
                "INSERT INTO contact_bindings(agent_id,peer_id,state,updated_at_ms)
                 VALUES (?1,NULL,?2,?3)",
                params![
                    contact.agent,
                    if contact.revoked { "revoked" } else { "bound" },
                    contact.updated_at_ms
                ],
            )
            .map_err(database_error)?;
        }
        for event in records.trust {
            if event.agent == [0; 32] || !(0..=now).contains(&event.created_at_ms) {
                return Err(AslError::InvalidMessage);
            }
            let agent = agent_text(AgentId(event.agent));
            tx.execute(
                "INSERT OR IGNORE INTO agents(agent_id) VALUES (?1)",
                [&agent],
            )
            .map_err(database_error)?;
            tx.execute(
                "INSERT INTO trust_events(event_id,agent_id,dimension,outcome,proof_json,dedupe_key,created_at_ms)
                 VALUES (?1,?2,?3,?4,'{\"kind\":\"migrated_local_observation\"}',?5,?6)",
                params![hex::encode(event.id), agent, event.dimension, event.outcome,
                    hex::encode(event.dedupe), event.created_at_ms],
            ).map_err(database_error)?;
        }
        for row in records.history {
            if row.expires_at_ms <= now {
                continue;
            }
            if row.agent == [0; 32]
                || !(0..=now).contains(&row.observed_at_ms)
                || row.expires_at_ms > row.observed_at_ms.saturating_add(7 * DAY_MS)
                || row.topics.len() > 64
                || row.peer.len() > 175
                || bs58::decode(&row.peer)
                    .into_vec()
                    .ok()
                    .and_then(|bytes| PeerId::from_bytes(bytes).ok())
                    .is_none()
            {
                return Err(AslError::InvalidMessage);
            }
            let topics =
                serde_json::to_string(&row.topics).map_err(|_| AslError::InvalidMessage)?;
            tx.execute(
                "INSERT INTO direct_inbound_observations(
                    agent_id,peer_id,message_id,root_task_id,observed_at_ms,expires_at_ms,
                    intent,result_shape,constraint_count,topics_json)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![
                    agent_text(AgentId(row.agent)),
                    row.peer,
                    hex::encode(row.message),
                    hex::encode(row.root),
                    row.observed_at_ms,
                    row.expires_at_ms,
                    row.intent,
                    row.result_shape,
                    row.constraint_count,
                    topics
                ],
            )
            .map_err(database_error)?;
        }
        tx.commit().map_err(database_error)
    }
}

impl PortableRecords {
    fn check_limits(&self) -> Result<(), AslError> {
        if self.contacts.len() > CONTACT_LIMIT
            || self.trust.len() > TRUST_LIMIT
            || self.history.len() > HISTORY_LIMIT
        {
            return Err(AslError::QuotaExceeded);
        }
        Ok(())
    }
}

fn read_hex<const N: usize>(row: &Row<'_>, index: usize) -> rusqlite::Result<[u8; N]> {
    hex::decode(row.get::<_, String>(index)?)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(rusqlite::Error::InvalidQuery)
}

fn read_agent(row: &Row<'_>, index: usize) -> rusqlite::Result<[u8; 32]> {
    bs58::decode(row.get::<_, String>(index)?)
        .into_vec()
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(rusqlite::Error::InvalidQuery)
}
