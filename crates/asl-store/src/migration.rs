use asl_types::{
    error::AslError,
    ids::{AgentId, PeerId},
};
use rusqlite::{Row, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

use crate::{
    Store, act_history::ActDirection, act_history::StoredActHistory, chain::agent_text,
    database_error, inbound_observations::DAY_MS,
};

const CONTACT_LIMIT: usize = 10_000;
const TRUST_LIMIT: usize = 20_000;
const HISTORY_LIMIT: usize = 200;
const ACT_LIMIT: usize = 200;
const GROUP_HINT_LIMIT: usize = 512;

#[derive(Clone, Copy, Default)]
pub struct Selection {
    pub contacts: bool,
    pub trust: bool,
    pub history: bool,
    pub groups: bool,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PortableRecords {
    contacts: Vec<Contact>,
    trust: Vec<Trust>,
    history: Vec<Observation>,
    #[serde(default)]
    acts: Vec<PortableAct>,
    #[serde(default)]
    groups: Vec<PortableGroup>,
}

pub struct MigrationGroupHint {
    pub wire_id: [u8; 32],
    pub local_name: String,
    pub owner: AgentId,
    pub last_epoch: u64,
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

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PortableAct {
    conversation_id: String,
    act_id: [u8; 32],
    mls_epoch: u64,
    direction: String,
    act_kind: u16,
    causal_root: [u8; 32],
    reply_to: Option<[u8; 32]>,
    body: Option<String>,
    received_at_ms: i64,
    expires_at_ms: i64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PortableGroup {
    wire_id: [u8; 32],
    local_name: String,
    owner: [u8; 32],
    last_epoch: u64,
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
            let mut statement = tx
                .prepare(
                    "SELECT conversation_id,act_id,mls_epoch,direction,act_kind,
                            causal_root,reply_to,ciphertext,received_at_ms,expires_at_ms
                     FROM conversation_act_events WHERE expires_at_ms>?1
                     ORDER BY received_at_ms DESC,conversation_id,act_id LIMIT ?2",
                )
                .map_err(database_error)?;
            let act_rows = statement
                .query_map(params![now, (ACT_LIMIT + 1) as i64], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        blob::<32>(row, 1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                        blob::<32>(row, 5)?,
                        row.get::<_, Option<Vec<u8>>>(6)?
                            .map(|value| {
                                value.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
                            })
                            .transpose()?,
                        row.get::<_, Vec<u8>>(7)?,
                        row.get::<_, i64>(8)?,
                        row.get::<_, i64>(9)?,
                    ))
                })
                .map_err(database_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(database_error)?;
            drop(statement);
            records.acts = act_rows
                .into_iter()
                .map(
                    |(
                        conversation_id,
                        act_id,
                        mls_epoch,
                        direction,
                        act_kind,
                        causal_root,
                        reply_to,
                        body,
                        received_at_ms,
                        expires_at_ms,
                    )| {
                        Ok(PortableAct {
                            conversation_id,
                            act_id,
                            mls_epoch: u64::try_from(mls_epoch)
                                .map_err(|_| AslError::InvalidDatabase)?,
                            direction,
                            act_kind: u16::try_from(act_kind)
                                .map_err(|_| AslError::InvalidDatabase)?,
                            causal_root,
                            reply_to,
                            body: crate::act_history::decode_stored_body(&body)?,
                            received_at_ms,
                            expires_at_ms,
                        })
                    },
                )
                .collect::<Result<Vec<_>, AslError>>()?;
        }
        if selection.groups {
            let mut statement = tx
                .prepare(
                    "SELECT lower(hex(s.wire_group_id)),g.local_name,p.agent_id,g.mls_epoch
                     FROM mls_room_states s
                     JOIN asl_groups g ON g.group_id=s.local_group_id
                     JOIN peers p ON p.peer_id=g.creator_peer_id
                     WHERE g.state IN ('active','needs_sync')
                     ORDER BY g.created_at_ms,g.group_id LIMIT ?1",
                )
                .map_err(database_error)?;
            records.groups = statement
                .query_map([(GROUP_HINT_LIMIT + 1) as i64], |row| {
                    Ok(PortableGroup {
                        wire_id: hex::decode(row.get::<_, String>(0)?)
                            .ok()
                            .and_then(|value| value.try_into().ok())
                            .ok_or(rusqlite::Error::InvalidQuery)?,
                        local_name: row.get(1)?,
                        owner: read_agent(row, 2)?,
                        last_epoch: u64::try_from(row.get::<_, i64>(3)?)
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
        let act_days = crate::group_observations::group_observation_days(&tx)?;
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
        for row in records.acts {
            let direction = match row.direction.as_str() {
                "in" => ActDirection::In,
                "out" => ActDirection::Out,
                _ => return Err(AslError::InvalidMessage),
            };
            if row.expires_at_ms <= now {
                continue;
            }
            crate::act_history::restore_act_history_on(
                &tx,
                act_days,
                StoredActHistory {
                    conversation_id: &row.conversation_id,
                    act_id: row.act_id,
                    mls_epoch: row.mls_epoch,
                    direction,
                    act_kind: row.act_kind,
                    causal_root: row.causal_root,
                    reply_to: row.reply_to,
                    body: row.body.as_deref(),
                    received_at_ms: u64::try_from(row.received_at_ms)
                        .map_err(|_| AslError::InvalidMessage)?,
                    expires_at_ms: u64::try_from(row.expires_at_ms)
                        .map_err(|_| AslError::InvalidMessage)?,
                },
            )?;
        }
        for group in records.groups {
            if group.wire_id == [0; 32]
                || group.owner == [0; 32]
                || group.local_name.is_empty()
                || group.local_name.chars().count() > 160
                || group.local_name.as_bytes().contains(&0)
                || group.last_epoch > i64::MAX as u64
                || now <= 0
            {
                return Err(AslError::InvalidMessage);
            }
            let owner = agent_text(AgentId(group.owner));
            tx.execute(
                "INSERT OR IGNORE INTO agents(agent_id) VALUES (?1)",
                [&owner],
            )
            .map_err(database_error)?;
            tx.execute(
                "INSERT INTO migration_group_hints(
                    wire_group_id,local_name,owner_agent_id,last_epoch,imported_at_ms)
                 VALUES (?1,?2,?3,?4,?5)",
                params![
                    group.wire_id.as_slice(),
                    group.local_name,
                    owner,
                    i64::try_from(group.last_epoch).map_err(|_| AslError::InvalidMessage)?,
                    now
                ],
            )
            .map_err(database_error)?;
        }
        tx.commit().map_err(database_error)
    }

    pub fn migration_group_hints(&self) -> Result<Vec<MigrationGroupHint>, AslError> {
        let mut statement = self
            .connection
            .prepare_cached(
                "SELECT wire_group_id,local_name,owner_agent_id,last_epoch
                 FROM migration_group_hints ORDER BY imported_at_ms,wire_group_id LIMIT ?1",
            )
            .map_err(database_error)?;
        statement
            .query_map([(GROUP_HINT_LIMIT + 1) as i64], |row| {
                Ok(MigrationGroupHint {
                    wire_id: row
                        .get::<_, Vec<u8>>(0)?
                        .try_into()
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    local_name: row.get(1)?,
                    owner: AgentId(read_agent(row, 2)?),
                    last_epoch: u64::try_from(row.get::<_, i64>(3)?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                })
            })
            .map_err(database_error)?
            .collect::<Result<_, _>>()
            .map_err(database_error)
    }
}

impl PortableRecords {
    fn check_limits(&self) -> Result<(), AslError> {
        if self.contacts.len() > CONTACT_LIMIT
            || self.trust.len() > TRUST_LIMIT
            || self.history.len() > HISTORY_LIMIT
            || self.acts.len() > ACT_LIMIT
            || self.groups.len() > GROUP_HINT_LIMIT
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

fn blob<const N: usize>(row: &Row<'_>, index: usize) -> rusqlite::Result<[u8; N]> {
    row.get::<_, Vec<u8>>(index)?
        .try_into()
        .map_err(|_| rusqlite::Error::InvalidQuery)
}

#[cfg(test)]
mod tests {
    use asl_types::{
        ids::{AgentId, Hash32, Id128, PeerId},
        task::GroupId,
    };

    use super::*;
    use crate::group_state::PendingMlsRoom;

    fn peer(seed: u8) -> PeerId {
        let mut bytes = [0; 32];
        bytes[0] = seed;
        let key = libp2p_identity::Keypair::ed25519_from_bytes(bytes).unwrap();
        PeerId::from_bytes(key.public().to_peer_id().to_bytes()).unwrap()
    }

    fn source_store(path: &std::path::Path, owner: AgentId, device: &PeerId) -> Store {
        let mut store = crate::open_store(path).unwrap();
        let agent = agent_text(owner);
        let peer = bs58::encode(device.as_bytes()).into_string();
        store
            .connection
            .execute("INSERT INTO agents(agent_id) VALUES (?1)", [&agent])
            .unwrap();
        store
            .connection
            .execute(
                "INSERT INTO device_identities
                 VALUES (?1,?2,printf('%064x',0),X'',1,1,NULL,0)",
                params![peer, agent],
            )
            .unwrap();
        store
            .connection
            .execute(
                "INSERT INTO peers(peer_id,agent_id) VALUES (?1,?2)",
                params![peer, agent],
            )
            .unwrap();
        store
            .stage_mls_room(PendingMlsRoom {
                local_id: &GroupId(Id128([3; 16])),
                wire_id: Hash32([4; 32]),
                creator: device,
                local_name: "Migrated group",
                mls_epoch: 7,
                sealed_snapshot: b"not copied",
            })
            .unwrap();
        store
            .connection
            .execute("UPDATE asl_groups SET state='active'", [])
            .unwrap();
        store
    }

    #[test]
    fn group_hints_export_ids_and_owner_without_mls_state() {
        let directory = tempfile::tempdir().unwrap();
        let owner = AgentId([1; 32]);
        let device = peer(1);
        let mut source = source_store(&directory.path().join("source.sqlite3"), owner, &device);
        let now = crate::current_time_ms();
        let records = source
            .portable_records(
                Selection {
                    groups: true,
                    ..Selection::default()
                },
                now,
            )
            .unwrap();
        let encoded = serde_json::to_string(&records).unwrap();
        assert!(!encoded.contains("not copied"));

        let mut target = crate::open_store(&directory.path().join("target.sqlite3")).unwrap();
        target.restore_portable_records(records, now).unwrap();
        let hints = target.migration_group_hints().unwrap();
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].wire_id, [4; 32]);
        assert_eq!(hints[0].local_name, "Migrated group");
        assert_eq!(hints[0].owner, owner);
        assert_eq!(hints[0].last_epoch, 7);
        assert!(
            !target
                .list_mls_room_ids()
                .unwrap()
                .iter()
                .any(|(wire, _)| wire.0 == [4; 32])
        );
    }
}
