//! A display-only projection of profiles accepted by Core's DHT verifier.

use asl_types::{error::AslError, protocol::Profile, record::MAX_RECORD_LIFETIME_MS};
use rusqlite::{Connection, TransactionBehavior, params};

use crate::{Store, database_error};

const MAX_REMOTE_PROFILES: u32 = 200;

#[derive(serde::Serialize)]
pub struct RemoteProfileRow {
    pub agent_id: String,
    pub topics: Vec<u32>,
    pub avatar_content_id: Option<String>,
    pub expires_at_ms: i64,
}

impl Store {
    pub fn visible_remote_profiles(&self) -> Result<Vec<RemoteProfileRow>, AslError> {
        read_remote_profiles(&self.connection, crate::current_time_ms())
    }

    /// The caller must verify the root signature, current identity and record history.
    pub fn observe_remote_profile(
        &mut self,
        profile: &Profile,
        registry_sequence: u64,
        issued_at_ms: u64,
        expires_at_ms: u64,
        now_ms: u64,
    ) -> Result<(), AslError> {
        if !(issued_at_ms..expires_at_ms).contains(&now_ms)
            || expires_at_ms - issued_at_ms > MAX_RECORD_LIFETIME_MS
        {
            return Err(AslError::ExpiredMessage);
        }
        let sql_integer = |value| i64::try_from(value).map_err(|_| AslError::InvalidMessage);
        let now_ms = sql_integer(now_ms)?;
        let mut topics = profile
            .capabilities
            .iter()
            .filter(|topic| topic.is_topic())
            .map(|topic| topic.concept_id)
            .collect::<Vec<_>>();
        topics.sort_unstable();
        topics.dedup();
        let topics_json = serde_json::to_string(&topics).map_err(|_| AslError::InvalidMessage)?;
        let agent = bs58::encode(profile.agent_id.as_bytes()).into_string();
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let changed = tx
            .execute(
                "INSERT INTO observed_remote_profiles(
                    agent_id,agent_key,chain_id,checkpoint_hash,registry_sequence,
                    profile_sequence,topics_json,issued_at_ms,expires_at_ms,observed_at_ms,avatar_content_id)
                 SELECT r.agent_id,?2,r.chain_id,c.checkpoint_hash,r.sequence,?4,?5,?6,?7,?8,?9
                 FROM identity_registry_states r JOIN chain_state_cache c USING(chain_id)
                 WHERE r.agent_id=?1 AND r.sequence=?3 AND r.status='active'
                   AND NOT EXISTS(SELECT 1 FROM local_agent_identity l WHERE l.agent_id=r.agent_id)
                   AND NOT EXISTS(SELECT 1 FROM contact_bindings b
                                  WHERE b.agent_id=?2 AND b.state='revoked')
                 ON CONFLICT(agent_id) DO UPDATE SET
                    chain_id=excluded.chain_id,checkpoint_hash=excluded.checkpoint_hash,
                    registry_sequence=excluded.registry_sequence,
                    profile_sequence=excluded.profile_sequence,topics_json=excluded.topics_json,
                    issued_at_ms=excluded.issued_at_ms,expires_at_ms=excluded.expires_at_ms,
                    observed_at_ms=excluded.observed_at_ms,avatar_content_id=excluded.avatar_content_id
                 WHERE observed_remote_profiles.chain_id<>excluded.chain_id
                    OR observed_remote_profiles.checkpoint_hash<>excluded.checkpoint_hash
                    OR observed_remote_profiles.registry_sequence<>excluded.registry_sequence
                    OR observed_remote_profiles.profile_sequence<excluded.profile_sequence",
                params![
                    agent,
                    profile.agent_id.as_bytes(),
                    sql_integer(registry_sequence)?,
                    &profile.sequence.to_be_bytes(),
                    topics_json,
                    sql_integer(issued_at_ms)?,
                    sql_integer(expires_at_ms)?,
                    now_ms,
                    profile.avatar.as_ref().map(|id| id.as_bytes().as_slice()),
                ],
            )
            .map_err(database_error)?;
        if changed > 0 {
            tx.execute(
                "DELETE FROM observed_remote_profiles
                 WHERE expires_at_ms<=?1 OR agent_id IN (
                     SELECT agent_id FROM observed_remote_profiles
                     WHERE expires_at_ms>?1
                     ORDER BY observed_at_ms DESC,agent_id LIMIT -1 OFFSET ?2
                 )",
                params![now_ms, MAX_REMOTE_PROFILES],
            )
            .map_err(database_error)?;
        }
        tx.commit().map_err(database_error)
    }
}

pub(super) const VISIBLE: &str = "FROM observed_remote_profiles p
             JOIN identity_registry_states r ON p.agent_id=r.agent_id AND p.chain_id=r.chain_id
             JOIN chain_state_cache c ON c.chain_id=r.chain_id
             WHERE r.status='active' AND p.registry_sequence=r.sequence
               AND p.checkpoint_hash=c.checkpoint_hash
               AND p.issued_at_ms<=?1 AND ?1<p.expires_at_ms
               AND (p.topics_json<>'[]' OR p.avatar_content_id IS NOT NULL)
               AND NOT EXISTS(SELECT 1 FROM local_agent_identity l WHERE l.agent_id=p.agent_id)
               AND NOT EXISTS(SELECT 1 FROM contact_bindings b
                              WHERE b.agent_id=p.agent_key AND b.state='revoked')";

pub(crate) fn profile_visible(
    db: &Connection,
    agent: asl_types::ids::AgentId,
    now_ms: i64,
) -> Result<bool, AslError> {
    db.prepare_cached(&format!(
        "SELECT EXISTS(SELECT 1 {VISIBLE} AND p.agent_id=?2)"
    ))
    .map_err(database_error)?
    .query_row(params![now_ms, crate::chain::agent_text(agent)], |row| {
        row.get(0)
    })
    .map_err(database_error)
}

pub(crate) fn read_remote_profiles(
    db: &Connection,
    now_ms: i64,
) -> Result<Vec<RemoteProfileRow>, AslError> {
    let mut statement = db
        .prepare_cached(&format!(
            "SELECT p.agent_id,p.topics_json,p.expires_at_ms,p.avatar_content_id {VISIBLE}
             ORDER BY p.observed_at_ms DESC,p.agent_id LIMIT ?2"
        ))
        .map_err(database_error)?;
    let rows = statement
        .query_map(params![now_ms, MAX_REMOTE_PROFILES], |row| {
            Ok((
                row.get(0)?,
                row.get::<_, String>(1)?,
                row.get(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
            ))
        })
        .map_err(database_error)?;
    rows.map(|row| {
        let (agent_id, topics, expires_at_ms, avatar) = row.map_err(database_error)?;
        Ok(RemoteProfileRow {
            agent_id,
            topics: serde_json::from_str(&topics).map_err(|_| AslError::InvalidDatabase)?,
            avatar_content_id: avatar.map(hex::encode),
            expires_at_ms,
        })
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use asl_types::{
        ids::{AgentId, Hash32},
        protocol::ConceptRef,
    };

    fn profile(agent: AgentId, sequence: u64, topics: Vec<ConceptRef>) -> Profile {
        Profile {
            agent_id: agent,
            sequence,
            capabilities: topics,
            avatar: Some(Hash32([9; 32])),
        }
    }

    fn store() -> (tempfile::TempDir, Store) {
        let directory = tempfile::tempdir().unwrap();
        let store = crate::open_store(&directory.path().join("state.sqlite3")).unwrap();
        store
            .connection
            .execute_batch(
                "INSERT INTO chain_state_cache VALUES
             (1,zeroblob(20),zeroblob(32),1,zeroblob(32),zeroblob(32),zeroblob(32),x'',0)",
            )
            .unwrap();
        (directory, store)
    }

    fn add_agent(store: &Store, agent: AgentId) -> String {
        let agent = bs58::encode(agent.as_bytes()).into_string();
        store
            .connection
            .execute("INSERT INTO agents(agent_id) VALUES (?1)", [&agent])
            .unwrap();
        store
            .connection
            .execute(
                "INSERT INTO identity_registry_states VALUES
             (?1,1,zeroblob(20),zeroblob(32),7,'active',1,zeroblob(32),0)",
                [&agent],
            )
            .unwrap();
        agent
    }

    #[test]
    fn remote_profiles_show_only_current_known_topics_without_granting_permissions() {
        let (_directory, mut store) = store();
        let agent = AgentId([2; 32]);
        let agent_text = add_agent(&store, agent);
        let entry = profile(
            agent,
            u64::MAX,
            vec![
                ConceptRef::RUST,
                ConceptRef::RUST,
                ConceptRef {
                    vocabulary_id: 1,
                    concept_id: 1,
                },
            ],
        );
        store.observe_remote_profile(&entry, 6, 10, 30, 11).unwrap();
        assert!(
            read_remote_profiles(&store.connection, 11)
                .unwrap()
                .is_empty()
        );
        store.observe_remote_profile(&entry, 7, 10, 30, 11).unwrap();
        let older = profile(agent, u64::MAX - 1, Vec::new());
        store.observe_remote_profile(&older, 7, 11, 30, 12).unwrap();
        let rows = read_remote_profiles(&store.connection, 12).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].topics, vec![101]);
        assert!(
            read_remote_profiles(&store.connection, 30)
                .unwrap()
                .is_empty()
        );
        let authorizations: i64 = store.connection.query_row(
            "SELECT (SELECT count(*) FROM authorized_contacts)+(SELECT count(*) FROM contact_bindings)
                    +(SELECT count(*) FROM preferred_peers)",
            [],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(authorizations, 0);

        store
            .connection
            .execute(
                "UPDATE identity_registry_states SET sequence=8 WHERE agent_id=?1",
                [&agent_text],
            )
            .unwrap();
        assert!(
            read_remote_profiles(&store.connection, 12)
                .unwrap()
                .is_empty()
        );
        store.observe_remote_profile(&entry, 8, 10, 30, 12).unwrap();
        assert_eq!(
            read_remote_profiles(&store.connection, 12).unwrap().len(),
            1
        );

        store
            .connection
            .execute(
                "INSERT INTO contact_bindings VALUES (?1, 'test-peer', 'bound', 12)",
                [agent.as_bytes()],
            )
            .unwrap();
        store.revoke_contact_binding(agent, 13).unwrap();
        assert!(
            read_remote_profiles(&store.connection, 13)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn remote_avatar_reference_is_replaced_or_withdrawn_only_by_newer_profiles() {
        let (_dir, mut store) = store();
        let agent = AgentId([10; 32]);
        add_agent(&store, agent);
        let mut profile = profile(agent, 1, vec![]);
        let visible = |s: &Store, now| {
            read_remote_profiles(&s.connection, now)
                .unwrap()
                .into_iter()
                .map(|r| r.avatar_content_id)
                .collect::<Vec<_>>()
        };
        store
            .observe_remote_profile(&profile, 7, 10, 40, 11)
            .unwrap();
        assert_eq!(visible(&store, 11), [Some(hex::encode([9; 32]))]);
        profile.sequence = 2;
        profile.avatar = Some(Hash32([8; 32]));
        store
            .observe_remote_profile(&profile, 7, 12, 42, 12)
            .unwrap();
        assert_eq!(visible(&store, 12), [Some(hex::encode([8; 32]))]);
        profile.avatar = None;
        profile.sequence = 3;
        store
            .observe_remote_profile(&profile, 7, 13, 43, 13)
            .unwrap();
        assert!(visible(&store, 13).is_empty());
        profile.sequence = 1;
        profile.avatar = Some(Hash32([9; 32]));
        store
            .observe_remote_profile(&profile, 7, 10, 40, 14)
            .unwrap();
        assert!(visible(&store, 14).is_empty());
    }

    #[test]
    fn upgrading_v23_keeps_topics_without_inventing_an_avatar_reference() {
        let (dir, mut store) = store();
        let agent = AgentId([11; 32]);
        add_agent(&store, agent);
        store
            .observe_remote_profile(&profile(agent, 1, vec![ConceptRef::RUST]), 7, 10, 30, 11)
            .unwrap();
        crate::avatar_receipts::remove_schema_for_legacy_fixture(&store);
        store
            .connection
            .execute_batch(
                "DROP TABLE avatar_reference_grant;
                 DROP TABLE local_avatar_selection;
                 ALTER TABLE observed_remote_profiles DROP COLUMN avatar_content_id;
                 DELETE FROM schema_migrations WHERE version>=24;",
            )
            .unwrap();
        drop(store);
        let upgraded = crate::open_store(&dir.path().join("state.sqlite3")).unwrap();
        let rows = read_remote_profiles(&upgraded.connection, 12).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].topics, [101]);
        assert!(rows[0].avatar_content_id.is_none());
    }

    #[test]
    fn profile_lookup_uses_current_projection_and_never_dials_on_a_cache_hit() {
        use crate::profile_lookup::{LookupState, status};
        let (_dir, mut store) = store();
        let agent = AgentId([4; 32]);
        let text = add_agent(&store, agent);
        let now = crate::current_time_ms() as u64;
        store
            .observe_remote_profile(
                &profile(agent, 1, vec![ConceptRef::RUST]),
                7,
                now,
                now + 60_000,
                now,
            )
            .unwrap();
        assert_eq!(
            store.request_profile_lookup(agent, [2; 16]).unwrap().state,
            LookupState::Available
        );
        store
            .advance_profile_lookup(true, |_, _| panic!("cache hit sent to network"))
            .unwrap();
        assert_eq!(
            status(&store.connection, (now + 60_000) as i64)
                .unwrap()
                .unwrap()
                .state,
            LookupState::NoLongerVisible
        );
        store
            .connection
            .execute(
                "UPDATE identity_registry_states SET status='revoked' WHERE agent_id=?1",
                [text],
            )
            .unwrap();
        assert_eq!(
            store.profile_lookup_status().unwrap().unwrap().state,
            LookupState::NoLongerVisible
        );
    }

    #[test]
    fn remote_profiles_limit_distinct_agents_and_hide_old_checkpoints() {
        let (_directory, mut store) = store();
        for i in 0..=MAX_REMOTE_PROFILES {
            let mut id = [1; 32];
            id[..4].copy_from_slice(&i.to_be_bytes());
            let agent = AgentId(id);
            add_agent(&store, agent);
            let entry = profile(agent, 1, vec![ConceptRef::RUST]);
            store
                .observe_remote_profile(&entry, 7, 10, 1000, 10 + u64::from(i))
                .unwrap();
        }
        let count: u32 = store
            .connection
            .query_row("SELECT count(*) FROM observed_remote_profiles", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, MAX_REMOTE_PROFILES);
        store
            .connection
            .execute(
                "UPDATE chain_state_cache SET checkpoint_hash=?1",
                [&[2_u8; 32]],
            )
            .unwrap();
        assert!(
            read_remote_profiles(&store.connection, 250)
                .unwrap()
                .is_empty()
        );
    }
}
