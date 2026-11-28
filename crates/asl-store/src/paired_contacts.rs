use asl_types::{
    error::AslError,
    ids::{AgentId, Id128},
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use crate::{Store, database_error};

const MAX_INVITE_LIFETIME_MS: u64 = 24 * 60 * 60 * 1_000;
const PAIRING_PROMPT_AGENT_WINDOW_MS: u64 = 24 * 60 * 60 * 1_000;
const PAIRING_PROMPT_GLOBAL_WINDOW_MS: u64 = 60 * 60 * 1_000;
const MAX_PAIRING_PROMPTS_PER_AGENT: i64 = 1;
const MAX_PAIRING_PROMPTS_PER_HOUR: i64 = 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairedContact {
    pub agent_id: AgentId,
    pub paired_at_ms: u64,
    pub invite_id: Id128,
}

impl Store {
    pub fn allow_pairing_prompt(
        &mut self,
        agent_id: AgentId,
        invite_id: Id128,
        now_ms: u64,
    ) -> Result<bool, AslError> {
        if agent_id.0 == [0; 32] || invite_id.0 == [0; 16] || now_ms > i64::MAX as u64 {
            return Err(AslError::InvalidMessage);
        }
        let now = now_ms as i64;
        let agent_window_start = now_ms.saturating_sub(PAIRING_PROMPT_AGENT_WINDOW_MS) as i64;
        let global_window_start = now_ms.saturating_sub(PAIRING_PROMPT_GLOBAL_WINDOW_MS) as i64;
        if !pairing_prompt_capacity(
            &self.connection,
            agent_id,
            invite_id,
            agent_window_start,
            global_window_start,
        )? {
            return Ok(false);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        transaction
            .execute(
                "DELETE FROM pairing_prompt_log WHERE shown_at_ms <= ?1",
                [agent_window_start],
            )
            .map_err(database_error)?;
        if !pairing_prompt_capacity(
            &transaction,
            agent_id,
            invite_id,
            agent_window_start,
            global_window_start,
        )? {
            transaction.commit().map_err(database_error)?;
            return Ok(false);
        }
        transaction
            .execute(
                "INSERT INTO pairing_prompt_log(invite_id, agent_id, shown_at_ms)
                 VALUES (?1, ?2, ?3)",
                params![
                    invite_id.as_bytes().as_slice(),
                    agent_id.as_bytes().as_slice(),
                    now,
                ],
            )
            .map_err(database_error)?;
        transaction.commit().map_err(database_error)?;
        Ok(true)
    }

    pub fn paired_contacts(&self) -> Result<Vec<PairedContact>, AslError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT agent_id, paired_at_ms, invite_id
                 FROM paired_contacts
                 ORDER BY paired_at_ms, agent_id",
            )
            .map_err(database_error)?;
        let rows = statement
            .query_map([], |row| {
                let agent: Vec<u8> = row.get(0)?;
                let paired_at_ms: i64 = row.get(1)?;
                let invite: Vec<u8> = row.get(2)?;
                Ok((agent, paired_at_ms, invite))
            })
            .map_err(database_error)?;

        rows.map(|row| {
            let (agent, paired_at_ms, invite) = row.map_err(database_error)?;
            Ok(PairedContact {
                agent_id: AgentId(agent.try_into().map_err(|_| AslError::InvalidDatabase)?),
                paired_at_ms: u64::try_from(paired_at_ms).map_err(|_| AslError::InvalidDatabase)?,
                invite_id: Id128(invite.try_into().map_err(|_| AslError::InvalidDatabase)?),
            })
        })
        .collect()
    }

    pub fn is_paired_contact(&self, agent_id: AgentId) -> Result<bool, AslError> {
        self.connection
            .query_row(
                "SELECT 1 FROM paired_contacts WHERE agent_id = ?1",
                [agent_id.as_bytes().as_slice()],
                |_| Ok(()),
            )
            .optional()
            .map(|value| value.is_some())
            .map_err(database_error)
    }

    pub fn remove_paired_contact(&mut self, agent_id: AgentId) -> Result<bool, AslError> {
        self.connection
            .execute(
                "DELETE FROM paired_contacts WHERE agent_id = ?1",
                [agent_id.as_bytes().as_slice()],
            )
            .map(|changed| changed == 1)
            .map_err(database_error)
    }

    /// Consumes a one-time invitation and records a local identity pin only
    /// when the local Agent approved it.
    pub fn consume_pairing_invite(
        &mut self,
        agent_id: AgentId,
        invite_id: Id128,
        expires_at_ms: u64,
        now_ms: u64,
        accepted: bool,
    ) -> Result<bool, AslError> {
        if invite_id.0 == [0; 16]
            || now_ms > i64::MAX as u64
            || expires_at_ms > i64::MAX as u64
            || expires_at_ms <= now_ms
            || expires_at_ms - now_ms > MAX_INVITE_LIFETIME_MS
        {
            return Err(AslError::InvalidMessage);
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        transaction
            .execute(
                "DELETE FROM pairing_invite_receipts WHERE expires_at_ms <= ?1",
                [now_ms as i64],
            )
            .map_err(database_error)?;
        let consumed = transaction
            .execute(
                "INSERT INTO pairing_invite_receipts(invite_id, agent_id, expires_at_ms)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(invite_id) DO NOTHING",
                params![
                    invite_id.as_bytes().as_slice(),
                    agent_id.as_bytes().as_slice(),
                    expires_at_ms as i64,
                ],
            )
            .map_err(database_error)?;
        if consumed == 1 && accepted {
            transaction
                .execute(
                    "INSERT INTO paired_contacts(agent_id, paired_at_ms, invite_id)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT(agent_id) DO NOTHING",
                    params![
                        agent_id.as_bytes().as_slice(),
                        now_ms as i64,
                        invite_id.as_bytes().as_slice(),
                    ],
                )
                .map_err(database_error)?;
        }
        transaction.commit().map_err(database_error)?;
        Ok(consumed == 1)
    }
}

fn pairing_prompt_capacity(
    connection: &rusqlite::Connection,
    agent_id: AgentId,
    invite_id: Id128,
    agent_window_start: i64,
    global_window_start: i64,
) -> Result<bool, AslError> {
    let invite_seen: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM pairing_prompt_log WHERE invite_id = ?1
             )",
            [invite_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    let agent_prompts: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM pairing_prompt_log
             WHERE agent_id = ?1 AND shown_at_ms > ?2",
            params![agent_id.as_bytes().as_slice(), agent_window_start],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    let global_prompts: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM pairing_prompt_log WHERE shown_at_ms > ?1",
            [global_window_start],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    Ok(!invite_seen
        && agent_prompts < MAX_PAIRING_PROMPTS_PER_AGENT
        && global_prompts < MAX_PAIRING_PROMPTS_PER_HOUR)
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::OsString,
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;
    use crate::open_store;

    static NEXT_DATABASE_ID: AtomicU64 = AtomicU64::new(1);

    struct TestDatabase(PathBuf);

    impl TestDatabase {
        fn new() -> Self {
            let directory = std::env::var_os("ASL_TEST_FIXTURE_BASE")
                .map(PathBuf::from)
                .unwrap_or_else(|| std::env::temp_dir().join("asl-test-fs"))
                .join("asl-store-paired-contacts");
            fs::create_dir_all(&directory).unwrap();
            let id = NEXT_DATABASE_ID.fetch_add(1, Ordering::Relaxed);
            Self(directory.join(format!("store-{}-{id}.sqlite3", std::process::id())))
        }
    }

    impl Drop for TestDatabase {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
            for suffix in ["-wal", "-shm"] {
                let mut sidecar = OsString::from(self.0.as_os_str());
                sidecar.push(suffix);
                let _ = fs::remove_file(PathBuf::from(sidecar));
            }
        }
    }

    #[test]
    fn accepted_invite_pins_agent_and_survives_reopen_without_granting_access() {
        let database = TestDatabase::new();
        let agent_id = AgentId([7; 32]);
        let invite_id = Id128([9; 16]);

        {
            let mut store = open_store(&database.0).unwrap();
            assert!(
                store
                    .consume_pairing_invite(agent_id, invite_id, 200_000, 100_000, true)
                    .unwrap()
            );
            assert!(store.is_paired_contact(agent_id).unwrap());
            assert!(!store.authorized_contacts().unwrap().contains(&agent_id));
        }

        let mut store = open_store(&database.0).unwrap();
        assert_eq!(
            store.paired_contacts().unwrap(),
            [PairedContact {
                agent_id,
                paired_at_ms: 100_000,
                invite_id
            }]
        );
        assert!(
            !store
                .consume_pairing_invite(agent_id, invite_id, 200_000, 110_000, true)
                .unwrap()
        );
        assert_eq!(store.paired_contacts().unwrap().len(), 1);
        assert!(store.remove_paired_contact(agent_id).unwrap());
        assert!(!store.is_paired_contact(agent_id).unwrap());
        assert!(
            !store
                .consume_pairing_invite(agent_id, invite_id, 200_000, 120_000, true)
                .unwrap()
        );
    }

    #[test]
    fn expired_invite_receipts_are_pruned_before_new_pairing() {
        let database = TestDatabase::new();
        let mut store = open_store(&database.0).unwrap();
        let first = AgentId([1; 32]);
        let second = AgentId([2; 32]);

        assert!(
            store
                .consume_pairing_invite(first, Id128([3; 16]), 110_000, 100_000, false)
                .unwrap()
        );
        assert!(
            store
                .consume_pairing_invite(second, Id128([4; 16]), 210_000, 110_000, true)
                .unwrap()
        );
        let expired_receipt_exists: bool = store
            .connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM pairing_invite_receipts WHERE invite_id = ?1
                 )",
                [Id128([3; 16]).as_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!expired_receipt_exists);
        assert!(!store.is_paired_contact(first).unwrap());
        assert!(store.is_paired_contact(second).unwrap());
    }

    #[test]
    fn rejected_invite_is_consumed_without_pinning_the_agent() {
        let database = TestDatabase::new();
        let mut store = open_store(&database.0).unwrap();
        let agent_id = AgentId([5; 32]);
        let invite_id = Id128([6; 16]);

        assert!(
            store
                .consume_pairing_invite(agent_id, invite_id, 200_000, 100_000, false)
                .unwrap()
        );
        assert!(!store.is_paired_contact(agent_id).unwrap());
        assert!(
            !store
                .consume_pairing_invite(agent_id, invite_id, 200_000, 110_000, true)
                .unwrap()
        );
    }

    #[test]
    fn pairing_prompt_history_limits_each_agent_and_the_global_hourly_budget() {
        let database = TestDatabase::new();
        let mut store = open_store(&database.0).unwrap();
        for value in 1..=20 {
            assert!(
                store
                    .allow_pairing_prompt(AgentId([value; 32]), Id128([value; 16]), 100_000,)
                    .unwrap()
            );
        }
        assert!(
            !store
                .allow_pairing_prompt(AgentId([21; 32]), Id128([21; 16]), 100_001)
                .unwrap()
        );
        assert!(
            !store
                .allow_pairing_prompt(AgentId([1; 32]), Id128([22; 16]), 100_001)
                .unwrap()
        );
        assert!(
            !store
                .allow_pairing_prompt(AgentId([22; 32]), Id128([1; 16]), 100_001)
                .unwrap()
        );
        assert!(
            store
                .allow_pairing_prompt(
                    AgentId([21; 32]),
                    Id128([21; 16]),
                    100_000 + PAIRING_PROMPT_GLOBAL_WINDOW_MS,
                )
                .unwrap()
        );
        assert!(
            store
                .allow_pairing_prompt(
                    AgentId([1; 32]),
                    Id128([23; 16]),
                    100_000 + PAIRING_PROMPT_AGENT_WINDOW_MS,
                )
                .unwrap()
        );
        drop(store);

        let mut reopened = open_store(&database.0).unwrap();
        assert!(
            !reopened
                .allow_pairing_prompt(
                    AgentId([1; 32]),
                    Id128([24; 16]),
                    100_000 + PAIRING_PROMPT_AGENT_WINDOW_MS + 1,
                )
                .unwrap()
        );
    }
}
