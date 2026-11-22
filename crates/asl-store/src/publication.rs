use asl_types::{error::AslError, ids::AgentId};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

use crate::{Store, current_time_ms, database_error};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PublicationSequenceCursor {
    version: u8,
    next_sequence: u64,
    exhausted: bool,
}

impl Store {
    /// Atomically reserves a persistent device-directory publication sequence.
    /// `minimum` accounts for records supplied outside this process.
    pub fn reserve_device_directory_sequence(
        &mut self,
        agent_id: AgentId,
        minimum: u64,
    ) -> Result<u64, AslError> {
        self.reserve_publication_sequence("device-directory", agent_id, minimum)
    }

    pub fn reserve_profile_sequence(&mut self, agent_id: AgentId) -> Result<u64, AslError> {
        self.reserve_publication_sequence("profile", agent_id, 0)
    }

    fn reserve_publication_sequence(
        &mut self,
        namespace: &str,
        agent_id: AgentId,
        minimum: u64,
    ) -> Result<u64, AslError> {
        let key = format!(
            "{namespace}-publication-sequence-v1/{}",
            bs58::encode(agent_id.as_bytes()).into_string()
        );
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let previous = transaction
            .query_row(
                "SELECT value_json FROM settings WHERE key = ?1",
                [&key],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(database_error)?
            .map(|value| {
                let cursor: PublicationSequenceCursor =
                    serde_json::from_str(&value).map_err(|_| AslError::InvalidDatabase)?;
                if cursor.version != 1 {
                    return Err(AslError::InvalidDatabase);
                }
                Ok(cursor)
            })
            .transpose()?;

        if previous.as_ref().is_some_and(|cursor| cursor.exhausted) {
            return Err(AslError::PolicyVersionConflict);
        }
        let sequence = previous.map_or(minimum, |cursor| cursor.next_sequence.max(minimum));
        let (next_sequence, exhausted) = match sequence.checked_add(1) {
            Some(next) => (next, false),
            None => (sequence, true),
        };
        let value = serde_json::to_string(&PublicationSequenceCursor {
            version: 1,
            next_sequence,
            exhausted,
        })
        .map_err(|_| AslError::InvalidDatabase)?;
        transaction
            .execute(
                "INSERT INTO settings(key, value_json, updated_at_ms)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(key) DO UPDATE SET
                    value_json = excluded.value_json,
                    updated_at_ms = excluded.updated_at_ms",
                params![key, value, current_time_ms()],
            )
            .map_err(database_error)?;
        transaction.commit().map_err(database_error)?;
        Ok(sequence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::open_store;

    #[test]
    fn directory_sequence_cursor_persists_and_respects_external_floor() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("asl.sqlite3");
        let agent = AgentId([7; 32]);

        let mut store = open_store(&database).unwrap();
        assert_eq!(
            store.reserve_device_directory_sequence(agent, 41).unwrap(),
            41
        );
        assert_eq!(
            store.reserve_device_directory_sequence(agent, 0).unwrap(),
            42
        );
        drop(store);

        let mut reopened = open_store(&database).unwrap();
        assert_eq!(
            reopened
                .reserve_device_directory_sequence(agent, 10)
                .unwrap(),
            43
        );
        assert_eq!(
            reopened
                .reserve_device_directory_sequence(agent, 100)
                .unwrap(),
            100
        );
        assert_eq!(
            reopened
                .reserve_device_directory_sequence(agent, 0)
                .unwrap(),
            101
        );
    }

    #[test]
    fn directory_sequence_cursor_exhaustion_never_wraps() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("asl.sqlite3");
        let agent = AgentId([9; 32]);
        let mut store = open_store(&database).unwrap();

        assert_eq!(
            store
                .reserve_device_directory_sequence(agent, u64::MAX)
                .unwrap(),
            u64::MAX
        );
        assert!(matches!(
            store.reserve_device_directory_sequence(agent, 0),
            Err(AslError::PolicyVersionConflict)
        ));
    }

    #[test]
    fn directory_sequence_cursors_are_isolated_by_agent() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("asl.sqlite3");
        let mut store = open_store(&database).unwrap();

        assert_eq!(
            store
                .reserve_device_directory_sequence(AgentId([1; 32]), 3)
                .unwrap(),
            3
        );
        assert_eq!(
            store
                .reserve_device_directory_sequence(AgentId([2; 32]), 3)
                .unwrap(),
            3
        );
    }
}
