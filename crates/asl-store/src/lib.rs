use std::{
    io,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use asl_types::error::AslError;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

pub mod act_history;
pub mod avatar_publication;
pub mod avatar_receipts;
pub mod budgets;
pub mod capacity;
pub mod chain;
pub mod contact_bindings;
pub mod contact_invites;
pub mod contact_policy;
pub mod conversation;
pub mod dashboard;
pub mod dht_cache;
pub mod diagnostics;
pub mod evidence;
pub mod group_access;
mod group_observations;
pub mod group_state;
pub mod group_topology;
mod host_inbox;
pub mod inbound_observations;
pub mod mailbox;
pub mod mcp_recovery;
pub mod migration;
pub mod network_privacy;
pub mod paired_contacts;
pub mod profile_lookup;
pub mod public_profile;
mod publication;
mod remote_profiles;
pub mod resources;
mod retention;
pub mod search;
pub mod semantic_context;
mod transfer_peers;
pub mod transfers;

const SCHEMA_VERSION: i64 = 50;
const SCHEMA_V1: &str = include_str!("../../../specs/schema-v1.sql");
const SCHEMA_V2: &str = include_str!("../../../specs/schema-v2.sql");
const SCHEMA_V3: &str = include_str!("../../../specs/schema-v3.sql");
const SCHEMA_V4: &str = include_str!("../../../specs/schema-v4.sql");
const SCHEMA_V5: &str = include_str!("../../../specs/schema-v5.sql");
const SCHEMA_V6: &str = include_str!("../../../specs/schema-v6.sql");
const SCHEMA_V7: &str = include_str!("../../../specs/schema-v7.sql");
const SCHEMA_V8: &str = include_str!("../../../specs/schema-v8.sql");
const SCHEMA_V9: &str = include_str!("../../../specs/schema-v9.sql");
const SCHEMA_V10: &str = include_str!("../../../specs/schema-v10.sql");
const SCHEMA_V11: &str = include_str!("../../../specs/schema-v11.sql");
const SCHEMA_V12: &str = include_str!("../../../specs/schema-v12.sql");
const SCHEMA_V13: &str = include_str!("../../../specs/schema-v13.sql");
const SCHEMA_V14: &str = include_str!("../../../specs/schema-v14.sql");
const SCHEMA_V15: &str = include_str!("../../../specs/schema-v15.sql");
const SCHEMA_V16: &str = include_str!("../../../specs/schema-v16.sql");
const SCHEMA_V17: &str = include_str!("../../../specs/schema-v17.sql");
const SCHEMA_V18: &str = include_str!("../../../specs/schema-v18.sql");
const SCHEMA_V19: &str = include_str!("../../../specs/schema-v19.sql");
const SCHEMA_V20: &str = include_str!("../../../specs/schema-v20.sql");
const SCHEMA_V21: &str = include_str!("../../../specs/schema-v21.sql");
const SCHEMA_V22: &str = include_str!("../../../specs/schema-v22.sql");
const SCHEMA_V23: &str = include_str!("../../../specs/schema-v23.sql");
const SCHEMA_V24: &str = include_str!("../../../specs/schema-v24.sql");
const SCHEMA_V25: &str = include_str!("../../../specs/schema-v25.sql");
const SCHEMA_V26: &str = include_str!("../../../specs/schema-v26.sql");
const SCHEMA_V27: &str = include_str!("../../../specs/schema-v27.sql");
const SCHEMA_V28: &str = include_str!("../../../specs/schema-v28.sql");
const SCHEMA_V29: &str = include_str!("../../../specs/schema-v29.sql");
const SCHEMA_V30: &str = include_str!("../../../specs/schema-v30.sql");
const SCHEMA_V31: &str = include_str!("../../../specs/schema-v31.sql");
const SCHEMA_V32: &str = include_str!("../../../specs/schema-v32.sql");
const SCHEMA_V33: &str = include_str!("../../../specs/schema-v33.sql");
const SCHEMA_V34: &str = include_str!("../../../specs/schema-v34.sql");
const SCHEMA_V35: &str = include_str!("../../../specs/schema-v35.sql");
const SCHEMA_V36: &str = include_str!("../../../specs/schema-v36.sql");
const SCHEMA_V37: &str = include_str!("../../../specs/schema-v37.sql");
const SCHEMA_V38: &str = include_str!("../../../specs/schema-v38.sql");
const SCHEMA_V39: &str = include_str!("../../../specs/schema-v39.sql");
const SCHEMA_V40: &str = include_str!("../../../specs/schema-v40.sql");
const SCHEMA_V41: &str = include_str!("../../../specs/schema-v41.sql");
const SCHEMA_V42: &str = include_str!("../../../specs/schema-v42.sql");
const SCHEMA_V43: &str = include_str!("../../../specs/schema-v43.sql");
const SCHEMA_V44: &str = include_str!("../../../specs/schema-v44.sql");
const SCHEMA_V45: &str = include_str!("../../../specs/schema-v45.sql");
const SCHEMA_V46: &str = include_str!("../../../specs/schema-v46.sql");
const SCHEMA_V47: &str = include_str!("../../../specs/schema-v47.sql");
const SCHEMA_V48: &str = include_str!("../../../specs/schema-v48.sql");
const SCHEMA_V49: &str = include_str!("../../../specs/schema-v49.sql");
const SCHEMA_V50: &str = include_str!("../../../specs/schema-v50.sql");

pub struct Store {
    connection: Connection,
}

impl Store {
    pub fn schema_version(&self) -> u32 {
        SCHEMA_VERSION as u32
    }

    pub fn policy_revision(&self) -> Result<u64, AslError> {
        let revision: i64 = self
            .connection
            .query_row(
                "SELECT revision FROM policy_state WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        u64::try_from(revision).map_err(|_| AslError::InvalidDatabase)
    }

    pub fn get_setting(&self, key: &str) -> Result<Option<String>, AslError> {
        read_setting(&self.connection, key)
    }

    pub fn take_setting(&self, key: &str) -> Result<Option<String>, AslError> {
        self.connection
            .query_row(
                "DELETE FROM settings WHERE key = ?1 RETURNING value_json",
                [key],
                |row| row.get(0),
            )
            .optional()
            .map_err(database_error)
    }

    pub fn set_setting(
        &self,
        key: &str,
        value_json: &str,
        updated_at_ms: i64,
    ) -> Result<(), AslError> {
        write_setting(&self.connection, key, value_json, updated_at_ms)
    }

    pub fn model_provider_approval(&self, id: &str) -> Result<Option<String>, AslError> {
        self.get_setting(&format!("agent.model_provider_approval_v1.{id}"))?
            .map(|value| serde_json::from_str::<Option<String>>(&value))
            .transpose()
            .map(Option::flatten)
            .map_err(|_| AslError::InvalidDatabase)
    }

    pub fn set_model_provider_approval(
        &self,
        id: &str,
        fingerprint: Option<&str>,
    ) -> Result<(), AslError> {
        let value = serde_json::to_string(&fingerprint).map_err(|_| AslError::InvalidMessage)?;
        self.set_setting(
            &format!("agent.model_provider_approval_v1.{id}"),
            &value,
            current_time_ms(),
        )
    }
}

fn read_setting(connection: &Connection, key: &str) -> Result<Option<String>, AslError> {
    connection
        .query_row(
            "SELECT value_json FROM settings WHERE key = ?1",
            [key],
            |row| row.get(0),
        )
        .optional()
        .map_err(database_error)
}

fn write_setting(
    connection: &Connection,
    key: &str,
    value_json: &str,
    updated_at_ms: i64,
) -> Result<(), AslError> {
    connection
        .execute(
            "INSERT INTO settings(key, value_json, updated_at_ms)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(key) DO UPDATE SET
                     value_json = excluded.value_json,
                     updated_at_ms = excluded.updated_at_ms",
            params![key, value_json, updated_at_ms],
        )
        .map_err(database_error)?;
    Ok(())
}

pub fn open_store_read_only(path: &Path) -> Result<Store, AslError> {
    let connection = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(database_error)?;
    connection
        .busy_timeout(std::time::Duration::from_millis(250))
        .map_err(database_error)?;
    if read_schema_version(&connection)? != Some(SCHEMA_VERSION) {
        return Err(AslError::UnsupportedSchemaVersion);
    }
    Ok(Store { connection })
}

pub fn open_store(path: &Path) -> Result<Store, AslError> {
    let mut connection = Connection::open(path).map_err(database_error)?;
    configure_connection(&connection)?;

    {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let version = read_schema_version(&transaction)?.unwrap_or(0);
        let now = current_time_ms();
        if version == 0 {
            apply_migration_in_transaction(&transaction, SCHEMA_V1, 1, now)?;
        }
        if version < 2 {
            apply_migration_in_transaction(&transaction, SCHEMA_V2, 2, now)?;
        }
        if version < 3 {
            apply_migration_in_transaction(&transaction, SCHEMA_V3, 3, now)?;
        }
        if version < 4 {
            apply_migration_in_transaction(&transaction, SCHEMA_V4, 4, now)?;
        }
        if version < 5 {
            apply_migration_in_transaction(&transaction, SCHEMA_V5, 5, now)?;
        }
        if version < 6 {
            apply_migration_in_transaction(&transaction, SCHEMA_V6, 6, now)?;
        }
        if version < 7 {
            apply_migration_in_transaction(&transaction, SCHEMA_V7, 7, now)?;
        }
        if version < 8 {
            apply_migration_in_transaction(&transaction, SCHEMA_V8, 8, now)?;
        }
        if version < 9 {
            apply_migration_in_transaction(&transaction, SCHEMA_V9, 9, now)?;
        }
        if version < 10 {
            apply_migration_in_transaction(&transaction, SCHEMA_V10, 10, now)?;
        }
        if version < 11 {
            apply_migration_in_transaction(&transaction, SCHEMA_V11, 11, now)?;
        }
        if version < 12 {
            apply_migration_in_transaction(&transaction, SCHEMA_V12, 12, now)?;
        }
        if version < 13 {
            apply_migration_in_transaction(&transaction, SCHEMA_V13, 13, now)?;
        }
        if version < 14 {
            apply_migration_in_transaction(&transaction, SCHEMA_V14, 14, now)?;
        }
        if version < 15 {
            apply_migration_in_transaction(&transaction, SCHEMA_V15, 15, now)?;
        }
        if version < 16 {
            apply_migration_in_transaction(&transaction, SCHEMA_V16, 16, now)?;
        }
        if version < 17 {
            apply_migration_in_transaction(&transaction, SCHEMA_V17, 17, now)?;
        }
        if version < 18 {
            apply_migration_in_transaction(&transaction, SCHEMA_V18, 18, now)?;
        }
        if version < 19 {
            apply_migration_in_transaction(&transaction, SCHEMA_V19, 19, now)?;
        }
        if version < 20 {
            apply_migration_in_transaction(&transaction, SCHEMA_V20, 20, now)?;
        }
        if version < 21 {
            apply_migration_in_transaction(&transaction, SCHEMA_V21, 21, now)?;
        }
        if version < 22 {
            apply_migration_in_transaction(&transaction, SCHEMA_V22, 22, now)?;
        }
        if version < 23 {
            apply_migration_in_transaction(&transaction, SCHEMA_V23, 23, now)?;
        }
        if version < 24 {
            apply_migration_in_transaction(&transaction, SCHEMA_V24, 24, now)?;
        }
        if version < 25 {
            apply_migration_in_transaction(&transaction, SCHEMA_V25, 25, now)?;
        }
        if version < 26 {
            apply_migration_in_transaction(&transaction, SCHEMA_V26, 26, now)?;
        }
        if version < 27 {
            apply_migration_in_transaction(&transaction, SCHEMA_V27, 27, now)?;
        }
        if version < 28 {
            apply_migration_in_transaction(&transaction, SCHEMA_V28, 28, now)?;
        }
        if version < 29 {
            apply_migration_in_transaction(&transaction, SCHEMA_V29, 29, now)?;
        }
        if version < 30 {
            apply_migration_in_transaction(&transaction, SCHEMA_V30, 30, now)?;
        }
        if version < 31 {
            apply_migration_in_transaction(&transaction, SCHEMA_V31, 31, now)?;
        }
        if version < 32 {
            apply_migration_in_transaction(&transaction, SCHEMA_V32, 32, now)?;
        }
        if version < 33 {
            apply_migration_in_transaction(&transaction, SCHEMA_V33, 33, now)?;
        }
        if version < 34 {
            apply_migration_in_transaction(&transaction, SCHEMA_V34, 34, now)?;
        }
        if version < 35 {
            apply_migration_in_transaction(&transaction, SCHEMA_V35, 35, now)?;
        }
        if version < 36 {
            apply_migration_in_transaction(&transaction, SCHEMA_V36, 36, now)?;
        }
        if version < 37 {
            apply_migration_in_transaction(&transaction, SCHEMA_V37, 37, now)?;
        }
        if version < 38 {
            apply_migration_in_transaction(&transaction, SCHEMA_V38, 38, now)?;
        }
        if version < 39 {
            apply_migration_in_transaction(&transaction, SCHEMA_V39, 39, now)?;
        }
        if version < 40 {
            apply_migration_in_transaction(&transaction, SCHEMA_V40, 40, now)?;
        }
        if version < 41 {
            apply_migration_in_transaction(&transaction, SCHEMA_V41, 41, now)?;
        }
        if version < 42 {
            apply_migration_in_transaction(&transaction, SCHEMA_V42, 42, now)?;
        }
        if version < 43 {
            apply_migration_in_transaction(&transaction, SCHEMA_V43, 43, now)?;
        }
        if version < 44 {
            apply_migration_in_transaction(&transaction, SCHEMA_V44, 44, now)?;
        }
        if version < 45 {
            apply_migration_in_transaction(&transaction, SCHEMA_V45, 45, now)?;
        }
        if version < 46 {
            apply_migration_in_transaction(&transaction, SCHEMA_V46, 46, now)?;
        }
        if version < 47 {
            apply_migration_in_transaction(&transaction, SCHEMA_V47, 47, now)?;
        }
        if version < 48 {
            apply_migration_in_transaction(&transaction, SCHEMA_V48, 48, now)?;
        }
        if version < 49 {
            apply_migration_in_transaction(&transaction, SCHEMA_V49, 49, now)?;
        }
        if version < 50 {
            apply_migration_in_transaction(&transaction, SCHEMA_V50, 50, now)?;
        }
        validate_existing_schema(&transaction)?;
        transaction.commit().map_err(database_error)?;
    }

    Ok(Store { connection })
}

fn configure_connection(connection: &Connection) -> Result<(), AslError> {
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(database_error)?;
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .map_err(database_error)?;
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(database_error)?;

    let foreign_keys: i64 = connection
        .pragma_query_value(None, "foreign_keys", |row| row.get(0))
        .map_err(database_error)?;
    let journal_mode: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(database_error)?;
    let synchronous: i64 = connection
        .pragma_query_value(None, "synchronous", |row| row.get(0))
        .map_err(database_error)?;

    if foreign_keys != 1 || !journal_mode.eq_ignore_ascii_case("wal") || synchronous != 2 {
        return Err(AslError::InvalidDatabase);
    }
    Ok(())
}

fn read_schema_version(connection: &Connection) -> Result<Option<i64>, AslError> {
    let has_migrations: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_schema
                WHERE type = 'table' AND name = 'schema_migrations'
            )",
            [],
            |row| row.get(0),
        )
        .map_err(database_error)?;

    if !has_migrations {
        let has_user_objects: bool = connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_schema
                    WHERE name NOT LIKE 'sqlite_%'
                )",
                [],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        return if has_user_objects {
            Err(AslError::InvalidDatabase)
        } else {
            Ok(None)
        };
    }

    let mut statement = connection
        .prepare("SELECT version FROM schema_migrations ORDER BY version")
        .map_err(database_error)?;
    let versions = statement
        .query_map([], |row| row.get::<_, i64>(0))
        .map_err(database_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(database_error)?;

    if versions.iter().any(|version| *version > SCHEMA_VERSION) {
        return Err(AslError::UnsupportedSchemaVersion);
    }
    if versions.is_empty() || versions.iter().copied().ne(1..=versions.len() as i64) {
        return Err(AslError::InvalidDatabase);
    }
    Ok(versions.last().copied())
}

fn apply_migration_in_transaction(
    transaction: &Transaction<'_>,
    migration_sql: &str,
    version: i64,
    applied_at_ms: i64,
) -> Result<(), AslError> {
    if version == 50 {
        ensure_v50_outbox_column(
            transaction,
            "delivery_kind",
            "TEXT NOT NULL DEFAULT 'forward' \
             CHECK(delivery_kind IN ('forward','owner_relay','owner_reply'))",
        )?;
        ensure_v50_outbox_column(
            transaction,
            "content_id",
            "BLOB CHECK(content_id IS NULL OR length(content_id)=32)",
        )?;
        ensure_v50_outbox_column(
            transaction,
            "target_peer_id",
            "TEXT CHECK(target_peer_id IS NULL OR length(target_peer_id) BETWEEN 1 AND 128)",
        )?;
    }
    transaction
        .execute_batch(migration_sql)
        .map_err(database_error)?;
    transaction
        .execute(
            "INSERT INTO schema_migrations(version, applied_at_ms) VALUES (?1, ?2)",
            params![version, applied_at_ms],
        )
        .map_err(database_error)?;
    Ok(())
}

fn ensure_v50_outbox_column(
    transaction: &Transaction<'_>,
    column: &str,
    definition: &str,
) -> Result<(), AslError> {
    let exists = {
        let mut statement = transaction
            .prepare("PRAGMA table_info(mls_shard_forward_outbox)")
            .map_err(database_error)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(database_error)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(database_error)?
            .iter()
            .any(|name| name == column)
    };
    if !exists {
        transaction
            .execute(
                &format!("ALTER TABLE mls_shard_forward_outbox ADD COLUMN {column} {definition}"),
                [],
            )
            .map_err(database_error)?;
    }
    Ok(())
}

fn validate_existing_schema(connection: &Connection) -> Result<(), AslError> {
    let policy_revision: Option<i64> = connection
        .query_row(
            "SELECT revision FROM policy_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(database_error)?;
    if !matches!(policy_revision, Some(revision) if revision >= 1) {
        return Err(AslError::InvalidDatabase);
    }

    let mut statement = connection
        .prepare("PRAGMA foreign_key_check")
        .map_err(database_error)?;
    if statement.exists([]).map_err(database_error)? {
        return Err(AslError::InvalidDatabase);
    }
    Ok(())
}

fn current_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

fn database_error(error: rusqlite::Error) -> AslError {
    AslError::Io(io::Error::other(error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        ffi::OsString,
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_DATABASE_ID: AtomicU64 = AtomicU64::new(1);

    struct TestDatabase {
        path: PathBuf,
    }

    impl TestDatabase {
        fn new() -> Self {
            let directory = std::env::var_os("ASL_TEST_FIXTURE_BASE")
                .map(PathBuf::from)
                .unwrap_or_else(|| std::env::temp_dir().join("asl-test-fs"))
                .join("asl-store");
            fs::create_dir_all(&directory).unwrap();
            let id = NEXT_DATABASE_ID.fetch_add(1, Ordering::Relaxed);
            let path = directory.join(format!("store-{}-{id}.sqlite3", std::process::id()));
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDatabase {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
            for suffix in ["-wal", "-shm"] {
                let mut sidecar = OsString::from(self.path.as_os_str());
                sidecar.push(suffix);
                let _ = fs::remove_file(PathBuf::from(sidecar));
            }
        }
    }

    #[test]
    fn initializes_and_reopens_without_reapplying_migrations() {
        let database = TestDatabase::new();

        {
            let store = open_store(database.path()).unwrap();
            assert_eq!(store.schema_version(), SCHEMA_VERSION as u32);
            assert_eq!(store.policy_revision().unwrap(), 1);
        }

        let store = open_store(database.path()).unwrap();
        assert_eq!(store.schema_version(), SCHEMA_VERSION as u32);
        assert_eq!(store.policy_revision().unwrap(), 1);

        let migration_count: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(migration_count, SCHEMA_VERSION);

        let integrity: String = store
            .connection
            .pragma_query_value(None, "integrity_check", |row| row.get(0))
            .unwrap();
        assert_eq!(integrity, "ok");
    }

    #[test]
    fn upgrades_v4_with_conversation_budget_and_pairing_storage() {
        let database = TestDatabase::new();
        let mut connection = Connection::open(database.path()).unwrap();
        let transaction = connection.transaction().unwrap();
        for (migration, version) in [
            (SCHEMA_V1, 1),
            (SCHEMA_V2, 2),
            (SCHEMA_V3, 3),
            (SCHEMA_V4, 4),
        ] {
            apply_migration_in_transaction(&transaction, migration, version, 0).unwrap();
        }
        transaction.commit().unwrap();
        drop(connection);

        let store = open_store(database.path()).unwrap();
        assert_eq!(store.schema_version(), SCHEMA_VERSION as u32);
        let conversations_exist: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
             WHERE type='table' AND name='direct_inbound_conversations'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let paired_contacts_exist: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE type='table' AND name='paired_contacts'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let invite_receipts_exist: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE type='table' AND name='pairing_invite_receipts'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let prompt_log_exists: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE type='table' AND name='pairing_prompt_log'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(conversations_exist, 1);
        assert_eq!(paired_contacts_exist, 1);
        assert_eq!(invite_receipts_exist, 1);
        assert_eq!(prompt_log_exists, 1);
    }

    #[test]
    fn upgrades_v16_with_device_bound_upload_approval_columns() {
        let database = TestDatabase::new();
        let mut connection = Connection::open(database.path()).unwrap();
        let transaction = connection.transaction().unwrap();
        for (migration, version) in [
            (SCHEMA_V1, 1),
            (SCHEMA_V2, 2),
            (SCHEMA_V3, 3),
            (SCHEMA_V4, 4),
            (SCHEMA_V5, 5),
            (SCHEMA_V6, 6),
            (SCHEMA_V7, 7),
            (SCHEMA_V8, 8),
            (SCHEMA_V9, 9),
            (SCHEMA_V10, 10),
            (SCHEMA_V11, 11),
            (SCHEMA_V12, 12),
            (SCHEMA_V13, 13),
            (SCHEMA_V14, 14),
            (SCHEMA_V15, 15),
            (SCHEMA_V16, 16),
        ] {
            apply_migration_in_transaction(&transaction, migration, version, 0).unwrap();
        }
        transaction.commit().unwrap();
        drop(connection);

        let store = open_store(database.path()).unwrap();
        assert_eq!(store.schema_version(), SCHEMA_VERSION as u32);
        let columns: Vec<String> = store
            .connection
            .prepare("PRAGMA table_info(transfer_consents)")
            .unwrap()
            .query_map([], |row| row.get(1))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(columns.iter().any(|column| column == "target_peer_id"));
        assert!(columns.iter().any(|column| column == "upload_filename"));
        assert!(columns.iter().any(|column| column == "upload_size"));
        let observation_table_exists: bool = store
            .connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema
                 WHERE type='table' AND name='direct_inbound_observations')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(observation_table_exists);
        let index_exists: bool = store
            .connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema
                 WHERE type='index' AND name='upload_consent_lookup')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(index_exists);
    }

    #[test]
    fn configures_wal_foreign_keys_and_full_synchronous_mode() {
        let database = TestDatabase::new();
        let store = open_store(database.path()).unwrap();

        let foreign_keys: i64 = store
            .connection
            .pragma_query_value(None, "foreign_keys", |row| row.get(0))
            .unwrap();
        let journal_mode: String = store
            .connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .unwrap();
        let synchronous: i64 = store
            .connection
            .pragma_query_value(None, "synchronous", |row| row.get(0))
            .unwrap();

        assert_eq!(foreign_keys, 1);
        assert_eq!(journal_mode.to_ascii_lowercase(), "wal");
        assert_eq!(synchronous, 2);
    }

    #[test]
    fn settings_use_bound_parameters() {
        let database = TestDatabase::new();
        let store = open_store(database.path()).unwrap();
        let key = "key'); DROP TABLE schema_migrations; --";
        let value = r#"{"local":"value'); DROP TABLE settings; --"}"#;

        store.set_setting(key, value, 42).unwrap();

        assert_eq!(store.get_setting(key).unwrap().as_deref(), Some(value));
        assert_eq!(store.schema_version(), SCHEMA_VERSION as u32);
    }

    #[test]
    fn rejects_unknown_schema_without_modifying_its_tables() {
        let database = TestDatabase::new();
        let connection = Connection::open(database.path()).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE schema_migrations(
                    version INTEGER PRIMARY KEY,
                    applied_at_ms INTEGER NOT NULL
                 );
                 CREATE TABLE preserved(value INTEGER);
                 INSERT INTO preserved(value) VALUES (7);",
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO schema_migrations(version, applied_at_ms) VALUES (?1, ?1)",
                [SCHEMA_VERSION + 1],
            )
            .unwrap();
        drop(connection);

        assert!(matches!(
            open_store(database.path()),
            Err(AslError::UnsupportedSchemaVersion)
        ));

        let connection = Connection::open(database.path()).unwrap();
        let preserved: i64 = connection
            .query_row("SELECT value FROM preserved", [], |row| row.get(0))
            .unwrap();
        assert_eq!(preserved, 7);
        let asl_tables: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE type = 'table' AND name = 'agents'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(asl_tables, 0);
    }

    #[test]
    fn rejects_partial_database_without_rebuilding_it() {
        let database = TestDatabase::new();
        let connection = Connection::open(database.path()).unwrap();
        connection
            .execute_batch("CREATE TABLE user_data(value INTEGER);")
            .unwrap();
        drop(connection);

        assert!(matches!(
            open_store(database.path()),
            Err(AslError::InvalidDatabase)
        ));

        let connection = Connection::open(database.path()).unwrap();
        let table_exists: bool = connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_schema
                    WHERE type = 'table' AND name = 'user_data'
                )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(table_exists);
    }

    #[test]
    fn migration_failure_rolls_back_the_complete_v1_schema() {
        let mut connection = Connection::open_in_memory().unwrap();
        let failing_migration = format!("{SCHEMA_V1}\nINSERT INTO absent_table VALUES (1);");
        {
            let tx = connection.transaction().unwrap();
            assert!(apply_migration_in_transaction(&tx, &failing_migration, 1, 10).is_err());
        }

        let user_tables: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE type IN ('table', 'view', 'trigger') AND name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(user_tables, 0);
    }

    #[test]
    fn upgrades_an_existing_v1_store_without_losing_settings() {
        let database = TestDatabase::new();
        let mut old = Connection::open(database.path()).unwrap();
        let tx = old.transaction().unwrap();
        apply_migration_in_transaction(&tx, SCHEMA_V1, 1, 0).unwrap();
        tx.execute("INSERT INTO settings VALUES ('keep', 'true', 0)", [])
            .unwrap();
        tx.commit().unwrap();
        drop(old);
        let upgraded = open_store(database.path()).unwrap();
        assert_eq!(
            upgraded.get_setting("keep").unwrap().as_deref(),
            Some("true")
        );
        assert_eq!(upgraded.schema_version(), SCHEMA_VERSION as u32);
    }
}
