use rusqlite::{Connection, params};
use zeroize::Zeroizing;

use crate::{
    current_time_ms, database_error, group_observations::group_observation_days,
    inbound_observations::DAY_MS, read_setting, write_setting,
};

use super::ActDirection;

const ARCHIVE_KEY_SETTING: &str = "activity.act_archive_key.v1";
const SCRUB_PENDING_SETTING: &str = "activity.act_archive_scrub_pending.v1";
const INDEX_SCRUBBED_SETTING: &str = "activity.act_archive_index_scrubbed.v1";
#[cfg(windows)]
const ARCHIVE_KEY_PREFIX: &[u8] = b"ASL-ACT-ARCHIVE-KEY-DPAPI-v1\0";
const ARCHIVE_RETENTION_MS: i64 = 365 * DAY_MS;
#[cfg(windows)]
const REBUILD_BATCH: i64 = 128;

#[cfg(windows)]
use super::{decode_stored_body, semantic_tokens};

pub(super) struct ArchiveKey(Zeroizing<[u8; 32]>);

pub(super) fn initialize_index(
    connection: &Connection,
    now_ms: i64,
) -> Result<Option<ArchiveKey>, asl_types::error::AslError> {
    if now_ms < 0 {
        return Err(asl_types::error::AslError::InvalidMessage);
    }
    connection
        .pragma_update(None, "secure_delete", true)
        .map_err(database_error)?;
    if group_observation_days(connection)? == 0 {
        discard_index(connection)?;
        return Ok(None);
    }

    #[cfg(windows)]
    {
        if let Some(value_json) = read_setting(connection, ARCHIVE_KEY_SETTING)?
            && let Ok(key) = decode_key_setting(&value_json)
        {
            return Ok(Some(key));
        }

        let (key, value_json) = create_key_setting()?;
        discard_index(connection)?;
        mark_scrub_pending(connection)?;
        rebuild_index(connection, now_ms, &key)?;
        write_setting(connection, ARCHIVE_KEY_SETTING, &value_json, now_ms)?;
        Ok(Some(key))
    }

    #[cfg(not(windows))]
    {
        if read_setting(connection, ARCHIVE_KEY_SETTING)?.is_none() {
            discard_index(connection)?;
        }
        Ok(None)
    }
}

pub(super) fn read_key(
    connection: &Connection,
) -> Result<Option<ArchiveKey>, asl_types::error::AslError> {
    if group_observation_days(connection)? == 0 {
        return Ok(None);
    }

    #[cfg(windows)]
    {
        read_key_setting(connection)
    }

    #[cfg(not(windows))]
    {
        let _ = connection;
        Ok(None)
    }
}

pub(super) fn discard_index(connection: &Connection) -> Result<(), asl_types::error::AslError> {
    connection
        .pragma_update(None, "secure_delete", true)
        .map_err(database_error)?;
    let first_scrub = read_setting(connection, INDEX_SCRUBBED_SETTING)?.is_none();
    let removed = connection
        .execute("DELETE FROM conversation_act_semantic_index", [])
        .map_err(database_error)?;
    let removed_key = connection
        .execute("DELETE FROM settings WHERE key=?1", [ARCHIVE_KEY_SETTING])
        .map_err(database_error)?;

    if removed > 0 || removed_key > 0 || first_scrub {
        mark_scrub_pending(connection)?;
    }
    if first_scrub {
        write_setting(
            connection,
            INDEX_SCRUBBED_SETTING,
            "true",
            current_time_ms(),
        )?;
    }
    Ok(())
}

fn mark_scrub_pending(connection: &Connection) -> Result<(), asl_types::error::AslError> {
    write_setting(connection, SCRUB_PENDING_SETTING, "true", current_time_ms())
}

pub(super) fn finish_pending_scrub(
    connection: &Connection,
) -> Result<(), asl_types::error::AslError> {
    let Some(value) = read_setting(connection, SCRUB_PENDING_SETTING)? else {
        return Ok(());
    };
    let pending: bool =
        serde_json::from_str(&value).map_err(|_| asl_types::error::AslError::InvalidDatabase)?;
    if !pending {
        return Ok(());
    }
    let busy: i64 = connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
        .map_err(database_error)?;
    if busy != 0 {
        return Ok(());
    }
    connection
        .execute("DELETE FROM settings WHERE key=?1", [SCRUB_PENDING_SETTING])
        .map_err(database_error)?;
    Ok(())
}

pub(super) fn prune_expired_index(
    connection: &Connection,
    now_ms: i64,
    limit: Option<i64>,
) -> Result<usize, asl_types::error::AslError> {
    let removed = if let Some(limit) = limit {
        connection.execute(
            "DELETE FROM conversation_act_semantic_index WHERE rowid IN (
                SELECT rowid FROM conversation_act_semantic_index
                WHERE expires_at_ms<=?1 LIMIT ?2
             )",
            params![now_ms, limit],
        )
    } else {
        connection.execute(
            "DELETE FROM conversation_act_semantic_index WHERE expires_at_ms<=?1",
            [now_ms],
        )
    }
    .map_err(database_error)?;
    if removed > 0 {
        mark_scrub_pending(connection)?;
    }
    Ok(removed)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn index_body(
    connection: &Connection,
    key: Option<&ArchiveKey>,
    conversation_id: &str,
    act_id: [u8; 32],
    direction: ActDirection,
    act_kind: u16,
    received_at_ms: i64,
    body: &str,
) -> Result<(), asl_types::error::AslError> {
    let Some(key) = key else {
        return Ok(());
    };
    let expires_at_ms = received_at_ms.saturating_add(ARCHIVE_RETENTION_MS);
    let removed = connection
        .execute(
            "DELETE FROM conversation_act_semantic_index
             WHERE conversation_id=?1 AND act_id=?2",
            params![conversation_id, act_id.as_slice()],
        )
        .map_err(database_error)?;
    if removed > 0 {
        mark_scrub_pending(connection)?;
    }
    insert_tokens(
        connection,
        key,
        conversation_id,
        act_id,
        direction,
        act_kind,
        received_at_ms,
        expires_at_ms,
        body,
    )
}

pub(super) fn token_hash(key: &ArchiveKey, token: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(&key.0);
    hasher.update(b"ASL-ACT-SEMANTIC-TOKEN-v2\0");
    hasher.update(token.as_bytes());
    *hasher.finalize().as_bytes()
}

#[cfg(windows)]
fn create_key_setting() -> Result<(ArchiveKey, String), asl_types::error::AslError> {
    use rand::{TryRng, rngs::SysRng};

    let mut key = Zeroizing::new([0_u8; 32]);
    SysRng
        .try_fill_bytes(&mut key[..])
        .map_err(|_| asl_types::error::AslError::KeyProtectionFailed)?;

    let mut plaintext = Zeroizing::new(Vec::with_capacity(ARCHIVE_KEY_PREFIX.len() + key.len()));
    plaintext.extend_from_slice(ARCHIVE_KEY_PREFIX);
    plaintext.extend_from_slice(&key[..]);
    let protected = asl_policy::protect_secret(&plaintext)?;
    let value_json = serde_json::to_string(&hex::encode(protected))
        .map_err(|_| asl_types::error::AslError::InvalidDatabase)?;
    Ok((ArchiveKey(key), value_json))
}

#[cfg(windows)]
fn read_key_setting(
    connection: &Connection,
) -> Result<Option<ArchiveKey>, asl_types::error::AslError> {
    let Some(value_json) = read_setting(connection, ARCHIVE_KEY_SETTING)? else {
        return Ok(None);
    };
    decode_key_setting(&value_json).map(Some)
}

#[cfg(windows)]
fn decode_key_setting(value_json: &str) -> Result<ArchiveKey, asl_types::error::AslError> {
    let protected_hex: String = serde_json::from_str(value_json)
        .map_err(|_| asl_types::error::AslError::InvalidDatabase)?;
    let protected =
        hex::decode(protected_hex).map_err(|_| asl_types::error::AslError::InvalidDatabase)?;
    let plaintext = asl_policy::unprotect_secret(&protected)?;
    let key_bytes = plaintext
        .strip_prefix(ARCHIVE_KEY_PREFIX)
        .filter(|bytes| bytes.len() == 32)
        .ok_or(asl_types::error::AslError::InvalidDatabase)?;
    let key: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| asl_types::error::AslError::InvalidDatabase)?;
    Ok(ArchiveKey(Zeroizing::new(key)))
}

#[cfg(windows)]
fn rebuild_index(
    connection: &Connection,
    now_ms: i64,
    key: &ArchiveKey,
) -> Result<(), asl_types::error::AslError> {
    let mut after_rowid = 0_i64;
    loop {
        let batch = {
            let mut statement = connection
                .prepare(
                    "SELECT rowid,conversation_id,act_id,direction,act_kind,ciphertext,
                            received_at_ms
                     FROM conversation_act_events
                     WHERE rowid>?1 AND expires_at_ms>?2
                     ORDER BY rowid LIMIT ?3",
                )
                .map_err(database_error)?;
            statement
                .query_map(params![after_rowid, now_ms, REBUILD_BATCH], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                })
                .map_err(database_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(database_error)?
        };
        if batch.is_empty() {
            break;
        }

        for (rowid, conversation_id, act_id, direction, act_kind, ciphertext, received_at_ms) in
            batch
        {
            after_rowid = rowid;
            let Ok(Some(body)) = decode_stored_body(&ciphertext) else {
                continue;
            };
            let body = Zeroizing::new(body);
            let direction = match direction.as_str() {
                "in" => ActDirection::In,
                "out" => ActDirection::Out,
                _ => return Err(asl_types::error::AslError::InvalidDatabase),
            };
            let act_id: [u8; 32] = act_id
                .try_into()
                .map_err(|_| asl_types::error::AslError::InvalidDatabase)?;
            let act_kind =
                u16::try_from(act_kind).map_err(|_| asl_types::error::AslError::InvalidDatabase)?;
            let expires_at_ms = received_at_ms.saturating_add(ARCHIVE_RETENTION_MS);
            if expires_at_ms <= now_ms {
                continue;
            }
            insert_tokens(
                connection,
                key,
                &conversation_id,
                act_id,
                direction,
                act_kind,
                received_at_ms,
                expires_at_ms,
                body.as_str(),
            )?;
        }
    }
    Ok(())
}

#[cfg(windows)]
#[allow(clippy::too_many_arguments)]
fn insert_tokens(
    connection: &Connection,
    key: &ArchiveKey,
    conversation_id: &str,
    act_id: [u8; 32],
    direction: ActDirection,
    act_kind: u16,
    received_at_ms: i64,
    expires_at_ms: i64,
    body: &str,
) -> Result<(), asl_types::error::AslError> {
    for token in semantic_tokens(body) {
        connection
            .execute(
                "INSERT OR REPLACE INTO conversation_act_semantic_index(
                    conversation_id,act_id,token_hash,direction,act_kind,
                    received_at_ms,expires_at_ms
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![
                    conversation_id,
                    act_id.as_slice(),
                    token_hash(key, &token).as_slice(),
                    direction.as_str(),
                    i64::from(act_kind),
                    received_at_ms,
                    expires_at_ms,
                ],
            )
            .map_err(database_error)?;
    }
    Ok(())
}

#[cfg(not(windows))]
fn insert_tokens(
    _: &Connection,
    _: &ArchiveKey,
    _: &str,
    _: [u8; 32],
    _: ActDirection,
    _: u16,
    _: i64,
    _: i64,
    _: &str,
) -> Result<(), asl_types::error::AslError> {
    Ok(())
}
