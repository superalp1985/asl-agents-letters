use asl_types::{error::AslError, ids::Id128};
use rusqlite::params;

use crate::{
    Store, database_error, group_observations::group_observation_days, inbound_observations::DAY_MS,
};

const MAX_BODY_BYTES: usize = 32 * 1024;
const MAX_ROWS: u32 = 1_000;
const DPAPI_PREFIX: &[u8] = b"ASL-ACT-BODY-DPAPI-v1\0";
const UTF8_PREFIX: &[u8] = b"ASL-ACT-BODY-UTF8-v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActDirection {
    In,
    Out,
}

impl ActDirection {
    fn as_str(self) -> &'static str {
        match self {
            Self::In => "in",
            Self::Out => "out",
        }
    }
}

#[derive(Clone, Copy)]
pub struct ActHistoryRecord<'a> {
    pub conversation_id: &'a str,
    pub message_id: Id128,
    pub mls_epoch: u64,
    pub direction: ActDirection,
    pub act_kind: u16,
    pub reply_to: Option<Id128>,
    pub causal_root: Id128,
    pub body: Option<&'a str>,
    pub now_ms: u64,
    pub expires_at_ms: u64,
}

pub struct StoredActHistory<'a> {
    pub conversation_id: &'a str,
    pub act_id: [u8; 32],
    pub mls_epoch: u64,
    pub direction: ActDirection,
    pub act_kind: u16,
    pub causal_root: [u8; 32],
    pub reply_to: Option<[u8; 32]>,
    pub body: Option<&'a str>,
    pub received_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActHistoryRow {
    pub conversation_id: String,
    pub direction: ActDirection,
    pub act_kind: u16,
    pub body: Option<String>,
    pub created_at_ms: i64,
}

impl Store {
    pub fn record_act_history(&mut self, record: ActHistoryRecord<'_>) -> Result<(), AslError> {
        validate_record(record)?;
        let days = group_observation_days(&self.connection)?;
        if days == 0 {
            return Ok(());
        }
        let body = protect_body(record.body.unwrap_or_default().as_bytes())?;
        let padded_size = padded_size(body.len())?;
        let act_id = digest(
            b"ASL-CONVERSATION-ACT-v1\0",
            record.conversation_id.as_bytes(),
            record.message_id.as_bytes(),
            &[match record.direction {
                ActDirection::In => 1,
                ActDirection::Out => 2,
            }],
        );
        let causal_root = digest(
            b"ASL-CONVERSATION-CAUSAL-v1\0",
            record.conversation_id.as_bytes(),
            record.causal_root.as_bytes(),
            &[],
        );
        let reply_to = record
            .reply_to
            .map(|reply| {
                Ok::<_, AslError>(digest(
                    b"ASL-CONVERSATION-REPLY-v1\0",
                    record.conversation_id.as_bytes(),
                    reply.as_bytes(),
                    &[],
                ))
            })
            .transpose()?;
        let now = i64::try_from(record.now_ms).map_err(|_| AslError::InvalidMessage)?;
        let retention = i64::from(days).saturating_mul(DAY_MS);
        let expires = i64::try_from(record.expires_at_ms)
            .map_err(|_| AslError::InvalidMessage)?
            .min(now.saturating_add(retention));
        if expires <= now {
            return Err(AslError::ExpiredMessage);
        }
        self.connection
            .execute(
                "INSERT INTO conversation_act_events(
                    conversation_id,act_id,mls_epoch,direction,act_kind,causal_root,reply_to,
                    ciphertext,padded_size,state,received_at_ms,expires_at_ms
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,'processed',?10,?11)
                 ON CONFLICT(conversation_id,act_id) DO UPDATE SET
                    mls_epoch=excluded.mls_epoch,act_kind=excluded.act_kind,
                    reply_to=excluded.reply_to,ciphertext=excluded.ciphertext,
                    padded_size=excluded.padded_size,state='processed',
                    received_at_ms=excluded.received_at_ms,expires_at_ms=excluded.expires_at_ms",
                params![
                    record.conversation_id,
                    act_id.as_slice(),
                    i64::try_from(record.mls_epoch).map_err(|_| AslError::InvalidMessage)?,
                    record.direction.as_str(),
                    i64::from(record.act_kind),
                    causal_root.as_slice(),
                    reply_to.as_ref().map(|value| value.as_slice()),
                    body,
                    i64::from(padded_size),
                    now,
                    expires,
                ],
            )
            .map_err(database_error)?;
        Ok(())
    }

    pub fn recent_act_history(
        &self,
        now_ms: i64,
        limit: u32,
    ) -> Result<Vec<ActHistoryRow>, AslError> {
        if now_ms < 0 || limit == 0 || limit > MAX_ROWS {
            return Err(AslError::InvalidMessage);
        }
        let mut statement = self
            .connection
            .prepare_cached(
                "SELECT conversation_id,direction,act_kind,ciphertext,received_at_ms
                 FROM conversation_act_events
                 WHERE expires_at_ms>?1 AND direction IN ('in','out')
                 ORDER BY received_at_ms DESC,conversation_id,act_id LIMIT ?2",
            )
            .map_err(database_error)?;
        statement
            .query_map(params![now_ms, i64::from(limit)], |row| {
                let direction = match row.get::<_, String>(1)?.as_str() {
                    "in" => ActDirection::In,
                    "out" => ActDirection::Out,
                    _ => return Err(rusqlite::Error::InvalidQuery),
                };
                Ok((
                    row.get::<_, String>(0)?,
                    direction,
                    u16::try_from(row.get::<_, i64>(2)?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })
            .map_err(database_error)?
            .map(|row| {
                let (conversation_id, direction, act_kind, body, created_at_ms) =
                    row.map_err(database_error)?;
                Ok(ActHistoryRow {
                    conversation_id,
                    direction,
                    act_kind,
                    body: unprotect_body(&body)?,
                    created_at_ms,
                })
            })
            .collect()
    }

    pub fn prune_act_history(&mut self, now_ms: i64) -> Result<usize, AslError> {
        if now_ms < 0 {
            return Err(AslError::InvalidMessage);
        }
        self.connection
            .execute(
                "DELETE FROM conversation_act_events WHERE expires_at_ms<=?1",
                [now_ms],
            )
            .map_err(database_error)
    }

    pub fn restore_act_history(&mut self, record: StoredActHistory<'_>) -> Result<(), AslError> {
        let days = group_observation_days(&self.connection)?;
        if days == 0 {
            return Ok(());
        }
        restore_act_history_on(&self.connection, days, record)
    }
}

pub(crate) fn restore_act_history_on(
    db: &rusqlite::Connection,
    days: u8,
    record: StoredActHistory<'_>,
) -> Result<(), AslError> {
    if days == 0 {
        return Ok(());
    }
    let now = i64::try_from(record.received_at_ms).map_err(|_| AslError::InvalidMessage)?;
    let expires = i64::try_from(record.expires_at_ms)
        .map_err(|_| AslError::InvalidMessage)?
        .min(now.saturating_add(i64::from(days).saturating_mul(DAY_MS)));
    if now < 0
        || expires <= now
        || record.conversation_id.is_empty()
        || record.conversation_id.len() > 128
        || record.conversation_id.as_bytes().contains(&0)
        || record.act_id == [0; 32]
        || record.causal_root == [0; 32]
        || record.reply_to == Some([0; 32])
        || record.mls_epoch > i64::MAX as u64
        || record.body.is_some_and(|body| {
            body.is_empty() || body.len() > MAX_BODY_BYTES || body.as_bytes().contains(&0)
        })
    {
        return Err(AslError::InvalidMessage);
    }
    let body = protect_body(record.body.unwrap_or_default().as_bytes())?;
    let padded_size = padded_size(body.len())?;
    db.execute(
        "INSERT OR IGNORE INTO conversation_act_events(
            conversation_id,act_id,mls_epoch,direction,act_kind,causal_root,reply_to,
            ciphertext,padded_size,state,received_at_ms,expires_at_ms
         ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,'processed',?10,?11)",
        params![
            record.conversation_id,
            record.act_id.as_slice(),
            i64::try_from(record.mls_epoch).map_err(|_| AslError::InvalidMessage)?,
            record.direction.as_str(),
            i64::from(record.act_kind),
            record.causal_root.as_slice(),
            record.reply_to.as_ref().map(|value| value.as_slice()),
            body,
            i64::from(padded_size),
            now,
            expires,
        ],
    )
    .map_err(database_error)?;
    Ok(())
}

fn validate_record(record: ActHistoryRecord<'_>) -> Result<(), AslError> {
    if record.conversation_id.is_empty()
        || record.conversation_id.len() > 128
        || record.conversation_id.as_bytes().contains(&0)
        || record.message_id.0 == [0; 16]
        || record.causal_root.0 == [0; 16]
        || record.mls_epoch > i64::MAX as u64
        || record.now_ms > i64::MAX as u64
        || record.expires_at_ms > i64::MAX as u64
        || record.body.is_some_and(|body| {
            body.is_empty() || body.len() > MAX_BODY_BYTES || body.as_bytes().contains(&0)
        })
    {
        return Err(AslError::InvalidMessage);
    }
    Ok(())
}

fn digest(domain: &[u8], first: &[u8], second: &[u8], suffix: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(first);
    hasher.update(second);
    hasher.update(suffix);
    *hasher.finalize().as_bytes()
}

fn padded_size(length: usize) -> Result<u32, AslError> {
    let size = length.checked_add(255).ok_or(AslError::InvalidMessage)? / 256 * 256;
    u32::try_from(size.max(256))
        .ok()
        .filter(|size| *size <= 1024 * 1024)
        .ok_or(AslError::QuotaExceeded)
}

#[cfg(windows)]
fn protect_body(body: &[u8]) -> Result<Vec<u8>, AslError> {
    if body.is_empty() {
        return Ok(UTF8_PREFIX.to_vec());
    }
    let protected = asl_policy::protect_secret(body)?;
    let mut value = Vec::with_capacity(DPAPI_PREFIX.len() + protected.len());
    value.extend_from_slice(DPAPI_PREFIX);
    value.extend_from_slice(&protected);
    Ok(value)
}

#[cfg(not(windows))]
fn protect_body(body: &[u8]) -> Result<Vec<u8>, AslError> {
    let mut value = Vec::with_capacity(UTF8_PREFIX.len() + body.len());
    value.extend_from_slice(UTF8_PREFIX);
    value.extend_from_slice(body);
    Ok(value)
}

#[cfg(windows)]
fn unprotect_body(value: &[u8]) -> Result<Option<String>, AslError> {
    if let Some(body) = value.strip_prefix(UTF8_PREFIX) {
        return String::from_utf8(body.to_vec())
            .map(Some)
            .map_err(|_| AslError::InvalidDatabase);
    }
    let protected = value
        .strip_prefix(DPAPI_PREFIX)
        .ok_or(AslError::InvalidDatabase)?;
    let body = asl_policy::unprotect_secret(protected)?;
    let body = String::from_utf8(body.to_vec()).map_err(|_| AslError::InvalidDatabase)?;
    Ok((!body.is_empty()).then_some(body))
}

pub(crate) fn decode_stored_body(value: &[u8]) -> Result<Option<String>, AslError> {
    unprotect_body(value)
}

#[cfg(not(windows))]
fn unprotect_body(value: &[u8]) -> Result<Option<String>, AslError> {
    let body = value
        .strip_prefix(UTF8_PREFIX)
        .ok_or(AslError::InvalidDatabase)?;
    let body = String::from_utf8(body.to_vec()).map_err(|_| AslError::InvalidDatabase)?;
    Ok((!body.is_empty()).then_some(body))
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::{current_time_ms, open_store};
    use asl_types::ids::Id128;

    fn fixture() -> (TempDir, Store) {
        let directory = tempfile::tempdir().unwrap();
        let store = open_store(&directory.path().join("act-history.sqlite3")).unwrap();
        (directory, store)
    }

    #[test]
    fn records_and_lists_encrypted_local_act_bodies() {
        let (_directory, mut store) = fixture();
        let now = current_time_ms() as u64;
        store
            .record_act_history(ActHistoryRecord {
                conversation_id: "00112233445566778899aabbccddeeff",
                message_id: Id128([1; 16]),
                mls_epoch: 3,
                direction: ActDirection::In,
                act_kind: 1,
                reply_to: None,
                causal_root: Id128([2; 16]),
                body: Some("question data"),
                now_ms: now,
                expires_at_ms: now + 1_000,
            })
            .unwrap();
        let rows = store.recent_act_history(current_time_ms(), 10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].body.as_deref(), Some("question data"));
        assert_eq!(rows[0].direction, ActDirection::In);
    }

    #[test]
    fn group_retention_controls_local_act_history() {
        let (_directory, mut store) = fixture();
        let now = current_time_ms() as u64;
        store
            .record_act_history(ActHistoryRecord {
                conversation_id: "00112233445566778899aabbccddeeff",
                message_id: Id128([4; 16]),
                mls_epoch: 1,
                direction: ActDirection::Out,
                act_kind: 0,
                reply_to: None,
                causal_root: Id128([5; 16]),
                body: Some("retained"),
                now_ms: now,
                expires_at_ms: now + 7 * 24 * 60 * 60 * 1_000,
            })
            .unwrap();
        assert_eq!(
            store
                .recent_act_history(current_time_ms(), 10)
                .unwrap()
                .len(),
            1
        );
        store.set_group_observation_days(0).unwrap();
        assert!(
            store
                .recent_act_history(current_time_ms(), 10)
                .unwrap()
                .is_empty()
        );
    }
}
