use std::collections::{BTreeMap, BTreeSet};

use asl_types::{error::AslError, ids::Id128};
use rusqlite::params;

use crate::{
    Store, database_error, group_observations::group_observation_days, inbound_observations::DAY_MS,
};

const MAX_BODY_BYTES: usize = 32 * 1024;
pub const MAX_ACT_HISTORY_ROWS: u32 = 1_000;
const MAX_SEARCH_RESULTS: u32 = 100;
const MAX_QUERY_BYTES: usize = 256;
const MAX_ARCHIVE_TOKENS: usize = 64;
const ARCHIVE_RETENTION_MS: i64 = 365 * DAY_MS;
const DPAPI_PREFIX: &[u8] = b"ASL-ACT-BODY-DPAPI-v1\0";
const UTF8_PREFIX: &[u8] = b"ASL-ACT-BODY-UTF8-v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActDirection {
    In,
    Out,
}

impl ActDirection {
    pub fn as_str(self) -> &'static str {
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
    pub act_id: [u8; 32],
    pub mls_epoch: u64,
    pub direction: ActDirection,
    pub act_kind: u16,
    pub causal_root: [u8; 32],
    pub reply_to: Option<[u8; 32]>,
    pub body: Option<String>,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActHistoryArchiveRow {
    pub conversation_id: String,
    pub act_id: [u8; 32],
    pub direction: ActDirection,
    pub act_kind: u16,
    pub score: u32,
    pub received_at_ms: i64,
    pub expires_at_ms: i64,
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
        index_act_body(
            &self.connection,
            record.conversation_id,
            act_id,
            record.direction,
            record.act_kind,
            now,
            record.body.unwrap_or_default(),
        )?;
        Ok(())
    }

    pub fn recent_act_history(
        &self,
        now_ms: i64,
        limit: u32,
    ) -> Result<Vec<ActHistoryRow>, AslError> {
        if now_ms < 0 || limit == 0 || limit > MAX_ACT_HISTORY_ROWS {
            return Err(AslError::InvalidMessage);
        }
        let mut statement = self
            .connection
            .prepare_cached(
                "SELECT conversation_id,act_id,mls_epoch,direction,act_kind,
                        causal_root,reply_to,ciphertext,received_at_ms,expires_at_ms
                 FROM conversation_act_events
                 WHERE expires_at_ms>?1 AND direction IN ('in','out')
                 ORDER BY received_at_ms DESC,conversation_id,act_id LIMIT ?2",
            )
            .map_err(database_error)?;
        statement
            .query_map(params![now_ms, i64::from(limit)], |row| {
                let direction = match row.get::<_, String>(3)?.as_str() {
                    "in" => ActDirection::In,
                    "out" => ActDirection::Out,
                    _ => return Err(rusqlite::Error::InvalidQuery),
                };
                Ok(ActHistoryRow {
                    conversation_id: row.get(0)?,
                    act_id: row
                        .get::<_, Vec<u8>>(1)?
                        .try_into()
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    mls_epoch: u64::try_from(row.get::<_, i64>(2)?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    direction,
                    act_kind: u16::try_from(row.get::<_, i64>(4)?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    causal_root: row
                        .get::<_, Vec<u8>>(5)?
                        .try_into()
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    reply_to: row
                        .get::<_, Option<Vec<u8>>>(6)?
                        .map(|value| value.try_into().map_err(|_| rusqlite::Error::InvalidQuery))
                        .transpose()?,
                    body: unprotect_body(&row.get::<_, Vec<u8>>(7)?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    created_at_ms: row.get(8)?,
                    expires_at_ms: row.get(9)?,
                })
            })
            .map_err(database_error)?
            .collect::<Result<_, _>>()
            .map_err(database_error)
    }

    pub fn search_act_history(
        &self,
        now_ms: i64,
        query: &str,
        limit: u32,
    ) -> Result<Vec<ActHistoryRow>, AslError> {
        if query.is_empty()
            || query.len() > MAX_QUERY_BYTES
            || query.as_bytes().contains(&0)
            || limit == 0
            || limit > MAX_SEARCH_RESULTS
        {
            return Err(AslError::InvalidMessage);
        }
        let query = query.to_lowercase();
        let rows = self.recent_act_history(now_ms, MAX_ACT_HISTORY_ROWS)?;
        let mut matches = rows
            .into_iter()
            .filter_map(|row| {
                let body = row.body.as_ref()?.to_lowercase();
                let score = body.matches(&query).count();
                (score > 0).then_some((score, row))
            })
            .collect::<Vec<_>>();
        matches.sort_by(|(left_score, left), (right_score, right)| {
            right_score
                .cmp(left_score)
                .then_with(|| right.created_at_ms.cmp(&left.created_at_ms))
                .then_with(|| left.conversation_id.cmp(&right.conversation_id))
                .then_with(|| left.act_id.cmp(&right.act_id))
        });
        Ok(matches
            .into_iter()
            .take(limit as usize)
            .map(|(_, row)| row)
            .collect())
    }

    pub fn prune_act_history(&mut self, now_ms: i64) -> Result<usize, AslError> {
        if now_ms < 0 {
            return Err(AslError::InvalidMessage);
        }
        let removed = self
            .connection
            .execute(
                "DELETE FROM conversation_act_events WHERE expires_at_ms<=?1",
                [now_ms],
            )
            .map_err(database_error)?;
        self.connection
            .execute(
                "DELETE FROM conversation_act_semantic_index WHERE expires_at_ms<=?1",
                [now_ms],
            )
            .map_err(database_error)?;
        Ok(removed)
    }

    /// Searches the long-lived semantic index without decrypting or retaining
    /// expired message bodies. Returned rows are metadata and match counts only.
    pub fn search_act_history_archive(
        &self,
        now_ms: i64,
        query: &str,
        limit: u32,
    ) -> Result<Vec<ActHistoryArchiveRow>, AslError> {
        validate_search_query(query, limit)?;
        let tokens = semantic_tokens(query);
        if tokens.is_empty() {
            return Ok(Vec::new());
        }
        let mut matches: BTreeMap<(String, [u8; 32]), ActHistoryArchiveRow> = BTreeMap::new();
        for token in tokens {
            let rows = archive_rows_for_token(&self.connection, now_ms, &token)?;
            for row in rows {
                let key = (row.conversation_id.clone(), row.act_id);
                matches
                    .entry(key)
                    .and_modify(|entry| entry.score = entry.score.saturating_add(1))
                    .or_insert(row);
            }
        }
        let mut rows = matches.into_values().collect::<Vec<_>>();
        rows.sort_by(|left, right| {
            right
                .score
                .cmp(&left.score)
                .then_with(|| right.received_at_ms.cmp(&left.received_at_ms))
                .then_with(|| left.conversation_id.cmp(&right.conversation_id))
                .then_with(|| left.act_id.cmp(&right.act_id))
        });
        rows.truncate(limit as usize);
        Ok(rows)
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
    index_act_body(
        db,
        record.conversation_id,
        record.act_id,
        record.direction,
        record.act_kind,
        now,
        record.body.unwrap_or_default(),
    )?;
    Ok(())
}

fn index_act_body(
    connection: &rusqlite::Connection,
    conversation_id: &str,
    act_id: [u8; 32],
    direction: ActDirection,
    act_kind: u16,
    now: i64,
    body: &str,
) -> Result<(), AslError> {
    connection
        .execute(
            "DELETE FROM conversation_act_semantic_index WHERE conversation_id=?1 AND act_id=?2",
            params![conversation_id, act_id.as_slice()],
        )
        .map_err(database_error)?;
    let expires = now.saturating_add(ARCHIVE_RETENTION_MS);
    for token in semantic_tokens(body) {
        let token_hash = semantic_token_hash(&token);
        connection
            .execute(
                "INSERT OR REPLACE INTO conversation_act_semantic_index(
                    conversation_id,act_id,token_hash,direction,act_kind,
                    received_at_ms,expires_at_ms
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![
                    conversation_id,
                    act_id.as_slice(),
                    token_hash.as_slice(),
                    direction.as_str(),
                    i64::from(act_kind),
                    now,
                    expires,
                ],
            )
            .map_err(database_error)?;
    }
    Ok(())
}

fn archive_rows_for_token(
    connection: &rusqlite::Connection,
    now_ms: i64,
    token: &str,
) -> Result<Vec<ActHistoryArchiveRow>, AslError> {
    let mut statement = connection
        .prepare(
            "SELECT conversation_id,act_id,direction,act_kind,received_at_ms,expires_at_ms
             FROM conversation_act_semantic_index
             WHERE token_hash=?1 AND expires_at_ms>?2
             ORDER BY received_at_ms DESC,conversation_id,act_id LIMIT 1000",
        )
        .map_err(database_error)?;
    let rows = statement
        .query_map(
            params![semantic_token_hash(token).as_slice(), now_ms],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .map_err(database_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(database_error)?;
    let mut result = Vec::new();
    for (conversation_id, act_id, direction, act_kind, received_at_ms, expires_at_ms) in rows {
        let direction = match direction.as_str() {
            "in" => ActDirection::In,
            "out" => ActDirection::Out,
            _ => return Err(AslError::InvalidDatabase),
        };
        result.push(ActHistoryArchiveRow {
            conversation_id,
            act_id: act_id.try_into().map_err(|_| AslError::InvalidDatabase)?,
            direction,
            act_kind: u16::try_from(act_kind).map_err(|_| AslError::InvalidDatabase)?,
            score: 1,
            received_at_ms,
            expires_at_ms,
        });
    }
    Ok(result)
}

fn validate_search_query(query: &str, limit: u32) -> Result<(), AslError> {
    if query.is_empty()
        || query.len() > MAX_QUERY_BYTES
        || query.as_bytes().contains(&0)
        || limit == 0
        || limit > MAX_SEARCH_RESULTS
    {
        return Err(AslError::InvalidMessage);
    }
    Ok(())
}

fn semantic_tokens(text: &str) -> Vec<String> {
    let mut tokens = BTreeSet::new();
    let mut current = String::new();
    for character in text.chars().chain(std::iter::once(' ')) {
        if character.is_alphanumeric() {
            current.extend(character.to_lowercase());
        } else {
            add_semantic_token(&mut tokens, &current);
            current.clear();
        }
    }
    tokens.into_iter().take(MAX_ARCHIVE_TOKENS).collect()
}

fn add_semantic_token(tokens: &mut BTreeSet<String>, token: &str) {
    if token.is_empty() {
        return;
    }
    if token.is_ascii() {
        tokens.insert(token.to_owned());
        return;
    }
    let characters = token.chars().collect::<Vec<_>>();
    for character in &characters {
        tokens.insert(character.to_string());
    }
    for pair in characters.windows(2) {
        tokens.insert(pair.iter().collect());
    }
    if characters.len() <= 8 {
        tokens.insert(token.to_owned());
    }
}

fn semantic_token_hash(token: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ASL-ACT-SEMANTIC-TOKEN-v1\0");
    hasher.update(token.as_bytes());
    *hasher.finalize().as_bytes()
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

    #[test]
    fn searches_only_decrypted_local_history_with_bounded_results() {
        let (_directory, mut store) = fixture();
        let now = current_time_ms() as u64;
        for (index, body) in ["Rust ownership", "rust channels", "unrelated"]
            .into_iter()
            .enumerate()
        {
            store
                .record_act_history(ActHistoryRecord {
                    conversation_id: "00112233445566778899aabbccddeeff",
                    message_id: Id128([index as u8 + 1; 16]),
                    mls_epoch: index as u64,
                    direction: ActDirection::In,
                    act_kind: 0,
                    reply_to: None,
                    causal_root: Id128([9; 16]),
                    body: Some(body),
                    now_ms: now + index as u64,
                    expires_at_ms: now + 7 * DAY_MS as u64,
                })
                .unwrap();
        }
        let rows = store
            .search_act_history(current_time_ms(), "RUST", 2)
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].body.as_deref(), Some("rust channels"));
        assert_eq!(rows[1].body.as_deref(), Some("Rust ownership"));
        assert!(store.search_act_history(current_time_ms(), "", 1).is_err());
        assert!(
            store
                .search_act_history(current_time_ms(), "rust", 0)
                .is_err()
        );
        assert!(
            store
                .search_act_history(current_time_ms(), &"x".repeat(MAX_QUERY_BYTES + 1), 1)
                .is_err()
        );
    }

    #[test]
    fn semantic_index_survives_body_expiry_without_retaining_plaintext() {
        let (_directory, mut store) = fixture();
        let now = current_time_ms() as u64;
        store
            .record_act_history(ActHistoryRecord {
                conversation_id: "00112233445566778899aabbccddeeff",
                message_id: Id128([7; 16]),
                mls_epoch: 2,
                direction: ActDirection::In,
                act_kind: 1,
                reply_to: None,
                causal_root: Id128([8; 16]),
                body: Some("Rust ownership evidence"),
                now_ms: now,
                expires_at_ms: now + 1,
            })
            .unwrap();
        let later = i64::try_from(now + 2).unwrap();
        assert_eq!(store.prune_act_history(later).unwrap(), 1);
        assert!(store.recent_act_history(later, 10).unwrap().is_empty());
        let archive = store
            .search_act_history_archive(later, "ownership", 10)
            .unwrap();
        assert_eq!(archive.len(), 1);
        assert_eq!(archive[0].act_kind, 1);
        assert_eq!(archive[0].score, 1);
    }
}
