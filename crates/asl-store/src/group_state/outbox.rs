use asl_types::{
    error::AslError,
    ids::{Hash32, Id128},
    protocol::MAX_EXTENDED_FRAME_BYTES,
};
use rusqlite::{OptionalExtension, Transaction, params};

use super::{sql_number, unsigned};
use crate::{Store, database_error};

pub const MAX_SHARD_FORWARD_OUTBOX_BATCH: usize = 16;
pub const SHARD_FORWARD_OUTBOX_RETRY_BASE_MS: u64 = 5_000;
pub const SHARD_FORWARD_OUTBOX_RETRY_MAX_MS: u64 = 5 * 60 * 1_000;
pub const SHARD_FORWARD_OUTBOX_TERMINAL_RETENTION_MS: u64 = 7 * 24 * 60 * 60 * 1_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShardForwardOutboxRoute {
    pub forward_id: Id128,
    pub source_message_id: Id128,
    pub logical_root: Hash32,
    pub source_child: Hash32,
    pub target_child: Hash32,
    pub target_binding_revision: u64,
    pub observed_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShardForwardOutboxRecord {
    pub route: ShardForwardOutboxRoute,
    pub frame: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingShardForwardOutbox {
    pub route: ShardForwardOutboxRoute,
    pub frame: Vec<u8>,
    pub attempts: u32,
    pub next_attempt_ms: u64,
}

impl Store {
    pub fn due_shard_forward_outbox(
        &self,
        now_ms: u64,
        limit: usize,
    ) -> Result<Vec<PendingShardForwardOutbox>, AslError> {
        if limit == 0 || limit > MAX_SHARD_FORWARD_OUTBOX_BATCH {
            return Err(AslError::InvalidMessage);
        }
        let mut statement = self
            .connection
            .prepare(
                "SELECT forward_id,source_message_id,logical_root,source_wire_id,target_wire_id,
                        target_binding_revision,frame_cbor,observed_at_ms,expires_at_ms,
                        attempts,next_attempt_ms
                 FROM mls_shard_forward_outbox
                 WHERE state='pending' AND next_attempt_ms<=?1
                 ORDER BY next_attempt_ms,created_at_ms,forward_id
                 LIMIT ?2",
            )
            .map_err(database_error)?;
        let rows = statement
            .query_map(
                params![
                    sql_number(now_ms)?,
                    i64::try_from(limit).map_err(|_| AslError::InvalidMessage)?
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, Vec<u8>>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, i64>(8)?,
                        row.get::<_, i64>(9)?,
                        row.get::<_, i64>(10)?,
                    ))
                },
            )
            .map_err(database_error)?;
        rows.map(|row| {
            let (
                forward_id,
                source_message_id,
                logical_root,
                source_child,
                target_child,
                target_binding_revision,
                frame,
                observed_at_ms,
                expires_at_ms,
                attempts,
                next_attempt_ms,
            ) = row.map_err(database_error)?;
            let route = ShardForwardOutboxRoute {
                forward_id: id128(forward_id)?,
                source_message_id: id128(source_message_id)?,
                logical_root: hash32(logical_root)?,
                source_child: hash32(source_child)?,
                target_child: hash32(target_child)?,
                target_binding_revision: unsigned(target_binding_revision)?,
                observed_at_ms: unsigned(observed_at_ms)?,
                expires_at_ms: unsigned(expires_at_ms)?,
            };
            if route.expires_at_ms <= route.observed_at_ms
                || !(1..=MAX_EXTENDED_FRAME_BYTES).contains(&frame.len())
                || u32::try_from(attempts).is_err()
            {
                return Err(AslError::InvalidDatabase);
            }
            Ok(PendingShardForwardOutbox {
                route,
                frame,
                attempts: u32::try_from(attempts).map_err(|_| AslError::InvalidDatabase)?,
                next_attempt_ms: unsigned(next_attempt_ms)?,
            })
        })
        .collect()
    }

    /// Successful local dispatch clears the durable row. Receipt semantics are
    /// transport-level: the caller has accepted the exact encrypted frame for
    /// delivery, not acknowledged receipt by a remote shard.
    pub fn complete_shard_forward_outbox(&self, forward_id: Id128) -> Result<(), AslError> {
        self.connection
            .execute(
                "DELETE FROM mls_shard_forward_outbox WHERE forward_id=?1",
                [forward_id.0.as_slice()],
            )
            .map(|_| ())
            .map_err(database_error)
    }

    pub fn reschedule_shard_forward_outbox(
        &self,
        route: &ShardForwardOutboxRoute,
        attempts: u32,
        next_attempt_ms: u64,
    ) -> Result<(), AslError> {
        if next_attempt_ms >= route.expires_at_ms {
            return Err(AslError::ExpiredMessage);
        }
        let changed = self
            .connection
            .execute(
                "UPDATE mls_shard_forward_outbox
                 SET attempts=?2,next_attempt_ms=?3
                 WHERE forward_id=?1 AND state='pending'",
                params![
                    route.forward_id.0.as_slice(),
                    i64::from(attempts),
                    sql_number(next_attempt_ms)?,
                ],
            )
            .map_err(database_error)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(AslError::NotFound)
        }
    }

    pub fn terminate_shard_forward_outbox(
        &self,
        forward_id: Id128,
        reason: &'static str,
        now_ms: u64,
    ) -> Result<(), AslError> {
        if reason.is_empty() || reason.len() > 64 {
            return Err(AslError::InvalidMessage);
        }
        self.connection
            .execute(
                "UPDATE mls_shard_forward_outbox
                 SET state='terminal',terminal_reason=?2,terminal_at_ms=?3
                 WHERE forward_id=?1 AND state='pending'",
                params![forward_id.0.as_slice(), reason, sql_number(now_ms)?,],
            )
            .map(|_| ())
            .map_err(database_error)
    }

    pub fn prune_shard_forward_outbox(&self, now_ms: u64) -> Result<usize, AslError> {
        let now = sql_number(now_ms)?;
        self.connection
            .execute(
                "UPDATE mls_shard_forward_outbox
                 SET state='terminal',terminal_reason='expired',terminal_at_ms=?1
                 WHERE state='pending' AND expires_at_ms<=?1",
                [now],
            )
            .map_err(database_error)?;
        let cutoff = now_ms.saturating_sub(SHARD_FORWARD_OUTBOX_TERMINAL_RETENTION_MS);
        self.connection
            .execute(
                "DELETE FROM mls_shard_forward_outbox
                 WHERE state='terminal' AND terminal_at_ms<=?1",
                [sql_number(cutoff)?],
            )
            .map_err(database_error)
    }

    pub fn shard_forward_outbox_state(
        &self,
        forward_id: Id128,
    ) -> Result<Option<(String, Option<String>)>, AslError> {
        self.connection
            .query_row(
                "SELECT state,terminal_reason FROM mls_shard_forward_outbox
                 WHERE forward_id=?1",
                [forward_id.0.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(database_error)
    }
}

pub(super) fn insert(
    tx: &Transaction<'_>,
    record: &ShardForwardOutboxRecord,
    now_ms: u64,
) -> Result<(), AslError> {
    let route = &record.route;
    if route.forward_id.0 == [0; 16]
        || route.source_message_id.0 == [0; 16]
        || route.logical_root.0 == [0; 32]
        || route.source_child.0 == [0; 32]
        || route.target_child.0 == [0; 32]
        || route.source_child == route.target_child
        || route.observed_at_ms > now_ms
        || route.expires_at_ms <= route.observed_at_ms
        || !(1..=MAX_EXTENDED_FRAME_BYTES).contains(&record.frame.len())
    {
        return Err(AslError::InvalidMessage);
    }
    let next_attempt_ms = now_ms
        .checked_add(SHARD_FORWARD_OUTBOX_RETRY_BASE_MS)
        .ok_or(AslError::InvalidMessage)?
        .min(route.expires_at_ms.saturating_sub(1));
    tx.execute(
        "INSERT INTO mls_shard_forward_outbox(
            forward_id,source_message_id,logical_root,source_wire_id,target_wire_id,
            target_binding_revision,frame_cbor,observed_at_ms,expires_at_ms,
            created_at_ms,next_attempt_ms,attempts,state)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,0,'pending')
         ON CONFLICT(forward_id) DO NOTHING",
        params![
            route.forward_id.0.as_slice(),
            route.source_message_id.0.as_slice(),
            route.logical_root.as_bytes(),
            route.source_child.as_bytes(),
            route.target_child.as_bytes(),
            sql_number(route.target_binding_revision)?,
            record.frame,
            sql_number(route.observed_at_ms)?,
            sql_number(route.expires_at_ms)?,
            sql_number(now_ms)?,
            sql_number(next_attempt_ms)?,
        ],
    )
    .map_err(database_error)?;
    Ok(())
}

fn id128(bytes: Vec<u8>) -> Result<Id128, AslError> {
    Ok(Id128(
        bytes.try_into().map_err(|_| AslError::InvalidDatabase)?,
    ))
}

fn hash32(bytes: Vec<u8>) -> Result<Hash32, AslError> {
    Ok(Hash32(
        bytes.try_into().map_err(|_| AslError::InvalidDatabase)?,
    ))
}
