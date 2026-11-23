use std::path::Path;

use asl_policy::{AuthorizedWriteFile, WriteGrant};
use asl_types::{error::AslError, ids::Id128};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};

use super::{
    DownloadBroker, TransferRow, destination_relative, load_row_tx, part_identity,
    restore_write_grant,
};
use crate::{Store, database_error, inbound_observations::DAY_MS};

const FAILED_PART_LIFETIME_MS: i64 = 3 * DAY_MS;
const MAX_INBOX_DAYS: u8 = 30;
const BATCH: i64 = 8;

impl Store {
    pub fn inbox_retention_days(&self, grant: Id128) -> Result<u8, AslError> {
        self.connection
            .query_row(
                "SELECT inbox_retention_days FROM write_grants
                 WHERE write_grant_id=?1 AND kind='inbox' AND status='active'",
                [hex::encode(grant.0)],
                |row| row.get(0),
            )
            .optional()
            .map_err(database_error)?
            .ok_or(AslError::PolicyDenied)
    }

    pub fn set_inbox_retention_days(&mut self, grant: Id128, days: u8) -> Result<(), AslError> {
        if days > MAX_INBOX_DAYS {
            return Err(AslError::InvalidMessage);
        }
        let grant = hex::encode(grant.0);
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        if tx
            .execute(
                "UPDATE write_grants SET inbox_retention_days=?2
                 WHERE write_grant_id=?1 AND kind='inbox' AND status='active'",
                params![grant, days],
            )
            .map_err(database_error)?
            != 1
        {
            return Err(AslError::PolicyDenied);
        }
        if days == 0 {
            tx.execute(
                "DELETE FROM received_file_retention WHERE transfer_id IN (
                    SELECT transfer_id FROM transfers WHERE write_grant_id=?1
                 )",
                [&grant],
            )
            .map_err(database_error)?;
        } else {
            tx.execute(
                "UPDATE received_file_retention AS keep
                 SET expires_at_ms=min(keep.expires_at_ms,t.updated_at_ms+?2)
                 FROM transfers t WHERE t.transfer_id=keep.transfer_id AND t.write_grant_id=?1",
                params![grant, i64::from(days) * DAY_MS],
            )
            .map_err(database_error)?;
        }
        tx.commit().map_err(database_error)
    }
}

pub(super) fn record_received_file(
    tx: &Transaction<'_>,
    row: &TransferRow,
    file: &AuthorizedWriteFile,
    now: i64,
) -> Result<(), AslError> {
    let days: i64 = tx
        .query_row(
            "SELECT w.inbox_retention_days FROM write_grants w
             JOIN transfers t USING(write_grant_id) WHERE t.transfer_id=?1",
            [&row.transfer],
            |value| value.get(0),
        )
        .map_err(database_error)?;
    if days == 0 {
        return Ok(());
    }
    let Ok(stamp) = write_stamp(file) else {
        return Ok(());
    };
    tx.execute(
        "INSERT INTO received_file_retention VALUES (?1,?2,?3)",
        params![row.transfer, now.saturating_add(days * DAY_MS), stamp],
    )
    .map_err(database_error)?;
    Ok(())
}

impl DownloadBroker {
    pub fn prune_failed_parts(&mut self, now_ms: i64) -> Result<usize, AslError> {
        if now_ms < FAILED_PART_LIFETIME_MS {
            return Ok(0);
        }
        let cutoff = now_ms - FAILED_PART_LIFETIME_MS;
        let tx = self
            .store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let transfers = {
            let mut statement = tx
                .prepare(
                    "SELECT t.transfer_id FROM transfers t
                     JOIN reservations r USING(reservation_id)
                     JOIN write_grants w USING(write_grant_id)
                     WHERE t.transfer_id>?1 AND t.updated_at_ms<=?2
                       AND t.state='failed' AND r.state='released' AND t.part_file_id IS NOT NULL
                       AND w.kind='inbox' AND w.status='active'
                       AND NOT EXISTS (
                         SELECT 1 FROM transfers other JOIN write_grants dest
                           ON dest.write_grant_id=other.write_grant_id
                         WHERE other.transfer_id<>t.transfer_id
                           AND other.part_file_id=t.part_file_id AND dest.root_volume=w.root_volume
                       )
                     ORDER BY t.transfer_id LIMIT ?3",
                )
                .map_err(database_error)?;
            statement
                .query_map(params![self.failed_part_cursor, cutoff, BATCH], |row| {
                    row.get::<_, String>(0)
                })
                .map_err(database_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(database_error)?
        };
        let mut removed = 0;
        for id in &transfers {
            let row = load_row_tx(&tx, id)?;
            destination_relative(&row)?;
            let Ok(mut part) = open_owned(&self.home, &row, Path::new(&row.part)) else {
                continue;
            };
            if part.remove().is_ok() {
                tx.execute(
                    "UPDATE transfers SET part_file_id=NULL WHERE transfer_id=?1",
                    [id],
                )
                .map_err(database_error)?;
                removed += 1;
            }
        }
        tx.commit().map_err(database_error)?;
        self.failed_part_cursor = if transfers.len() == BATCH as usize {
            transfers.into_iter().last().unwrap_or_default()
        } else {
            String::new()
        };
        Ok(removed)
    }

    pub fn prune_received_files(&mut self, now_ms: i64) -> Result<usize, AslError> {
        let tx = self
            .store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let transfers = {
            let mut statement = tx
                .prepare(
                    "SELECT t.transfer_id,k.write_stamp FROM received_file_retention k
                     JOIN transfers t USING(transfer_id) JOIN reservations r USING(reservation_id)
                     JOIN write_grants w USING(write_grant_id)
                     WHERE t.transfer_id>?1 AND k.expires_at_ms<=?2 AND t.state='complete'
                       AND r.state='consumed' AND w.kind='inbox' AND w.status='active'
                       AND w.inbox_retention_days>0
                       AND NOT EXISTS (SELECT 1 FROM resources x WHERE x.content_id=t.content_id
                                       AND x.active=1)
                       AND NOT EXISTS (SELECT 1 FROM offers o WHERE o.content_id=t.content_id
                                       AND o.expires_at_ms>?2)
                       AND NOT EXISTS (SELECT 1 FROM transfers live WHERE live.content_id=t.content_id
                                       AND live.state IN ('pending','running','paused','verifying')
                                       AND live.expires_at_ms>?2)
                       AND NOT EXISTS (
                         SELECT 1 FROM transfers other JOIN write_grants dest
                           ON dest.write_grant_id=other.write_grant_id
                         WHERE other.transfer_id<>t.transfer_id
                           AND other.part_file_id=t.part_file_id AND dest.root_volume=w.root_volume
                       )
                     ORDER BY t.transfer_id LIMIT ?3",
                )
                .map_err(database_error)?;
            statement
                .query_map(params![self.received_file_cursor, now_ms, BATCH], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })
                .map_err(database_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(database_error)?
        };
        let mut removed = 0;
        for (id, stamp) in &transfers {
            let row = load_row_tx(&tx, id)?;
            let destination = destination_relative(&row)?;
            let Ok(grant) = restore_inbox(&self.home, &row) else {
                continue;
            };
            match grant.open_existing(&destination, &part_identity(&row)?) {
                Ok(mut file) => {
                    if write_stamp(&file).ok() != Some(*stamp)
                        || file.len().ok() != u64::try_from(row.durable_bytes).ok()
                    {
                        forget_received_file(&tx, id)?;
                        continue;
                    }
                    if file.remove().is_err() {
                        continue;
                    }
                    removed += 1;
                }
                Err(AslError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => continue,
            }
            tx.execute(
                "UPDATE reservations SET state='released' WHERE reservation_id=?1",
                [&row.reservation],
            )
            .map_err(database_error)?;
            tx.execute(
                "UPDATE transfers SET part_file_id=NULL WHERE transfer_id=?1",
                [id],
            )
            .map_err(database_error)?;
            forget_received_file(&tx, id)?;
        }
        tx.commit().map_err(database_error)?;
        self.received_file_cursor = if transfers.len() == BATCH as usize {
            transfers
                .into_iter()
                .last()
                .map(|(id, _)| id)
                .unwrap_or_default()
        } else {
            String::new()
        };
        Ok(removed)
    }
}

fn open_owned(
    home: &Path,
    row: &TransferRow,
    path: &Path,
) -> Result<AuthorizedWriteFile, AslError> {
    restore_inbox(home, row)?.open_existing(path, &part_identity(row)?)
}

fn restore_inbox(home: &Path, row: &TransferRow) -> Result<WriteGrant, AslError> {
    let identity = super::file_identity(row.root_volume.as_deref(), row.root_file_id.as_deref())?;
    restore_write_grant(Path::new(&row.root), home, &identity)
}

fn write_stamp(file: &AuthorizedWriteFile) -> Result<i64, AslError> {
    i64::try_from(file.last_write_stamp()?).map_err(|_| AslError::InvalidPolicyState)
}

fn forget_received_file(tx: &Transaction<'_>, id: &str) -> Result<(), AslError> {
    tx.execute(
        "DELETE FROM received_file_retention WHERE transfer_id=?1",
        [id],
    )
    .map_err(database_error)?;
    Ok(())
}
