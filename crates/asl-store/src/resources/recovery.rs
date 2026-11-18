use std::io;

use asl_policy::snapshot_files::ImportOwner;
use asl_types::error::AslError;
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use super::{
    SnapshotBroker, current_time_ms, database_error, immediate, parse_id,
    reservations::{self, Hold},
};

const PAGE: usize = 16;

#[derive(Debug, Default)]
pub struct RecoveryReport {
    pub released: usize,
    pub live_owners: usize,
    /// Owner/cleanup could not be verified. The claim and quota remain held.
    pub deferred: usize,
}

pub(super) fn claim_install(
    db: &mut Connection,
    hold: &Hold,
    id: [u8; 32],
) -> Result<(), AslError> {
    let tx = immediate(db)?;
    reservations::check_live(&tx, hold, current_time_ms())?;
    let content = hex::encode(id);
    let claimed = tx.execute(
        "UPDATE snapshot_imports SET install_content_id=?2 WHERE reservation_id=?1 AND install_content_id IS NULL
         AND NOT EXISTS(SELECT 1 FROM snapshot_imports WHERE install_content_id=?2)",
        params![hold.reservation, content],
    ).map_err(database_error)?;
    if claimed != 1 {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "snapshot install already claimed",
        )
        .into());
    }
    // The claim is still invisible. Never grant rollback authority over an
    // unreferenced name that already existed before this install.
    if !snapshot_exists(&tx, &content)? {
        hold.owner.require_absent(id)?;
    }
    tx.commit().map_err(database_error)
}

fn snapshot_exists(tx: &Transaction<'_>, content: &str) -> Result<bool, AslError> {
    tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM snapshots WHERE content_id=?1 COLLATE NOCASE)",
        [content],
        |row| row.get(0),
    )
    .map_err(database_error)
}

/// Used for a known failure with its original owner, or after reacquiring an
/// expired import. Keep the writer and owner through the reference check and unlink.
pub(super) fn rollback_held(tx: &Transaction<'_>, hold: &Hold) -> Result<(), AslError> {
    let content: Option<String> = tx.query_row(
        "SELECT install_content_id FROM snapshot_imports JOIN reservations USING(reservation_id)
         WHERE reservation_id=?1 AND task_id=?2 AND kind='snapshot' AND state='held'",
        params![hold.reservation,hold.task], |row| row.get(0),
    ).map_err(database_error)?;
    if let Some(text) = content {
        let mut id = [0; 32];
        hex::decode_to_slice(&text, &mut id).map_err(|_| AslError::InvalidDatabase)?;
        if text != hex::encode(id) {
            return Err(AslError::InvalidDatabase);
        }
        // The unique claim excludes every other installer, expired or not.
        // Every snapshot state protects the final files, even without a resource.
        if !snapshot_exists(tx, &text)? {
            hold.owner
                .clean_unreferenced(id)
                .map_err(|_| AslError::SnapshotRecoveryRequired)?;
        }
    }
    reservations::finish(tx, hold, "released", "failed")
}

// Persist the keyset cursor before attempting the page. Repeated opens, busy
// owners and failed cleanups cannot keep the first page at the head forever.
// Freeze the upper time bound so new expiries cannot prevent wraparound.
fn candidates(db: &mut Connection) -> Result<Vec<String>, AslError> {
    let tx = immediate(db)?;
    let cursor: Option<(i64, i64, String)> = tx
        .query_row(
            "SELECT through_ms,after_ms,after_id FROM snapshot_recovery_cursor WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
        .map_err(database_error)?;
    let had_cursor = cursor.is_some();
    let (through, after, id) =
        cursor.unwrap_or_else(|| (current_time_ms(), i64::MIN, String::new()));
    let rows: Vec<(i64, String)> = {
        let mut stmt = tx
            .prepare(
                "SELECT expires_at_ms,reservation_id FROM reservations
             WHERE kind='snapshot' AND state='held' AND (expires_at_ms,reservation_id)>(?1,?2)
             AND expires_at_ms<=?3 ORDER BY expires_at_ms,reservation_id LIMIT ?4",
            )
            .map_err(database_error)?;
        stmt.query_map(params![after, id, through, PAGE as i64], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .map_err(database_error)?
        .collect::<Result<_, _>>()
        .map_err(database_error)?
    };
    if rows.len() == PAGE {
        let (ms, last) = &rows[PAGE - 1];
        tx.execute("INSERT INTO snapshot_recovery_cursor(singleton,through_ms,after_ms,after_id)
                    VALUES(1,?1,?2,?3) ON CONFLICT(singleton) DO UPDATE SET
                    through_ms=excluded.through_ms,after_ms=excluded.after_ms,after_id=excluded.after_id",
                   params![through,ms,last]).map_err(database_error)?;
    } else if had_cursor {
        tx.execute("DELETE FROM snapshot_recovery_cursor WHERE singleton=1", [])
            .map_err(database_error)?;
    }
    tx.commit().map_err(database_error)?;
    Ok(rows.into_iter().map(|(_, id)| id).collect())
}

impl SnapshotBroker {
    /// Attempt at most 16 expired snapshot reservations. Safe on startup and
    /// periodically, including with other live brokers on the same home.
    pub fn recover_expired_imports(&mut self) -> Result<RecoveryReport, AslError> {
        let db = &mut self.store.connection;
        let mut report = RecoveryReport::default();
        for reservation in candidates(db)? {
            let tx = immediate(db)?;
            let task: Option<String> = tx.query_row(
                "SELECT task_id FROM reservations JOIN snapshot_imports USING(reservation_id)
                 WHERE reservation_id=?1 AND kind='snapshot' AND state='held' AND expires_at_ms<=?2",
                params![reservation,current_time_ms()], |r| r.get(0),
            ).optional().map_err(database_error)?;
            let Some(task) = task else { continue };
            let Ok(id) = parse_id(&reservation).and_then(|id| {
                (reservation == hex::encode(id.0))
                    .then_some(id)
                    .ok_or(AslError::InvalidDatabase)
            }) else {
                report.deferred += 1;
                continue;
            };
            let owner = match ImportOwner::try_acquire(&self.home, id.0) {
                Ok(Some(owner)) => owner,
                Ok(None) => {
                    report.live_owners += 1;
                    continue;
                }
                Err(_) => {
                    report.deferred += 1;
                    continue;
                }
            };
            let hold = Hold {
                owner,
                task,
                reservation,
            };
            match rollback_held(&tx, &hold) {
                Ok(()) => {
                    tx.commit().map_err(database_error)?;
                    report.released += 1;
                }
                Err(AslError::SnapshotRecoveryRequired | AslError::InvalidDatabase) => {
                    report.deferred += 1
                }
                Err(e) => return Err(e),
            }
        }
        Ok(report)
    }
}
