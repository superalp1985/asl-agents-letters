use asl_types::{error::AslError, ids::Id128};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::Serialize;

use crate::{Store, database_error};

const TTL_MS: i64 = 60 * 60 * 1000;
const MAX_TASKS: i64 = 64;
const PAGE: usize = 20;

pub struct RecoverySubmission {
    pub request_id: Id128,
    pub digest: [u8; 32],
    pub valid_until_ms: i64,
}

#[derive(Debug, Eq, PartialEq)]
pub enum RecoveryReservation {
    New,
    Existing(Id128),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum State {
    Queued,
    Active,
    Complete,
    Expired,
    Failed,
    Interrupted,
}

impl State {
    fn value(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Active => "active",
            Self::Complete => "complete",
            Self::Expired => "expired",
            Self::Failed => "failed",
            Self::Interrupted => "interrupted",
        }
    }
}

pub struct RecoveryResult {
    pub status: String,
    pub snapshot: Option<Vec<u8>>,
}

#[derive(Serialize)]
pub struct RecoveryEvent {
    sequence: i64,
    task_id: String,
    status: String,
}

#[derive(Serialize)]
pub struct RecoveryPage {
    events: Vec<RecoveryEvent>,
    oldest_cursor: Option<i64>,
    next_cursor: i64,
    has_more: bool,
}

impl Store {
    pub fn configure_mcp_recovery(
        &self,
        subject: Option<&[u8; 32]>,
        now: i64,
    ) -> Result<(), AslError> {
        let tx = self.recovery_tx()?;
        if subject.is_none() || current_subject(&tx)?.as_deref() != subject.map(|id| &id[..]) {
            tx.execute("DELETE FROM mcp_recovery_download_decisions", [])
                .map_err(database_error)?;
            tx.execute("DELETE FROM mcp_recovery_downloads", [])
                .map_err(database_error)?;
            tx.execute("DELETE FROM mcp_recovery_tasks", [])
                .map_err(database_error)?;
            tx.execute("DELETE FROM mcp_recovery_grant", [])
                .map_err(database_error)?;
            if let Some(subject) = subject {
                tx.execute(
                    "INSERT INTO mcp_recovery_grant(singleton,subject) VALUES (1, ?1)",
                    [subject.as_slice()],
                )
                .map_err(database_error)?;
            }
        } else {
            prune(&tx, now)?;
            interrupt(&tx)?;
        }
        tx.commit().map_err(database_error)
    }

    pub fn start_recovery_task(
        &self,
        subject: &[u8; 32],
        id: Id128,
        now: i64,
    ) -> Result<(), AslError> {
        let tx = self.recovery_tx()?;
        require_subject(&tx, subject)?;
        prune(&tx, now)?;
        insert_task(&tx, id, None, now)?;
        tx.commit().map_err(database_error)
    }

    pub fn reserve_recovery_submission(
        &self,
        subject: &[u8; 32],
        id: Id128,
        submission: &RecoverySubmission,
        can_start: bool,
        now: i64,
    ) -> Result<RecoveryReservation, AslError> {
        let tx = self.recovery_tx()?;
        require_subject(&tx, subject)?;
        prune(&tx, now)?;
        let floor: i64 = tx
            .query_row(
                "SELECT replay_floor_ms FROM mcp_recovery_grant WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if submission.valid_until_ms <= now.max(floor) {
            // Persist expiry pruning even when this call is rejected.
            tx.commit().map_err(database_error)?;
            return Err(AslError::ExpiredMessage);
        }
        if submission.valid_until_ms > now.checked_add(TTL_MS).ok_or(AslError::InvalidMessage)? {
            return Err(AslError::InvalidMessage);
        }
        let previous: Option<([u8; 16], [u8; 32])> = tx
            .query_row(
                "SELECT task_id,request_digest FROM mcp_recovery_tasks WHERE request_id=?1",
                [submission.request_id.0.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(database_error)?;
        if let Some((task, digest)) = previous {
            if digest != submission.digest {
                return Err(AslError::InvalidMessage);
            }
            tx.commit().map_err(database_error)?;
            return Ok(RecoveryReservation::Existing(Id128(task)));
        }
        if !can_start {
            return Err(AslError::QuotaExceeded);
        }
        insert_task(&tx, id, Some(submission), now)?;
        tx.commit().map_err(database_error)?;
        Ok(RecoveryReservation::New)
    }

    pub fn update_recovery_task(
        &self,
        subject: &[u8; 32],
        id: Id128,
        state: State,
        now: i64,
    ) -> Result<(), AslError> {
        self.update_recovery_snapshot(subject, id, state, None, now)
    }

    pub fn update_recovery_snapshot(
        &self,
        subject: &[u8; 32],
        id: Id128,
        state: State,
        snapshot: Option<&[u8]>,
        now: i64,
    ) -> Result<(), AslError> {
        let tx = self.recovery_tx()?;
        require_subject(&tx, subject)?;
        if let Some(snapshot) = snapshot {
            tx.execute(
                "UPDATE mcp_recovery_tasks SET result_snapshot=?2 WHERE task_id=?1
                 AND expires_at_ms>?3 AND status IN ('queued','active')",
                params![id.0.as_slice(), snapshot, now],
            )
            .map_err(database_error)?;
        }
        let changed = tx.execute(
            "UPDATE mcp_recovery_tasks SET status=?2
             WHERE task_id=?1 AND expires_at_ms>?3
             AND ((status='queued' AND ?2!='queued') OR (status='active' AND ?2 NOT IN ('queued','active')))",
            params![id.0.as_slice(), state.value(), now],
        ).map_err(database_error)?;
        if changed != 0 {
            append(&tx, id, state)?;
        }
        tx.commit().map_err(database_error)
    }

    pub fn clear_recovery_results(&self, subject: &[u8; 32]) -> Result<(), AslError> {
        let tx = self.recovery_tx()?;
        require_subject(&tx, subject)?;
        tx.execute(
            "UPDATE mcp_recovery_tasks SET result_snapshot=NULL WHERE result_snapshot IS NOT NULL",
            [],
        )
        .map_err(database_error)?;
        tx.commit().map_err(database_error)
    }

    pub fn interrupt_recovery_tasks(&self, subject: &[u8; 32], now: i64) -> Result<(), AslError> {
        let tx = self.recovery_tx()?;
        require_subject(&tx, subject)?;
        prune(&tx, now)?;
        interrupt(&tx)?;
        tx.commit().map_err(database_error)
    }

    pub fn recovery_task(
        &self,
        subject: &[u8; 32],
        id: Id128,
        now: i64,
    ) -> Result<String, AslError> {
        let tx = self.recovery_tx()?;
        require_subject(&tx, subject)?;
        prune(&tx, now)?;
        let status = tx
            .query_row(
                "SELECT status FROM mcp_recovery_tasks WHERE task_id=?1 AND expires_at_ms>?2",
                params![id.0.as_slice(), now],
                |row| row.get(0),
            )
            .optional()
            .map_err(database_error)?;
        tx.commit().map_err(database_error)?;
        status.ok_or(AslError::NotFound)
    }

    pub fn recovery_result(
        &self,
        subject: &[u8; 32],
        id: Id128,
        now: i64,
    ) -> Result<RecoveryResult, AslError> {
        let tx = self.recovery_tx()?;
        require_subject(&tx, subject)?;
        prune(&tx, now)?;
        let result = tx
            .query_row(
                "SELECT status,result_snapshot FROM mcp_recovery_tasks WHERE task_id=?1",
                [id.0.as_slice()],
                |row| {
                    Ok(RecoveryResult {
                        status: row.get(0)?,
                        snapshot: row.get(1)?,
                    })
                },
            )
            .optional()
            .map_err(database_error)?;
        tx.commit().map_err(database_error)?;
        result.ok_or(AslError::NotFound)
    }

    pub fn recovery_events(
        &self,
        subject: &[u8; 32],
        after: i64,
        now: i64,
    ) -> Result<RecoveryPage, AslError> {
        let tx = self.recovery_tx()?;
        require_subject(&tx, subject)?;
        prune(&tx, now)?;
        let oldest_cursor = tx
            .query_row(
                "SELECT min(e.sequence) FROM mcp_recovery_events e
             JOIN mcp_recovery_tasks t USING(task_id) WHERE t.expires_at_ms>?1",
                [now],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        let mut query = tx
            .prepare(
                "SELECT e.sequence, lower(hex(e.task_id)), e.status FROM mcp_recovery_events e
             JOIN mcp_recovery_tasks t USING(task_id)
             WHERE e.sequence>?1 AND t.expires_at_ms>?2 ORDER BY e.sequence LIMIT ?3",
            )
            .map_err(database_error)?;
        let mut events = query
            .query_map(params![after, now, (PAGE + 1) as i64], |row| {
                Ok(RecoveryEvent {
                    sequence: row.get(0)?,
                    task_id: row.get(1)?,
                    status: row.get(2)?,
                })
            })
            .map_err(database_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(database_error)?;
        let has_more = events.len() > PAGE;
        events.truncate(PAGE);
        let next_cursor = events.last().map_or(after, |event| event.sequence);
        drop(query);
        tx.commit().map_err(database_error)?;
        Ok(RecoveryPage {
            events,
            oldest_cursor,
            next_cursor,
            has_more,
        })
    }

    fn recovery_tx(&self) -> Result<Transaction<'_>, AslError> {
        Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(database_error)
    }
}

fn current_subject(db: &Connection) -> Result<Option<Vec<u8>>, AslError> {
    db.query_row(
        "SELECT subject FROM mcp_recovery_grant WHERE singleton=1",
        [],
        |r| r.get(0),
    )
    .optional()
    .map_err(database_error)
}

pub(crate) fn require_subject(db: &Connection, subject: &[u8; 32]) -> Result<(), AslError> {
    if current_subject(db)?.as_deref() != Some(subject.as_slice()) {
        return Err(AslError::PolicyDenied);
    }
    Ok(())
}

pub(crate) fn prune(db: &Connection, now: i64) -> Result<(), AslError> {
    db.execute(
        "DELETE FROM mcp_recovery_downloads WHERE expires_at_ms<=?1",
        [now],
    )
    .map_err(database_error)?;
    // Keep a time fence when discarding keyed tasks so a clock rollback cannot
    // make their original submission valid again.
    db.execute(
        "UPDATE mcp_recovery_grant SET replay_floor_ms=max(replay_floor_ms,coalesce(
            (SELECT max(expires_at_ms) FROM mcp_recovery_tasks WHERE expires_at_ms<=?1 AND request_id IS NOT NULL),0))
         WHERE EXISTS (SELECT 1 FROM mcp_recovery_tasks WHERE expires_at_ms<=?1 AND request_id IS NOT NULL)",
        [now],
    ).map_err(database_error)?;
    db.execute(
        "DELETE FROM mcp_recovery_tasks WHERE expires_at_ms<=?1",
        [now],
    )
    .map_err(database_error)?;
    Ok(())
}

fn insert_task(
    db: &Connection,
    id: Id128,
    submission: Option<&RecoverySubmission>,
    now: i64,
) -> Result<(), AslError> {
    let count: i64 = db
        .query_row("SELECT count(*) FROM mcp_recovery_tasks", [], |r| r.get(0))
        .map_err(database_error)?;
    if count >= MAX_TASKS {
        return Err(AslError::QuotaExceeded);
    }
    let expiry = now.checked_add(TTL_MS).ok_or(AslError::InvalidMessage)?;
    db.execute(
        "INSERT INTO mcp_recovery_tasks(task_id,status,expires_at_ms,request_id,request_digest)
         VALUES (?1,'queued',?2,?3,?4)",
        params![
            id.0.as_slice(),
            expiry,
            submission.map(|s| s.request_id.0.as_slice()),
            submission.map(|s| s.digest.as_slice())
        ],
    )
    .map_err(database_error)?;
    append(db, id, State::Queued)
}
fn append(db: &Connection, id: Id128, state: State) -> Result<(), AslError> {
    db.execute(
        "INSERT INTO mcp_recovery_events(task_id,status) VALUES (?1,?2)",
        params![id.0.as_slice(), state.value()],
    )
    .map_err(database_error)?;
    Ok(())
}

fn interrupt(db: &Connection) -> Result<(), AslError> {
    db.execute(
        "INSERT INTO mcp_recovery_events(task_id,status)
         SELECT task_id,'interrupted' FROM mcp_recovery_tasks WHERE status IN ('queued','active')",
        [],
    )
    .map_err(database_error)?;
    db.execute(
        "UPDATE mcp_recovery_tasks SET status='interrupted' WHERE status IN ('queued','active')",
        [],
    )
    .map_err(database_error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::open_store;

    #[test]
    fn retry_resolves_before_capacity_checks_and_pruned_requests_cannot_reopen() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("recovery.sqlite3");
        let store = open_store(&path).unwrap();
        let subject = [1; 32];
        let id = Id128([2; 16]);
        let replacement = Id128([3; 16]);
        let submitted_at = 100;
        let submission = RecoverySubmission {
            request_id: Id128([4; 16]),
            digest: [5; 32],
            valid_until_ms: submitted_at + TTL_MS,
        };
        store
            .configure_mcp_recovery(Some(&subject), submitted_at)
            .unwrap();
        assert_eq!(
            store
                .reserve_recovery_submission(&subject, id, &submission, true, submitted_at)
                .unwrap(),
            RecoveryReservation::New,
        );
        drop(store);
        let store = open_store(&path).unwrap();
        store
            .configure_mcp_recovery(Some(&subject), submitted_at + 1)
            .unwrap();
        assert_eq!(
            store
                .reserve_recovery_submission(
                    &subject,
                    replacement,
                    &submission,
                    false,
                    submitted_at + 1
                )
                .unwrap(),
            RecoveryReservation::Existing(id),
        );
        assert_eq!(
            store.recovery_task(&subject, id, submitted_at + 1).unwrap(),
            "interrupted"
        );
        assert!(matches!(
            store.recovery_task(&subject, replacement, submitted_at + 1),
            Err(AslError::NotFound)
        ));
        let after_expiry = submitted_at + TTL_MS;
        assert!(matches!(
            store.reserve_recovery_submission(
                &subject,
                replacement,
                &submission,
                true,
                after_expiry
            ),
            Err(AslError::ExpiredMessage)
        ));
        assert!(matches!(
            store.reserve_recovery_submission(
                &subject,
                replacement,
                &submission,
                true,
                submitted_at + 1
            ),
            Err(AslError::ExpiredMessage)
        ));
    }

    #[test]
    fn schema_v28_query_status_survives_upgrade_without_invented_request_ids() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("recovery.sqlite3");
        let store = open_store(&path).unwrap();
        let subject = [9; 32];
        let id = Id128([8; 16]);
        store.configure_mcp_recovery(Some(&subject), 1).unwrap();
        store.start_recovery_task(&subject, id, 1).unwrap();
        store
            .update_recovery_task(&subject, id, State::Complete, 2)
            .unwrap();
        store
            .connection
            .execute_batch(
                "DROP TABLE mcp_recovery_download_decisions;
             DROP TABLE mcp_recovery_downloads;
             ALTER TABLE mcp_recovery_tasks DROP COLUMN result_snapshot;
             DROP INDEX mcp_recovery_request_id;
             ALTER TABLE mcp_recovery_tasks DROP COLUMN request_digest;
             ALTER TABLE mcp_recovery_tasks DROP COLUMN request_id;
             ALTER TABLE mcp_recovery_grant DROP COLUMN replay_floor_ms;
             DROP TABLE conversation_attachment_refs;
             DROP TABLE conversation_act_events;
             DROP TABLE conversation_budget_grants;
             DROP TABLE mailbox_shards;
             DROP TABLE mailbox_slots;
             DROP TABLE gossip_topic_state;
             DROP TABLE local_capacity_measurements;
             DROP TABLE semantic_context_resources;
             DROP TABLE semantic_context_candidates;
             DELETE FROM schema_migrations WHERE version IN (29,30,31,32,33,34,35);",
            )
            .unwrap();
        drop(store);

        let upgraded = open_store(&path).unwrap();
        assert_eq!(upgraded.schema_version(), crate::SCHEMA_VERSION as u32);
        assert_eq!(upgraded.recovery_task(&subject, id, 3).unwrap(), "complete");
        let submission = RecoverySubmission {
            request_id: id,
            digest: [7; 32],
            valid_until_ms: 100,
        };
        assert_eq!(
            upgraded
                .reserve_recovery_submission(&subject, Id128([6; 16]), &submission, true, 3)
                .unwrap(),
            RecoveryReservation::New
        );
    }

    #[test]
    fn recovery_pages_are_bounded_and_boot_interrupts_unfinished_work() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("recovery.sqlite3");
        let store = open_store(&path).unwrap();
        let subject = [1; 32];
        let other = [2; 32];
        store.configure_mcp_recovery(Some(&subject), 1).unwrap();
        for n in 0..64 {
            store
                .start_recovery_task(&subject, Id128([n; 16]), 1)
                .unwrap();
        }
        assert!(matches!(
            store.start_recovery_task(&subject, Id128([64; 16]), 1),
            Err(AslError::QuotaExceeded)
        ));
        let id = Id128([1; 16]);
        assert!(matches!(
            store.recovery_task(&other, id, 1),
            Err(AslError::PolicyDenied)
        ));
        store
            .update_recovery_task(&subject, id, State::Complete, 2)
            .unwrap();
        drop(store);
        let store = open_store(&path).unwrap();
        store.configure_mcp_recovery(Some(&subject), 3).unwrap();
        assert_eq!(store.recovery_task(&subject, id, 3).unwrap(), "complete");
        assert_eq!(
            store.recovery_task(&subject, Id128([0; 16]), 3).unwrap(),
            "interrupted"
        );
        let page = store.recovery_events(&subject, 0, 3).unwrap();
        assert_eq!(page.events.len(), PAGE);
        assert!(page.has_more);
        let next = store
            .recovery_events(&subject, page.next_cursor, 3)
            .unwrap();
        assert!(next.events[0].sequence > page.next_cursor);
        assert!(
            store
                .recovery_events(&subject, 0, TTL_MS + 1)
                .unwrap()
                .events
                .is_empty()
        );
        assert!(matches!(
            store.recovery_task(&subject, id, 4),
            Err(AslError::NotFound)
        ));
        let id = Id128([99; 16]);
        store.start_recovery_task(&subject, id, 4).unwrap();
        store.configure_mcp_recovery(None, 4).unwrap();
        store.configure_mcp_recovery(Some(&subject), 5).unwrap();
        assert!(matches!(
            store.recovery_task(&subject, id, 5),
            Err(AslError::NotFound)
        ));
    }
}
