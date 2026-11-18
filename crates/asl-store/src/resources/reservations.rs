use asl_policy::snapshot_files::ImportOwner;
use asl_types::{error::AslError, manifest};
use rusqlite::{Connection, OptionalExtension, params};

use super::{
    ImportAuthority, SnapshotBroker, bump_revision, current_time_ms, database_error, immediate,
    random_id,
};

const DEFAULT_GLOBAL: i64 = 20 << 30;
const DEFAULT_TASK: i64 = 1 << 30;
const IDLE_MS: i64 = 300_000;

pub(super) struct Hold {
    pub(super) reservation: String,
    pub(super) task: String,
    pub(super) owner: ImportOwner,
}

fn limit(db: &Connection, key: &str, default: i64) -> Result<i64, AslError> {
    let value: Option<String> = db
        .query_row("SELECT value_json FROM settings WHERE key=?1", [key], |r| {
            r.get(0)
        })
        .optional()
        .map_err(database_error)?;
    match value {
        None => Ok(default),
        Some(raw) => serde_json::from_str::<i64>(&raw)
            .ok()
            .filter(|v| *v >= 0)
            .ok_or(AslError::InvalidPolicyState),
    }
}

fn fits(used: i64, held: i64, requested: i64, maximum: i64) -> bool {
    used.checked_add(held)
        .and_then(|v| v.checked_add(requested))
        .is_some_and(|v| v <= maximum)
}

fn check_limits(
    db: &Connection,
    grant: &str,
    grant_limit: i64,
    task_bytes: i64,
    extra_logical: i64,
    extra_physical: i64,
) -> Result<(), AslError> {
    let global_limit = limit(db, "storage.snapshot_quota_bytes", DEFAULT_GLOBAL)?;
    let task_limit = limit(db, "storage.snapshot_task_quota_bytes", DEFAULT_TASK)?;
    let empty_manifest =
        manifest::encoded_len_for_size(0).map_err(|_| AslError::InvalidPolicyState)?;
    let used = db
        .query_row(
            "SELECT coalesce(sum(file_size+?1+?2*chunk_count),0) FROM snapshots",
            params![empty_manifest as i64, size_of::<[u8; 32]>() as i64],
            |r| r.get(0),
        )
        .map_err(database_error)?;
    let held = db.query_row("SELECT coalesce(sum(i.physical_bytes),0) FROM snapshot_imports i JOIN reservations r USING(reservation_id) WHERE r.state='held'", [], |r|r.get(0)).map_err(database_error)?;
    let grant_used = db.query_row("SELECT coalesce(sum(s.file_size),0) FROM resources r JOIN snapshots s USING(content_id) WHERE r.grant_id=?1 AND r.active=1", [grant], |r|r.get(0)).map_err(database_error)?;
    let grant_held = db.query_row("SELECT coalesce(sum(r.bytes),0) FROM snapshot_imports i JOIN reservations r USING(reservation_id) WHERE i.grant_id=?1 AND r.state='held'", [grant], |r|r.get(0)).map_err(database_error)?;
    if task_bytes > task_limit
        || !fits(used, held, extra_physical, global_limit)
        || !fits(grant_used, grant_held, extra_logical, grant_limit)
    {
        return Err(AslError::QuotaExceeded);
    }
    Ok(())
}

pub(super) fn check_current_limits(db: &Connection, hold: &Hold) -> Result<(), AslError> {
    let (grant,cap,bytes): (String,i64,i64) = db.query_row("SELECT i.grant_id,g.max_snapshot_bytes,r.bytes FROM snapshot_imports i JOIN grants g USING(grant_id)
        JOIN reservations r USING(reservation_id) WHERE i.reservation_id=?1", [&hold.reservation],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(database_error)?;
    check_limits(db, &grant, cap, bytes, 0, 0)
}

impl SnapshotBroker {
    /// Trusted local storage settings, persisted independently of any import request.
    pub fn set_snapshot_limits(
        &mut self,
        global_bytes: i64,
        task_bytes: i64,
    ) -> Result<(), AslError> {
        if global_bytes < 0 || task_bytes < 0 {
            return Err(AslError::InvalidPolicyState);
        }
        let tx = immediate(&mut self.store.connection)?;
        for (key, value) in [
            ("storage.snapshot_quota_bytes", global_bytes),
            ("storage.snapshot_task_quota_bytes", task_bytes),
        ] {
            tx.execute("INSERT INTO settings(key,value_json,updated_at_ms) VALUES (?1,?2,?3)
                ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json,updated_at_ms=excluded.updated_at_ms",
                params![key,value.to_string(),current_time_ms()]).map_err(database_error)?;
        }
        bump_revision(&tx)?;
        tx.commit().map_err(database_error)
    }

    pub(super) fn reserve(&mut self, auth: &ImportAuthority, size: u64) -> Result<Hold, AslError> {
        let bytes = i64::try_from(size).map_err(|_| AslError::QuotaExceeded)?;
        let tx = immediate(&mut self.store.connection)?;
        let grant_limit: i64 = tx.query_row("SELECT max_snapshot_bytes FROM grants WHERE grant_id=?1 AND epoch=?2 AND status='active'",
                params![auth.id,auth.epoch],|r|r.get(0)).optional().map_err(database_error)?.ok_or(AslError::GrantRevoked)?;
        // Charge one physical manifest per object, including empty files. Held imports
        // each need their own staging space even if they eventually deduplicate.
        let physical = 2
            * (bytes
                + manifest::encoded_len_for_size(size).map_err(|_| AslError::QuotaExceeded)?
                    as i64);
        check_limits(&tx, &auth.id, grant_limit, bytes, bytes, physical)?;
        let id = random_id().0;
        let owner =
            ImportOwner::try_acquire(&self.home, id)?.ok_or(AslError::InvalidPolicyState)?;
        let hold = Hold {
            task: hex::encode(random_id().0),
            reservation: hex::encode(id),
            owner,
        };
        let now = current_time_ms();
        tx.execute("INSERT INTO tasks(task_id,direction,audience_json,state,created_at_ms,expires_at_ms) VALUES (?1,'local','{\"kind\":\"private\"}','queued',?2,?3)",params![hold.task,now,now+IDLE_MS]).map_err(database_error)?;
        tx.execute("INSERT INTO reservations(reservation_id,task_id,kind,bytes,state,progress_at_ms,expires_at_ms) VALUES (?1,?2,'snapshot',?3,'held',?4,?5)",params![hold.reservation,hold.task,bytes,now,now+IDLE_MS]).map_err(database_error)?;
        tx.execute("INSERT INTO snapshot_imports(reservation_id,grant_id,grant_epoch,physical_bytes) VALUES (?1,?2,?3,?4)",params![hold.reservation,auth.id,auth.epoch,physical]).map_err(database_error)?;
        tx.commit().map_err(database_error)?;
        Ok(hold)
    }

    pub(super) fn release(&mut self, hold: &Hold) -> Result<(), AslError> {
        let tx = immediate(&mut self.store.connection)?;
        super::recovery::rollback_held(&tx, hold)?;
        tx.commit().map_err(database_error)
    }
}

pub(super) fn check_live(db: &Connection, hold: &Hold, now: i64) -> Result<(), AslError> {
    let ok: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM snapshot_imports i JOIN reservations r USING(reservation_id)
        JOIN grants g USING(grant_id) JOIN tasks t ON t.task_id=r.task_id WHERE i.reservation_id=?1 AND r.task_id=?2
        AND r.kind='snapshot' AND r.state='held' AND r.expires_at_ms>?3 AND t.state='queued' AND t.direction='local'
        AND g.status='active' AND g.epoch=i.grant_epoch)",params![hold.reservation,hold.task,now],|r|r.get(0)).map_err(database_error)?;
    if ok {
        Ok(())
    } else {
        Err(AslError::PolicyDenied)
    }
}

pub(super) fn progress(db: &mut Connection, hold: &Hold) -> Result<(), AslError> {
    let tx = immediate(db)?;
    let now = current_time_ms();
    check_live(&tx, hold, now)?;
    tx.execute(
        "UPDATE reservations SET progress_at_ms=?2,expires_at_ms=?3 WHERE reservation_id=?1",
        params![hold.reservation, now, now + IDLE_MS],
    )
    .map_err(database_error)?;
    tx.execute(
        "UPDATE tasks SET expires_at_ms=?2 WHERE task_id=?1",
        params![hold.task, now + IDLE_MS],
    )
    .map_err(database_error)?;
    tx.commit().map_err(database_error)
}

pub(super) fn finish(
    db: &Connection,
    hold: &Hold,
    reservation_state: &str,
    task_state: &str,
) -> Result<(), AslError> {
    let changed = db.execute(
        "UPDATE reservations SET state=?2 WHERE reservation_id=?1 AND task_id=?3 AND state='held'",
        params![hold.reservation, reservation_state, hold.task],
    )
    .map_err(database_error)?;
    if changed != 1 {
        return Err(AslError::InvalidPolicyState);
    }
    db.execute(
        "UPDATE snapshot_imports SET install_content_id=NULL WHERE reservation_id=?1",
        [&hold.reservation],
    )
    .map_err(database_error)?;
    db.execute(
        "UPDATE tasks SET state=?2 WHERE task_id=?1 AND state='queued'",
        params![hold.task, task_state],
    )
    .map_err(database_error)?;
    Ok(())
}
