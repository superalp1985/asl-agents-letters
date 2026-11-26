use asl_types::error::AslError;
use rusqlite::{Connection, TransactionBehavior, params};

use crate::{
    Store, current_time_ms, database_error,
    inbound_observations::{DAY_MS, MAX_OBSERVATION_DAYS, observation_days},
    write_setting,
};

const RETENTION_KEY: &str = "activity.group_observation_days.v1";

pub(crate) fn group_observation_days(db: &Connection) -> Result<u8, AslError> {
    observation_days(db, RETENTION_KEY)
}

pub(crate) fn browse_deadline(
    db: &Connection,
    now: i64,
    journal_deadline: i64,
) -> Result<Option<i64>, AslError> {
    let days = group_observation_days(db)?;
    Ok((days > 0).then(|| journal_deadline.min(now.saturating_add(i64::from(days) * DAY_MS))))
}

impl Store {
    pub fn set_group_observation_days(&mut self, days: u8) -> Result<(), AslError> {
        if days > MAX_OBSERVATION_DAYS {
            return Err(AslError::InvalidMessage);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let now = current_time_ms();
        write_setting(&tx, RETENTION_KEY, &days.to_string(), now)?;
        let limit_ms = i64::from(days) * DAY_MS;
        // Only the activity projection changes. MLS still needs its journal.
        tx.execute(
            "UPDATE group_events SET browse_kind=NULL,browse_expires_at_ms=NULL
             WHERE browse_kind IS NOT NULL
               AND (?1=0 OR browse_expires_at_ms<=?2 OR created_at_ms<=?2-?1)",
            params![limit_ms, now],
        )
        .map_err(database_error)?;
        tx.execute(
            "UPDATE group_events SET browse_expires_at_ms=created_at_ms+?1
             WHERE browse_expires_at_ms-created_at_ms>?1",
            [limit_ms],
        )
        .map_err(database_error)?;
        if days == 0 {
            tx.execute("DELETE FROM conversation_act_events", [])
                .map_err(database_error)?;
        } else {
            tx.execute(
                "DELETE FROM conversation_act_events
                 WHERE expires_at_ms<=?1 OR received_at_ms<=?2",
                params![now, now.saturating_sub(limit_ms)],
            )
            .map_err(database_error)?;
            tx.execute(
                "UPDATE conversation_act_events
                 SET expires_at_ms=min(expires_at_ms,received_at_ms+?1)",
                [limit_ms],
            )
            .map_err(database_error)?;
        }
        tx.commit().map_err(database_error)
    }
}
