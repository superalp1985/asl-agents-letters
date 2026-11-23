use asl_types::error::AslError;
use rusqlite::{TransactionBehavior, params};

use crate::{Store, database_error, inbound_observations};

const PRUNE_BATCH: i64 = 256;

impl Store {
    /// Clear one batch of expired local activity using the persisted deadlines.
    pub fn prune_expired_activity(&mut self, now_ms: i64) -> Result<(), AslError> {
        if now_ms < 0 {
            return Err(AslError::InvalidMessage);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        inbound_observations::delete_expired(&tx, now_ms)?;
        crate::mcp_recovery::prune(&tx, now_ms)?;

        tx.execute(
            "DELETE FROM outbox WHERE message_id IN (
                SELECT message_id FROM outbox WHERE expires_at_ms<=?1 LIMIT ?2
             )",
            params![now_ms, PRUNE_BATCH],
        )
        .map_err(database_error)?;
        // Message IDs are also replay markers while their tasks are live.
        tx.execute(
            "DELETE FROM messages WHERE message_id IN (
                SELECT m.message_id FROM messages m JOIN tasks t ON t.task_id=m.task_id
                WHERE m.expires_at_ms<=?1 AND t.expires_at_ms<=?1
                  AND NOT EXISTS (SELECT 1 FROM outbox o WHERE o.message_id=m.message_id)
                ORDER BY m.expires_at_ms LIMIT ?2
             )",
            params![now_ms, PRUNE_BATCH],
        )
        .map_err(database_error)?;
        tx.execute(
            "UPDATE group_events SET browse_kind=NULL,browse_expires_at_ms=NULL
             WHERE event_id IN (
                SELECT event_id FROM group_events WHERE browse_expires_at_ms<=?1 LIMIT ?2
             )",
            params![now_ms, PRUNE_BATCH],
        )
        .map_err(database_error)?;
        tx.commit().map_err(database_error)
    }
}
