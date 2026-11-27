use asl_types::error::AslError;
use rusqlite::{OptionalExtension, params};

use crate::{Store, database_error};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetKind {
    MessageBytes,
    ModelCalls,
    CpuMs,
    MailboxBytes,
}

impl BudgetKind {
    fn code(self) -> i64 {
        match self {
            Self::MessageBytes => 1,
            Self::ModelCalls => 2,
            Self::CpuMs => 3,
            Self::MailboxBytes => 4,
        }
    }
}

impl Store {
    pub fn grant_resource_budget(
        &self,
        conversation_id: &str,
        kind: BudgetKind,
        granted: u64,
        expires_at_ms: u64,
        now_ms: u64,
    ) -> Result<(), AslError> {
        if conversation_id.is_empty() || conversation_id.len() > 128 || expires_at_ms <= now_ms {
            return Err(AslError::InvalidMessage);
        }
        self.connection
            .execute(
                "INSERT INTO resource_budget_grants(
                    conversation_id,kind,granted,consumed,expires_at_ms,updated_at_ms
                 ) VALUES (?1,?2,?3,0,?4,?5)
                 ON CONFLICT(conversation_id,kind) DO UPDATE SET
                   granted=excluded.granted,
                   consumed=MIN(resource_budget_grants.consumed,excluded.granted),
                   expires_at_ms=excluded.expires_at_ms,
                   updated_at_ms=excluded.updated_at_ms
                 WHERE excluded.expires_at_ms > resource_budget_grants.expires_at_ms",
                params![
                    conversation_id,
                    kind.code(),
                    i64::try_from(granted).map_err(|_| AslError::InvalidMessage)?,
                    i64::try_from(expires_at_ms).map_err(|_| AslError::InvalidMessage)?,
                    i64::try_from(now_ms).map_err(|_| AslError::InvalidMessage)?,
                ],
            )
            .map(|_| ())
            .map_err(database_error)
    }

    pub fn resource_budget_available(
        &self,
        conversation_id: &str,
        kind: BudgetKind,
        now_ms: u64,
    ) -> Result<bool, AslError> {
        let available: Option<bool> = self
            .connection
            .query_row(
                "SELECT granted>consumed FROM resource_budget_grants
                 WHERE conversation_id=?1 AND kind=?2 AND expires_at_ms>?3",
                params![
                    conversation_id,
                    kind.code(),
                    i64::try_from(now_ms).map_err(|_| AslError::InvalidMessage)?,
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(database_error)?;
        Ok(available.unwrap_or(true))
    }

    pub fn consume_resource_budget(
        &self,
        conversation_id: &str,
        kind: BudgetKind,
        amount: u64,
        now_ms: u64,
    ) -> Result<bool, AslError> {
        if amount == 0 {
            return Ok(true);
        }
        let changed = self
            .connection
            .execute(
                "UPDATE resource_budget_grants
                 SET consumed=consumed+?1,updated_at_ms=?2
                 WHERE conversation_id=?3 AND kind=?4 AND expires_at_ms>?2
                   AND consumed+?1<=granted",
                params![
                    i64::try_from(amount).map_err(|_| AslError::InvalidMessage)?,
                    i64::try_from(now_ms).map_err(|_| AslError::InvalidMessage)?,
                    conversation_id,
                    kind.code(),
                ],
            )
            .map_err(database_error)?;
        Ok(changed == 1)
    }
}
