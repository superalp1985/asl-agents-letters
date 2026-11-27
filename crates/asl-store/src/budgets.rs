use asl_types::error::AslError;
use rusqlite::{OptionalExtension, params};

use crate::{Store, database_error};

pub const DEFAULT_MESSAGE_BYTE_BUDGET: u64 = 64 * 1024 * 1024;
pub const DEFAULT_MODEL_CALL_BUDGET: u64 = 1_000;
pub const DEFAULT_CPU_BUDGET_MS: u64 = 10 * 60 * 1_000;
pub const DEFAULT_MAILBOX_BYTE_BUDGET: u64 = 16 * 1024 * 1024;

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
        Ok(available.unwrap_or(false))
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

    pub fn renew_resource_budget(
        &self,
        conversation_id: &str,
        kind: BudgetKind,
        additional: u64,
        expires_at_ms: u64,
        now_ms: u64,
    ) -> Result<bool, AslError> {
        if conversation_id.is_empty()
            || conversation_id.len() > 128
            || additional == 0
            || expires_at_ms <= now_ms
        {
            return Err(AslError::InvalidMessage);
        }
        self.connection
            .execute(
                "INSERT INTO resource_budget_grants(
                    conversation_id,kind,granted,consumed,expires_at_ms,updated_at_ms
                 ) VALUES (?1,?2,?3,0,?4,?5)
                 ON CONFLICT(conversation_id,kind) DO UPDATE SET
                   granted=resource_budget_grants.granted+excluded.granted,
                   expires_at_ms=MAX(resource_budget_grants.expires_at_ms,excluded.expires_at_ms),
                   updated_at_ms=excluded.updated_at_ms",
                params![
                    conversation_id,
                    kind.code(),
                    i64::try_from(additional).map_err(|_| AslError::InvalidMessage)?,
                    i64::try_from(expires_at_ms).map_err(|_| AslError::InvalidMessage)?,
                    i64::try_from(now_ms).map_err(|_| AslError::InvalidMessage)?,
                ],
            )
            .map_err(database_error)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_budgets_fail_closed_consume_and_renew_atomically() {
        let directory = tempfile::tempdir().unwrap();
        let store = crate::open_store(&directory.path().join("budget.sqlite3")).unwrap();
        let conversation = "00112233445566778899aabbccddeeff";
        assert!(
            !store
                .resource_budget_available(conversation, BudgetKind::ModelCalls, 10)
                .unwrap()
        );
        store
            .renew_resource_budget(conversation, BudgetKind::ModelCalls, 2, 100, 10)
            .unwrap();
        assert!(
            store
                .resource_budget_available(conversation, BudgetKind::ModelCalls, 10)
                .unwrap()
        );
        assert!(
            store
                .consume_resource_budget(conversation, BudgetKind::ModelCalls, 2, 10)
                .unwrap()
        );
        assert!(
            !store
                .resource_budget_available(conversation, BudgetKind::ModelCalls, 10)
                .unwrap()
        );
        assert!(
            !store
                .consume_resource_budget(conversation, BudgetKind::ModelCalls, 1, 10)
                .unwrap()
        );
        store
            .renew_resource_budget(conversation, BudgetKind::ModelCalls, 3, 200, 20)
            .unwrap();
        assert!(
            store
                .resource_budget_available(conversation, BudgetKind::ModelCalls, 20)
                .unwrap()
        );
    }
}
