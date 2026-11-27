use asl_types::error::AslError;
use rusqlite::{OptionalExtension, params};

use crate::{Store, database_error};

use crate::mailbox::{
    MAX_BUDGET_MESSAGES, MAX_BUDGET_RENEWALS, MAX_BUDGET_WINDOW_MS, MAX_MAILBOX_QUOTA_BYTES,
};

pub const DEFAULT_MESSAGE_BYTE_BUDGET: u64 = 64 * 1024 * 1024;
pub const DEFAULT_MODEL_CALL_BUDGET: u64 = 1_000;
pub const DEFAULT_CPU_BUDGET_MS: u64 = 10 * 60 * 1_000;
pub const DEFAULT_MAILBOX_BYTE_BUDGET: u64 = 16 * 1024 * 1024;

#[derive(Debug)]
pub struct BudgetReservation {
    conversation_id: String,
    message_allocations: Vec<([u8; 32], u32)>,
    resource_charges: Vec<(BudgetKind, u64)>,
}

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
                   granted=MAX(resource_budget_grants.granted,excluded.granted),
                   expires_at_ms=MAX(resource_budget_grants.expires_at_ms,excluded.expires_at_ms),
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

    /// Atomically reserves semantic messages and resource amounts before work
    /// is queued or dispatched. Dropping the reservation keeps it charged.
    pub fn reserve_budget(
        &self,
        conversation_id: &str,
        messages: u32,
        charges: &[(BudgetKind, u64)],
        now_ms: u64,
    ) -> Result<Option<BudgetReservation>, AslError> {
        validate_conversation_id(conversation_id)?;
        validate_now_ms(now_ms)?;
        if messages > MAX_BUDGET_MESSAGES || (messages == 0 && charges.is_empty()) {
            return Err(AslError::InvalidMessage);
        }
        let now = i64::try_from(now_ms).map_err(|_| AslError::InvalidMessage)?;
        let mut normalized = Vec::<(BudgetKind, u64)>::new();
        for (kind, amount) in charges {
            if *amount == 0 {
                continue;
            }
            i64::try_from(*amount).map_err(|_| AslError::InvalidMessage)?;
            if let Some((_, existing)) = normalized.iter_mut().find(|(entry, _)| entry == kind) {
                *existing = existing
                    .checked_add(*amount)
                    .ok_or(AslError::InvalidMessage)?;
                i64::try_from(*existing).map_err(|_| AslError::InvalidMessage)?;
            } else {
                normalized.push((*kind, *amount));
            }
        }
        if messages == 0 && normalized.is_empty() {
            return Err(AslError::InvalidMessage);
        }

        let tx = self
            .connection
            .unchecked_transaction()
            .map_err(database_error)?;
        let authorized: bool = tx
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM conversation_budget_grants
                    WHERE conversation_id=?1 AND expires_at_ms>?2
                 )",
                params![conversation_id, now],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if !authorized {
            return Ok(None);
        }
        let mut message_allocations = Vec::new();
        if messages != 0 {
            let grants = {
                let mut statement = tx
                    .prepare(
                        "SELECT grant_id,messages_granted-messages_consumed
                         FROM conversation_budget_grants
                         WHERE conversation_id=?1 AND expires_at_ms>?2
                           AND messages_consumed<messages_granted
                         ORDER BY expires_at_ms,created_at_ms,grant_id",
                    )
                    .map_err(database_error)?;
                statement
                    .query_map(params![conversation_id, now], |row| {
                        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
                    })
                    .map_err(database_error)?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(database_error)?
            };
            let available = grants.iter().try_fold(0_i64, |total, (_, amount)| {
                total.checked_add(*amount).ok_or(AslError::QuotaExceeded)
            })?;
            if available < i64::from(messages) {
                return Ok(None);
            }

            let mut remaining = i64::from(messages);
            for (raw_id, available) in grants {
                if remaining == 0 {
                    break;
                }
                let grant_id: [u8; 32] =
                    raw_id.try_into().map_err(|_| AslError::InvalidDatabase)?;
                let amount = available.min(remaining);
                let changed = tx
                    .execute(
                        "UPDATE conversation_budget_grants
                         SET messages_consumed=messages_consumed+?3
                         WHERE conversation_id=?1 AND grant_id=?2
                           AND messages_consumed+?3<=messages_granted
                           AND expires_at_ms>?4",
                        params![conversation_id, grant_id.as_slice(), amount, now],
                    )
                    .map_err(database_error)?;
                if changed != 1 {
                    return Ok(None);
                }
                message_allocations.push((
                    grant_id,
                    u32::try_from(amount).map_err(|_| AslError::InvalidDatabase)?,
                ));
                remaining -= amount;
            }
        }

        for (kind, amount) in &normalized {
            let amount = i64::try_from(*amount).map_err(|_| AslError::InvalidMessage)?;
            let changed = tx
                .execute(
                    "UPDATE resource_budget_grants
                     SET consumed=consumed+?1,updated_at_ms=?2
                     WHERE conversation_id=?3 AND kind=?4 AND expires_at_ms>?2
                       AND granted>=consumed AND ?1<=granted-consumed",
                    params![amount, now, conversation_id, kind.code()],
                )
                .map_err(database_error)?;
            if changed != 1 {
                return Ok(None);
            }
        }

        tx.commit().map_err(database_error)?;
        Ok(Some(BudgetReservation {
            conversation_id: conversation_id.to_owned(),
            message_allocations,
            resource_charges: normalized,
        }))
    }

    /// Keeps reserved message counts and settles resource holds to measured
    /// usage. Resource kinds omitted from `actual` remain fully charged.
    pub fn settle_budget_reservation(
        &self,
        reservation: BudgetReservation,
        actual: &[(BudgetKind, u64)],
        now_ms: u64,
    ) -> Result<(), AslError> {
        validate_now_ms(now_ms)?;
        let now = i64::try_from(now_ms).map_err(|_| AslError::InvalidMessage)?;
        let mut actual_by_kind = Vec::<(BudgetKind, u64)>::new();
        for (kind, amount) in actual {
            i64::try_from(*amount).map_err(|_| AslError::InvalidMessage)?;
            if let Some((_, existing)) = actual_by_kind.iter_mut().find(|(entry, _)| entry == kind)
            {
                *existing = existing
                    .checked_add(*amount)
                    .ok_or(AslError::InvalidMessage)?;
                i64::try_from(*existing).map_err(|_| AslError::InvalidMessage)?;
            } else {
                actual_by_kind.push((*kind, *amount));
            }
        }
        if actual_by_kind.iter().any(|(kind, _)| {
            !reservation
                .resource_charges
                .iter()
                .any(|(held, _)| held == kind)
        }) {
            return Err(AslError::InvalidMessage);
        }

        let tx = self
            .connection
            .unchecked_transaction()
            .map_err(database_error)?;
        for (kind, reserved) in &reservation.resource_charges {
            let actual = actual_by_kind
                .iter()
                .find(|(actual_kind, _)| actual_kind == kind)
                .map_or(*reserved, |(_, amount)| *amount);
            let delta = actual.abs_diff(*reserved);
            if delta == 0 {
                continue;
            }
            let delta = i64::try_from(delta).map_err(|_| AslError::InvalidMessage)?;
            let changed = if actual < *reserved {
                tx.execute(
                    "UPDATE resource_budget_grants
                     SET consumed=consumed-?1,updated_at_ms=?2
                     WHERE conversation_id=?3 AND kind=?4 AND consumed>=?1",
                    params![delta, now, reservation.conversation_id, kind.code()],
                )
            } else {
                tx.execute(
                    "UPDATE resource_budget_grants
                     SET consumed=consumed+?1,updated_at_ms=?2
                     WHERE conversation_id=?3 AND kind=?4 AND expires_at_ms>?2
                       AND granted>=consumed AND ?1<=granted-consumed",
                    params![delta, now, reservation.conversation_id, kind.code()],
                )
            }
            .map_err(database_error)?;
            if changed != 1 {
                return Err(AslError::QuotaExceeded);
            }
        }
        tx.commit().map_err(database_error)
    }

    /// Releases a reservation only after the caller has established that
    /// dispatch did not happen.
    pub fn refund_budget_reservation(
        &self,
        reservation: BudgetReservation,
        now_ms: u64,
    ) -> Result<(), AslError> {
        validate_now_ms(now_ms)?;
        let now = i64::try_from(now_ms).map_err(|_| AslError::InvalidMessage)?;
        let tx = self
            .connection
            .unchecked_transaction()
            .map_err(database_error)?;
        for (grant_id, amount) in reservation.message_allocations {
            let changed = tx
                .execute(
                    "UPDATE conversation_budget_grants
                     SET messages_consumed=messages_consumed-?3
                     WHERE conversation_id=?1 AND grant_id=?2
                       AND messages_consumed>=?3",
                    params![
                        reservation.conversation_id,
                        grant_id.as_slice(),
                        i64::from(amount)
                    ],
                )
                .map_err(database_error)?;
            if changed != 1 {
                return Err(AslError::InvalidPolicyState);
            }
        }
        for (kind, amount) in reservation.resource_charges {
            let amount = i64::try_from(amount).map_err(|_| AslError::InvalidMessage)?;
            let changed = tx
                .execute(
                    "UPDATE resource_budget_grants
                     SET consumed=consumed-?1,updated_at_ms=?2
                     WHERE conversation_id=?3 AND kind=?4 AND consumed>=?1",
                    params![amount, now, reservation.conversation_id, kind.code()],
                )
                .map_err(database_error)?;
            if changed != 1 {
                return Err(AslError::InvalidPolicyState);
            }
        }
        tx.commit().map_err(database_error)
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
            || conversation_id.as_bytes().contains(&0)
            || additional == 0
            || expires_at_ms <= now_ms
            || expires_at_ms
                .checked_sub(now_ms)
                .is_none_or(|window| window > MAX_BUDGET_WINDOW_MS as u64)
        {
            return Err(AslError::InvalidMessage);
        }
        if additional > default_resource_budget(kind) {
            return Ok(false);
        }
        let now = i64::try_from(now_ms).map_err(|_| AslError::InvalidMessage)?;
        let expires = i64::try_from(expires_at_ms).map_err(|_| AslError::InvalidMessage)?;
        let additional = i64::try_from(additional).map_err(|_| AslError::InvalidMessage)?;
        let max_total =
            i64::try_from(max_resource_budget_total(kind)).map_err(|_| AslError::InvalidMessage)?;
        let tx = self
            .connection
            .unchecked_transaction()
            .map_err(database_error)?;
        let authorized_expiry: Option<i64> = tx
            .query_row(
                "SELECT MAX(expires_at_ms) FROM conversation_budget_grants
                 WHERE conversation_id=?1 AND expires_at_ms>?2",
                params![conversation_id, now],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if !authorized_expiry.is_some_and(|authorized_expiry| expires <= authorized_expiry) {
            return Ok(false);
        }
        let current_granted: Option<i64> = tx
            .query_row(
                "SELECT granted FROM resource_budget_grants
                 WHERE conversation_id=?1 AND kind=?2 AND expires_at_ms>?3",
                params![conversation_id, kind.code(), now],
                |row| row.get(0),
            )
            .optional()
            .map_err(database_error)?;
        let Some(current_granted) = current_granted else {
            return Ok(false);
        };
        if current_granted < 0
            || current_granted
                .checked_add(additional)
                .is_none_or(|total| total > max_total)
        {
            return Ok(false);
        }
        let changed = tx
            .execute(
                "UPDATE resource_budget_grants
                 SET granted=granted+?1,expires_at_ms=MAX(expires_at_ms,?2),updated_at_ms=?3
                 WHERE conversation_id=?4 AND kind=?5 AND expires_at_ms>?3
                   AND ?1<=?6-granted",
                params![
                    additional,
                    expires,
                    now,
                    conversation_id,
                    kind.code(),
                    max_total
                ],
            )
            .map_err(database_error)?;
        if changed != 1 {
            return Ok(false);
        }
        tx.commit().map_err(database_error)?;
        Ok(true)
    }
}

fn validate_conversation_id(conversation_id: &str) -> Result<(), AslError> {
    if conversation_id.is_empty()
        || conversation_id.len() > 128
        || conversation_id.as_bytes().contains(&0)
    {
        Err(AslError::InvalidMessage)
    } else {
        Ok(())
    }
}

fn validate_now_ms(now_ms: u64) -> Result<(), AslError> {
    i64::try_from(now_ms)
        .map(|_| ())
        .map_err(|_| AslError::InvalidMessage)
}

fn default_resource_budget(kind: BudgetKind) -> u64 {
    match kind {
        BudgetKind::MessageBytes => DEFAULT_MESSAGE_BYTE_BUDGET,
        BudgetKind::ModelCalls => DEFAULT_MODEL_CALL_BUDGET,
        BudgetKind::CpuMs => DEFAULT_CPU_BUDGET_MS,
        BudgetKind::MailboxBytes => DEFAULT_MAILBOX_BYTE_BUDGET,
    }
}

fn max_resource_budget_total(kind: BudgetKind) -> u64 {
    let total = default_resource_budget(kind).saturating_mul(u64::from(MAX_BUDGET_RENEWALS) + 1);
    if kind == BudgetKind::MailboxBytes {
        total.min(MAX_MAILBOX_QUOTA_BYTES as u64)
    } else {
        total
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mailbox::ConversationBudgetGrant;

    #[test]
    fn resource_budgets_fail_closed_consume_and_renew_atomically() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = crate::open_store(&directory.path().join("budget.sqlite3")).unwrap();
        let conversation = "00112233445566778899aabbccddeeff";
        store
            .grant_conversation_budget(ConversationBudgetGrant {
                conversation_id: conversation,
                grant_id: [1; 32],
                messages_granted: 1,
                max_renewals: 0,
                now_ms: 10,
                expires_at_ms: 200,
            })
            .unwrap();
        store
            .grant_resource_budget(conversation, BudgetKind::ModelCalls, 0, 200, 10)
            .unwrap();
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

    #[test]
    fn multi_budget_reservation_is_atomic_and_refundable() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = crate::open_store(&directory.path().join("budget.sqlite3")).unwrap();
        let conversation = "00112233445566778899aabbccddeeff";
        store
            .grant_conversation_budget(ConversationBudgetGrant {
                conversation_id: conversation,
                grant_id: [1; 32],
                messages_granted: 3,
                max_renewals: 0,
                now_ms: 10,
                expires_at_ms: 100,
            })
            .unwrap();
        for (kind, granted) in [
            (BudgetKind::MessageBytes, 10),
            (BudgetKind::MailboxBytes, 4),
        ] {
            store
                .grant_resource_budget(conversation, kind, granted, 100, 10)
                .unwrap();
        }

        assert!(
            store
                .reserve_budget(
                    conversation,
                    2,
                    &[(BudgetKind::MessageBytes, 5), (BudgetKind::MailboxBytes, 5),],
                    20,
                )
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .conversation_budget_available(conversation, 3, 20)
                .unwrap()
        );

        let reservation = store
            .reserve_budget(
                conversation,
                3,
                &[
                    (BudgetKind::MessageBytes, 10),
                    (BudgetKind::MailboxBytes, 4),
                ],
                20,
            )
            .unwrap()
            .unwrap();
        store.refund_budget_reservation(reservation, 20).unwrap();
        let reservation = store
            .reserve_budget(
                conversation,
                3,
                &[
                    (BudgetKind::MessageBytes, 10),
                    (BudgetKind::MailboxBytes, 4),
                ],
                20,
            )
            .unwrap()
            .unwrap();
        store
            .settle_budget_reservation(
                reservation,
                &[(BudgetKind::MessageBytes, 5), (BudgetKind::MailboxBytes, 0)],
                20,
            )
            .unwrap();
        assert!(
            store
                .consume_resource_budget(conversation, BudgetKind::MessageBytes, 5, 20)
                .unwrap()
        );
        assert!(
            store
                .consume_resource_budget(conversation, BudgetKind::MailboxBytes, 4, 20)
                .unwrap()
        );
    }

    #[test]
    fn resource_grants_preserve_consumption_and_bound_renewals() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = crate::open_store(&directory.path().join("budget.sqlite3")).unwrap();
        let conversation = "00112233445566778899aabbccddeeff";
        store
            .grant_conversation_budget(ConversationBudgetGrant {
                conversation_id: conversation,
                grant_id: [1; 32],
                messages_granted: 3,
                max_renewals: 0,
                now_ms: 10,
                expires_at_ms: 100,
            })
            .unwrap();
        store
            .grant_resource_budget(conversation, BudgetKind::ModelCalls, 10, 50, 10)
            .unwrap();
        assert!(
            store
                .consume_resource_budget(conversation, BudgetKind::ModelCalls, 4, 20)
                .unwrap()
        );
        store
            .grant_resource_budget(conversation, BudgetKind::ModelCalls, 20, 80, 30)
            .unwrap();
        assert!(
            store
                .consume_resource_budget(conversation, BudgetKind::ModelCalls, 16, 30)
                .unwrap()
        );
        assert!(
            !store
                .consume_resource_budget(conversation, BudgetKind::ModelCalls, 1, 30)
                .unwrap()
        );

        let cap = max_resource_budget_total(BudgetKind::ModelCalls);
        assert!(
            !store
                .renew_resource_budget(conversation, BudgetKind::ModelCalls, cap, 90, 30)
                .unwrap()
        );
    }

    #[test]
    fn resource_reservations_require_an_active_conversation_grant() {
        let directory = tempfile::tempdir().unwrap();
        let store = crate::open_store(&directory.path().join("budget.sqlite3")).unwrap();
        let conversation = "00112233445566778899aabbccddeeff";
        store
            .grant_resource_budget(conversation, BudgetKind::ModelCalls, 2, 100, 10)
            .unwrap();

        assert!(
            store
                .reserve_budget(conversation, 0, &[(BudgetKind::ModelCalls, 1)], 20)
                .unwrap()
                .is_none()
        );
    }
}
