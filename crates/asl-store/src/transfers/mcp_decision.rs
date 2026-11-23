use super::{
    AslError, Connection, Id128, OptionalExtension, Store, Transaction, TransactionBehavior,
    TransferId, current_time_ms, database_error, group_binding, group_membership_current, id_text,
    params, parse_transfer,
};

pub struct RecoveryDownloadDecision {
    pub transfer_id: TransferId,
    pub state: &'static str,
    pub expires_at_ms: i64,
}

impl Store {
    pub fn authorize_recovery_download_decision(
        &self,
        approval: Id128,
    ) -> Result<RecoveryDownloadDecision, AslError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let approval = id_text(approval.0);
        let now = current_time_ms();
        let decision = read_decision(&tx, &approval, now)?.ok_or(AslError::NotFound)?;
        if !matches!(decision.state, "awaiting_approval" | "approved") {
            return Err(AslError::PolicyDenied);
        }
        let changed = tx
            .execute(
                "INSERT INTO mcp_recovery_download_decisions(approval_id,subject)
             SELECT ?1,subject FROM mcp_recovery_grant WHERE singleton=1
             ON CONFLICT(approval_id) DO UPDATE SET subject=excluded.subject",
                [&approval],
            )
            .map_err(database_error)?;
        if changed != 1 {
            return Err(AslError::PolicyDenied);
        }
        tx.commit().map_err(database_error)?;
        Ok(decision)
    }

    pub fn revoke_recovery_download_decision(&self, approval: Id128) -> Result<(), AslError> {
        self.connection
            .execute(
                "DELETE FROM mcp_recovery_download_decisions WHERE approval_id=?1",
                [id_text(approval.0)],
            )
            .map_err(database_error)?;
        Ok(())
    }

    pub fn recovery_download_decision(
        &self,
        approval: Id128,
        subject: &[u8; 32],
    ) -> Result<RecoveryDownloadDecision, AslError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(database_error)?;
        crate::mcp_recovery::require_subject(&tx, subject)?;
        let approval = id_text(approval.0);
        let now = current_time_ms();
        let expires: i64 = tx
            .query_row(
                "SELECT c.expires_at_ms FROM mcp_recovery_download_decisions b
             JOIN transfer_consents c USING(approval_id)
             WHERE b.approval_id=?1 AND b.subject=?2",
                params![approval, subject.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(database_error)?
            .ok_or(AslError::NotFound)?;
        if expires <= now {
            tx.execute(
                "DELETE FROM mcp_recovery_download_decisions WHERE approval_id=?1",
                [&approval],
            )
            .map_err(database_error)?;
            tx.commit().map_err(database_error)?;
            return Err(AslError::ExpiredMessage);
        }
        let decision = read_decision(&tx, &approval, now)?.ok_or(AslError::NotFound)?;
        tx.commit().map_err(database_error)?;
        Ok(decision)
    }
}

fn read_decision(
    db: &Connection,
    approval: &str,
    now: i64,
) -> Result<Option<RecoveryDownloadDecision>, AslError> {
    let record = db.query_row(
        "SELECT c.transfer_id,c.state,c.expires_at_ms,c.group_id,c.group_epoch
         FROM transfer_consents c JOIN write_grants w ON w.write_grant_id=c.destination_write_grant_id
         WHERE c.approval_id=?1 AND c.direction='download' AND c.destination_filename IS NOT NULL
           AND c.expires_at_ms>?2 AND w.kind='inbox' AND w.status='active' AND w.epoch=c.grant_epoch",
        params![approval, now],
        |row| Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, Option<i64>>(4)?,
        )),
    ).optional().map_err(database_error)?;
    let Some((transfer, state, expires_at_ms, group_id, group_epoch)) = record else {
        return Ok(None);
    };
    if let Some(group) = group_binding(group_id, group_epoch)?
        && !group_membership_current(db, &group, now)?
    {
        return Err(AslError::PolicyDenied);
    }
    let state = match state.as_str() {
        "pending" => "awaiting_approval",
        "approved" => "approved",
        "denied" => "denied",
        "consumed" => "consumed",
        "expired" => return Err(AslError::ExpiredMessage),
        _ => return Err(AslError::InvalidDatabase),
    };
    Ok(Some(RecoveryDownloadDecision {
        transfer_id: parse_transfer(&transfer)?,
        state,
        expires_at_ms,
    }))
}
