use asl_types::ids::AgentId;

use super::*;

const MAX_RECOVERY_DOWNLOADS: i64 = 16;

pub enum RecoveryDownload {
    Complete,
    Resumable { durable_bytes: u64 },
}

impl Store {
    pub fn revoke_recovery_download(&self, id: &TransferId) -> Result<(), AslError> {
        self.connection
            .execute(
                "DELETE FROM mcp_recovery_downloads WHERE transfer_id=?1",
                [id_text(id.0.0)],
            )
            .map_err(database_error)?;
        Ok(())
    }

    pub fn authorize_recovery_download(&self, id: &TransferId) -> Result<i64, AslError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let now = current_time_ms();
        tx.execute(
            "DELETE FROM mcp_recovery_downloads WHERE expires_at_ms<=?1",
            [now],
        )
        .map_err(database_error)?;
        let id = id_text(id.0.0);
        let row = load_row_tx(&tx, &id)?;
        ensure_active_transfer(&tx, &row)?;
        if row.part_file_id.is_none() || row.expires_at_ms <= now {
            return Err(AslError::PolicyDenied);
        }
        let subject: Vec<u8> = tx
            .query_row(
                "SELECT subject FROM mcp_recovery_grant WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(database_error)?
            .ok_or(AslError::PolicyDenied)?;
        let count: i64 = tx
            .query_row(
                "SELECT count(*) FROM mcp_recovery_downloads WHERE transfer_id<>?1",
                [&id],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if count >= MAX_RECOVERY_DOWNLOADS {
            return Err(AslError::QuotaExceeded);
        }
        let expiry = now.saturating_add(DOWNLOAD_IDLE_MS);
        tx.execute(
            "INSERT INTO mcp_recovery_downloads(transfer_id,subject,grant_epoch,expires_at_ms)
             SELECT t.transfer_id,?2,w.epoch,?3 FROM transfers t
             JOIN write_grants w USING(write_grant_id) WHERE t.transfer_id=?1
             ON CONFLICT(transfer_id) DO UPDATE SET subject=excluded.subject,
                grant_epoch=excluded.grant_epoch,expires_at_ms=excluded.expires_at_ms",
            params![id, subject, expiry],
        )
        .map_err(database_error)?;
        tx.commit().map_err(database_error)?;
        Ok(expiry)
    }

    pub fn recovery_download(
        &self,
        id: &TransferId,
        subject: &[u8; 32],
    ) -> Result<RecoveryDownload, AslError> {
        let now = current_time_ms();
        self.retire_expired_binding(id, subject, now)?;
        let tx = self
            .connection
            .unchecked_transaction()
            .map_err(database_error)?;
        let state = read_binding(&tx, id, subject, now)?;
        tx.commit().map_err(database_error)?;
        Ok(state)
    }

    fn retire_expired_binding(
        &self,
        id: &TransferId,
        subject: &[u8; 32],
        now: i64,
    ) -> Result<(), AslError> {
        let id = id_text(id.0.0);
        let values = params![id, subject.as_slice(), now];
        let expired: bool = self
            .connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM mcp_recovery_downloads
              WHERE transfer_id=?1 AND subject=?2 AND expires_at_ms<=?3)",
                values,
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if expired {
            self.connection
                .execute(
                    "DELETE FROM mcp_recovery_downloads
                 WHERE transfer_id=?1 AND subject=?2 AND expires_at_ms<=?3",
                    values,
                )
                .map_err(database_error)?;
        }
        Ok(())
    }
}

impl DownloadBroker {
    pub fn check_recovery_download(
        &self,
        id: &TransferId,
        subject: &[u8; 32],
    ) -> Result<(), AslError> {
        self.store.recovery_download(id, subject).map(|_| ())
    }

    pub fn recovery_sources(
        &self,
        id: &TransferId,
        subject: &[u8; 32],
        limit: i64,
    ) -> Result<Option<Vec<(AgentId, PeerId)>>, AslError> {
        let now = current_time_ms();
        self.store.retire_expired_binding(id, subject, now)?;
        let tx = self
            .store
            .connection
            .unchecked_transaction()
            .map_err(database_error)?;
        match read_binding(&tx, id, subject, now)? {
            RecoveryDownload::Complete => return Ok(None),
            RecoveryDownload::Resumable { .. } => {}
        }
        let row = load_row_tx(&tx, &id_text(id.0.0))?;
        self.open_part(&row)?;
        let group = row.group_binding()?;
        let sources = {
            let mut query = tx
                .prepare(
                    "SELECT p.agent_id,s.peer_id FROM transfer_sources s
                 JOIN peers p USING(peer_id) JOIN device_identities d USING(peer_id,agent_id)
                 WHERE s.transfer_id=?1 AND s.state IN ('candidate','active')
                   AND d.revoked_at_ms IS NULL AND d.certificate_expires_ms>?2
                 ORDER BY s.peer_id LIMIT ?3",
                )
                .map_err(database_error)?;
            query
                .query_map(params![id_text(id.0.0), now, limit], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(database_error)?
                .map(|row| {
                    let (agent, peer) = row.map_err(database_error)?;
                    if let Some(group) = &group {
                        ensure_group_member(
                            &tx,
                            &id_text(group.group_id.0.0),
                            sql_number(group.membership_epoch)?,
                            &peer,
                            now,
                        )?;
                    }
                    let agent = bs58::decode(agent)
                        .into_vec()
                        .map_err(|_| AslError::InvalidDatabase)?;
                    Ok((
                        AgentId(agent.try_into().map_err(|_| AslError::InvalidDatabase)?),
                        parse_peer(&peer)?,
                    ))
                })
                .collect::<Result<Vec<_>, AslError>>()?
        };
        tx.commit().map_err(database_error)?;
        Ok(Some(sources))
    }
}

fn read_binding(
    tx: &Transaction<'_>,
    id: &TransferId,
    subject: &[u8; 32],
    now: i64,
) -> Result<RecoveryDownload, AslError> {
    let id_text = id_text(id.0.0);
    let projection = tx
        .query_row(
            "SELECT t.state,t.durable_bytes,t.expires_at_ms,t.part_file_id IS NOT NULL,r.state,
                    t.group_id,t.group_epoch
         FROM mcp_recovery_downloads b
         JOIN mcp_recovery_grant g USING(subject)
         JOIN transfers t USING(transfer_id) JOIN write_grants w USING(write_grant_id)
         JOIN reservations r USING(reservation_id)
         WHERE b.transfer_id=?1 AND b.subject=?2 AND b.expires_at_ms>?3
           AND w.status='active' AND w.kind='inbox' AND w.epoch=b.grant_epoch",
            params![id_text, subject.as_slice(), now],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, bool>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                ))
            },
        )
        .optional()
        .map_err(database_error)?;
    let Some((state, durable_bytes, expiry, has_part, reservation, group_id, group_epoch)) =
        projection
    else {
        let current: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM mcp_recovery_grant WHERE subject=?1)",
                [subject.as_slice()],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        return Err(if current {
            AslError::NotFound
        } else {
            AslError::PolicyDenied
        });
    };
    if let Some(group) = group_binding(group_id, group_epoch)?
        && !group_membership_current(tx, &group, now)?
    {
        return Err(AslError::PolicyDenied);
    }
    if state == "complete" {
        return Ok(RecoveryDownload::Complete);
    }
    if !matches!(
        state.as_str(),
        "pending" | "running" | "paused" | "verifying"
    ) || reservation != "held"
    {
        return Err(AslError::PolicyDenied);
    }
    if !has_part || expiry <= now {
        return Err(AslError::ExpiredMessage);
    }
    Ok(RecoveryDownload::Resumable {
        durable_bytes: u64::try_from(durable_bytes).map_err(|_| AslError::InvalidDatabase)?,
    })
}
