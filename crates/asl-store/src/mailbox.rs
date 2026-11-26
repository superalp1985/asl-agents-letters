use asl_types::error::AslError;
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};

use crate::{Store, database_error};

pub const MAILBOX_ID_BYTES: usize = 32;
pub const MAX_MAILBOX_CIPHERTEXT_BYTES: usize = 64 * 1024;
pub const MAX_MAILBOX_PADDED_BYTES: u32 = 1024 * 1024;
pub const MAX_MAILBOX_TTL_MS: i64 = 30 * 24 * 60 * 60 * 1_000;
pub const MAX_MAILBOX_QUOTA_ENTRIES: u32 = 4_096;
pub const MAX_MAILBOX_QUOTA_BYTES: i64 = 256 * 1024 * 1024;

pub const MAX_BUDGET_MESSAGES: u32 = 1_000_000;
pub const MAX_BUDGET_RENEWALS: u16 = 32;
pub const MAX_BUDGET_WINDOW_MS: i64 = 30 * 24 * 60 * 60 * 1_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MailboxQuota {
    pub max_entries: u32,
    pub max_bytes: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MailboxPut {
    Inserted,
    Duplicate,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MailboxPruneReport {
    pub envelopes_removed: u64,
    pub shards_removed: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MailboxEnvelope<'a> {
    pub topic_id: [u8; MAILBOX_ID_BYTES],
    pub mailbox_id: [u8; MAILBOX_ID_BYTES],
    pub envelope_hash: [u8; MAILBOX_ID_BYTES],
    pub ciphertext: &'a [u8],
    pub padded_size: u32,
    pub now_ms: i64,
    pub expires_at_ms: i64,
    pub quota: MailboxQuota,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MailboxShard<'a> {
    pub topic_id: [u8; MAILBOX_ID_BYTES],
    pub mailbox_id: [u8; MAILBOX_ID_BYTES],
    pub shard_id: [u8; MAILBOX_ID_BYTES],
    pub shard_hash: [u8; MAILBOX_ID_BYTES],
    pub ciphertext: &'a [u8],
    pub padded_size: u32,
    pub now_ms: i64,
    pub expires_at_ms: i64,
    pub quota: MailboxQuota,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredMailboxEnvelope {
    pub topic_id: [u8; MAILBOX_ID_BYTES],
    pub mailbox_id: [u8; MAILBOX_ID_BYTES],
    pub envelope_hash: [u8; MAILBOX_ID_BYTES],
    pub ciphertext: Vec<u8>,
    pub padded_size: u32,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredMailboxShard {
    pub topic_id: [u8; MAILBOX_ID_BYTES],
    pub mailbox_id: [u8; MAILBOX_ID_BYTES],
    pub shard_id: [u8; MAILBOX_ID_BYTES],
    pub shard_hash: [u8; MAILBOX_ID_BYTES],
    pub ciphertext: Vec<u8>,
    pub padded_size: u32,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConversationBudgetGrant<'a> {
    pub conversation_id: &'a str,
    pub grant_id: [u8; MAILBOX_ID_BYTES],
    pub messages_granted: u32,
    pub max_renewals: u16,
    pub now_ms: i64,
    pub expires_at_ms: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConversationBudgetRenewal<'a> {
    pub conversation_id: &'a str,
    pub grant_id: [u8; MAILBOX_ID_BYTES],
    pub renewed_from: [u8; MAILBOX_ID_BYTES],
    pub additional_messages: u32,
    pub now_ms: i64,
    pub expires_at_ms: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConversationBudgetConsumption {
    pub messages_consumed: u32,
    pub messages_remaining: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversationBudgetGrantView {
    pub conversation_id: String,
    pub grant_id: [u8; MAILBOX_ID_BYTES],
    pub renewed_from: Option<[u8; MAILBOX_ID_BYTES]>,
    pub renewal_depth: u32,
    pub max_renewals: u32,
    pub messages_granted: u32,
    pub messages_consumed: u32,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
}

impl Store {
    pub fn put_mailbox_envelope(
        &mut self,
        envelope: MailboxEnvelope<'_>,
    ) -> Result<MailboxPut, AslError> {
        validate_mailbox_put(
            &envelope.topic_id,
            &envelope.mailbox_id,
            &envelope.envelope_hash,
            envelope.ciphertext,
            envelope.padded_size,
            envelope.now_ms,
            envelope.expires_at_ms,
            envelope.quota,
        )?;

        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        prune_mailbox_target(
            &tx,
            &envelope.topic_id,
            &envelope.mailbox_id,
            envelope.now_ms,
        )?;

        let existing = tx
            .query_row(
                "SELECT envelope_hash,ciphertext,padded_size,expires_at_ms
                 FROM mailbox_slots
                 WHERE topic_id=?1 AND mailbox_id=?2",
                params![envelope.topic_id.as_slice(), envelope.mailbox_id.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(database_error)?;

        if let Some((hash, ciphertext, padded_size, expires_at_ms)) = existing {
            if hash.as_slice() == envelope.envelope_hash
                && ciphertext.as_slice() == envelope.ciphertext
                && padded_size == i64::from(envelope.padded_size)
                && expires_at_ms == envelope.expires_at_ms
            {
                tx.commit().map_err(database_error)?;
                return Ok(MailboxPut::Duplicate);
            }
            return Err(AslError::InvalidMessage);
        }

        ensure_mailbox_quota(
            &tx,
            &envelope.topic_id,
            &envelope.mailbox_id,
            envelope.padded_size,
            envelope.quota,
        )?;
        tx.execute(
            "INSERT INTO mailbox_slots(
                topic_id,mailbox_id,envelope_hash,ciphertext,padded_size,
                created_at_ms,expires_at_ms
             ) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                envelope.topic_id.as_slice(),
                envelope.mailbox_id.as_slice(),
                envelope.envelope_hash.as_slice(),
                envelope.ciphertext,
                i64::from(envelope.padded_size),
                envelope.now_ms,
                envelope.expires_at_ms,
            ],
        )
        .map_err(database_error)?;
        tx.commit().map_err(database_error)?;
        Ok(MailboxPut::Inserted)
    }

    pub fn put_mailbox_shard(&mut self, shard: MailboxShard<'_>) -> Result<MailboxPut, AslError> {
        validate_mailbox_put(
            &shard.topic_id,
            &shard.mailbox_id,
            &shard.shard_id,
            shard.ciphertext,
            shard.padded_size,
            shard.now_ms,
            shard.expires_at_ms,
            shard.quota,
        )?;
        validate_random_id(&shard.shard_hash)?;

        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        prune_mailbox_target(&tx, &shard.topic_id, &shard.mailbox_id, shard.now_ms)?;

        let existing = tx
            .query_row(
                "SELECT shard_hash,ciphertext,padded_size,expires_at_ms
                 FROM mailbox_shards
                 WHERE topic_id=?1 AND mailbox_id=?2 AND shard_id=?3",
                params![
                    shard.topic_id.as_slice(),
                    shard.mailbox_id.as_slice(),
                    shard.shard_id.as_slice()
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(database_error)?;

        if let Some((hash, ciphertext, padded_size, expires_at_ms)) = existing {
            if hash.as_slice() == shard.shard_hash
                && ciphertext.as_slice() == shard.ciphertext
                && padded_size == i64::from(shard.padded_size)
                && expires_at_ms == shard.expires_at_ms
            {
                tx.commit().map_err(database_error)?;
                return Ok(MailboxPut::Duplicate);
            }
            return Err(AslError::InvalidMessage);
        }

        let hash_owner = tx
            .query_row(
                "SELECT shard_id FROM mailbox_shards
                 WHERE topic_id=?1 AND mailbox_id=?2 AND shard_hash=?3",
                params![
                    shard.topic_id.as_slice(),
                    shard.mailbox_id.as_slice(),
                    shard.shard_hash.as_slice()
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(database_error)?;
        if hash_owner.is_some() {
            return Err(AslError::InvalidMessage);
        }

        ensure_mailbox_quota(
            &tx,
            &shard.topic_id,
            &shard.mailbox_id,
            shard.padded_size,
            shard.quota,
        )?;
        tx.execute(
            "INSERT INTO mailbox_shards(
                topic_id,mailbox_id,shard_id,shard_hash,ciphertext,padded_size,
                created_at_ms,expires_at_ms
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                shard.topic_id.as_slice(),
                shard.mailbox_id.as_slice(),
                shard.shard_id.as_slice(),
                shard.shard_hash.as_slice(),
                shard.ciphertext,
                i64::from(shard.padded_size),
                shard.now_ms,
                shard.expires_at_ms,
            ],
        )
        .map_err(database_error)?;
        tx.commit().map_err(database_error)?;
        Ok(MailboxPut::Inserted)
    }

    pub fn load_mailbox_envelope(
        &self,
        topic_id: &[u8; MAILBOX_ID_BYTES],
        mailbox_id: &[u8; MAILBOX_ID_BYTES],
        now_ms: i64,
    ) -> Result<Option<StoredMailboxEnvelope>, AslError> {
        validate_random_id(topic_id)?;
        validate_random_id(mailbox_id)?;
        validate_now(now_ms)?;
        self.connection
            .query_row(
                "SELECT envelope_hash,ciphertext,padded_size,created_at_ms,expires_at_ms
                 FROM mailbox_slots
                 WHERE topic_id=?1 AND mailbox_id=?2 AND expires_at_ms>?3",
                params![topic_id.as_slice(), mailbox_id.as_slice(), now_ms],
                |row| {
                    Ok(StoredMailboxEnvelope {
                        topic_id: *topic_id,
                        mailbox_id: *mailbox_id,
                        envelope_hash: blob_id(row.get(0)?)?,
                        ciphertext: row.get(1)?,
                        padded_size: integer_u32(row.get(2)?)?,
                        created_at_ms: row.get(3)?,
                        expires_at_ms: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(database_error)
    }

    /// Lists only non-expired opaque envelopes for one locally derived mailbox
    /// topic. The topic key is a routing identifier, never a decryption key.
    pub fn list_mailbox_envelopes(
        &self,
        topic_id: &[u8; MAILBOX_ID_BYTES],
        now_ms: i64,
        limit: u32,
    ) -> Result<Vec<StoredMailboxEnvelope>, AslError> {
        validate_random_id(topic_id)?;
        validate_now(now_ms)?;
        if limit == 0 || limit > MAX_MAILBOX_QUOTA_ENTRIES {
            return Err(AslError::QuotaExceeded);
        }
        let mut statement = self
            .connection
            .prepare_cached(
                "SELECT mailbox_id,envelope_hash,ciphertext,padded_size,
                        created_at_ms,expires_at_ms
                 FROM mailbox_slots
                 WHERE topic_id=?1 AND expires_at_ms>?2
                 ORDER BY created_at_ms,mailbox_id
                 LIMIT ?3",
            )
            .map_err(database_error)?;
        statement
            .query_map(
                params![topic_id.as_slice(), now_ms, i64::from(limit)],
                |row| {
                    Ok(StoredMailboxEnvelope {
                        topic_id: *topic_id,
                        mailbox_id: blob_id(row.get(0)?)?,
                        envelope_hash: blob_id(row.get(1)?)?,
                        ciphertext: row.get(2)?,
                        padded_size: integer_u32(row.get(3)?)?,
                        created_at_ms: row.get(4)?,
                        expires_at_ms: row.get(5)?,
                    })
                },
            )
            .map_err(database_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(database_error)
    }

    pub fn load_mailbox_shard(
        &self,
        topic_id: &[u8; MAILBOX_ID_BYTES],
        mailbox_id: &[u8; MAILBOX_ID_BYTES],
        shard_id: &[u8; MAILBOX_ID_BYTES],
        now_ms: i64,
    ) -> Result<Option<StoredMailboxShard>, AslError> {
        validate_random_id(topic_id)?;
        validate_random_id(mailbox_id)?;
        validate_random_id(shard_id)?;
        validate_now(now_ms)?;
        self.connection
            .query_row(
                "SELECT shard_hash,ciphertext,padded_size,created_at_ms,expires_at_ms
                 FROM mailbox_shards
                 WHERE topic_id=?1 AND mailbox_id=?2 AND shard_id=?3
                   AND expires_at_ms>?4",
                params![
                    topic_id.as_slice(),
                    mailbox_id.as_slice(),
                    shard_id.as_slice(),
                    now_ms
                ],
                |row| {
                    Ok(StoredMailboxShard {
                        topic_id: *topic_id,
                        mailbox_id: *mailbox_id,
                        shard_id: *shard_id,
                        shard_hash: blob_id(row.get(0)?)?,
                        ciphertext: row.get(1)?,
                        padded_size: integer_u32(row.get(2)?)?,
                        created_at_ms: row.get(3)?,
                        expires_at_ms: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(database_error)
    }

    pub fn ack_mailbox_envelope(
        &mut self,
        topic_id: &[u8; MAILBOX_ID_BYTES],
        mailbox_id: &[u8; MAILBOX_ID_BYTES],
        envelope_hash: &[u8; MAILBOX_ID_BYTES],
    ) -> Result<bool, AslError> {
        validate_random_id(topic_id)?;
        validate_random_id(mailbox_id)?;
        validate_random_id(envelope_hash)?;
        let removed = self
            .connection
            .execute(
                "DELETE FROM mailbox_slots
                 WHERE topic_id=?1 AND mailbox_id=?2 AND envelope_hash=?3",
                params![
                    topic_id.as_slice(),
                    mailbox_id.as_slice(),
                    envelope_hash.as_slice()
                ],
            )
            .map_err(database_error)?;
        Ok(removed == 1)
    }

    pub fn ack_mailbox_shard(
        &mut self,
        topic_id: &[u8; MAILBOX_ID_BYTES],
        mailbox_id: &[u8; MAILBOX_ID_BYTES],
        shard_id: &[u8; MAILBOX_ID_BYTES],
        shard_hash: &[u8; MAILBOX_ID_BYTES],
    ) -> Result<bool, AslError> {
        validate_random_id(topic_id)?;
        validate_random_id(mailbox_id)?;
        validate_random_id(shard_id)?;
        validate_random_id(shard_hash)?;
        let removed = self
            .connection
            .execute(
                "DELETE FROM mailbox_shards
                 WHERE topic_id=?1 AND mailbox_id=?2 AND shard_id=?3 AND shard_hash=?4",
                params![
                    topic_id.as_slice(),
                    mailbox_id.as_slice(),
                    shard_id.as_slice(),
                    shard_hash.as_slice()
                ],
            )
            .map_err(database_error)?;
        Ok(removed == 1)
    }

    pub fn prune_mailboxes(&mut self, now_ms: i64) -> Result<MailboxPruneReport, AslError> {
        validate_now(now_ms)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let envelopes_removed = tx
            .execute(
                "DELETE FROM mailbox_slots WHERE expires_at_ms<=?1",
                [now_ms],
            )
            .map_err(database_error)? as u64;
        let shards_removed = tx
            .execute(
                "DELETE FROM mailbox_shards WHERE expires_at_ms<=?1",
                [now_ms],
            )
            .map_err(database_error)? as u64;
        tx.commit().map_err(database_error)?;
        Ok(MailboxPruneReport {
            envelopes_removed,
            shards_removed,
        })
    }

    pub fn grant_conversation_budget(
        &mut self,
        grant: ConversationBudgetGrant<'_>,
    ) -> Result<MailboxPut, AslError> {
        validate_conversation_id(grant.conversation_id)?;
        validate_random_id(&grant.grant_id)?;
        validate_budget_amount(grant.messages_granted)?;
        validate_budget_renewals(grant.max_renewals)?;
        validate_budget_expiry(grant.now_ms, grant.expires_at_ms)?;

        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        if let Some(existing) = read_budget_grant(&tx, grant.conversation_id, &grant.grant_id)? {
            if existing.renewed_from.is_none()
                && existing.renewal_depth == 0
                && existing.max_renewals == u32::from(grant.max_renewals)
                && existing.messages_granted == grant.messages_granted
                && existing.expires_at_ms == grant.expires_at_ms
            {
                tx.commit().map_err(database_error)?;
                return Ok(MailboxPut::Duplicate);
            }
            return Err(AslError::InvalidMessage);
        }
        tx.execute(
            "INSERT INTO conversation_budget_grants(
                conversation_id,grant_id,renewed_from,renewal_depth,max_renewals,
                messages_granted,messages_consumed,created_at_ms,expires_at_ms
             ) VALUES (?1,?2,NULL,0,?3,?4,0,?5,?6)",
            params![
                grant.conversation_id,
                grant.grant_id.as_slice(),
                i64::from(grant.max_renewals),
                i64::from(grant.messages_granted),
                grant.now_ms,
                grant.expires_at_ms
            ],
        )
        .map_err(database_error)?;
        tx.commit().map_err(database_error)?;
        Ok(MailboxPut::Inserted)
    }

    pub fn renew_conversation_budget(
        &mut self,
        renewal: ConversationBudgetRenewal<'_>,
    ) -> Result<MailboxPut, AslError> {
        validate_conversation_id(renewal.conversation_id)?;
        validate_random_id(&renewal.grant_id)?;
        validate_random_id(&renewal.renewed_from)?;
        validate_budget_amount(renewal.additional_messages)?;
        validate_budget_expiry(renewal.now_ms, renewal.expires_at_ms)?;

        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let parent = read_budget_grant(&tx, renewal.conversation_id, &renewal.renewed_from)?
            .ok_or(AslError::NotFound)?;
        if parent.expires_at_ms <= renewal.now_ms {
            return Err(AslError::ExpiredMessage);
        }
        let next_depth = parent
            .renewal_depth
            .checked_add(1)
            .ok_or(AslError::QuotaExceeded)?;
        if next_depth > parent.max_renewals || renewal.expires_at_ms < parent.expires_at_ms {
            return Err(AslError::QuotaExceeded);
        }

        if let Some(existing) = read_budget_grant(&tx, renewal.conversation_id, &renewal.grant_id)?
        {
            if existing.renewed_from == Some(renewal.renewed_from)
                && existing.renewal_depth == next_depth
                && existing.messages_granted == renewal.additional_messages
                && existing.expires_at_ms == renewal.expires_at_ms
            {
                tx.commit().map_err(database_error)?;
                return Ok(MailboxPut::Duplicate);
            }
            return Err(AslError::InvalidMessage);
        }

        tx.execute(
            "INSERT INTO conversation_budget_grants(
                conversation_id,grant_id,renewed_from,renewal_depth,max_renewals,
                messages_granted,messages_consumed,created_at_ms,expires_at_ms
             ) VALUES (?1,?2,?3,?4,?5,?6,0,?7,?8)",
            params![
                renewal.conversation_id,
                renewal.grant_id.as_slice(),
                renewal.renewed_from.as_slice(),
                i64::from(next_depth),
                i64::from(parent.max_renewals),
                i64::from(renewal.additional_messages),
                renewal.now_ms,
                renewal.expires_at_ms
            ],
        )
        .map_err(database_error)?;
        tx.commit().map_err(database_error)?;
        Ok(MailboxPut::Inserted)
    }

    pub fn consume_conversation_budget(
        &mut self,
        conversation_id: &str,
        messages: u32,
        now_ms: i64,
    ) -> Result<ConversationBudgetConsumption, AslError> {
        validate_conversation_id(conversation_id)?;
        validate_budget_amount(messages)?;
        validate_now(now_ms)?;

        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
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
                .query_map(params![conversation_id, now_ms], |row| {
                    Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
                })
                .map_err(database_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(database_error)?
        };

        let available = grants.iter().map(|(_, available)| *available).sum::<i64>();
        if available < i64::from(messages) {
            return Err(AslError::QuotaExceeded);
        }

        let mut remaining_to_charge = i64::from(messages);
        for (grant_id, available) in grants {
            if remaining_to_charge == 0 {
                break;
            }
            let charge = available.min(remaining_to_charge);
            let updated = tx
                .execute(
                    "UPDATE conversation_budget_grants
                     SET messages_consumed=messages_consumed+?3
                     WHERE conversation_id=?1 AND grant_id=?2
                       AND messages_consumed+?3<=messages_granted
                       AND expires_at_ms>?4",
                    params![conversation_id, grant_id, charge, now_ms],
                )
                .map_err(database_error)?;
            if updated != 1 {
                return Err(AslError::QuotaExceeded);
            }
            remaining_to_charge -= charge;
        }

        let messages_remaining = tx
            .query_row(
                "SELECT COALESCE(SUM(messages_granted-messages_consumed),0)
                 FROM conversation_budget_grants
                 WHERE conversation_id=?1 AND expires_at_ms>?2",
                params![conversation_id, now_ms],
                |row| row.get::<_, i64>(0),
            )
            .map_err(database_error)?;
        tx.commit().map_err(database_error)?;
        Ok(ConversationBudgetConsumption {
            messages_consumed: messages,
            messages_remaining: messages_remaining.clamp(0, i64::from(u32::MAX)) as u32,
        })
    }

    pub fn conversation_budget_available(
        &self,
        conversation_id: &str,
        messages: u32,
        now_ms: i64,
    ) -> Result<bool, AslError> {
        validate_conversation_id(conversation_id)?;
        validate_budget_amount(messages)?;
        validate_now(now_ms)?;
        let available = self
            .connection
            .query_row(
                "SELECT COALESCE(SUM(messages_granted-messages_consumed),0)
                 FROM conversation_budget_grants
                 WHERE conversation_id=?1 AND expires_at_ms>?2
                   AND messages_consumed<messages_granted",
                params![conversation_id, now_ms],
                |row| row.get::<_, i64>(0),
            )
            .map_err(database_error)?;
        Ok(available >= i64::from(messages))
    }

    pub fn latest_active_conversation_budget(
        &self,
        conversation_id: &str,
        now_ms: i64,
    ) -> Result<Option<ConversationBudgetGrantView>, AslError> {
        validate_conversation_id(conversation_id)?;
        validate_now(now_ms)?;
        self.connection
            .query_row(
                "SELECT grant_id,renewed_from,renewal_depth,max_renewals,
                        messages_granted,messages_consumed,created_at_ms,expires_at_ms
                 FROM conversation_budget_grants
                 WHERE conversation_id=?1 AND expires_at_ms>?2
                 ORDER BY expires_at_ms DESC,created_at_ms DESC,grant_id DESC
                 LIMIT 1",
                params![conversation_id, now_ms],
                |row| {
                    Ok(ConversationBudgetGrantView {
                        conversation_id: conversation_id.to_owned(),
                        grant_id: blob_id(row.get(0)?)?,
                        renewed_from: row.get::<_, Option<Vec<u8>>>(1)?.map(blob_id).transpose()?,
                        renewal_depth: integer_u32(row.get(2)?)?,
                        max_renewals: integer_u32(row.get(3)?)?,
                        messages_granted: integer_u32(row.get(4)?)?,
                        messages_consumed: integer_u32(row.get(5)?)?,
                        created_at_ms: row.get(6)?,
                        expires_at_ms: row.get(7)?,
                    })
                },
            )
            .optional()
            .map_err(database_error)
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_mailbox_put(
    topic_id: &[u8; MAILBOX_ID_BYTES],
    mailbox_id: &[u8; MAILBOX_ID_BYTES],
    content_id: &[u8; MAILBOX_ID_BYTES],
    ciphertext: &[u8],
    padded_size: u32,
    now_ms: i64,
    expires_at_ms: i64,
    quota: MailboxQuota,
) -> Result<(), AslError> {
    validate_random_id(topic_id)?;
    validate_random_id(mailbox_id)?;
    validate_random_id(content_id)?;
    validate_now(now_ms)?;
    if ciphertext.is_empty()
        || ciphertext.len() > MAX_MAILBOX_CIPHERTEXT_BYTES
        || padded_size < ciphertext.len() as u32
        || padded_size > MAX_MAILBOX_PADDED_BYTES
        || expires_at_ms <= now_ms
        || expires_at_ms
            .checked_sub(now_ms)
            .is_none_or(|ttl| ttl > MAX_MAILBOX_TTL_MS)
        || quota.max_entries == 0
        || quota.max_entries > MAX_MAILBOX_QUOTA_ENTRIES
        || quota.max_bytes <= 0
        || quota.max_bytes > MAX_MAILBOX_QUOTA_BYTES
    {
        return Err(AslError::InvalidMessage);
    }
    Ok(())
}

fn validate_random_id(id: &[u8; MAILBOX_ID_BYTES]) -> Result<(), AslError> {
    if id.iter().all(|byte| *byte == 0) {
        Err(AslError::InvalidMessage)
    } else {
        Ok(())
    }
}

fn validate_now(now_ms: i64) -> Result<(), AslError> {
    if now_ms < 0 {
        Err(AslError::InvalidMessage)
    } else {
        Ok(())
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

fn validate_budget_amount(messages: u32) -> Result<(), AslError> {
    if messages == 0 || messages > MAX_BUDGET_MESSAGES {
        Err(AslError::InvalidMessage)
    } else {
        Ok(())
    }
}

fn validate_budget_renewals(max_renewals: u16) -> Result<(), AslError> {
    if max_renewals > MAX_BUDGET_RENEWALS {
        Err(AslError::InvalidMessage)
    } else {
        Ok(())
    }
}

fn validate_budget_expiry(now_ms: i64, expires_at_ms: i64) -> Result<(), AslError> {
    validate_now(now_ms)?;
    if expires_at_ms <= now_ms
        || expires_at_ms
            .checked_sub(now_ms)
            .is_none_or(|window| window > MAX_BUDGET_WINDOW_MS)
    {
        Err(AslError::InvalidMessage)
    } else {
        Ok(())
    }
}

fn prune_mailbox_target(
    tx: &Transaction<'_>,
    topic_id: &[u8; MAILBOX_ID_BYTES],
    mailbox_id: &[u8; MAILBOX_ID_BYTES],
    now_ms: i64,
) -> Result<(), AslError> {
    tx.execute(
        "DELETE FROM mailbox_slots
         WHERE topic_id=?1 AND mailbox_id=?2 AND expires_at_ms<=?3",
        params![topic_id.as_slice(), mailbox_id.as_slice(), now_ms],
    )
    .map_err(database_error)?;
    tx.execute(
        "DELETE FROM mailbox_shards
         WHERE topic_id=?1 AND mailbox_id=?2 AND expires_at_ms<=?3",
        params![topic_id.as_slice(), mailbox_id.as_slice(), now_ms],
    )
    .map_err(database_error)?;
    Ok(())
}

fn ensure_mailbox_quota(
    tx: &Transaction<'_>,
    topic_id: &[u8; MAILBOX_ID_BYTES],
    mailbox_id: &[u8; MAILBOX_ID_BYTES],
    additional_bytes: u32,
    quota: MailboxQuota,
) -> Result<(), AslError> {
    let (entries, bytes) = tx
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM mailbox_slots
                 WHERE topic_id=?1 AND mailbox_id=?2)+
                (SELECT COUNT(*) FROM mailbox_shards
                 WHERE topic_id=?1 AND mailbox_id=?2),
                (SELECT COALESCE(SUM(padded_size),0) FROM mailbox_slots
                 WHERE topic_id=?1 AND mailbox_id=?2)+
                (SELECT COALESCE(SUM(padded_size),0) FROM mailbox_shards
                 WHERE topic_id=?1 AND mailbox_id=?2)",
            params![topic_id.as_slice(), mailbox_id.as_slice()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .map_err(database_error)?;
    if entries + 1 > i64::from(quota.max_entries)
        || bytes.saturating_add(i64::from(additional_bytes)) > quota.max_bytes
    {
        return Err(AslError::QuotaExceeded);
    }
    Ok(())
}

fn read_budget_grant(
    tx: &Transaction<'_>,
    conversation_id: &str,
    grant_id: &[u8; MAILBOX_ID_BYTES],
) -> Result<Option<ConversationBudgetGrantView>, AslError> {
    tx.query_row(
        "SELECT renewed_from,renewal_depth,max_renewals,messages_granted,
                messages_consumed,created_at_ms,expires_at_ms
         FROM conversation_budget_grants
         WHERE conversation_id=?1 AND grant_id=?2",
        params![conversation_id, grant_id.as_slice()],
        |row| {
            let renewed_from = row.get::<_, Option<Vec<u8>>>(0)?.map(blob_id).transpose()?;
            Ok(ConversationBudgetGrantView {
                conversation_id: conversation_id.to_owned(),
                grant_id: *grant_id,
                renewed_from,
                renewal_depth: integer_u32(row.get(1)?)?,
                max_renewals: integer_u32(row.get(2)?)?,
                messages_granted: integer_u32(row.get(3)?)?,
                messages_consumed: integer_u32(row.get(4)?)?,
                created_at_ms: row.get(5)?,
                expires_at_ms: row.get(6)?,
            })
        },
    )
    .optional()
    .map_err(database_error)
}

fn blob_id(bytes: Vec<u8>) -> rusqlite::Result<[u8; MAILBOX_ID_BYTES]> {
    bytes.try_into().map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Blob,
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid opaque id length").into(),
        )
    })
}

fn integer_u32(value: i64) -> rusqlite::Result<u32> {
    u32::try_from(value).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Integer,
            std::io::Error::new(std::io::ErrorKind::InvalidData, "integer is out of range").into(),
        )
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use asl_types::error::AslError;
    use rusqlite::Connection;
    use tempfile::TempDir;

    use super::*;
    use crate::open_store;

    fn test_store() -> (TempDir, PathBuf, Store) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mailbox.sqlite3");
        let store = open_store(&path).unwrap();
        (directory, path, store)
    }

    fn id(seed: u8) -> [u8; MAILBOX_ID_BYTES] {
        [seed.max(1); MAILBOX_ID_BYTES]
    }

    fn quota(entries: u32, bytes: i64) -> MailboxQuota {
        MailboxQuota {
            max_entries: entries,
            max_bytes: bytes,
        }
    }

    #[test]
    fn v35_through_v39_migrations_create_all_new_tables() {
        let (_directory, _path, store) = test_store();
        assert_eq!(store.schema_version(), crate::SCHEMA_VERSION as u32);
        for table in [
            "mailbox_slots",
            "mailbox_shards",
            "conversation_budget_grants",
            "conversation_act_events",
            "conversation_attachment_refs",
            "gossip_topic_state",
            "local_capacity_measurements",
            "group_access_policies",
            "group_access_members",
            "contact_invites",
            "contact_invite_receipts",
            "contact_invite_prompts",
            "contact_invite_actions",
            "group_invite_requests",
            "migration_group_hints",
        ] {
            let exists: bool = store
                .connection
                .query_row(
                    "SELECT EXISTS(
                        SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1
                     )",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(exists, "missing table {table}");
        }
    }

    #[test]
    fn upgrades_a_v34_store_to_v35() {
        let (_directory, path, store) = test_store();
        drop(store);

        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "DROP TABLE conversation_attachment_refs;
                 DROP TABLE conversation_act_events;
                 DROP TABLE conversation_budget_grants;
                 DROP TABLE mailbox_shards;
                 DROP TABLE mailbox_slots;
                 DROP TABLE gossip_topic_state;
                 DROP TABLE local_capacity_measurements;
                 DROP TABLE group_access_members;
                 DROP TABLE group_access_policies;
                 DROP TABLE group_invite_requests;
                 DROP TABLE migration_group_hints;
                 DELETE FROM schema_migrations WHERE version IN (35,36,37,38,39);",
            )
            .unwrap();
        drop(connection);

        let store = open_store(&path).unwrap();
        assert_eq!(store.schema_version(), crate::SCHEMA_VERSION as u32);
        let migration_count: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(migration_count, crate::SCHEMA_VERSION);
        let budget_table_exists: bool = store
            .connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_schema
                    WHERE type='table' AND name='conversation_budget_grants'
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(budget_table_exists);
    }

    #[test]
    fn envelope_put_is_idempotent_and_rejects_overwrite() {
        let (_directory, _path, mut store) = test_store();
        let envelope = MailboxEnvelope {
            topic_id: id(1),
            mailbox_id: id(2),
            envelope_hash: id(3),
            ciphertext: b"opaque-ciphertext",
            padded_size: 128,
            now_ms: 1_000,
            expires_at_ms: 10_000,
            quota: quota(2, 1_024),
        };
        assert_eq!(
            store.put_mailbox_envelope(envelope).unwrap(),
            MailboxPut::Inserted
        );
        assert_eq!(
            store.put_mailbox_envelope(envelope).unwrap(),
            MailboxPut::Duplicate
        );
        let loaded = store
            .load_mailbox_envelope(&envelope.topic_id, &envelope.mailbox_id, 2_000)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.ciphertext, b"opaque-ciphertext");
        assert_eq!(loaded.padded_size, 128);

        let mut different = envelope;
        different.envelope_hash = id(4);
        assert!(matches!(
            store.put_mailbox_envelope(different),
            Err(AslError::InvalidMessage)
        ));
        assert!(
            store
                .ack_mailbox_envelope(
                    &envelope.topic_id,
                    &envelope.mailbox_id,
                    &envelope.envelope_hash
                )
                .unwrap()
        );
        assert!(
            !store
                .ack_mailbox_envelope(
                    &envelope.topic_id,
                    &envelope.mailbox_id,
                    &envelope.envelope_hash
                )
                .unwrap()
        );
    }

    #[test]
    fn lists_live_opaque_envelopes_for_one_topic() {
        let (_directory, _path, mut store) = test_store();
        let topic_id = id(1);
        for (seed, expires_at_ms) in [(2, 10_000), (3, 5_000)] {
            store
                .put_mailbox_envelope(MailboxEnvelope {
                    topic_id,
                    mailbox_id: id(seed),
                    envelope_hash: id(seed + 10),
                    ciphertext: &[seed; 16],
                    padded_size: 32,
                    now_ms: 1_000,
                    expires_at_ms,
                    quota: quota(4, 1_024),
                })
                .unwrap();
        }
        store
            .put_mailbox_envelope(MailboxEnvelope {
                topic_id: id(9),
                mailbox_id: id(4),
                envelope_hash: id(14),
                ciphertext: b"other",
                padded_size: 16,
                now_ms: 1_000,
                expires_at_ms: 10_000,
                quota: quota(4, 1_024),
            })
            .unwrap();

        let live = store.list_mailbox_envelopes(&topic_id, 6_000, 8).unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].mailbox_id, id(2));
        assert_eq!(live[0].ciphertext, [2; 16]);
    }

    #[test]
    fn mailbox_rejects_invalid_expired_and_over_quota_writes() {
        let (_directory, _path, mut store) = test_store();
        let invalid_id = MailboxEnvelope {
            topic_id: [0; MAILBOX_ID_BYTES],
            mailbox_id: id(2),
            envelope_hash: id(3),
            ciphertext: b"x",
            padded_size: 1,
            now_ms: 1,
            expires_at_ms: 2,
            quota: quota(1, 10),
        };
        assert!(matches!(
            store.put_mailbox_envelope(invalid_id),
            Err(AslError::InvalidMessage)
        ));

        let expired = MailboxEnvelope {
            topic_id: id(1),
            mailbox_id: id(2),
            envelope_hash: id(3),
            ciphertext: b"x",
            padded_size: 1,
            now_ms: 10,
            expires_at_ms: 10,
            quota: quota(1, 10),
        };
        assert!(matches!(
            store.put_mailbox_envelope(expired),
            Err(AslError::InvalidMessage)
        ));

        let bounded = MailboxShard {
            topic_id: id(1),
            mailbox_id: id(2),
            shard_id: id(3),
            shard_hash: id(4),
            ciphertext: b"12345",
            padded_size: 8,
            now_ms: 1,
            expires_at_ms: 100,
            quota: quota(2, 10),
        };
        assert_eq!(
            store.put_mailbox_shard(bounded).unwrap(),
            MailboxPut::Inserted
        );
        let over_quota = MailboxShard {
            shard_id: id(5),
            shard_hash: id(6),
            ciphertext: b"12345",
            ..bounded
        };
        assert!(matches!(
            store.put_mailbox_shard(over_quota),
            Err(AslError::QuotaExceeded)
        ));
    }

    #[test]
    fn expired_slots_are_pruned_and_can_be_reused() {
        let (_directory, _path, mut store) = test_store();
        let first = MailboxEnvelope {
            topic_id: id(1),
            mailbox_id: id(2),
            envelope_hash: id(3),
            ciphertext: b"first",
            padded_size: 8,
            now_ms: 1,
            expires_at_ms: 10,
            quota: quota(1, 64),
        };
        store.put_mailbox_envelope(first).unwrap();
        let second = MailboxEnvelope {
            envelope_hash: id(4),
            ciphertext: b"second",
            now_ms: 10,
            expires_at_ms: 20,
            ..first
        };
        assert_eq!(
            store.put_mailbox_envelope(second).unwrap(),
            MailboxPut::Inserted
        );
        let loaded = store
            .load_mailbox_envelope(&second.topic_id, &second.mailbox_id, 10)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.envelope_hash, second.envelope_hash);
        let report = store.prune_mailboxes(20).unwrap();
        assert_eq!(report.envelopes_removed, 1);
    }

    #[test]
    fn budget_consumption_is_persistent_and_renewal_is_finite() {
        let (_directory, path, mut store) = test_store();
        let grant = ConversationBudgetGrant {
            conversation_id: "conversation-1",
            grant_id: id(1),
            messages_granted: 5,
            max_renewals: 1,
            now_ms: 1_000,
            expires_at_ms: 10_000,
        };
        assert_eq!(
            store.grant_conversation_budget(grant).unwrap(),
            MailboxPut::Inserted
        );
        assert_eq!(
            store.grant_conversation_budget(grant).unwrap(),
            MailboxPut::Duplicate
        );
        assert_eq!(
            store
                .consume_conversation_budget("conversation-1", 3, 2_000)
                .unwrap(),
            ConversationBudgetConsumption {
                messages_consumed: 3,
                messages_remaining: 2
            }
        );
        drop(store);

        let mut store = open_store(&path).unwrap();
        assert_eq!(
            store
                .consume_conversation_budget("conversation-1", 2, 2_100)
                .unwrap(),
            ConversationBudgetConsumption {
                messages_consumed: 2,
                messages_remaining: 0
            }
        );
        assert!(matches!(
            store.consume_conversation_budget("conversation-1", 1, 2_200),
            Err(AslError::QuotaExceeded)
        ));

        let renewal = ConversationBudgetRenewal {
            conversation_id: "conversation-1",
            grant_id: id(2),
            renewed_from: id(1),
            additional_messages: 4,
            now_ms: 3_000,
            expires_at_ms: 20_000,
        };
        assert_eq!(
            store.renew_conversation_budget(renewal).unwrap(),
            MailboxPut::Inserted
        );
        assert_eq!(
            store
                .latest_active_conversation_budget("conversation-1", 3_100)
                .unwrap()
                .unwrap()
                .grant_id,
            id(2)
        );
        assert_eq!(
            store.renew_conversation_budget(renewal).unwrap(),
            MailboxPut::Duplicate
        );
        let second_renewal = ConversationBudgetRenewal {
            grant_id: id(3),
            renewed_from: id(2),
            now_ms: 4_000,
            expires_at_ms: 30_000,
            ..renewal
        };
        assert!(matches!(
            store.renew_conversation_budget(second_renewal),
            Err(AslError::QuotaExceeded)
        ));
    }
}
