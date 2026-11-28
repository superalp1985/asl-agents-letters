use asl_types::{
    error::AslError,
    ids::{AgentId, Id128},
};
use rusqlite::{OptionalExtension, Row, TransactionBehavior, params};

use crate::{Store, database_error};

pub const MAX_CONTACT_INVITE_LIFETIME_MS: u64 = 24 * 60 * 60 * 1_000;
const MAX_PENDING_CONTACT_INVITES_PER_AGENT: i64 = 4;
const MAX_PENDING_CONTACT_INVITES: i64 = 64;
const MAX_PENDING_CONTACT_INVITE_PROMPTS: i64 = 64;
const MAX_CONTACT_INVITE_NOTE_CHARS: usize = 80;
const MAX_PROMPT_TAG_CHARS: usize = 64;
const MAX_ACTION_BATCH: i64 = 32;
const MAX_ACTION_HISTORY: i64 = 256;
const MAX_PENDING_ACTIONS: i64 = 64;
const MAX_ACTION_RESULT_CHARS: usize = 512;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContactInvite {
    pub invite_id: Id128,
    pub token: Id128,
    pub agent_id: AgentId,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub note: Option<String>,
    pub signature: [u8; 65],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContactInvitePromptState {
    Pending,
    Approved,
    Rejected,
    Expired,
}

impl ContactInvitePromptState {
    fn parse(value: &str) -> Result<Self, AslError> {
        match value {
            "pending" => Ok(Self::Pending),
            "approved" => Ok(Self::Approved),
            "rejected" => Ok(Self::Rejected),
            "expired" => Ok(Self::Expired),
            _ => Err(AslError::InvalidDatabase),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContactInvitePrompt {
    pub prompt_id: Id128,
    pub tag: String,
    pub invite_id: Id128,
    pub remote_agent: AgentId,
    pub note: String,
    pub expires_at_ms: u64,
    pub state: ContactInvitePromptState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContactInviteActionKind {
    Add,
    Import,
    Decide,
}

impl ContactInviteActionKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Import => "import",
            Self::Decide => "decide",
        }
    }

    fn parse(value: &str) -> Result<Self, AslError> {
        match value {
            "add" => Ok(Self::Add),
            "import" => Ok(Self::Import),
            "decide" => Ok(Self::Decide),
            _ => Err(AslError::InvalidDatabase),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContactInviteActionPayload {
    Envelope(Vec<u8>),
    Prompt(Id128),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContactInviteAction {
    pub action_id: i64,
    pub kind: ContactInviteActionKind,
    pub payload: ContactInviteActionPayload,
}

impl Store {
    #[allow(clippy::too_many_arguments)]
    pub fn create_contact_invite(
        &mut self,
        invite_id: Id128,
        token: Id128,
        agent_id: AgentId,
        created_at_ms: u64,
        expires_at_ms: u64,
        note: &str,
        signature: [u8; 65],
    ) -> Result<(), AslError> {
        if invite_id.0 == [0; 16]
            || token.0 == [0; 16]
            || agent_id.0 == [0; 32]
            || created_at_ms > i64::MAX as u64
            || expires_at_ms > i64::MAX as u64
            || expires_at_ms <= created_at_ms
            || expires_at_ms - created_at_ms > MAX_CONTACT_INVITE_LIFETIME_MS
        {
            return Err(AslError::InvalidMessage);
        }
        let note = normalize_note(note)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        transaction
            .execute(
                "DELETE FROM contact_invites WHERE expires_at_ms<=?1",
                [created_at_ms as i64],
            )
            .map_err(database_error)?;
        let duplicate: bool = transaction
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM contact_invites
                    WHERE invite_id=?1 OR token=?2
                    UNION ALL
                    SELECT 1 FROM contact_invite_receipts
                    WHERE invite_id=?1 OR token_hash=?3
                 )",
                params![
                    invite_id.as_bytes().as_slice(),
                    token.as_bytes().as_slice(),
                    invite_token_hash(token).as_slice(),
                ],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if duplicate {
            return Err(AslError::InvalidMessage);
        }
        let agent_pending: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM contact_invites
                 WHERE agent_id=?1 AND state='pending'",
                [agent_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        let total_pending: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM contact_invites WHERE state='pending'",
                [],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if agent_pending >= MAX_PENDING_CONTACT_INVITES_PER_AGENT
            || total_pending >= MAX_PENDING_CONTACT_INVITES
        {
            return Err(AslError::QuotaExceeded);
        }
        transaction
            .execute(
                "INSERT INTO contact_invites(
                    invite_id,token,agent_id,created_at_ms,expires_at_ms,state,note,signature
                 ) VALUES (?1,?2,?3,?4,?5,'pending',?6,?7)",
                params![
                    invite_id.as_bytes().as_slice(),
                    token.as_bytes().as_slice(),
                    agent_id.as_bytes().as_slice(),
                    created_at_ms as i64,
                    expires_at_ms as i64,
                    note,
                    signature.as_slice(),
                ],
            )
            .map_err(database_error)?;
        transaction.commit().map_err(database_error)
    }

    pub fn active_contact_invites(&self, now_ms: u64) -> Result<Vec<ContactInvite>, AslError> {
        if now_ms > i64::MAX as u64 {
            return Err(AslError::InvalidMessage);
        }
        let mut statement = self
            .connection
            .prepare(
                "SELECT invite_id,token,agent_id,created_at_ms,expires_at_ms,note,signature
                 FROM contact_invites
                 WHERE state='pending' AND expires_at_ms>?1
                 ORDER BY expires_at_ms,invite_id",
            )
            .map_err(database_error)?;
        let rows = statement
            .query_map([now_ms as i64], decode_invite)
            .map_err(database_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(database_error)
    }

    pub fn find_active_contact_invite_by_token(
        &self,
        token: Id128,
        now_ms: u64,
    ) -> Result<Option<ContactInvite>, AslError> {
        if token.0 == [0; 16] || now_ms > i64::MAX as u64 {
            return Err(AslError::InvalidMessage);
        }
        self.connection
            .query_row(
                "SELECT invite_id,token,agent_id,created_at_ms,expires_at_ms,note,signature
                 FROM contact_invites
                 WHERE token=?1 AND state='pending' AND expires_at_ms>?2",
                params![token.as_bytes().as_slice(), now_ms as i64],
                decode_invite,
            )
            .optional()
            .map_err(database_error)
    }

    pub fn consume_contact_invite(
        &mut self,
        invite_id: Id128,
        now_ms: u64,
        accepted: bool,
    ) -> Result<bool, AslError> {
        if invite_id.0 == [0; 16] || now_ms > i64::MAX as u64 {
            return Err(AslError::InvalidMessage);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let invite: Option<(Id128, i64)> = transaction
            .query_row(
                "SELECT token,expires_at_ms FROM contact_invites
                 WHERE invite_id=?1 AND state='pending'",
                [invite_id.as_bytes().as_slice()],
                |row| {
                    let token: Vec<u8> = row.get(0)?;
                    Ok((
                        Id128(
                            token
                                .try_into()
                                .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        ),
                        row.get(1)?,
                    ))
                },
            )
            .optional()
            .map_err(database_error)?;
        let Some((token, expires_at_ms)) = invite else {
            return Ok(false);
        };
        if expires_at_ms <= now_ms as i64 {
            return Ok(false);
        }
        let consumed = transaction
            .execute(
                "UPDATE contact_invites SET state='consumed'
                 WHERE invite_id=?1 AND state='pending' AND expires_at_ms>?2",
                params![invite_id.as_bytes().as_slice(), now_ms as i64],
            )
            .map_err(database_error)?;
        if consumed != 1 {
            return Ok(false);
        }
        let receipt = transaction
            .execute(
                "INSERT INTO contact_invite_receipts(
                    invite_id,token_hash,consumed_at_ms,accepted
                 ) VALUES (?1,?2,?3,?4)
                 ON CONFLICT(invite_id) DO NOTHING",
                params![
                    invite_id.as_bytes().as_slice(),
                    invite_token_hash(token).as_slice(),
                    now_ms as i64,
                    i64::from(accepted),
                ],
            )
            .map_err(database_error)?;
        if receipt != 1 {
            return Ok(false);
        }
        transaction.commit().map_err(database_error)?;
        Ok(true)
    }

    pub fn revoke_contact_invite(&self, invite_id: Id128, now_ms: u64) -> Result<bool, AslError> {
        if invite_id.0 == [0; 16] || now_ms > i64::MAX as u64 {
            return Err(AslError::InvalidMessage);
        }
        self.connection
            .execute(
                "UPDATE contact_invites SET state='revoked'
                 WHERE invite_id=?1 AND state='pending' AND expires_at_ms>?2",
                params![invite_id.as_bytes().as_slice(), now_ms as i64],
            )
            .map(|changed| changed == 1)
            .map_err(database_error)
    }

    pub fn cleanup_expired_contact_invites(&self, now_ms: u64) -> Result<usize, AslError> {
        if now_ms > i64::MAX as u64 {
            return Err(AslError::InvalidMessage);
        }
        self.connection
            .execute(
                "DELETE FROM contact_invites WHERE expires_at_ms<=?1",
                [now_ms as i64],
            )
            .map_err(database_error)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn upsert_contact_invite_prompt(
        &mut self,
        prompt_id: Id128,
        tag: &str,
        invite_id: Id128,
        remote_agent: AgentId,
        note: &str,
        expires_at_ms: u64,
        now_ms: u64,
    ) -> Result<(), AslError> {
        let tag = tag.trim();
        let note = note.trim();
        if prompt_id.0 == [0; 16]
            || tag.is_empty()
            || tag.chars().count() > MAX_PROMPT_TAG_CHARS
            || invite_id.0 == [0; 16]
            || remote_agent.0 == [0; 32]
            || note.is_empty()
            || note.chars().count() > MAX_CONTACT_INVITE_NOTE_CHARS
            || now_ms > i64::MAX as u64
            || expires_at_ms > i64::MAX as u64
            || expires_at_ms <= now_ms
        {
            return Err(AslError::InvalidMessage);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        transaction
            .execute(
                "UPDATE contact_invite_prompts SET state='expired',updated_at_ms=?1
                 WHERE state='pending' AND expires_at_ms<=?1",
                [now_ms as i64],
            )
            .map_err(database_error)?;
        let existing_invite: Option<String> = transaction
            .query_row(
                "SELECT state FROM contact_invite_prompts WHERE invite_id=?1",
                [invite_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(database_error)?;
        if existing_invite.is_none() {
            let pending: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM contact_invite_prompts WHERE state='pending'",
                    [],
                    |row| row.get(0),
                )
                .map_err(database_error)?;
            if pending >= MAX_PENDING_CONTACT_INVITE_PROMPTS {
                return Err(AslError::QuotaExceeded);
            }
            let conflict: bool = transaction
                .query_row(
                    "SELECT EXISTS(
                        SELECT 1 FROM contact_invite_prompts
                        WHERE prompt_id=?1 OR tag=?2
                     )",
                    params![prompt_id.as_bytes().as_slice(), tag],
                    |row| row.get(0),
                )
                .map_err(database_error)?;
            if conflict {
                return Err(AslError::InvalidMessage);
            }
            transaction
                .execute(
                    "INSERT INTO contact_invite_prompts(
                        prompt_id,tag,invite_id,remote_agent,note,expires_at_ms,state,updated_at_ms
                     ) VALUES (?1,?2,?3,?4,?5,?6,'pending',?7)",
                    params![
                        prompt_id.as_bytes().as_slice(),
                        tag,
                        invite_id.as_bytes().as_slice(),
                        remote_agent.as_bytes().as_slice(),
                        note,
                        expires_at_ms as i64,
                        now_ms as i64,
                    ],
                )
                .map_err(database_error)?;
        } else {
            transaction
                .execute(
                    "UPDATE contact_invite_prompts
                     SET remote_agent=?2,note=?3,expires_at_ms=?4,updated_at_ms=?5
                     WHERE invite_id=?1 AND state='pending'",
                    params![
                        invite_id.as_bytes().as_slice(),
                        remote_agent.as_bytes().as_slice(),
                        note,
                        expires_at_ms as i64,
                        now_ms as i64,
                    ],
                )
                .map_err(database_error)?;
        }
        transaction.commit().map_err(database_error)
    }

    pub fn list_contact_invite_prompts(
        &mut self,
        now_ms: u64,
    ) -> Result<Vec<ContactInvitePrompt>, AslError> {
        if now_ms > i64::MAX as u64 {
            return Err(AslError::InvalidMessage);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        transaction
            .execute(
                "UPDATE contact_invite_prompts SET state='expired',updated_at_ms=?1
                 WHERE state='pending' AND expires_at_ms<=?1",
                [now_ms as i64],
            )
            .map_err(database_error)?;
        let prompts = {
            let mut statement = transaction
                .prepare(
                    "SELECT prompt_id,tag,invite_id,remote_agent,note,expires_at_ms,state
                     FROM contact_invite_prompts
                     WHERE state='pending'
                     ORDER BY expires_at_ms,tag",
                )
                .map_err(database_error)?;
            let rows = statement
                .query_map([], decode_prompt)
                .map_err(database_error)?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(database_error)?
        };
        transaction.commit().map_err(database_error)?;
        Ok(prompts)
    }

    pub fn decide_contact_invite_prompt(
        &mut self,
        prompt_id: Id128,
        now_ms: u64,
        accepted: bool,
    ) -> Result<bool, AslError> {
        if prompt_id.0 == [0; 16] || now_ms > i64::MAX as u64 {
            return Err(AslError::InvalidMessage);
        }
        let state = if accepted { "approved" } else { "rejected" };
        self.connection
            .execute(
                "UPDATE contact_invite_prompts SET state=?2,updated_at_ms=?3
                 WHERE prompt_id=?1 AND state='pending' AND expires_at_ms>?3",
                params![prompt_id.as_bytes().as_slice(), state, now_ms as i64],
            )
            .map(|changed| changed == 1)
            .map_err(database_error)
    }

    pub fn contact_invite_prompt(
        &mut self,
        prompt_id: Id128,
        now_ms: u64,
    ) -> Result<Option<ContactInvitePrompt>, AslError> {
        if prompt_id.0 == [0; 16] || now_ms > i64::MAX as u64 {
            return Err(AslError::InvalidMessage);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        transaction
            .execute(
                "UPDATE contact_invite_prompts SET state='expired',updated_at_ms=?2
                 WHERE prompt_id=?1 AND state='pending' AND expires_at_ms<=?2",
                params![prompt_id.as_bytes().as_slice(), now_ms as i64],
            )
            .map_err(database_error)?;
        let prompt = transaction
            .query_row(
                "SELECT prompt_id,tag,invite_id,remote_agent,note,expires_at_ms,state
                 FROM contact_invite_prompts WHERE prompt_id=?1",
                [prompt_id.as_bytes().as_slice()],
                decode_prompt,
            )
            .optional()
            .map_err(database_error)?;
        transaction.commit().map_err(database_error)?;
        Ok(prompt)
    }

    pub fn enqueue_contact_invite_action(
        &mut self,
        kind: ContactInviteActionKind,
        payload: ContactInviteActionPayload,
        now_ms: u64,
    ) -> Result<i64, AslError> {
        if now_ms > i64::MAX as u64 {
            return Err(AslError::InvalidMessage);
        }
        let (envelope, prompt_id) = match (kind, payload) {
            (
                ContactInviteActionKind::Add | ContactInviteActionKind::Import,
                ContactInviteActionPayload::Envelope(envelope),
            ) => {
                if envelope.is_empty() || envelope.len() > 65_536 {
                    return Err(AslError::InvalidMessage);
                }
                (Some(envelope), None)
            }
            (ContactInviteActionKind::Decide, ContactInviteActionPayload::Prompt(prompt_id)) => {
                if prompt_id.0 == [0; 16] {
                    return Err(AslError::InvalidMessage);
                }
                (None, Some(prompt_id))
            }
            _ => return Err(AslError::InvalidMessage),
        };
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        if let Some(prompt_id) = prompt_id {
            let exists: bool = transaction
                .query_row(
                    "SELECT EXISTS(
                        SELECT 1 FROM contact_invite_prompts WHERE prompt_id=?1
                     )",
                    [prompt_id.as_bytes().as_slice()],
                    |row| row.get(0),
                )
                .map_err(database_error)?;
            if !exists {
                return Err(AslError::NotFound);
            }
        }
        let pending: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM contact_invite_actions
                 WHERE state IN ('queued','working')",
                [],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if pending >= MAX_PENDING_ACTIONS {
            return Err(AslError::QuotaExceeded);
        }
        transaction
            .execute(
                "INSERT INTO contact_invite_actions(
                    kind,envelope,prompt_id,requested_at_ms,state
                 ) VALUES (?1,?2,?3,?4,'queued')",
                params![
                    kind.as_str(),
                    envelope.as_deref(),
                    prompt_id.map(|prompt_id| prompt_id.0.to_vec()),
                    now_ms as i64,
                ],
            )
            .map_err(database_error)?;
        let action_id = transaction.last_insert_rowid();
        transaction.commit().map_err(database_error)?;
        Ok(action_id)
    }

    pub fn claim_contact_invite_actions(&mut self) -> Result<Vec<ContactInviteAction>, AslError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let actions = {
            let mut statement = transaction
                .prepare(
                    "SELECT action_id,kind,envelope,prompt_id
                     FROM contact_invite_actions
                     WHERE state='queued'
                     ORDER BY action_id
                     LIMIT ?1",
                )
                .map_err(database_error)?;
            let rows = statement
                .query_map([MAX_ACTION_BATCH], |row| {
                    let action_id: i64 = row.get(0)?;
                    let kind: String = row.get(1)?;
                    let envelope: Option<Vec<u8>> = row.get(2)?;
                    let prompt_id: Option<Vec<u8>> = row.get(3)?;
                    let kind = ContactInviteActionKind::parse(&kind)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?;
                    let payload = match (kind, envelope, prompt_id) {
                        (
                            ContactInviteActionKind::Add | ContactInviteActionKind::Import,
                            Some(envelope),
                            None,
                        ) => ContactInviteActionPayload::Envelope(envelope),
                        (ContactInviteActionKind::Decide, None, Some(prompt_id)) => {
                            ContactInviteActionPayload::Prompt(Id128(
                                prompt_id
                                    .try_into()
                                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
                            ))
                        }
                        _ => return Err(rusqlite::Error::InvalidQuery),
                    };
                    Ok(ContactInviteAction {
                        action_id,
                        kind,
                        payload,
                    })
                })
                .map_err(database_error)?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(database_error)?
        };
        for action in &actions {
            transaction
                .execute(
                    "UPDATE contact_invite_actions SET state='working'
                     WHERE action_id=?1 AND state='queued'",
                    [action.action_id],
                )
                .map_err(database_error)?;
        }
        transaction.commit().map_err(database_error)?;
        Ok(actions)
    }

    pub fn finish_contact_invite_action(
        &self,
        action_id: i64,
        result: Result<&str, &str>,
    ) -> Result<(), AslError> {
        let (state, message) = match result {
            Ok(message) => ("complete", message),
            Err(message) => ("failed", message),
        };
        let message = message.trim();
        if action_id <= 0 || message.chars().count() > MAX_ACTION_RESULT_CHARS || message.is_empty()
        {
            return Err(AslError::InvalidMessage);
        }
        self.connection
            .execute(
                "UPDATE contact_invite_actions SET state=?2,result=?3
                 WHERE action_id=?1 AND state='working'",
                params![action_id, state, message],
            )
            .map_err(database_error)?;
        self.connection
            .execute(
                "DELETE FROM contact_invite_actions
                 WHERE action_id IN (
                    SELECT action_id FROM contact_invite_actions
                    WHERE state IN ('complete','failed')
                    ORDER BY action_id DESC LIMIT -1 OFFSET ?1
                 )",
                [MAX_ACTION_HISTORY],
            )
            .map_err(database_error)?;
        Ok(())
    }

    pub fn resume_contact_invite_actions(&self) -> Result<(), AslError> {
        self.connection
            .execute(
                "UPDATE contact_invite_actions SET state='queued'
                 WHERE state='working'",
                [],
            )
            .map_err(database_error)?;
        Ok(())
    }
}

fn normalize_note(note: &str) -> Result<Option<&str>, AslError> {
    let note = note.trim();
    if note.is_empty() {
        return Ok(None);
    }
    if note.chars().count() > MAX_CONTACT_INVITE_NOTE_CHARS {
        return Err(AslError::InvalidMessage);
    }
    Ok(Some(note))
}

pub(crate) fn active_invites_for_dashboard(
    db: &rusqlite::Connection,
    now_ms: i64,
) -> Result<Vec<ContactInvite>, AslError> {
    let mut statement = db
        .prepare(
            "SELECT invite_id,token,agent_id,created_at_ms,expires_at_ms,note,signature
             FROM contact_invites
             WHERE state='pending' AND expires_at_ms>?1
             ORDER BY expires_at_ms,invite_id",
        )
        .map_err(database_error)?;
    let rows = statement
        .query_map([now_ms], decode_invite)
        .map_err(database_error)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(database_error)
}

pub(crate) fn prompts_for_dashboard(
    db: &rusqlite::Connection,
    _now_ms: i64,
) -> Result<Vec<ContactInvitePrompt>, AslError> {
    let mut statement = db
        .prepare(
            "SELECT prompt_id,tag,invite_id,remote_agent,note,expires_at_ms,state
             FROM contact_invite_prompts
             WHERE state='pending'
             ORDER BY expires_at_ms,tag",
        )
        .map_err(database_error)?;
    let rows = statement
        .query_map([], decode_prompt)
        .map_err(database_error)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(database_error)
}

fn invite_token_hash(token: Id128) -> [u8; 32] {
    *blake3::hash(token.as_bytes()).as_bytes()
}

fn decode_invite(row: &Row<'_>) -> rusqlite::Result<ContactInvite> {
    let invite_id: Vec<u8> = row.get(0)?;
    let token: Vec<u8> = row.get(1)?;
    let agent_id: Vec<u8> = row.get(2)?;
    let created_at_ms: i64 = row.get(3)?;
    let expires_at_ms: i64 = row.get(4)?;
    let signature: Vec<u8> = row.get(6)?;
    Ok(ContactInvite {
        invite_id: Id128(
            invite_id
                .try_into()
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
        ),
        token: Id128(
            token
                .try_into()
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
        ),
        agent_id: AgentId(
            agent_id
                .try_into()
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
        ),
        created_at_ms: u64::try_from(created_at_ms).map_err(|_| rusqlite::Error::InvalidQuery)?,
        expires_at_ms: u64::try_from(expires_at_ms).map_err(|_| rusqlite::Error::InvalidQuery)?,
        note: row.get(5)?,
        signature: signature
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
    })
}

fn decode_prompt(row: &Row<'_>) -> rusqlite::Result<ContactInvitePrompt> {
    let prompt_id: Vec<u8> = row.get(0)?;
    let note: String = row.get(4)?;
    let expires_at_ms: i64 = row.get(5)?;
    let state: String = row.get(6)?;
    let invite_id: Vec<u8> = row.get(2)?;
    let remote_agent: Vec<u8> = row.get(3)?;
    Ok(ContactInvitePrompt {
        prompt_id: Id128(
            prompt_id
                .try_into()
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
        ),
        tag: row.get(1)?,
        invite_id: Id128(
            invite_id
                .try_into()
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
        ),
        remote_agent: AgentId(
            remote_agent
                .try_into()
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
        ),
        note,
        expires_at_ms: u64::try_from(expires_at_ms).map_err(|_| rusqlite::Error::InvalidQuery)?,
        state: ContactInvitePromptState::parse(&state)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
    })
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, sync::Barrier, thread};

    use super::*;
    use crate::open_store;
    use tempfile::TempDir;

    struct TestDatabase {
        _directory: TempDir,
        path: PathBuf,
    }

    impl TestDatabase {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("store.sqlite3");
            Self {
                _directory: directory,
                path,
            }
        }
    }

    fn create_invite(
        store: &mut Store,
        invite: u8,
        token: u8,
        agent: u8,
        created_at_ms: u64,
        expires_at_ms: u64,
        note: &str,
    ) -> Id128 {
        let invite_id = Id128([invite; 16]);
        store
            .create_contact_invite(
                invite_id,
                Id128([token; 16]),
                AgentId([agent; 32]),
                created_at_ms,
                expires_at_ms,
                note,
                [invite; 65],
            )
            .unwrap();
        invite_id
    }

    #[test]
    fn contact_invites_create_list_and_find_active_rows_without_contact_access() {
        let database = TestDatabase::new();
        let mut store = open_store(&database.path).unwrap();
        let first = create_invite(&mut store, 1, 101, 7, 1_000, 301_000, "reply to question");
        create_invite(&mut store, 2, 102, 7, 2_000, 902_000, "");

        let active = store.active_contact_invites(2_001).unwrap();
        assert_eq!(active.len(), 2);
        assert_eq!(active[0].invite_id, first);
        assert_eq!(active[0].note.as_deref(), Some("reply to question"));
        assert_eq!(active[0].signature, [1; 65]);
        assert_eq!(active[1].note, None);
        assert_eq!(
            store
                .find_active_contact_invite_by_token(Id128([101; 16]), 2_001)
                .unwrap(),
            Some(active[0].clone())
        );
        assert!(store.paired_contacts().unwrap().is_empty());
    }

    #[test]
    fn contact_invites_expire_and_cleanup_removes_expired_rows() {
        let database = TestDatabase::new();
        let mut store = open_store(&database.path).unwrap();
        let invite_id = create_invite(&mut store, 3, 103, 8, 10_000, 310_000, "");

        assert_eq!(store.active_contact_invites(309_999).unwrap().len(), 1);
        assert!(store.active_contact_invites(310_000).unwrap().is_empty());
        assert!(
            store
                .find_active_contact_invite_by_token(Id128([103; 16]), 310_000)
                .unwrap()
                .is_none()
        );
        assert_eq!(store.cleanup_expired_contact_invites(310_000).unwrap(), 1);
        assert!(
            store
                .consume_contact_invite(invite_id, 310_000, true)
                .unwrap()
                .eq(&false)
        );
    }

    #[test]
    fn contact_invites_consume_once_and_persist_acceptance_without_pairing() {
        let database = TestDatabase::new();
        let mut store = open_store(&database.path).unwrap();
        let invite_id = create_invite(&mut store, 4, 104, 9, 20_000, 3_620_000, "one sentence");

        assert!(
            store
                .consume_contact_invite(invite_id, 21_000, true)
                .unwrap()
        );
        assert!(store.paired_contacts().unwrap().is_empty());
        drop(store);

        let mut reopened = open_store(&database.path).unwrap();
        assert!(
            !reopened
                .consume_contact_invite(invite_id, 22_000, true)
                .unwrap()
        );
        let accepted: i64 = reopened
            .connection
            .query_row(
                "SELECT accepted FROM contact_invite_receipts WHERE invite_id=?1",
                [invite_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(accepted, 1);
        assert!(reopened.paired_contacts().unwrap().is_empty());
    }

    #[test]
    fn contact_invites_revoke_prevents_consumption() {
        let database = TestDatabase::new();
        let mut store = open_store(&database.path).unwrap();
        let invite_id = create_invite(&mut store, 5, 105, 10, 30_000, 3_630_000, "");

        assert!(store.revoke_contact_invite(invite_id, 31_000).unwrap());
        assert!(!store.revoke_contact_invite(invite_id, 32_000).unwrap());
        assert!(
            !store
                .consume_contact_invite(invite_id, 32_000, false)
                .unwrap()
        );
    }

    #[test]
    fn contact_invites_enforce_per_agent_quota() {
        let database = TestDatabase::new();
        let mut store = open_store(&database.path).unwrap();
        let now_ms = 40_000;
        for value in 1..=MAX_PENDING_CONTACT_INVITES_PER_AGENT {
            create_invite(
                &mut store,
                value as u8,
                110 + value as u8,
                11,
                now_ms,
                now_ms + 300_000,
                "",
            );
        }

        assert!(matches!(
            store.create_contact_invite(
                Id128([20; 16]),
                Id128([120; 16]),
                AgentId([11; 32]),
                now_ms,
                now_ms + 300_000,
                "",
                [20; 65],
            ),
            Err(AslError::QuotaExceeded)
        ));
        assert_eq!(
            store
                .cleanup_expired_contact_invites(now_ms + 300_000)
                .unwrap(),
            MAX_PENDING_CONTACT_INVITES_PER_AGENT as usize
        );
        create_invite(
            &mut store,
            21,
            121,
            11,
            now_ms,
            now_ms + MAX_CONTACT_INVITE_LIFETIME_MS,
            "",
        );
    }

    #[test]
    fn contact_invites_concurrent_consumption_has_one_winner() {
        let database = TestDatabase::new();
        let mut store = open_store(&database.path).unwrap();
        let invite_id = create_invite(&mut store, 6, 106, 12, 50_000, 3_650_000, "");
        drop(store);

        let barrier = Barrier::new(3);
        let (left, right) = thread::scope(|scope| {
            let left = scope.spawn(|| {
                let mut store = open_store(&database.path).unwrap();
                barrier.wait();
                store.consume_contact_invite(invite_id, 51_000, true)
            });
            let right = scope.spawn(|| {
                let mut store = open_store(&database.path).unwrap();
                barrier.wait();
                store.consume_contact_invite(invite_id, 51_000, false)
            });
            barrier.wait();
            (left.join().unwrap(), right.join().unwrap())
        });

        assert_eq!(
            [left.unwrap(), right.unwrap()]
                .into_iter()
                .filter(|consumed| *consumed)
                .count(),
            1
        );
        let store = open_store(&database.path).unwrap();
        let receipts: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM contact_invite_receipts", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(receipts, 1);
    }

    #[test]
    fn contact_invite_prompts_upsert_list_and_expire() {
        let database = TestDatabase::new();
        let mut store = open_store(&database.path).unwrap();
        let prompt_id = Id128([31; 16]);
        store
            .upsert_contact_invite_prompt(
                prompt_id,
                "pair-31",
                Id128([41; 16]),
                AgentId([51; 32]),
                "Can we compare notes?",
                120_000,
                100_000,
            )
            .unwrap();
        store
            .upsert_contact_invite_prompt(
                Id128([32; 16]),
                "ignored-replacement-tag",
                Id128([41; 16]),
                AgentId([51; 32]),
                "Updated sentence.",
                130_000,
                101_000,
            )
            .unwrap();

        let prompts = store.list_contact_invite_prompts(102_000).unwrap();
        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0].prompt_id, prompt_id);
        assert_eq!(prompts[0].tag, "pair-31");
        assert_eq!(prompts[0].note, "Updated sentence.");
        assert_eq!(prompts[0].state, ContactInvitePromptState::Pending);
        assert!(
            store
                .list_contact_invite_prompts(130_000)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store
                .contact_invite_prompt(prompt_id, 130_000)
                .unwrap()
                .unwrap()
                .state,
            ContactInvitePromptState::Expired
        );
    }

    #[test]
    fn contact_invite_prompts_decide_once() {
        let database = TestDatabase::new();
        let mut store = open_store(&database.path).unwrap();
        let prompt_id = Id128([33; 16]);
        store
            .upsert_contact_invite_prompt(
                prompt_id,
                "pair-33",
                Id128([43; 16]),
                AgentId([53; 32]),
                "May I add you?",
                200_000,
                100_000,
            )
            .unwrap();

        assert!(
            store
                .decide_contact_invite_prompt(prompt_id, 101_000, true)
                .unwrap()
        );
        assert!(
            !store
                .decide_contact_invite_prompt(prompt_id, 102_000, false)
                .unwrap()
        );
        assert!(
            store
                .list_contact_invite_prompts(102_000)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store
                .contact_invite_prompt(prompt_id, 102_000)
                .unwrap()
                .unwrap()
                .state,
            ContactInvitePromptState::Approved
        );
        assert!(store.paired_contacts().unwrap().is_empty());
    }

    #[test]
    fn contact_invite_actions_queue_claim_resume_and_finish() {
        let database = TestDatabase::new();
        let mut store = open_store(&database.path).unwrap();
        let prompt_id = Id128([61; 16]);
        store
            .upsert_contact_invite_prompt(
                prompt_id,
                "pair-61",
                Id128([62; 16]),
                AgentId([63; 32]),
                "Please decide.",
                300_000,
                200_000,
            )
            .unwrap();
        let import_id = store
            .enqueue_contact_invite_action(
                ContactInviteActionKind::Import,
                ContactInviteActionPayload::Envelope(vec![1, 2, 3, 4]),
                201_000,
            )
            .unwrap();
        let decide_id = store
            .enqueue_contact_invite_action(
                ContactInviteActionKind::Decide,
                ContactInviteActionPayload::Prompt(prompt_id),
                202_000,
            )
            .unwrap();

        let claimed = store.claim_contact_invite_actions().unwrap();
        assert_eq!(claimed.len(), 2);
        assert_eq!(claimed[0].action_id, import_id);
        assert_eq!(
            claimed[0].payload,
            ContactInviteActionPayload::Envelope(vec![1, 2, 3, 4])
        );
        assert_eq!(claimed[1].action_id, decide_id);
        assert_eq!(
            claimed[1].payload,
            ContactInviteActionPayload::Prompt(prompt_id)
        );
        assert!(store.claim_contact_invite_actions().unwrap().is_empty());

        store.resume_contact_invite_actions().unwrap();
        assert_eq!(store.claim_contact_invite_actions().unwrap().len(), 2);
        store
            .finish_contact_invite_action(import_id, Ok("imported"))
            .unwrap();
        store
            .finish_contact_invite_action(decide_id, Err("expired"))
            .unwrap();
        let states: Vec<String> = store
            .connection
            .prepare(
                "SELECT state FROM contact_invite_actions
                 ORDER BY action_id",
            )
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(states, ["complete", "failed"]);
    }
}
