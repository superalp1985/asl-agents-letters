//! Local operator decisions. A queued decision names the exact invitation shown.
use asl_types::{
    error::AslError,
    ids::{AgentId, Id128, PeerId},
};
use rusqlite::{Connection, TransactionBehavior};
use serde::{Deserialize, Serialize};

use super::{MlsIncomingInvite, invite::list_invites, sql_number};
use crate::{Store, database_error, read_setting, write_setting};

const KEY: &str = "mls.operator_review.v1";
const DECISION_WINDOW_MS: u64 = 30_000;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Choice {
    Approve,
    Reject,
    Retry,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Queued,
    Applying,
    Declined,
    JoinQueued,
    ApprovedNotSent,
    Failed,
    Unconfirmed,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReviewedInvite {
    pub id: Id128,
    pub room: String,
    pub inviter: String,
    pub device: String,
    pub epoch: u64,
    pub expires_ms: u64,
    pub approved: bool,
    pub tag: String,
}

fn review(i: MlsIncomingInvite, approved: bool) -> ReviewedInvite {
    // Length-prefix each endpoint; the token is a comparison key, not an authorization secret.
    let mut digest = blake3::Hasher::new_derive_key("ASL local MLS invitation review v1");
    for field in [
        i.id.as_bytes().as_slice(),
        i.wire_id.as_bytes(),
        &i.base_epoch.to_be_bytes(),
        i.inviter.as_bytes(),
        i.inviter_device.as_bytes(),
        i.recipient.as_bytes(),
        i.recipient_device.as_bytes(),
        &i.expires_at_ms.to_be_bytes(),
        &[u8::from(approved)],
    ] {
        digest.update(&(field.len() as u32).to_be_bytes());
        digest.update(field);
    }
    ReviewedInvite {
        id: i.id,
        room: hex::encode(i.wire_id.as_bytes()),
        inviter: crate::chain::agent_text(i.inviter),
        device: bs58::encode(i.inviter_device.as_bytes()).into_string(),
        epoch: i.base_epoch,
        expires_ms: i.expires_at_ms,
        approved,
        tag: digest.finalize().to_hex().to_string(),
    }
}

pub(crate) fn list(
    db: &Connection,
    agent: AgentId,
    device: &PeerId,
    now: u64,
) -> Result<Vec<ReviewedInvite>, AslError> {
    let mut rows = Vec::new();
    for (state, approved) in [("pending", false), ("approved", true)] {
        rows.extend(
            list_invites(db, agent, device, sql_number(now)?, state)?
                .into_iter()
                .map(|i| review(i, approved)),
        );
    }
    Ok(rows)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Decision {
    pub invite: Id128,
    pub tag: String,
    pub choice: Choice,
    pub outcome: Outcome,
    pub expires_ms: u64,
}

pub(crate) fn status(db: &Connection, now: u64) -> Result<Option<Decision>, AslError> {
    let Some(value) = read_setting(db, KEY)? else {
        return Ok(None);
    };
    let mut decision: Decision =
        serde_json::from_str(&value).map_err(|_| AslError::InvalidDatabase)?;
    if now >= decision.expires_ms && matches!(decision.outcome, Outcome::Queued | Outcome::Applying)
    {
        decision.outcome = Outcome::Unconfirmed;
    }
    Ok(Some(decision))
}
fn save(db: &Connection, d: &Decision, now: u64) -> Result<(), AslError> {
    write_setting(
        db,
        KEY,
        &serde_json::to_string(d).map_err(|_| AslError::InvalidDatabase)?,
        sql_number(now)?,
    )
}

impl Store {
    pub fn local_group_invitations(
        &self,
        agent: AgentId,
        device: &PeerId,
        now: u64,
    ) -> Result<Vec<ReviewedInvite>, AslError> {
        list(&self.connection, agent, device, now)
    }
    pub fn queue_group_decision(
        &mut self,
        agent: AgentId,
        device: &PeerId,
        tag: &str,
        choice: Choice,
        now: u64,
    ) -> Result<(), AslError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let row = list(&tx, agent, device, now)?
            .into_iter()
            .find(|r| r.tag == tag && r.approved == (choice == Choice::Retry))
            .ok_or(AslError::NotFound)?;
        if let Some(old) =
            status(&tx, now)?.filter(|d| matches!(d.outcome, Outcome::Queued | Outcome::Applying))
        {
            return if old.tag == tag && old.choice == choice {
                Ok(())
            } else {
                Err(AslError::QuotaExceeded)
            };
        }
        save(
            &tx,
            &Decision {
                invite: row.id,
                tag: row.tag,
                choice,
                outcome: Outcome::Queued,
                expires_ms: row.expires_ms.min(now.saturating_add(DECISION_WINDOW_MS)),
            },
            now,
        )?;
        tx.commit().map_err(database_error)
    }
    pub fn claim_group_decision(
        &mut self,
        agent: AgentId,
        device: &PeerId,
        now: u64,
    ) -> Result<Option<Decision>, AslError> {
        if !status(&self.connection, now)?.is_some_and(|d| d.outcome == Outcome::Queued) {
            return Ok(None);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let Some(mut d) = status(&tx, now)?.filter(|d| d.outcome == Outcome::Queued) else {
            return Ok(None);
        };
        let valid = list(&tx, agent, device, now)?.iter().any(|r| {
            r.id == d.invite && r.tag == d.tag && r.approved == (d.choice == Choice::Retry)
        });
        d.outcome = if valid {
            Outcome::Applying
        } else {
            Outcome::Failed
        };
        save(&tx, &d, now)?;
        tx.commit().map_err(database_error)?;
        Ok(valid.then_some(d))
    }
    pub fn finish_group_decision(
        &mut self,
        d: &Decision,
        outcome: Outcome,
        now: u64,
    ) -> Result<(), AslError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let Some(mut current) = status(&tx, now)?.filter(|r| {
            r.tag == d.tag
                && r.choice == d.choice
                && r.expires_ms == d.expires_ms
                && r.outcome == Outcome::Applying
        }) else {
            return Ok(());
        };
        current.outcome = outcome;
        save(&tx, &current, now)?;
        tx.commit().map_err(database_error)
    }
}
