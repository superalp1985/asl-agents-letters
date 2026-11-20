use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, PeerId},
    task::TaskId,
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use crate::{Store, chain::agent_text, database_error};

const CONTRIBUTION_WINDOW_MS: i64 = 24 * 60 * 60 * 1_000;
const MAX_CONTRIBUTIONS_PER_WINDOW: i64 = 100;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustDimension {
    Integrity,
    Availability,
    Evidence,
    Promise,
}

impl TrustDimension {
    fn as_str(self) -> &'static str {
        match self {
            Self::Integrity => "integrity",
            Self::Availability => "availability",
            Self::Evidence => "evidence",
            Self::Promise => "promise",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustOutcome {
    Positive,
    Negative,
    Neutral,
}

impl TrustOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Positive => "positive",
            Self::Negative => "negative",
            Self::Neutral => "neutral",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContributionKind {
    UsedFile,
    UsedAnswer,
}

impl ContributionKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::UsedFile => "used_file",
            Self::UsedAnswer => "used_answer",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TrustCounts {
    pub positive: u32,
    pub negative: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContactEvidence {
    pub agent_id: AgentId,
    pub integrity: TrustCounts,
    pub availability: TrustCounts,
    pub evidence: TrustCounts,
    pub promise: TrustCounts,
    pub contributions: u32,
}

impl Store {
    /// Persists a local observation. The evidence hash is a local reference,
    /// not a peer-supplied score or free-form explanation.
    pub fn record_trust_observation(
        &mut self,
        agent_id: AgentId,
        task_id: Option<&TaskId>,
        dimension: TrustDimension,
        outcome: TrustOutcome,
        evidence_id: Hash32,
        now_ms: u64,
    ) -> Result<bool, AslError> {
        if agent_id.0 == [0; 32] || evidence_id.0 == [0; 32] || now_ms > i64::MAX as u64 {
            return Err(AslError::InvalidMessage);
        }
        let agent = agent_text(agent_id);
        let task = task_id.map(|value| hex::encode(value.0.0));
        if task_id.is_some_and(|value| value.0.0 == [0; 16]) {
            return Err(AslError::InvalidMessage);
        }

        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let known_agent: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM agents WHERE agent_id=?1)",
                [&agent],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if !known_agent {
            return Err(AslError::NotFound);
        }
        if let Some(task) = &task {
            let matches_agent: bool = tx
                .query_row(
                    "SELECT EXISTS(
                        SELECT 1 FROM tasks WHERE task_id=?1 AND agent_id=?2
                     )",
                    params![task, agent],
                    |row| row.get(0),
                )
                .map_err(database_error)?;
            if !matches_agent {
                return Err(AslError::PolicyDenied);
            }
        }

        let mut dedupe = Vec::with_capacity(128);
        dedupe.extend_from_slice(b"ASL-TRUST-EVENT-v1\0");
        dedupe.extend_from_slice(agent_id.as_bytes());
        dedupe.extend_from_slice(task_id.map_or(&[0; 16], |value| value.0.as_bytes()));
        dedupe.push(trust_dimension_tag(dimension));
        dedupe.push(trust_outcome_tag(outcome));
        dedupe.extend_from_slice(evidence_id.as_bytes());
        let dedupe_key = hex::encode(blake3::hash(&dedupe).as_bytes());
        let event_id = hex::encode(rand::random::<[u8; 16]>());
        let proof_json = format!(
            "{{\"kind\":\"local_observation\",\"evidence_id\":\"{}\"}}",
            hex::encode(evidence_id.0)
        );
        let inserted = tx
            .execute(
                "INSERT INTO trust_events(
                    event_id,agent_id,task_id,dimension,outcome,proof_json,dedupe_key,created_at_ms
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
                 ON CONFLICT(dedupe_key) DO NOTHING",
                params![
                    event_id,
                    agent,
                    task,
                    dimension.as_str(),
                    outcome.as_str(),
                    proof_json,
                    dedupe_key,
                    now_ms as i64
                ],
            )
            .map_err(database_error)?;
        tx.commit().map_err(database_error)?;
        Ok(inserted == 1)
    }

    pub fn record_peer_trust_observation(
        &mut self,
        peer_id: &PeerId,
        dimension: TrustDimension,
        outcome: TrustOutcome,
        evidence_id: Hash32,
        now_ms: u64,
    ) -> Result<bool, AslError> {
        let peer = bs58::encode(peer_id.as_bytes()).into_string();
        let agent = self
            .connection
            .query_row(
                "SELECT agent_id FROM peers WHERE peer_id=?1",
                [&peer],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(database_error)?
            .ok_or(AslError::NotFound)?;
        self.record_trust_observation(
            decode_agent(&agent)?,
            None,
            dimension,
            outcome,
            evidence_id,
            now_ms,
        )
    }

    /// Credits a completed task only when its remote content has an active,
    /// locally verified resource record. Transport completion alone is not
    /// useful-work evidence.
    pub fn record_contribution(
        &mut self,
        agent_id: AgentId,
        task_id: &TaskId,
        content_id: Hash32,
        kind: ContributionKind,
        now_ms: u64,
    ) -> Result<bool, AslError> {
        if agent_id.0 == [0; 32]
            || task_id.0.0 == [0; 16]
            || content_id.0 == [0; 32]
            || now_ms > i64::MAX as u64
        {
            return Err(AslError::InvalidMessage);
        }
        let agent = agent_text(agent_id);
        let task = hex::encode(task_id.0.0);
        let content = hex::encode(content_id.0);
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;

        let valid_task: bool = tx
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM tasks
                    WHERE task_id=?1 AND direction='outgoing' AND agent_id=?2 AND state='done'
                 )",
                params![task, agent],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        let valid_resource: bool = tx
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM resources
                    WHERE content_id=?1 AND source_agent_id=?2
                      AND origin='remote' AND active=1 AND evidence_status='verified'
                 )",
                params![content, agent],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if !valid_task || !valid_resource {
            return Err(AslError::PolicyDenied);
        }

        let duplicate: bool = tx
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM contribution_events
                    WHERE task_id=?1 AND content_id=?2 AND help_kind=?3
                 )",
                params![task, content, kind.as_str()],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if duplicate {
            tx.commit().map_err(database_error)?;
            return Ok(false);
        }
        let window_start = (now_ms as i64).saturating_sub(CONTRIBUTION_WINDOW_MS);
        let count: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM contribution_events WHERE created_at_ms>?1",
                [window_start],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if count >= MAX_CONTRIBUTIONS_PER_WINDOW {
            return Err(AslError::QuotaExceeded);
        }

        let event_id = hex::encode(rand::random::<[u8; 16]>());
        let proof_json =
            format!("{{\"kind\":\"verified_local_resource\",\"content_id\":\"{content}\"}}");
        let inserted = tx
            .execute(
                "INSERT INTO contribution_events(
                    event_id,agent_id,task_id,content_id,help_kind,proof_json,created_at_ms
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7)
                 ON CONFLICT(task_id,content_id,help_kind) DO NOTHING",
                params![
                    event_id,
                    agent,
                    task,
                    content,
                    kind.as_str(),
                    proof_json,
                    now_ms as i64
                ],
            )
            .map_err(database_error)?;
        tx.commit().map_err(database_error)?;
        Ok(inserted == 1)
    }

    /// Preferences remain independent of the authorization table.
    pub fn set_preferred_peer(&self, agent_id: AgentId, now_ms: u64) -> Result<(), AslError> {
        if agent_id.0 == [0; 32] || now_ms > i64::MAX as u64 {
            return Err(AslError::InvalidMessage);
        }
        self.connection
            .execute(
                "INSERT INTO preferred_peers(agent_id,reason,last_used_ms)
                 VALUES (?1,'manual',?2)
                 ON CONFLICT(agent_id) DO UPDATE SET reason='manual',last_used_ms=excluded.last_used_ms",
                params![agent_text(agent_id), now_ms as i64],
            )
            .map_err(database_error)?;
        Ok(())
    }

    pub fn remove_preferred_peer(&self, agent_id: AgentId) -> Result<bool, AslError> {
        self.connection
            .execute(
                "DELETE FROM preferred_peers WHERE agent_id=?1",
                [agent_text(agent_id)],
            )
            .map(|changed| changed == 1)
            .map_err(database_error)
    }

    pub fn preferred_agents(&self) -> Result<Vec<AgentId>, AslError> {
        let mut statement = self
            .connection
            .prepare("SELECT agent_id FROM preferred_peers ORDER BY last_used_ms DESC,agent_id")
            .map_err(database_error)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(database_error)?;
        rows.map(|row| decode_agent(&row.map_err(database_error)?))
            .collect()
    }

    /// Returns scores only for already-authorized contacts, preserving their
    /// authorization order for deterministic ties.
    pub fn authorized_contact_evidence(&self) -> Result<Vec<ContactEvidence>, AslError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT c.agent_id,
                    (SELECT COUNT(*) FROM trust_events t WHERE t.agent_id=c.agent_id
                     AND t.dimension='integrity' AND t.outcome='positive'),
                    (SELECT COUNT(*) FROM trust_events t WHERE t.agent_id=c.agent_id
                     AND t.dimension='integrity' AND t.outcome='negative'),
                    (SELECT COUNT(*) FROM trust_events t WHERE t.agent_id=c.agent_id
                     AND t.dimension='availability' AND t.outcome='positive'),
                    (SELECT COUNT(*) FROM trust_events t WHERE t.agent_id=c.agent_id
                     AND t.dimension='availability' AND t.outcome='negative'),
                    (SELECT COUNT(*) FROM trust_events t WHERE t.agent_id=c.agent_id
                     AND t.dimension='evidence' AND t.outcome='positive'),
                    (SELECT COUNT(*) FROM trust_events t WHERE t.agent_id=c.agent_id
                     AND t.dimension='evidence' AND t.outcome='negative'),
                    (SELECT COUNT(*) FROM trust_events t WHERE t.agent_id=c.agent_id
                     AND t.dimension='promise' AND t.outcome='positive'),
                    (SELECT COUNT(*) FROM trust_events t WHERE t.agent_id=c.agent_id
                     AND t.dimension='promise' AND t.outcome='negative'),
                    (SELECT COUNT(*) FROM contribution_events e WHERE e.agent_id=c.agent_id)
                 FROM authorized_contacts c
                 ORDER BY c.authorized_at_ms,c.agent_id",
            )
            .map_err(database_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                ))
            })
            .map_err(database_error)?;
        rows.map(|row| {
            let (
                agent,
                integrity_positive,
                integrity_negative,
                availability_positive,
                availability_negative,
                evidence_positive,
                evidence_negative,
                promise_positive,
                promise_negative,
                contributions,
            ) = row.map_err(database_error)?;
            Ok(ContactEvidence {
                agent_id: decode_agent(&agent)?,
                integrity: counts(integrity_positive, integrity_negative),
                availability: counts(availability_positive, availability_negative),
                evidence: counts(evidence_positive, evidence_negative),
                promise: counts(promise_positive, promise_negative),
                contributions: bounded_count(contributions),
            })
        })
        .collect()
    }
}

fn decode_agent(text: &str) -> Result<AgentId, AslError> {
    let mut bytes = [0; 32];
    let length = bs58::decode(text)
        .onto(&mut bytes)
        .map_err(|_| AslError::InvalidDatabase)?;
    let agent = AgentId(bytes);
    if length != bytes.len() || agent_text(agent) != text {
        return Err(AslError::InvalidDatabase);
    }
    Ok(agent)
}

fn counts(positive: i64, negative: i64) -> TrustCounts {
    TrustCounts {
        positive: bounded_count(positive),
        negative: bounded_count(negative),
    }
}

fn bounded_count(value: i64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn trust_dimension_tag(value: TrustDimension) -> u8 {
    match value {
        TrustDimension::Integrity => 1,
        TrustDimension::Availability => 2,
        TrustDimension::Evidence => 3,
        TrustDimension::Promise => 4,
    }
}

fn trust_outcome_tag(value: TrustOutcome) -> u8 {
    match value {
        TrustOutcome::Positive => 1,
        TrustOutcome::Negative => 2,
        TrustOutcome::Neutral => 3,
    }
}
