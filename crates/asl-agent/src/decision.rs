//! Turns a bounded model response into local, typed advice. This module never sends peer frames.

mod prompt;
#[cfg(test)]
mod tests;

use asl_policy::{AccessOperation, Permit, PolicyService, Principal};
use asl_types::{
    error::ErrorCode,
    protocol::{Claim, ConceptRef, Query, TypedValue, WireFrame, encode_control},
    task::{ProviderId, ResourceKey, TaskId},
};
use serde::{Deserialize, Serialize};

use crate::gateway::{MAX_MODEL_TEXT_BYTES, ModelGateway, ModelGatewayError};

const MAX_CANDIDATES: usize = 4;
const MAX_SNIPPET_CHARS: usize = 1_200;
const MAX_CLAIMS: usize = 32;
const MAX_TERMS: usize = 5;
const MAX_FILE_BYTES: i64 = 64 * 1024 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Incoming,
    Outgoing,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DeclineReason {
    NoMatch,
    InsufficientEvidence,
    PolicyDenied,
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupportedClaim {
    claim: Claim,
    source: ResourceKey,
}

impl SupportedClaim {
    pub fn claim(&self) -> &Claim {
        &self.claim
    }

    pub fn source(&self) -> &ResourceKey {
        &self.source
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValidatedDecision {
    Answer(Vec<SupportedClaim>),
    Decline(DeclineReason),
    RequestMore(Vec<ConceptRef>),
}

pub struct CandidateEvidence {
    snippet: String,
    read: Permit,
    model: Permit,
}

impl CandidateEvidence {
    /// The trusted broker supplies this snippet from the snapshot bound to both permits.
    pub fn new(snippet: String, read: Permit, model: Permit) -> Result<Self, ErrorCode> {
        if snippet.len() > MAX_SNIPPET_CHARS * 4
            || snippet.chars().count() > MAX_SNIPPET_CHARS
            || snippet.trim().is_empty()
        {
            return Err(ErrorCode::ModelUnavailable);
        }
        if read.operation() != AccessOperation::ReadChunk
            || model.operation() != AccessOperation::ModelInput
            || read.resource_key() != model.resource_key()
            || read.grant_id() != model.grant_id()
            || read.grant_epoch() != model.grant_epoch()
            || read.content_id() != model.content_id()
        {
            return Err(ErrorCode::PolicyDenied);
        }
        Ok(Self {
            snippet,
            read,
            model,
        })
    }
}

pub struct DecisionContext {
    query: Query,
    direction: Direction,
    candidates: Vec<CandidateEvidence>,
}

impl DecisionContext {
    pub fn new(
        query: Query,
        direction: Direction,
        candidates: Vec<CandidateEvidence>,
    ) -> Result<Self, ErrorCode> {
        encode_control(&WireFrame::Query(query.clone())).map_err(|_| ErrorCode::InvalidMessage)?;
        if !(1..=MAX_CANDIDATES).contains(&candidates.len()) {
            return Err(ErrorCode::ModelUnavailable);
        }
        let task = Principal::LocalTask(TaskId(query.root_task_id));
        for (index, candidate) in candidates.iter().enumerate() {
            let valid_scope = match direction {
                Direction::Incoming => candidate.read.requester_agent_id().is_some(),
                Direction::Outgoing => candidate.read.principal() == &task,
            };
            if !valid_scope
                || candidates[..index]
                    .iter()
                    .any(|other| other.read.resource_key() == candidate.read.resource_key())
            {
                return Err(ErrorCode::PolicyDenied);
            }
        }
        Ok(Self {
            query,
            direction,
            candidates,
        })
    }

    fn revalidate(
        &self,
        provider: &ProviderId,
        read_policy: &(dyn PolicyService + Sync),
        model_policy: &(dyn PolicyService + Sync),
        now_ms: u64,
    ) -> Result<(), ErrorCode> {
        if now_ms < self.query.created_at_ms || now_ms >= self.query.expires_at_ms {
            return Err(ErrorCode::Timeout);
        }
        for candidate in &self.candidates {
            if !candidate
                .model
                .model_provider()
                .is_some_and(|(granted, _)| granted == provider)
                || read_policy.revalidate(&candidate.read, now_ms).is_err()
                || model_policy.revalidate(&candidate.model, now_ms).is_err()
            {
                return Err(ErrorCode::PolicyDenied);
            }
        }
        Ok(())
    }

    fn candidate(&self, reference: u8) -> Result<&CandidateEvidence, InvalidDecision> {
        reference
            .checked_sub(1)
            .and_then(|index| self.candidates.get(usize::from(index)))
            .ok_or(InvalidDecision::Reference)
    }
}

pub fn validate_decision(
    response: &str,
    context: &DecisionContext,
    provider: &ProviderId,
    read_policy: &(dyn PolicyService + Sync),
    model_policy: &(dyn PolicyService + Sync),
    now_ms: u64,
) -> Result<ValidatedDecision, ErrorCode> {
    context.revalidate(provider, read_policy, model_policy, now_ms)?;
    parse_decision(response, context).map_err(|_| ErrorCode::ModelInvalid)
}

/// A fresh clock reading is required after each model call. The caller still owns
/// cancellation, network routing, response IDs, and the final pre-send policy check.
pub async fn decide(
    gateway: &impl ModelGateway,
    context: &DecisionContext,
    provider: &ProviderId,
    read_policy: &(dyn PolicyService + Sync),
    model_policy: &(dyn PolicyService + Sync),
    now_ms: impl Fn() -> u64,
) -> Result<ValidatedDecision, ErrorCode> {
    let mut repair = None;
    for _ in 0..2 {
        let now = now_ms();
        context.revalidate(provider, read_policy, model_policy, now)?;
        let prompt = prompt::build(context, provider, repair)?;
        let response = gateway
            .complete(provider, prompt, model_policy, now)
            .await
            .map_err(|error| match error {
                ModelGatewayError::AuthorizationDenied => ErrorCode::PolicyDenied,
                ModelGatewayError::TimedOut => ErrorCode::Timeout,
                _ => ErrorCode::ModelUnavailable,
            })?;
        context.revalidate(provider, read_policy, model_policy, now_ms())?;
        match parse_decision(response.as_str(), context) {
            Ok(decision) => return Ok(decision),
            Err(error) => repair = Some(error),
        }
    }
    Err(ErrorCode::ModelInvalid)
}

#[derive(Clone, Copy)]
#[repr(u8)]
enum InvalidDecision {
    Shape = 1,
    Limit,
    Reference,
    Vocabulary,
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum RawDecision {
    Answer { v: u8, claims: Vec<RawClaim> },
    Decline { v: u8, reason: DeclineReason },
    RequestMore { v: u8, terms: Vec<LocalConcept> },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawClaim {
    subject: LocalValue,
    predicate: LocalConcept,
    object: LocalValue,
    evidence: u8,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
struct LocalConcept(u16, u32);

impl From<ConceptRef> for LocalConcept {
    fn from(concept: ConceptRef) -> Self {
        Self(concept.vocabulary_id, concept.concept_id)
    }
}

impl LocalConcept {
    fn known(self) -> Result<ConceptRef, InvalidDecision> {
        let concept = ConceptRef {
            vocabulary_id: self.0,
            concept_id: self.1,
        };
        concept
            .is_known()
            .then_some(concept)
            .ok_or(InvalidDecision::Vocabulary)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum LocalValue {
    Integer { value: i64 },
    Boolean { value: bool },
    Null {},
    Concept { value: LocalConcept },
    Concepts { value: Vec<LocalConcept> },
    Content {},
    Constraint { index: u8 },
}

impl LocalValue {
    fn resolve(
        self,
        context: &DecisionContext,
        candidate: &CandidateEvidence,
    ) -> Result<TypedValue, InvalidDecision> {
        Ok(match self {
            Self::Integer { value } => TypedValue::Integer(value),
            Self::Boolean { value } => TypedValue::Boolean(value),
            Self::Null {} => TypedValue::Null,
            Self::Concept { value } => TypedValue::Concept(value.known()?),
            Self::Concepts { value } => TypedValue::Concepts(unique_concepts(value, 64)?),
            Self::Content {} => TypedValue::Hash(candidate.read.content_id()),
            Self::Constraint { index } => match index
                .checked_sub(1)
                .and_then(|index| context.query.constraints.get(usize::from(index)))
                .map(|constraint| &constraint.value)
            {
                Some(
                    value @ (TypedValue::Hash(_) | TypedValue::Agent(_) | TypedValue::Quantity(..)),
                ) => value.clone(),
                _ => return Err(InvalidDecision::Reference),
            },
        })
    }
}

fn unique_concepts(
    values: Vec<LocalConcept>,
    max: usize,
) -> Result<Vec<ConceptRef>, InvalidDecision> {
    if values.len() > max {
        return Err(InvalidDecision::Limit);
    }
    let mut concepts = Vec::with_capacity(values.len());
    for value in values {
        let concept = value.known()?;
        if concepts.contains(&concept) {
            return Err(InvalidDecision::Vocabulary);
        }
        concepts.push(concept);
    }
    Ok(concepts)
}

fn parse_decision(
    response: &str,
    context: &DecisionContext,
) -> Result<ValidatedDecision, InvalidDecision> {
    if response.len() > MAX_MODEL_TEXT_BYTES {
        return Err(InvalidDecision::Limit);
    }
    let raw = serde_json::from_str(response).map_err(|_| InvalidDecision::Shape)?;
    match raw {
        RawDecision::Answer { v: 1, claims } => {
            if !(1..=MAX_CLAIMS).contains(&claims.len()) {
                return Err(InvalidDecision::Limit);
            }
            let mut bound = Vec::with_capacity(claims.len());
            for raw in claims {
                let candidate = context.candidate(raw.evidence)?;
                let subject = raw.subject.resolve(context, candidate)?;
                let predicate = raw.predicate.known()?;
                let object = raw.object.resolve(context, candidate)?;
                if !predicate.accepts_object(&object) || !model_object_allowed(predicate, &object) {
                    return Err(InvalidDecision::Vocabulary);
                }
                bound.push(SupportedClaim {
                    claim: Claim {
                        subject,
                        predicate,
                        object,
                        evidence: Some(candidate.read.content_id()),
                    },
                    source: candidate.read.resource_key().clone(),
                });
            }
            Ok(ValidatedDecision::Answer(bound))
        }
        RawDecision::Decline { v: 1, reason } => Ok(ValidatedDecision::Decline(reason)),
        RawDecision::RequestMore { v: 1, terms } => {
            let terms = unique_concepts(terms, MAX_TERMS)?;
            if terms.is_empty() || !terms.iter().all(|term| term.is_topic()) {
                return Err(InvalidDecision::Vocabulary);
            }
            Ok(match context.direction {
                Direction::Incoming => {
                    ValidatedDecision::Decline(DeclineReason::InsufficientEvidence)
                }
                Direction::Outgoing => ValidatedDecision::RequestMore(terms),
            })
        }
        _ => Err(InvalidDecision::Shape),
    }
}

fn model_object_allowed(predicate: ConceptRef, object: &TypedValue) -> bool {
    match (predicate.concept_id, object) {
        (201, TypedValue::Integer(value)) => (0..=2).contains(value),
        (202, TypedValue::Integer(value)) => (0..=6).contains(value),
        (203 | 204, TypedValue::Concepts(values)) => values.iter().all(|value| value.is_topic()),
        (205, TypedValue::Integer(value)) => *value >= 0,
        (206, TypedValue::Integer(value)) => (0..=MAX_FILE_BYTES).contains(value),
        (209, _) => false, // A model response cannot assign a verification status.
        _ => true,
    }
}
