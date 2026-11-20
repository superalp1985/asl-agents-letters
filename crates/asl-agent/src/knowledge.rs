//! Persists only claims already validated against the current model evidence set.

use asl_policy::{AccessOperation, AccessRequest, PolicyService, Principal};
use asl_store::resources::{DerivedResourceInfo, SnapshotBroker};
use asl_types::{
    error::AslError,
    ids::Id128,
    protocol::{Claim, ConceptRef, TypedValue},
    task::{ResourceKey, TaskId},
};
use serde::Serialize;

use crate::decision::{SupportedClaim, ValidatedDecision};

const MAX_CLAIMS: usize = 32;
const MAX_SOURCES: usize = 8;
const MAX_CONCEPTS: usize = 64;

pub struct KnowledgeRepository;

impl KnowledgeRepository {
    /// Saves answer claims as a local derived resource. Publication is decided
    /// from source permits; no model-provided field can make a record public.
    pub fn save_answer(
        broker: &mut SnapshotBroker,
        decision: &ValidatedDecision,
        write_grant_id: Id128,
        task_id: &TaskId,
        policy: &dyn PolicyService,
        now_ms: u64,
    ) -> Result<Option<DerivedResourceInfo>, AslError> {
        let ValidatedDecision::Answer(claims) = decision else {
            return Ok(None);
        };
        if claims.is_empty() || claims.len() > MAX_CLAIMS {
            return Err(AslError::InvalidMessage);
        }

        let mut sources = Vec::new();
        let mut concepts = Vec::new();
        for supported in claims {
            if !sources.contains(supported.source()) {
                sources.push(supported.source().clone());
            }
            collect_claim_concepts(supported.claim(), &mut concepts)?;
        }
        if sources.is_empty() || sources.len() > MAX_SOURCES {
            return Err(AslError::QuotaExceeded);
        }

        let source_facts = broker.derived_sources(&sources)?;
        let principal = Principal::LocalTask(task_id.clone());
        let mut write_permits = Vec::with_capacity(source_facts.len());
        let mut publish_permits = Vec::with_capacity(source_facts.len());
        for source in &source_facts {
            write_permits.push(policy.authorize(
                &AccessRequest {
                    grant_id: source.grant_id.clone(),
                    resource_key: source.resource_key.clone(),
                    principal: principal.clone(),
                    operation: AccessOperation::WriteDerived,
                },
                now_ms,
            )?);
            if let Ok(permit) = policy.authorize(
                &AccessRequest {
                    grant_id: source.grant_id.clone(),
                    resource_key: source.resource_key.clone(),
                    principal: principal.clone(),
                    operation: AccessOperation::PublishRecord,
                },
                now_ms,
            ) {
                publish_permits.push(permit);
            }
        }

        let document = StoredKnowledge::from_claims(claims, &sources, now_ms)?;
        let bytes = serde_json::to_vec(&document).map_err(|_| AslError::InvalidMessage)?;
        let result = broker.save_derived_knowledge(
            write_grant_id,
            task_id,
            &bytes,
            &sources,
            &concepts,
            &write_permits,
            &publish_permits,
            policy,
            now_ms,
        )?;
        Ok(Some(result))
    }
}

#[derive(Serialize)]
struct StoredKnowledge {
    version: u8,
    claims: Vec<StoredClaim>,
    conditions: Vec<(u16, u32)>,
    source_resource_keys: Vec<String>,
    verification: &'static str,
    created_at_ms: u64,
}

#[derive(Serialize)]
struct StoredClaim {
    subject: StoredValue,
    predicate: (u16, u32),
    value: StoredValue,
    evidence: Option<String>,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum StoredValue {
    Integer { value: i64 },
    Boolean { value: bool },
    Null {},
    Hash { value: String },
    Agent { value: String },
    Concept { value: (u16, u32) },
    Concepts { value: Vec<(u16, u32)> },
    Quantity { value: i64, unit: (u16, u32) },
}

impl StoredKnowledge {
    fn from_claims(
        claims: &[SupportedClaim],
        sources: &[ResourceKey],
        now_ms: u64,
    ) -> Result<Self, AslError> {
        if now_ms > i64::MAX as u64 {
            return Err(AslError::InvalidMessage);
        }
        let claims = claims
            .iter()
            .map(|supported| stored_claim(supported.claim()))
            .collect();
        Ok(Self {
            version: 1,
            claims,
            conditions: Vec::new(),
            source_resource_keys: sources.iter().map(|key| hex::encode(key.0.0)).collect(),
            verification: "derived_unverified",
            created_at_ms: now_ms,
        })
    }
}

fn stored_claim(claim: &Claim) -> StoredClaim {
    StoredClaim {
        subject: stored_value(&claim.subject),
        predicate: concept_pair(claim.predicate),
        value: stored_value(&claim.object),
        evidence: claim.evidence.map(|hash| hex::encode(hash.0)),
    }
}

fn stored_value(value: &TypedValue) -> StoredValue {
    match value {
        TypedValue::Integer(value) => StoredValue::Integer { value: *value },
        TypedValue::Boolean(value) => StoredValue::Boolean { value: *value },
        TypedValue::Null => StoredValue::Null {},
        TypedValue::Hash(value) => StoredValue::Hash {
            value: hex::encode(value.0),
        },
        TypedValue::Agent(value) => StoredValue::Agent {
            value: hex::encode(value.0),
        },
        TypedValue::Concept(value) => StoredValue::Concept {
            value: concept_pair(*value),
        },
        TypedValue::Concepts(values) => StoredValue::Concepts {
            value: values.iter().copied().map(concept_pair).collect(),
        },
        TypedValue::Quantity(value, unit) => StoredValue::Quantity {
            value: *value,
            unit: concept_pair(*unit),
        },
    }
}

fn collect_claim_concepts(claim: &Claim, concepts: &mut Vec<ConceptRef>) -> Result<(), AslError> {
    if !claim.predicate.is_known() {
        return Err(AslError::InvalidMessage);
    }
    let mut used = Vec::new();
    collect_value_concepts(&claim.subject, &mut used);
    collect_value_concepts(&claim.object, &mut used);
    for concept in used {
        if !concept.is_known() {
            return Err(AslError::InvalidMessage);
        }
        if concept.is_topic() && !concepts.contains(&concept) {
            concepts.push(concept);
        }
    }
    if concepts.len() > MAX_CONCEPTS {
        return Err(AslError::QuotaExceeded);
    }
    Ok(())
}

fn collect_value_concepts(value: &TypedValue, concepts: &mut Vec<ConceptRef>) {
    match value {
        TypedValue::Concept(concept) => {
            if !concepts.contains(concept) {
                concepts.push(*concept);
            }
        }
        TypedValue::Concepts(values) => {
            for concept in values {
                if !concepts.contains(concept) {
                    concepts.push(*concept);
                }
            }
        }
        TypedValue::Quantity(_, unit) => {
            if !concepts.contains(unit) {
                concepts.push(*unit);
            }
        }
        TypedValue::Integer(_)
        | TypedValue::Boolean(_)
        | TypedValue::Null
        | TypedValue::Hash(_)
        | TypedValue::Agent(_) => {}
    }
}

fn concept_pair(concept: ConceptRef) -> (u16, u32) {
    (concept.vocabulary_id, concept.concept_id)
}
