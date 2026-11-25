use std::collections::BTreeMap;

use cbor2::{Value, de::Deserializer, value::Integer};
use serde::Deserialize;

use crate::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, Signature65},
};

use super::Expression;

pub const MAX_SEMANTIC_CONTEXT_BUNDLE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_SEMANTIC_CONTEXT_CONCEPTS: usize = 4_096;
pub const MAX_SEMANTIC_CONTEXT_DEPENDENCIES: usize = 64;
pub const MAX_SEMANTIC_CONTEXT_VECTORS: usize = 4_096;
const MAX_UNSIGNED_CONTEXT_BYTES: usize = MAX_SEMANTIC_CONTEXT_BUNDLE_BYTES - 128;
const MAX_VECTOR_INPUTS: usize = 16;
const MAX_CBOR_DEPTH: usize = 16;
const MAX_CBOR_ITEMS: usize = 4_096;
const CONTEXT_DOMAIN: &[u8] = b"ASL-SEMANTIC-CONTEXT-v1\0";
const SIGNING_DOMAIN: &[u8] = b"ASL-SEMANTIC-CONTEXT-SIGN-v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SemanticContextRef {
    pub authority: AgentId,
    pub namespace: u32,
    pub revision: u16,
    pub digest: Hash32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContextAgreementStatus {
    Conformant,
    Unresolved,
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContextRequest {
    pub message_id: Id128,
    pub reference: SemanticContextRef,
    pub expires_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContextOffer {
    pub message_id: Id128,
    pub request_id: Id128,
    pub reference: SemanticContextRef,
    pub content_id: Hash32,
    pub file_size: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContextAgreement {
    pub message_id: Id128,
    pub request_id: Id128,
    pub reference: SemanticContextRef,
    pub status: ContextAgreementStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextExpression {
    pub message_id: Id128,
    pub root_task_id: Id128,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub required_contexts: Vec<SemanticContextRef>,
    pub expression: Expression,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticConceptDefinition {
    pub concept_id: u32,
    pub arity: u8,
    pub definition: Expression,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticConformanceVector {
    pub concept_id: u32,
    pub case_id: u32,
    pub inputs: Vec<Expression>,
    pub expected: Expression,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticContextBundle {
    pub authority: AgentId,
    pub namespace: u32,
    pub revision: u16,
    pub kernel_revision: u16,
    pub dependencies: Vec<SemanticContextRef>,
    pub concepts: Vec<SemanticConceptDefinition>,
    pub vectors: Vec<SemanticConformanceVector>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedSemanticContextBundle {
    pub bundle: SemanticContextBundle,
    pub signature: Signature65,
}

impl SemanticContextBundle {
    pub fn encode_unsigned(&self) -> Result<Vec<u8>, AslError> {
        self.validate()?;
        let encoded =
            cbor2::to_canonical_vec(&self.to_value()).map_err(|_| AslError::InvalidMessage)?;
        if encoded.len() > MAX_UNSIGNED_CONTEXT_BYTES {
            return Err(AslError::QuotaExceeded);
        }
        Ok(encoded)
    }

    fn to_value(&self) -> Value {
        Value::Map(
            [
                (0, uint(1)),
                (1, bytes(self.authority.as_bytes())),
                (2, uint(u64::from(self.namespace))),
                (3, uint(u64::from(self.revision))),
                (4, uint(u64::from(self.kernel_revision))),
                (
                    5,
                    Value::Array(self.dependencies.iter().map(reference_value).collect()),
                ),
                (
                    6,
                    Value::Array(self.concepts.iter().map(concept_value).collect()),
                ),
                (
                    7,
                    Value::Array(self.vectors.iter().map(vector_value).collect()),
                ),
            ]
            .into_iter()
            .map(|(key, value)| (uint(key), value))
            .collect(),
        )
    }

    pub fn decode_unsigned(bytes: &[u8]) -> Result<Self, AslError> {
        let value = decode_canonical(bytes, MAX_UNSIGNED_CONTEXT_BYTES)?;
        let mut fields = fields(value)?;
        check_keys(&fields, &[0, 1, 2, 3, 4, 5, 6, 7])?;
        if as_u64(take(&mut fields, 0)?)? != 1 {
            return Err(AslError::IncompatibleVersion);
        }
        let bundle = Self {
            authority: AgentId(fixed_bytes::<32>(take(&mut fields, 1)?)?),
            namespace: bounded_uint(take(&mut fields, 2)?, u32::MAX as u64)?,
            revision: bounded_uint(take(&mut fields, 3)?, u16::MAX as u64)?,
            kernel_revision: bounded_uint(take(&mut fields, 4)?, u16::MAX as u64)?,
            dependencies: array(take(&mut fields, 5)?, MAX_SEMANTIC_CONTEXT_DEPENDENCIES)?
                .into_iter()
                .map(decode_reference)
                .collect::<Result<_, _>>()?,
            concepts: array(take(&mut fields, 6)?, MAX_SEMANTIC_CONTEXT_CONCEPTS)?
                .into_iter()
                .map(decode_concept)
                .collect::<Result<_, _>>()?,
            vectors: array(take(&mut fields, 7)?, MAX_SEMANTIC_CONTEXT_VECTORS)?
                .into_iter()
                .map(decode_vector)
                .collect::<Result<_, _>>()?,
        };
        finish(fields)?;
        bundle.validate()?;
        Ok(bundle)
    }

    pub fn context_ref(&self) -> Result<SemanticContextRef, AslError> {
        let encoded = self.encode_unsigned()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(CONTEXT_DOMAIN);
        hasher.update(&encoded);
        Ok(SemanticContextRef {
            authority: self.authority,
            namespace: self.namespace,
            revision: self.revision,
            digest: Hash32(*hasher.finalize().as_bytes()),
        })
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, AslError> {
        let reference = self.context_ref()?;
        let mut bytes = Vec::with_capacity(SIGNING_DOMAIN.len() + 32 + 4 + 2 + 2 + 32);
        bytes.extend_from_slice(SIGNING_DOMAIN);
        bytes.extend_from_slice(reference.authority.as_bytes());
        bytes.extend_from_slice(&reference.namespace.to_be_bytes());
        bytes.extend_from_slice(&reference.revision.to_be_bytes());
        bytes.extend_from_slice(&self.kernel_revision.to_be_bytes());
        bytes.extend_from_slice(reference.digest.as_bytes());
        Ok(bytes)
    }

    fn validate(&self) -> Result<(), AslError> {
        if self.revision == 0
            || self.kernel_revision == 0
            || self.concepts.is_empty()
            || self.concepts.len() > MAX_SEMANTIC_CONTEXT_CONCEPTS
            || self.dependencies.len() > MAX_SEMANTIC_CONTEXT_DEPENDENCIES
            || self.vectors.is_empty()
            || self.vectors.len() > MAX_SEMANTIC_CONTEXT_VECTORS
            || self.authority.0.iter().all(|byte| *byte == 0)
            || self
                .concepts
                .windows(2)
                .any(|pair| pair[0].concept_id >= pair[1].concept_id)
            || self.vectors.windows(2).any(|pair| {
                (pair[0].concept_id, pair[0].case_id) >= (pair[1].concept_id, pair[1].case_id)
            })
        {
            return Err(AslError::InvalidMessage);
        }
        if self.dependencies.iter().any(|dependency| {
            dependency.authority.0.iter().all(|byte| *byte == 0)
                || dependency.digest.0.iter().all(|byte| *byte == 0)
        }) {
            return Err(AslError::InvalidMessage);
        }
        for pair in self.dependencies.windows(2) {
            if reference_key(pair[0]) >= reference_key(pair[1])
                || (pair[0].authority == pair[1].authority
                    && pair[0].namespace == pair[1].namespace
                    && pair[0].revision == pair[1].revision)
            {
                return Err(AslError::InvalidMessage);
            }
        }
        if self.dependencies.iter().any(|dependency| {
            dependency.authority == self.authority
                && dependency.namespace == self.namespace
                && dependency.revision == self.revision
        }) {
            return Err(AslError::InvalidMessage);
        }
        for concept in &self.concepts {
            if concept.arity > MAX_VECTOR_INPUTS as u8
                || !concept.definition.is_definition_of(
                    self.authority,
                    self.namespace,
                    self.revision,
                    concept.concept_id,
                    concept.arity,
                )
            {
                return Err(AslError::InvalidMessage);
            }
            self.validate_references(&concept.definition)?;
            if self
                .vectors
                .binary_search_by_key(&concept.concept_id, |vector| vector.concept_id)
                .is_err()
            {
                return Err(AslError::InvalidMessage);
            }
        }
        for vector in &self.vectors {
            let concept = self
                .concepts
                .binary_search_by_key(&vector.concept_id, |concept| concept.concept_id)
                .ok()
                .map(|index| &self.concepts[index])
                .ok_or(AslError::InvalidMessage)?;
            if vector.inputs.len() != usize::from(concept.arity)
                || vector.inputs.len() > MAX_VECTOR_INPUTS
            {
                return Err(AslError::InvalidMessage);
            }
            for input in &vector.inputs {
                self.validate_references(input)?;
            }
            self.validate_references(&vector.expected)?;
        }
        Ok(())
    }

    fn validate_references(&self, expression: &Expression) -> Result<(), AslError> {
        for (authority, namespace, revision, concept_id) in expression.referenced_concepts() {
            if authority == self.authority
                && namespace == self.namespace
                && revision == self.revision
            {
                if self
                    .concepts
                    .binary_search_by_key(&concept_id, |concept| concept.concept_id)
                    .is_err()
                {
                    return Err(AslError::InvalidMessage);
                }
            } else if !self.dependencies.iter().any(|dependency| {
                dependency.authority == authority
                    && dependency.namespace == namespace
                    && dependency.revision == revision
            }) {
                return Err(AslError::InvalidMessage);
            }
        }
        Ok(())
    }
}

impl SignedSemanticContextBundle {
    pub fn encode(&self) -> Result<Vec<u8>, AslError> {
        self.bundle.validate()?;
        let value = Value::Map(
            [
                (0, uint(1)),
                (1, self.bundle.to_value()),
                (2, bytes(self.signature.as_bytes())),
            ]
            .into_iter()
            .map(|(key, value)| (uint(key), value))
            .collect(),
        );
        let encoded = cbor2::to_canonical_vec(&value).map_err(|_| AslError::InvalidMessage)?;
        if encoded.len() > MAX_SEMANTIC_CONTEXT_BUNDLE_BYTES {
            return Err(AslError::QuotaExceeded);
        }
        Ok(encoded)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, AslError> {
        let value = decode_canonical(bytes, MAX_SEMANTIC_CONTEXT_BUNDLE_BYTES)?;
        let mut fields = fields(value)?;
        check_keys(&fields, &[0, 1, 2])?;
        if as_u64(take(&mut fields, 0)?)? != 1 {
            return Err(AslError::IncompatibleVersion);
        }
        let unsigned = cbor2::to_canonical_vec(&take(&mut fields, 1)?)
            .map_err(|_| AslError::InvalidMessage)?;
        let bundle = SemanticContextBundle::decode_unsigned(&unsigned)?;
        let signature = Signature65(fixed_bytes::<65>(take(&mut fields, 2)?)?);
        finish(fields)?;
        Ok(Self { bundle, signature })
    }
}

fn concept_value(concept: &SemanticConceptDefinition) -> Value {
    Value::Array(vec![
        uint(u64::from(concept.concept_id)),
        uint(u64::from(concept.arity)),
        concept.definition.to_cbor(),
    ])
}

fn decode_concept(value: Value) -> Result<SemanticConceptDefinition, AslError> {
    let values = array(value, 3)?;
    if values.len() != 3 {
        return Err(AslError::InvalidMessage);
    }
    let mut values = values.into_iter();
    Ok(SemanticConceptDefinition {
        concept_id: bounded_uint(
            values.next().ok_or(AslError::InvalidMessage)?,
            u32::MAX as u64,
        )?,
        arity: bounded_uint(
            values.next().ok_or(AslError::InvalidMessage)?,
            MAX_VECTOR_INPUTS as u64,
        )?,
        definition: Expression::from_cbor(&values.next().ok_or(AslError::InvalidMessage)?)?,
    })
}

fn vector_value(vector: &SemanticConformanceVector) -> Value {
    Value::Array(vec![
        uint(u64::from(vector.concept_id)),
        uint(u64::from(vector.case_id)),
        Value::Array(vector.inputs.iter().map(Expression::to_cbor).collect()),
        vector.expected.to_cbor(),
    ])
}

fn decode_vector(value: Value) -> Result<SemanticConformanceVector, AslError> {
    let values = array(value, 4)?;
    if values.len() != 4 {
        return Err(AslError::InvalidMessage);
    }
    let mut values = values.into_iter();
    Ok(SemanticConformanceVector {
        concept_id: bounded_uint(
            values.next().ok_or(AslError::InvalidMessage)?,
            u32::MAX as u64,
        )?,
        case_id: bounded_uint(
            values.next().ok_or(AslError::InvalidMessage)?,
            u32::MAX as u64,
        )?,
        inputs: array(
            values.next().ok_or(AslError::InvalidMessage)?,
            MAX_VECTOR_INPUTS,
        )?
        .iter()
        .map(Expression::from_cbor)
        .collect::<Result<_, _>>()?,
        expected: Expression::from_cbor(&values.next().ok_or(AslError::InvalidMessage)?)?,
    })
}

fn reference_value(reference: &SemanticContextRef) -> Value {
    Value::Array(vec![
        bytes(reference.authority.as_bytes()),
        uint(u64::from(reference.namespace)),
        uint(u64::from(reference.revision)),
        bytes(reference.digest.as_bytes()),
    ])
}

fn decode_reference(value: Value) -> Result<SemanticContextRef, AslError> {
    let values = array(value, 4)?;
    if values.len() != 4 {
        return Err(AslError::InvalidMessage);
    }
    let mut values = values.into_iter();
    Ok(SemanticContextRef {
        authority: AgentId(fixed_bytes::<32>(
            values.next().ok_or(AslError::InvalidMessage)?,
        )?),
        namespace: bounded_uint(
            values.next().ok_or(AslError::InvalidMessage)?,
            u32::MAX as u64,
        )?,
        revision: bounded_uint(
            values.next().ok_or(AslError::InvalidMessage)?,
            u16::MAX as u64,
        )?,
        digest: Hash32(fixed_bytes::<32>(
            values.next().ok_or(AslError::InvalidMessage)?,
        )?),
    })
}

fn reference_key(reference: SemanticContextRef) -> ([u8; 32], u32, u16, [u8; 32]) {
    (
        reference.authority.0,
        reference.namespace,
        reference.revision,
        reference.digest.0,
    )
}

fn decode_canonical(bytes: &[u8], maximum: usize) -> Result<Value, AslError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(AslError::InvalidMessage);
    }
    cbor2::validate_slice(bytes).map_err(|_| AslError::InvalidMessage)?;
    let mut decoder = Deserializer::from_slice_with_recursion_limit(bytes, MAX_CBOR_DEPTH);
    let value = Value::deserialize(&mut decoder).map_err(|_| AslError::InvalidMessage)?;
    if decoder.offset() != bytes.len() {
        return Err(AslError::InvalidMessage);
    }
    validate_data_tree(&value, 0)?;
    if cbor2::to_canonical_vec(&value).map_err(|_| AslError::InvalidMessage)? != bytes {
        return Err(AslError::InvalidMessage);
    }
    Ok(value)
}

fn validate_data_tree(value: &Value, depth: usize) -> Result<(), AslError> {
    if depth > MAX_CBOR_DEPTH {
        return Err(AslError::InvalidMessage);
    }
    match value {
        Value::Integer(_) | Value::Bytes(_) | Value::Bool(_) | Value::Null => Ok(()),
        Value::Array(values) if values.len() <= MAX_CBOR_ITEMS => values
            .iter()
            .try_for_each(|value| validate_data_tree(value, depth + 1)),
        Value::Map(fields) if fields.len() <= 8 => fields.iter().try_for_each(|(key, value)| {
            if !matches!(key, Value::Integer(_)) {
                return Err(AslError::InvalidMessage);
            }
            validate_data_tree(key, depth + 1)?;
            validate_data_tree(value, depth + 1)
        }),
        _ => Err(AslError::InvalidMessage),
    }
}

fn fields(value: Value) -> Result<BTreeMap<u64, Value>, AslError> {
    let Value::Map(values) = value else {
        return Err(AslError::InvalidMessage);
    };
    let mut result = BTreeMap::new();
    for (key, value) in values {
        if result.insert(as_u64(key)?, value).is_some() {
            return Err(AslError::InvalidMessage);
        }
    }
    Ok(result)
}

fn check_keys(fields: &BTreeMap<u64, Value>, allowed: &[u64]) -> Result<(), AslError> {
    if fields.len() == allowed.len() && fields.keys().all(|key| allowed.contains(key)) {
        Ok(())
    } else {
        Err(AslError::InvalidMessage)
    }
}

fn take(fields: &mut BTreeMap<u64, Value>, key: u64) -> Result<Value, AslError> {
    fields.remove(&key).ok_or(AslError::InvalidMessage)
}

fn finish(fields: BTreeMap<u64, Value>) -> Result<(), AslError> {
    if fields.is_empty() {
        Ok(())
    } else {
        Err(AslError::InvalidMessage)
    }
}

fn uint(value: u64) -> Value {
    Value::Integer(Integer::from(value))
}

fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}

fn as_u64(value: Value) -> Result<u64, AslError> {
    match value {
        Value::Integer(value) => u64::try_from(value).map_err(|_| AslError::InvalidMessage),
        _ => Err(AslError::InvalidMessage),
    }
}

fn bounded_uint<T>(value: Value, maximum: u64) -> Result<T, AslError>
where
    T: TryFrom<u64>,
{
    let value = as_u64(value)?;
    if value > maximum {
        return Err(AslError::InvalidMessage);
    }
    T::try_from(value).map_err(|_| AslError::InvalidMessage)
}

fn fixed_bytes<const N: usize>(value: Value) -> Result<[u8; N], AslError> {
    match value {
        Value::Bytes(bytes) => bytes.try_into().map_err(|_| AslError::InvalidMessage),
        _ => Err(AslError::InvalidMessage),
    }
}

fn array(value: Value, maximum: usize) -> Result<Vec<Value>, AslError> {
    match value {
        Value::Array(values) if values.len() <= maximum => Ok(values),
        _ => Err(AslError::InvalidMessage),
    }
}
