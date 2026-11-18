use std::collections::BTreeMap;

use cbor2::{Value, value::Integer};
use serde::Deserialize;

use crate::{
    error::{AslError, ErrorCode},
    ids::{AgentId, Hash32, Id128, PeerId, Signature65},
    protocol::{
        Ack, Answer, AnswerStatus, Claim, ConceptRef, Constraint, ConstraintOperator,
        DeviceCertificate, Feature, FetchGrant, FetchRequest, GroupEnvelope, GroupOperation, Hello,
        IdentityProof, IdentityProofRequest, Intent, MediaKind, Offer, PairingExchange,
        PairingInvite, Profile, ProtocolError, Query, ResultShape, ResultStatus, StorageProof,
        TypedValue, WireFrame,
    },
};

pub const MAX_CONTROL_FRAME_BYTES: usize = 65_536;
pub const MAX_EXTENDED_FRAME_BYTES: usize = 256 * 1024;
const MAX_PAIRING_FRAME_BYTES: usize = 8 * 1024;
const MAX_FILE_SIZE: u64 = 68_719_476_736;
const MAX_TIME_MS: u64 = i64::MAX as u64;
const MAX_CERTIFICATE_TTL_MS: u64 = 30 * 24 * 60 * 60 * 1_000;
const MAX_CONCEPTS: usize = 64;
const MAX_CONSTRAINTS: usize = 16;
const MAX_CLAIMS: usize = 32;

type Fields = BTreeMap<u64, Value>;

fn invalid<T>() -> Result<T, AslError> {
    Err(AslError::InvalidMessage)
}

pub(crate) fn uint(value: u64) -> Value {
    Value::Integer(Integer::from(value))
}

fn sint(value: i64) -> Value {
    Value::Integer(Integer::from(value))
}

pub(crate) fn map(entries: impl IntoIterator<Item = (u64, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(key, value)| (uint(key), value))
            .collect(),
    )
}

pub(crate) fn fields(value: Value) -> Result<Fields, AslError> {
    let Value::Map(entries) = value else {
        return invalid();
    };
    let mut result = BTreeMap::new();
    for (key, value) in entries {
        let key = as_u64(key)?;
        if result.insert(key, value).is_some() {
            return invalid();
        }
    }
    Ok(result)
}

pub(crate) fn check_keys(fields: &Fields, allowed: &[u64]) -> Result<(), AslError> {
    if fields.keys().all(|key| allowed.contains(key)) {
        Ok(())
    } else {
        invalid()
    }
}

pub(crate) fn take(fields: &mut Fields, key: u64) -> Result<Value, AslError> {
    fields.remove(&key).ok_or(AslError::InvalidMessage)
}

fn take_optional(fields: &mut Fields, key: u64) -> Option<Value> {
    fields.remove(&key)
}

pub(crate) fn finish(fields: Fields) -> Result<(), AslError> {
    if fields.is_empty() { Ok(()) } else { invalid() }
}

pub(crate) fn as_u64(value: Value) -> Result<u64, AslError> {
    match value {
        Value::Integer(value) => u64::try_from(value).map_err(|_| AslError::InvalidMessage),
        _ => invalid(),
    }
}

fn as_i64(value: Value) -> Result<i64, AslError> {
    match value {
        Value::Integer(value) => i64::try_from(value).map_err(|_| AslError::InvalidMessage),
        _ => invalid(),
    }
}

fn as_bool(value: Value) -> Result<bool, AslError> {
    match value {
        Value::Bool(value) => Ok(value),
        _ => invalid(),
    }
}

fn bounded_uint<T>(value: Value, max: u64) -> Result<T, AslError>
where
    T: TryFrom<u64>,
{
    let value = as_u64(value)?;
    if value > max {
        return invalid();
    }
    T::try_from(value).map_err(|_| AslError::InvalidMessage)
}

pub(crate) fn fixed_bytes<const N: usize>(value: Value) -> Result<[u8; N], AslError> {
    match value {
        Value::Bytes(bytes) => bytes.try_into().map_err(|_| AslError::InvalidMessage),
        _ => invalid(),
    }
}

pub(crate) fn byte_string(value: Value, min: usize, max: usize) -> Result<Vec<u8>, AslError> {
    match value {
        Value::Bytes(bytes) if (min..=max).contains(&bytes.len()) => Ok(bytes),
        _ => invalid(),
    }
}

fn peer_id(value: Value) -> Result<PeerId, AslError> {
    match value {
        Value::Bytes(bytes) => PeerId::from_bytes(bytes).map_err(|_| AslError::InvalidMessage),
        _ => invalid(),
    }
}

pub(crate) fn array(value: Value, max: usize) -> Result<Vec<Value>, AslError> {
    match value {
        Value::Array(values) if values.len() <= max => Ok(values),
        _ => invalid(),
    }
}

fn validate_tree(value: &Value, depth: usize) -> Result<(), AslError> {
    if depth > 16 {
        return invalid();
    }
    match value {
        Value::Integer(_) | Value::Bytes(_) | Value::Bool(_) | Value::Null => Ok(()),
        Value::Array(values) if values.len() <= 4_096 => {
            for item in values {
                validate_tree(item, depth + 1)?;
            }
            Ok(())
        }
        Value::Map(entries) if entries.len() <= 4_096 => {
            for (key, value) in entries {
                validate_tree(key, depth + 1)?;
                validate_tree(value, depth + 1)?;
            }
            Ok(())
        }
        _ => invalid(),
    }
}

pub(crate) fn decode_canonical(bytes: &[u8]) -> Result<Value, AslError> {
    if bytes.is_empty() || bytes.len() > MAX_EXTENDED_FRAME_BYTES {
        return invalid();
    }
    cbor2::validate_slice(bytes).map_err(|_| AslError::InvalidMessage)?;
    let mut decoder = cbor2::de::Deserializer::from_slice_with_recursion_limit(bytes, 16);
    let value = Value::deserialize(&mut decoder).map_err(|_| AslError::InvalidMessage)?;
    if decoder.offset() != bytes.len() {
        return invalid();
    }
    validate_tree(&value, 0)?;
    let canonical = cbor2::to_canonical_vec(&value).map_err(|_| AslError::InvalidMessage)?;
    if canonical != bytes {
        return invalid();
    }
    Ok(value)
}

fn concept_ref(value: Value) -> Result<ConceptRef, AslError> {
    let values = array(value, 2)?;
    if values.len() != 2 {
        return invalid();
    }
    let mut values = values.into_iter();
    let vocabulary_id = bounded_uint(
        values.next().ok_or(AslError::InvalidMessage)?,
        u16::MAX as u64,
    )?;
    let concept_id = bounded_uint(
        values.next().ok_or(AslError::InvalidMessage)?,
        u32::MAX as u64,
    )?;
    let concept = ConceptRef {
        vocabulary_id,
        concept_id,
    };
    if known_concept(concept) {
        Ok(concept)
    } else {
        invalid()
    }
}

fn known_concept(concept: ConceptRef) -> bool {
    concept.vocabulary_id == 1
        && matches!(
            concept.concept_id,
            1..=6 | 100..=111 | 200..=209
        )
}

fn is_topic(concept: ConceptRef) -> bool {
    concept.is_topic()
}

fn is_predicate(concept: ConceptRef) -> bool {
    concept.vocabulary_id == 1 && (200..=209).contains(&concept.concept_id)
}

fn concept_ref_value(concept: ConceptRef) -> Value {
    Value::Array(vec![
        uint(u64::from(concept.vocabulary_id)),
        uint(u64::from(concept.concept_id)),
    ])
}

fn concept_refs(value: Value, max: usize) -> Result<Vec<ConceptRef>, AslError> {
    let values = array(value, max)?;
    let mut result = Vec::with_capacity(values.len());
    for value in values {
        let concept = concept_ref(value)?;
        if result.contains(&concept) {
            return invalid();
        }
        result.push(concept);
    }
    Ok(result)
}

fn concept_refs_value(values: &[ConceptRef]) -> Value {
    Value::Array(values.iter().copied().map(concept_ref_value).collect())
}

fn typed_value(value: Value) -> Result<TypedValue, AslError> {
    let mut values = array(value, 3)?.into_iter();
    let kind = bounded_uint::<u8>(
        values.next().ok_or(AslError::InvalidMessage)?,
        u8::MAX as u64,
    )?;
    let value = values.next().ok_or(AslError::InvalidMessage)?;
    let parsed = match kind {
        0 if values.next().is_none() => TypedValue::Integer(as_i64(value)?),
        1 if values.next().is_none() => TypedValue::Boolean(as_bool(value)?),
        2 if values.next().is_none() && matches!(&value, Value::Null) => TypedValue::Null,
        3 if values.next().is_none() => TypedValue::Hash(Hash32(fixed_bytes::<32>(value)?)),
        4 if values.next().is_none() => TypedValue::Agent(AgentId(fixed_bytes::<32>(value)?)),
        5 if values.next().is_none() => TypedValue::Concept(concept_ref(value)?),
        6 => {
            let unit = concept_ref(values.next().ok_or(AslError::InvalidMessage)?)?;
            if values.next().is_some() {
                return invalid();
            }
            TypedValue::Quantity(as_i64(value)?, unit)
        }
        7 => {
            let concepts = concept_refs(value, MAX_CONCEPTS)?;
            if values.next().is_some() {
                return invalid();
            }
            TypedValue::Concepts(concepts)
        }
        _ => return invalid(),
    };
    Ok(parsed)
}

fn typed_value_value(value: &TypedValue) -> Value {
    match value {
        TypedValue::Integer(value) => Value::Array(vec![uint(0), sint(*value)]),
        TypedValue::Boolean(value) => Value::Array(vec![uint(1), Value::Bool(*value)]),
        TypedValue::Null => Value::Array(vec![uint(2), Value::Null]),
        TypedValue::Hash(value) => Value::Array(vec![uint(3), Value::Bytes(value.0.to_vec())]),
        TypedValue::Agent(value) => Value::Array(vec![uint(4), Value::Bytes(value.0.to_vec())]),
        TypedValue::Concept(value) => Value::Array(vec![uint(5), concept_ref_value(*value)]),
        TypedValue::Quantity(value, unit) => {
            Value::Array(vec![uint(6), sint(*value), concept_ref_value(*unit)])
        }
        TypedValue::Concepts(values) => Value::Array(vec![uint(7), concept_refs_value(values)]),
    }
}

fn constraint_value(value: Value) -> Result<Constraint, AslError> {
    let mut fields = fields(value)?;
    check_keys(&fields, &[0, 1, 2])?;
    let concept = concept_ref(take(&mut fields, 0)?)?;
    let operator = constraint_operator(take(&mut fields, 1)?)?;
    let value = typed_value(take(&mut fields, 2)?)?;
    finish(fields)?;
    if !is_predicate(concept) || !predicate_accepts(concept.concept_id, &value) {
        return invalid();
    }
    Ok(Constraint {
        predicate: concept,
        operator,
        value,
    })
}

fn predicate_accepts(id: u32, value: &TypedValue) -> bool {
    match id {
        200 => true,
        201 | 202 | 205 | 206 | 209 => matches!(value, TypedValue::Integer(_)),
        203 | 204 => matches!(value, TypedValue::Concepts(_)),
        207 => matches!(value, TypedValue::Hash(_)),
        208 => matches!(value, TypedValue::Agent(_)),
        _ => false,
    }
}

fn constraint_value_value(value: &Constraint) -> Value {
    map([
        (0, concept_ref_value(value.predicate)),
        (1, uint(constraint_operator_code(value.operator))),
        (2, typed_value_value(&value.value)),
    ])
}

fn claim(value: Value) -> Result<Claim, AslError> {
    let mut fields = fields(value)?;
    check_keys(&fields, &[0, 1, 2, 3])?;
    let subject = typed_value(take(&mut fields, 0)?)?;
    let predicate = concept_ref(take(&mut fields, 1)?)?;
    let object = typed_value(take(&mut fields, 2)?)?;
    let evidence = take_optional(&mut fields, 3)
        .map(|value| fixed_bytes::<32>(value).map(Hash32))
        .transpose()?;
    finish(fields)?;
    if !is_predicate(predicate) {
        return invalid();
    }
    Ok(Claim {
        subject,
        predicate,
        object,
        evidence,
    })
}

fn claim_value(value: &Claim) -> Value {
    let mut entries = vec![
        (0, typed_value_value(&value.subject)),
        (1, concept_ref_value(value.predicate)),
        (2, typed_value_value(&value.object)),
    ];
    if let Some(evidence) = value.evidence {
        entries.push((3, Value::Bytes(evidence.0.to_vec())));
    }
    map(entries)
}

pub(crate) fn device_certificate(value: Value) -> Result<DeviceCertificate, AslError> {
    let mut fields = fields(value)?;
    check_keys(&fields, &[0, 1, 2, 3, 4, 5, 6])?;
    let version = bounded_uint::<u8>(take(&mut fields, 0)?, 1)?;
    let agent_id = AgentId(fixed_bytes::<32>(take(&mut fields, 1)?)?);
    let peer_id = peer_id(take(&mut fields, 2)?)?;
    let serial = as_u64(take(&mut fields, 3)?)?;
    let issued_at_ms = as_u64(take(&mut fields, 4)?)?;
    let expires_at_ms = as_u64(take(&mut fields, 5)?)?;
    let signature = Signature65(fixed_bytes::<65>(take(&mut fields, 6)?)?);
    finish(fields)?;
    if version != 1
        || serial == 0
        || issued_at_ms > MAX_TIME_MS
        || expires_at_ms > MAX_TIME_MS
        || expires_at_ms < issued_at_ms
        || expires_at_ms - issued_at_ms > MAX_CERTIFICATE_TTL_MS
    {
        return invalid();
    }
    Ok(DeviceCertificate {
        agent_id,
        peer_id,
        serial,
        issued_at_ms,
        expires_at_ms,
        signature,
    })
}

pub(crate) fn device_certificate_value(value: &DeviceCertificate) -> Value {
    map([
        (0, uint(1)),
        (1, Value::Bytes(value.agent_id.0.to_vec())),
        (2, Value::Bytes(value.peer_id.as_bytes().to_vec())),
        (3, uint(value.serial)),
        (4, uint(value.issued_at_ms)),
        (5, uint(value.expires_at_ms)),
        (6, Value::Bytes(value.signature.0.to_vec())),
    ])
}

fn feature(value: Value) -> Result<Feature, AslError> {
    match bounded_uint::<u8>(value, u8::MAX as u64)? {
        1 => Ok(Feature::Query),
        2 => Ok(Feature::Blob),
        3 => Ok(Feature::Inline),
        4 => Ok(Feature::Profile),
        _ => invalid(),
    }
}

fn feature_code(value: Feature) -> u64 {
    match value {
        Feature::Query => 1,
        Feature::Blob => 2,
        Feature::Inline => 3,
        Feature::Profile => 4,
    }
}

fn intent(value: Value) -> Result<Intent, AslError> {
    match bounded_uint::<u8>(value, 6)? {
        1 => Ok(Intent::FindEvidence),
        2 => Ok(Intent::LocateResource),
        3 => Ok(Intent::VerifyClaim),
        4 => Ok(Intent::IdentifyAgent),
        5 => Ok(Intent::OfferResource),
        6 => Ok(Intent::GroupReview),
        _ => invalid(),
    }
}

fn intent_code(value: Intent) -> u64 {
    match value {
        Intent::FindEvidence => 1,
        Intent::LocateResource => 2,
        Intent::VerifyClaim => 3,
        Intent::IdentifyAgent => 4,
        Intent::OfferResource => 5,
        Intent::GroupReview => 6,
    }
}

fn constraint_operator(value: Value) -> Result<ConstraintOperator, AslError> {
    match bounded_uint::<u8>(value, 7)? {
        0 => Ok(ConstraintOperator::Equal),
        1 => Ok(ConstraintOperator::NotEqual),
        2 => Ok(ConstraintOperator::LessThan),
        3 => Ok(ConstraintOperator::LessOrEqual),
        4 => Ok(ConstraintOperator::GreaterThan),
        5 => Ok(ConstraintOperator::GreaterOrEqual),
        6 => Ok(ConstraintOperator::Contains),
        7 => Ok(ConstraintOperator::In),
        _ => invalid(),
    }
}

fn constraint_operator_code(value: ConstraintOperator) -> u64 {
    match value {
        ConstraintOperator::Equal => 0,
        ConstraintOperator::NotEqual => 1,
        ConstraintOperator::LessThan => 2,
        ConstraintOperator::LessOrEqual => 3,
        ConstraintOperator::GreaterThan => 4,
        ConstraintOperator::GreaterOrEqual => 5,
        ConstraintOperator::Contains => 6,
        ConstraintOperator::In => 7,
    }
}

fn result_shape(value: Value) -> Result<ResultShape, AslError> {
    match bounded_uint::<u8>(value, 2)? {
        0 => Ok(ResultShape::Claims),
        1 => Ok(ResultShape::Resources),
        2 => Ok(ResultShape::Agents),
        _ => invalid(),
    }
}

fn result_shape_code(value: ResultShape) -> u64 {
    match value {
        ResultShape::Claims => 0,
        ResultShape::Resources => 1,
        ResultShape::Agents => 2,
    }
}

fn answer_status(value: Value) -> Result<AnswerStatus, AslError> {
    match bounded_uint::<u8>(value, 3)? {
        0 => Ok(AnswerStatus::Answered),
        1 => Ok(AnswerStatus::NoMatch),
        2 => Ok(AnswerStatus::Declined),
        3 => Ok(AnswerStatus::Unsupported),
        _ => invalid(),
    }
}

fn answer_status_code(value: AnswerStatus) -> u64 {
    match value {
        AnswerStatus::Answered => 0,
        AnswerStatus::NoMatch => 1,
        AnswerStatus::Declined => 2,
        AnswerStatus::Unsupported => 3,
    }
}

fn result_status(value: Value) -> Result<ResultStatus, AslError> {
    match bounded_uint::<u8>(value, 2)? {
        0 => Ok(ResultStatus::Complete),
        1 => Ok(ResultStatus::Partial),
        2 => Ok(ResultStatus::Unverified),
        _ => invalid(),
    }
}

fn result_status_code(value: ResultStatus) -> u64 {
    match value {
        ResultStatus::Complete => 0,
        ResultStatus::Partial => 1,
        ResultStatus::Unverified => 2,
    }
}

fn media_kind(value: Value) -> Result<MediaKind, AslError> {
    match bounded_uint::<u8>(value, 6)? {
        0 => Ok(MediaKind::Other),
        1 => Ok(MediaKind::Document),
        2 => Ok(MediaKind::Image),
        3 => Ok(MediaKind::Audio),
        4 => Ok(MediaKind::Video),
        5 => Ok(MediaKind::Archive),
        6 => Ok(MediaKind::StructuredData),
        _ => invalid(),
    }
}

fn media_kind_code(value: MediaKind) -> u64 {
    match value {
        MediaKind::Other => 0,
        MediaKind::Document => 1,
        MediaKind::Image => 2,
        MediaKind::Audio => 3,
        MediaKind::Video => 4,
        MediaKind::Archive => 5,
        MediaKind::StructuredData => 6,
    }
}

fn group_operation(value: Value) -> Result<GroupOperation, AslError> {
    match bounded_uint::<u8>(value, 1)? {
        0 => Ok(GroupOperation::Application),
        1 => Ok(GroupOperation::Membership),
        _ => invalid(),
    }
}

fn group_operation_code(value: GroupOperation) -> u64 {
    match value {
        GroupOperation::Application => 0,
        GroupOperation::Membership => 1,
    }
}

fn decode_hello(mut fields: Fields) -> Result<WireFrame, AslError> {
    check_keys(&fields, &[2, 3, 4, 5, 6, 7, 8])?;
    let message_id = Id128(fixed_bytes::<16>(take(&mut fields, 2)?)?);
    let agent_id = AgentId(fixed_bytes::<32>(take(&mut fields, 3)?)?);
    let peer_id = peer_id(take(&mut fields, 4)?)?;
    let device_certificate = device_certificate(take(&mut fields, 5)?)?;
    let major = bounded_uint(take(&mut fields, 6)?, u16::MAX as u64)?;
    let minor = bounded_uint(take(&mut fields, 7)?, u16::MAX as u64)?;
    let features = array(take(&mut fields, 8)?, 16)?
        .into_iter()
        .map(feature)
        .collect::<Result<Vec<_>, _>>()?;
    finish(fields)?;
    if major != 1
        || device_certificate.agent_id != agent_id
        || device_certificate.peer_id != peer_id
        || features
            .iter()
            .enumerate()
            .any(|(index, item)| features[..index].contains(item))
    {
        return invalid();
    }
    Ok(WireFrame::Hello(Hello {
        message_id,
        agent_id,
        peer_id,
        device_certificate,
        major,
        minor,
        features,
    }))
}

fn decode_query(mut fields: Fields) -> Result<WireFrame, AslError> {
    check_keys(&fields, &[2, 3, 4, 5, 6, 7, 8, 9, 10])?;
    let message_id = Id128(fixed_bytes::<16>(take(&mut fields, 2)?)?);
    let root_task_id = Id128(fixed_bytes::<16>(take(&mut fields, 3)?)?);
    let created_at_ms = as_u64(take(&mut fields, 4)?)?;
    let expires_at_ms = as_u64(take(&mut fields, 5)?)?;
    let intent_id = intent(take(&mut fields, 6)?)?;
    let topics = concept_refs(take(&mut fields, 7)?, MAX_CONCEPTS)?;
    let constraints = array(take(&mut fields, 8)?, MAX_CONSTRAINTS)?
        .into_iter()
        .map(constraint_value)
        .collect::<Result<Vec<_>, _>>()?;
    let result_shape = result_shape(take(&mut fields, 9)?)?;
    let budget = bounded_uint(take(&mut fields, 10)?, 64)?;
    finish(fields)?;
    if topics.iter().any(|concept| !is_topic(*concept))
        || created_at_ms > MAX_TIME_MS
        || expires_at_ms > MAX_TIME_MS
        || expires_at_ms < created_at_ms
    {
        return invalid();
    }
    Ok(WireFrame::Query(Query {
        message_id,
        root_task_id,
        created_at_ms,
        expires_at_ms,
        intent_id,
        topics,
        constraints,
        result_shape,
        budget,
    }))
}

fn decode_answer(mut fields: Fields) -> Result<WireFrame, AslError> {
    check_keys(&fields, &[2, 3, 4, 5, 6, 7, 8, 9])?;
    let message_id = Id128(fixed_bytes::<16>(take(&mut fields, 2)?)?);
    let root_task_id = Id128(fixed_bytes::<16>(take(&mut fields, 3)?)?);
    let created_at_ms = as_u64(take(&mut fields, 4)?)?;
    let expires_at_ms = as_u64(take(&mut fields, 5)?)?;
    let status = answer_status(take(&mut fields, 6)?)?;
    let claims = array(take(&mut fields, 7)?, MAX_CLAIMS)?
        .into_iter()
        .map(claim)
        .collect::<Result<Vec<_>, _>>()?;
    let evidence_ids = array(take(&mut fields, 8)?, 32)?
        .into_iter()
        .map(|value| fixed_bytes::<16>(value).map(Id128))
        .collect::<Result<Vec<_>, _>>()?;
    let result_status = result_status(take(&mut fields, 9)?)?;
    finish(fields)?;
    if created_at_ms > MAX_TIME_MS
        || expires_at_ms > MAX_TIME_MS
        || expires_at_ms < created_at_ms
        || evidence_ids
            .iter()
            .enumerate()
            .any(|(index, item)| evidence_ids[..index].contains(item))
    {
        return invalid();
    }
    Ok(WireFrame::Answer(Answer {
        message_id,
        root_task_id,
        created_at_ms,
        expires_at_ms,
        status,
        claims,
        evidence_ids,
        result_status,
    }))
}

fn decode_offer(mut fields: Fields) -> Result<WireFrame, AslError> {
    check_keys(&fields, &[2, 3, 4, 5, 6, 7, 8])?;
    let message_id = Id128(fixed_bytes::<16>(take(&mut fields, 2)?)?);
    let root_task_id = Id128(fixed_bytes::<16>(take(&mut fields, 3)?)?);
    let content_id = Hash32(fixed_bytes::<32>(take(&mut fields, 4)?)?);
    let file_size = as_u64(take(&mut fields, 5)?)?;
    let media_kind = media_kind(take(&mut fields, 6)?)?;
    let concepts = concept_refs(take(&mut fields, 7)?, 16)?;
    let expires_at_ms = as_u64(take(&mut fields, 8)?)?;
    finish(fields)?;
    if file_size > MAX_FILE_SIZE
        || expires_at_ms > MAX_TIME_MS
        || concepts.iter().any(|concept| !is_topic(*concept))
    {
        return invalid();
    }
    Ok(WireFrame::Offer(Offer {
        message_id,
        root_task_id,
        content_id,
        file_size,
        media_kind,
        concepts,
        expires_at_ms,
    }))
}

fn decode_fetch_request(mut fields: Fields) -> Result<WireFrame, AslError> {
    check_keys(&fields, &[2, 3, 4])?;
    let message_id = Id128(fixed_bytes::<16>(take(&mut fields, 2)?)?);
    let root_task_id = Id128(fixed_bytes::<16>(take(&mut fields, 3)?)?);
    let content_id = Hash32(fixed_bytes::<32>(take(&mut fields, 4)?)?);
    finish(fields)?;
    Ok(WireFrame::FetchRequest(FetchRequest {
        message_id,
        root_task_id,
        content_id,
    }))
}

fn decode_fetch_grant(mut fields: Fields) -> Result<WireFrame, AslError> {
    check_keys(&fields, &[2, 3, 4, 5, 6])?;
    let message_id = Id128(fixed_bytes::<16>(take(&mut fields, 2)?)?);
    let content_id = Hash32(fixed_bytes::<32>(take(&mut fields, 3)?)?);
    let lease_id = Hash32(fixed_bytes::<32>(take(&mut fields, 4)?)?);
    let expires_at_ms = as_u64(take(&mut fields, 5)?)?;
    let file_size = as_u64(take(&mut fields, 6)?)?;
    finish(fields)?;
    if expires_at_ms > MAX_TIME_MS || file_size > MAX_FILE_SIZE {
        return invalid();
    }
    Ok(WireFrame::FetchGrant(FetchGrant {
        message_id,
        content_id,
        lease_id,
        expires_at_ms,
        file_size,
    }))
}

fn decode_error(mut fields: Fields) -> Result<WireFrame, AslError> {
    check_keys(&fields, &[2, 3])?;
    let message_id = Id128(fixed_bytes::<16>(take(&mut fields, 2)?)?);
    let code = decode_error_code(bounded_uint(take(&mut fields, 3)?, u8::MAX as u64)?)?;
    finish(fields)?;
    Ok(WireFrame::Error(ProtocolError { message_id, code }))
}

fn decode_error_code(value: u8) -> Result<ErrorCode, AslError> {
    match value {
        1 => Ok(ErrorCode::PolicyDenied),
        2 => Ok(ErrorCode::GrantRevoked),
        3 => Ok(ErrorCode::NotFound),
        4 => Ok(ErrorCode::Offline),
        5 => Ok(ErrorCode::Timeout),
        6 => Ok(ErrorCode::Busy),
        7 => Ok(ErrorCode::QuotaExceeded),
        8 => Ok(ErrorCode::IntegrityFailed),
        9 => Ok(ErrorCode::InvalidMessage),
        10 => Ok(ErrorCode::IncompatibleVersion),
        11 => Ok(ErrorCode::ModelInvalid),
        12 => Ok(ErrorCode::ModelUnavailable),
        13 => Ok(ErrorCode::SandboxUnavailable),
        14 => Ok(ErrorCode::DiskFull),
        15 => Ok(ErrorCode::RelayCapacity),
        16 => Ok(ErrorCode::Cancelled),
        17 => Ok(ErrorCode::InternalError),
        _ => invalid(),
    }
}

fn encode_error_code(value: ErrorCode) -> u64 {
    match value {
        ErrorCode::PolicyDenied => 1,
        ErrorCode::GrantRevoked => 2,
        ErrorCode::NotFound => 3,
        ErrorCode::Offline => 4,
        ErrorCode::Timeout => 5,
        ErrorCode::Busy => 6,
        ErrorCode::QuotaExceeded => 7,
        ErrorCode::IntegrityFailed => 8,
        ErrorCode::InvalidMessage => 9,
        ErrorCode::IncompatibleVersion => 10,
        ErrorCode::ModelInvalid => 11,
        ErrorCode::ModelUnavailable => 12,
        ErrorCode::SandboxUnavailable => 13,
        ErrorCode::DiskFull => 14,
        ErrorCode::RelayCapacity => 15,
        ErrorCode::Cancelled => 16,
        ErrorCode::InternalError => 17,
    }
}

fn decode_ack(mut fields: Fields) -> Result<WireFrame, AslError> {
    check_keys(&fields, &[2, 3])?;
    let message_id = Id128(fixed_bytes::<16>(take(&mut fields, 2)?)?);
    let received_id = Id128(fixed_bytes::<16>(take(&mut fields, 3)?)?);
    finish(fields)?;
    Ok(WireFrame::Ack(Ack {
        message_id,
        received_id,
    }))
}

fn decode_profile(mut fields: Fields) -> Result<WireFrame, AslError> {
    check_keys(&fields, &[2, 3, 4, 5])?;
    let agent_id = AgentId(fixed_bytes::<32>(take(&mut fields, 2)?)?);
    let sequence = as_u64(take(&mut fields, 3)?)?;
    let capabilities = concept_refs(take(&mut fields, 4)?, 128)?;
    let avatar = take_optional(&mut fields, 5)
        .map(|value| fixed_bytes::<32>(value).map(Hash32))
        .transpose()?;
    finish(fields)?;
    Ok(WireFrame::Profile(Profile {
        agent_id,
        sequence,
        capabilities,
        avatar,
    }))
}

fn decode_identity_proof_request(mut fields: Fields) -> Result<WireFrame, AslError> {
    check_keys(&fields, &[2, 3, 4])?;
    let request_id = Id128(fixed_bytes::<16>(take(&mut fields, 2)?)?);
    let agent_id = AgentId(fixed_bytes::<32>(take(&mut fields, 3)?)?);
    let checkpoint_hash = Hash32(fixed_bytes::<32>(take(&mut fields, 4)?)?);
    finish(fields)?;
    Ok(WireFrame::IdentityProofRequest(IdentityProofRequest {
        request_id,
        agent_id,
        checkpoint_hash,
    }))
}

fn proof_nodes(value: Value) -> Result<Vec<Vec<u8>>, AslError> {
    array(value, 32)?
        .into_iter()
        .map(|value| byte_string(value, 1, 2_048))
        .collect()
}

fn decode_storage_proof(value: Value) -> Result<StorageProof, AslError> {
    let mut fields = fields(value)?;
    check_keys(&fields, &[0, 1])?;
    let slot = as_u64(take(&mut fields, 0)?)?;
    let nodes = proof_nodes(take(&mut fields, 1)?)?;
    finish(fields)?;
    Ok(StorageProof { slot, nodes })
}

fn decode_identity_proof(mut fields: Fields) -> Result<WireFrame, AslError> {
    check_keys(&fields, &[2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])?;
    let request_id = Id128(fixed_bytes::<16>(take(&mut fields, 2)?)?);
    let agent_id = AgentId(fixed_bytes::<32>(take(&mut fields, 3)?)?);
    let finalized_height = as_u64(take(&mut fields, 4)?)?;
    let block_hash = Hash32(fixed_bytes::<32>(take(&mut fields, 5)?)?);
    let state_root = Hash32(fixed_bytes::<32>(take(&mut fields, 6)?)?);
    let account_proof = proof_nodes(take(&mut fields, 7)?)?;
    let storage_proofs = array(take(&mut fields, 8)?, 8)?
        .into_iter()
        .map(decode_storage_proof)
        .collect::<Result<Vec<_>, _>>()?;
    let controller_address = fixed_bytes::<20>(take(&mut fields, 9)?)?;
    let state_commitment = Hash32(fixed_bytes::<32>(take(&mut fields, 10)?)?);
    let sequence = as_u64(take(&mut fields, 11)?)?;
    let revoked = match bounded_uint::<u8>(take(&mut fields, 12)?, 1)? {
        0 => false,
        1 => true,
        _ => return invalid(),
    };
    finish(fields)?;
    Ok(WireFrame::IdentityProof(IdentityProof {
        request_id,
        agent_id,
        finalized_height,
        block_hash,
        state_root,
        account_proof,
        storage_proofs,
        controller_address,
        state_commitment,
        sequence,
        revoked,
    }))
}

fn decode_pairing_invite(mut fields: Fields) -> Result<WireFrame, AslError> {
    check_keys(&fields, &[2, 3, 4, 5, 6, 7])?;
    let invite_id = Id128(fixed_bytes::<16>(take(&mut fields, 2)?)?);
    let inviter = AgentId(fixed_bytes::<32>(take(&mut fields, 3)?)?);
    let target = AgentId(fixed_bytes::<32>(take(&mut fields, 4)?)?);
    let expires_at_ms = as_u64(take(&mut fields, 5)?)?;
    let token = byte_string(take(&mut fields, 6)?, 16, 256)?;
    let signature = Signature65(fixed_bytes::<65>(take(&mut fields, 7)?)?);
    finish(fields)?;
    if expires_at_ms > MAX_TIME_MS {
        return invalid();
    }
    Ok(WireFrame::PairingInvite(PairingInvite {
        invite_id,
        inviter,
        target,
        expires_at_ms,
        token,
        signature,
    }))
}

fn decode_pairing_exchange(mut fields: Fields) -> Result<WireFrame, AslError> {
    check_keys(&fields, &[2, 3, 4, 5, 6, 7])?;
    let exchange_id = Id128(fixed_bytes::<16>(take(&mut fields, 2)?)?);
    let agent_id = AgentId(fixed_bytes::<32>(take(&mut fields, 3)?)?);
    let peer_id = peer_id(take(&mut fields, 4)?)?;
    let attempt = bounded_uint::<u8>(take(&mut fields, 5)?, 5)?;
    if attempt == 0 {
        return invalid();
    }
    let payload = byte_string(take(&mut fields, 6)?, 1, 4_096)?;
    let transcript_hash = Hash32(fixed_bytes::<32>(take(&mut fields, 7)?)?);
    finish(fields)?;
    Ok(WireFrame::PairingExchange(PairingExchange {
        exchange_id,
        agent_id,
        peer_id,
        attempt,
        payload,
        transcript_hash,
    }))
}

fn decode_group_envelope(mut fields: Fields) -> Result<WireFrame, AslError> {
    check_keys(&fields, &[2, 3, 4, 5, 6])?;
    let message_id = Id128(fixed_bytes::<16>(take(&mut fields, 2)?)?);
    let group_id = Hash32(fixed_bytes::<32>(take(&mut fields, 3)?)?);
    let epoch = as_u64(take(&mut fields, 4)?)?;
    let operation = group_operation(take(&mut fields, 5)?)?;
    let ciphertext = byte_string(take(&mut fields, 6)?, 1, 65_536)?;
    finish(fields)?;
    Ok(WireFrame::GroupEnvelope(GroupEnvelope {
        message_id,
        group_id,
        epoch,
        operation,
        ciphertext,
    }))
}

fn frame_kind(frame: &WireFrame) -> u64 {
    match frame {
        WireFrame::Hello(_) => 0,
        WireFrame::Query(_) => 1,
        WireFrame::Answer(_) => 2,
        WireFrame::Offer(_) => 3,
        WireFrame::FetchRequest(_) => 4,
        WireFrame::FetchGrant(_) => 5,
        WireFrame::Error(_) => 6,
        WireFrame::Ack(_) => 7,
        WireFrame::Profile(_) => 8,
        WireFrame::IdentityProofRequest(_) => 9,
        WireFrame::IdentityProof(_) => 10,
        WireFrame::PairingInvite(_) => 11,
        WireFrame::PairingExchange(_) => 12,
        WireFrame::GroupEnvelope(_) => 13,
    }
}

fn frame_limit(kind: u64) -> usize {
    match kind {
        0..=8 => MAX_CONTROL_FRAME_BYTES,
        9..=10 | 13 => MAX_EXTENDED_FRAME_BYTES,
        11..=12 => MAX_PAIRING_FRAME_BYTES,
        _ => 0,
    }
}

pub fn decode_frame(bytes: &[u8]) -> Result<WireFrame, AslError> {
    let root = decode_canonical(bytes)?;
    let mut fields = fields(root)?;
    check_keys(&fields, &(0..=12).collect::<Vec<_>>())?;
    let version = as_u64(take(&mut fields, 0)?)?;
    if version != 1 {
        return Err(AslError::IncompatibleVersion);
    }
    let kind = bounded_uint::<u8>(take(&mut fields, 1)?, 13)?;
    let frame = match kind {
        0 => decode_hello(fields)?,
        1 => decode_query(fields)?,
        2 => decode_answer(fields)?,
        3 => decode_offer(fields)?,
        4 => decode_fetch_request(fields)?,
        5 => decode_fetch_grant(fields)?,
        6 => decode_error(fields)?,
        7 => decode_ack(fields)?,
        8 => decode_profile(fields)?,
        9 => decode_identity_proof_request(fields)?,
        10 => decode_identity_proof(fields)?,
        11 => decode_pairing_invite(fields)?,
        12 => decode_pairing_exchange(fields)?,
        13 => decode_group_envelope(fields)?,
        _ => return invalid(),
    };
    if bytes.len() > frame_limit(u64::from(kind)) {
        return invalid();
    }
    Ok(frame)
}

fn encode_value(frame: &WireFrame) -> Value {
    let mut entries = vec![(0, uint(1)), (1, uint(frame_kind(frame)))];
    match frame {
        WireFrame::Hello(value) => entries.extend([
            (2, Value::Bytes(value.message_id.0.to_vec())),
            (3, Value::Bytes(value.agent_id.0.to_vec())),
            (4, Value::Bytes(value.peer_id.as_bytes().to_vec())),
            (5, device_certificate_value(&value.device_certificate)),
            (6, uint(u64::from(value.major))),
            (7, uint(u64::from(value.minor))),
            (
                8,
                Value::Array(
                    value
                        .features
                        .iter()
                        .map(|feature| uint(feature_code(*feature)))
                        .collect(),
                ),
            ),
        ]),
        WireFrame::Query(value) => entries.extend([
            (2, Value::Bytes(value.message_id.0.to_vec())),
            (3, Value::Bytes(value.root_task_id.0.to_vec())),
            (4, uint(value.created_at_ms)),
            (5, uint(value.expires_at_ms)),
            (6, uint(intent_code(value.intent_id))),
            (7, concept_refs_value(&value.topics)),
            (
                8,
                Value::Array(
                    value
                        .constraints
                        .iter()
                        .map(constraint_value_value)
                        .collect(),
                ),
            ),
            (9, uint(result_shape_code(value.result_shape))),
            (10, uint(u64::from(value.budget))),
        ]),
        WireFrame::Answer(value) => entries.extend([
            (2, Value::Bytes(value.message_id.0.to_vec())),
            (3, Value::Bytes(value.root_task_id.0.to_vec())),
            (4, uint(value.created_at_ms)),
            (5, uint(value.expires_at_ms)),
            (6, uint(answer_status_code(value.status))),
            (
                7,
                Value::Array(value.claims.iter().map(claim_value).collect()),
            ),
            (
                8,
                Value::Array(
                    value
                        .evidence_ids
                        .iter()
                        .map(|id| Value::Bytes(id.0.to_vec()))
                        .collect(),
                ),
            ),
            (9, uint(result_status_code(value.result_status))),
        ]),
        WireFrame::Offer(value) => entries.extend([
            (2, Value::Bytes(value.message_id.0.to_vec())),
            (3, Value::Bytes(value.root_task_id.0.to_vec())),
            (4, Value::Bytes(value.content_id.0.to_vec())),
            (5, uint(value.file_size)),
            (6, uint(media_kind_code(value.media_kind))),
            (7, concept_refs_value(&value.concepts)),
            (8, uint(value.expires_at_ms)),
        ]),
        WireFrame::FetchRequest(value) => entries.extend([
            (2, Value::Bytes(value.message_id.0.to_vec())),
            (3, Value::Bytes(value.root_task_id.0.to_vec())),
            (4, Value::Bytes(value.content_id.0.to_vec())),
        ]),
        WireFrame::FetchGrant(value) => entries.extend([
            (2, Value::Bytes(value.message_id.0.to_vec())),
            (3, Value::Bytes(value.content_id.0.to_vec())),
            (4, Value::Bytes(value.lease_id.0.to_vec())),
            (5, uint(value.expires_at_ms)),
            (6, uint(value.file_size)),
        ]),
        WireFrame::Error(value) => entries.extend([
            (2, Value::Bytes(value.message_id.0.to_vec())),
            (3, uint(encode_error_code(value.code))),
        ]),
        WireFrame::Ack(value) => entries.extend([
            (2, Value::Bytes(value.message_id.0.to_vec())),
            (3, Value::Bytes(value.received_id.0.to_vec())),
        ]),
        WireFrame::Profile(value) => {
            entries.extend([
                (2, Value::Bytes(value.agent_id.0.to_vec())),
                (3, uint(value.sequence)),
                (4, concept_refs_value(&value.capabilities)),
            ]);
            if let Some(avatar) = value.avatar {
                entries.push((5, Value::Bytes(avatar.0.to_vec())));
            }
        }
        WireFrame::IdentityProofRequest(value) => entries.extend([
            (2, Value::Bytes(value.request_id.0.to_vec())),
            (3, Value::Bytes(value.agent_id.0.to_vec())),
            (4, Value::Bytes(value.checkpoint_hash.0.to_vec())),
        ]),
        WireFrame::IdentityProof(value) => entries.extend([
            (2, Value::Bytes(value.request_id.0.to_vec())),
            (3, Value::Bytes(value.agent_id.0.to_vec())),
            (4, uint(value.finalized_height)),
            (5, Value::Bytes(value.block_hash.0.to_vec())),
            (6, Value::Bytes(value.state_root.0.to_vec())),
            (
                7,
                Value::Array(
                    value
                        .account_proof
                        .iter()
                        .cloned()
                        .map(Value::Bytes)
                        .collect(),
                ),
            ),
            (
                8,
                Value::Array(
                    value
                        .storage_proofs
                        .iter()
                        .map(|proof| {
                            map([
                                (0, uint(proof.slot)),
                                (
                                    1,
                                    Value::Array(
                                        proof.nodes.iter().cloned().map(Value::Bytes).collect(),
                                    ),
                                ),
                            ])
                        })
                        .collect(),
                ),
            ),
            (9, Value::Bytes(value.controller_address.to_vec())),
            (10, Value::Bytes(value.state_commitment.0.to_vec())),
            (11, uint(value.sequence)),
            (12, uint(if value.revoked { 1 } else { 0 })),
        ]),
        WireFrame::PairingInvite(value) => entries.extend([
            (2, Value::Bytes(value.invite_id.0.to_vec())),
            (3, Value::Bytes(value.inviter.0.to_vec())),
            (4, Value::Bytes(value.target.0.to_vec())),
            (5, uint(value.expires_at_ms)),
            (6, Value::Bytes(value.token.clone())),
            (7, Value::Bytes(value.signature.0.to_vec())),
        ]),
        WireFrame::PairingExchange(value) => entries.extend([
            (2, Value::Bytes(value.exchange_id.0.to_vec())),
            (3, Value::Bytes(value.agent_id.0.to_vec())),
            (4, Value::Bytes(value.peer_id.as_bytes().to_vec())),
            (5, uint(u64::from(value.attempt))),
            (6, Value::Bytes(value.payload.clone())),
            (7, Value::Bytes(value.transcript_hash.0.to_vec())),
        ]),
        WireFrame::GroupEnvelope(value) => entries.extend([
            (2, Value::Bytes(value.message_id.0.to_vec())),
            (3, Value::Bytes(value.group_id.0.to_vec())),
            (4, uint(value.epoch)),
            (5, uint(group_operation_code(value.operation))),
            (6, Value::Bytes(value.ciphertext.clone())),
        ]),
    }
    map(entries)
}

pub fn encode_frame(frame: &WireFrame) -> Result<Vec<u8>, AslError> {
    let bytes =
        cbor2::to_canonical_vec(&encode_value(frame)).map_err(|_| AslError::InvalidMessage)?;
    let limit = frame_limit(frame_kind(frame));
    if bytes.len() > limit {
        return invalid();
    }
    decode_frame(&bytes)?;
    Ok(bytes)
}

pub fn decode_control(bytes: &[u8]) -> Result<WireFrame, AslError> {
    if bytes.len() > MAX_CONTROL_FRAME_BYTES {
        return invalid();
    }
    let frame = decode_frame(bytes)?;
    if frame.is_control() {
        Ok(frame)
    } else {
        invalid()
    }
}

pub fn encode_control(frame: &WireFrame) -> Result<Vec<u8>, AslError> {
    if !frame.is_control() {
        return invalid();
    }
    let bytes = encode_frame(frame)?;
    if bytes.len() > MAX_CONTROL_FRAME_BYTES {
        return invalid();
    }
    Ok(bytes)
}
