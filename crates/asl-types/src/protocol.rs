use serde::{Deserialize, Deserializer, de::DeserializeOwned};
use serde_json::value::RawValue;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    error::{AslError, ErrorCode},
    ids::{AgentIdText, Hash32, Id128, PeerIdText, Signature64},
};

const MAX_CONTROL_FRAME_BYTES: usize = 65_536;
const MAX_CLOCK_SKEW_MS: u64 = 5 * 60 * 1_000;
const MAX_TIME_MS: u64 = i64::MAX as u64;
const MAX_DEVICE_CERTIFICATE_TTL_MS: u64 = 30 * 24 * 60 * 60 * 1_000;
const MAX_FILE_SIZE: u64 = 68_719_476_736;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum WireKind {
    Hello,
    Query,
    Answer,
    Offer,
    FetchRequest,
    FetchGrant,
    Error,
    Ack,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Feature {
    Query,
    Blob,
    Inline,
    Profile,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    SourceBacked,
    DerivedUnverified,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWireEnvelope {
    v: u16,
    kind: WireKind,
    id: Id128,
    root_task_id: Id128,
    #[serde(deserialize_with = "required_nullable_id")]
    reply_to: Option<Id128>,
    created_at_ms: u64,
    expires_at_ms: u64,
    body: Box<RawValue>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireEnvelope {
    pub v: u16,
    pub kind: WireKind,
    pub id: Id128,
    pub root_task_id: Id128,
    pub reply_to: Option<Id128>,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub body: WireBody,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WireBody {
    Hello(HelloBody),
    Query(QueryBody),
    Answer(AnswerBody),
    Offer(OfferBody),
    FetchRequest(FetchRequestBody),
    FetchGrant(FetchGrantBody),
    Error(ErrorBody),
    Ack(AckBody),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DeviceCertificate {
    pub v: u8,
    pub serial: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub signature: Signature64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HelloBody {
    pub peer_id: PeerIdText,
    pub agent_id: AgentIdText,
    pub device_certificate: DeviceCertificate,
    pub major: u16,
    pub minor: u16,
    pub features: Vec<Feature>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct QueryBody {
    pub text: String,
    pub terms: Vec<String>,
    pub round: u8,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AnswerBody {
    pub text: String,
    pub offer_ids: Vec<Id128>,
    pub evidence_status: EvidenceStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OfferBody {
    pub offer_id: Id128,
    pub content_id: Hash32,
    pub title: String,
    pub summary: String,
    pub tags: Vec<String>,
    pub file_size: u64,
    pub source_peer: PeerIdText,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FetchRequestBody {
    #[serde(deserialize_with = "required_nullable_id")]
    pub offer_id: Option<Id128>,
    pub content_id: Hash32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FetchGrantBody {
    pub content_id: Hash32,
    pub lease_id: Hash32,
    pub expires_at_ms: u64,
    pub file_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ErrorBody {
    pub code: ErrorCode,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AckBody {
    pub received_id: Id128,
}

fn required_nullable_id<'de, D>(deserializer: D) -> Result<Option<Id128>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<Id128>::deserialize(deserializer)
}

fn decode_body<T: DeserializeOwned>(raw: &RawValue) -> Result<T, AslError> {
    serde_json::from_str(raw.get()).map_err(|_| AslError::InvalidMessage)
}

fn has_unique<T: Eq>(items: &[T]) -> bool {
    items
        .iter()
        .enumerate()
        .all(|(index, item)| !items[..index].contains(item))
}

fn valid_len(value: &str, min: usize, max: usize) -> bool {
    let length = value.chars().count();
    (min..=max).contains(&length)
}

fn validate_time(value: u64) -> Result<(), AslError> {
    if value <= MAX_TIME_MS {
        Ok(())
    } else {
        Err(AslError::InvalidMessage)
    }
}

fn validate_hello(body: &HelloBody, now_ms: u64) -> Result<(), AslError> {
    if body.major != 1 {
        return Err(AslError::IncompatibleVersion);
    }
    if body.device_certificate.v != 1
        || body.device_certificate.serial == 0
        || body.device_certificate.expires_at_ms < body.device_certificate.issued_at_ms
        || body
            .device_certificate
            .expires_at_ms
            .saturating_sub(body.device_certificate.issued_at_ms)
            > MAX_DEVICE_CERTIFICATE_TTL_MS
        || !has_unique(&body.features)
        || body.features.len() > 16
    {
        return Err(AslError::InvalidMessage);
    }
    validate_time(body.device_certificate.issued_at_ms)?;
    validate_time(body.device_certificate.expires_at_ms)?;
    if body.device_certificate.issued_at_ms.saturating_sub(now_ms) > MAX_CLOCK_SKEW_MS {
        return Err(AslError::InvalidMessage);
    }
    if body.device_certificate.expires_at_ms < now_ms {
        return Err(AslError::ExpiredMessage);
    }
    Ok(())
}

fn validate_body(body: &WireBody, now_ms: u64) -> Result<(), AslError> {
    match body {
        WireBody::Hello(body) => validate_hello(body, now_ms),
        WireBody::Query(body) => {
            if !valid_len(&body.text, 1, 2_000)
                || body.terms.len() > 5
                || body.terms.iter().any(|term| !valid_len(term, 1, 48))
                || !has_unique(&body.terms)
                || body.round > 2
            {
                return Err(AslError::InvalidMessage);
            }
            Ok(())
        }
        WireBody::Answer(body) => {
            if !valid_len(&body.text, 1, 4_000)
                || body.offer_ids.len() > 8
                || !has_unique(&body.offer_ids)
            {
                return Err(AslError::InvalidMessage);
            }
            Ok(())
        }
        WireBody::Offer(body) => {
            if !valid_len(&body.title, 0, 160)
                || !valid_len(&body.summary, 0, 1_200)
                || body.tags.len() > 8
                || body.tags.iter().any(|tag| !valid_len(tag, 1, 48))
                || !has_unique(&body.tags)
                || body.file_size > MAX_FILE_SIZE
            {
                return Err(AslError::InvalidMessage);
            }
            validate_time(body.expires_at_ms)?;
            if body.expires_at_ms < now_ms {
                return Err(AslError::ExpiredMessage);
            }
            Ok(())
        }
        WireBody::FetchRequest(_) => Ok(()),
        WireBody::FetchGrant(body) => {
            if body.file_size > MAX_FILE_SIZE {
                return Err(AslError::InvalidMessage);
            }
            validate_time(body.expires_at_ms)?;
            if body.expires_at_ms < now_ms {
                return Err(AslError::ExpiredMessage);
            }
            Ok(())
        }
        WireBody::Error(_) | WireBody::Ack(_) => Ok(()),
    }
}

pub fn parse_wire(bytes: &[u8]) -> Result<WireEnvelope, AslError> {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64;
    parse_wire_at(bytes, now_ms)
}

pub fn parse_wire_at(bytes: &[u8], now_ms: u64) -> Result<WireEnvelope, AslError> {
    if bytes.len() > MAX_CONTROL_FRAME_BYTES {
        return Err(AslError::InvalidMessage);
    }
    let raw: RawWireEnvelope =
        serde_json::from_slice(bytes).map_err(|_| AslError::InvalidMessage)?;
    if raw.v != 1 {
        return Err(AslError::IncompatibleVersion);
    }
    validate_time(raw.created_at_ms)?;
    validate_time(raw.expires_at_ms)?;
    if raw.expires_at_ms < raw.created_at_ms {
        return Err(AslError::InvalidMessage);
    }
    if raw.created_at_ms.saturating_sub(now_ms) > MAX_CLOCK_SKEW_MS {
        return Err(AslError::InvalidMessage);
    }
    if raw.expires_at_ms < now_ms {
        return Err(AslError::ExpiredMessage);
    }

    let body = match raw.kind {
        WireKind::Hello => WireBody::Hello(decode_body(&raw.body)?),
        WireKind::Query => WireBody::Query(decode_body(&raw.body)?),
        WireKind::Answer => WireBody::Answer(decode_body(&raw.body)?),
        WireKind::Offer => WireBody::Offer(decode_body(&raw.body)?),
        WireKind::FetchRequest => WireBody::FetchRequest(decode_body(&raw.body)?),
        WireKind::FetchGrant => WireBody::FetchGrant(decode_body(&raw.body)?),
        WireKind::Error => WireBody::Error(decode_body(&raw.body)?),
        WireKind::Ack => WireBody::Ack(decode_body(&raw.body)?),
    };
    validate_body(&body, now_ms)?;

    Ok(WireEnvelope {
        v: raw.v,
        kind: raw.kind,
        id: raw.id,
        root_task_id: raw.root_task_id,
        reply_to: raw.reply_to,
        created_at_ms: raw.created_at_ms,
        expires_at_ms: raw.expires_at_ms,
        body,
    })
}
