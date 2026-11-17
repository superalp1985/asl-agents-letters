use std::collections::BTreeSet;

use cbor2::Value;

use crate::{
    error::AslError,
    ids::{AgentId, Hash32, Signature65},
    protocol::{
        DeviceCertificate, Profile, WireFrame,
        cbor::{
            array, as_u64, byte_string, check_keys, decode_canonical, device_certificate,
            device_certificate_value, fields, finish, fixed_bytes, map, take, uint,
        },
        decode_frame, encode_frame,
    },
};

pub const MAX_RECORD_BYTES: usize = 8_192;
pub const MAX_RECORD_LIFETIME_MS: u64 = 1_800_000;

const MAX_DIRECTORY_ENTRIES: usize = 64;
const SHORT_CODE_MODULUS: u64 = 10_000_000_000_000_000;
const RECORD_DOMAIN: &[u8] = b"ASL-RECORD-v1\0";
const DIRECTORY_DOMAIN: &[u8] = b"ASL-DEVICE-DIRECTORY-v1\0";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RecordKind {
    Profile,
    DeviceDirectory,
    ShortCode,
}

impl RecordKind {
    fn code(self) -> u8 {
        match self {
            Self::Profile => 1,
            Self::DeviceDirectory => 2,
            Self::ShortCode => 3,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceDirectory {
    pub agent_id: AgentId,
    pub registry_sequence: u64,
    pub devices: Vec<DeviceCertificate>,
    pub revoked_serials: Vec<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShortCodeClaim {
    pub agent_id: AgentId,
    pub code: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordPayload {
    Profile(Profile),
    DeviceDirectory(DeviceDirectory),
    ShortCode(ShortCodeClaim),
}

impl RecordPayload {
    pub fn kind(&self) -> RecordKind {
        match self {
            Self::Profile(_) => RecordKind::Profile,
            Self::DeviceDirectory(_) => RecordKind::DeviceDirectory,
            Self::ShortCode(_) => RecordKind::ShortCode,
        }
    }

    pub fn agent_id(&self) -> AgentId {
        match self {
            Self::Profile(value) => value.agent_id,
            Self::DeviceDirectory(value) => value.agent_id,
            Self::ShortCode(value) => value.agent_id,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsignedRecord {
    pub payload: RecordPayload,
    pub sequence: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedRecord {
    pub record: UnsignedRecord,
    pub signature: Signature65,
}

fn validate_directory(value: &DeviceDirectory) -> Result<(), AslError> {
    if value.registry_sequence == 0
        || value.devices.len() > MAX_DIRECTORY_ENTRIES
        || value.revoked_serials.len() > MAX_DIRECTORY_ENTRIES
        || value
            .devices
            .windows(2)
            .any(|pair| pair[0].peer_id.as_bytes() >= pair[1].peer_id.as_bytes())
        || value.revoked_serials.contains(&0)
        || value
            .revoked_serials
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(AslError::InvalidMessage);
    }
    let mut active_serials = BTreeSet::new();
    for device in &value.devices {
        if device.agent_id != value.agent_id
            || !active_serials.insert(device.serial)
            || value.revoked_serials.binary_search(&device.serial).is_ok()
        {
            return Err(AslError::InvalidMessage);
        }
    }
    Ok(())
}

fn canonical_bytes(value: &Value) -> Result<Vec<u8>, AslError> {
    let bytes = cbor2::to_canonical_vec(value).map_err(|_| AslError::InvalidMessage)?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(AslError::InvalidMessage);
    }
    Ok(bytes)
}

fn decode_payload(kind: RecordKind, bytes: &[u8]) -> Result<RecordPayload, AslError> {
    if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
        return Err(AslError::InvalidMessage);
    }
    if kind == RecordKind::Profile {
        return match decode_frame(bytes)? {
            WireFrame::Profile(value) => Ok(RecordPayload::Profile(value)),
            _ => Err(AslError::InvalidMessage),
        };
    }
    let mut fields = fields(decode_canonical(bytes)?)?;
    check_keys(
        &fields,
        match kind {
            RecordKind::DeviceDirectory => &[0, 1, 2, 3, 4],
            _ => &[0, 1, 2],
        },
    )?;
    if as_u64(take(&mut fields, 0)?)? != 1 {
        return Err(AslError::IncompatibleVersion);
    }
    let agent_id = AgentId(fixed_bytes::<32>(take(&mut fields, 1)?)?);
    let payload = match kind {
        RecordKind::DeviceDirectory => {
            let value = DeviceDirectory {
                agent_id,
                registry_sequence: as_u64(take(&mut fields, 2)?)?,
                devices: array(take(&mut fields, 3)?, MAX_DIRECTORY_ENTRIES)?
                    .into_iter()
                    .map(device_certificate)
                    .collect::<Result<_, _>>()?,
                revoked_serials: array(take(&mut fields, 4)?, MAX_DIRECTORY_ENTRIES)?
                    .into_iter()
                    .map(as_u64)
                    .collect::<Result<_, _>>()?,
            };
            validate_directory(&value)?;
            RecordPayload::DeviceDirectory(value)
        }
        RecordKind::ShortCode => {
            let code = as_u64(take(&mut fields, 2)?)?;
            if code >= SHORT_CODE_MODULUS || code != short_code(agent_id) {
                return Err(AslError::InvalidMessage);
            }
            RecordPayload::ShortCode(ShortCodeClaim { agent_id, code })
        }
        RecordKind::Profile => return Err(AslError::InvalidMessage),
    };
    finish(fields)?;
    Ok(payload)
}

pub fn encode_record_payload(payload: &RecordPayload) -> Result<Vec<u8>, AslError> {
    let bytes = match payload {
        RecordPayload::Profile(value) => encode_frame(&WireFrame::Profile(value.clone()))?,
        RecordPayload::DeviceDirectory(value) => {
            validate_directory(value)?;
            canonical_bytes(&map([
                (0, uint(1)),
                (1, Value::Bytes(value.agent_id.0.to_vec())),
                (2, uint(value.registry_sequence)),
                (
                    3,
                    Value::Array(value.devices.iter().map(device_certificate_value).collect()),
                ),
                (
                    4,
                    Value::Array(value.revoked_serials.iter().copied().map(uint).collect()),
                ),
            ]))?
        }
        RecordPayload::ShortCode(value) => canonical_bytes(&map([
            (0, uint(1)),
            (1, Value::Bytes(value.agent_id.0.to_vec())),
            (2, uint(value.code)),
        ]))?,
    };
    decode_payload(payload.kind(), &bytes)?;
    Ok(bytes)
}

fn validate_record(record: &UnsignedRecord) -> Result<(), AslError> {
    if record.issued_at_ms > i64::MAX as u64
        || record.expires_at_ms > i64::MAX as u64
        || record.expires_at_ms <= record.issued_at_ms
        || record.expires_at_ms - record.issued_at_ms > MAX_RECORD_LIFETIME_MS
        || matches!(
            &record.payload,
            RecordPayload::Profile(value) if value.sequence != record.sequence
        )
    {
        return Err(AslError::InvalidMessage);
    }
    Ok(())
}

fn encoded_parts(
    record: &UnsignedRecord,
    signature: Signature65,
) -> Result<(Vec<u8>, Vec<u8>), AslError> {
    validate_record(record)?;
    let payload = encode_record_payload(&record.payload)?;
    let envelope = canonical_bytes(&map([
        (0, uint(1)),
        (1, uint(u64::from(record.payload.kind().code()))),
        (2, Value::Bytes(record.payload.agent_id().0.to_vec())),
        (3, uint(record.sequence)),
        (4, uint(record.issued_at_ms)),
        (5, uint(record.expires_at_ms)),
        (6, Value::Bytes(payload.clone())),
        (7, Value::Bytes(signature.0.to_vec())),
    ]))?;
    Ok((payload, envelope))
}

pub fn record_signing_bytes(record: &UnsignedRecord) -> Result<Vec<u8>, AslError> {
    // Reserve the complete signature field when enforcing the envelope size cap.
    let (payload, _) = encoded_parts(record, Signature65([0; 65]))?;
    let mut bytes = Vec::with_capacity(RECORD_DOMAIN.len() + 61 + payload.len());
    bytes.extend_from_slice(RECORD_DOMAIN);
    bytes.push(record.payload.kind().code());
    bytes.extend_from_slice(record.payload.agent_id().as_bytes());
    bytes.extend_from_slice(&record.sequence.to_be_bytes());
    bytes.extend_from_slice(&record.issued_at_ms.to_be_bytes());
    bytes.extend_from_slice(&record.expires_at_ms.to_be_bytes());
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

pub fn encode_record(record: &SignedRecord) -> Result<Vec<u8>, AslError> {
    encoded_parts(&record.record, record.signature).map(|(_, envelope)| envelope)
}

pub fn decode_record(bytes: &[u8]) -> Result<SignedRecord, AslError> {
    if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
        return Err(AslError::InvalidMessage);
    }
    let mut fields = fields(decode_canonical(bytes)?)?;
    check_keys(&fields, &[0, 1, 2, 3, 4, 5, 6, 7])?;
    if as_u64(take(&mut fields, 0)?)? != 1 {
        return Err(AslError::IncompatibleVersion);
    }
    let kind = match as_u64(take(&mut fields, 1)?)? {
        1 => RecordKind::Profile,
        2 => RecordKind::DeviceDirectory,
        3 => RecordKind::ShortCode,
        _ => return Err(AslError::InvalidMessage),
    };
    let agent_id = AgentId(fixed_bytes::<32>(take(&mut fields, 2)?)?);
    let sequence = as_u64(take(&mut fields, 3)?)?;
    let issued_at_ms = as_u64(take(&mut fields, 4)?)?;
    let expires_at_ms = as_u64(take(&mut fields, 5)?)?;
    let payload = byte_string(take(&mut fields, 6)?, 1, MAX_RECORD_BYTES)?;
    let signature = Signature65(fixed_bytes::<65>(take(&mut fields, 7)?)?);
    finish(fields)?;
    let record = UnsignedRecord {
        payload: decode_payload(kind, &payload)?,
        sequence,
        issued_at_ms,
        expires_at_ms,
    };
    if record.payload.agent_id() != agent_id {
        return Err(AslError::InvalidMessage);
    }
    validate_record(&record)?;
    Ok(SignedRecord { record, signature })
}

pub fn device_directory_commitment(value: &DeviceDirectory) -> Result<Hash32, AslError> {
    let payload = encode_record_payload(&RecordPayload::DeviceDirectory(value.clone()))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(DIRECTORY_DOMAIN);
    hasher.update(&payload);
    Ok(Hash32(*hasher.finalize().as_bytes()))
}

pub fn short_code(agent_id: AgentId) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ASL-HANDLE-ID-v1\0");
    hasher.update(agent_id.as_bytes());
    let hash = hasher.finalize();
    let mut prefix = [0; 8];
    prefix.copy_from_slice(&hash.as_bytes()[..8]);
    u64::from_le_bytes(prefix) % SHORT_CODE_MODULUS
}
