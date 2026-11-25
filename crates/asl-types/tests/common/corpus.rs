use std::{collections::BTreeSet, error::Error, fs, path::Path};

use asl_types::{
    ids::Signature65,
    protocol::{WireFrame, decode_frame, encode_frame},
    record::{
        DeviceDirectory, RecordPayload, ShortCodeClaim, SignedRecord, UnsignedRecord,
        decode_record, encode_record, short_code,
    },
};
use cbor2::{Value, value::Integer};
use serde::{Deserialize, Serialize};

#[path = "frames.rs"]
pub mod frames;

pub type CorpusResult<T> = Result<T, Box<dyn Error>>;

pub const VECTOR_COUNT: usize = 33;
pub const ACCEPTED_COUNT: usize = 23;
pub const REJECTED_COUNT: usize = 10;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Codec {
    Frame,
    Record,
}

#[derive(Debug)]
pub struct VectorCase {
    pub name: &'static str,
    pub root: &'static str,
    pub codec: Codec,
    pub accepted: bool,
    pub bytes: Vec<u8>,
}

impl VectorCase {
    pub fn check_codec(&self, bytes: &[u8]) -> CorpusResult<()> {
        let reencoded = match self.codec {
            Codec::Frame => decode_frame(bytes).and_then(|value| encode_frame(&value)),
            Codec::Record => decode_record(bytes).and_then(|value| encode_record(&value)),
        };
        match (self.accepted, reencoded) {
            (true, Ok(encoded)) if encoded == bytes => Ok(()),
            (false, Err(_)) => Ok(()),
            (true, Ok(_)) => Err(format!("{} changed bytes after decoding", self.name).into()),
            (true, Err(error)) => Err(format!("{} was rejected: {error:?}", self.name).into()),
            (false, Ok(_)) => Err(format!("{} must be rejected", self.name).into()),
        }
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VectorEntry {
    pub name: String,
    pub root: String,
    pub codec: Codec,
    pub accepted: bool,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VectorIndex {
    pub version: u32,
    pub vectors: Vec<VectorEntry>,
}

pub fn vector_index(cases: &[VectorCase]) -> VectorIndex {
    VectorIndex {
        version: 1,
        vectors: cases
            .iter()
            .map(|case| VectorEntry {
                name: case.name.to_owned(),
                root: case.root.to_owned(),
                codec: case.codec,
                accepted: case.accepted,
            })
            .collect(),
    }
}

pub fn vector_cases() -> Vec<VectorCase> {
    let frames = frames::sample_frames();
    let mut cases: Vec<_> = frames
        .iter()
        .map(|frame| {
            let (name, root) = match frame {
                WireFrame::Hello(_) => ("hello-v1", "hello"),
                WireFrame::Query(_) => ("query-v1", "query"),
                WireFrame::Answer(_) => ("answer-v1", "answer"),
                WireFrame::Offer(_) => ("offer-v1", "offer"),
                WireFrame::FetchRequest(_) => ("fetch-request-v1", "fetch-request"),
                WireFrame::FetchGrant(_) => ("fetch-grant-v1", "fetch-grant"),
                WireFrame::FetchPending(_) => ("fetch-pending-v1", "fetch-pending"),
                WireFrame::Error(_) => ("error-v1", "error"),
                WireFrame::Ack(_) => ("ack-v1", "ack"),
                WireFrame::Profile(_) => ("profile-v1", "profile"),
                WireFrame::IdentityProofRequest(_) => {
                    ("identity-proof-request-v1", "identity-proof-request")
                }
                WireFrame::IdentityProof(_) => ("identity-proof-v1", "identity-proof"),
                WireFrame::PairingInvite(_) => ("pairing-invite-v1", "pairing-invite"),
                WireFrame::PairingExchange(_) => ("pairing-exchange-v1", "pairing-exchange"),
                WireFrame::GroupEnvelope(_) => ("group-envelope-v1", "group-envelope"),
                WireFrame::Expression(_) => ("expression-letter-v1", "expression-letter"),
                WireFrame::ContextRequest(_) => ("context-request-v1", "context-request"),
                WireFrame::ContextOffer(_) => ("context-offer-v1", "context-offer"),
                WireFrame::ContextAgreement(_) => ("context-agreement-v1", "context-agreement"),
                WireFrame::ContextExpression(_) => ("context-expression-v1", "context-expression"),
            };
            VectorCase {
                name,
                root,
                codec: Codec::Frame,
                accepted: true,
                bytes: encode_frame(frame).unwrap(),
            }
        })
        .collect();

    let hello = frames
        .iter()
        .find_map(|frame| match frame {
            WireFrame::Hello(value) => Some(value),
            _ => None,
        })
        .unwrap();
    let profile = frames
        .iter()
        .find_map(|frame| match frame {
            WireFrame::Profile(value) => Some(value),
            _ => None,
        })
        .unwrap();
    let certificate = &hello.device_certificate;
    // All signature bytes are synthetic shape fixtures, never signature evidence.
    for payload in [
        RecordPayload::Profile(profile.clone()),
        RecordPayload::DeviceDirectory(DeviceDirectory {
            agent_id: hello.agent_id,
            registry_sequence: 4,
            devices: vec![certificate.clone()],
            revoked_serials: vec![3, 7],
        }),
        RecordPayload::ShortCode(ShortCodeClaim {
            agent_id: hello.agent_id,
            code: short_code(hello.agent_id),
        }),
    ] {
        let (name, root) = match &payload {
            RecordPayload::Profile(_) => ("signed-profile-record-v1", "signed-profile-record"),
            RecordPayload::DeviceDirectory(_) => (
                "signed-device-directory-record-v1",
                "signed-device-directory-record",
            ),
            RecordPayload::ShortCode(_) => {
                ("signed-short-code-record-v1", "signed-short-code-record")
            }
        };
        cases.push(VectorCase {
            name,
            root,
            codec: Codec::Record,
            accepted: true,
            bytes: encode_record(&SignedRecord {
                record: UnsignedRecord {
                    payload,
                    sequence: profile.sequence,
                    issued_at_ms: certificate.issued_at_ms,
                    expires_at_ms: certificate.expires_at_ms,
                },
                signature: Signature65([0x5a; 65]),
            })
            .unwrap(),
        });
    }

    let ack = cases.iter().find(|case| case.name == "ack-v1").unwrap();
    let Value::Map(fields) = cbor2::from_slice::<Value>(&ack.bytes).unwrap() else {
        panic!("ACK fixture must be a map");
    };
    for (name, key, replacement) in [
        ("ack-unknown-field-v1", 4, Value::Integer(Integer::from(0))),
        ("ack-text-field-v1", 3, Value::Text("free text".to_owned())),
        ("ack-unknown-kind-v1", 1, Value::Integer(Integer::from(255))),
    ] {
        let mut fields = fields.clone();
        let key = Value::Integer(Integer::from(key));
        if let Some((_, value)) = fields.iter_mut().find(|(field, _)| *field == key) {
            *value = replacement;
        } else {
            fields.push((key, replacement));
        }
        cases.push(VectorCase {
            name,
            root: "ack",
            codec: Codec::Frame,
            accepted: false,
            bytes: cbor2::to_canonical_vec(&Value::Map(fields)).unwrap(),
        });
    }

    let expression = cases
        .iter()
        .find(|case| case.name == "expression-letter-v1")
        .unwrap();
    let Value::Map(fields) = cbor2::from_slice::<Value>(&expression.bytes).unwrap() else {
        panic!("expression fixture must be a map");
    };
    let uint = |value: u64| Value::Integer(Integer::from(value));
    for (name, term) in [
        (
            "expression-text-literal-v1",
            Value::Array(vec![uint(0), Value::Text("1".into())]),
        ),
        (
            "expression-wrong-operator-arity-v1",
            Value::Array(vec![uint(3), uint(0), Value::Array(vec![uint(0), uint(1)])]),
        ),
    ] {
        let mut fields = fields.clone();
        let (_, value) = fields.iter_mut().find(|(key, _)| *key == uint(6)).unwrap();
        *value = term;
        cases.push(VectorCase {
            name,
            root: "expression-letter",
            codec: Codec::Frame,
            accepted: false,
            bytes: cbor2::to_canonical_vec(&Value::Map(fields)).unwrap(),
        });
    }
    let invalid_context_fields: [(&str, u64, u64, u64); 5] = [
        ("context-request-zero-expiry-v1", 16, 7, 0),
        ("context-request-zero-revision-v1", 16, 5, 0),
        ("context-offer-oversized-v1", 17, 9, 8_388_609),
        ("context-offer-zero-expiry-v1", 17, 10, 0),
        ("context-agreement-unknown-status-v1", 18, 8, 3),
    ];
    for (name, kind, field, value) in invalid_context_fields {
        let frame = frames
            .iter()
            .find(|frame| frame_kind(frame) == kind)
            .unwrap();
        let mut encoded: Value = cbor2::from_slice(&encode_frame(frame).unwrap()).unwrap();
        let Value::Map(fields) = &mut encoded else {
            panic!("encoded frame must be a map");
        };
        let key = Value::Integer(Integer::from(field));
        let (_, current) = fields.iter_mut().find(|(entry, _)| *entry == key).unwrap();
        *current = Value::Integer(Integer::from(value));
        cases.push(VectorCase {
            name,
            root: match kind {
                16 => "context-request",
                17 => "context-offer",
                18 => "context-agreement",
                _ => unreachable!(),
            },
            codec: Codec::Frame,
            accepted: false,
            bytes: cbor2::to_canonical_vec(&encoded).unwrap(),
        });
    }
    cases
}

fn frame_kind(frame: &WireFrame) -> u64 {
    match frame {
        WireFrame::ContextRequest(_) => 16,
        WireFrame::ContextOffer(_) => 17,
        WireFrame::ContextAgreement(_) => 18,
        _ => 0,
    }
}

pub fn check_case_counts(cases: &[VectorCase]) -> CorpusResult<()> {
    let accepted = cases.iter().filter(|case| case.accepted).count();
    let rejected = cases.len() - accepted;
    let frames = cases
        .iter()
        .filter(|case| case.accepted && case.codec == Codec::Frame)
        .count();
    let records = cases
        .iter()
        .filter(|case| case.accepted && case.codec == Codec::Record)
        .count();
    let unique_names: BTreeSet<_> = cases.iter().map(|case| case.name).collect();
    if cases.len() != VECTOR_COUNT
        || accepted != ACCEPTED_COUNT
        || rejected != REJECTED_COUNT
        || frames != 20
        || records != 3
        || unique_names.len() != cases.len()
    {
        return Err(
            "expected 33 unique vectors: 20 frames + 3 records accepted, 10 rejected".into(),
        );
    }
    Ok(())
}

pub fn parse_hex(text: &str) -> CorpusResult<Vec<u8>> {
    let compact: Vec<_> = text
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if compact.is_empty()
        || !compact.len().is_multiple_of(2)
        || !compact.iter().all(u8::is_ascii_hexdigit)
    {
        return Err("expected nonempty whitespace-separated hex bytes".into());
    }
    compact
        .as_slice()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect()
}

pub fn check_vectors(directory: &Path) -> CorpusResult<()> {
    let cases = vector_cases();
    check_case_counts(&cases)?;
    let actual: VectorIndex = serde_json::from_slice(&fs::read(directory.join("index.json"))?)?;
    if actual != vector_index(&cases) {
        return Err(
            "index.json differs from the typed corpus; run exporter --write explicitly".into(),
        );
    }
    let expected_files: BTreeSet<_> = cases
        .iter()
        .map(|case| format!("{}.hex", case.name))
        .collect();
    let mut actual_files = BTreeSet::new();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.extension().is_some_and(|value| value == "hex") {
            actual_files.insert(path.file_name().unwrap().to_string_lossy().into_owned());
        }
    }
    if actual_files != expected_files {
        return Err("hex file inventory differs from the typed vectors".into());
    }
    for case in &cases {
        let path = directory.join(format!("{}.hex", case.name));
        let bytes = parse_hex(&fs::read_to_string(&path)?)?;
        if bytes != case.bytes {
            return Err(format!("{} differs from its encoded fixture", path.display()).into());
        }
        case.check_codec(&bytes)?;
    }
    Ok(())
}
