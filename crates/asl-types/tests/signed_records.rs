use asl_types::{
    ids::{AgentId, Hash32, PeerId, Signature65},
    protocol::{ConceptRef, DeviceCertificate, Profile, WireFrame, encode_frame},
    record::{
        DeviceDirectory, MAX_RECORD_BYTES, MAX_RECORD_LIFETIME_MS, RecordKind, RecordPayload,
        ShortCodeClaim, SignedRecord, UnsignedRecord, decode_record, device_directory_commitment,
        encode_record, encode_record_payload, record_signing_bytes, short_code,
    },
};
use cbor2::{Value, value::Integer};

const OWNER: AgentId = AgentId([7; 32]);

fn uint(value: u64) -> Value {
    Value::Integer(Integer::from(value))
}

fn map(entries: impl IntoIterator<Item = (u64, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(key, value)| (uint(key), value))
            .collect(),
    )
}

fn canonical(value: &Value) -> Vec<u8> {
    cbor2::to_canonical_vec(value).unwrap()
}

fn entries(value: &mut Value) -> &mut Vec<(Value, Value)> {
    let Value::Map(entries) = value else {
        panic!("expected map");
    };
    entries
}

fn field(value: &mut Value, key: u64) -> &mut Value {
    &mut entries(value)
        .iter_mut()
        .find(|(entry, _)| *entry == uint(key))
        .unwrap()
        .1
}

fn set(value: &mut Value, key: u64, replacement: Value) {
    *field(value, key) = replacement;
}

fn peer(seed: u8) -> PeerId {
    let mut bytes = vec![0x12, 0x20];
    bytes.extend([seed; 32]);
    PeerId::from_bytes(bytes).unwrap()
}

fn certificate(seed: u8) -> DeviceCertificate {
    DeviceCertificate {
        agent_id: OWNER,
        peer_id: peer(seed),
        serial: u64::from(seed),
        issued_at_ms: 100,
        expires_at_ms: 200,
        signature: Signature65([0x5a; 65]),
    }
}

fn directory() -> DeviceDirectory {
    DeviceDirectory {
        agent_id: OWNER,
        registry_sequence: 4,
        devices: vec![certificate(1), certificate(2)],
        revoked_serials: vec![3, 7],
    }
}

fn samples() -> Vec<(u8, RecordPayload)> {
    vec![
        (
            1,
            RecordPayload::Profile(Profile {
                agent_id: OWNER,
                sequence: 9,
                capabilities: vec![
                    ConceptRef {
                        vocabulary_id: 1,
                        concept_id: 1,
                    },
                    ConceptRef {
                        vocabulary_id: 1,
                        concept_id: 100,
                    },
                ],
                avatar: Some(Hash32([9; 32])),
            }),
        ),
        (2, RecordPayload::DeviceDirectory(directory())),
        (
            3,
            RecordPayload::ShortCode(ShortCodeClaim {
                agent_id: OWNER,
                code: short_code(OWNER),
            }),
        ),
    ]
}

fn signed(payload: RecordPayload) -> SignedRecord {
    SignedRecord {
        record: UnsignedRecord {
            payload,
            sequence: 9,
            issued_at_ms: 100,
            expires_at_ms: 200,
        },
        signature: Signature65([0x5a; 65]),
    }
}

fn certificate_value(value: &DeviceCertificate) -> Value {
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

fn payload_value(payload: &RecordPayload) -> Value {
    match payload {
        RecordPayload::Profile(value) => {
            cbor2::from_slice(&encode_frame(&WireFrame::Profile(value.clone())).unwrap()).unwrap()
        }
        RecordPayload::DeviceDirectory(value) => map([
            (0, uint(1)),
            (1, Value::Bytes(value.agent_id.0.to_vec())),
            (2, uint(value.registry_sequence)),
            (
                3,
                Value::Array(value.devices.iter().map(certificate_value).collect()),
            ),
            (
                4,
                Value::Array(value.revoked_serials.iter().copied().map(uint).collect()),
            ),
        ]),
        RecordPayload::ShortCode(value) => map([
            (0, uint(1)),
            (1, Value::Bytes(value.agent_id.0.to_vec())),
            (2, uint(value.code)),
        ]),
    }
}

fn envelope(record: &SignedRecord, kind: u8, payload: Vec<u8>) -> Value {
    map([
        (0, uint(1)),
        (1, uint(u64::from(kind))),
        (2, Value::Bytes(record.record.payload.agent_id().0.to_vec())),
        (3, uint(record.record.sequence)),
        (4, uint(record.record.issued_at_ms)),
        (5, uint(record.record.expires_at_ms)),
        (6, Value::Bytes(payload)),
        (7, Value::Bytes(record.signature.0.to_vec())),
    ])
}

fn raw_record(kind: u8, payload: RecordPayload) -> Vec<u8> {
    let bytes = canonical(&payload_value(&payload));
    canonical(&envelope(&signed(payload), kind, bytes))
}

fn mutated_payload(kind: u8, payload: &RecordPayload, change: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut value = payload_value(payload);
    change(&mut value);
    canonical(&envelope(
        &signed(payload.clone()),
        kind,
        cbor2::to_vec(&value).unwrap(),
    ))
}

fn reject_directory(value: DeviceDirectory) {
    let payload = RecordPayload::DeviceDirectory(value.clone());
    assert!(encode_record_payload(&payload).is_err(), "{value:?}");
    assert!(
        encode_record(&signed(payload.clone())).is_err(),
        "{value:?}"
    );
    assert!(
        record_signing_bytes(&signed(payload.clone()).record).is_err(),
        "{value:?}"
    );
    assert!(device_directory_commitment(&value).is_err(), "{value:?}");
    assert!(decode_record(&raw_record(2, payload)).is_err(), "{value:?}");
}

#[test]
fn every_kind_round_trips_with_exact_canonical_envelope_and_structured_payload() {
    for ((kind, payload), expected_kind) in samples().into_iter().zip([
        RecordKind::Profile,
        RecordKind::DeviceDirectory,
        RecordKind::ShortCode,
    ]) {
        assert_eq!(payload.kind(), expected_kind);
        assert_eq!(payload.agent_id(), OWNER);
        let expected_payload = canonical(&payload_value(&payload));
        assert_eq!(encode_record_payload(&payload).unwrap(), expected_payload);
        let record = signed(payload);
        let bytes = encode_record(&record).unwrap();
        assert_eq!(bytes, canonical(&envelope(&record, kind, expected_payload)));
        assert_eq!(encode_record(&record).unwrap(), bytes);
        assert_eq!(decode_record(&bytes).unwrap(), record);
    }
}

#[test]
fn fixed_profile_preimage_matches_frozen_domain_endianness_and_existing_frame() {
    let record = signed(samples().remove(0).1).record;
    let mut fixed_payload = vec![0xa6, 0x00, 0x01, 0x01, 0x08, 0x02, 0x58, 0x20];
    fixed_payload.extend([7; 32]);
    fixed_payload.extend([
        0x03, 0x09, 0x04, 0x82, 0x82, 0x01, 0x01, 0x82, 0x01, 0x18, 0x64, 0x05, 0x58, 0x20,
    ]);
    fixed_payload.extend([9; 32]);
    assert_eq!(fixed_payload.len(), 86);

    let mut expected = b"ASL-RECORD-v1\0\x01".to_vec();
    expected.extend([7; 32]);
    expected.extend([0, 0, 0, 0, 0, 0, 0, 9]);
    expected.extend([0, 0, 0, 0, 0, 0, 0, 100]);
    expected.extend([0, 0, 0, 0, 0, 0, 0, 200]);
    expected.extend([0, 0, 0, 86]);
    expected.extend(&fixed_payload);
    assert_eq!(
        encode_record_payload(&record.payload).unwrap(),
        fixed_payload
    );
    assert_eq!(record_signing_bytes(&record).unwrap(), expected);
}

#[test]
fn directory_and_short_code_preimages_bind_their_numeric_kind_and_payload_length() {
    for (kind, payload) in samples().into_iter().skip(1) {
        let payload_bytes = canonical(&payload_value(&payload));
        let record = signed(payload).record;
        let mut expected = b"ASL-RECORD-v1\0".to_vec();
        expected.push(kind);
        expected.extend([7; 32]);
        expected.extend([0, 0, 0, 0, 0, 0, 0, 9]);
        expected.extend([0, 0, 0, 0, 0, 0, 0, 100]);
        expected.extend([0, 0, 0, 0, 0, 0, 0, 200]);
        expected.extend((payload_bytes.len() as u32).to_be_bytes());
        expected.extend(payload_bytes);
        assert_eq!(record_signing_bytes(&record).unwrap(), expected);
    }
}

#[test]
fn short_code_uses_the_fixed_domain_little_endian_and_modulus() {
    for agent in [AgentId([0; 32]), OWNER, AgentId([255; 32])] {
        let mut input = b"ASL-HANDLE-ID-v1\0".to_vec();
        input.extend(agent.0);
        let digest = blake3::hash(&input);
        let prefix: [u8; 8] = digest.as_bytes()[..8].try_into().unwrap();
        let expected = u64::from_le_bytes(prefix) % 10_000_000_000_000_000;
        assert_eq!(short_code(agent), expected);
        assert_ne!(
            expected,
            u64::from_be_bytes(prefix) % 10_000_000_000_000_000
        );
    }
}

#[test]
fn directory_commitment_binds_exact_payload_and_registry_sequence_only() {
    let value = directory();
    let payload = RecordPayload::DeviceDirectory(value.clone());
    let bytes = encode_record_payload(&payload).unwrap();
    let mut input = b"ASL-DEVICE-DIRECTORY-v1\0".to_vec();
    input.extend(&bytes);
    let expected = Hash32(*blake3::hash(&input).as_bytes());
    assert_eq!(device_directory_commitment(&value).unwrap(), expected);
    assert_ne!(expected, Hash32(*blake3::hash(&bytes).as_bytes()));

    let first = signed(payload);
    let mut renewed = first.clone();
    renewed.record.sequence = 10;
    renewed.record.issued_at_ms = 201;
    renewed.record.expires_at_ms = 300;
    assert!(encode_record(&renewed).is_ok());
    assert_eq!(
        encode_record_payload(&first.record.payload).unwrap(),
        encode_record_payload(&renewed.record.payload).unwrap()
    );
    assert_ne!(
        record_signing_bytes(&first.record).unwrap(),
        record_signing_bytes(&renewed.record).unwrap()
    );
    let mut changed = value.clone();
    changed.registry_sequence += 1;
    assert_ne!(device_directory_commitment(&changed).unwrap(), expected);
    changed = value.clone();
    changed.revoked_serials.push(8);
    assert_ne!(device_directory_commitment(&changed).unwrap(), expected);
    changed = value;
    changed.devices[0].signature.0[0] ^= 1;
    assert_ne!(device_directory_commitment(&changed).unwrap(), expected);
}

#[test]
fn zero_and_maximum_outer_sequences_are_allowed_with_independent_registry_sequence() {
    for (_, payload) in samples() {
        for sequence in [0, u64::MAX] {
            let mut record = signed(payload.clone());
            record.record.sequence = sequence;
            if let RecordPayload::Profile(profile) = &mut record.record.payload {
                profile.sequence = sequence;
            }
            let bytes = encode_record(&record).unwrap();
            assert_eq!(decode_record(&bytes).unwrap(), record);
        }
    }
    for registry_sequence in [1, u64::MAX] {
        let mut value = directory();
        value.registry_sequence = registry_sequence;
        let mut record = signed(RecordPayload::DeviceDirectory(value));
        record.record.sequence = 0;
        assert_eq!(
            decode_record(&encode_record(&record).unwrap()).unwrap(),
            record
        );
    }
}

#[test]
fn rejects_unknown_duplicate_and_missing_envelope_fields() {
    let record = signed(samples().remove(0).1);
    let root: Value = cbor2::from_slice(&encode_record(&record).unwrap()).unwrap();
    let mut unknown = root.clone();
    entries(&mut unknown).push((uint(8), uint(0)));
    assert!(decode_record(&canonical(&unknown)).is_err());
    for key in 0..=7 {
        let mut duplicate = root.clone();
        let value = field(&mut duplicate, key).clone();
        entries(&mut duplicate).push((uint(key), value));
        assert!(
            decode_record(&cbor2::to_vec(&duplicate).unwrap()).is_err(),
            "duplicate {key}"
        );
        let mut missing = root.clone();
        entries(&mut missing).retain(|(entry, _)| *entry != uint(key));
        assert!(
            decode_record(&canonical(&missing)).is_err(),
            "missing {key}"
        );
    }
}

#[test]
fn rejects_unknown_duplicate_and_missing_payload_fields_for_every_kind() {
    for (kind, payload) in samples() {
        let unknown = mutated_payload(kind, &payload, |value| {
            entries(value).push((uint(99), uint(0)));
        });
        assert!(decode_record(&unknown).is_err());
        let keys = match kind {
            1 => 0..=4,
            2 => 0..=4,
            _ => 0..=2,
        };
        for key in keys {
            let duplicate = mutated_payload(kind, &payload, |value| {
                let item = field(value, key).clone();
                entries(value).push((uint(key), item));
            });
            assert!(
                decode_record(&duplicate).is_err(),
                "kind {kind} duplicate {key}"
            );
            let missing = mutated_payload(kind, &payload, |value| {
                entries(value).retain(|(entry, _)| *entry != uint(key));
            });
            assert!(
                decode_record(&missing).is_err(),
                "kind {kind} missing {key}"
            );
        }
    }
}

#[test]
fn rejects_raw_payload_text_cbor_text_and_arbitrary_blobs_for_every_kind() {
    for (kind, payload) in samples() {
        let record = signed(payload);
        for bytes in [
            b"raw payload prose".to_vec(),
            canonical(&Value::Text("payload prose".into())),
            vec![0xde, 0xad, 0xbe, 0xef],
            canonical(&Value::Bytes(b"wrapped prose".to_vec())),
            vec![],
        ] {
            assert!(decode_record(&canonical(&envelope(&record, kind, bytes))).is_err());
        }
        let mut root = envelope(&record, kind, vec![1]);
        set(&mut root, 6, Value::Text("unwrapped prose".into()));
        assert!(decode_record(&canonical(&root)).is_err());
    }
}

#[test]
fn rejects_text_keys_and_text_inside_envelopes_payloads_and_certificates() {
    for (kind, payload) in samples() {
        let record = signed(payload.clone());
        for key in 0..=7 {
            let mut root = envelope(&record, kind, canonical(&payload_value(&payload)));
            set(&mut root, key, Value::Text("text".into()));
            assert!(decode_record(&canonical(&root)).is_err(), "outer key {key}");
        }
        let mut root = envelope(&record, kind, canonical(&payload_value(&payload)));
        entries(&mut root)[0].0 = Value::Text("version".into());
        assert!(decode_record(&canonical(&root)).is_err());
        let keys = match kind {
            1 => 0..=5,
            2 => 0..=4,
            _ => 0..=2,
        };
        for key in keys {
            assert!(
                decode_record(&mutated_payload(kind, &payload, |value| {
                    set(value, key, Value::Text("nested text".into()));
                }))
                .is_err(),
                "kind {kind} key {key}"
            );
        }
        assert!(
            decode_record(&mutated_payload(kind, &payload, |value| {
                entries(value)[0].0 = Value::Text("version".into());
            }))
            .is_err()
        );
    }
    let payload = RecordPayload::DeviceDirectory(directory());
    for key in 0..=6 {
        assert!(
            decode_record(&mutated_payload(2, &payload, |value| {
                let Value::Array(devices) = field(value, 3) else {
                    panic!("devices");
                };
                set(&mut devices[0], key, Value::Text("certificate text".into()));
            }))
            .is_err()
        );
    }
}

fn malformed_encodings(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut nonpreferred = bytes.to_vec();
    assert_eq!(nonpreferred[2], 1);
    nonpreferred.splice(2..3, [0x18, 0x01]);
    let mut indefinite = bytes.to_vec();
    indefinite[0] = 0xbf;
    indefinite.push(0xff);
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    let mut reordered: Value = cbor2::from_slice(bytes).unwrap();
    entries(&mut reordered).swap(0, 1);
    let mut deep = vec![0x81; 20];
    deep.push(0);
    let mut tagged = vec![0xc0];
    tagged.extend(bytes);
    vec![
        nonpreferred,
        indefinite,
        trailing,
        cbor2::to_vec(&reordered).unwrap(),
        bytes[..bytes.len() - 1].to_vec(),
        deep,
        tagged,
    ]
}

#[test]
fn rejects_noncanonical_indefinite_trailing_truncated_tagged_and_deep_data_at_both_layers() {
    for (kind, payload) in samples() {
        let record = signed(payload.clone());
        let bytes = encode_record(&record).unwrap();
        for malformed in malformed_encodings(&bytes) {
            assert!(decode_record(&malformed).is_err());
        }
        for malformed in malformed_encodings(&canonical(&payload_value(&payload))) {
            assert!(decode_record(&canonical(&envelope(&record, kind, malformed))).is_err());
        }
        assert!(
            decode_record(&mutated_payload(kind, &payload, |value| {
                let mut deep = uint(0);
                for _ in 0..20 {
                    deep = Value::Array(vec![deep]);
                }
                set(value, if kind == 1 { 4 } else { 2 }, deep);
            }))
            .is_err()
        );
    }
    assert!(decode_record(&[]).is_err());
}

#[test]
fn rejects_wrong_versions_unknown_kinds_wrong_schema_and_wrong_scalar_shapes() {
    for (kind, payload) in samples() {
        let record = signed(payload.clone());
        let root = envelope(&record, kind, canonical(&payload_value(&payload)));
        for version in [0, 2, u64::MAX] {
            let mut wrong = root.clone();
            set(&mut wrong, 0, uint(version));
            assert!(decode_record(&canonical(&wrong)).is_err());
            assert!(
                decode_record(&mutated_payload(kind, &payload, |value| {
                    set(value, 0, uint(version));
                }))
                .is_err()
            );
        }
        for bad_kind in [0, 4, 255, u64::MAX] {
            let mut wrong = root.clone();
            set(&mut wrong, 1, uint(bad_kind));
            assert!(decode_record(&canonical(&wrong)).is_err());
        }
        for (other_kind, other_payload) in samples() {
            if other_kind != kind {
                assert!(
                    decode_record(&canonical(&envelope(
                        &record,
                        kind,
                        canonical(&payload_value(&other_payload))
                    )))
                    .is_err()
                );
            }
        }
        for key in [1, 3, 4, 5] {
            for wrong_type in [
                Value::Bool(false),
                Value::Null,
                Value::Float(1.0),
                Value::Integer(Integer::from(-1)),
            ] {
                let mut wrong = root.clone();
                set(&mut wrong, key, wrong_type);
                assert!(decode_record(&canonical(&wrong)).is_err());
            }
        }
        for length in [0, 31, 33] {
            let mut wrong = root.clone();
            set(&mut wrong, 2, Value::Bytes(vec![7; length]));
            assert!(decode_record(&canonical(&wrong)).is_err());
        }
        for length in [0, 64, 66] {
            let mut wrong = root.clone();
            set(&mut wrong, 7, Value::Bytes(vec![0; length]));
            assert!(decode_record(&canonical(&wrong)).is_err());
        }
    }
}

#[test]
fn rejects_owner_mismatches_for_every_kind_and_profile_sequence_mismatches() {
    for (kind, payload) in samples() {
        let record = signed(payload.clone());
        let mut root = envelope(&record, kind, canonical(&payload_value(&payload)));
        set(&mut root, 2, Value::Bytes(vec![8; 32]));
        assert!(decode_record(&canonical(&root)).is_err());
    }
    let profile = samples().remove(0).1;
    let mut record = signed(profile.clone());
    record.record.sequence += 1;
    assert!(encode_record(&record).is_err());
    assert!(record_signing_bytes(&record.record).is_err());
    let mut root = envelope(&record, 1, canonical(&payload_value(&profile)));
    assert!(decode_record(&canonical(&root)).is_err());
    set(&mut root, 3, uint(9));
    assert!(decode_record(&canonical(&root)).is_ok());
    assert!(
        decode_record(&mutated_payload(1, &profile, |value| {
            set(value, 3, uint(10));
        }))
        .is_err()
    );
    let mut wrong = directory();
    wrong.devices[0].agent_id = AgentId([8; 32]);
    reject_directory(wrong);
}

#[test]
fn record_time_bounds_reject_zero_negative_overlong_and_overflow_lifetimes() {
    assert_eq!(MAX_RECORD_LIFETIME_MS, 1_800_000);
    for (kind, payload) in samples() {
        for (issued, expires) in [
            (0, 0),
            (100, 100),
            (200, 100),
            (0, MAX_RECORD_LIFETIME_MS + 1),
            (i64::MAX as u64, i64::MAX as u64 + 1),
            (u64::MAX - 1, u64::MAX),
            (u64::MAX, 0),
        ] {
            let mut record = signed(payload.clone());
            record.record.issued_at_ms = issued;
            record.record.expires_at_ms = expires;
            assert!(encode_record(&record).is_err());
            assert!(record_signing_bytes(&record.record).is_err());
            assert!(
                decode_record(&canonical(&envelope(
                    &record,
                    kind,
                    canonical(&payload_value(&payload))
                )))
                .is_err()
            );
        }
        for (issued, expires) in [
            (0, 1),
            (100, 100 + MAX_RECORD_LIFETIME_MS),
            (i64::MAX as u64 - MAX_RECORD_LIFETIME_MS, i64::MAX as u64),
        ] {
            let mut record = signed(payload.clone());
            record.record.issued_at_ms = issued;
            record.record.expires_at_ms = expires;
            assert_eq!(
                decode_record(&encode_record(&record).unwrap()).unwrap(),
                record
            );
        }
    }
}

#[test]
fn signature_bytes_are_structural_and_codec_does_not_verify_crypto_or_wall_clock() {
    let mut record = signed(samples().remove(0).1);
    let preimage = record_signing_bytes(&record.record).unwrap();
    for signature in [Signature65([0; 65]), Signature65([255; 65])] {
        record.signature = signature;
        assert_eq!(record_signing_bytes(&record.record).unwrap(), preimage);
        assert_eq!(
            decode_record(&encode_record(&record).unwrap()).unwrap(),
            record
        );
    }
}

#[test]
fn directory_requires_raw_peer_order_and_unique_peer_ids_and_serials() {
    let valid = directory();
    assert!(valid.devices[0].peer_id.as_bytes() < valid.devices[1].peer_id.as_bytes());
    let mut wrong = valid.clone();
    wrong.devices.reverse();
    reject_directory(wrong);
    let mut wrong = valid.clone();
    wrong.devices[1].peer_id = wrong.devices[0].peer_id.clone();
    reject_directory(wrong);
    let mut wrong = valid;
    wrong.devices[1].serial = wrong.devices[0].serial;
    reject_directory(wrong);
}

#[test]
fn directory_requires_nonzero_registry_sequence_and_bounded_cert_and_revocation_arrays() {
    let mut wrong = directory();
    wrong.registry_sequence = 0;
    reject_directory(wrong);
    let mut wrong = directory();
    wrong.devices = (1..=65).map(certificate).collect();
    wrong.revoked_serials.clear();
    reject_directory(wrong);
    let mut wrong = directory();
    wrong.revoked_serials = (100..165).collect();
    reject_directory(wrong);
    let payload = RecordPayload::DeviceDirectory(directory());
    for key in [3, 4] {
        assert!(
            decode_record(&mutated_payload(2, &payload, |value| {
                set(value, key, Value::Array(vec![Value::Null; 65]));
            }))
            .is_err()
        );
    }
}

#[test]
fn revocations_require_sorted_unique_nonzero_serials_disjoint_from_active_devices() {
    for revoked_serials in [vec![0], vec![3, 3], vec![7, 3], vec![1], vec![2, 3]] {
        let mut wrong = directory();
        wrong.revoked_serials = revoked_serials;
        reject_directory(wrong);
    }
    for (devices, revoked_serials) in [
        (vec![], vec![]),
        (vec![], vec![1, 2, u64::MAX]),
        (vec![certificate(1)], (2..66).collect()),
    ] {
        let record = signed(RecordPayload::DeviceDirectory(DeviceDirectory {
            agent_id: OWNER,
            registry_sequence: 1,
            devices,
            revoked_serials,
        }));
        assert_eq!(
            decode_record(&encode_record(&record).unwrap()).unwrap(),
            record
        );
    }
}

#[test]
fn revocations_and_devices_reject_non_array_and_non_uint_shapes() {
    let payload = RecordPayload::DeviceDirectory(directory());
    for key in [3, 4] {
        for wrong in [
            Value::Null,
            uint(1),
            Value::Bytes(vec![1]),
            map([(0, uint(1))]),
        ] {
            assert!(
                decode_record(&mutated_payload(2, &payload, |value| {
                    set(value, key, wrong);
                }))
                .is_err()
            );
        }
    }
    for wrong in [
        Value::Null,
        Value::Bool(true),
        Value::Integer(Integer::from(-1)),
        Value::Bytes(vec![1]),
        Value::Array(vec![uint(1)]),
    ] {
        assert!(
            decode_record(&mutated_payload(2, &payload, |value| {
                set(value, 4, Value::Array(vec![wrong]));
            }))
            .is_err()
        );
    }
}

#[test]
fn device_certificates_reuse_existing_version_peer_serial_time_and_signature_rules() {
    let payload = RecordPayload::DeviceDirectory(directory());
    for (key, replacement) in [
        (0, uint(2)),
        (1, Value::Bytes(vec![7; 31])),
        (2, Value::Bytes(vec![0xff])),
        (3, uint(0)),
        (4, uint(201)),
        (4, uint(i64::MAX as u64 + 1)),
        (5, uint(100 + 30 * 24 * 60 * 60 * 1000 + 1)),
        (5, uint(i64::MAX as u64 + 1)),
        (6, Value::Bytes(vec![0; 64])),
    ] {
        assert!(
            decode_record(&mutated_payload(2, &payload, |value| {
                let Value::Array(devices) = field(value, 3) else {
                    panic!("devices");
                };
                set(&mut devices[0], key, replacement);
            }))
            .is_err(),
            "certificate key {key}"
        );
    }
    for bad in [0, 1, 2] {
        assert!(
            decode_record(&mutated_payload(2, &payload, |value| {
                let Value::Array(devices) = field(value, 3) else {
                    panic!("devices");
                };
                match bad {
                    0 => entries(&mut devices[0]).push((uint(7), uint(0))),
                    1 => entries(&mut devices[0]).push((uint(0), uint(1))),
                    _ => entries(&mut devices[0]).retain(|(key, _)| *key != uint(3)),
                }
            }))
            .is_err()
        );
    }
    let mut wrong = directory();
    wrong.devices[0].serial = 0;
    reject_directory(wrong);
    let mut wrong = directory();
    wrong.devices[0].expires_at_ms = 100 + 30 * 24 * 60 * 60 * 1000 + 1;
    reject_directory(wrong);
    let mut valid = directory();
    valid.devices[0].expires_at_ms = 100 + 30 * 24 * 60 * 60 * 1000;
    valid.devices[1].expires_at_ms = valid.devices[1].issued_at_ms;
    let record = signed(RecordPayload::DeviceDirectory(valid));
    assert_eq!(
        decode_record(&encode_record(&record).unwrap()).unwrap(),
        record
    );
}

#[test]
fn short_code_claims_reject_wrong_derivation_out_of_range_and_wrong_shapes() {
    let payload = samples().remove(2).1;
    for code in [
        (short_code(OWNER) + 1) % 10_000_000_000_000_000,
        10_000_000_000_000_000,
        u64::MAX,
    ] {
        let wrong = RecordPayload::ShortCode(ShortCodeClaim {
            agent_id: OWNER,
            code,
        });
        assert!(encode_record_payload(&wrong).is_err());
        assert!(encode_record(&signed(wrong.clone())).is_err());
        assert!(record_signing_bytes(&signed(wrong.clone()).record).is_err());
        assert!(decode_record(&raw_record(3, wrong)).is_err());
    }
    for wrong in [
        Value::Bool(true),
        Value::Null,
        Value::Bytes(vec![0; 8]),
        Value::Integer(Integer::from(-1)),
    ] {
        assert!(
            decode_record(&mutated_payload(3, &payload, |value| {
                set(value, 2, wrong);
            }))
            .is_err()
        );
    }
}

#[test]
fn profile_payload_keeps_existing_concept_and_avatar_validation() {
    let payload = samples().remove(0).1;
    for wrong in [
        Value::Array(vec![Value::Array(vec![uint(1), uint(65_000)])]),
        Value::Array(vec![Value::Array(vec![uint(2), uint(1)])]),
        Value::Array(vec![Value::Array(vec![uint(1), uint(1)]); 2]),
        Value::Array(vec![Value::Array(vec![uint(1), uint(1)]); 129]),
    ] {
        assert!(
            decode_record(&mutated_payload(1, &payload, |value| {
                set(value, 4, wrong);
            }))
            .is_err()
        );
    }
    assert!(
        decode_record(&mutated_payload(1, &payload, |value| {
            set(value, 5, Value::Bytes(vec![0; 31]));
        }))
        .is_err()
    );
    let mut profile = match payload {
        RecordPayload::Profile(value) => value,
        _ => unreachable!(),
    };
    profile.avatar = None;
    let record = signed(RecordPayload::Profile(profile.clone()));
    assert_eq!(
        decode_record(&encode_record(&record).unwrap()).unwrap(),
        record
    );
    profile.capabilities.push(profile.capabilities[0]);
    assert!(encode_record_payload(&RecordPayload::Profile(profile)).is_err());
}

#[test]
fn total_envelope_limit_accepts_exactly_8192_and_rejects_8193_before_signing() {
    assert_eq!(MAX_RECORD_BYTES, 8192);
    let mut value = directory();
    value.devices = (1..=53).map(certificate).collect();
    value.revoked_serials.clear();
    for device in &mut value.devices[..6] {
        device.issued_at_ms = 0;
    }
    let payload = RecordPayload::DeviceDirectory(value.clone());
    let record = signed(payload.clone());
    let bytes = encode_record(&record).unwrap();
    assert_eq!(bytes.len(), MAX_RECORD_BYTES);
    assert_eq!(decode_record(&bytes).unwrap(), record);
    assert!(record_signing_bytes(&record.record).is_ok());

    value.devices[0].issued_at_ms = 24;
    let payload = RecordPayload::DeviceDirectory(value);
    assert!(encode_record_payload(&payload).unwrap().len() < MAX_RECORD_BYTES);
    let raw = raw_record(2, payload.clone());
    assert_eq!(raw.len(), MAX_RECORD_BYTES + 1);
    assert!(decode_record(&raw).is_err());
    assert!(encode_record(&signed(payload.clone())).is_err());
    assert!(record_signing_bytes(&signed(payload).record).is_err());
}

#[test]
fn total_size_cap_still_applies_below_64_certificates_and_to_huge_raw_input() {
    let mut value = directory();
    value.devices = (1..=54).map(certificate).collect();
    value.revoked_serials.clear();
    assert!(value.devices.len() < 64);
    reject_directory(value);
    assert!(decode_record(&vec![0; MAX_RECORD_BYTES + 1]).is_err());
    let record = signed(samples().remove(2).1);
    assert!(
        decode_record(&canonical(&envelope(
            &record,
            3,
            vec![0; MAX_RECORD_BYTES + 1]
        )))
        .is_err()
    );
}
