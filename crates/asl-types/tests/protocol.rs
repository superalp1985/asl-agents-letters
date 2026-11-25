use asl_types::{
    error::ErrorCode,
    ids::{Hash32, Id128, PeerId},
    protocol::{
        ContextAgreement, ContextAgreementStatus, ContextExpression, ContextOffer, ContextRequest,
        MediaKind, Offer, ProtocolError, SemanticContextRef, WireFrame, decode_control,
        decode_frame, encode_control, encode_frame,
    },
};
use cbor2::{Value, value::Integer};

#[path = "common/frames.rs"]
mod frames;

use frames::sample_frames;

fn replace_value(bytes: &[u8], key: u64, replacement: Value) -> Vec<u8> {
    let mut value: Value = cbor2::from_slice(bytes).unwrap();
    let Value::Map(entries) = &mut value else {
        panic!("encoded frame must be a map");
    };
    let target = Value::Integer(Integer::from(key));
    let (_, value) = entries
        .iter_mut()
        .find(|(entry_key, _)| *entry_key == target)
        .unwrap();
    *value = replacement;
    cbor2::to_vec(&value).unwrap()
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn every_declared_frame_round_trips_with_deterministic_bytes() {
    for frame in sample_frames() {
        let bytes = encode_frame(&frame).unwrap();
        assert_eq!(encode_frame(&frame).unwrap(), bytes);
        assert_eq!(decode_frame(&bytes).unwrap(), frame);
    }
}

#[test]
fn control_codec_accepts_only_control_frames() {
    let control = sample_frames().remove(0);
    let bytes = encode_control(&control).unwrap();
    assert_eq!(decode_control(&bytes).unwrap(), control);

    let identity_proof = sample_frames()[10].clone();
    assert!(encode_control(&identity_proof).is_err());
    let bytes = encode_frame(&identity_proof).unwrap();
    assert!(decode_control(&bytes).is_err());
}

#[test]
fn identity_proof_v11_carries_verifier_inputs_and_the_signed_device_directory() {
    let byte_string = |byte| Value::Bytes(vec![byte; 32]);
    let nodes = || Value::Array(vec![Value::Bytes(vec![1, 2, 3])]);
    let account = Value::Map(vec![
        (Value::Integer(0.into()), Value::Integer(1.into())),
        (Value::Integer(1.into()), byte_string(2)),
        (Value::Integer(2.into()), byte_string(3)),
        (Value::Integer(3.into()), byte_string(4)),
        (Value::Integer(4.into()), nodes()),
    ]);
    let storage = Value::Array(
        (1..=3)
            .map(|slot| {
                Value::Map(vec![
                    (Value::Integer(0.into()), byte_string(slot)),
                    (Value::Integer(1.into()), byte_string(slot + 3)),
                    (Value::Integer(2.into()), nodes()),
                ])
            })
            .collect(),
    );
    let proof = Value::Map(vec![
        (Value::Integer(0.into()), Value::Integer(1.into())),
        (Value::Integer(1.into()), Value::Integer(10.into())),
        (Value::Integer(2.into()), Value::Bytes(vec![5; 16])),
        (Value::Integer(3.into()), Value::Bytes(vec![6; 32])),
        (Value::Integer(4.into()), Value::Integer(123.into())),
        (Value::Integer(5.into()), byte_string(7)),
        (Value::Integer(6.into()), byte_string(8)),
        (Value::Integer(7.into()), account),
        (Value::Integer(8.into()), storage),
        (Value::Integer(9.into()), Value::Bytes(vec![9; 8_192])),
    ]);
    let encoded = cbor2::to_canonical_vec(&proof).unwrap();
    assert!(matches!(
        decode_frame(&encoded),
        Ok(WireFrame::IdentityProof(_))
    ));
}

#[test]
fn identity_proof_requires_the_revised_envelope_and_three_fixed_width_storage_paths() {
    let proof = encode_frame(&sample_frames()[10]).unwrap();
    let request = encode_frame(&sample_frames()[9]).unwrap();
    for frame in [&proof, &request] {
        assert!(decode_frame(&replace_value(frame, 0, Value::Integer(1.into()))).is_err());
    }
    assert!(decode_frame(&replace_value(&proof, 6, Value::Array(vec![]))).is_err());
    assert!(decode_frame(&replace_value(&proof, 7, Value::Bytes(vec![0; 8_193]))).is_err());
    assert!(decode_frame(&replace_value(&request, 4, Value::Bytes(vec![0; 31]))).is_err());
    let Value::Map(fields) = cbor2::from_slice(&proof).unwrap() else {
        panic!("expected proof map");
    };
    let Value::Array(mut paths) = fields[8].1.clone() else {
        panic!("expected storage paths");
    };
    let Value::Map(first) = &mut paths[0] else {
        panic!("expected a storage proof map");
    };
    first[0].1 = Value::Integer(0.into());
    assert!(decode_frame(&replace_value(&proof, 8, Value::Array(paths))).is_err());
    assert!(decode_frame(&replace_value(&proof, 8, Value::Array(vec![]))).is_err());
    assert!(decode_frame(&replace_value(&proof, 9, Value::Bytes(vec![9; 8_193]))).is_err());
}

#[test]
fn rejects_duplicate_map_keys_at_root_and_nested_levels() {
    let root_duplicate = cbor2::to_vec(&Value::Map(vec![
        (
            Value::Integer(Integer::from(0)),
            Value::Integer(Integer::from(1)),
        ),
        (
            Value::Integer(Integer::from(0)),
            Value::Integer(Integer::from(1)),
        ),
    ]))
    .unwrap();
    assert!(decode_frame(&root_duplicate).is_err());

    let query = sample_frames().remove(1);
    let bytes = encode_frame(&query).unwrap();
    let mut value: Value = cbor2::from_slice(&bytes).unwrap();
    let Value::Map(root) = &mut value else {
        panic!("encoded frame must be a map");
    };
    let (_, constraints) = root
        .iter_mut()
        .find(|(key, _)| *key == Value::Integer(Integer::from(8)))
        .unwrap();
    let Value::Array(constraints) = constraints else {
        panic!("query constraints must be an array");
    };
    let Value::Map(fields) = &mut constraints[0] else {
        panic!("constraint must be a map");
    };
    fields.push((
        Value::Integer(Integer::from(0)),
        Value::Array(vec![
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(100)),
        ]),
    ));
    assert!(decode_frame(&cbor2::to_vec(&value).unwrap()).is_err());
}

#[test]
fn rejects_unknown_fields_text_values_and_unknown_concepts() {
    let query = encode_frame(&sample_frames().remove(1)).unwrap();
    let unknown_field = {
        let mut value: Value = cbor2::from_slice(&query).unwrap();
        let Value::Map(fields) = &mut value else {
            panic!("encoded frame must be a map");
        };
        fields.push((
            Value::Integer(Integer::from(11)),
            Value::Integer(Integer::from(0)),
        ));
        cbor2::to_canonical_vec(&value).unwrap()
    };
    assert!(decode_frame(&unknown_field).is_err());

    let text_value = replace_value(&query, 10, Value::Text(String::from("free text")));
    assert!(decode_frame(&text_value).is_err());

    let unknown_concept = replace_value(
        &query,
        7,
        Value::Array(vec![Value::Array(vec![
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(65_000)),
        ])]),
    );
    assert!(decode_frame(&unknown_concept).is_err());
}

#[test]
fn rejects_noncanonical_indefinite_and_trailing_encodings() {
    let ack = encode_frame(&sample_frames()[7]).unwrap();

    let mut noncanonical_integer = ack.clone();
    noncanonical_integer.splice(2..3, [0x18, 0x01]);
    assert!(decode_frame(&noncanonical_integer).is_err());

    let mut indefinite_map = ack.clone();
    assert_eq!(indefinite_map[0], 0xa4);
    indefinite_map[0] = 0xbf;
    indefinite_map.push(0xff);
    assert!(decode_frame(&indefinite_map).is_err());

    let mut trailing = ack;
    trailing.push(0x00);
    assert!(decode_frame(&trailing).is_err());
}

#[test]
fn rejects_wrong_versions_bounds_and_invalid_peer_ids() {
    let ack = encode_frame(&sample_frames()[7]).unwrap();
    let mut wrong_version = ack;
    wrong_version[2] = 2;
    let decoded = decode_frame(&wrong_version);
    assert!(
        matches!(
            decoded,
            Err(asl_types::error::AslError::IncompatibleVersion)
        ),
        "unexpected version result: {decoded:?}"
    );

    let oversized = WireFrame::Offer(Offer {
        message_id: Id128([1; 16]),
        root_task_id: Id128([2; 16]),
        content_id: Hash32([3; 32]),
        file_size: 68_719_476_737,
        media_kind: MediaKind::Document,
        concepts: vec![],
        expires_at_ms: 200,
    });
    assert!(encode_frame(&oversized).is_err());

    assert!(PeerId::from_bytes(vec![0xff]).is_err());
}

#[test]
fn error_codes_use_fixed_numeric_wire_values() {
    let variants: [(ErrorCode, u8); 17] = [
        (ErrorCode::PolicyDenied, 1),
        (ErrorCode::GrantRevoked, 2),
        (ErrorCode::NotFound, 3),
        (ErrorCode::Offline, 4),
        (ErrorCode::Timeout, 5),
        (ErrorCode::Busy, 6),
        (ErrorCode::QuotaExceeded, 7),
        (ErrorCode::IntegrityFailed, 8),
        (ErrorCode::InvalidMessage, 9),
        (ErrorCode::IncompatibleVersion, 10),
        (ErrorCode::ModelInvalid, 11),
        (ErrorCode::ModelUnavailable, 12),
        (ErrorCode::SandboxUnavailable, 13),
        (ErrorCode::DiskFull, 14),
        (ErrorCode::RelayCapacity, 15),
        (ErrorCode::Cancelled, 16),
        (ErrorCode::InternalError, 17),
    ];
    for (code, wire_value) in variants {
        let frame = WireFrame::Error(ProtocolError {
            message_id: Id128([1; 16]),
            code,
        });
        let bytes = encode_frame(&frame).unwrap();
        assert_eq!(bytes.last(), Some(&wire_value));
        assert_eq!(decode_frame(&bytes).unwrap(), frame);
    }

    let valid = encode_frame(&WireFrame::Error(ProtocolError {
        message_id: Id128([1; 16]),
        code: ErrorCode::NotFound,
    }))
    .unwrap();
    assert!(decode_frame(&replace_value(&valid, 3, Value::Integer(Integer::from(18)))).is_err());
}

#[test]
fn asl12_semantic_context_frames_round_trip_and_bind_exact_references() {
    let authority = asl_types::ids::AgentId([0x31; 32]);
    let reference = SemanticContextRef {
        authority,
        namespace: 17,
        revision: 3,
        digest: Hash32([0x42; 32]),
    };
    let request_id = Id128([0x11; 16]);
    let frames = [
        WireFrame::ContextRequest(ContextRequest {
            message_id: Id128([1; 16]),
            reference,
            expires_at_ms: 200,
        }),
        WireFrame::ContextOffer(ContextOffer {
            message_id: Id128([2; 16]),
            request_id,
            reference,
            content_id: Hash32([0x53; 32]),
            file_size: 4096,
            expires_at_ms: 200,
        }),
        WireFrame::ContextAgreement(ContextAgreement {
            message_id: Id128([3; 16]),
            request_id,
            reference,
            status: ContextAgreementStatus::Conformant,
        }),
        WireFrame::ContextExpression(ContextExpression {
            message_id: Id128([4; 16]),
            root_task_id: Id128([5; 16]),
            created_at_ms: 100,
            expires_at_ms: 200,
            required_contexts: vec![reference],
            expression: asl_types::protocol::Expression::from_json(&serde_json::json!([
                "meaning",
                ["concept", hex_bytes(&authority.0), 17, 3, 9]
            ]))
            .unwrap(),
        }),
    ];
    for frame in frames {
        let encoded = encode_control(&frame).unwrap();
        assert_eq!(decode_control(&encoded).unwrap(), frame);
    }
}

#[test]
fn contextual_expression_rejects_missing_duplicate_and_unreferenced_contexts() {
    let first = SemanticContextRef {
        authority: asl_types::ids::AgentId([0x21; 32]),
        namespace: 1,
        revision: 1,
        digest: Hash32([0x41; 32]),
    };
    let second = SemanticContextRef {
        authority: asl_types::ids::AgentId([0x22; 32]),
        namespace: 2,
        revision: 1,
        digest: Hash32([0x42; 32]),
    };
    let expression = || {
        asl_types::protocol::Expression::from_json(&serde_json::json!([
            "tuple",
            [
                [
                    "meaning",
                    ["concept", hex_bytes(&first.authority.0), 1, 1, 5]
                ],
                [
                    "meaning",
                    ["concept", hex_bytes(&second.authority.0), 2, 1, 6]
                ]
            ]
        ]))
        .unwrap()
    };
    let frame = |required_contexts| {
        WireFrame::ContextExpression(ContextExpression {
            message_id: Id128([7; 16]),
            root_task_id: Id128([8; 16]),
            created_at_ms: 10,
            expires_at_ms: 20,
            required_contexts,
            expression: expression(),
        })
    };
    assert!(encode_frame(&frame(vec![first])).is_err());
    assert!(encode_frame(&frame(vec![first, first, second])).is_err());
    assert!(
        encode_frame(&frame(vec![
            first,
            second,
            SemanticContextRef {
                digest: Hash32([0x43; 32]),
                ..second
            }
        ]))
        .is_err()
    );
    assert!(encode_frame(&frame(vec![second, first])).is_err());
}

#[test]
fn semantic_context_frames_reject_expiry_zero_ids_and_empty_content() {
    let reference = SemanticContextRef {
        authority: asl_types::ids::AgentId([0x31; 32]),
        namespace: 17,
        revision: 3,
        digest: Hash32([0x42; 32]),
    };
    assert!(
        encode_frame(&WireFrame::ContextRequest(ContextRequest {
            message_id: Id128([0; 16]),
            reference,
            expires_at_ms: 200,
        }))
        .is_err()
    );
    assert!(
        encode_frame(&WireFrame::ContextOffer(ContextOffer {
            message_id: Id128([1; 16]),
            request_id: Id128([0; 16]),
            reference,
            content_id: Hash32([0; 32]),
            file_size: 0,
            expires_at_ms: 200,
        }))
        .is_err()
    );
    assert!(
        encode_frame(&WireFrame::ContextAgreement(ContextAgreement {
            message_id: Id128([2; 16]),
            request_id: Id128([3; 16]),
            reference: SemanticContextRef {
                digest: Hash32([0; 32]),
                ..reference
            },
            status: ContextAgreementStatus::Unresolved,
        }))
        .is_err()
    );
}

#[test]
fn rejects_unknown_enumerations_and_out_of_range_pairing_attempts() {
    let query = encode_frame(&sample_frames()[1]).unwrap();
    assert!(decode_frame(&replace_value(&query, 9, Value::Integer(Integer::from(3)))).is_err());

    let mut invalid_operator: Value = cbor2::from_slice(&query).unwrap();
    let Value::Map(root) = &mut invalid_operator else {
        panic!("encoded frame must be a map");
    };
    let (_, constraints) = root
        .iter_mut()
        .find(|(key, _)| *key == Value::Integer(Integer::from(8)))
        .unwrap();
    let Value::Array(constraints) = constraints else {
        panic!("query constraints must be an array");
    };
    let Value::Map(first_constraint) = &mut constraints[0] else {
        panic!("constraint must be a map");
    };
    let (_, operator) = first_constraint
        .iter_mut()
        .find(|(key, _)| *key == Value::Integer(Integer::from(1)))
        .unwrap();
    *operator = Value::Integer(Integer::from(8));
    assert!(decode_frame(&cbor2::to_canonical_vec(&invalid_operator).unwrap()).is_err());

    let answer = encode_frame(&sample_frames()[2]).unwrap();
    assert!(decode_frame(&replace_value(&answer, 6, Value::Integer(Integer::from(4)))).is_err());
    assert!(decode_frame(&replace_value(&answer, 9, Value::Integer(Integer::from(3)))).is_err());

    let offer = encode_frame(&sample_frames()[3]).unwrap();
    assert!(decode_frame(&replace_value(&offer, 6, Value::Integer(Integer::from(7)))).is_err());

    let pairing = encode_frame(&sample_frames()[12]).unwrap();
    assert!(
        decode_frame(&replace_value(
            &pairing,
            5,
            Value::Integer(Integer::from(0))
        ))
        .is_err()
    );

    let group = encode_frame(&sample_frames()[13]).unwrap();
    assert!(decode_frame(&replace_value(&group, 5, Value::Integer(Integer::from(2)))).is_err());
}

#[test]
fn pairing_note_is_one_bounded_line_and_counts_unicode_characters() {
    let mut invite = sample_frames()
        .into_iter()
        .find(|frame| matches!(frame, WireFrame::PairingInvite(_)))
        .unwrap();
    let WireFrame::PairingInvite(invite) = &mut invite else {
        panic!("pairing fixture must be an invite");
    };

    invite.note = "中".repeat(120);
    assert!(encode_frame(&WireFrame::PairingInvite(invite.clone())).is_ok());
    invite.note = "中".repeat(121);
    assert!(encode_frame(&WireFrame::PairingInvite(invite.clone())).is_err());
    invite.note = "First. Second.".into();
    assert!(encode_frame(&WireFrame::PairingInvite(invite.clone())).is_err());
    invite.note = "Line one\u{2028}line two".into();
    assert!(encode_frame(&WireFrame::PairingInvite(invite.clone())).is_err());
}

#[test]
fn acknowledgement_matches_the_fixed_cbor_wire_vector() {
    let frame = sample_frames()[7].clone();
    let encoded = encode_frame(&frame).unwrap();
    let mut expected = vec![0xa4, 0x00, 0x01, 0x01, 0x07, 0x02, 0x50];
    expected.extend([1; 16]);
    expected.extend([0x03, 0x50]);
    expected.extend([8; 16]);
    assert_eq!(encoded, expected);
    assert_eq!(decode_frame(&expected).unwrap(), frame);
}
