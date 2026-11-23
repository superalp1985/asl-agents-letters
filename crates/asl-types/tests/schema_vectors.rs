use std::{fs, path::PathBuf};

use asl_types::{
    protocol::{WireFrame, decode_frame},
    record::{RecordPayload, decode_record},
};
use cbor2::{Value, value::Integer};

#[path = "common/corpus.rs"]
mod corpus;

use corpus::{check_vectors, parse_hex, vector_cases};

fn vector_directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schemas/vectors")
}

fn fixed_bytes(name: &str) -> Vec<u8> {
    parse_hex(&fs::read_to_string(vector_directory().join(format!("{name}.hex"))).unwrap()).unwrap()
}

#[test]
fn fixed_vectors_and_structured_index_match_the_typed_corpus() {
    check_vectors(&vector_directory()).unwrap();
}

#[test]
fn positive_frames_decode_to_the_existing_shared_fixtures() {
    let cases: Vec<_> = vector_cases()
        .into_iter()
        .filter(|case| case.accepted && case.codec == corpus::Codec::Frame)
        .collect();
    let frames = corpus::frames::sample_frames();
    assert_eq!(cases.len(), frames.len());
    for (case, frame) in cases.iter().zip(frames) {
        assert_eq!(decode_frame(&fixed_bytes(case.name)).unwrap(), frame);
    }
}

#[test]
fn signed_payloads_reuse_the_profile_and_nested_device_certificate() {
    let WireFrame::Profile(profile) = decode_frame(&fixed_bytes("profile-v1")).unwrap() else {
        panic!("expected profile frame");
    };
    let signed_profile = decode_record(&fixed_bytes("signed-profile-record-v1")).unwrap();
    assert_eq!(
        signed_profile.record.payload,
        RecordPayload::Profile(profile),
    );

    let WireFrame::Hello(hello) = decode_frame(&fixed_bytes("hello-v1")).unwrap() else {
        panic!("expected hello frame");
    };
    let signed_directory =
        decode_record(&fixed_bytes("signed-device-directory-record-v1")).unwrap();
    let RecordPayload::DeviceDirectory(directory) = signed_directory.record.payload else {
        panic!("expected device directory payload");
    };
    assert_eq!(directory.agent_id, hello.agent_id);
    let Value::Map(fields) = cbor2::from_slice(&fixed_bytes("hello-v1")).unwrap() else {
        panic!("expected hello map");
    };
    let (_, nested) = fields
        .iter()
        .find(|(key, _)| key == &Value::Integer(5.into()))
        .unwrap();
    assert_eq!(
        hello.device_certificate.to_canonical_cbor().unwrap(),
        cbor2::to_canonical_vec(nested).unwrap()
    );
    assert_eq!(directory.devices, vec![hello.device_certificate]);
}

#[test]
fn schema_negatives_are_canonical_ack_maps_with_one_structural_violation() {
    let baseline: Value = cbor2::from_slice(&fixed_bytes("ack-v1")).unwrap();
    for case in vector_cases()
        .into_iter()
        .filter(|case| !case.accepted && case.root == "ack")
    {
        let bytes = fixed_bytes(case.name);
        let value: Value = cbor2::from_slice(&bytes).unwrap();
        assert_eq!(cbor2::to_canonical_vec(&value).unwrap(), bytes);
        assert!(decode_frame(&bytes).is_err(), "{}", case.name);

        let Value::Map(mut fields) = value else {
            panic!("negative fixture must still be a CBOR map");
        };
        match case.name {
            "ack-unknown-field-v1" => {
                assert_eq!(fields.len(), 5);
                assert_eq!(
                    fields.pop(),
                    Some((
                        Value::Integer(Integer::from(4)),
                        Value::Integer(Integer::from(0)),
                    )),
                );
            }
            "ack-text-field-v1" => {
                assert_eq!(fields.len(), 4);
                assert_eq!(fields[3].1, Value::Text("free text".to_owned()));
                fields[3].1 = Value::Bytes(vec![8; 16]);
            }
            "ack-unknown-kind-v1" => {
                assert_eq!(fields.len(), 4);
                assert_eq!(fields[1].1, Value::Integer(Integer::from(255)));
                fields[1].1 = Value::Integer(Integer::from(7));
            }
            _ => panic!("unexpected schema-negative case: {}", case.name),
        }
        assert_eq!(Value::Map(fields), baseline);
    }
}
