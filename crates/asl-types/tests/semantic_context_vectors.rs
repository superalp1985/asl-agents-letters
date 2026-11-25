use std::{fs, path::PathBuf};

use asl_types::protocol::{Expression, SemanticContextBundle, SignedSemanticContextBundle};
use cbor2::{Value, value::Integer};
use serde::Deserialize;

#[derive(Deserialize)]
struct Index {
    version: u8,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    accepted: bool,
}

fn directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schemas/context-vectors")
}

fn parse_hex(value: &str) -> Vec<u8> {
    let digits: Vec<_> = value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    let (pairs, remainder) = digits.as_chunks::<2>();
    assert!(remainder.is_empty());
    pairs
        .iter()
        .map(|pair| u8::from_str_radix(&pair.iter().collect::<String>(), 16).unwrap())
        .collect()
}

#[test]
fn fixed_context_file_vectors_match_rust_acceptance() {
    let directory = directory();
    let index: Index =
        serde_json::from_slice(&fs::read(directory.join("index.json")).unwrap()).unwrap();
    assert_eq!(index.version, 1);
    assert_eq!(index.vectors.len(), 5);

    for vector in index.vectors {
        let bytes =
            parse_hex(&fs::read_to_string(directory.join(format!("{}.hex", vector.name))).unwrap());
        assert_eq!(
            SignedSemanticContextBundle::decode(&bytes).is_ok(),
            vector.accepted,
            "{}",
            vector.name
        );
    }
}

#[test]
fn accepted_file_matches_the_expected_namespace_and_semantic_vectors() {
    let bytes = parse_hex(&fs::read_to_string(directory().join("context-file-v1.hex")).unwrap());
    let signed = SignedSemanticContextBundle::decode(&bytes).unwrap();
    assert_eq!(signed.bundle.authority.0, [0x11; 32]);
    assert_eq!(signed.bundle.namespace, 4);
    assert_eq!(signed.bundle.revision, 1);
    assert_eq!(signed.bundle.kernel_revision, 1);
    assert_eq!(signed.bundle.dependencies, []);
    assert_eq!(signed.bundle.concepts.len(), 1);
    assert_eq!(signed.bundle.concepts[0].concept_id, 7);
    assert_eq!(signed.bundle.concepts[0].arity, 1);
    assert_eq!(signed.bundle.vectors.len(), 1);
    assert_eq!(signed.bundle.vectors[0].case_id, 1);
    assert_eq!(
        signed.bundle.vectors[0].inputs[0],
        Expression::from_json(&serde_json::json!(["int", "2"])).unwrap()
    );
    assert_eq!(
        signed.bundle.vectors[0].expected,
        Expression::from_json(&serde_json::json!(["bool", true])).unwrap()
    );
    assert_eq!(signed.signature.0, [0; 65]);
}

#[test]
fn cddl_only_framed_file_still_fails_rust_semantic_validation() {
    let bytes = parse_hex(
        &fs::read_to_string(directory().join("context-bundle-unknown-version.hex")).unwrap(),
    );
    let value: Value = cbor2::from_slice(&bytes).unwrap();
    let Value::Map(envelope) = value else {
        panic!("file envelope must be a map");
    };
    let payload = envelope
        .iter()
        .find(|(key, _)| *key == Value::Integer(Integer::from(1)))
        .map(|(_, value)| value)
        .unwrap();
    let payload = cbor2::to_canonical_vec(payload).unwrap();
    assert!(SemanticContextBundle::decode_unsigned(&payload).is_err());
}
