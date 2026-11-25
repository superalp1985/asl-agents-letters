use asl_types::{
    ids::{AgentId, Hash32, Signature65},
    protocol::{
        Expression, SemanticConceptDefinition, SemanticConformanceVector, SemanticContextBundle,
        SemanticContextRef, SignedSemanticContextBundle,
    },
};
use serde_json::json;

fn expression(value: serde_json::Value) -> Expression {
    Expression::from_json(&value).unwrap()
}

fn definition(authority: AgentId, namespace: u32, revision: u16, concept_id: u32) -> Expression {
    let authority = authority
        .0
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    expression(json!([
        "meaning_is",
        ["concept", authority, namespace, revision, concept_id],
        1,
        ["op", "gt", ["var", 0], ["int", "0"]]
    ]))
}

fn sample_bundle() -> SemanticContextBundle {
    let authority = AgentId([0x11; 32]);
    SemanticContextBundle {
        authority,
        namespace: 4,
        revision: 1,
        kernel_revision: 1,
        dependencies: vec![],
        concepts: vec![SemanticConceptDefinition {
            concept_id: 7,
            arity: 1,
            definition: definition(authority, 4, 1, 7),
        }],
        vectors: vec![SemanticConformanceVector {
            concept_id: 7,
            case_id: 1,
            inputs: vec![expression(json!(["int", "2"]))],
            expected: expression(json!(["bool", true])),
        }],
    }
}

#[test]
fn canonical_context_bundle_round_trips_with_a_stable_content_address() {
    let bundle = sample_bundle();
    let encoded = bundle.encode_unsigned().unwrap();
    let decoded = SemanticContextBundle::decode_unsigned(&encoded).unwrap();

    assert_eq!(decoded, bundle);
    assert_eq!(decoded.encode_unsigned().unwrap(), encoded);
    assert_eq!(
        bundle.context_ref().unwrap().digest,
        Hash32(
            *blake3::hash(&[b"ASL-SEMANTIC-CONTEXT-v1\0".as_slice(), encoded.as_slice()].concat())
                .as_bytes()
        )
    );
}

#[test]
fn a_definition_cannot_claim_another_namespace_or_revision() {
    let mut bundle = sample_bundle();
    bundle.concepts[0].definition = definition(bundle.authority, bundle.namespace + 1, 1, 7);

    assert!(bundle.encode_unsigned().is_err());

    let mut wrong_owner = sample_bundle();
    wrong_owner.concepts[0].definition =
        definition(AgentId([0x44; 32]), wrong_owner.namespace, 1, 7);
    assert!(wrong_owner.encode_unsigned().is_err());
}

#[test]
fn context_packages_reject_duplicate_concepts_and_unordered_dependencies() {
    let mut duplicate = sample_bundle();
    duplicate.concepts.push(duplicate.concepts[0].clone());
    assert!(duplicate.encode_unsigned().is_err());

    let mut unordered = sample_bundle();
    unordered.dependencies = vec![
        SemanticContextRef {
            authority: AgentId([0x22; 32]),
            namespace: 5,
            revision: 2,
            digest: Hash32([0x33; 32]),
        },
        SemanticContextRef {
            authority: AgentId([0x01; 32]),
            namespace: 1,
            revision: 1,
            digest: Hash32([0x02; 32]),
        },
    ];
    assert!(unordered.encode_unsigned().is_err());
}

#[test]
fn context_packages_reject_a_dependency_on_their_own_namespace() {
    let mut bundle = sample_bundle();
    bundle.dependencies.push(SemanticContextRef {
        authority: bundle.authority,
        namespace: bundle.namespace,
        revision: bundle.revision,
        digest: Hash32([0x99; 32]),
    });

    assert!(bundle.encode_unsigned().is_err());
}

#[test]
fn context_package_decoder_rejects_noncanonical_bytes_and_unknown_versions() {
    let encoded = sample_bundle().encode_unsigned().unwrap();
    let mut noncanonical = encoded.clone();
    noncanonical.push(0);
    assert!(SemanticContextBundle::decode_unsigned(&noncanonical).is_err());

    let mut value: cbor2::Value = cbor2::from_slice(&encoded).unwrap();
    let cbor2::Value::Map(fields) = &mut value else {
        panic!("context bundle root is a map");
    };
    fields
        .iter_mut()
        .find(|(key, _)| *key == cbor2::Value::Integer(0.into()))
        .unwrap()
        .1 = cbor2::Value::Integer(2.into());
    let unsupported = cbor2::to_canonical_vec(&value).unwrap();
    assert!(SemanticContextBundle::decode_unsigned(&unsupported).is_err());

    assert_eq!(encoded[0], 0xa8);
    assert_eq!(&encoded[1..3], &[0x00, 0x01]);
    let mut duplicate_key = vec![0xa9];
    duplicate_key.extend_from_slice(&encoded[1..3]);
    duplicate_key.extend_from_slice(&encoded[1..]);
    assert!(SemanticContextBundle::decode_unsigned(&duplicate_key).is_err());
}

#[test]
fn context_packages_reject_vectors_for_unknown_concepts_or_wrong_arities() {
    let mut unknown = sample_bundle();
    unknown.vectors[0].concept_id = 8;
    assert!(unknown.encode_unsigned().is_err());

    let mut wrong_arity = sample_bundle();
    wrong_arity.vectors[0].inputs.clear();
    assert!(wrong_arity.encode_unsigned().is_err());

    let mut without_vectors = sample_bundle();
    without_vectors.vectors.clear();
    assert!(without_vectors.encode_unsigned().is_err());
}

#[test]
fn concept_references_require_an_exact_declared_dependency() {
    let mut bundle = sample_bundle();
    let authority = AgentId([0x22; 32]);
    bundle.concepts[0].definition = expression(json!([
        "meaning_is",
        [
            "concept",
            "1111111111111111111111111111111111111111111111111111111111111111",
            4,
            1,
            7
        ],
        1,
        [
            "apply",
            [
                "concept",
                "2222222222222222222222222222222222222222222222222222222222222222",
                5,
                2,
                9
            ],
            [["var", 0]]
        ]
    ]));
    assert!(bundle.encode_unsigned().is_err());

    bundle.dependencies.push(SemanticContextRef {
        authority,
        namespace: 5,
        revision: 2,
        digest: Hash32([0x33; 32]),
    });
    assert!(bundle.encode_unsigned().is_ok());

    bundle.dependencies.push(SemanticContextRef {
        authority,
        namespace: 5,
        revision: 2,
        digest: Hash32([0x34; 32]),
    });
    assert!(bundle.encode_unsigned().is_err());
}

#[test]
fn signed_context_container_preserves_signature_and_rejects_bad_envelopes() {
    let signed = SignedSemanticContextBundle {
        bundle: sample_bundle(),
        signature: Signature65([0x44; 65]),
    };
    let encoded = signed.encode().unwrap();
    assert_eq!(
        SignedSemanticContextBundle::decode(&encoded).unwrap(),
        signed
    );

    let mut trailing = encoded;
    trailing.push(0);
    assert!(SignedSemanticContextBundle::decode(&trailing).is_err());
}

#[test]
fn signed_context_container_rejects_duplicate_map_keys() {
    let signed = SignedSemanticContextBundle {
        bundle: sample_bundle(),
        signature: Signature65([0x44; 65]),
    };
    let encoded = signed.encode().unwrap();
    assert_eq!(encoded[0], 0xa3);
    assert_eq!(&encoded[1..3], &[0x00, 0x01]);
    let mut duplicate = vec![0xa4];
    duplicate.extend_from_slice(&encoded[1..3]);
    duplicate.extend_from_slice(&encoded[1..]);

    assert!(SignedSemanticContextBundle::decode(&duplicate).is_err());
}

#[test]
fn context_bundle_decoder_rejects_oversized_packages_before_decoding() {
    let bytes = vec![0; asl_types::protocol::MAX_SEMANTIC_CONTEXT_BUNDLE_BYTES + 1];
    assert!(SemanticContextBundle::decode_unsigned(&bytes).is_err());
}
