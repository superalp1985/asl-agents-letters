use asl_app::{
    identity::AgentIdentity,
    semantic_context::{
        SemanticEvaluation, SemanticValue, check_context_conformance, evaluate_semantic_expression,
    },
    semantic_context::{authenticate_semantic_context, sign_semantic_context},
};
use asl_types::{
    ids::{AgentId, Hash32},
    protocol::{
        Expression, SemanticConceptDefinition, SemanticConformanceVector, SemanticContextBundle,
        SemanticContextRef,
    },
};
use serde_json::json;

fn expression(value: serde_json::Value) -> Expression {
    Expression::from_json(&value).unwrap()
}

fn bundle(authority: AgentId) -> SemanticContextBundle {
    let authority_hex = authority
        .0
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    SemanticContextBundle {
        authority,
        namespace: 4,
        revision: 1,
        kernel_revision: 1,
        dependencies: vec![SemanticContextRef {
            authority: AgentId([0x22; 32]),
            namespace: 5,
            revision: 2,
            digest: Hash32([0x33; 32]),
        }],
        concepts: vec![SemanticConceptDefinition {
            concept_id: 7,
            arity: 1,
            definition: expression(json!([
                "meaning_is",
                ["concept", authority_hex, 4, 1, 7],
                1,
                ["op", "gt", ["var", 0], ["int", "0"]]
            ])),
        }],
        vectors: vec![SemanticConformanceVector {
            concept_id: 7,
            case_id: 1,
            inputs: vec![expression(json!(["int", "2"]))],
            expected: expression(json!(["bool", true])),
        }],
    }
}

fn bundle_with(
    authority: AgentId,
    namespace: u32,
    revision: u16,
    concept_id: u32,
    definition: serde_json::Value,
    dependencies: Vec<SemanticContextRef>,
) -> SemanticContextBundle {
    let term = expression(definition);
    SemanticContextBundle {
        authority,
        namespace,
        revision,
        kernel_revision: 1,
        dependencies,
        concepts: vec![SemanticConceptDefinition {
            concept_id,
            arity: 1,
            definition: term,
        }],
        vectors: vec![SemanticConformanceVector {
            concept_id,
            case_id: 1,
            inputs: vec![expression(json!(["int", "2"]))],
            expected: expression(json!(["bool", true])),
        }],
    }
}

fn ready_context() -> (
    AgentIdentity,
    asl_app::semantic_context::ConformanceReadySemanticContextBundle,
) {
    let identity = AgentIdentity::generate().unwrap();
    let mut bundle = bundle(identity.agent_id());
    bundle.dependencies.clear();
    let signed = sign_semantic_context(&identity, bundle).unwrap();
    let authenticated =
        authenticate_semantic_context(signed, identity.agent_id(), identity.controller_address())
            .unwrap();
    let ready = check_context_conformance(authenticated, Vec::new()).unwrap();
    (identity, ready)
}

#[test]
fn signed_context_authenticates_under_the_expected_active_agent_controller() {
    let identity = AgentIdentity::generate().unwrap();
    let signed = sign_semantic_context(&identity, bundle(identity.agent_id())).unwrap();

    let authenticated =
        authenticate_semantic_context(signed, identity.agent_id(), identity.controller_address())
            .unwrap();

    assert_eq!(authenticated.bundle().authority, identity.agent_id());
    assert_eq!(
        authenticated.context_ref(),
        bundle(identity.agent_id()).context_ref().unwrap()
    );
}

#[test]
fn context_signing_rejects_a_bundle_claiming_another_agent() {
    let identity = AgentIdentity::generate().unwrap();

    assert!(sign_semantic_context(&identity, bundle(AgentId([0x77; 32]))).is_err());
}

#[test]
fn context_authentication_rejects_a_different_controller_or_agent() {
    let identity = AgentIdentity::generate().unwrap();
    let signed = sign_semantic_context(&identity, bundle(identity.agent_id())).unwrap();
    assert!(
        authenticate_semantic_context(signed.clone(), identity.agent_id(), [0x55; 20]).is_err()
    );
    assert!(
        authenticate_semantic_context(signed, AgentId([0x77; 32]), identity.controller_address())
            .is_err()
    );
}

#[test]
fn context_signature_cannot_be_replayed_for_another_revision() {
    let identity = AgentIdentity::generate().unwrap();
    let signed = sign_semantic_context(&identity, bundle(identity.agent_id())).unwrap();
    let mut changed = signed;
    changed.bundle.revision += 1;

    assert!(
        authenticate_semantic_context(changed, identity.agent_id(), identity.controller_address())
            .is_err()
    );
}

#[test]
fn pure_evaluator_matches_the_structured_arithmetic_and_boolean_operators() {
    let (_, context) = ready_context();
    let cases = [
        (
            json!(["op", "add", ["int", "2"], ["int", "3"]]),
            Expected::Number(5, 1),
        ),
        (
            json!(["op", "sub", ["int", "2"], ["int", "3"]]),
            Expected::Number(-1, 1),
        ),
        (
            json!(["op", "mul", ["int", "2"], ["decimal", "25", 1]]),
            Expected::Number(5, 1),
        ),
        (
            json!(["op", "div", ["int", "1"], ["int", "2"]]),
            Expected::Number(1, 2),
        ),
        (json!(["op", "neg", ["int", "2"]]), Expected::Number(-2, 1)),
        (
            json!(["op", "eq", ["int", "1"], ["decimal", "10", 1]]),
            Expected::Boolean(true),
        ),
        (
            json!(["op", "ne", ["int", "1"], ["int", "2"]]),
            Expected::Boolean(true),
        ),
        (
            json!(["op", "lt", ["int", "1"], ["int", "2"]]),
            Expected::Boolean(true),
        ),
        (
            json!(["op", "le", ["int", "2"], ["int", "2"]]),
            Expected::Boolean(true),
        ),
        (
            json!(["op", "gt", ["int", "3"], ["int", "2"]]),
            Expected::Boolean(true),
        ),
        (
            json!(["op", "ge", ["int", "3"], ["int", "3"]]),
            Expected::Boolean(true),
        ),
        (
            json!(["op", "and", ["bool", true], ["bool", false]]),
            Expected::Boolean(false),
        ),
        (
            json!(["op", "or", ["bool", true], ["bool", false]]),
            Expected::Boolean(true),
        ),
        (
            json!(["op", "not", ["bool", false]]),
            Expected::Boolean(true),
        ),
    ];
    for (input, expected) in cases {
        let result =
            evaluate_semantic_expression(&expression(input), std::slice::from_ref(&context));
        match (expected, result) {
            (
                Expected::Number(numerator, denominator),
                SemanticEvaluation::Value(SemanticValue::Number(value)),
            ) => {
                assert_eq!(
                    (value.numerator(), value.denominator()),
                    (numerator, denominator)
                );
            }
            (
                Expected::Boolean(expected),
                SemanticEvaluation::Value(SemanticValue::Boolean(actual)),
            ) => {
                assert_eq!(actual, expected);
            }
            (expected, actual) => panic!("unexpected evaluation: {expected:?}, {actual:?}"),
        }
    }
}

#[derive(Debug)]
enum Expected {
    Number(i128, i128),
    Boolean(bool),
}

#[test]
fn evaluator_captures_let_and_local_definitions_without_executing_them() {
    let (_, context) = ready_context();
    let expression = expression(json!([
        "let",
        ["int", "3"],
        [
            "define",
            1,
            ["op", "add", ["var", 0], ["var", 1]],
            ["call", 0, [["int", "4"]]]
        ]
    ]));

    assert_eq!(
        evaluate_semantic_expression(&expression, std::slice::from_ref(&context)),
        SemanticEvaluation::Value(SemanticValue::Number(
            asl_app::semantic_context::Rational::integer(7)
        ))
    );
}

#[test]
fn unknown_concepts_division_by_zero_and_arithmetic_budget_fail_closed() {
    let (_, context) = ready_context();
    let unknown = expression(json!([
        "apply",
        [
            "concept",
            "9999999999999999999999999999999999999999999999999999999999999999",
            9,
            1,
            77
        ],
        [["int", "1"]]
    ]));
    assert_eq!(
        evaluate_semantic_expression(&unknown, std::slice::from_ref(&context)),
        SemanticEvaluation::Unresolved
    );

    let division = expression(json!(["op", "div", ["int", "1"], ["int", "0"]]));
    assert_eq!(
        evaluate_semantic_expression(&division, std::slice::from_ref(&context)),
        SemanticEvaluation::Invalid
    );

    let overflow = expression(json!([
        "op",
        "mul",
        [
            "op",
            "mul",
            [
                "op",
                "mul",
                ["int", "9223372036854775807"],
                ["int", "9223372036854775807"]
            ],
            ["int", "9223372036854775807"]
        ],
        ["int", "9223372036854775807"]
    ]));
    assert_eq!(
        evaluate_semantic_expression(&overflow, std::slice::from_ref(&context)),
        SemanticEvaluation::Unresolved
    );
}

#[test]
fn recursive_concept_evaluation_stops_at_the_fixed_budget() {
    let identity = AgentIdentity::generate().unwrap();
    let owner = identity.agent_id();
    let recursive = bundle_with(
        owner,
        4,
        1,
        7,
        json!([
            "meaning_is",
            [
                "concept",
                owner
                    .0
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
                4,
                1,
                7
            ],
            1,
            [
                "apply",
                [
                    "concept",
                    owner
                        .0
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>(),
                    4,
                    1,
                    7
                ],
                [["var", 0]]
            ]
        ]),
        Vec::new(),
    );
    let authenticated = authenticate_semantic_context(
        sign_semantic_context(&identity, recursive).unwrap(),
        owner,
        identity.controller_address(),
    )
    .unwrap();

    assert!(check_context_conformance(authenticated, Vec::new()).is_err());
}

#[test]
fn any_failed_conformance_vector_keeps_the_bundle_unverified() {
    let identity = AgentIdentity::generate().unwrap();
    let mut bundle = bundle(identity.agent_id());
    bundle.dependencies.clear();
    bundle.vectors[0].expected = expression(json!(["bool", false]));
    let signed = sign_semantic_context(&identity, bundle).unwrap();
    let authenticated =
        authenticate_semantic_context(signed, identity.agent_id(), identity.controller_address())
            .unwrap();

    assert!(check_context_conformance(authenticated, Vec::new()).is_err());
}

#[test]
fn a_signed_future_kernel_is_not_evaluated_as_version_one() {
    let identity = AgentIdentity::generate().unwrap();
    let mut bundle = bundle(identity.agent_id());
    bundle.dependencies.clear();
    bundle.kernel_revision = 2;
    let signed = sign_semantic_context(&identity, bundle).unwrap();
    let authenticated =
        authenticate_semantic_context(signed, identity.agent_id(), identity.controller_address())
            .unwrap();
    assert!(matches!(
        check_context_conformance(authenticated, Vec::new()),
        Err(asl_types::error::AslError::IncompatibleVersion)
    ));
}

#[test]
fn conformance_uses_the_exact_authenticated_dependency_digest() {
    let dependency_identity = AgentIdentity::generate().unwrap();
    let dependency_authority = dependency_identity.agent_id();
    let dependency_bundle = bundle_with(
        dependency_authority,
        5,
        2,
        9,
        json!([
            "meaning_is",
            [
                "concept",
                dependency_authority
                    .0
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
                5,
                2,
                9
            ],
            1,
            ["op", "gt", ["var", 0], ["int", "0"]]
        ]),
        Vec::new(),
    );
    let dependency_ref = dependency_bundle.context_ref().unwrap();
    let dependency = authenticate_semantic_context(
        sign_semantic_context(&dependency_identity, dependency_bundle).unwrap(),
        dependency_authority,
        dependency_identity.controller_address(),
    )
    .unwrap();

    let parent_identity = AgentIdentity::generate().unwrap();
    let parent_authority = parent_identity.agent_id();
    let parent_bundle = bundle_with(
        parent_authority,
        4,
        1,
        7,
        json!([
            "meaning_is",
            [
                "concept",
                parent_authority
                    .0
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
                4,
                1,
                7
            ],
            1,
            [
                "apply",
                [
                    "concept",
                    dependency_authority
                        .0
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>(),
                    5,
                    2,
                    9
                ],
                [["var", 0]]
            ]
        ]),
        vec![dependency_ref],
    );
    let parent = authenticate_semantic_context(
        sign_semantic_context(&parent_identity, parent_bundle.clone()).unwrap(),
        parent_authority,
        parent_identity.controller_address(),
    )
    .unwrap();
    let parent_ready = check_context_conformance(parent, vec![dependency.clone()]).unwrap();
    let dependency_ready = check_context_conformance(dependency.clone(), Vec::new()).unwrap();
    let result = evaluate_semantic_expression(
        &expression(json!([
            "apply",
            [
                "concept",
                parent_authority
                    .0
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
                4,
                1,
                7
            ],
            [["int", "2"]]
        ])),
        &[parent_ready, dependency_ready],
    );
    assert_eq!(
        result,
        SemanticEvaluation::Value(SemanticValue::Boolean(true))
    );

    let mut wrong_digest = parent_bundle;
    wrong_digest.dependencies[0].digest = Hash32([0x44; 32]);
    let wrong_digest = authenticate_semantic_context(
        sign_semantic_context(&parent_identity, wrong_digest).unwrap(),
        parent_authority,
        parent_identity.controller_address(),
    )
    .unwrap();
    assert!(check_context_conformance(wrong_digest, vec![dependency]).is_err());
}

#[test]
fn unavailable_dependency_digests_cannot_be_marked_conformant() {
    let first = AgentIdentity::generate().unwrap();
    let second = AgentIdentity::generate().unwrap();
    let mut first_bundle = bundle(first.agent_id());
    first_bundle.dependencies = vec![SemanticContextRef {
        authority: second.agent_id(),
        namespace: 4,
        revision: 1,
        digest: Hash32([2; 32]),
    }];
    let mut second_bundle = bundle(second.agent_id());
    second_bundle.dependencies = vec![SemanticContextRef {
        authority: first.agent_id(),
        namespace: 4,
        revision: 1,
        digest: Hash32([1; 32]),
    }];
    let first_bundle = authenticate_semantic_context(
        sign_semantic_context(&first, first_bundle).unwrap(),
        first.agent_id(),
        first.controller_address(),
    )
    .unwrap();
    let second_bundle = authenticate_semantic_context(
        sign_semantic_context(&second, second_bundle).unwrap(),
        second.agent_id(),
        second.controller_address(),
    )
    .unwrap();
    assert!(check_context_conformance(first_bundle, vec![second_bundle]).is_err());
}
