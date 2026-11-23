use asl_types::{
    error::AslError,
    ids::Id128,
    protocol::{Expression, ExpressionLetter, WireFrame, decode_control, encode_control},
};
use cbor2::Value as Cbor;
use serde_json::{Value, json};

const AUTHORITY: &str = "abababababababababababababababababababababababababababababababab";

fn letter(json: &Value) -> WireFrame {
    WireFrame::Expression(ExpressionLetter {
        message_id: Id128([1; 16]),
        root_task_id: Id128([2; 16]),
        created_at_ms: 100,
        expires_at_ms: 200,
        expression: Expression::from_json(json).unwrap(),
    })
}

#[test]
fn control_kind_15_matches_the_hand_encoded_integer_letter() {
    let frame = letter(&json!(["int", "-1"]));
    let mut expected = vec![0xa7, 0, 1, 1, 15, 2, 0x50];
    expected.extend([1; 16]);
    expected.extend([3, 0x50]);
    expected.extend([2; 16]);
    expected.extend([4, 0x18, 100, 5, 0x18, 200, 6, 0x82, 0, 0x20]);
    assert!(frame.is_control());
    assert_eq!(encode_control(&frame).unwrap(), expected);
    assert_eq!(decode_control(&expected).unwrap(), frame);
}

#[test]
fn structural_definitions_and_qualified_concepts_round_trip() {
    let concept = json!(["concept", AUTHORITY, 4, 1, 27]);
    let source = json!([
        "let",
        ["decimal", "-9223372036854775808", 18],
        [
            "define",
            2,
            ["op", "sub", ["var", 0], ["var", 1]],
            [
                "tuple",
                [
                    [
                        "request",
                        [
                            "if",
                            ["bool", true],
                            ["apply", concept, [["call", 0, [["var", 0], ["int", "3"]]]]],
                            ["meaning", concept]
                        ]
                    ],
                    [
                        "meaning_is",
                        concept,
                        1,
                        ["op", "gt", ["var", 0], ["int", "0"]]
                    ],
                    ["assert", ["op", "eq", ["int", "7"], ["int", "7"]]]
                ]
            ]
        ]
    ]);
    let frame = letter(&source);
    let WireFrame::Expression(restored) = decode_control(&encode_control(&frame).unwrap()).unwrap()
    else {
        panic!("expected expression");
    };
    assert_eq!(restored.expression.to_json(), source);
}

#[test]
fn rejects_unbound_references_recursion_and_wrong_arity() {
    for invalid in [
        json!(["var", 0]),
        json!(["let", ["var", 0], ["int", "1"]]),
        json!(["call", 0, []]),
        json!(["define", 0, ["call", 0, []], ["int", "1"]]),
        json!(["define", 1, ["var", 0], ["call", 0, []]]),
        json!(["define", 1, ["var", 1], ["int", "1"]]),
        json!([
            "meaning_is",
            ["concept", AUTHORITY, 4, 1, 27],
            0,
            ["var", 0]
        ]),
        json!([
            "define",
            0,
            ["int", "1"],
            [
                "meaning_is",
                ["concept", AUTHORITY, 4, 1, 27],
                0,
                ["call", 0, []]
            ]
        ]),
        json!(["op", "add", ["int", "1"]]),
    ] {
        assert!(
            matches!(
                Expression::from_json(&invalid),
                Err(AslError::InvalidMessage)
            ),
            "{invalid}"
        );
    }
    let nested = json!([
        "let",
        ["int", "3"],
        [
            "define",
            1,
            ["op", "add", ["var", 0], ["var", 1]],
            [
                "define",
                0,
                ["call", 0, [["int", "2"]]],
                ["tuple", [["call", 0, []], ["call", 1, [["int", "4"]]]]]
            ]
        ]
    ]);
    assert_eq!(Expression::from_json(&nested).unwrap().to_json(), nested);
}

#[test]
fn rejects_noncanonical_json_scalars_and_unrecognized_syntax() {
    for invalid in [
        json!("natural language"),
        json!({"int": "1"}),
        json!(["int", 42]),
        json!(["int", "+1"]),
        json!(["int", "-0"]),
        json!(["int", "01"]),
        json!(["int", "9223372036854775808"]),
        json!(["int", "1", "extra"]),
        json!(["decimal", "1", 0]),
        json!(["decimal", "1", 19]),
        json!(["concept", AUTHORITY.to_uppercase(), 4, 1, 27]),
        json!(["meaning", ["int", "1"]]),
        json!(["op", "eval", ["int", "1"]]),
        json!(["unknown"]),
    ] {
        assert!(Expression::from_json(&invalid).is_err(), "{invalid}");
    }
}

#[test]
fn both_boundaries_enforce_depth_node_and_list_limits() {
    let mut deep = json!(["int", "0"]);
    for _ in 0..7 {
        deep = json!(["tuple", [deep]]);
    }
    let valid = encode_control(&letter(&deep)).unwrap();
    assert!(decode_control(&valid).is_ok());
    assert!(Expression::from_json(&json!(["tuple", [deep]])).is_err());

    let full = json!(["tuple", vec![json!(["int", "0"]); 16]]);
    assert!(Expression::from_json(&json!(["tuple", vec![json!(["int", "0"]); 17]])).is_err());
    let mut nodes = vec![full.clone(); 15];
    let bytes = encode_control(&letter(&json!(["tuple", nodes]))).unwrap(); // 1 + 15 * 17 = 256
    assert!(decode_control(&bytes).is_ok());
    nodes.push(json!(["int", "0"]));
    assert!(Expression::from_json(&json!(["tuple", nodes])).is_err()); // exactly 257

    let full = Cbor::Array(vec![integer(11), Cbor::Array(vec![term_int(); 16])]);
    let mut nodes = vec![full; 15];
    nodes.push(term_int());
    assert!(decode_with(6, Cbor::Array(vec![integer(11), Cbor::Array(nodes)])).is_err());
}

#[test]
fn rejects_invalid_cbor_shapes_and_timestamps() {
    for invalid in [
        Cbor::Array(vec![integer(4), integer(0)]), // unbound variable
        Cbor::Array(vec![integer(16)]),            // unknown tag
        Cbor::Array(vec![integer(0), Cbor::Text("1".into())]),
        Cbor::Array(vec![integer(0), Cbor::Bytes(vec![1])]),
        Cbor::Array(vec![integer(0), Cbor::Float(1.0)]),
        Cbor::Array(vec![integer(0), integer(u64::MAX)]),
        Cbor::Array(vec![integer(0), integer(1), integer(1)]),
    ] {
        assert!(decode_with(6, invalid).is_err());
    }
    assert!(decode_with(5, integer(99)).is_err());
    assert!(decode_with(5, integer(u64::MAX)).is_err());
    let WireFrame::Expression(mut frame) = letter(&json!(["int", "0"])) else {
        unreachable!();
    };
    frame.expires_at_ms = 99;
    assert!(encode_control(&WireFrame::Expression(frame)).is_err());
}

fn integer(value: u64) -> Cbor {
    Cbor::Integer(value.into())
}

fn term_int() -> Cbor {
    Cbor::Array(vec![integer(0), integer(0)])
}

fn decode_with(key: usize, replacement: Cbor) -> Result<WireFrame, AslError> {
    let bytes = encode_control(&letter(&json!(["int", "0"]))).unwrap();
    let Cbor::Map(mut fields) = cbor2::from_slice(&bytes).unwrap() else {
        unreachable!();
    };
    assert_eq!(fields[key].0, integer(key as u64));
    fields[key].1 = replacement;
    decode_control(&cbor2::to_canonical_vec(&Cbor::Map(fields)).unwrap())
}
