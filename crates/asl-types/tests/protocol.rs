use asl_types::{
    error::{AslError, ErrorCode},
    ids::{AgentIdText, CandidateId, Hash32, Id128, PeerIdText},
    protocol::{WireBody, parse_wire_at},
    task::TimeMs,
};
use std::str::FromStr;

const NOW_MS: u64 = 1_700_000_000_000;
const PEER_ID: &str = "12D3KooWRNw2pJC9748Fmq4WNV27HoSTcX3r37132FLkQMrbKAiC";
const ID: &str = "00000000000000000000000000000001";
const ROOT_ID: &str = "00000000000000000000000000000002";
const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn envelope(kind: &str, body: &str) -> Vec<u8> {
    format!(
        r#"{{"v":1,"kind":"{kind}","id":"{ID}","root_task_id":"{ROOT_ID}","reply_to":null,"created_at_ms":{},"expires_at_ms":{},"body":{body}}}"#,
        NOW_MS - 1_000,
        NOW_MS + 10_000
    )
    .into_bytes()
}

fn agent_id() -> String {
    let mut public_key = [0; 34];
    public_key[..2].copy_from_slice(&[0xed, 0x01]);
    format!("did:key:z{}", bs58::encode(public_key).into_string())
}

fn valid_hello() -> Vec<u8> {
    let agent_id = agent_id();
    envelope(
        "hello",
        &format!(
            r#"{{"peer_id":"{PEER_ID}","agent_id":"{agent_id}","device_certificate":{{"v":1,"serial":1,"issued_at_ms":{},"expires_at_ms":{},"signature":"{}"}},"major":1,"minor":0,"features":["query","blob"]}}"#,
            NOW_MS - 1_000,
            NOW_MS + 10_000,
            "00".repeat(64)
        ),
    )
}

#[test]
fn parses_valid_query_and_offer() {
    let query = envelope(
        "query",
        r#"{"text":"find Rust notes","terms":["rust","notes"],"round":0}"#,
    );
    assert!(matches!(
        parse_wire_at(&query, NOW_MS).unwrap().body,
        WireBody::Query(_)
    ));

    let offer = envelope(
        "offer",
        &format!(
            r#"{{"offer_id":"{ID}","content_id":"{HASH}","title":"notes","summary":"","tags":["rust"],"file_size":12,"source_peer":"{PEER_ID}","expires_at_ms":{}}}"#,
            NOW_MS + 10_000
        ),
    );
    assert!(matches!(
        parse_wire_at(&offer, NOW_MS).unwrap().body,
        WireBody::Offer(_)
    ));

    let fetch_request = envelope(
        "fetch_request",
        &format!(r#"{{"offer_id":null,"content_id":"{HASH}"}}"#),
    );
    assert!(matches!(
        parse_wire_at(&fetch_request, NOW_MS).unwrap().body,
        WireBody::FetchRequest(_)
    ));

    let fetch_grant = envelope(
        "fetch_grant",
        &format!(
            r#"{{"content_id":"{HASH}","lease_id":"{HASH}","expires_at_ms":{},"file_size":12}}"#,
            NOW_MS + 10_000
        ),
    );
    assert!(matches!(
        parse_wire_at(&fetch_grant, NOW_MS).unwrap().body,
        WireBody::FetchGrant(_)
    ));
}

#[test]
fn parses_hello_but_does_not_claim_certificate_authentication() {
    let parsed = parse_wire_at(&valid_hello(), NOW_MS).unwrap();
    let WireBody::Hello(hello) = parsed.body else {
        panic!("expected hello");
    };
    assert_eq!(hello.peer_id.as_str(), PEER_ID);
    assert_eq!(hello.device_certificate.serial, 1);
}

#[test]
fn rejects_overlong_device_certificates() {
    let valid = String::from_utf8(valid_hello()).unwrap();
    let short_expiry = NOW_MS + 10_000;
    let long_expiry = NOW_MS + 31 * 24 * 60 * 60 * 1_000;
    let overlong = valid.replace(
        &format!("\"expires_at_ms\":{short_expiry}"),
        &format!("\"expires_at_ms\":{long_expiry}"),
    );
    assert!(parse_wire_at(overlong.as_bytes(), NOW_MS).is_err());
}

#[test]
fn rejects_duplicate_fields_at_every_known_level() {
    let duplicate_envelope = br#"{"v":1,"v":1,"kind":"query","id":"00000000000000000000000000000001","root_task_id":"00000000000000000000000000000002","reply_to":null,"created_at_ms":1699999999000,"expires_at_ms":1700000010000,"body":{"text":"x","terms":[],"round":0}}"#;
    assert!(parse_wire_at(duplicate_envelope, NOW_MS).is_err());

    let duplicate_body = envelope("query", r#"{"text":"x","text":"y","terms":[],"round":0}"#);
    assert!(parse_wire_at(&duplicate_body, NOW_MS).is_err());
}

#[test]
fn rejects_unknown_fields_and_excessive_frames() {
    let unknown = envelope(
        "query",
        r#"{"text":"x","terms":[],"round":0,"path":"C:\\secret"}"#,
    );
    assert!(parse_wire_at(&unknown, NOW_MS).is_err());
    assert!(parse_wire_at(&vec![b'x'; 65_537], NOW_MS).is_err());
}

#[test]
fn rejects_excessive_json_nesting() {
    let mut body = String::from(r#"{"text":"x","terms":[],"round":0,"extra":{"#);
    body.push_str(&"[".repeat(140));
    body.push('0');
    body.push_str(&"]".repeat(140));
    body.push_str("}}");
    let nested = envelope("query", &body);
    assert!(parse_wire_at(&nested, NOW_MS).is_err());
}

#[test]
fn rejects_invalid_versions_ids_hashes_and_peers() {
    let mut wrong_version = envelope("query", r#"{"text":"x","terms":[],"round":0}"#);
    let version_pos = wrong_version
        .windows(br#""v":1"#.len())
        .position(|window| window == br#""v":1"#)
        .unwrap();
    wrong_version[version_pos + 4] = b'2';
    assert!(matches!(
        parse_wire_at(&wrong_version, NOW_MS),
        Err(AslError::IncompatibleVersion)
    ));

    assert!(Id128::from_str("z".repeat(32).as_str()).is_err());
    assert!(Hash32::from_str(&"A".repeat(64)).is_err());
    assert!(PeerIdText::from_str("not-a-peer-id").is_err());
    assert!(AgentIdText::from_str("did:key:znot-a-key").is_err());
    assert!(CandidateId::from_str("c_0123456789abcdef").is_ok());
    assert!(CandidateId::from_str("c_0123456789ABCDEf").is_err());

    let bad_peer = envelope(
        "offer",
        &format!(
            r#"{{"offer_id":"{ID}","content_id":"invalid","title":"x","summary":"","tags":[],"file_size":0,"source_peer":"bad","expires_at_ms":{}}}"#,
            NOW_MS + 10_000
        ),
    );
    assert!(parse_wire_at(&bad_peer, NOW_MS).is_err());
}

#[test]
fn rejects_expired_and_inconsistent_timestamps() {
    let expired = format!(
        r#"{{"v":1,"kind":"query","id":"{ID}","root_task_id":"{ROOT_ID}","reply_to":null,"created_at_ms":100,"expires_at_ms":200,"body":{{"text":"x","terms":[],"round":0}}}}"#
    );
    assert!(matches!(
        parse_wire_at(expired.as_bytes(), NOW_MS),
        Err(AslError::ExpiredMessage)
    ));

    let just_expired = format!(
        r#"{{"v":1,"kind":"query","id":"{ID}","root_task_id":"{ROOT_ID}","reply_to":null,"created_at_ms":{},"expires_at_ms":{},"body":{{"text":"x","terms":[],"round":0}}}}"#,
        NOW_MS - 1_000,
        NOW_MS - 1
    );
    assert!(matches!(
        parse_wire_at(just_expired.as_bytes(), NOW_MS),
        Err(AslError::ExpiredMessage)
    ));

    let inconsistent = format!(
        r#"{{"v":1,"kind":"query","id":"{ID}","root_task_id":"{ROOT_ID}","reply_to":null,"created_at_ms":{},"expires_at_ms":{},"body":{{"text":"x","terms":[],"round":0}}}}"#,
        NOW_MS + 1_000,
        NOW_MS
    );
    assert!(parse_wire_at(inconsistent.as_bytes(), NOW_MS).is_err());
}

#[test]
fn error_codes_round_trip_as_wire_strings() {
    let variants = [
        (ErrorCode::PolicyDenied, "\"policy_denied\""),
        (ErrorCode::GrantRevoked, "\"grant_revoked\""),
        (ErrorCode::NotFound, "\"not_found\""),
        (ErrorCode::Offline, "\"offline\""),
        (ErrorCode::Timeout, "\"timeout\""),
        (ErrorCode::Busy, "\"busy\""),
        (ErrorCode::QuotaExceeded, "\"quota_exceeded\""),
        (ErrorCode::IntegrityFailed, "\"integrity_failed\""),
        (ErrorCode::InvalidMessage, "\"invalid_message\""),
        (ErrorCode::IncompatibleVersion, "\"incompatible_version\""),
        (ErrorCode::ModelInvalid, "\"model_invalid\""),
        (ErrorCode::ModelUnavailable, "\"model_unavailable\""),
        (ErrorCode::SandboxUnavailable, "\"sandbox_unavailable\""),
        (ErrorCode::DiskFull, "\"disk_full\""),
        (ErrorCode::RelayCapacity, "\"relay_capacity\""),
        (ErrorCode::Cancelled, "\"cancelled\""),
        (ErrorCode::InternalError, "\"internal_error\""),
    ];
    for (code, json) in variants {
        assert_eq!(serde_json::to_string(&code).unwrap(), json);
        assert_eq!(serde_json::from_str::<ErrorCode>(json).unwrap(), code);
    }
    assert!(serde_json::from_str::<ErrorCode>("\"unknown\"").is_err());
}

#[test]
fn timestamp_type_enforces_protocol_range() {
    let timestamp = TimeMs::try_from(42).unwrap();
    assert_eq!(timestamp.get(), 42);
    assert_eq!(serde_json::to_string(&timestamp).unwrap(), "42");
    assert!(TimeMs::try_from(u64::MAX).is_err());
    assert!(serde_json::from_str::<TimeMs>("9223372036854775808").is_err());
}
