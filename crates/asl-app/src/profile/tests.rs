use std::collections::HashSet;

use alloy_primitives::U256;
use asl_policy::{
    AccessOperation, AccessRequest, Audience, GrantPolicy, ModelPolicy, Permit, PolicyEngine,
    PolicyRevision, PolicyService, PolicySnapshot, ResourceOrigin, ResourcePolicy,
};
use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId, Signature65},
    protocol::{ConceptRef, DeviceCertificate, Profile},
    record::{
        DeviceDirectory, RecordKind, RecordPayload, ShortCodeClaim, SignedRecord, UnsignedRecord,
        decode_record, device_directory_commitment, encode_record, encode_record_payload,
        record_signing_bytes, short_code,
    },
    task::{GrantId, GroupId, ResourceKey, TaskId},
};
use cbor2::{Value, value::Integer};
use k256::ecdsa::Signature;

use crate::{
    chain::{
        EthereumProofVerifier, IdentityProofVerifier, IdentityResolution, IdentityResolver,
        LimitedReason, VerifiedIdentity,
        test_support::{BOOTSTRAP_TIME, proof_fixture_for_agent},
    },
    identity::{AgentIdentity, DeviceIdentity, verify_root_signature},
};

use super::{
    AvatarReference, ProfileConfiguration, ProfilePublisher, RecordHistory, sign_record,
    verify_record,
};

const NOW: u64 = BOOTSTRAP_TIME * 1_000 + 123;
const RENEWAL: u64 = 300_000;
const LIFETIME: u64 = 1_800_000;
const AVATAR: Hash32 = Hash32([71; 32]);

struct FixtureResolver {
    version: u16,
    resolution: IdentityResolution,
    valid_until_secs: Option<u64>,
    requests: Vec<(AgentId, u64)>,
}

impl FixtureResolver {
    fn verified(identity: VerifiedIdentity) -> Self {
        Self {
            version: 1,
            resolution: IdentityResolution::Verified(Box::new(identity)),
            valid_until_secs: None,
            requests: Vec::new(),
        }
    }

    fn limited(reason: LimitedReason) -> Self {
        Self {
            version: 1,
            resolution: IdentityResolution::Limited(reason),
            valid_until_secs: None,
            requests: Vec::new(),
        }
    }
}

impl IdentityResolver for FixtureResolver {
    fn interface_version(&self) -> u16 {
        self.version
    }

    fn resolve(&mut self, agent: AgentId, now_secs: u64) -> IdentityResolution {
        self.requests.push((agent, now_secs));
        if self.valid_until_secs.is_some_and(|until| now_secs >= until) {
            IdentityResolution::Limited(LimitedReason::StaleProof)
        } else {
            self.resolution.clone()
        }
    }
}

// Synthetic MPT evidence only: no RPC, user keys, or live chain state is used.
fn proved_identity(
    agent: AgentId,
    controller: [u8; 20],
    sequence: u64,
    commitment: [u8; 32],
    status: u8,
) -> VerifiedIdentity {
    let mut values = [[0; 32]; 3];
    values[0][12..].copy_from_slice(&controller);
    values[1] = commitment;
    values[2][23] = status;
    values[2][24..].copy_from_slice(&sequence.to_be_bytes());
    let (deployment, finalized, proof) = proof_fixture_for_agent(values, 8, agent);
    EthereumProofVerifier::new(deployment)
        .unwrap()
        .verify(&finalized, agent, &proof)
        .unwrap()
}

fn active(root: &AgentIdentity) -> FixtureResolver {
    FixtureResolver::verified(proved_identity(
        root.agent_id(),
        root.controller_address(),
        7,
        [42; 32],
        1,
    ))
}

fn directory_resolver(root: &AgentIdentity, directory: &DeviceDirectory) -> FixtureResolver {
    FixtureResolver::verified(proved_identity(
        directory.agent_id,
        root.controller_address(),
        directory.registry_sequence,
        device_directory_commitment(directory).unwrap().0,
        1,
    ))
}

fn rejected_resolvers(root: &AgentIdentity) -> Vec<(&'static str, FixtureResolver)> {
    let other = AgentIdentity::generate().unwrap();
    let mut old_version = active(root);
    old_version.version = 0;
    let mut new_version = active(root);
    new_version.version = 2;
    let mut cases = vec![
        ("old interface", old_version),
        ("unknown interface", new_version),
        ("other agent", active(&other)),
        (
            "other controller",
            FixtureResolver::verified(proved_identity(
                root.agent_id(),
                other.controller_address(),
                8,
                [42; 32],
                1,
            )),
        ),
        (
            "revoked state",
            FixtureResolver::verified(proved_identity(
                root.agent_id(),
                root.controller_address(),
                8,
                [42; 32],
                2,
            )),
        ),
        (
            "unregistered state",
            FixtureResolver::verified(proved_identity(root.agent_id(), [0; 20], 0, [0; 32], 0)),
        ),
    ];
    for (label, reason) in [
        ("unknown", LimitedReason::Unknown),
        ("stale", LimitedReason::StaleProof),
        ("unavailable", LimitedReason::ChainUnavailable),
        ("unregistered", LimitedReason::Unregistered),
        ("revoked", LimitedReason::Revoked),
    ] {
        cases.push((label, FixtureResolver::limited(reason)));
    }
    cases
}

fn capabilities() -> Vec<ConceptRef> {
    vec![
        ConceptRef {
            vocabulary_id: 1,
            concept_id: 1,
        },
        ConceptRef {
            vocabulary_id: 1,
            concept_id: 100,
        },
    ]
}

fn profile(agent: AgentId, sequence: u64) -> RecordPayload {
    RecordPayload::Profile(Profile {
        agent_id: agent,
        sequence,
        capabilities: capabilities(),
        avatar: None,
    })
}

fn signed_profile(root: &AgentIdentity, sequence: u64, issued: u64, ttl: u64) -> Vec<u8> {
    sign_record(
        root,
        profile(root.agent_id(), sequence),
        sequence,
        issued,
        ttl,
    )
    .unwrap()
}

fn short_claim(agent: AgentId) -> RecordPayload {
    RecordPayload::ShortCode(ShortCodeClaim {
        agent_id: agent,
        code: short_code(agent),
    })
}

fn sign_as(root: &AgentIdentity, record: UnsignedRecord) -> Vec<u8> {
    let signature = root
        .sign_domain_message(&record_signing_bytes(&record).unwrap())
        .unwrap();
    encode_record(&SignedRecord { record, signature }).unwrap()
}

fn peers(count: usize) -> Vec<PeerId> {
    let mut peers: Vec<_> = (0..count)
        .map(|_| DeviceIdentity::generate().unwrap().peer_id())
        .collect();
    peers.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    peers
}

fn certificate(root: &AgentIdentity, peer: &PeerId, serial: u64) -> DeviceCertificate {
    root.issue_device_certificate(peer.clone(), serial, NOW - 1_000, NOW + 86_400_000)
        .unwrap()
}

fn directory(
    root: &AgentIdentity,
    registry_sequence: u64,
    mut devices: Vec<DeviceCertificate>,
    revoked_serials: Vec<u64>,
) -> DeviceDirectory {
    devices.sort_by(|left, right| left.peer_id.as_bytes().cmp(right.peer_id.as_bytes()));
    DeviceDirectory {
        agent_id: root.agent_id(),
        registry_sequence,
        devices,
        revoked_serials,
    }
}

fn signed_directory(root: &AgentIdentity, value: &DeviceDirectory, sequence: u64) -> Vec<u8> {
    sign_record(
        root,
        RecordPayload::DeviceDirectory(value.clone()),
        sequence,
        NOW,
        LIFETIME,
    )
    .unwrap()
}

fn accept_directory(
    history: &mut RecordHistory,
    root: &AgentIdentity,
    directory: &DeviceDirectory,
    sequence: u64,
) -> Result<super::VerifiedRecord, AslError> {
    let bytes = signed_directory(root, directory, sequence);
    let mut resolver = directory_resolver(root, directory);
    // A history rejection must not be an unrelated proof or signature failure.
    verify_record(&bytes, root.agent_id(), NOW, &mut resolver).unwrap();
    history.accept(&bytes, NOW, &mut resolver)
}

mod connection_tests;

fn high_s(mut signature: Signature65) -> Signature65 {
    let order = U256::from_be_slice(&[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ]);
    let scalar = U256::from_be_slice(&signature.0[32..64]);
    signature.0[32..64].copy_from_slice(&(order - scalar).to_be_bytes::<32>());
    signature.0[64] = if signature.0[64] == 27 { 28 } else { 27 };
    let parsed = Signature::from_slice(&signature.0[..64]).unwrap();
    assert_ne!(parsed.normalize_s(), parsed);
    signature
}

fn replace_envelope(bytes: &[u8], key: u64, replacement: Value) -> Vec<u8> {
    let mut value: Value = cbor2::from_slice(bytes).unwrap();
    let Value::Map(fields) = &mut value else {
        panic!("record envelope must be a map");
    };
    let (_, target) = fields
        .iter_mut()
        .find(|(field, _)| *field == Value::Integer(Integer::from(key)))
        .unwrap();
    *target = replacement;
    cbor2::to_canonical_vec(&value).unwrap()
}

fn task() -> TaskId {
    TaskId(Id128([9; 16]))
}

fn avatar_reference() -> AvatarReference {
    AvatarReference {
        grant_id: GrantId(Id128([1; 16])),
        resource_key: ResourceKey(Id128([2; 16])),
    }
}

fn configuration(avatar: bool) -> ProfileConfiguration {
    ProfileConfiguration {
        capabilities: capabilities(),
        avatar: avatar.then(avatar_reference),
    }
}

fn avatar_snapshot(audience: Audience) -> PolicySnapshot {
    let avatar = avatar_reference();
    let mut state = PolicySnapshot::default();
    state.local_tasks.insert(task());
    state.grants.insert(
        avatar.grant_id.clone(),
        GrantPolicy {
            epoch: 1,
            active: true,
            audience,
            model_policy: ModelPolicy::Never,
            extensions: HashSet::from([".png".into()]),
            max_snapshot_bytes: 65_536,
            allowed_operations: HashSet::from([AccessOperation::PublishRecord]),
            allow_derived_disclosure: true,
        },
    );
    state.resources.insert(
        avatar.resource_key,
        ResourcePolicy {
            content_id: AVATAR,
            grant_id: avatar.grant_id,
            grant_epoch: 1,
            active: true,
            snapshot_ready: true,
            file_size: 1_024,
            extension: ".png".into(),
            retention_until_ms: None,
            origin: ResourceOrigin::Local,
        },
    );
    state
}

fn policy_without_resources() -> PolicyEngine {
    PolicyEngine::new(PolicySnapshot::default(), 60_000).unwrap()
}

fn published_profile(
    bytes: &[u8],
    root: &AgentIdentity,
    now: u64,
    sequence: u64,
    avatar: Option<Hash32>,
) {
    let verified = verify_record(bytes, root.agent_id(), now, &mut active(root)).unwrap();
    assert_eq!(verified.signed().record.sequence, sequence);
    assert_eq!(verified.signed().record.issued_at_ms, now);
    assert_eq!(verified.signed().record.expires_at_ms, now + 1_800_000);
    assert_eq!(
        verified.signed().record.payload,
        RecordPayload::Profile(Profile {
            agent_id: root.agent_id(),
            sequence,
            capabilities: capabilities(),
            avatar,
        })
    );
}

#[test]
fn signing_uses_the_frozen_root_preimage_for_each_record_kind() {
    let root = AgentIdentity::generate().unwrap();
    let directory = directory(&root, 7, vec![], vec![19]);
    let payloads = [
        (1_u8, profile(root.agent_id(), 0x0102_0304_0506_0708)),
        (2, RecordPayload::DeviceDirectory(directory)),
        (3, short_claim(root.agent_id())),
    ];
    for (kind, payload) in payloads {
        let bytes =
            sign_record(&root, payload.clone(), 0x0102_0304_0506_0708, NOW, 60_000).unwrap();
        let signed = decode_record(&bytes).unwrap();
        let payload_bytes = encode_record_payload(&payload).unwrap();
        let mut preimage = b"ASL-RECORD-v1\0".to_vec();
        preimage.push(kind);
        preimage.extend_from_slice(root.agent_id().as_bytes());
        preimage.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        preimage.extend_from_slice(&NOW.to_be_bytes());
        preimage.extend_from_slice(&(NOW + 60_000).to_be_bytes());
        preimage.extend_from_slice(&(payload_bytes.len() as u32).to_be_bytes());
        preimage.extend_from_slice(&payload_bytes);
        verify_root_signature(&preimage, signed.signature, root.controller_address()).unwrap();
        let signature = Signature::from_slice(&signed.signature.0[..64]).unwrap();
        assert_eq!(signature.normalize_s(), signature);
        assert!(matches!(signed.signature.0[64], 27 | 28));
        let mut resolver = if let RecordPayload::DeviceDirectory(value) = &payload {
            directory_resolver(&root, value)
        } else {
            active(&root)
        };
        let verified = verify_record(&bytes, root.agent_id(), NOW, &mut resolver).unwrap();
        assert_eq!(verified.signed().record.payload, payload);
        assert_eq!(verified.bytes(), bytes);
        assert_eq!(verified.registry_sequence(), 7);
        assert_eq!(resolver.requests, vec![(root.agent_id(), NOW / 1_000)]);
    }
}

#[test]
fn signing_rejects_foreign_owners_inconsistent_sequences_and_invalid_lifetimes() {
    let root = AgentIdentity::generate().unwrap();
    let other = AgentIdentity::generate().unwrap();
    for payload in [
        profile(other.agent_id(), 1),
        short_claim(other.agent_id()),
        RecordPayload::DeviceDirectory(directory(&other, 1, vec![], vec![])),
    ] {
        assert!(matches!(
            sign_record(&root, payload, 1, NOW, 1_000),
            Err(AslError::InvalidIdentity)
        ));
    }
    assert!(matches!(
        sign_record(&root, profile(root.agent_id(), 2), 1, NOW, 1_000),
        Err(AslError::InvalidMessage)
    ));
    for (issued, ttl) in [
        (NOW, 0),
        (NOW, 1_800_001),
        (u64::MAX - 10, 20),
        (i64::MAX as u64 - 10, 20),
    ] {
        assert!(sign_record(&root, profile(root.agent_id(), 1), 1, issued, ttl).is_err());
    }
    let bytes = signed_profile(&root, 0, NOW, 1_800_000);
    verify_record(&bytes, root.agent_id(), NOW, &mut active(&root)).unwrap();
}

#[test]
fn verification_rejects_high_s_invalid_recovery_ids_and_corrupted_signatures() {
    let root = AgentIdentity::generate().unwrap();
    let bytes = signed_profile(&root, 3, NOW, LIFETIME);
    let original = decode_record(&bytes).unwrap();
    let mut signatures = vec![
        ("high S", high_s(original.signature)),
        ("zero", Signature65([0; 65])),
    ];
    for v in [0, 1, 26, 29, 30, 255] {
        let mut invalid = original.signature;
        invalid.0[64] = v;
        signatures.push(("invalid recovery id", invalid));
    }
    let mut corrupt = original.signature;
    corrupt.0[0] ^= 1;
    signatures.push(("corrupted r", corrupt));
    let mut wrong_parity = original.signature;
    wrong_parity.0[64] = if wrong_parity.0[64] == 27 { 28 } else { 27 };
    signatures.push(("wrong recovery parity", wrong_parity));
    for (label, signature) in signatures {
        let mut altered = original.clone();
        altered.signature = signature;
        let bytes = encode_record(&altered).unwrap();
        assert!(
            matches!(
                verify_record(&bytes, root.agent_id(), NOW, &mut active(&root)),
                Err(AslError::InvalidIdentity)
            ),
            "{label}"
        );
    }
}

#[test]
fn verification_authenticates_every_structurally_valid_record_field() {
    let root = AgentIdentity::generate().unwrap();
    let other = AgentIdentity::generate().unwrap();
    let original = decode_record(&signed_profile(&root, 5, NOW, 60_000)).unwrap();
    for field in [
        "capabilities",
        "avatar",
        "sequence",
        "issued",
        "expires",
        "kind",
        "owner",
    ] {
        let mut altered = original.clone();
        let mut expected_agent = root.agent_id();
        match field {
            "capabilities" => {
                let RecordPayload::Profile(value) = &mut altered.record.payload else {
                    unreachable!()
                };
                value.capabilities[0].concept_id += 1;
            }
            "avatar" => {
                let RecordPayload::Profile(value) = &mut altered.record.payload else {
                    unreachable!()
                };
                value.avatar = Some(AVATAR);
            }
            "sequence" => {
                altered.record.sequence += 1;
                let RecordPayload::Profile(value) = &mut altered.record.payload else {
                    unreachable!()
                };
                value.sequence += 1;
            }
            "issued" => altered.record.issued_at_ms -= 1,
            "expires" => altered.record.expires_at_ms -= 1,
            "kind" => altered.record.payload = short_claim(root.agent_id()),
            "owner" => {
                expected_agent = other.agent_id();
                let RecordPayload::Profile(value) = &mut altered.record.payload else {
                    unreachable!()
                };
                value.agent_id = expected_agent;
            }
            _ => unreachable!(),
        }
        let bytes = encode_record(&altered).unwrap();
        // Keep the expected controller unchanged to isolate the signed preimage.
        let mut resolver = FixtureResolver::verified(proved_identity(
            expected_agent,
            root.controller_address(),
            7,
            [42; 32],
            1,
        ));
        assert!(
            matches!(
                verify_record(&bytes, expected_agent, NOW, &mut resolver),
                Err(AslError::InvalidIdentity)
            ),
            "{field}"
        );
    }
}

#[test]
fn verification_rejects_malformed_envelopes_and_text_before_identity_resolution() {
    let root = AgentIdentity::generate().unwrap();
    let bytes = signed_profile(&root, 5, NOW, LIFETIME);
    let mut trailing = bytes.clone();
    trailing.push(0);
    let mut truncated = bytes.clone();
    truncated.pop();
    let cases = [
        replace_envelope(&bytes, 0, Value::Integer(Integer::from(2))),
        replace_envelope(&bytes, 1, Value::Integer(Integer::from(99))),
        replace_envelope(&bytes, 2, Value::Bytes(vec![0; 32])),
        replace_envelope(&bytes, 3, Value::Integer(Integer::from(6))),
        replace_envelope(&bytes, 4, Value::Integer(Integer::from(NOW + LIFETIME))),
        replace_envelope(&bytes, 6, Value::Text("unstructured profile".into())),
        replace_envelope(&bytes, 6, Value::Bytes(vec![0x61, b'x'])),
        replace_envelope(&bytes, 7, Value::Bytes(vec![0; 64])),
        vec![0; 8_193],
        trailing,
        truncated,
    ];
    for bytes in cases {
        let mut resolver = active(&root);
        assert!(verify_record(&bytes, root.agent_id(), NOW, &mut resolver).is_err());
        assert!(resolver.requests.is_empty());
    }
}

#[test]
fn verification_enforces_inclusive_issue_and_exclusive_expiry() {
    let root = AgentIdentity::generate().unwrap();
    let bytes = signed_profile(&root, 1, NOW, 1_000);
    for now in [NOW, NOW + 999] {
        verify_record(&bytes, root.agent_id(), now, &mut active(&root)).unwrap();
    }
    for now in [NOW - 1, NOW + 1_000, NOW + 1_001] {
        assert!(matches!(
            verify_record(&bytes, root.agent_id(), now, &mut active(&root)),
            Err(AslError::ExpiredMessage)
        ));
    }
}

#[test]
fn verification_requires_the_requested_owner_and_fresh_active_versioned_resolution() {
    let root = AgentIdentity::generate().unwrap();
    let bytes = signed_profile(&root, 1, NOW, LIFETIME);
    for (label, mut resolver) in rejected_resolvers(&root) {
        assert!(
            matches!(
                verify_record(&bytes, root.agent_id(), NOW, &mut resolver),
                Err(AslError::InvalidIdentity)
            ),
            "{label}"
        );
    }
    let other = AgentIdentity::generate().unwrap();
    let mut resolver = active(&root);
    assert!(matches!(
        verify_record(&bytes, other.agent_id(), NOW, &mut resolver),
        Err(AslError::InvalidIdentity)
    ));
    assert!(resolver.requests.is_empty());
    let mut resolver = active(&root);
    resolver.valid_until_secs = Some((NOW + 1_000) / 1_000);
    verify_record(&bytes, root.agent_id(), NOW, &mut resolver).unwrap();
    assert!(matches!(
        verify_record(&bytes, root.agent_id(), NOW + 1_000, &mut resolver),
        Err(AslError::InvalidIdentity)
    ));
}

#[test]
fn current_controller_rotation_accepts_new_root_for_stable_owner_and_rejects_old_root() {
    let old_root = AgentIdentity::generate().unwrap();
    let new_root = AgentIdentity::generate().unwrap();
    let stable_agent = old_root.agent_id();
    let old_bytes = signed_profile(&old_root, 11, NOW, LIFETIME);
    let record = decode_record(&old_bytes).unwrap().record;
    assert!(matches!(
        sign_record(&new_root, record.payload.clone(), 11, NOW, LIFETIME),
        Err(AslError::InvalidIdentity)
    ));
    let new_bytes = sign_as(&new_root, record.clone());
    let mut rotated = FixtureResolver::verified(proved_identity(
        stable_agent,
        new_root.controller_address(),
        8,
        [42; 32],
        1,
    ));
    let verified = verify_record(&new_bytes, stable_agent, NOW, &mut rotated).unwrap();
    assert_eq!(verified.signed().record, record);
    assert_eq!(verified.registry_sequence(), 8);
    assert!(matches!(
        verify_record(&old_bytes, stable_agent, NOW, &mut rotated),
        Err(AslError::InvalidIdentity)
    ));
    assert!(matches!(
        verify_record(&new_bytes, stable_agent, NOW, &mut active(&old_root)),
        Err(AslError::InvalidIdentity)
    ));
}

#[test]
fn directory_requires_both_exact_commitment_and_proved_registry_sequence() {
    let root = AgentIdentity::generate().unwrap();
    let peer = peers(1).remove(0);
    let value = directory(&root, 7, vec![certificate(&root, &peer, 10)], vec![20]);
    let bytes = signed_directory(&root, &value, 100);
    verify_record(
        &bytes,
        root.agent_id(),
        NOW,
        &mut directory_resolver(&root, &value),
    )
    .unwrap();
    let commitment = device_directory_commitment(&value).unwrap().0;
    for (sequence, commitment) in [(7, [0; 32]), (8, commitment)] {
        let mut resolver = FixtureResolver::verified(proved_identity(
            root.agent_id(),
            root.controller_address(),
            sequence,
            commitment,
            1,
        ));
        assert!(matches!(
            verify_record(&bytes, root.agent_id(), NOW, &mut resolver),
            Err(AslError::InvalidIdentity)
        ));
    }
    let renewed = sign_record(
        &root,
        RecordPayload::DeviceDirectory(value.clone()),
        101,
        NOW + RENEWAL,
        LIFETIME,
    )
    .unwrap();
    let verified = verify_record(
        &renewed,
        root.agent_id(),
        NOW + RENEWAL,
        &mut directory_resolver(&root, &value),
    )
    .unwrap();
    assert_eq!(verified.signed().record.sequence, 101);
    assert_eq!(verified.registry_sequence(), 7);
}

#[test]
fn directory_checks_inner_device_signatures_even_when_outer_signature_and_commitment_match() {
    let root = AgentIdentity::generate().unwrap();
    let peer = peers(1).remove(0);
    let original = certificate(&root, &peer, 10);
    let other = AgentIdentity::generate().unwrap();
    for field in [
        "signature",
        "high S",
        "v",
        "serial",
        "peer",
        "issued",
        "expires",
        "root",
    ] {
        let mut cert = original.clone();
        match field {
            "signature" => cert.signature.0[0] ^= 1,
            "high S" => cert.signature = high_s(cert.signature),
            "v" => cert.signature.0[64] = 0,
            "serial" => cert.serial += 1,
            "peer" => cert.peer_id = peers(1).remove(0),
            "issued" => cert.issued_at_ms -= 1,
            "expires" => cert.expires_at_ms += 1,
            "root" => cert.signature = certificate(&other, &peer, 10).signature,
            _ => unreachable!(),
        }
        let value = directory(&root, 7, vec![cert], vec![]);
        let bytes = signed_directory(&root, &value, 1);
        assert!(
            matches!(
                verify_record(
                    &bytes,
                    root.agent_id(),
                    NOW,
                    &mut directory_resolver(&root, &value)
                ),
                Err(AslError::InvalidDeviceCertificate)
            ),
            "{field}"
        );
    }
}

#[test]
fn directory_rejects_not_yet_valid_and_expired_devices_inside_a_live_outer_record() {
    let root = AgentIdentity::generate().unwrap();
    let peer = peers(1).remove(0);
    for (issued, expires) in [(NOW + 1, NOW + 1_000), (NOW - 1_000, NOW)] {
        let cert = root
            .issue_device_certificate(peer.clone(), 10, issued, expires)
            .unwrap();
        let value = directory(&root, 7, vec![cert], vec![]);
        let bytes = signed_directory(&root, &value, 1);
        assert!(matches!(
            verify_record(
                &bytes,
                root.agent_id(),
                NOW,
                &mut directory_resolver(&root, &value)
            ),
            Err(AslError::ExpiredMessage)
        ));
    }
}

#[test]
fn history_only_accepts_exact_bytes_at_an_existing_sequence() {
    let root = AgentIdentity::generate().unwrap();
    let mut history = RecordHistory::new(root.agent_id(), 4).unwrap();
    let mut resolver = active(&root);
    let original = signed_profile(&root, 5, NOW, 60_000);
    history.accept(&original, NOW, &mut resolver).unwrap();
    assert_eq!(
        history
            .accept(&original, NOW + 1, &mut resolver)
            .unwrap()
            .bytes(),
        original
    );

    let mut changed = profile(root.agent_id(), 5);
    let RecordPayload::Profile(value) = &mut changed else {
        unreachable!()
    };
    value.avatar = Some(AVATAR);
    let payload_changed = sign_record(&root, changed, 5, NOW, 60_000).unwrap();
    let timestamps_changed = signed_profile(&root, 5, NOW + 1, 60_000);
    for bytes in [&payload_changed, &timestamps_changed] {
        verify_record(bytes, root.agent_id(), NOW + 1, &mut resolver).unwrap();
        assert!(matches!(
            history.accept(bytes, NOW + 1, &mut resolver),
            Err(AslError::PolicyVersionConflict)
        ));
        assert_eq!(history.highest_sequence(RecordKind::Profile), Some(5));
    }
    assert_eq!(
        history
            .accept(&original, NOW + 2, &mut resolver)
            .unwrap()
            .bytes(),
        original
    );
}

#[test]
fn history_keeps_its_watermark_after_expiry_and_failed_replacements() {
    let root = AgentIdentity::generate().unwrap();
    let mut history = RecordHistory::new(root.agent_id(), 4).unwrap();
    let mut resolver = active(&root);
    let original = signed_profile(&root, 5, NOW, 1_000);
    history.accept(&original, NOW, &mut resolver).unwrap();
    assert!(matches!(
        history.accept(&original, NOW + 1_000, &mut resolver),
        Err(AslError::ExpiredMessage)
    ));
    let older = signed_profile(&root, 4, NOW + 2_000, 60_000);
    assert!(matches!(
        history.accept(&older, NOW + 2_000, &mut resolver),
        Err(AslError::PolicyVersionConflict)
    ));
    let expired_higher = signed_profile(&root, 50, NOW, 1_000);
    assert!(matches!(
        history.accept(&expired_higher, NOW + 2_000, &mut resolver),
        Err(AslError::ExpiredMessage)
    ));
    let future_higher = signed_profile(&root, 50, NOW + 2_001, 60_000);
    assert!(matches!(
        history.accept(&future_higher, NOW + 2_000, &mut resolver),
        Err(AslError::ExpiredMessage)
    ));
    let mut corrupt = decode_record(&signed_profile(&root, 50, NOW + 2_000, 60_000)).unwrap();
    corrupt.signature.0[0] ^= 1;
    assert!(matches!(
        history.accept(
            &encode_record(&corrupt).unwrap(),
            NOW + 2_000,
            &mut resolver
        ),
        Err(AslError::InvalidIdentity)
    ));
    assert_eq!(history.highest_sequence(RecordKind::Profile), Some(5));
    let next = signed_profile(&root, 6, NOW + 2_000, 60_000);
    history.accept(&next, NOW + 2_000, &mut resolver).unwrap();
    assert_eq!(history.highest_sequence(RecordKind::Profile), Some(6));
}

#[test]
fn history_sequences_are_independent_for_profile_directory_and_short_code() {
    let root = AgentIdentity::generate().unwrap();
    let mut history = RecordHistory::new(root.agent_id(), 1).unwrap();
    history
        .accept(
            &signed_profile(&root, 100, NOW, LIFETIME),
            NOW,
            &mut active(&root),
        )
        .unwrap();
    let claim = sign_record(&root, short_claim(root.agent_id()), 0, NOW, LIFETIME).unwrap();
    history.accept(&claim, NOW, &mut active(&root)).unwrap();
    let value = directory(&root, 7, vec![], vec![10]);
    accept_directory(&mut history, &root, &value, 1).unwrap();
    accept_directory(&mut history, &root, &value, 1).unwrap();
    assert_eq!(history.highest_sequence(RecordKind::Profile), Some(100));
    assert_eq!(history.highest_sequence(RecordKind::ShortCode), Some(0));
    assert_eq!(
        history.highest_sequence(RecordKind::DeviceDirectory),
        Some(1)
    );
    assert!(history.observed_revocation(10));
}

#[test]
fn history_rechecks_identity_even_for_exact_idempotent_records() {
    let root = AgentIdentity::generate().unwrap();
    let mut history = RecordHistory::new(root.agent_id(), 1).unwrap();
    let bytes = signed_profile(&root, 1, NOW, LIFETIME);
    history.accept(&bytes, NOW, &mut active(&root)).unwrap();
    assert!(matches!(
        history.accept(
            &bytes,
            NOW,
            &mut FixtureResolver::limited(LimitedReason::Revoked),
        ),
        Err(AslError::InvalidIdentity)
    ));
    assert_eq!(history.highest_sequence(RecordKind::Profile), Some(1));
    history.accept(&bytes, NOW, &mut active(&root)).unwrap();
}

#[test]
fn history_serial_watermarks_are_per_peer_and_survive_directory_omission() {
    let root = AgentIdentity::generate().unwrap();
    let peers = peers(2);
    let a10 = certificate(&root, &peers[0], 10);
    let a11 = certificate(&root, &peers[0], 11);
    let b100 = certificate(&root, &peers[1], 100);
    let mut history = RecordHistory::new(root.agent_id(), 4).unwrap();
    accept_directory(
        &mut history,
        &root,
        &directory(&root, 1, vec![a10.clone(), b100.clone()], vec![]),
        1,
    )
    .unwrap();
    accept_directory(
        &mut history,
        &root,
        &directory(&root, 2, vec![a11.clone(), b100.clone()], vec![]),
        2,
    )
    .unwrap();
    accept_directory(
        &mut history,
        &root,
        &directory(&root, 3, vec![b100.clone()], vec![]),
        3,
    )
    .unwrap();
    assert!(matches!(
        accept_directory(
            &mut history,
            &root,
            &directory(&root, 4, vec![a10, b100.clone()], vec![]),
            4,
        ),
        Err(AslError::PolicyVersionConflict)
    ));
    assert_eq!(history.highest_device_serial(&peers[0]), Some(11));
    assert_eq!(history.highest_device_serial(&peers[1]), Some(100));
    assert_eq!(
        history.highest_sequence(RecordKind::DeviceDirectory),
        Some(3)
    );
    accept_directory(
        &mut history,
        &root,
        &directory(&root, 4, vec![a11, b100], vec![]),
        4,
    )
    .unwrap();
}

#[test]
fn history_never_rebinds_an_observed_serial_to_another_peer() {
    let root = AgentIdentity::generate().unwrap();
    let peers = peers(2);
    let mut history = RecordHistory::new(root.agent_id(), 3).unwrap();
    accept_directory(
        &mut history,
        &root,
        &directory(&root, 1, vec![certificate(&root, &peers[0], 10)], vec![]),
        1,
    )
    .unwrap();
    accept_directory(&mut history, &root, &directory(&root, 2, vec![], vec![]), 2).unwrap();
    assert!(matches!(
        accept_directory(
            &mut history,
            &root,
            &directory(&root, 3, vec![certificate(&root, &peers[1], 10)], vec![]),
            3,
        ),
        Err(AslError::PolicyVersionConflict)
    ));
    assert_eq!(history.highest_device_serial(&peers[0]), Some(10));
    assert_eq!(history.highest_device_serial(&peers[1]), None);
    accept_directory(
        &mut history,
        &root,
        &directory(&root, 3, vec![certificate(&root, &peers[1], 11)], vec![]),
        3,
    )
    .unwrap();
}

#[test]
fn history_rejects_a_validly_resigned_modified_certificate_at_the_same_serial() {
    let root = AgentIdentity::generate().unwrap();
    let peer = peers(1).remove(0);
    let original = certificate(&root, &peer, 10);
    let modified = root
        .issue_device_certificate(
            peer.clone(),
            10,
            original.issued_at_ms,
            original.expires_at_ms + 1,
        )
        .unwrap();
    let mut history = RecordHistory::new(root.agent_id(), 2).unwrap();
    accept_directory(
        &mut history,
        &root,
        &directory(&root, 1, vec![original.clone()], vec![]),
        1,
    )
    .unwrap();
    assert!(matches!(
        accept_directory(
            &mut history,
            &root,
            &directory(&root, 2, vec![modified], vec![]),
            2,
        ),
        Err(AslError::PolicyVersionConflict)
    ));
    assert_eq!(
        history.highest_sequence(RecordKind::DeviceDirectory),
        Some(1)
    );
    accept_directory(
        &mut history,
        &root,
        &directory(&root, 2, vec![original], vec![]),
        2,
    )
    .unwrap();
}

#[test]
fn history_remembers_revocations_of_known_and_previously_unseen_serials() {
    let root = AgentIdentity::generate().unwrap();
    let peers = peers(2);
    let mut history = RecordHistory::new(root.agent_id(), 4).unwrap();
    accept_directory(
        &mut history,
        &root,
        &directory(&root, 1, vec![certificate(&root, &peers[0], 10)], vec![]),
        1,
    )
    .unwrap();
    accept_directory(
        &mut history,
        &root,
        &directory(&root, 2, vec![], vec![10, 20]),
        2,
    )
    .unwrap();
    accept_directory(&mut history, &root, &directory(&root, 3, vec![], vec![]), 3).unwrap();
    for (peer, serial) in [(&peers[0], 10), (&peers[1], 20)] {
        assert!(matches!(
            accept_directory(
                &mut history,
                &root,
                &directory(&root, 4, vec![certificate(&root, peer, serial)], vec![]),
                4,
            ),
            Err(AslError::PolicyVersionConflict)
        ));
    }
    assert!(history.observed_revocation(10));
    assert!(history.observed_revocation(20));
    assert_eq!(
        history.highest_sequence(RecordKind::DeviceDirectory),
        Some(3)
    );
    accept_directory(
        &mut history,
        &root,
        &directory(&root, 4, vec![certificate(&root, &peers[1], 21)], vec![]),
        4,
    )
    .unwrap();
}

#[test]
fn history_quota_rejection_is_atomic_for_devices_revocations_and_record_sequence() {
    let root = AgentIdentity::generate().unwrap();
    let peers = peers(2);
    let original = certificate(&root, &peers[0], 10);
    let newcomer = certificate(&root, &peers[1], 20);
    let mut history = RecordHistory::new(root.agent_id(), 2).unwrap();
    accept_directory(
        &mut history,
        &root,
        &directory(&root, 1, vec![original.clone()], vec![]),
        1,
    )
    .unwrap();
    assert!(matches!(
        accept_directory(
            &mut history,
            &root,
            &directory(&root, 2, vec![original.clone(), newcomer.clone()], vec![30]),
            2,
        ),
        Err(AslError::PolicyDenied)
    ));
    assert_eq!(history.highest_device_serial(&peers[0]), Some(10));
    assert_eq!(history.highest_device_serial(&peers[1]), None);
    assert!(!history.observed_revocation(30));
    assert_eq!(
        history.highest_sequence(RecordKind::DeviceDirectory),
        Some(1)
    );
    accept_directory(
        &mut history,
        &root,
        &directory(&root, 2, vec![original, newcomer], vec![]),
        2,
    )
    .unwrap();
    assert_eq!(history.highest_device_serial(&peers[1]), Some(20));
}

#[test]
fn history_conflict_after_a_valid_prefix_does_not_commit_partial_observations() {
    let root = AgentIdentity::generate().unwrap();
    let peers = peers(2);
    let original = certificate(&root, &peers[1], 20);
    let newcomer = certificate(&root, &peers[0], 10);
    let rollback = certificate(&root, &peers[1], 19);
    let mut history = RecordHistory::new(root.agent_id(), 3).unwrap();
    accept_directory(
        &mut history,
        &root,
        &directory(&root, 1, vec![original.clone()], vec![]),
        1,
    )
    .unwrap();
    assert!(matches!(
        accept_directory(
            &mut history,
            &root,
            &directory(&root, 2, vec![newcomer.clone(), rollback], vec![30]),
            2,
        ),
        Err(AslError::PolicyVersionConflict)
    ));
    assert_eq!(history.highest_device_serial(&peers[0]), None);
    assert_eq!(history.highest_device_serial(&peers[1]), Some(20));
    assert!(!history.observed_revocation(30));
    assert_eq!(
        history.highest_sequence(RecordKind::DeviceDirectory),
        Some(1)
    );
    accept_directory(
        &mut history,
        &root,
        &directory(&root, 2, vec![newcomer, original], vec![30]),
        2,
    )
    .unwrap();
    assert!(history.observed_revocation(30));
}

#[test]
fn history_observation_limit_counts_retired_serials_and_unknown_revocation_tombstones() {
    let root = AgentIdentity::generate().unwrap();
    let peer = peers(1).remove(0);
    let mut history = RecordHistory::new(root.agent_id(), 2).unwrap();
    accept_directory(
        &mut history,
        &root,
        &directory(&root, 1, vec![certificate(&root, &peer, 10)], vec![20]),
        1,
    )
    .unwrap();
    accept_directory(&mut history, &root, &directory(&root, 2, vec![], vec![]), 2).unwrap();
    assert!(matches!(
        accept_directory(
            &mut history,
            &root,
            &directory(&root, 3, vec![certificate(&root, &peer, 11)], vec![]),
            3,
        ),
        Err(AslError::PolicyDenied)
    ));
    assert!(matches!(
        accept_directory(
            &mut history,
            &root,
            &directory(&root, 3, vec![], vec![30]),
            3,
        ),
        Err(AslError::PolicyDenied)
    ));
    assert_eq!(history.highest_device_serial(&peer), Some(10));
    assert!(history.observed_revocation(20));
    assert!(!history.observed_revocation(30));
    assert_eq!(
        history.highest_sequence(RecordKind::DeviceDirectory),
        Some(2)
    );
    accept_directory(
        &mut history,
        &root,
        &directory(&root, 3, vec![], vec![10, 20]),
        3,
    )
    .unwrap();
}

#[test]
fn history_refuses_unbounded_or_zero_observation_budgets() {
    let root = AgentIdentity::generate().unwrap();
    for limit in [0, 4_097, usize::MAX] {
        assert!(matches!(
            RecordHistory::new(root.agent_id(), limit),
            Err(AslError::InvalidPolicyState)
        ));
    }
}

#[test]
fn publisher_stays_disabled_until_explicitly_configured() {
    let root = AgentIdentity::generate().unwrap();
    let mut publisher = ProfilePublisher::new(&root, 0);
    let policy = policy_without_resources();
    let mut resolver = FixtureResolver::limited(LimitedReason::ChainUnavailable);
    for now in [NOW, NOW + RENEWAL, NOW + LIFETIME] {
        assert!(
            publisher
                .poll_record(now, task(), &policy, &mut resolver)
                .unwrap()
                .is_none()
        );
    }
    assert!(resolver.requests.is_empty());
    publisher.configure(configuration(false));
    let bytes = publisher
        .poll_record(NOW + LIFETIME, task(), &policy, &mut active(&root))
        .unwrap()
        .unwrap();
    published_profile(&bytes, &root, NOW + LIFETIME, 0, None);
}

#[test]
fn publisher_renews_at_five_minutes_with_fresh_timestamps_and_monotonic_sequences() {
    let root = AgentIdentity::generate().unwrap();
    let policy = policy_without_resources();
    let mut resolver = active(&root);
    let mut publisher = ProfilePublisher::new(&root, 41);
    publisher.configure(configuration(false));
    let first = publisher
        .poll_record(NOW, task(), &policy, &mut resolver)
        .unwrap()
        .unwrap();
    published_profile(&first, &root, NOW, 41, None);
    for now in [NOW, NOW + 1, NOW + 299_999] {
        assert!(
            publisher
                .poll_record(now, task(), &policy, &mut resolver)
                .unwrap()
                .is_none()
        );
    }
    let second = publisher
        .poll_record(NOW + 300_000, task(), &policy, &mut resolver)
        .unwrap()
        .unwrap();
    published_profile(&second, &root, NOW + 300_000, 42, None);
    assert_ne!(first, second);
    let late = publisher
        .poll_record(NOW + 1_200_000, task(), &policy, &mut resolver)
        .unwrap()
        .unwrap();
    published_profile(&late, &root, NOW + 1_200_000, 43, None);
    assert!(
        publisher
            .poll_record(NOW + 1_200_001, task(), &policy, &mut resolver,)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        resolver.requests,
        vec![
            (root.agent_id(), NOW / 1_000),
            (root.agent_id(), (NOW + 300_000) / 1_000),
            (root.agent_id(), (NOW + 1_200_000) / 1_000),
        ]
    );
}

#[test]
fn publisher_does_not_resolve_identity_or_emit_records_before_renewal_is_due() {
    let root = AgentIdentity::generate().unwrap();
    let policy = policy_without_resources();
    let mut publisher = ProfilePublisher::new(&root, 1);
    publisher.configure(configuration(false));
    publisher
        .poll_record(NOW, task(), &policy, &mut active(&root))
        .unwrap()
        .unwrap();
    let mut resolver = FixtureResolver::limited(LimitedReason::StaleProof);
    assert!(
        publisher
            .poll_record(NOW + 299_999, task(), &policy, &mut resolver,)
            .unwrap()
            .is_none()
    );
    assert!(resolver.requests.is_empty());
    assert!(matches!(
        publisher.poll_record(NOW + 300_000, task(), &policy, &mut resolver),
        Err(AslError::InvalidIdentity)
    ));
    let bytes = publisher
        .poll_record(NOW + 300_000, task(), &policy, &mut active(&root))
        .unwrap()
        .unwrap();
    published_profile(&bytes, &root, NOW + 300_000, 2, None);
}

#[test]
fn publisher_withdrawal_prevents_renewal_and_resurrection_without_new_local_configuration() {
    let root = AgentIdentity::generate().unwrap();
    let policy = policy_without_resources();
    let mut publisher = ProfilePublisher::new(&root, 10);
    publisher.configure(configuration(false));
    let old = publisher
        .poll_record(NOW, task(), &policy, &mut active(&root))
        .unwrap()
        .unwrap();
    publisher.withdraw();
    publisher.withdraw();
    let mut resolver = active(&root);
    for now in [NOW + 1, NOW + RENEWAL, NOW + LIFETIME] {
        assert!(
            publisher
                .poll_record(now, task(), &policy, &mut resolver)
                .unwrap()
                .is_none()
        );
    }
    assert!(resolver.requests.is_empty());
    // Withdrawal stops local publication; existing copies keep their original TTL.
    verify_record(&old, root.agent_id(), NOW + RENEWAL, &mut resolver).unwrap();
    assert!(matches!(
        verify_record(&old, root.agent_id(), NOW + LIFETIME, &mut resolver),
        Err(AslError::ExpiredMessage)
    ));
    publisher.configure(configuration(false));
    let next = publisher
        .poll_record(NOW + LIFETIME, task(), &policy, &mut resolver)
        .unwrap()
        .unwrap();
    published_profile(&next, &root, NOW + LIFETIME, 11, None);
}

#[test]
fn publisher_reconfiguration_is_immediately_due_without_resetting_sequence() {
    let root = AgentIdentity::generate().unwrap();
    let policy = policy_without_resources();
    let mut publisher = ProfilePublisher::new(&root, 3);
    publisher.configure(configuration(false));
    publisher
        .poll_record(NOW, task(), &policy, &mut active(&root))
        .unwrap()
        .unwrap();
    let mut updated = configuration(false);
    updated.capabilities = vec![ConceptRef {
        vocabulary_id: 1,
        concept_id: 200,
    }];
    publisher.configure(updated.clone());
    let bytes = publisher
        .poll_record(NOW + 1, task(), &policy, &mut active(&root))
        .unwrap()
        .unwrap();
    let verified = verify_record(&bytes, root.agent_id(), NOW + 1, &mut active(&root)).unwrap();
    assert_eq!(verified.signed().record.sequence, 4);
    let RecordPayload::Profile(value) = &verified.signed().record.payload else {
        panic!()
    };
    assert_eq!(value.capabilities, updated.capabilities);
    assert!(
        publisher
            .poll_record(NOW + 300_000, task(), &policy, &mut active(&root),)
            .unwrap()
            .is_none()
    );
    let bytes = publisher
        .poll_record(NOW + 300_001, task(), &policy, &mut active(&root))
        .unwrap()
        .unwrap();
    assert_eq!(decode_record(&bytes).unwrap().record.sequence, 5);
}

#[test]
fn publisher_rejects_wrong_limited_revoked_and_versioned_resolvers_without_consuming_sequence() {
    let root = AgentIdentity::generate().unwrap();
    let policy = policy_without_resources();
    for (label, mut resolver) in rejected_resolvers(&root) {
        let mut publisher = ProfilePublisher::new(&root, 17);
        publisher.configure(configuration(false));
        assert!(
            matches!(
                publisher.poll_record(NOW, task(), &policy, &mut resolver),
                Err(AslError::InvalidIdentity)
            ),
            "{label}"
        );
        let bytes = publisher
            .poll_record(NOW, task(), &policy, &mut active(&root))
            .unwrap()
            .unwrap();
        published_profile(&bytes, &root, NOW, 17, None);
    }
}

#[test]
fn publisher_requires_a_fresh_chain_resolution_for_each_due_renewal() {
    let root = AgentIdentity::generate().unwrap();
    let policy = policy_without_resources();
    let mut resolver = active(&root);
    resolver.valid_until_secs = Some((NOW + RENEWAL) / 1_000);
    let mut publisher = ProfilePublisher::new(&root, 4);
    publisher.configure(configuration(false));
    publisher
        .poll_record(NOW, task(), &policy, &mut resolver)
        .unwrap()
        .unwrap();
    for now in [NOW + RENEWAL, NOW + LIFETIME] {
        assert!(matches!(
            publisher.poll_record(now, task(), &policy, &mut resolver),
            Err(AslError::InvalidIdentity)
        ));
    }
    let bytes = publisher
        .poll_record(NOW + LIFETIME, task(), &policy, &mut active(&root))
        .unwrap()
        .unwrap();
    published_profile(&bytes, &root, NOW + LIFETIME, 5, None);
}

#[test]
fn publisher_rejects_clock_rollback_without_spending_the_next_sequence() {
    let root = AgentIdentity::generate().unwrap();
    let policy = policy_without_resources();
    let mut publisher = ProfilePublisher::new(&root, 3);
    publisher.configure(configuration(false));
    publisher
        .poll_record(NOW, task(), &policy, &mut active(&root))
        .unwrap()
        .unwrap();
    assert!(matches!(
        publisher.poll_record(NOW - 1, task(), &policy, &mut active(&root)),
        Err(AslError::ExpiredMessage)
    ));
    let bytes = publisher
        .poll_record(NOW + RENEWAL, task(), &policy, &mut active(&root))
        .unwrap()
        .unwrap();
    published_profile(&bytes, &root, NOW + RENEWAL, 4, None);
    publisher.withdraw();
    assert!(matches!(
        publisher.poll_record(NOW, task(), &policy, &mut active(&root)),
        Err(AslError::ExpiredMessage)
    ));
}

#[test]
fn publisher_sequence_exhaustion_cannot_wrap_or_be_reset_by_reconfiguration() {
    let root = AgentIdentity::generate().unwrap();
    let policy = policy_without_resources();
    let mut publisher = ProfilePublisher::new(&root, u64::MAX);
    publisher.configure(configuration(false));
    let bytes = publisher
        .poll_record(NOW, task(), &policy, &mut active(&root))
        .unwrap()
        .unwrap();
    published_profile(&bytes, &root, NOW, u64::MAX, None);
    assert!(
        publisher
            .poll_record(NOW + RENEWAL - 1, task(), &policy, &mut active(&root),)
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        publisher.poll_record(NOW + RENEWAL, task(), &policy, &mut active(&root)),
        Err(AslError::PolicyVersionConflict)
    ));
    publisher.withdraw();
    assert!(
        publisher
            .poll_record(NOW + RENEWAL, task(), &policy, &mut active(&root),)
            .unwrap()
            .is_none()
    );
    publisher.configure(configuration(false));
    assert!(matches!(
        publisher.poll_record(NOW + RENEWAL, task(), &policy, &mut active(&root)),
        Err(AslError::PolicyVersionConflict)
    ));
}

#[test]
fn publisher_rejects_clock_exhaustion_at_the_wire_limit_and_arithmetic_overflow() {
    let root = AgentIdentity::generate().unwrap();
    let policy = policy_without_resources();
    let last_issue = i64::MAX as u64 - 1_800_000;
    let mut publisher = ProfilePublisher::new(&root, 1);
    publisher.configure(configuration(false));
    let bytes = publisher
        .poll_record(last_issue, task(), &policy, &mut active(&root))
        .unwrap()
        .unwrap();
    published_profile(&bytes, &root, last_issue, 1, None);
    for now in [last_issue + RENEWAL, u64::MAX - 1, u64::MAX] {
        assert!(matches!(
            publisher.poll_record(now, task(), &policy, &mut active(&root)),
            Err(AslError::InvalidMessage)
        ));
    }
}

#[test]
fn publisher_includes_only_the_publicly_authorized_avatar_content_reference() {
    let root = AgentIdentity::generate().unwrap();
    let policy = PolicyEngine::new(avatar_snapshot(Audience::Public), 60_000).unwrap();
    let mut publisher = ProfilePublisher::new(&root, 1);
    publisher.configure(configuration(true));
    let first = publisher
        .poll_record(NOW, task(), &policy, &mut active(&root))
        .unwrap()
        .unwrap();
    published_profile(&first, &root, NOW, 1, Some(AVATAR));
    policy.revoke(avatar_reference().grant_id, 1).unwrap();
    for now in [NOW + RENEWAL, NOW + LIFETIME] {
        assert!(matches!(
            publisher.poll_record(now, task(), &policy, &mut active(&root)),
            Err(AslError::NotFound)
        ));
    }
    publisher.configure(configuration(false));
    let next = publisher
        .poll_record(NOW + LIFETIME, task(), &policy, &mut active(&root))
        .unwrap()
        .unwrap();
    published_profile(&next, &root, NOW + LIFETIME, 2, None);
}

#[test]
fn publisher_rejects_private_avatars_even_when_the_local_task_can_read_them() {
    let root = AgentIdentity::generate().unwrap();
    for audience in [
        Audience::Contacts,
        Audience::Peers(HashSet::from([root.agent_id()])),
        Audience::Group(GroupId(Id128([4; 16]))),
    ] {
        let mut snapshot = avatar_snapshot(audience);
        snapshot
            .grants
            .get_mut(&avatar_reference().grant_id)
            .unwrap()
            .allowed_operations
            .insert(AccessOperation::ReadChunk);
        let policy = PolicyEngine::new(snapshot, 60_000).unwrap();
        policy
            .authorize(
                &AccessRequest {
                    grant_id: avatar_reference().grant_id,
                    resource_key: avatar_reference().resource_key,
                    principal: asl_policy::Principal::LocalTask(task()),
                    operation: AccessOperation::ReadChunk,
                },
                NOW,
            )
            .unwrap();
        let mut publisher = ProfilePublisher::new(&root, 1);
        publisher.configure(configuration(true));
        assert!(matches!(
            publisher.poll_record(NOW, task(), &policy, &mut active(&root)),
            Err(AslError::NotFound)
        ));
        publisher.configure(configuration(false));
        let bytes = publisher
            .poll_record(NOW, task(), &policy, &mut active(&root))
            .unwrap()
            .unwrap();
        published_profile(&bytes, &root, NOW, 1, None);
    }
}

#[test]
fn publisher_requires_a_current_bound_resource_and_explicit_publish_permission() {
    let root = AgentIdentity::generate().unwrap();
    for failure in [
        "no resource",
        "no grant",
        "wrong grant",
        "inactive",
        "not ready",
        "expired",
        "wrong epoch",
        "no publication operation",
        "unknown task",
    ] {
        let mut snapshot = avatar_snapshot(Audience::Public);
        let avatar = avatar_reference();
        match failure {
            "no resource" => {
                snapshot.resources.clear();
            }
            "no grant" => {
                snapshot.grants.clear();
            }
            "wrong grant" => {
                let other_grant_id = GrantId(Id128([99; 16]));
                let original_grant = snapshot.grants[&avatar.grant_id].clone();
                snapshot
                    .grants
                    .insert(other_grant_id.clone(), original_grant);
                snapshot
                    .resources
                    .get_mut(&avatar.resource_key)
                    .unwrap()
                    .grant_id = other_grant_id;
            }
            "inactive" => {
                snapshot
                    .resources
                    .get_mut(&avatar.resource_key)
                    .unwrap()
                    .active = false;
            }
            "not ready" => {
                snapshot
                    .resources
                    .get_mut(&avatar.resource_key)
                    .unwrap()
                    .snapshot_ready = false;
            }
            "expired" => {
                snapshot
                    .resources
                    .get_mut(&avatar.resource_key)
                    .unwrap()
                    .retention_until_ms = Some(NOW);
            }
            "wrong epoch" => {
                snapshot
                    .resources
                    .get_mut(&avatar.resource_key)
                    .unwrap()
                    .grant_epoch = 2;
            }
            "no publication operation" => {
                snapshot
                    .grants
                    .get_mut(&avatar.grant_id)
                    .unwrap()
                    .allowed_operations = HashSet::from([AccessOperation::ReadChunk]);
            }
            "unknown task" => {
                snapshot.local_tasks.clear();
            }
            _ => unreachable!(),
        }
        let policy = PolicyEngine::new(snapshot, 60_000).unwrap();
        let mut publisher = ProfilePublisher::new(&root, 7);
        publisher.configure(configuration(true));
        assert!(
            matches!(
                publisher.poll_record(NOW, task(), &policy, &mut active(&root)),
                Err(AslError::NotFound)
            ),
            "{failure}"
        );
    }
}

struct RevokeAfterAuthorization {
    engine: PolicyEngine,
}

impl PolicyService for RevokeAfterAuthorization {
    fn authorize(&self, request: &AccessRequest, now_ms: u64) -> Result<Permit, AslError> {
        let permit = self.engine.authorize(request, now_ms)?;
        self.engine
            .revoke(request.grant_id.clone(), permit.grant_epoch())?;
        Ok(permit)
    }

    fn revalidate(&self, permit: &Permit, now_ms: u64) -> Result<(), AslError> {
        self.engine.revalidate(permit, now_ms)
    }

    fn revoke(&self, grant: GrantId, expected_epoch: u64) -> Result<PolicyRevision, AslError> {
        self.engine.revoke(grant, expected_epoch)
    }
}

#[test]
fn publisher_discards_a_signed_candidate_if_its_avatar_grant_is_revoked_before_return() {
    let root = AgentIdentity::generate().unwrap();
    let policy = RevokeAfterAuthorization {
        engine: PolicyEngine::new(avatar_snapshot(Audience::Public), 60_000).unwrap(),
    };
    let mut publisher = ProfilePublisher::new(&root, 8);
    publisher.configure(configuration(true));
    assert!(matches!(
        publisher.poll_record(NOW, task(), &policy, &mut active(&root)),
        Err(AslError::NotFound)
    ));
    publisher.configure(configuration(false));
    let bytes = publisher
        .poll_record(NOW, task(), &policy, &mut active(&root))
        .unwrap()
        .unwrap();
    published_profile(&bytes, &root, NOW, 8, None);
}
