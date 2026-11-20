use asl_groups::GroupApplication;
use openmls::prelude::{
    BasicCredential, Ciphersuite, CredentialWithKey, GroupId, KeyPackage, MlsGroup,
    MlsGroupCreateConfig, MlsGroupJoinConfig, MlsMessageBodyIn, MlsMessageIn, MlsMessageOut,
    ProcessedMessageContent, ProtocolMessage, Sender, StagedWelcome, tls_codec::Deserialize as _,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

fn fixture_member(id: u8) -> (CredentialWithKey, SignatureKeyPair) {
    // No chain admission in this library integration fixture.
    let signer = SignatureKeyPair::new(SUITE.signature_algorithm()).unwrap();
    let credential = CredentialWithKey {
        credential: BasicCredential::new(vec![id; 32]).into(),
        signature_key: signer.to_public_vec().into(),
    };
    (credential, signer)
}

fn read_wire(message: MlsMessageOut) -> MlsMessageIn {
    MlsMessageIn::tls_deserialize_exact(message.to_bytes().unwrap()).unwrap()
}

fn protocol(message: MlsMessageOut) -> ProtocolMessage {
    read_wire(message).try_into_protocol_message().unwrap()
}

#[test]
fn mls_members_receive_structured_application_data_and_removal_blocks_new_messages() {
    let creator = OpenMlsRustCrypto::default();
    let joiner = OpenMlsRustCrypto::default();
    let (creator_credential, creator_signer) = fixture_member(1);
    let (joiner_credential, joiner_signer) = fixture_member(2);
    let group_id = GroupId::from_slice(&[3; 32]);
    let parameters = MlsGroupCreateConfig::builder()
        .ciphersuite(SUITE)
        .use_ratchet_tree_extension(true)
        .build();
    let mut room = MlsGroup::new_with_group_id(
        &creator,
        &creator_signer,
        &parameters,
        group_id.clone(),
        creator_credential.clone(),
    )
    .unwrap();
    let package = KeyPackage::builder()
        .build(SUITE, &joiner, &joiner_signer, joiner_credential)
        .unwrap();
    let (_, welcome, _) = room
        .add_members(&creator, &creator_signer, &[package.key_package().clone()])
        .unwrap();
    room.merge_pending_commit(&creator).unwrap();
    let MlsMessageBodyIn::Welcome(welcome) = read_wire(welcome).extract() else {
        panic!("expected MLS Welcome");
    };
    let joined = StagedWelcome::new_from_welcome(
        &joiner,
        &MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build(),
        welcome,
        None,
    )
    .unwrap()
    .into_group(&joiner)
    .unwrap();
    assert_eq!(joined.group_id(), &group_id);
    assert_eq!(joined.epoch(), room.epoch());

    #[cfg(windows)]
    let (joiner, mut joined) = roundtrip_state(&joiner, &joined);
    #[cfg(not(windows))]
    let mut joined = joined;

    let bytes: Vec<u8> = include_str!("../../../schemas/vectors/query-v1.hex")
        .split_ascii_whitespace()
        .map(|byte| u8::from_str_radix(byte, 16).unwrap())
        .collect();
    let query = GroupApplication::decode(&bytes).unwrap();
    let encoded = query.clone().encode().unwrap();
    for (plaintext, expected) in [(&encoded[..], Some(query)), (b"free text", None)] {
        let message = room
            .create_message(&creator, &creator_signer, plaintext)
            .unwrap();
        let received = joined.process_message(&joiner, protocol(message)).unwrap();
        assert_eq!(received.sender(), &Sender::Member(room.own_leaf_index()));
        assert_eq!(received.credential(), &creator_credential.credential);
        let ProcessedMessageContent::ApplicationMessage(message) = received.into_content() else {
            panic!("expected authenticated MLS application plaintext");
        };
        assert_eq!(
            GroupApplication::decode(&message.into_bytes()).ok(),
            expected
        );
    }

    let (commit, _, _) = room
        .remove_members(&creator, &creator_signer, &[joined.own_leaf_index()])
        .unwrap();
    room.merge_pending_commit(&creator).unwrap();
    let received = joined.process_message(&joiner, protocol(commit)).unwrap();
    let ProcessedMessageContent::StagedCommitMessage(commit) = received.into_content() else {
        panic!("expected authenticated removal commit");
    };
    joined.merge_staged_commit(&joiner, *commit).unwrap();
    assert!(!joined.is_active());
    let next = room
        .create_message(&creator, &creator_signer, &encoded)
        .unwrap();
    assert!(joined.process_message(&joiner, protocol(next)).is_err());
}

#[cfg(windows)]
fn roundtrip_state(
    provider: &OpenMlsRustCrypto,
    group: &MlsGroup,
) -> (OpenMlsRustCrypto, MlsGroup) {
    use asl_groups::local_state::{RoomBinding, restore, seal};
    use asl_store::group_state::{MlsRoomSnapshot, RoomVersion};
    use asl_types::{
        ids::{Hash32, Id128, PeerId},
        task::GroupId,
    };

    let mut encoded_peer = vec![0x12, 0x20];
    encoded_peer.extend_from_slice(&[4; 32]);
    let device = PeerId::from_bytes(encoded_peer).unwrap();
    let local = GroupId(Id128([5; 16]));
    let binding = RoomBinding {
        local_id: &local,
        wire_id: Hash32(group.group_id().as_slice().try_into().unwrap()),
        device: &device,
    };
    let sealed = seal(&binding, 1, group, provider).unwrap();
    let mut row = MlsRoomSnapshot {
        local_id: local.clone(),
        sealed_snapshot: sealed,
        version: RoomVersion {
            revision: 2,
            mls_epoch: group.epoch().as_u64(),
            membership_epoch: 1,
            policy_revision: 1,
        },
    };
    assert!(restore(&binding, &row).is_err(), "wrong persisted revision");
    row.version.revision = 1;
    row.version.mls_epoch += 1;
    assert!(restore(&binding, &row).is_err(), "wrong persisted epoch");
    row.version.mls_epoch -= 1;
    let wrong_binding = RoomBinding {
        wire_id: Hash32([9; 32]),
        ..binding
    };
    assert!(restore(&wrong_binding, &row).is_err(), "wrong group");
    let (provider, loaded) = restore(&binding, &row).unwrap();
    assert!(loaded.members().eq(group.members()));
    assert_eq!(
        loaded.epoch_authenticator().as_slice(),
        group.epoch_authenticator().as_slice()
    );
    (provider, loaded)
}
