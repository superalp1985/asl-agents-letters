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
    let mut joined = StagedWelcome::new_from_welcome(
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
