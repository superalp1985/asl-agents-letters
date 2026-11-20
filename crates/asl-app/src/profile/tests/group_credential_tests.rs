use openmls::prelude::{
    BasicCredential, CredentialWithKey, GroupId, MlsGroup, MlsGroupCreateConfig,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

use super::*;
use crate::profile::group_credential::{
    GROUP_CIPHERSUITE, issue_group_credential, verify_group_leaf,
};

#[test]
fn mls_leaf_binds_exact_room_key_and_current_chain_device() {
    let root = AgentIdentity::generate().unwrap();
    let peer = DeviceIdentity::generate().unwrap().peer_id();
    let certificate = root
        .issue_device_certificate(peer.clone(), 1, NOW, NOW + RENEWAL)
        .unwrap();
    let directory_v1 = directory(&root, 1, vec![certificate.clone()], vec![]);
    let signed_v1 = signed_directory(&root, &directory_v1, 1);
    let mut history = RecordHistory::new(root.agent_id(), 16).unwrap();
    let mut resolver = directory_resolver(&root, &directory_v1);
    let room_id = Hash32([7; 32]);
    let (signer, credential) = issue_group_credential(&root, room_id, &certificate, NOW).unwrap();
    let group = MlsGroup::new_with_group_id(
        &OpenMlsRustCrypto::default(),
        &signer,
        &MlsGroupCreateConfig::builder()
            .ciphersuite(GROUP_CIPHERSUITE)
            .build(),
        GroupId::from_slice(room_id.as_bytes()),
        credential,
    )
    .unwrap();
    let leaf = CredentialWithKey::from(&group.members().next().unwrap());
    assert_eq!(
        verify_group_leaf(room_id, &leaf, &signed_v1, &mut history, &mut resolver, NOW).unwrap(),
        certificate
    );

    let other_signer = SignatureKeyPair::new(GROUP_CIPHERSUITE.signature_algorithm()).unwrap();
    let wrong_key = CredentialWithKey {
        signature_key: other_signer.to_public_vec().into(),
        ..leaf.clone()
    };
    let bad_signature = {
        let mut bytes = leaf.credential.serialized_content().to_vec();
        bytes[0] ^= 1;
        CredentialWithKey {
            credential: BasicCredential::new(bytes).into(),
            ..leaf.clone()
        }
    };
    for (id, leaf) in [
        (Hash32([8; 32]), &leaf),
        (room_id, &wrong_key),
        (room_id, &bad_signature),
    ] {
        assert!(verify_group_leaf(id, leaf, &signed_v1, &mut history, &mut resolver, NOW).is_err());
    }
    assert!(matches!(
        verify_group_leaf(
            room_id,
            &leaf,
            &signed_v1,
            &mut history,
            &mut resolver,
            NOW + RENEWAL
        ),
        Err(AslError::ExpiredMessage)
    ));

    let renewed = root
        .issue_device_certificate(peer, 2, NOW, NOW + LIFETIME)
        .unwrap();
    let directory_v2 = directory(&root, 2, vec![renewed], vec![1]);
    let signed_v2 = signed_directory(&root, &directory_v2, 2);
    let mut resolver = directory_resolver(&root, &directory_v2);
    for signed in [&signed_v1, &signed_v2] {
        assert!(
            verify_group_leaf(room_id, &leaf, signed, &mut history, &mut resolver, NOW).is_err()
        );
    }
}
