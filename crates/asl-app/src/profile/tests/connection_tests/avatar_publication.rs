use super::*;
use asl_store::dashboard::LocalIdentityProjection;
use image::{ExtendedColorType, ImageEncoder, codecs::png::PngEncoder};

#[test]
fn core_signs_and_withdraws_the_reviewed_avatar_reference() {
    let root = AgentIdentity::generate().unwrap();
    let owner = root.agent_id();
    let device = DeviceIdentity::generate().unwrap().peer_id();
    let dir = directory(&root, 7, vec![certificate(&root, &device, 1)], vec![]);
    let (db, resolver, _) = durable_directory_resolver(&root, &dir);
    let (_remote_db, mut remote, _) = durable_directory_resolver(&root, &dir);
    let mut core = CoreAdmission::for_local_identity(
        &root,
        device.clone(),
        signed_directory(&root, &dir, 1),
        resolver,
        NOW,
    )
    .unwrap();
    let mut store = db.open();
    store
        .set_local_identity_projection(&LocalIdentityProjection {
            agent_id: bs58::encode(owner.0).into_string(),
            peer_id: bs58::encode(device.as_bytes()).into_string(),
            binding_code: String::new(),
            network_state: "network_active".into(),
        })
        .unwrap();
    let mut png = Vec::new();
    PngEncoder::new(&mut png)
        .write_image(&[4, 5, 6, 255], 1, 1, ExtendedColorType::Rgba8)
        .unwrap();
    store.replace_sanitized_avatar(Some(&png)).unwrap();
    store.approve_profile_publication(owner, vec![101]).unwrap();
    let token = store.avatar_review().unwrap().unwrap().token.unwrap();
    store.approve_avatar_reference(owner, &token).unwrap();
    let mut history = RecordHistory::new(owner, 4).unwrap();
    let mut previous = None;
    for disclosed in [true, false] {
        if !disclosed {
            store.withdraw_avatar_reference().unwrap();
        }
        let approval = store.current_public_profile(owner).unwrap().unwrap();
        let seq = store.reserve_profile_sequence(owner).unwrap();
        let bytes = core
            .prepare_local_profile(&root, &store, &approval, seq, NOW)
            .unwrap()
            .unwrap();
        assert!(store.observe_profile_candidate(&approval, &bytes).unwrap());
        let verified = history.accept(&bytes, NOW, &mut remote).unwrap();
        let RecordPayload::Profile(profile) = &verified.signed().record.payload else {
            panic!("expected signed profile");
        };
        assert_eq!(profile.avatar.is_some(), disclosed);
        assert_eq!(profile.avatar, approval.avatar().map(|a| a.content_id));
        assert_eq!(
            profile.capabilities,
            [asl_store::public_profile::profile_topic(101)]
        );
        if let Some(old) = previous.as_deref() {
            assert!(history.accept(old, NOW, &mut remote).is_err());
        }
        previous = Some(bytes);
    }
}
