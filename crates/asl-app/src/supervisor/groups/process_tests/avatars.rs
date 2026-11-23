use super::*;
use asl_store::{resources::SnapshotBroker, search::LocalIndexText, transfers::UploadMode};
use asl_types::{
    manifest::{Manifest, content_id, encode_manifest},
    protocol::Profile,
};
use image::{ExtendedColorType, ImageEncoder, codecs::png::PngEncoder};

pub(super) fn verify(registry: &Path, nodes: &[(PeerId, PathBuf, RegistryClaim); 3]) {
    let [
        (peer, home, (owner, _)),
        (_, receiver_home, (recipient, _)),
        _,
    ] = nodes;
    let (mut sender, sender_ready) = CoreProcess::start(home, registry, false);
    let (mut receiver, receiver_ready) = CoreProcess::start(receiver_home, registry, false);
    receiver.dial(&sender_ready, peer);
    receiver.connection(&sender_ready["peer"]);
    sender.connection(&receiver_ready["peer"]);
    let db = home.join("state/asl.sqlite3");
    crate::direct_inbound::configure(&db, "answer").unwrap();
    let mut provider = asl_store::open_store(&db).unwrap();
    provider.set_upload_mode(UploadMode::Ask).unwrap();
    let mut consumer = asl_store::open_store(&receiver_home.join("state/asl.sqlite3")).unwrap();

    // A regular image explicitly shared from a library, not the private local avatar.
    let mut png = Vec::new();
    PngEncoder::new(&mut png)
        .write_image(&vec![73; 256 * 192 * 3], 256, 192, ExtendedColorType::Rgb8)
        .unwrap();
    let content = Hash32(content_id(
        &encode_manifest(&Manifest::from_bytes(&png).unwrap()).unwrap(),
    ));
    let library = home.with_extension("library");
    fs::create_dir(&library).unwrap();
    fs::write(library.join("shared.png"), &png).unwrap();
    let mut broker = SnapshotBroker::open(home).unwrap();
    let grant = broker
        .authorize_directory(
            &library,
            &["png".into()],
            &asl_policy::Audience::Public,
            65536,
        )
        .unwrap();
    let key = broker
        .import_source(&grant, Path::new("shared.png"))
        .unwrap();
    provider
        .index_local_text(
            &key,
            content,
            LocalIndexText {
                title: "shared",
                summary: "",
                body: "",
                concepts: &[ConceptRef::RUST],
            },
        )
        .unwrap();
    let now = unix_time_ms().unwrap();
    // Start at the verified-profile projection. Signature/DHT ingestion has its own fixture.
    consumer
        .observe_remote_profile(
            &Profile {
                agent_id: *owner,
                sequence: 1,
                capabilities: vec![],
                avatar: Some(content),
            },
            1,
            now,
            now + 90_000,
            now,
        )
        .unwrap();
    assert_eq!(consumer.visible_remote_profiles().unwrap().len(), 1);
    assert!(consumer.pending_avatar_download(now).unwrap().is_none());
    assert!(consumer.received_avatar(*owner, content).unwrap().is_none());
    assert!(provider.upload_consents().unwrap().is_empty());
    consumer.request_avatar_download(*owner, content).unwrap();
    let approval = wait("provider upload approval", || {
        provider.upload_consents().unwrap().pop()
    });
    assert_eq!(approval.target_agent_id, Some(*recipient));
    assert_eq!(approval.content_id, content);
    assert!(consumer.received_avatar(*owner, content).unwrap().is_none());
    provider.decide_upload(approval.approval_id, true).unwrap();

    let sanitized = wait("isolated avatar cache", || {
        consumer.received_avatar(*owner, content).unwrap()
    });
    assert_ne!(sanitized, png);
    let image = image::load_from_memory(&sanitized).unwrap().into_rgb8();
    assert_eq!(image.dimensions(), (128, 96));
    assert_eq!(image.get_pixel(0, 0).0, [73; 3]);
    assert!(
        consumer
            .pending_avatar_download(unix_time_ms().unwrap())
            .unwrap()
            .is_none()
    );
    assert!(consumer.download_consents().unwrap().is_empty());
    receiver.close();
    sender.close();
}

fn wait<T>(stage: &str, mut read: impl FnMut() -> Option<T>) -> T {
    let start = Instant::now();
    loop {
        if let Some(value) = read() {
            return value;
        }
        assert!(start.elapsed() < WAIT * 2, "{stage} timed out");
        thread::sleep(Duration::from_millis(100));
    }
}
