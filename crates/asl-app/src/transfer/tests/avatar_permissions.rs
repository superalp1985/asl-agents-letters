use asl_net::codec::{BulkOperation, BulkRequest, BulkStatus};
use asl_store::{
    Store, dashboard::LocalIdentityProjection, open_store, search::direct::DirectRequester,
};
use asl_types::{
    error::AslError,
    ids::{Hash32, Id128},
    manifest::{Manifest, content_id, encode_manifest},
    protocol::{ConceptRef, FetchRequest},
};
use image::{ExtendedColorType, ImageEncoder, codecs::png::PngEncoder};
use rusqlite::{Connection, params};

use super::Fixture;
use crate::{
    identity::{AgentIdentity, DeviceIdentity},
    libraries::LocalLibraries,
    paths::AppPaths,
    supervisor::unix_time_ms,
    transfer::TransferService,
};

#[test]
fn approved_avatar_reference_does_not_authorize_direct_fetch_or_bare_bulk() {
    let fixture = Fixture::new();
    let paths = AppPaths::open(&fixture.path().join("home")).unwrap();
    let database = paths.state().join("asl.sqlite3");
    let libraries = LocalLibraries::open(&paths).unwrap();
    let mut store = open_store(&database).unwrap();
    let owner = AgentIdentity::generate().unwrap().agent_id();
    let owner_device = DeviceIdentity::generate().unwrap().peer_id();
    store
        .set_local_identity_projection(&LocalIdentityProjection {
            agent_id: bs58::encode(owner.as_bytes()).into_string(),
            peer_id: bs58::encode(owner_device.as_bytes()).into_string(),
            network_state: "network_active".into(),
            binding_code: String::new(),
        })
        .unwrap();
    store
        .approve_profile_publication(owner, vec![ConceptRef::RUST.concept_id])
        .unwrap();
    let mut png = Vec::new();
    PngEncoder::new(&mut png)
        .write_image(&[29, 73, 143, 255], 1, 1, ExtendedColorType::Rgba8)
        .unwrap();
    store.replace_sanitized_avatar(Some(&png)).unwrap();
    let review = store.avatar_review().unwrap().unwrap();
    assert!(!review.approved);
    assert_eq!(review.bytes, png);
    store
        .approve_avatar_reference(owner, review.token.as_deref().unwrap())
        .unwrap();
    assert!(store.avatar_review().unwrap().unwrap().approved);
    let profile = store.current_public_profile(owner).unwrap().unwrap();
    let avatar = profile
        .avatar()
        .expect("publication must reference the approved avatar");
    let manifest = encode_manifest(&Manifest::from_bytes(&png).unwrap()).unwrap();
    assert_eq!(avatar.content_id, Hash32(content_id(&manifest)));

    let now = unix_time_ms().unwrap();
    let requester = admitted_requester(&mut store, &Connection::open(&database).unwrap(), now);
    let (direct_policy, _) = store.direct_search_snapshot(&requester).unwrap();
    assert!(direct_policy.devices.contains_key(&requester.peer));
    let mut transfer = TransferService::open(&database).unwrap();
    let fetch = FetchRequest {
        message_id: Id128([1; 16]),
        root_task_id: Id128([2; 16]),
        content_id: avatar.content_id,
    };
    assert!(matches!(
        transfer.prepare_fetch(requester.clone(), &fetch, now, |_, _| Ok(())),
        Err(AslError::NotFound)
    ));
    assert_eq!(transfer.leases.active_count().unwrap(), 0);
    assert!(store.upload_consents().unwrap().is_empty());

    for (operation, id) in [
        (BulkOperation::Manifest, 3),
        (BulkOperation::Chunk, 4),
        (BulkOperation::Inline, 5),
    ] {
        let request_id = Id128([id; 16]);
        let prepared = transfer.prepare_bulk(
            &libraries,
            requester.clone(),
            BulkRequest {
                operation,
                request_id,
                content_id: avatar.content_id,
                lease_id: Hash32([0; 32]),
                chunk_index: 0,
            },
            now,
        );
        let mut response = None;
        transfer
            .finish_bulk(prepared, now, |value| {
                response = Some(value);
                Ok(())
            })
            .unwrap();
        let response = response.expect("bulk rejection was not queued");
        assert_eq!(response.request_id, request_id);
        assert_eq!(response.status, BulkStatus::NotFound, "{operation:?}");
        assert!(response.payload.is_empty(), "{operation:?} returned bytes");
    }
}

fn admitted_requester(store: &mut Store, db: &Connection, now: u64) -> DirectRequester {
    let root = AgentIdentity::generate().unwrap();
    let device = DeviceIdentity::generate().unwrap();
    let requester = DirectRequester {
        agent: root.agent_id(),
        peer: device.peer_id(),
        session_expires_at_ms: now + 60_000,
        registry_sequence: 1,
        directory_commitment: [0x33; 32],
        controller: root.controller_address(),
    };
    let agent = bs58::encode(requester.agent.as_bytes()).into_string();
    db.execute_batch(
        "INSERT INTO chain_state_cache VALUES
            (1,zeroblob(20),zeroblob(32),0,zeroblob(32),zeroblob(32),zeroblob(32),x'',0);",
    )
    .unwrap();
    db.execute(
        "INSERT INTO agents(agent_id,identity_state) VALUES (?1,'verified')",
        [&agent],
    )
    .unwrap();
    db.execute(
        "INSERT INTO identity_registry_states
         (agent_id,chain_id,controller_address,state_commitment,sequence,status,
          finalized_height,storage_proof_hash,verified_at_ms)
         VALUES (?1,1,?2,?3,1,'active',0,zeroblob(32),0)",
        params![
            agent,
            requester.controller.as_slice(),
            requester.directory_commitment.as_slice()
        ],
    )
    .unwrap();
    let certificate = root
        .issue_device_certificate(
            requester.peer.clone(),
            1,
            now,
            requester.session_expires_at_ms,
        )
        .unwrap();
    let device_key = device
        .into_keypair()
        .public()
        .try_into_ed25519()
        .unwrap()
        .to_bytes();
    store
        .register_transfer_peer(&requester, 1, &certificate, device_key, now)
        .unwrap();
    requester
}
