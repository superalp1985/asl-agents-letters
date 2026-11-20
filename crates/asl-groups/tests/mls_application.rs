use asl_groups::{
    GroupApplication,
    membership::{
        GROUP_CIPHERSUITE as SUITE, read_group_message, read_key_package, read_sync_commit,
        stage_welcome, sync_epoch_binding,
    },
};
use asl_types::{
    ids::{Hash32, Id128},
    protocol::{GroupBody, GroupMembership, GroupPacket},
};
use openmls::prelude::{
    BasicCredential, CredentialWithKey, GroupId, KeyPackage, MlsGroup, MlsGroupCreateConfig,
    MlsMessageIn, MlsMessageOut, OpenMlsProvider, ProcessedMessageContent, ProtocolMessage, Sender,
    tls_codec::Deserialize as _,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

const WIRE_ID: Hash32 = Hash32([3; 32]);

fn packet(id: u8, epoch: u64, body: GroupBody) -> GroupPacket {
    GroupPacket {
        message_id: Id128([id; 16]),
        group_id: WIRE_ID,
        epoch,
        body,
    }
}

fn fixture_member(id: u8) -> (CredentialWithKey, SignatureKeyPair) {
    // No chain admission in this library integration fixture.
    let signer = SignatureKeyPair::new(SUITE.signature_algorithm()).unwrap();
    let credential = CredentialWithKey {
        credential: BasicCredential::new(vec![id; 32]).into(),
        signature_key: signer.to_public_vec().into(),
    };
    (credential, signer)
}

fn fixture_room(
    provider: &OpenMlsRustCrypto,
    signer: &SignatureKeyPair,
    credential: CredentialWithKey,
) -> MlsGroup {
    let parameters = MlsGroupCreateConfig::builder()
        .ciphersuite(SUITE)
        .use_ratchet_tree_extension(true)
        .build();
    MlsGroup::new_with_group_id(
        provider,
        signer,
        &parameters,
        GroupId::from_slice(WIRE_ID.as_bytes()),
        credential,
    )
    .unwrap()
}

fn read_wire(message: MlsMessageOut) -> MlsMessageIn {
    MlsMessageIn::tls_deserialize_exact(message.to_bytes().unwrap()).unwrap()
}

fn protocol(message: MlsMessageOut) -> ProtocolMessage {
    read_wire(message).try_into_protocol_message().unwrap()
}

#[cfg(windows)]
fn fixture_peer(id: u8) -> asl_types::ids::PeerId {
    let mut bytes = vec![0x12, 0x20];
    bytes.extend_from_slice(&[id; 32]);
    asl_types::ids::PeerId::from_bytes(bytes).unwrap()
}

#[cfg(windows)]
fn join_request(
    invite: Id128,
    credential: CredentialWithKey,
    signer: &SignatureKeyPair,
) -> (GroupPacket, OpenMlsRustCrypto, Hash32) {
    use asl_groups::pending_join;
    use asl_store::group_state::MlsIncomingInvite;
    use asl_types::ids::AgentId;

    let inviter = fixture_peer(1);
    let local = fixture_peer(2);
    let invite = MlsIncomingInvite {
        id: invite,
        wire_id: WIRE_ID,
        base_epoch: 0,
        inviter: AgentId([1; 32]),
        inviter_device: inviter.clone(),
        recipient: AgentId([2; 32]),
        recipient_device: local,
        expires_at_ms: 100_000,
    };
    let draft = pending_join::prepare(&invite, Id128([8; 16]), credential, signer).unwrap();
    for wrong in [
        MlsIncomingInvite {
            id: Id128([9; 16]),
            ..invite.clone()
        },
        MlsIncomingInvite {
            recipient_device: inviter,
            ..invite.clone()
        },
        MlsIncomingInvite {
            recipient: AgentId([3; 32]),
            ..invite.clone()
        },
        MlsIncomingInvite {
            expires_at_ms: invite.expires_at_ms + 1,
            ..invite.clone()
        },
    ] {
        assert!(pending_join::restore(&wrong, draft.key, &draft.sealed_package).is_err());
    }
    let (request, provider) =
        pending_join::restore(&invite, draft.key, &draft.sealed_package).unwrap();
    let (retried, _) = pending_join::restore(&invite, draft.key, &draft.sealed_package).unwrap();
    assert_eq!(request, retried);
    assert!(
        SignatureKeyPair::read(
            provider.storage(),
            signer.public(),
            SUITE.signature_algorithm()
        )
        .is_some()
    );
    (request, provider, draft.key.package_ref)
}

#[cfg(not(windows))]
fn join_request(
    invite: Id128,
    credential: CredentialWithKey,
    signer: &SignatureKeyPair,
) -> (GroupPacket, OpenMlsRustCrypto, Hash32) {
    let provider = OpenMlsRustCrypto::default();
    let package = KeyPackage::builder()
        .build(SUITE, &provider, signer, credential)
        .unwrap();
    let key_package = package.into_key_package();
    let reference = key_package.hash_ref(provider.crypto()).unwrap();
    let request = packet(
        8,
        0,
        GroupBody::Membership(GroupMembership::KeyPackage {
            invite,
            message: MlsMessageOut::from(key_package).to_bytes().unwrap(),
        }),
    );
    (
        request,
        provider,
        Hash32(reference.as_slice().try_into().unwrap()),
    )
}

#[test]
fn key_package_reader_does_not_accept_a_last_resort_package() {
    let provider = OpenMlsRustCrypto::default();
    let (credential, signer) = fixture_member(2);
    let last_resort = KeyPackage::builder()
        .mark_as_last_resort()
        .build(SUITE, &provider, &signer, credential)
        .unwrap();
    let request = packet(
        1,
        0,
        GroupBody::Membership(GroupMembership::KeyPackage {
            invite: Id128([3; 16]),
            message: MlsMessageOut::from(last_resort).to_bytes().unwrap(),
        }),
    );
    assert!(read_key_package(&request, provider.crypto()).is_err());
}

#[test]
fn mls_members_receive_structured_application_data_and_removal_blocks_new_messages() {
    let creator = OpenMlsRustCrypto::default();
    let (creator_credential, creator_signer) = fixture_member(1);
    let (joiner_credential, joiner_signer) = fixture_member(2);
    let mut room = fixture_room(&creator, &creator_signer, creator_credential.clone());
    let invite = Id128([7; 16]);
    let (request, joiner, local_ref) = join_request(invite, joiner_credential, &joiner_signer);
    let (verified, reference) = read_key_package(&request, creator.crypto()).unwrap();
    assert_eq!(reference, local_ref);
    let (_, welcome, _) = room
        .add_members(&creator, &creator_signer, &[verified])
        .unwrap();
    room.merge_pending_commit(&creator).unwrap();
    let welcome = packet(
        8,
        1,
        GroupBody::Membership(GroupMembership::Welcome {
            invite,
            package_ref: reference,
            message: welcome.to_bytes().unwrap(),
        }),
    );
    assert!(stage_welcome(&request, &welcome, Hash32([9; 32]), &joiner).is_err());
    for (group_id, epoch) in [(Hash32([9; 32]), 0), (WIRE_ID, 1)] {
        // Staging can consume the package in its provider even when ASL
        // later rejects the candidate. The durable provider is not reused.
        let candidate = OpenMlsRustCrypto::default();
        *candidate.storage().values.write().unwrap() =
            joiner.storage().values.read().unwrap().clone();
        let base = GroupPacket {
            group_id,
            epoch,
            ..request.clone()
        };
        let reply = GroupPacket {
            group_id,
            epoch: epoch + 1,
            ..welcome.clone()
        };
        assert!(stage_welcome(&base, &reply, reference, &candidate).is_err());
    }
    let mut trailing = welcome.clone();
    let GroupBody::Membership(GroupMembership::Welcome { message, .. }) = &mut trailing.body else {
        unreachable!();
    };
    message.push(0);
    assert!(stage_welcome(&request, &trailing, reference, &joiner).is_err());
    let joined = stage_welcome(&request, &welcome, reference, &joiner)
        .unwrap()
        .into_group(&joiner)
        .unwrap();
    assert_eq!(joined.group_id(), room.group_id());
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
        let packet = packet(
            1,
            room.epoch().as_u64(),
            GroupBody::Application(message.to_bytes().unwrap()),
        );
        let received = joined
            .process_message(&joiner, read_group_message(&packet).unwrap())
            .unwrap();
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

    let base_epoch = room.epoch().as_u64();
    let epoch_binding = sync_epoch_binding(&room, creator.crypto()).unwrap();
    assert_eq!(
        sync_epoch_binding(&joined, joiner.crypto()).unwrap(),
        epoch_binding
    );
    assert_ne!(
        epoch_binding.as_bytes(),
        room.epoch_authenticator().as_slice()
    );
    let sync_request = packet(
        3,
        base_epoch,
        GroupBody::Membership(GroupMembership::SyncRequest { epoch_binding }),
    );
    let (commit, _, _) = room
        .remove_members(&creator, &creator_signer, &[joined.own_leaf_index()])
        .unwrap();
    room.merge_pending_commit(&creator).unwrap();
    assert_ne!(
        sync_epoch_binding(&room, creator.crypto()).unwrap(),
        epoch_binding
    );
    let commit = commit.to_bytes().unwrap();
    let application = packet(4, base_epoch, GroupBody::Application(commit.clone()));
    assert!(read_group_message(&application).is_err());
    let direct = packet(
        4,
        base_epoch,
        GroupBody::Membership(GroupMembership::Commit(commit.clone())),
    );
    assert!(read_group_message(&direct).is_ok());
    let wrong_epoch = GroupPacket {
        epoch: base_epoch + 1,
        ..direct
    };
    assert!(read_group_message(&wrong_epoch).is_err());
    let sync_reply = packet(
        3,
        base_epoch,
        GroupBody::Membership(GroupMembership::SyncCommit(commit)),
    );
    let received = joined
        .process_message(
            &joiner,
            read_sync_commit(&sync_request, &sync_reply).unwrap(),
        )
        .unwrap();
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
#[test]
fn outgoing_welcome_survives_store_reopen_and_joins_the_mls_room() {
    use asl_groups::local_state::{RoomBinding, restore, seal};
    use asl_store::{
        group_state::{
            MlsInviteResponse, MlsJournalEntry, MlsJournalKind, MlsRoomUpdate, MlsWelcomeRequest,
            PendingMlsRoom,
        },
        open_store,
    };
    use asl_types::{ids::AgentId, task::GroupId as LocalGroupId};

    const NOW: u64 = 1_000;
    let database = OutgoingDatabase::new();
    let mut store = open_store(&database.0).unwrap();
    let peers = [fixture_peer(1), fixture_peer(2)];
    let [sender, recipient] = &peers;
    register_outgoing_devices(&mut store, &peers, NOW);

    let provider = OpenMlsRustCrypto::default();
    let (credential, signer) = fixture_member(1);
    let mut room = fixture_room(&provider, &signer, credential);
    let local_id = LocalGroupId(Id128([5; 16]));
    let binding = RoomBinding {
        local_id: &local_id,
        wire_id: WIRE_ID,
        device: sender,
    };
    let epoch = room.epoch().as_u64();
    store
        .stage_mls_room(PendingMlsRoom {
            local_id: &local_id,
            wire_id: WIRE_ID,
            creator: sender,
            local_name: "Outgoing test",
            mls_epoch: epoch,
            sealed_snapshot: &seal(&binding, 1, &room, &provider).unwrap(),
        })
        .unwrap();
    let initial = store.mls_room_snapshot(WIRE_ID).unwrap().unwrap().version;
    let base = store
        .commit_mls_room_candidate(MlsRoomUpdate {
            local_id: &local_id,
            wire_id: WIRE_ID,
            expected: initial,
            mls_epoch: epoch,
            sealed_snapshot: &seal(&binding, initial.revision + 1, &room, &provider).unwrap(),
            members: std::slice::from_ref(sender),
            event: None,
        })
        .unwrap();

    let agent = AgentId([2; 32]);
    let invite = packet(
        7,
        epoch,
        GroupBody::Membership(GroupMembership::Invite {
            agent,
            device: recipient.clone(),
            expires_at_ms: 100_000,
        }),
    );
    store.issue_mls_invite(sender, &invite, NOW).unwrap();
    let (credential, joiner_signer) = fixture_member(2);
    let (request, joiner, local_ref) = join_request(invite.message_id, credential, &joiner_signer);
    let (verified, package_ref) = read_key_package(&request, provider.crypto()).unwrap();
    assert_eq!(package_ref, local_ref);
    let lookup = MlsWelcomeRequest {
        local_creator: sender,
        recipient: agent,
        device: recipient,
        packet: &request,
        package_ref,
        package_expires_at_ms: verified.life_time().not_after().checked_mul(1_000).unwrap(),
    };
    let (commit, welcome, _) = room.add_members(&provider, &signer, &[verified]).unwrap();
    room.merge_pending_commit(&provider).unwrap();
    let epoch = room.epoch().as_u64();
    let welcome = welcome.to_bytes().unwrap();
    let version = store
        .commit_mls_invite_welcome(
            &lookup,
            MlsRoomUpdate {
                local_id: &local_id,
                wire_id: WIRE_ID,
                expected: base,
                mls_epoch: epoch,
                sealed_snapshot: &seal(&binding, base.revision + 1, &room, &provider).unwrap(),
                members: &peers,
                event: Some(MlsJournalEntry {
                    sender,
                    kind: MlsJournalKind::Commit,
                    ciphertext: &commit.to_bytes().unwrap(),
                }),
            },
            welcome.clone(),
            NOW,
        )
        .unwrap();
    drop(store);

    let store = open_store(&database.0).unwrap();
    let Some(MlsInviteResponse::Committed(reply)) =
        store.mls_invite_response(&lookup, NOW).unwrap()
    else {
        panic!("expected the committed Welcome after reopening the sender store");
    };
    assert_eq!(
        reply,
        GroupPacket {
            message_id: request.message_id,
            group_id: WIRE_ID,
            epoch,
            body: GroupBody::Membership(GroupMembership::Welcome {
                invite: invite.message_id,
                package_ref,
                message: welcome,
            }),
        }
    );
    let snapshot = store.mls_room_snapshot(WIRE_ID).unwrap().unwrap();
    assert_eq!(snapshot.version, version);
    let (_, restored) = restore(&binding, &snapshot).unwrap();
    let joined = stage_welcome(&request, &reply, package_ref, &joiner)
        .unwrap()
        .into_group(&joiner)
        .unwrap();
    assert_eq!(joined.group_id(), restored.group_id());
    assert_eq!(joined.epoch(), restored.epoch());
    assert_eq!(
        joined.epoch_authenticator().as_slice(),
        restored.epoch_authenticator().as_slice()
    );
}

#[cfg(windows)]
fn register_outgoing_devices(
    store: &mut asl_store::Store,
    peers: &[asl_types::ids::PeerId; 2],
    now: u64,
) {
    use asl_store::{
        chain::{ChainBundle, ChainStateRow, IdentityObservationRow, ObservationStatus},
        search::direct::DirectRequester,
    };
    use asl_types::{
        ids::{AgentId, Signature65},
        protocol::DeviceCertificate,
    };

    // Supply synthetic admission facts; this fixture does not verify chain proofs.
    let bundle = ChainBundle {
        state: ChainStateRow {
            chain_id: 1,
            registry_address: [1; 20],
            registry_code_hash: [2; 32],
            finalized_height: 1,
            finalized_block_hash: [3; 32],
            execution_state_root: [4; 32],
            checkpoint_hash: [5; 32],
            verified_header_state: vec![1],
            updated_at_ms: now,
        },
        observations: [1, 2]
            .into_iter()
            .map(|id| IdentityObservationRow {
                agent_id: AgentId([id; 32]),
                chain_id: 1,
                controller_address: [id; 20],
                state_commitment: [id; 32],
                sequence: 1,
                status: ObservationStatus::Active,
                finalized_height: 1,
                storage_proof_hash: [id; 32],
                verified_at_ms: now,
            })
            .collect(),
        proofs: vec![],
    };
    store.save_chain_bundle(&bundle, None).unwrap();
    for (peer, observation) in peers.iter().zip(bundle.observations) {
        let certificate = DeviceCertificate {
            agent_id: observation.agent_id,
            peer_id: peer.clone(),
            serial: 1,
            issued_at_ms: now,
            expires_at_ms: now + 100_000,
            signature: Signature65([0; 65]),
        };
        let requester = DirectRequester {
            agent: certificate.agent_id,
            peer: peer.clone(),
            session_expires_at_ms: certificate.expires_at_ms,
            registry_sequence: observation.sequence,
            directory_commitment: observation.state_commitment,
            controller: observation.controller_address,
        };
        store
            .register_transfer_peer(&requester, observation.chain_id, &certificate, [1; 32], now)
            .unwrap();
    }
}

#[cfg(windows)]
struct OutgoingDatabase(std::path::PathBuf);

#[cfg(windows)]
impl OutgoingDatabase {
    fn new() -> Self {
        use std::{env, fs, path::PathBuf, process, time::SystemTime};

        let base = env::var_os("ASL_TEST_FIXTURE_BASE")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/asl-test-fs")
            });
        fs::create_dir_all(&base).unwrap();
        let timestamp = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_nanos();
        Self(base.join(format!(
            "asl-mls-outgoing-{}-{timestamp}.sqlite3",
            process::id()
        )))
    }
}

#[cfg(windows)]
impl Drop for OutgoingDatabase {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        for extension in ["sqlite3-wal", "sqlite3-shm"] {
            let _ = std::fs::remove_file(self.0.with_extension(extension));
        }
    }
}

#[cfg(windows)]
fn roundtrip_state(
    provider: &OpenMlsRustCrypto,
    group: &MlsGroup,
) -> (OpenMlsRustCrypto, MlsGroup) {
    use asl_groups::local_state::{RoomBinding, restore, seal};
    use asl_store::group_state::{MlsRoomSnapshot, RoomVersion};
    use asl_types::{ids::PeerId, task::GroupId};

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
