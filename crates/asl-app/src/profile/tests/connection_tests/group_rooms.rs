use std::collections::HashMap;

use asl_groups::{
    local_state::{RoomBinding, RoomProvider, restore},
    membership::{GROUP_CIPHERSUITE, read_key_package},
    pending_join,
};
use asl_store::{Store, group_state::MlsIncomingInvite, search::direct::DirectRequester};
use asl_types::protocol::{GroupBody, GroupMembership, GroupPacket};
use openmls::prelude::{GroupId as MlsGroupId, MlsGroup, MlsGroupCreateConfig, OpenMlsProvider};
use openmls_basic_credential::SignatureKeyPair;

use crate::profile::{
    ApprovedMlsWelcome, admission::transport_ed25519_key, group_credential::issue_group_credential,
};

use super::*;

#[test]
fn group_welcome_requires_a_committed_origin_and_reconciles_after_restart() {
    let root = AgentIdentity::generate().unwrap();
    let creator_cert = certificate(&root, &DeviceIdentity::generate().unwrap().peer_id(), 1);
    let local_cert = certificate(&root, &DeviceIdentity::generate().unwrap().peer_id(), 2);
    let dir = directory(
        &root,
        7,
        vec![creator_cert.clone(), local_cert.clone()],
        vec![],
    );
    let signed = signed_directory(&root, &dir, 1);
    let (creator_db, resolver, _) = durable_directory_resolver(&root, &dir);
    let mut creator = CoreAdmission::for_local_identity(
        &root,
        creator_cert.peer_id.clone(),
        signed.clone(),
        resolver,
        NOW,
    )
    .unwrap();
    let mut creator_store = creator_db.open();
    let creator_local_id = GroupId(Id128([1; 16]));
    assert!(
        creator
            .create_local_mls_room(
                &mut creator_store,
                &root,
                &creator_local_id,
                "Creator room",
                NOW,
            )
            .is_err()
    );
    register_devices(&mut creator_store, &root, &dir);
    let (wire_id, version) = creator
        .create_local_mls_room(
            &mut creator_store,
            &root,
            &creator_local_id,
            "Creator room",
            NOW,
        )
        .unwrap();
    let dirs = HashMap::new();
    let reconciled = creator
        .reconcile_mls_room(&creator_store, wire_id, &dirs, NOW)
        .unwrap()
        .unwrap();
    assert_eq!(reconciled.version, version);
    assert_eq!(reconciled.creator, creator_cert.peer_id);
    assert_eq!(reconciled.members, vec![creator_cert.peer_id.clone()]);
    let snapshot = creator_store.mls_room_snapshot(wire_id).unwrap().unwrap();
    let binding = RoomBinding {
        local_id: &creator_local_id,
        wire_id,
        device: &creator_cert.peer_id,
    };
    let (provider, mut creator_room) = restore(&binding, &snapshot).unwrap();
    let pubkey = creator_room.members().next().unwrap().signature_key;
    let creator_signer = SignatureKeyPair::read(
        provider.storage(),
        &pubkey,
        GROUP_CIPHERSUITE.signature_algorithm(),
    )
    .unwrap();

    let (local_db, resolver, proof) = durable_directory_resolver(&root, &dir);
    let mut recipient = CoreAdmission::for_local_identity(
        &root,
        local_cert.peer_id.clone(),
        signed.clone(),
        resolver,
        NOW,
    )
    .unwrap();
    let mut store = local_db.open();
    register_devices(&mut store, &root, &dir);
    let connection_id = [4; 16];
    recipient.handle_event(
        NetworkEvent::TransportConnected {
            connection_id,
            peer_id: creator_cert.peer_id.clone(),
        },
        NOW,
    );
    let batch = recipient.handle_event(
        NetworkEvent::UnverifiedControlRequest {
            connection_id,
            response_id: [5; 16],
            request: WireFrame::Hello(hello(&creator_cert)),
        },
        NOW,
    );
    let request = batch
        .commands
        .iter()
        .find_map(|command| match command {
            NetworkCommand::RequestIdentityProof { request, .. } => Some(request),
            _ => None,
        })
        .unwrap();
    let proof = crate::chain::identity_proof_to_wire(request, proof, signed.clone());
    let admitted = recipient.handle_event(
        NetworkEvent::IdentityProofReceived {
            connection_id,
            proof,
        },
        NOW,
    );
    assert!(matches!(
        admitted.events.as_slice(),
        [AdmittedNetworkEvent::PeerAdmitted { .. }]
    ));

    let invite = MlsIncomingInvite {
        id: Id128([6; 16]),
        wire_id,
        base_epoch: 0,
        inviter: creator_cert.agent_id,
        inviter_device: creator_cert.peer_id.clone(),
        recipient: local_cert.agent_id,
        recipient_device: local_cert.peer_id.clone(),
        expires_at_ms: NOW + 60_000,
    };
    assert!(store.receive_mls_invite(&invite, NOW).unwrap());
    let (signer, credential) = issue_group_credential(&root, wire_id, &local_cert, NOW).unwrap();
    let join = pending_join::prepare(&invite, Id128([7; 16]), credential, &signer).unwrap();
    assert!(
        store
            .save_mls_join_package(&invite, join.key, &join.sealed_package, NOW)
            .unwrap()
    );
    let (request, _) = pending_join::restore(&invite, join.key, &join.sealed_package).unwrap();
    let local_id = GroupId(Id128([8; 16]));
    let welcome = |reply| ApprovedMlsWelcome {
        connection_id,
        invite: &invite,
        reply,
        local_id: &local_id,
        local_name: "Locally approved",
        directories: &dirs,
    };

    // A verified credential and an MLS-valid Welcome do not establish origin.
    let other_provider = RoomProvider::default();
    let (other_signer, credential) =
        issue_group_credential(&root, wire_id, &creator_cert, NOW).unwrap();
    let mut missing_origin = MlsGroup::new_with_group_id(
        &other_provider,
        &other_signer,
        &MlsGroupCreateConfig::builder()
            .ciphersuite(GROUP_CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build(),
        MlsGroupId::from_slice(wire_id.as_bytes()),
        credential,
    )
    .unwrap();
    let invalid = welcome_from(
        &mut missing_origin,
        &other_provider,
        &other_signer,
        &request,
        &invite,
    );
    let (_, candidate) = pending_join::restore(&invite, join.key, &join.sealed_package).unwrap();
    asl_groups::membership::stage_welcome(&request, &invalid, join.key.package_ref, &candidate)
        .unwrap();
    assert!(matches!(
        recipient.finish_approved_mls_welcome(&mut store, welcome(&invalid), NOW),
        Err(AslError::InvalidMessage)
    ));
    assert!(
        store
            .pending_mls_join_package(&invite, NOW)
            .unwrap()
            .is_some()
    );
    assert!(store.mls_room_snapshot(wire_id).unwrap().is_none());
    let valid = welcome_from(
        &mut creator_room,
        &provider,
        &creator_signer,
        &request,
        &invite,
    );
    let version = recipient
        .finish_approved_mls_welcome(&mut store, welcome(&valid), NOW)
        .unwrap();
    assert_eq!(version.mls_epoch, 1);
    assert!(
        store
            .pending_mls_join_package(&invite, NOW)
            .unwrap()
            .is_none()
    );
    drop(store);
    drop(recipient);

    let (_chain_db, resolver, _) = durable_directory_resolver(&root, &dir);
    let mut recipient = CoreAdmission::for_local_identity(
        &root,
        local_cert.peer_id.clone(),
        signed.clone(),
        resolver,
        NOW,
    )
    .unwrap();
    let store = local_db.open();
    let room = recipient
        .reconcile_mls_room(&store, wire_id, &dirs, NOW)
        .unwrap()
        .unwrap();
    assert_eq!(room.version, version);
    assert_eq!(room.local_id, local_id);
    assert_eq!(room.creator, creator_cert.peer_id);
    assert_eq!(room.members.len(), 2);
    assert_eq!(store.policy_revision().unwrap(), version.policy_revision);

    let renewed = signed_directory(&root, &dir, 2);
    let key =
        asl_net::dht::identity_record_key(root.agent_id(), RecordKind::DeviceDirectory).unwrap();
    let batch = recipient.handle_event(
        NetworkEvent::DhtRecordCandidate {
            candidate_id: [9; 16],
            key: key.as_ref().try_into().unwrap(),
            value: renewed.clone(),
        },
        NOW,
    );
    assert!(matches!(
        batch.events.as_slice(),
        [AdmittedNetworkEvent::DhtRecordAvailable { sequence: 2, .. }]
    ));
    assert!(matches!(
        recipient.reconcile_mls_room(&store, wire_id, &dirs, NOW),
        Err(AslError::PolicyVersionConflict)
    ));
    recipient.renew_local_mls_directory(renewed, NOW).unwrap();
    assert!(matches!(
        recipient.renew_local_mls_directory(signed, NOW),
        Err(AslError::PolicyVersionConflict)
    ));
    assert!(
        recipient
            .reconcile_mls_room(&store, wire_id, &dirs, NOW)
            .unwrap()
            .is_some()
    );
    let sql = rusqlite::Connection::open(&local_db.path).unwrap();
    assert_eq!(
        sql.query_row("SELECT state FROM asl_groups", [], |r| r
            .get::<_, String>(0))
            .unwrap(),
        "needs_sync"
    );
    sql.execute(
        "UPDATE device_identities SET revoked_at_ms=?1 WHERE peer_id=?2",
        rusqlite::params![
            NOW as i64,
            bs58::encode(creator_cert.peer_id.as_bytes()).into_string()
        ],
    )
    .unwrap();
    assert!(matches!(
        recipient.reconcile_mls_room(&store, wire_id, &dirs, NOW),
        Err(AslError::InvalidDeviceCertificate)
    ));
}

fn register_devices(store: &mut Store, root: &AgentIdentity, directory: &DeviceDirectory) {
    for cert in &directory.devices {
        store
            .register_transfer_peer(
                &DirectRequester {
                    agent: cert.agent_id,
                    peer: cert.peer_id.clone(),
                    session_expires_at_ms: NOW + LIFETIME,
                    registry_sequence: directory.registry_sequence,
                    directory_commitment: device_directory_commitment(directory).unwrap().0,
                    controller: root.controller_address(),
                },
                consensus_config().chain_id,
                cert,
                transport_ed25519_key(&cert.peer_id).unwrap(),
                NOW,
            )
            .unwrap();
    }
}

fn welcome_from(
    group: &mut MlsGroup,
    provider: &RoomProvider,
    signer: &SignatureKeyPair,
    request: &GroupPacket,
    invite: &MlsIncomingInvite,
) -> GroupPacket {
    let (package, package_ref) = read_key_package(request, provider.crypto()).unwrap();
    let (_, welcome, _) = group.add_members(provider, signer, &[package]).unwrap();
    GroupPacket {
        message_id: request.message_id,
        group_id: invite.wire_id,
        epoch: invite.base_epoch + 1,
        body: GroupBody::Membership(GroupMembership::Welcome {
            invite: invite.id,
            package_ref,
            message: welcome.to_bytes().unwrap(),
        }),
    }
}
