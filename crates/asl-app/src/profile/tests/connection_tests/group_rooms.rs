use std::collections::HashMap;

use asl_groups::{
    local_state::{RoomBinding, RoomProvider, restore},
    membership::{GROUP_CIPHERSUITE, read_key_package, sync_epoch_binding},
    pending_join,
};
use asl_store::{Store, group_state::MlsIncomingInvite, search::direct::DirectRequester};
use asl_types::protocol::{GroupBody, GroupMembership, GroupPacket};
use openmls::prelude::{GroupId as MlsGroupId, MlsGroup, MlsGroupCreateConfig, OpenMlsProvider};
use openmls_basic_credential::SignatureKeyPair;

use crate::profile::{
    MlsInviteSend, MlsJoinSend, MlsNetworkOutcome, admission::transport_ed25519_key,
    group_credential::issue_group_credential,
};

use super::*;

#[test]
fn group_add_and_welcome_require_authority_and_reconcile_after_restart() {
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
    let (creator_db, resolver, creator_proof) = durable_directory_resolver(&root, &dir);
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
    assert!(
        creator
            .issue_targeted_mls_invite(
                &mut creator_store,
                connection_id,
                wire_id,
                NOW + 60_000,
                &dirs,
                NOW,
            )
            .is_err()
    );
    admit(
        &mut creator,
        connection_id,
        &local_cert,
        creator_proof,
        &signed,
    );
    admit(
        &mut recipient,
        connection_id,
        &creator_cert,
        proof.clone(),
        &signed,
    );
    let creator_sql = rusqlite::Connection::open(&creator_db.path).unwrap();
    creator_sql
        .execute("UPDATE identity_registry_states SET sequence=8", [])
        .unwrap();
    assert!(matches!(
        creator.issue_targeted_mls_invite(
            &mut creator_store,
            connection_id,
            wire_id,
            NOW + 60_000,
            &dirs,
            NOW,
        ),
        Err(AslError::InvalidDeviceCertificate)
    ));
    creator_sql
        .execute("UPDATE identity_registry_states SET sequence=7", [])
        .unwrap();
    let invite_send = |expires_at_ms| MlsInviteSend {
        connection_id,
        wire_id,
        expires_at_ms,
    };
    let mut failed_send = None;
    assert!(matches!(
        creator.send_targeted_mls_invite(
            &mut creator_store,
            invite_send(NOW + 60_000),
            &dirs,
            NOW,
            |command| {
                failed_send = Some(command);
                Err(AslError::QuotaExceeded)
            }
        ),
        Err(AslError::QuotaExceeded)
    ));
    let Some(NetworkCommand::SendGroup {
        request: persisted_invite,
        request_handle: failed_handle,
        ..
    }) = failed_send
    else {
        panic!("expected the first Invite before enqueue failed");
    };
    drop(creator_store);
    let mut creator_store = creator_db.open();
    let mut sent = None;
    creator
        .send_targeted_mls_invite(
            &mut creator_store,
            invite_send(NOW + 90_000),
            &dirs,
            NOW,
            |command| {
                sent = Some(command);
                Ok(())
            },
        )
        .unwrap();
    let Some(NetworkCommand::SendGroup {
        connection_id: target,
        request_handle: retry_handle,
        request: invitation,
        ..
    }) = sent
    else {
        panic!("expected a targeted Invite");
    };
    assert_eq!(target, connection_id);
    assert_eq!(invitation, persisted_invite);
    assert_ne!(retry_handle, failed_handle);
    let wrong_device = GroupPacket {
        body: GroupBody::Membership(GroupMembership::Invite {
            agent: local_cert.agent_id,
            device: creator_cert.peer_id.clone(),
            expires_at_ms: NOW + 60_000,
        }),
        ..invitation.clone()
    };
    assert!(matches!(
        recipient.receive_targeted_mls_invite(&mut store, connection_id, &wrong_device, &dirs, NOW),
        Err(AslError::InvalidIdentity)
    ));
    let offer = || NetworkEvent::UnverifiedGroupRequest {
        connection_id,
        response_id: [17; 16],
        deadline_ms: NOW + 100,
        request: invitation.clone(),
    };
    let Some(MlsNetworkOutcome::InviteForApproval(invite)) = recipient
        .handle_mls_network_event(&mut store, offer(), &dirs, NOW, |command| {
            let NetworkCommand::ReplyGroup {
                connection_id: target,
                response_id,
                response,
            } = command
            else {
                panic!("invitation must only send a receipt");
            };
            assert_eq!(target, connection_id);
            assert_eq!(response_id, [17; 16]);
            invitation.match_reply(&response).unwrap();
            Ok(())
        })
        .unwrap()
    else {
        panic!("expected one local approval prompt");
    };
    assert_eq!(invite.inviter_device, creator_cert.peer_id);
    assert_eq!(invite.recipient_device, local_cert.peer_id);
    assert!(
        recipient
            .handle_mls_network_event(&mut store, offer(), &dirs, NOW, |_| Ok(()))
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        recipient.prepare_approved_mls_join(&mut store, connection_id, &invite, &dirs, NOW),
        Err(AslError::PolicyDenied)
    ));
    let recipient_sql = rusqlite::Connection::open(&local_db.path).unwrap();
    recipient_sql
        .execute("UPDATE identity_registry_states SET sequence=8", [])
        .unwrap();
    assert!(matches!(
        recipient.approve_targeted_mls_invite(
            &mut store,
            &root,
            connection_id,
            &invite,
            &dirs,
            NOW
        ),
        Err(AslError::InvalidDeviceCertificate)
    ));
    recipient_sql
        .execute("UPDATE identity_registry_states SET sequence=7", [])
        .unwrap();
    assert!(
        recipient
            .approve_targeted_mls_invite(&mut store, &root, connection_id, &invite, &dirs, NOW)
            .unwrap()
    );
    let request = recipient
        .prepare_approved_mls_join(&mut store, connection_id, &invite, &dirs, NOW)
        .unwrap();
    drop(store);
    let mut store = local_db.open();
    assert_eq!(
        recipient
            .prepare_approved_mls_join(&mut store, connection_id, &invite, &dirs, NOW)
            .unwrap(),
        request
    );
    let (join_key, sealed_package) = store
        .pending_mls_join_package(&invite, NOW)
        .unwrap()
        .unwrap();
    let local_id = GroupId(Id128([8; 16]));
    let send = |connection_id| MlsJoinSend {
        connection_id,
        invite: &invite,
        local_id: &local_id,
        local_name: "Locally approved",
    };
    let response =
        |connection_id, request_handle, response| NetworkEvent::UnverifiedGroupResponse {
            connection_id,
            request_handle,
            response,
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
    let (_, candidate) = pending_join::restore(&invite, join_key, &sealed_package).unwrap();
    asl_groups::membership::stage_welcome(&request, &invalid, join_key.package_ref, &candidate)
        .unwrap();
    let attempt = recipient
        .send_approved_mls_join(&mut store, send(connection_id), &dirs, NOW, |_| Ok(()))
        .unwrap();
    assert!(matches!(
        recipient.handle_mls_network_event(
            &mut store,
            response(connection_id, attempt, invalid),
            &dirs,
            NOW,
            |_| panic!("Welcome does not carry a send handle")
        ),
        Err(AslError::InvalidMessage)
    ));
    assert!(
        store
            .pending_mls_join_package(&invite, NOW)
            .unwrap()
            .is_some()
    );
    assert!(store.mls_room_snapshot(wire_id).unwrap().is_none());
    creator_sql
        .execute("UPDATE identity_registry_states SET sequence=8", [])
        .unwrap();
    assert!(matches!(
        creator.answer_mls_key_package(&mut creator_store, connection_id, &request, &dirs, NOW),
        Err(AslError::InvalidDeviceCertificate)
    ));
    assert_eq!(
        creator_store
            .mls_room_snapshot(wire_id)
            .unwrap()
            .unwrap()
            .version
            .mls_epoch,
        0
    );
    creator_sql
        .execute("UPDATE identity_registry_states SET sequence=7", [])
        .unwrap();
    let key_package = |deadline_ms| NetworkEvent::UnverifiedGroupRequest {
        connection_id,
        response_id: [18; 16],
        deadline_ms,
        request: request.clone(),
    };
    assert!(matches!(
        creator.handle_mls_network_event(
            &mut creator_store,
            key_package(NOW),
            &dirs,
            NOW,
            |_| panic!("expired request must not receive a Welcome")
        ),
        Err(AslError::ExpiredMessage)
    ));
    assert_eq!(
        creator_store
            .mls_room_snapshot(wire_id)
            .unwrap()
            .unwrap()
            .version
            .mls_epoch,
        0
    );
    let mut sent = None;
    assert!(
        creator
            .handle_mls_network_event(
                &mut creator_store,
                key_package(NOW + 100),
                &dirs,
                NOW,
                |command| {
                    sent = Some(command);
                    Ok(())
                },
            )
            .unwrap()
            .is_none()
    );
    let Some(NetworkCommand::ReplyGroup {
        connection_id: target,
        response_id,
        response: valid,
    }) = sent
    else {
        panic!("expected Welcome on the original reply channel");
    };
    assert_eq!(target, connection_id);
    assert_eq!(response_id, [18; 16]);
    let committed = creator_store
        .mls_room_snapshot(wire_id)
        .unwrap()
        .unwrap()
        .version;
    assert_eq!(committed.mls_epoch, 1);
    drop(creator_store);
    let mut creator_store = creator_db.open();
    creator_sql
        .execute("UPDATE identity_registry_states SET sequence=8", [])
        .unwrap();
    assert!(matches!(
        creator.answer_mls_key_package(&mut creator_store, connection_id, &request, &dirs, NOW),
        Err(AslError::InvalidDeviceCertificate)
    ));
    creator_sql
        .execute("UPDATE identity_registry_states SET sequence=7", [])
        .unwrap();
    assert_eq!(
        creator
            .answer_mls_key_package(&mut creator_store, connection_id, &request, &dirs, NOW)
            .unwrap(),
        valid,
    );
    let mut mismatched = request.clone();
    mismatched.message_id = Id128([3; 16]);
    assert!(
        creator
            .answer_mls_key_package(&mut creator_store, connection_id, &mismatched, &dirs, NOW,)
            .is_err()
    );
    let snapshot = creator_store.mls_room_snapshot(wire_id).unwrap().unwrap();
    assert_eq!(snapshot.version, committed);
    let (provider, creator_room) = restore(
        &RoomBinding {
            local_id: &creator_local_id,
            wire_id,
            device: &creator_cert.peer_id,
        },
        &snapshot,
    )
    .unwrap();
    let check_send = |expected_connection_id| {
        let request = &request;
        move |command| {
            let NetworkCommand::SendGroup {
                connection_id,
                request: sent,
                ..
            } = command
            else {
                panic!("expected the approved KeyPackage");
            };
            assert_eq!(connection_id, expected_connection_id);
            assert_eq!(&sent, request);
            Ok(())
        }
    };
    let never_send = |_| panic!("receiving a Welcome must not send anything");
    let retry_at = NOW + 10_001;
    let first = recipient
        .send_approved_mls_join(
            &mut store,
            send(connection_id),
            &dirs,
            NOW,
            check_send(connection_id),
        )
        .unwrap();
    let first_reply = || response(connection_id, first, valid.clone());
    assert!(
        recipient
            .handle_mls_network_event(&mut store, first_reply(), &dirs, retry_at, never_send)
            .unwrap()
            .is_none()
    );
    let second = recipient
        .send_approved_mls_join(
            &mut store,
            send(connection_id),
            &dirs,
            retry_at,
            check_send(connection_id),
        )
        .unwrap();
    assert_ne!(first, second);
    assert!(
        recipient
            .handle_mls_network_event(&mut store, first_reply(), &dirs, retry_at, never_send)
            .unwrap()
            .is_none()
    );
    recipient.handle_event(
        NetworkEvent::RequestFailed {
            connection_id,
            request_id: second,
            protocol: crate::ipc::NetworkProtocol::Group,
            code: crate::ipc::NetworkErrorCode::TimedOut,
        },
        retry_at,
    );
    assert!(
        recipient
            .handle_mls_network_event(
                &mut store,
                response(connection_id, second, valid.clone()),
                &dirs,
                retry_at,
                never_send
            )
            .unwrap()
            .is_none()
    );
    let disconnected = recipient
        .send_approved_mls_join(
            &mut store,
            send(connection_id),
            &dirs,
            retry_at,
            check_send(connection_id),
        )
        .unwrap();
    recipient.handle_event(NetworkEvent::PeerDisconnected { connection_id }, retry_at);
    let reconnect = [19; 16];
    admit(&mut recipient, reconnect, &creator_cert, proof, &signed);
    assert!(matches!(
        recipient.send_approved_mls_join(&mut store, send(reconnect), &dirs, retry_at, |_| Err(
            AslError::QuotaExceeded
        )),
        Err(AslError::QuotaExceeded)
    ));
    let current = recipient
        .send_approved_mls_join(
            &mut store,
            send(reconnect),
            &dirs,
            retry_at,
            check_send(reconnect),
        )
        .unwrap();
    assert_ne!(current, disconnected);
    for (connection, handle) in [(reconnect, disconnected), (connection_id, current)] {
        assert!(
            recipient
                .handle_mls_network_event(
                    &mut store,
                    response(connection, handle, valid.clone()),
                    &dirs,
                    retry_at,
                    never_send
                )
                .unwrap()
                .is_none()
        );
    }
    let wrong_group = GroupPacket {
        group_id: Hash32([11; 32]),
        ..valid.clone()
    };
    assert!(matches!(
        recipient.handle_mls_network_event(
            &mut store,
            response(reconnect, current, wrong_group),
            &dirs,
            retry_at,
            never_send
        ),
        Err(AslError::InvalidMessage)
    ));
    assert!(store.mls_room_snapshot(wire_id).unwrap().is_none());
    let reply = || response(reconnect, current, valid.clone());
    let Some(MlsNetworkOutcome::Joined {
        local_id: joined_id,
        version,
    }) = recipient
        .handle_mls_network_event(&mut store, reply(), &dirs, retry_at, never_send)
        .unwrap()
    else {
        panic!("only the live matched reply should commit the Welcome");
    };
    assert_eq!(joined_id, local_id);
    assert!(
        recipient
            .handle_mls_network_event(&mut store, reply(), &dirs, retry_at, never_send)
            .unwrap()
            .is_none()
    );
    assert_eq!(version.mls_epoch, 1);
    let (join_provider, joined_room) = restore(
        &RoomBinding {
            local_id: &local_id,
            wire_id,
            device: &local_cert.peer_id,
        },
        &store.mls_room_snapshot(wire_id).unwrap().unwrap(),
    )
    .unwrap();
    assert_eq!(
        sync_epoch_binding(&creator_room, provider.crypto()).unwrap(),
        sync_epoch_binding(&joined_room, join_provider.crypto()).unwrap(),
    );
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

fn admit(
    admission: &mut CoreAdmission,
    connection_id: [u8; 16],
    remote: &DeviceCertificate,
    proof: IdentityProofV1,
    signed: &[u8],
) {
    admission.handle_event(
        NetworkEvent::TransportConnected {
            connection_id,
            peer_id: remote.peer_id.clone(),
        },
        NOW,
    );
    let batch = admission.handle_event(
        NetworkEvent::UnverifiedControlRequest {
            connection_id,
            response_id: [5; 16],
            request: WireFrame::Hello(hello(remote)),
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
    let proof = crate::chain::identity_proof_to_wire(request, proof, signed.to_vec());
    let admitted = admission.handle_event(
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
