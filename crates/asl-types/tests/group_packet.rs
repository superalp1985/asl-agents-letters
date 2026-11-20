use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId},
    protocol::{
        GroupBody, GroupEnvelope, GroupMembership as Member, GroupOperation, GroupPacket,
        MAX_GROUP_MLS_OBJECT_BYTES, MAX_GROUP_PAYLOAD_BYTES, WireFrame, decode_frame, encode_frame,
    },
};

fn membership(body: Member) -> GroupPacket {
    GroupPacket {
        message_id: Id128([1; 16]),
        group_id: Hash32([2; 32]),
        epoch: 7,
        body: GroupBody::Membership(body),
    }
}

#[test]
fn membership_uses_versioned_cbor_without_changing_the_outer_frame() {
    let receipt = membership(Member::Receipt);
    let envelope = receipt.clone().into_envelope().unwrap();
    assert_eq!(
        envelope,
        GroupEnvelope {
            message_id: Id128([1; 16]),
            group_id: Hash32([2; 32]),
            epoch: 7,
            operation: GroupOperation::Membership,
            ciphertext: vec![0x82, 1, 8],
        }
    );
    let frame = WireFrame::GroupEnvelope(envelope.clone());
    let WireFrame::GroupEnvelope(decoded) = decode_frame(&encode_frame(&frame).unwrap()).unwrap()
    else {
        panic!("expected a group envelope");
    };
    assert_eq!(decoded, envelope);
    assert_eq!(GroupPacket::from_envelope(decoded).unwrap(), receipt);

    let mut peer = vec![0x12, 0x20];
    peer.extend_from_slice(&[4; 32]);
    let invite = Member::Invite {
        agent: AgentId([3; 32]),
        device: PeerId::from_bytes(peer.clone()).unwrap(),
        expires_at_ms: 500,
    };
    let mut expected = vec![0x85, 1, 0, 0x58, 0x20];
    expected.extend_from_slice(&[3; 32]);
    expected.extend_from_slice(&[0x58, 0x22]);
    expected.extend_from_slice(&peer);
    expected.extend_from_slice(&[0x19, 1, 0xf4]);
    assert_eq!(invite.clone().encode().unwrap(), expected);
    assert_eq!(Member::decode(&expected).unwrap(), invite);
}

#[test]
fn membership_rejects_free_text_noncanonical_and_unknown_versions() {
    for bytes in [
        &[0x83, 1, 3, 0x61, b'x'][..],
        &[0x82, 0x18, 1, 8],
        &[0x83, 1, 8, 0],
        &[0x82, 1, 9],
        &[0x82, 1, 8, 0],
    ] {
        assert!(matches!(
            Member::decode(bytes),
            Err(AslError::InvalidMessage)
        ));
    }
    assert!(matches!(
        Member::decode(&[0x82, 2, 8]),
        Err(AslError::IncompatibleVersion)
    ));
}

#[test]
fn membership_reserves_framing_space_at_the_outer_payload_limit() {
    let mut welcome = membership(Member::Welcome {
        invite: Id128([3; 16]),
        package_ref: Hash32([4; 32]),
        message: vec![0; MAX_GROUP_MLS_OBJECT_BYTES],
    });
    let envelope = welcome.clone().into_envelope().unwrap();
    assert!(envelope.ciphertext.len() <= MAX_GROUP_PAYLOAD_BYTES);
    assert_eq!(GroupPacket::from_envelope(envelope).unwrap(), welcome);
    let GroupBody::Membership(Member::Welcome { message, .. }) = &mut welcome.body else {
        unreachable!();
    };
    message.push(0);
    assert!(welcome.into_envelope().is_err());
}

#[test]
fn welcome_matches_the_complete_room_request_invite_and_next_epoch() {
    let request = membership(Member::KeyPackage {
        invite: Id128([3; 16]),
        message: vec![1],
    });
    let reply = GroupPacket {
        epoch: 8,
        ..membership(Member::Welcome {
            invite: Id128([3; 16]),
            package_ref: Hash32([4; 32]),
            message: vec![1],
        })
    };
    request.match_reply(&reply).unwrap();
    let mut wrong_room = reply.group_id;
    wrong_room.0[31] ^= 1;
    for mismatch in [
        GroupPacket {
            group_id: wrong_room,
            ..reply.clone()
        },
        GroupPacket {
            message_id: Id128([5; 16]),
            ..reply.clone()
        },
        GroupPacket {
            epoch: 7,
            ..reply.clone()
        },
        GroupPacket {
            epoch: 9,
            ..reply.clone()
        },
        GroupPacket {
            epoch: 8,
            ..membership(Member::Welcome {
                invite: Id128([5; 16]),
                package_ref: Hash32([4; 32]),
                message: vec![1],
            })
        },
        membership(Member::Receipt),
    ] {
        assert!(request.match_reply(&mismatch).is_err());
    }
    assert!(reply.validate_request().is_err());
}

#[test]
fn sync_replies_are_for_one_base_epoch_and_at_head_matches_the_binding() {
    let epoch_binding = Hash32([3; 32]);
    let request = membership(Member::SyncRequest { epoch_binding });
    for response in [
        Member::SyncCommit(vec![1]),
        Member::AtHead { epoch_binding },
        Member::SyncUnavailable,
    ] {
        let response = membership(response);
        request.match_reply(&response).unwrap();
        assert!(response.validate_request().is_err());
        assert!(
            request
                .match_reply(&GroupPacket {
                    epoch: 8,
                    ..response
                })
                .is_err()
        );
    }
    for response in [
        Member::AtHead {
            epoch_binding: Hash32([4; 32]),
        },
        Member::Commit(vec![1]),
        Member::Receipt,
    ] {
        assert!(request.match_reply(&membership(response)).is_err());
    }
}
