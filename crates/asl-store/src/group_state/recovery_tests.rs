use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId, Signature65},
    protocol::{DeviceCertificate, MAX_GROUP_MEMBERS},
    task::GroupId,
};
use rusqlite::params;

use super::{
    MlsMemberEvidence, MlsRoomUpdate, PendingMlsRoom,
    tests::{register_agent_peer, register_peer, test_peer},
    transition::peer_text,
};
use crate::{Store, chain::agent_text, open_store};

pub(super) fn register_evidence(
    store: &Store,
    agent: AgentId,
    peer: &PeerId,
    expires_at_ms: u64,
) -> MlsMemberEvidence {
    register_agent_peer(store, agent, peer, 1);
    let certificate = DeviceCertificate {
        agent_id: agent,
        peer_id: peer.clone(),
        serial: 1,
        issued_at_ms: 10,
        expires_at_ms,
        signature: Signature65([1; 65]),
    };
    store
        .connection
        .execute_batch(
            "INSERT OR IGNORE INTO chain_state_cache VALUES
         (1,zeroblob(20),zeroblob(32),0,zeroblob(32),zeroblob(32),zeroblob(32),X'',0);",
        )
        .unwrap();
    store
        .connection
        .execute(
            "INSERT INTO identity_registry_states VALUES
         (?1,1,zeroblob(20),zeroblob(32),1,'active',0,zeroblob(32),0)",
            [agent_text(agent)],
        )
        .unwrap();
    store.connection.execute(
        "UPDATE device_identities SET certificate_cbor=?2,certificate_expires_ms=?3 WHERE peer_id=?1",
        params![peer_text(peer), certificate.to_canonical_cbor().unwrap(), expires_at_ms as i64],
    ).unwrap();
    MlsMemberEvidence {
        certificate,
        registry_sequence: 1,
        controller: [0; 20],
        directory_commitment: Hash32([0; 32]),
    }
}

#[test]
fn reconciliation_reads_a_bounded_active_projection_of_the_paused_room() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("recovery.sqlite3");
    let mut store = open_store(&path).unwrap();
    let creator = test_peer(1);
    let member = test_peer(2);
    let invited = test_peer(3);
    register_peer(&store, &creator, 1);
    register_peer(&store, &member, 2);
    register_peer(&store, &invited, 3);
    let local_id = GroupId(Id128([4; 16]));
    let local_text = hex::encode(local_id.0.as_bytes());
    let wire_id = Hash32([5; 32]);
    assert!(
        store
            .mls_room_for_reconciliation(wire_id)
            .unwrap()
            .is_none()
    );
    store
        .stage_mls_room(PendingMlsRoom {
            local_id: &local_id,
            wire_id,
            creator: &creator,
            local_name: "Paused",
            mls_epoch: 4,
            sealed_snapshot: b"staged",
        })
        .unwrap();
    assert!(matches!(
        store.mls_room_for_reconciliation(wire_id),
        Err(AslError::InvalidDatabase)
    ));
    let base = store.mls_room_snapshot(wire_id).unwrap().unwrap().version;
    let version = store
        .commit_mls_room_candidate(MlsRoomUpdate {
            local_id: &local_id,
            wire_id,
            expected: base,
            mls_epoch: 4,
            sealed_snapshot: b"projected",
            members: &[creator.clone(), member.clone()],
            event: None,
        })
        .unwrap();
    store
        .connection
        .execute(
            "INSERT INTO group_members(group_id,peer_id,role,state)
             VALUES (?1,?2,'member','invited')",
            params![local_text, peer_text(&invited)],
        )
        .unwrap();
    drop(store);

    let store = open_store(&path).unwrap();
    let room = store.mls_room_for_reconciliation(wire_id).unwrap().unwrap();
    assert_eq!(room.snapshot.local_id, local_id);
    assert_eq!(room.snapshot.version, version);
    assert_eq!(room.snapshot.sealed_snapshot, b"projected");
    assert_eq!(room.creator, creator);
    assert_eq!(room.members.len(), 2);
    assert!(room.members.contains(&creator));
    assert!(room.members.contains(&member));

    let set_role = |peer: &PeerId, role: &str| {
        store
            .connection
            .execute(
                "UPDATE group_members SET role=?2 WHERE group_id=?1 AND peer_id=?3",
                params![local_text, role, peer_text(peer)],
            )
            .unwrap();
    };
    let invalid = || {
        assert!(matches!(
            store.mls_room_for_reconciliation(wire_id),
            Err(AslError::InvalidDatabase)
        ));
    };
    set_role(&member, "creator");
    invalid();
    set_role(&creator, "member");
    invalid();
    set_role(&creator, "creator");
    set_role(&member, "member");

    for index in 0..(MAX_GROUP_MEMBERS - 1) {
        let peer = test_peer(u8::try_from(index + 10).unwrap());
        register_peer(&store, &peer, i64::try_from(index + 10).unwrap());
        store
            .connection
            .execute(
                "INSERT INTO group_members(group_id,peer_id,role,state)
                 VALUES (?1,?2,'member','active')",
                params![local_text, peer_text(&peer)],
            )
            .unwrap();
    }
    invalid();
    store
        .connection
        .execute("UPDATE asl_groups SET state='active'", [])
        .unwrap();
    assert!(
        store
            .mls_room_for_reconciliation(wire_id)
            .unwrap()
            .is_none()
    );
}

#[test]
fn reconciliation_requires_exact_live_device_and_chain_records() {
    let directory = tempfile::tempdir().unwrap();
    let store = open_store(&directory.path().join("devices.sqlite3")).unwrap();
    let mut evidence = register_evidence(&store, AgentId([1; 32]), &test_peer(1), 20);
    let peer = peer_text(&evidence.certificate.peer_id);
    let matches = |member: &MlsMemberEvidence, chain, now| {
        store.require_mls_member(member, chain, now).is_ok()
    };
    assert!(matches(&evidence, 1, 10));
    assert!(!matches(&evidence, 1, 9));
    assert!(!matches(&evidence, 1, 20));
    assert!(!matches(&evidence, 2, 10));
    evidence.registry_sequence = 2;
    assert!(!matches(&evidence, 1, 10));
    evidence.registry_sequence = 1;
    evidence.certificate.signature = Signature65([2; 65]);
    assert!(!matches(&evidence, 1, 10));
    evidence.certificate.signature = Signature65([1; 65]);

    store
        .connection
        .execute(
            "UPDATE device_identities SET revoked_at_ms=10 WHERE peer_id=?1",
            [&peer],
        )
        .unwrap();
    assert!(!matches(&evidence, 1, 10));
    store
        .connection
        .execute(
            "UPDATE device_identities SET revoked_at_ms=NULL WHERE peer_id=?1",
            [&peer],
        )
        .unwrap();
    store
        .connection
        .execute("DELETE FROM peers WHERE peer_id=?1", [&peer])
        .unwrap();
    assert!(!matches(&evidence, 1, 10));
}
