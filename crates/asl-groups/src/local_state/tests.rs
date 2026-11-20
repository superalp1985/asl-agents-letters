use asl_types::ids::Id128;
use openmls::prelude::{
    BasicCredential, CredentialWithKey, LeafNodeParameters, MlsGroupCreateConfig,
};
use openmls_basic_credential::SignatureKeyPair;

use super::*;
use crate::membership::GROUP_CIPHERSUITE;
use asl_store::group_state::RoomVersion;

const FIRST: Hash32 = Hash32([1; 32]);
const SECOND: Hash32 = Hash32([2; 32]);

#[test]
fn history_rejects_gaps_and_repeats_without_mutation() {
    let mut history = SyncHistory::default();
    assert_eq!(history.digest(7), None);
    history.append(7, FIRST).unwrap();
    for epoch in [6, 7, 9] {
        assert!(history.append(epoch, SECOND).is_err());
    }
    history.append(8, SECOND).unwrap();
    assert_eq!(history.digest(6), None);
    assert_eq!(history.digest(7), Some(FIRST));
    assert_eq!(history.digest(8), Some(SECOND));
    assert_eq!(history.digest(9), None);
}

#[test]
fn history_evicts_only_after_a_valid_append_at_capacity() {
    let mut history = SyncHistory::default();
    for epoch in 10..=265 {
        history.append(epoch, FIRST).unwrap();
    }
    assert!(history.append(267, SECOND).is_err());
    assert_eq!(history.digest(10), Some(FIRST));
    history.append(266, SECOND).unwrap();
    assert_eq!(history.digest(10), None);
    assert_eq!(history.digest(11), Some(FIRST));
    assert_eq!(history.digest(265), Some(FIRST));
    assert_eq!(history.digest(266), Some(SECOND));
}

#[test]
fn history_rejects_an_epoch_with_no_representable_successor() {
    let mut history = SyncHistory::default();
    assert!(history.append(u64::MAX, FIRST).is_err());
    history.append(u64::MAX - 1, FIRST).unwrap();
    assert!(history.append(u64::MAX, SECOND).is_err());
    assert_eq!(history.digest(u64::MAX - 1), Some(FIRST));
    assert_eq!(history.digest(u64::MAX), None);
    assert!(history.matches_epoch(u64::MAX));
}

#[test]
fn snapshot_history_is_versioned_and_must_end_at_the_saved_epoch() {
    let mut history = SyncHistory::default();
    assert!(read_history(FORMAT_V1, 9, None).unwrap().is_empty());
    assert!(
        read_history(FORMAT_V2, 9, Some(&history.0))
            .unwrap()
            .is_empty()
    );
    assert!(read_history(FORMAT_V2, 9, None).is_err());

    history.append(7, FIRST).unwrap();
    history.append(8, SECOND).unwrap();
    assert!(read_history(FORMAT_V1, 9, Some(&history.0)).is_err());
    assert!(read_history(FORMAT_V2, 8, Some(&history.0)).is_err());
    assert!(read_history(FORMAT_V2, 10, Some(&history.0)).is_err());
    let restored = read_history(FORMAT_V2, 9, Some(&history.0)).unwrap();
    assert_eq!(restored.digest(7), Some(FIRST));
    assert_eq!(restored.digest(8), Some(SECOND));
}

#[test]
fn snapshot_rejects_overlong_or_overflowing_history() {
    let mut window = HistoryWindow {
        first_base_epoch: 3,
        digests: VecDeque::from(vec![FIRST; 257]),
        downloaded: None,
    };
    assert!(read_history(FORMAT_V2, 260, Some(&window)).is_err());
    window.first_base_epoch = u64::MAX;
    window.digests.truncate(1);
    assert!(read_history(FORMAT_V2, 0, Some(&window)).is_err());
}

#[test]
fn catchup_budget_survives_snapshot_reopen_and_window_eviction() {
    let mut history = SyncHistory::default();
    for epoch in 10..265 {
        history.append_downloaded(epoch, FIRST).unwrap();
    }
    assert_eq!(history.remaining_catchup(), 1);
    assert!(read_history(FORMAT_V2, 265, Some(&history.0)).is_err());
    let mut reopened = read_history(FORMAT_V3, 265, Some(&history.0)).unwrap();
    assert_eq!(reopened.remaining_catchup(), 1);
    reopened.append_downloaded(265, SECOND).unwrap();
    reopened.append(266, FIRST).unwrap();
    assert_eq!(reopened.digest(10), None);
    assert_eq!(reopened.remaining_catchup(), 0);
    assert!(matches!(
        reopened.append_downloaded(267, SECOND),
        Err(AslError::QuotaExceeded)
    ));
    assert_eq!(reopened.digest(267), None);
}

#[test]
fn legacy_window_is_conservatively_charged_until_the_first_new_sync() {
    let mut history = SyncHistory::default();
    history.append(7, FIRST).unwrap();
    let mut reopened = read_history(FORMAT_V2, 8, Some(&history.0)).unwrap();
    assert_eq!(reopened.remaining_catchup(), MLS_SYNC_MAX_STEPS - 1);
    assert!(reopened.append_downloaded(9, SECOND).is_err());
    assert_eq!(reopened.remaining_catchup(), MLS_SYNC_MAX_STEPS - 1);
    reopened.append_downloaded(8, SECOND).unwrap();
    assert_eq!(reopened.remaining_catchup(), MLS_SYNC_MAX_STEPS - 2);
    assert!(read_history(FORMAT_V3, 8, Some(&history.0)).is_err());
    reopened.0.downloaded = Some(3);
    assert!(read_history(FORMAT_V3, 9, Some(&reopened.0)).is_err());
}

#[test]
fn sealed_history_cannot_be_dropped_by_the_legacy_api() {
    let provider = RoomProvider::default();
    let signer = SignatureKeyPair::new(GROUP_CIPHERSUITE.signature_algorithm()).unwrap();
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(GROUP_CIPHERSUITE)
        .build();
    let credential = CredentialWithKey {
        credential: BasicCredential::new(vec![1; 32]).into(),
        signature_key: signer.to_public_vec().into(),
    };
    let mut group = MlsGroup::new_with_group_id(
        &provider,
        &signer,
        &config,
        MlsGroupId::from_slice(FIRST.as_bytes()),
        credential,
    )
    .unwrap();
    group
        .self_update(&provider, &signer, LeafNodeParameters::default())
        .unwrap();
    group.merge_pending_commit(&provider).unwrap();

    let mut peer_bytes = vec![0x12, 0x20];
    peer_bytes.extend_from_slice(SECOND.as_bytes());
    let device = PeerId::from_bytes(peer_bytes).unwrap();
    let local_id = GroupId(Id128([3; 16]));
    let binding = RoomBinding {
        local_id: &local_id,
        wire_id: FIRST,
        device: &device,
    };
    let mut history = SyncHistory::default();
    history.append_downloaded(0, SECOND).unwrap();
    let sealed_snapshot = seal_with_history(&binding, 1, &group, &provider, &history).unwrap();
    assert!(seal(&binding, 2, &group, &provider).is_err());
    let row = MlsRoomSnapshot {
        local_id: local_id.clone(),
        sealed_snapshot,
        version: RoomVersion {
            revision: 1,
            mls_epoch: 1,
            membership_epoch: 1,
            policy_revision: 1,
        },
    };
    assert!(matches!(
        restore(&binding, &row),
        Err(AslError::IncompatibleVersion)
    ));
    let (provider, group, history) = restore_with_history(&binding, &row).unwrap();
    assert_eq!(history.digest(0), Some(SECOND));
    assert_eq!(history.remaining_catchup(), MLS_SYNC_MAX_STEPS - 1);
    assert!(seal(&binding, 2, &group, &provider).is_err());
    assert!(seal_with_history(&binding, 2, &group, &provider, &SyncHistory::default()).is_err());
    let mut downgrade = history.clone();
    downgrade.0.downloaded = None;
    assert!(seal_with_history(&binding, 2, &group, &provider, &downgrade).is_err());
    assert!(seal_with_history(&binding, 2, &group, &provider, &history).is_ok());
}

fn read_history(
    format: &str,
    epoch: u64,
    history: Option<&HistoryWindow>,
) -> Result<SyncHistory, AslError> {
    let snapshot = Snapshot {
        format,
        room: GroupId(Id128([1; 16])),
        wire: Hash32([3; 32]),
        device: Bytes::new(&[4; 16]),
        revision: 1,
        epoch,
        records: Vec::<(&Bytes, &Bytes)>::new(),
        history,
    };
    let plaintext = cbor2::to_vec(&snapshot).unwrap();
    decode_snapshot(&plaintext).map(|(_, history)| history)
}
