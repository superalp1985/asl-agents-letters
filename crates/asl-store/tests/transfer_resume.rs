#![cfg(windows)]

use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use asl_policy::Audience;
use asl_store::{
    dashboard::Dashboard,
    open_store,
    resources::SnapshotBroker,
    transfers::{
        DownloadBroker, DownloadMode, DownloadRequest, DownloadStart, GroupTransferBinding,
        UploadAdmission, UploadBinding, UploadMode,
    },
};
use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId},
    manifest::{Manifest, content_id, encode_manifest},
    task::{GroupId, TransferId},
};
use rusqlite::Connection;
use tempfile::TempDir;

struct Fixture {
    home: PathBuf,
    destination: PathBuf,
    write_grant: Id128,
    peer: PeerId,
    _temp: TempDir,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let destination = temp.path().join("downloads");
        fs::create_dir_all(home.join("state")).unwrap();
        fs::create_dir_all(&destination).unwrap();
        let peer = peer();
        let broker = DownloadBroker::open(&home).unwrap();
        drop(broker);
        let db = Connection::open(home.join("state/asl.sqlite3")).unwrap();
        seed_peer(&db, &peer, 3);
        drop(db);
        let mut snapshots = SnapshotBroker::open(&home).unwrap();
        let write_grant = snapshots
            .authorize_inbox_directory(&destination, 4 << 20)
            .unwrap();
        Self {
            home,
            destination,
            write_grant,
            peer,
            _temp: temp,
        }
    }

    fn open(&self) -> DownloadBroker {
        DownloadBroker::open(&self.home).unwrap()
    }

    fn open_with_mode(&self, mode: DownloadMode) -> DownloadBroker {
        let broker = self.open();
        broker.set_download_mode(mode).unwrap();
        broker
    }

    fn db(&self) -> Connection {
        Connection::open(self.home.join("state/asl.sqlite3")).unwrap()
    }

    fn download_counts(&self) -> (i64, i64, i64) {
        self.db()
            .query_row(
                "SELECT (SELECT count(*) FROM tasks), (SELECT count(*) FROM transfers),
                        (SELECT count(*) FROM reservations)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap()
    }

    fn assert_no_download(&self) {
        assert_eq!(self.download_counts(), (0, 0, 0));
        assert!(fs::read_dir(&self.destination).unwrap().next().is_none());
    }

    fn valid_request(&self, bytes: &[u8]) -> DownloadRequest {
        self.request(bytes, *blake3::hash(bytes).as_bytes())
    }

    fn request(&self, bytes: &[u8], declared_file_hash: [u8; 32]) -> DownloadRequest {
        let chunk_hashes = bytes
            .chunks(1_048_576)
            .map(|chunk| *blake3::hash(chunk).as_bytes())
            .collect();
        let manifest = encode_manifest(&Manifest {
            file_size: bytes.len() as u64,
            file_hash: declared_file_hash,
            chunk_hashes,
        })
        .unwrap();
        DownloadRequest {
            content_id: Hash32(asl_types::manifest::content_id(&manifest)),
            manifest,
            write_grant_id: self.write_grant,
            destination_relative: PathBuf::from("item.bin"),
            sources: vec![self.peer.clone()],
            group: None,
        }
    }
}

#[test]
fn recovered_download_decision_is_read_only_and_bound_to_the_original_grant() {
    let fixture = Fixture::new();
    let mut broker = fixture.open_with_mode(DownloadMode::Ask);
    let request = fixture.valid_request(b"awaiting approval");
    let DownloadStart::Pending {
        approval_id,
        transfer_id,
    } = broker.request_download(&request).unwrap()
    else {
        panic!("expected a pending decision")
    };
    let mut store = open_store(&fixture.home.join("state/asl.sqlite3")).unwrap();
    let subject = [15; 32];
    store.configure_mcp_recovery(Some(&subject), 0).unwrap();
    assert!(matches!(
        store.recovery_download_decision(approval_id, &subject),
        Err(AslError::NotFound)
    ));
    store
        .authorize_recovery_download_decision(approval_id)
        .unwrap();
    assert!(matches!(
        store.recovery_download_decision(approval_id, &[16; 32]),
        Err(AslError::PolicyDenied)
    ));
    let pending = store
        .recovery_download_decision(approval_id, &subject)
        .unwrap();
    assert_eq!(pending.transfer_id, transfer_id);
    assert_eq!(pending.state, "awaiting_approval");
    fixture.assert_no_download();
    store.decide_download(approval_id, true).unwrap();
    drop(store);
    let mut store = open_store(&fixture.home.join("state/asl.sqlite3")).unwrap();
    store.configure_mcp_recovery(Some(&subject), 1).unwrap();
    assert_eq!(
        store
            .recovery_download_decision(approval_id, &subject)
            .unwrap()
            .state,
        "approved"
    );
    fixture.assert_no_download();
    store.decide_download(approval_id, false).unwrap();
    assert_eq!(
        store
            .recovery_download_decision(approval_id, &subject)
            .unwrap()
            .state,
        "denied"
    );
    fixture.assert_no_download();
    store.configure_mcp_recovery(Some(&[16; 32]), 2).unwrap();
    assert!(matches!(
        store.recovery_download_decision(approval_id, &[16; 32]),
        Err(AslError::NotFound)
    ));
}

#[test]
fn expired_or_revoked_recovery_decisions_do_not_remain_visible() {
    let f = Fixture::new();
    let mut broker = f.open_with_mode(DownloadMode::Ask);
    let store = open_store(&f.home.join("state/asl.sqlite3")).unwrap();
    let subject = [15; 32];
    store.configure_mcp_recovery(Some(&subject), 0).unwrap();
    let offer = |broker: &mut DownloadBroker, body: &[u8]| {
        let DownloadStart::Pending { approval_id, .. } =
            broker.request_download(&f.valid_request(body)).unwrap()
        else {
            panic!("expected pending approval");
        };
        store
            .authorize_recovery_download_decision(approval_id)
            .unwrap();
        approval_id
    };
    let expired = offer(&mut broker, b"expires");
    let revoked = offer(&mut broker, b"revoked");
    let db = f.db();
    let expiry: i64 = db
        .query_row(
            "UPDATE transfer_consents SET expires_at_ms=created_at_ms
         WHERE approval_id=?1 RETURNING expires_at_ms",
            [hex::encode(expired.0)],
            |row| row.get(0),
        )
        .unwrap();
    assert!(matches!(
        store.recovery_download_decision(expired, &subject),
        Err(AslError::ExpiredMessage)
    ));
    // Changing the underlying deadline after expiry does not restore visibility.
    db.execute(
        "UPDATE transfer_consents SET expires_at_ms=?2 WHERE approval_id=?1",
        rusqlite::params![hex::encode(expired.0), expiry + 300_000],
    )
    .unwrap();
    assert!(matches!(
        store.recovery_download_decision(expired, &subject),
        Err(AslError::NotFound)
    ));
    SnapshotBroker::open(&f.home)
        .unwrap()
        .revoke_inbox_directory(f.write_grant)
        .unwrap();
    assert!(matches!(
        store.recovery_download_decision(revoked, &subject),
        Err(AslError::NotFound)
    ));
    f.assert_no_download();
}

#[test]
fn observing_expired_recovery_consent_removes_it() {
    let fixture = Fixture::new();
    let mut broker = fixture.open();
    let info = broker
        .begin_download(&fixture.valid_request(b"bytes"))
        .unwrap();
    let store = open_store(&fixture.home.join("state/asl.sqlite3")).unwrap();
    let subject = [15; 32];
    store.configure_mcp_recovery(Some(&subject), 0).unwrap();
    store
        .authorize_recovery_download(&info.transfer_id)
        .unwrap();
    assert!(store.recovery_download(&info.transfer_id, &subject).is_ok());
    fixture
        .db()
        .execute("UPDATE mcp_recovery_downloads SET expires_at_ms=0", [])
        .unwrap();
    assert!(matches!(
        store.recovery_download(&info.transfer_id, &subject),
        Err(AslError::NotFound)
    ));
    let remaining: i64 = fixture
        .db()
        .query_row("SELECT count(*) FROM mcp_recovery_downloads", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(remaining, 0);
}

#[test]
fn dashboard_shows_downloads_that_are_not_local_snapshots() {
    let fixture = Fixture::new();
    let mut broker = fixture.open();
    let bytes = b"download in progress";
    let info = broker
        .begin_download(&fixture.valid_request(bytes))
        .unwrap();

    let dashboard = Dashboard::load(&fixture.home.join("state/asl.sqlite3")).unwrap();
    let [row] = dashboard.transfers.as_slice() else {
        panic!("expected one projected download");
    };
    assert_eq!(row.transfer_id, hex::encode(info.transfer_id.0.as_bytes()));
    assert_eq!(
        (row.durable_bytes, row.file_size, row.source_count),
        (0, bytes.len() as u64, 1)
    );
}

#[test]
fn a_second_download_broker_cannot_recover_while_the_owner_is_live() {
    let f = Fixture::new();
    let bytes = b"assigned to the live broker";
    let mut broker = f.open_with_mode(DownloadMode::Automatic);
    let info = broker.begin_download(&f.valid_request(bytes)).unwrap();
    broker
        .assign_chunk(info.transfer_id.clone(), &f.peer, 0)
        .unwrap();

    assert!(matches!(
        DownloadBroker::open(&f.home),
        Err(AslError::InvalidPolicyState)
    ));
    broker
        .write_chunk(info.transfer_id.clone(), &f.peer, 0, bytes)
        .unwrap();
    drop(broker);

    assert!(f.home.join("state/download-worker.lock").is_file());
    let reopened = f.open();
    assert_eq!(reopened.info(&info.transfer_id).unwrap().state, "complete");
}

#[test]
fn group_epoch_change_invalidates_transfer_chunks() {
    let f = Fixture::new();
    let group = seed_group(&f, 1);
    let bytes = b"group-scoped chunk";
    let mut request = f.request(bytes, *blake3::hash(bytes).as_bytes());
    request.group = Some(GroupTransferBinding {
        group_id: group.clone(),
        membership_epoch: 1,
    });
    let mut broker = f.open_with_mode(DownloadMode::Automatic);
    let info = broker.begin_download(&request).unwrap();
    broker
        .assign_chunk(info.transfer_id.clone(), &f.peer, 0)
        .unwrap();
    f.db()
        .execute(
            "UPDATE asl_groups
             SET state='needs_sync',membership_epoch=2,updated_at_ms=updated_at_ms+1
             WHERE group_id=?1",
            [hex::encode(group.0.as_bytes())],
        )
        .unwrap();

    assert!(matches!(
        broker.write_chunk(info.transfer_id, &f.peer, 0, bytes),
        Err(AslError::PolicyDenied)
    ));
}

#[test]
fn recovery_retires_a_stale_group_before_publishing_and_completes_other_work() {
    let f = Fixture::new();
    let group = seed_group(&f, 1);
    let mut broker = f.open_with_mode(DownloadMode::Automatic);
    let mut stale = f.valid_request(b"group file");
    stale.group = Some(GroupTransferBinding {
        group_id: group.clone(),
        membership_epoch: 1,
    });
    let mut valid = f.valid_request(b"independent file");
    valid.destination_relative = "independent.bin".into();
    let stale = broker.begin_download(&stale).unwrap();
    let valid = broker.begin_download(&valid).unwrap();
    for (transfer, bytes) in [
        (&stale.transfer_id, b"group file".as_slice()),
        (&valid.transfer_id, b"independent file".as_slice()),
    ] {
        broker.assign_chunk(transfer.clone(), &f.peer, 0).unwrap();
        broker
            .write_chunk(transfer.clone(), &f.peer, 0, bytes)
            .unwrap();
    }
    drop(broker);
    let db = f.db();
    db.execute(
        "UPDATE asl_groups SET membership_epoch=membership_epoch+1 WHERE group_id=?1",
        [hex::encode(group.0.as_bytes())],
    )
    .unwrap();

    let broker = f.open();
    assert!(matches!(
        broker.schedule(&stale.transfer_id),
        Err(AslError::PolicyDenied)
    ));
    let reservation: String = db
        .query_row(
            "SELECT r.state FROM transfers t JOIN reservations r USING(reservation_id)
         WHERE t.transfer_id=lower(hex(?1))",
            [stale.transfer_id.0.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(reservation, "released");
    assert!(!stale.part_path.exists());
    assert!(!stale.destination_path.exists());
    assert_eq!(broker.info(&valid.transfer_id).unwrap().state, "complete");
    assert_eq!(
        fs::read(valid.destination_path).unwrap(),
        b"independent file"
    );
}

#[test]
fn stale_group_cleanup_leaves_a_revoked_inbox_untouched() {
    let f = Fixture::new();
    let group = seed_group(&f, 1);
    let mut broker = f.open_with_mode(DownloadMode::Automatic);
    let mut request = f.valid_request(b"retained part");
    request.group = Some(GroupTransferBinding {
        group_id: group.clone(),
        membership_epoch: 1,
    });
    let info = broker.begin_download(&request).unwrap();
    drop(broker);
    let before = fs::read(&info.part_path).unwrap();
    f.db()
        .execute(
            "UPDATE asl_groups SET membership_epoch=membership_epoch+1 WHERE group_id=?1",
            [hex::encode(group.0.as_bytes())],
        )
        .unwrap();
    SnapshotBroker::open(&f.home)
        .unwrap()
        .revoke_inbox_directory(f.write_grant)
        .unwrap();

    let broker = f.open();
    assert!(matches!(
        broker.schedule(&info.transfer_id),
        Err(AslError::PolicyDenied)
    ));
    assert_eq!(fs::read(info.part_path).unwrap(), before);
    assert!(!info.destination_path.exists());
}

#[test]
fn group_epoch_change_hides_pending_download_consent() {
    let f = Fixture::new();
    let group = seed_group(&f, 1);
    let bytes = b"group consent";
    let mut request = f.request(bytes, *blake3::hash(bytes).as_bytes());
    request.group = Some(GroupTransferBinding {
        group_id: group.clone(),
        membership_epoch: 1,
    });
    let mut broker = f.open_with_mode(DownloadMode::Ask);
    let DownloadStart::Pending { approval_id, .. } = broker.request_download(&request).unwrap()
    else {
        panic!("ask mode must create a consent");
    };
    assert_eq!(broker.download_consents().unwrap().len(), 1);
    let store = open_store(&f.home.join("state/asl.sqlite3")).unwrap();
    let subject = [15; 32];
    store.configure_mcp_recovery(Some(&subject), 0).unwrap();
    store
        .authorize_recovery_download_decision(approval_id)
        .unwrap();
    f.db()
        .execute(
            "UPDATE asl_groups
             SET state='needs_sync',membership_epoch=2,updated_at_ms=updated_at_ms+1
             WHERE group_id=?1",
            [hex::encode(group.0.as_bytes())],
        )
        .unwrap();

    assert!(broker.download_consents().unwrap().is_empty());
    assert!(matches!(
        store.recovery_download_decision(approval_id, &subject),
        Err(AslError::PolicyDenied)
    ));
    assert!(matches!(
        broker.decide_download(approval_id, true),
        Err(AslError::PolicyDenied)
    ));
}

#[test]
fn durable_chunks_survive_reopen_and_finish_after_missing_chunks_arrive() {
    let f = Fixture::new();
    let mut bytes = vec![7; 1_048_579];
    bytes[1_048_576..].copy_from_slice(&[9; 3]);
    let request = f.request(&bytes, *blake3::hash(&bytes).as_bytes());
    let mut broker = f.open_with_mode(DownloadMode::Automatic);
    let info = broker.begin_download(&request).unwrap();
    broker
        .assign_chunk(info.transfer_id.clone(), &f.peer, 0)
        .unwrap();
    broker
        .write_chunk(info.transfer_id.clone(), &f.peer, 0, &bytes[..1_048_576])
        .unwrap();
    drop(broker);

    let mut broker = f.open();
    let resumed = broker.info(&info.transfer_id).unwrap();
    assert_eq!(resumed.durable_bytes, 1_048_576);
    let schedule = broker.schedule(&info.transfer_id).unwrap();
    assert_eq!(schedule.durable_indexes, [0]);
    assert_eq!(schedule.sources, std::slice::from_ref(&f.peer));
    assert_eq!(schedule.manifest.file_size, bytes.len() as u64);
    broker
        .assign_chunk(info.transfer_id.clone(), &f.peer, 1)
        .unwrap();
    broker
        .write_chunk(info.transfer_id.clone(), &f.peer, 1, &bytes[1_048_576..])
        .unwrap();
    let completed = broker.complete(info.transfer_id).unwrap();
    assert_eq!(completed.state, "complete");
    assert_eq!(fs::read(f.destination.join("item.bin")).unwrap(), bytes);
}

#[test]
fn an_unfulfilled_assignment_can_return_to_missing_without_crediting_progress() {
    let fixture = Fixture::new();
    let bytes = [7; 32];
    let request = fixture.request(&bytes, *blake3::hash(&bytes).as_bytes());
    let mut broker = fixture.open_with_mode(DownloadMode::Automatic);
    let info = broker.begin_download(&request).unwrap();
    broker
        .assign_chunk(info.transfer_id.clone(), &fixture.peer, 0)
        .unwrap();
    assert!(
        !broker
            .unassign_chunk(&info.transfer_id, &peer_with_key([9; 32]), 0)
            .unwrap()
    );
    assert!(
        broker
            .unassign_chunk(&info.transfer_id, &fixture.peer, 0)
            .unwrap()
    );
    assert!(
        !broker
            .unassign_chunk(&info.transfer_id, &fixture.peer, 0)
            .unwrap()
    );
    broker
        .assign_chunk(info.transfer_id.clone(), &fixture.peer, 0)
        .unwrap();
    assert!(
        broker
            .schedule(&info.transfer_id)
            .unwrap()
            .durable_indexes
            .is_empty()
    );
    broker
        .write_chunk(info.transfer_id.clone(), &fixture.peer, 0, &bytes)
        .unwrap();
    assert!(
        !broker
            .unassign_chunk(&info.transfer_id, &fixture.peer, 0)
            .unwrap()
    );
    assert_eq!(
        broker.schedule(&info.transfer_id).unwrap().durable_indexes,
        [0]
    );
}

#[test]
fn restart_repairs_a_corrupted_durable_chunk_without_cooling_the_content() {
    let f = Fixture::new();
    let bytes = vec![7; 32];
    let request = f.request(&bytes, *blake3::hash(&bytes).as_bytes());
    let mut broker = f.open_with_mode(DownloadMode::Automatic);
    let info = broker.begin_download(&request).unwrap();
    broker
        .assign_chunk(info.transfer_id.clone(), &f.peer, 0)
        .unwrap();
    broker
        .write_chunk(info.transfer_id.clone(), &f.peer, 0, &bytes)
        .unwrap();
    fs::write(&info.part_path, [8; 32]).unwrap();
    drop(broker);

    let mut broker = f.open();
    let repaired = broker.info(&info.transfer_id).unwrap();
    assert_eq!(repaired.durable_bytes, 0);
    assert_eq!(repaired.state, "running");
    broker
        .assign_chunk(info.transfer_id.clone(), &f.peer, 0)
        .unwrap();
    broker
        .write_chunk(info.transfer_id.clone(), &f.peer, 0, &bytes)
        .unwrap();
    broker.complete(info.transfer_id).unwrap();
    assert_eq!(fs::read(f.destination.join("item.bin")).unwrap(), bytes);
}

#[test]
fn full_hash_mismatch_releases_and_cools_the_transfer() {
    let f = Fixture::new();
    let bytes = vec![7; 32];
    let request = f.request(&bytes, [99; 32]);
    let mut broker = f.open_with_mode(DownloadMode::Automatic);
    let info = broker.begin_download(&request).unwrap();
    broker
        .assign_chunk(info.transfer_id.clone(), &f.peer, 0)
        .unwrap();
    broker
        .write_chunk(info.transfer_id.clone(), &f.peer, 0, &bytes)
        .unwrap();
    assert!(matches!(
        broker.complete(info.transfer_id).unwrap_err(),
        AslError::InvalidMessage
    ));
    drop(broker);
    let mut retry = f.open_with_mode(DownloadMode::Automatic);
    assert!(matches!(
        retry.begin_download(&request),
        Err(AslError::PolicyDenied)
    ));
}

#[test]
fn download_quota_is_reserved_before_part_creation() {
    let f = Fixture::new();
    let db = Connection::open(f.home.join("state/asl.sqlite3")).unwrap();
    db.execute(
        "INSERT INTO settings(key,value_json,updated_at_ms)
         VALUES ('storage.download_quota_bytes','16',0)",
        [],
    )
    .unwrap();
    drop(db);
    let bytes = vec![7; 32];
    let request = f.request(&bytes, *blake3::hash(&bytes).as_bytes());
    let mut broker = f.open_with_mode(DownloadMode::Automatic);
    assert!(matches!(
        broker.begin_download(&request),
        Err(AslError::QuotaExceeded)
    ));
    assert!(!f.destination.join("item.bin.part").exists());
    let db = Connection::open(f.home.join("state/asl.sqlite3")).unwrap();
    let reservations: i64 = db
        .query_row("SELECT count(*) FROM reservations", [], |row| row.get(0))
        .unwrap();
    assert_eq!(reservations, 0);
}

#[test]
fn stranger_sources_share_one_reservation_limit_even_with_a_contact_candidate() {
    let fixture = Fixture::new();
    let stranger = peer_with_key([4; 32]);
    let contact = peer_with_key([5; 32]);
    let database = Connection::open(fixture.home.join("state/asl.sqlite3")).unwrap();
    seed_peer(&database, &stranger, 4);
    seed_peer(&database, &contact, 5);
    database
        .execute(
            "INSERT INTO settings(key,value_json,updated_at_ms)
             VALUES ('storage.unknown_source_reservation_bytes','48',0)",
            [],
        )
        .unwrap();
    database
        .execute(
            "INSERT INTO authorized_contacts(agent_id,authorized_at_ms,authorization_revision)
             VALUES (?1,0,1)",
            [bs58::encode(AgentId([5; 32]).0).into_string()],
        )
        .unwrap();
    drop(database);

    let data = [7; 32];
    let first = fixture.request(&data, *blake3::hash(&data).as_bytes());
    let mut broker = fixture.open_with_mode(DownloadMode::Automatic);
    let first = broker.begin_download(&first).unwrap();

    let mut second = fixture.request(&data, *blake3::hash(&data).as_bytes());
    second.destination_relative = PathBuf::from("second.bin");
    second.sources = vec![contact.clone(), stranger.clone()];
    assert!(matches!(
        broker.begin_download(&second),
        Err(AslError::QuotaExceeded)
    ));
    assert!(!fixture.destination.join("second.bin.part").exists());

    broker.release(first.transfer_id).unwrap();
    let mixed = broker.begin_download(&second).unwrap();
    second.destination_relative = PathBuf::from("third.bin");
    second.sources = vec![stranger];
    assert!(matches!(
        broker.begin_download(&second),
        Err(AslError::QuotaExceeded)
    ));
    assert!(!fixture.destination.join("third.bin.part").exists());
    second.sources = vec![contact];
    assert!(broker.begin_download(&second).is_ok());
    assert!(mixed.part_path.exists());
}

#[test]
fn inbox_write_grant_quota_counts_existing_reservations() {
    let f = Fixture::new();
    let db = Connection::open(f.home.join("state/asl.sqlite3")).unwrap();
    db.execute(
        "UPDATE write_grants SET max_bytes=32 WHERE write_grant_id=?1",
        [hex::encode(f.write_grant.0)],
    )
    .unwrap();
    drop(db);

    let first_bytes = vec![7; 32];
    let first = f.request(&first_bytes, *blake3::hash(&first_bytes).as_bytes());
    let mut broker = f.open_with_mode(DownloadMode::Automatic);
    let first_info = broker.begin_download(&first).unwrap();

    let second_bytes = vec![8; 1];
    let mut second = f.request(&second_bytes, *blake3::hash(&second_bytes).as_bytes());
    second.destination_relative = PathBuf::from("second.bin");
    assert!(matches!(
        broker.begin_download(&second),
        Err(AslError::QuotaExceeded)
    ));
    assert!(first_info.part_path.exists());
    assert!(!f.destination.join("second.bin.part").exists());

    broker
        .assign_chunk(first_info.transfer_id.clone(), &f.peer, 0)
        .unwrap();
    broker
        .write_chunk(first_info.transfer_id.clone(), &f.peer, 0, &first_bytes)
        .unwrap();
    broker.complete(first_info.transfer_id).unwrap();
    assert!(matches!(
        broker.begin_download(&second),
        Err(AslError::QuotaExceeded)
    ));
    assert!(f.destination.join("item.bin").exists());
    assert!(!f.destination.join("second.bin.part").exists());
}

#[test]
fn an_unassigned_peer_cannot_write_a_verified_chunk_to_the_part_file() {
    let f = Fixture::new();
    let bytes = vec![7; 32];
    let request = f.request(&bytes, *blake3::hash(&bytes).as_bytes());
    let mut broker = f.open_with_mode(DownloadMode::Automatic);
    let info = broker.begin_download(&request).unwrap();
    broker
        .assign_chunk(info.transfer_id.clone(), &f.peer, 0)
        .unwrap();

    assert!(matches!(
        broker.write_chunk(info.transfer_id, &peer_with_key([9; 32]), 0, &bytes),
        Err(AslError::NotFound)
    ));
    assert_eq!(fs::read(&info.part_path).unwrap(), [0; 32]);
}

#[test]
fn recovery_does_not_remove_a_replaced_part_file() {
    let f = Fixture::new();
    let bytes = vec![7; 32];
    let request = f.request(&bytes, *blake3::hash(&bytes).as_bytes());
    let mut broker = f.open_with_mode(DownloadMode::Automatic);
    let info = broker.begin_download(&request).unwrap();
    drop(broker);

    fs::remove_file(&info.part_path).unwrap();
    fs::write(&info.part_path, b"not the authorized transfer file").unwrap();
    drop(f.open());

    assert_eq!(
        fs::read(&info.part_path).unwrap(),
        b"not the authorized transfer file"
    );
}

#[test]
fn failed_part_retention_removes_only_expired_owned_parts() {
    let fixture = Fixture::new();
    let mut broker = fixture.open();
    let day = 86_400_000;
    let now = 10 * day;
    let begin = |broker: &mut DownloadBroker, name: &str| {
        let mut request = fixture.valid_request(name.as_bytes());
        request.destination_relative = name.into();
        broker.begin_download(&request).unwrap()
    };
    let expired = begin(&mut broker, "expired.bin");
    let recent = begin(&mut broker, "recent.bin");
    let replaced = begin(&mut broker, "replaced.bin");
    let active = begin(&mut broker, "active.bin");
    for (info, failed_at) in [
        (&expired, now - 3 * day),
        (&recent, now - 3 * day + 1),
        (&replaced, now - 4 * day),
    ] {
        let database = fixture.db();
        let id = hex::encode(info.transfer_id.0.as_bytes());
        database
            .execute(
                "UPDATE reservations SET state='released' WHERE reservation_id=(
                     SELECT reservation_id FROM transfers WHERE transfer_id=?1)",
                [&id],
            )
            .unwrap();
        database
            .execute(
                "UPDATE transfers SET state='failed',updated_at_ms=?2 WHERE transfer_id=?1",
                rusqlite::params![id, failed_at],
            )
            .unwrap();
    }
    fs::rename(&replaced.part_path, &replaced.destination_path).unwrap();
    fs::write(&replaced.part_path, b"replacement").unwrap();

    assert_eq!(broker.prune_failed_parts(now).unwrap(), 1);
    assert!(!expired.part_path.exists());
    assert!(recent.part_path.is_file());
    assert!(active.part_path.is_file());
    assert!(replaced.destination_path.is_file());
    assert_eq!(fs::read(&replaced.part_path).unwrap(), b"replacement");
    assert_eq!(broker.prune_failed_parts(now).unwrap(), 0);
    assert_eq!(broker.info(&expired.transfer_id).unwrap().state, "failed");
}

#[test]
fn received_file_retention_applies_only_to_opted_in_unchanged_files() {
    let fixture = Fixture::new();
    let mut broker = fixture.open();
    let mut store = open_store(&fixture.home.join("state/asl.sqlite3")).unwrap();
    let now_ms = || {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
    };
    let receive = |broker: &mut DownloadBroker, name: &str| {
        let bytes = name.as_bytes();
        let mut request = fixture.valid_request(bytes);
        request.destination_relative = name.into();
        let id = broker.begin_download(&request).unwrap().transfer_id;
        broker.assign_chunk(id.clone(), &fixture.peer, 0).unwrap();
        broker
            .write_chunk(id.clone(), &fixture.peer, 0, bytes)
            .unwrap();
        let info = broker.complete(id).unwrap();
        assert_eq!(info.state, "complete");
        info
    };
    let existing = receive(&mut broker, "existing.bin");
    assert_eq!(store.inbox_retention_days(fixture.write_grant).unwrap(), 0);
    store
        .set_inbox_retention_days(fixture.write_grant, 30)
        .unwrap();
    let removed = receive(&mut broker, "removed.bin");
    let edited = receive(&mut broker, "edited.bin");
    fs::write(&edited.destination_path, b"changed after delivery").unwrap();
    let deadline = || {
        fixture
            .db()
            .query_row(
                "SELECT k.expires_at_ms-t.updated_at_ms FROM received_file_retention k
                 JOIN transfers t USING(transfer_id) WHERE t.transfer_id=?1",
                [hex::encode(removed.transfer_id.0.as_bytes())],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
    };
    assert_eq!(deadline(), 30 * 86_400_000);
    store
        .set_inbox_retention_days(fixture.write_grant, 1)
        .unwrap();
    store
        .set_inbox_retention_days(fixture.write_grant, 30)
        .unwrap();
    assert_eq!(deadline(), 86_400_000);
    let after_shorter_deadline = now_ms() + 86_400_000;
    assert_eq!(
        broker.prune_received_files(after_shorter_deadline).unwrap(),
        1
    );
    assert!(!removed.destination_path.exists());
    assert!(existing.destination_path.is_file());
    assert_eq!(
        fs::read(edited.destination_path).unwrap(),
        b"changed after delivery"
    );

    let kept = receive(&mut broker, "kept.bin");
    store
        .set_inbox_retention_days(fixture.write_grant, 0)
        .unwrap();
    store
        .set_inbox_retention_days(fixture.write_grant, 1)
        .unwrap();
    assert_eq!(
        broker
            .prune_received_files(now_ms() + 31 * 86_400_000)
            .unwrap(),
        0
    );
    assert!(kept.destination_path.is_file());
    let state: String = fixture
        .db()
        .query_row(
            "SELECT r.state FROM reservations r JOIN transfers t USING(reservation_id)
         WHERE t.transfer_id=?1",
            [hex::encode(removed.transfer_id.0.as_bytes())],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(state, "released");
}

fn pending_id(broker: &mut DownloadBroker, request: &DownloadRequest) -> Id128 {
    pending_ids(broker, request).0
}

fn pending_ids(broker: &mut DownloadBroker, request: &DownloadRequest) -> (Id128, TransferId) {
    match broker.request_download(request).unwrap() {
        DownloadStart::Pending {
            approval_id,
            transfer_id,
        } => (approval_id, transfer_id),
        DownloadStart::Started(_) => panic!("download started without local approval"),
    }
}

#[test]
fn default_mode_starts_only_with_an_active_inbox_grant() {
    let f = Fixture::new();
    let mut request = f.valid_request(b"download");
    let mut broker = f.open();
    let mut snapshots = SnapshotBroker::open(&f.home).unwrap();
    snapshots.revoke_inbox_directory(f.write_grant).unwrap();
    assert!(matches!(
        broker.request_download(&request),
        Err(AslError::PolicyDenied | AslError::GrantRevoked)
    ));
    f.assert_no_download();

    request.write_grant_id = snapshots
        .authorize_inbox_directory(&f.destination, 4 << 20)
        .unwrap();
    let DownloadStart::Started(info) = broker.request_download(&request).unwrap() else {
        panic!("an active inbox grant should suffice in the default mode");
    };
    assert!(info.part_path.is_file());
    assert_eq!(f.download_counts(), (1, 1, 1));
}

#[test]
fn ask_deduplicates_pending_requests_and_does_not_start_after_denial() {
    let f = Fixture::new();
    let request = f.valid_request(b"download");
    let mut broker = f.open_with_mode(DownloadMode::Ask);
    assert!(matches!(
        broker.begin_download(&request),
        Err(AslError::PolicyDenied)
    ));
    let (id, transfer_id) = pending_ids(&mut broker, &request);
    drop(broker);

    let mut broker = f.open();
    assert_eq!(pending_ids(&mut broker, &request), (id, transfer_id));
    let consents: i64 = f
        .db()
        .query_row("SELECT count(*) FROM transfer_consents", [], |r| r.get(0))
        .unwrap();
    assert_eq!(consents, 1);
    assert!(matches!(
        broker.begin_approved_download(&request, id),
        Err(AslError::PolicyDenied)
    ));
    f.assert_no_download();

    broker.decide_download(id, false).unwrap();
    assert!(matches!(
        broker.request_download(&request),
        Err(AslError::PolicyDenied)
    ));
    assert!(matches!(
        broker.begin_approved_download(&request, id),
        Err(AslError::PolicyDenied)
    ));
    f.assert_no_download();
}

#[test]
fn approved_download_can_start_only_once_even_after_release_and_reopen() {
    let f = Fixture::new();
    let request = f.valid_request(b"download");
    let mut broker = f.open_with_mode(DownloadMode::Ask);
    let (id, transfer_id) = pending_ids(&mut broker, &request);
    broker.decide_download(id, true).unwrap();
    let mut wrong_id = id;
    wrong_id.0[0] ^= 1;
    assert!(matches!(
        broker.begin_approved_download(&request, wrong_id),
        Err(AslError::PolicyDenied)
    ));
    f.assert_no_download();

    let info = broker.begin_approved_download(&request, id).unwrap();
    assert_eq!(info.transfer_id, transfer_id);
    assert!(info.part_path.is_file());
    assert_eq!(f.download_counts(), (1, 1, 1));
    broker.release(info.transfer_id).unwrap();
    assert!(!info.part_path.exists());
    drop(broker);

    let counts = f.download_counts();
    let mut broker = f.open();
    assert!(matches!(
        broker.begin_approved_download(&request, id),
        Err(AslError::PolicyDenied)
    ));
    assert_eq!(f.download_counts(), counts);
    assert!(fs::read_dir(&f.destination).unwrap().next().is_none());
}

#[track_caller]
fn assert_approval_rejects_change(change: impl FnOnce(&Fixture, &mut DownloadRequest)) {
    let f = Fixture::new();
    let mut request = f.valid_request(b"original");
    let mut broker = f.open_with_mode(DownloadMode::Ask);
    let id = pending_id(&mut broker, &request);
    broker.decide_download(id, true).unwrap();
    change(&f, &mut request);
    assert!(matches!(
        broker.begin_approved_download(&request, id),
        Err(AslError::PolicyDenied | AslError::GrantRevoked)
    ));
    f.assert_no_download();
}

#[test]
fn approval_is_bound_to_the_source_set_destination_name_and_content() {
    assert_approval_rejects_change(|f, request| {
        let extra = peer_with_key([4; 32]);
        seed_peer(&f.db(), &extra, 4);
        request.sources.push(extra);
    });
    assert_approval_rejects_change(|_, request| {
        request.destination_relative = PathBuf::from("renamed.bin");
    });
    assert_approval_rejects_change(|f, request| {
        *request = f.valid_request(b"modified");
    });
}

#[test]
fn approval_is_invalid_after_an_inbox_epoch_change_or_revocation() {
    assert_approval_rejects_change(|f, _| {
        assert_eq!(
            f.db()
                .execute(
                    "UPDATE write_grants SET epoch=epoch+1 WHERE write_grant_id=?1",
                    [hex::encode(f.write_grant.0)],
                )
                .unwrap(),
            1
        );
    });
    assert_approval_rejects_change(|f, _| {
        SnapshotBroker::open(&f.home)
            .unwrap()
            .revoke_inbox_directory(f.write_grant)
            .unwrap();
    });
}

#[test]
fn expiration_blocks_both_a_late_decision_and_a_late_start() {
    for approve_before_expiry in [false, true] {
        let f = Fixture::new();
        let request = f.valid_request(b"download");
        let mut broker = f.open_with_mode(DownloadMode::Ask);
        let id = pending_id(&mut broker, &request);
        if approve_before_expiry {
            broker.decide_download(id, true).unwrap();
        }
        assert_eq!(
            f.db()
                .execute(
                    "UPDATE transfer_consents SET expires_at_ms=created_at_ms WHERE approval_id=?1",
                    [hex::encode(id.0)],
                )
                .unwrap(),
            1
        );
        if !approve_before_expiry {
            assert!(matches!(
                broker.decide_download(id, true),
                Err(AslError::PolicyDenied | AslError::ExpiredMessage)
            ));
        }
        assert!(matches!(
            broker.begin_approved_download(&request, id),
            Err(AslError::PolicyDenied | AslError::ExpiredMessage)
        ));
        f.assert_no_download();
    }
}

#[test]
fn switching_from_automatic_to_ask_requires_consent_for_the_same_request() {
    let f = Fixture::new();
    let request = f.valid_request(b"download");
    let mut broker = f.open_with_mode(DownloadMode::Automatic);
    let DownloadStart::Started(info) = broker.request_download(&request).unwrap() else {
        panic!("automatic mode did not start the download");
    };
    broker.release(info.transfer_id).unwrap();
    let counts = f.download_counts();

    broker.set_download_mode(DownloadMode::Ask).unwrap();
    assert!(matches!(
        broker.begin_download(&request),
        Err(AslError::PolicyDenied)
    ));
    pending_id(&mut broker, &request);
    assert_eq!(f.download_counts(), counts);
    assert!(fs::read_dir(&f.destination).unwrap().next().is_none());
}

#[test]
fn local_inbox_shows_the_bound_details_and_drops_decided_or_revoked_prompts() {
    let f = Fixture::new();
    let mut request = f.valid_request(b"show me");
    let extra = peer_with_key([4; 32]);
    seed_peer(&f.db(), &extra, 4);
    request.sources.push(extra.clone());
    let mut broker = f.open_with_mode(DownloadMode::Ask);
    let id = pending_id(&mut broker, &request);
    request.sources.reverse();
    request.sources.push(extra.clone());
    assert_eq!(pending_id(&mut broker, &request), id);
    let entries = broker.download_consents().unwrap();
    assert_eq!(entries.len(), 1);
    let prompt = &entries[0];
    assert_eq!(prompt.approval_id, id);
    assert_eq!(prompt.destination_path, f.destination.join("item.bin"));
    assert_eq!(prompt.file_size, 7);
    assert_eq!(prompt.write_grant_id, f.write_grant);
    assert_eq!(prompt.content_id, request.content_id);
    assert_eq!(prompt.sources.len(), 2);
    assert!(prompt.sources.contains(&extra) && prompt.sources.contains(&f.peer));
    broker.decide_download(id, true).unwrap();
    assert!(broker.download_consents().unwrap()[0].approved);
    broker.decide_download(id, false).unwrap();
    assert!(broker.download_consents().unwrap().is_empty());
    broker.set_download_mode(DownloadMode::Automatic).unwrap();
    assert!(matches!(
        broker.request_download(&request),
        Err(AslError::PolicyDenied)
    ));
    f.assert_no_download();

    broker.set_download_mode(DownloadMode::Ask).unwrap();
    request.destination_relative = "different.bin".into();
    let other = pending_id(&mut broker, &request);
    SnapshotBroker::open(&f.home)
        .unwrap()
        .revoke_inbox_directory(f.write_grant)
        .unwrap();
    assert!(broker.download_consents().unwrap().is_empty());
    assert!(broker.decide_download(other, true).is_err());
}

#[test]
fn changing_filenames_or_denying_does_not_refill_the_local_prompt_budget() {
    let f = Fixture::new();
    let mut request = f.valid_request(b"bounded");
    let mut broker = f.open_with_mode(DownloadMode::Ask);
    for index in 0..32 {
        request.destination_relative = format!("{index}.bin").into();
        let id = pending_id(&mut broker, &request);
        broker.decide_download(id, false).unwrap();
    }
    request.destination_relative = "overflow.bin".into();
    assert!(matches!(
        broker.request_download(&request),
        Err(AslError::QuotaExceeded)
    ));
    f.assert_no_download();
    f.db()
        .execute(
            "UPDATE transfer_consents SET expires_at_ms=created_at_ms",
            [],
        )
        .unwrap();
    pending_id(&mut broker, &request);
    assert_eq!(broker.download_consents().unwrap().len(), 1);
    f.assert_no_download();
}

#[test]
fn a_mode_change_during_reservation_prevents_part_creation_and_releases_quota() {
    let f = Fixture::new();
    let request = f.valid_request(b"switch before creating the file");
    let mut broker = f.open_with_mode(DownloadMode::Automatic);
    f.db()
        .execute_batch(
            r#"CREATE TRIGGER ask_before_file AFTER INSERT ON transfers BEGIN
        UPDATE settings SET value_json='"ask"' WHERE key='transfer_approval.download_mode';
        END;"#,
        )
        .unwrap();
    assert!(matches!(
        broker.request_download(&request),
        Err(AslError::PolicyDenied)
    ));
    assert!(fs::read_dir(&f.destination).unwrap().next().is_none());
    let released: i64 = f
        .db()
        .query_row(
            "SELECT count(*) FROM reservations WHERE state='released'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(released, 1);
}

#[test]
fn upload_approval_binds_device_content_and_source_epoch() {
    let f = Fixture::new();
    let source = f._temp.path().join("shared");
    fs::create_dir_all(&source).unwrap();
    let bytes = b"authorized upload source";
    fs::write(source.join("note.md"), bytes).unwrap();
    let mut snapshots = SnapshotBroker::open(&f.home).unwrap();
    let source_grant = snapshots
        .authorize_directory(&source, &["md".into()], &Audience::Public, 1 << 20)
        .unwrap();
    snapshots
        .import_source(&source_grant, std::path::Path::new("note.md"))
        .unwrap();
    drop(snapshots);

    let manifest = encode_manifest(&Manifest {
        file_size: bytes.len() as u64,
        file_hash: *blake3::hash(bytes).as_bytes(),
        chunk_hashes: vec![*blake3::hash(bytes).as_bytes()],
    })
    .unwrap();
    let content_id = Hash32(content_id(&manifest));
    let binding = UploadBinding {
        source_grant_id: source_grant.0,
        grant_epoch: 1,
        content_id,
        target_agent_id: Some(AgentId([3; 32])),
        target_peer_id: f.peer.clone(),
        group: None,
        file_size: bytes.len() as u64,
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap();
    f.db()
        .execute(
            "UPDATE device_identities SET certificate_expires_ms=?1 WHERE peer_id=?2",
            rusqlite::params![i64::MAX, bs58::encode(f.peer.as_bytes()).into_string()],
        )
        .unwrap();
    let mut store = open_store(&f.home.join("state/asl.sqlite3")).unwrap();
    store.set_upload_mode(UploadMode::Ask).unwrap();

    let UploadAdmission::Pending {
        approval_id,
        expires_at_ms,
    } = store.admit_upload(&binding, now).unwrap()
    else {
        panic!("ask mode must not grant access before local approval");
    };
    assert!(expires_at_ms > now);
    assert_eq!(
        store.admit_upload(&binding, now + 1).unwrap(),
        UploadAdmission::Pending {
            approval_id,
            expires_at_ms
        }
    );
    let consent = store.upload_consents().unwrap().pop().unwrap();
    assert_eq!(consent.approval_id, approval_id);
    assert_eq!(consent.content_id, content_id);
    assert_eq!(consent.source_grant_id, source_grant.0);
    assert_eq!(consent.target_agent_id, binding.target_agent_id);
    assert_eq!(consent.target_peer_id, f.peer);
    assert_eq!(consent.filename, "note.md");
    assert_eq!(consent.file_size, bytes.len() as u64);
    assert!(!consent.approved);

    store.decide_upload(approval_id, true).unwrap();
    assert_eq!(
        store.admit_upload(&binding, now + 2).unwrap(),
        UploadAdmission::Allowed(Some(approval_id))
    );
    store.consume_upload_approval(approval_id, now + 2).unwrap();
    assert!(store.consume_upload_approval(approval_id, now + 3).is_err());
    assert_eq!(
        store.admit_upload(&binding, now + 3).unwrap(),
        UploadAdmission::Denied
    );
    let UploadAdmission::Pending {
        approval_id: renewed_approval,
        ..
    } = store.admit_upload(&binding, now + 300_001).unwrap()
    else {
        panic!("an expired one-time approval should require a fresh local decision");
    };
    assert_ne!(renewed_approval, approval_id);
    store.decide_upload(renewed_approval, false).unwrap();
    assert_eq!(
        store.admit_upload(&binding, now + 300_002).unwrap(),
        UploadAdmission::Denied
    );

    let revoked_peer = peer_with_key([9; 32]);
    let db = f.db();
    seed_peer(&db, &revoked_peer, 9);
    db.execute(
        "UPDATE device_identities SET certificate_expires_ms=?1 WHERE peer_id=?2",
        rusqlite::params![
            i64::MAX,
            bs58::encode(revoked_peer.as_bytes()).into_string()
        ],
    )
    .unwrap();
    drop(db);
    let revoked_binding = UploadBinding {
        target_agent_id: Some(AgentId([9; 32])),
        target_peer_id: revoked_peer.clone(),
        ..binding.clone()
    };
    let UploadAdmission::Pending {
        approval_id: revoked_approval,
        ..
    } = store.admit_upload(&revoked_binding, now + 4).unwrap()
    else {
        panic!("active target device should create a local approval");
    };
    f.db()
        .execute(
            "UPDATE device_identities SET revoked_at_ms=?1 WHERE peer_id=?2",
            rusqlite::params![
                i64::try_from(now + 5).unwrap(),
                bs58::encode(revoked_peer.as_bytes()).into_string()
            ],
        )
        .unwrap();
    assert!(store.upload_consents().unwrap().is_empty());
    assert!(store.decide_upload(revoked_approval, true).is_err());
    assert!(store.admit_upload(&revoked_binding, now + 5).is_err());

    let group_id = seed_group(&f, 1);
    let group_binding = UploadBinding {
        target_agent_id: None,
        group: Some(GroupTransferBinding {
            group_id: group_id.clone(),
            membership_epoch: 1,
        }),
        ..binding
    };
    let UploadAdmission::Pending {
        approval_id: group_approval,
        ..
    } = store.admit_upload(&group_binding, now + 300_003).unwrap()
    else {
        panic!("group upload must request its own local approval");
    };
    f.db()
        .execute(
            "UPDATE asl_groups SET membership_epoch=2 WHERE group_id=?1",
            [hex::encode(group_id.0.as_bytes())],
        )
        .unwrap();
    assert!(store.upload_consents().unwrap().is_empty());
    assert!(store.decide_upload(group_approval, true).is_err());
    assert!(matches!(
        store.admit_upload(&group_binding, now + 300_004),
        Err(AslError::PolicyDenied)
    ));
}

fn peer() -> PeerId {
    peer_with_key([1; 32])
}

fn peer_with_key(key: [u8; 32]) -> PeerId {
    let mut bytes = vec![0, 36, 8, 1, 18, 32];
    bytes.extend_from_slice(&key);
    PeerId::from_bytes(bytes).unwrap()
}

fn seed_peer(db: &Connection, peer: &PeerId, agent_seed: u8) {
    let agent = bs58::encode(AgentId([agent_seed; 32]).0).into_string();
    let peer = bs58::encode(peer.as_bytes()).into_string();
    db.execute(
        "INSERT INTO agents(agent_id,identity_state) VALUES (?1,'verified')",
        [&agent],
    )
    .unwrap();
    db.execute(
        "INSERT INTO device_identities(peer_id,agent_id,public_key_hex,certificate_cbor,
         certificate_serial,certificate_expires_ms,created_at_ms)
         VALUES (?1,?2,?3,?4,1,?5,0)",
        rusqlite::params![peer, agent, "11".repeat(32), vec![0_u8], i64::MAX],
    )
    .unwrap();
    db.execute(
        "INSERT INTO peers(peer_id,agent_id) VALUES (?1,?2)",
        rusqlite::params![peer, agent],
    )
    .unwrap();
}

fn seed_group(fixture: &Fixture, membership_epoch: u64) -> GroupId {
    let group = GroupId(Id128([21; 16]));
    let group_text = hex::encode(group.0.as_bytes());
    let peer_text = bs58::encode(fixture.peer.as_bytes()).into_string();
    let db = fixture.db();
    db.execute(
        "INSERT INTO asl_groups(
             group_id,creator_peer_id,local_name,mls_epoch,membership_epoch,state,
             created_at_ms,updated_at_ms)
         VALUES (?1,?2,'fixture',1,?3,'active',0,0)",
        rusqlite::params![group_text, peer_text, membership_epoch as i64],
    )
    .unwrap();
    db.execute(
        "INSERT INTO group_members(group_id,peer_id,role,state,joined_at_ms)
         VALUES (?1,?2,'creator','active',0)",
        rusqlite::params![group_text, peer_text],
    )
    .unwrap();
    group
}
