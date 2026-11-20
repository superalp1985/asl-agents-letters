#![cfg(windows)]

use std::{fs, path::PathBuf};

use asl_store::{
    resources::SnapshotBroker,
    transfers::{DownloadBroker, DownloadMode, DownloadRequest, DownloadStart},
};
use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId},
    manifest::{Manifest, encode_manifest},
    task::TransferId,
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
        }
    }
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
         VALUES (?1,?2,?3,?4,1,999999999,0)",
        rusqlite::params![peer, agent, "11".repeat(32), vec![0_u8]],
    )
    .unwrap();
    db.execute(
        "INSERT INTO peers(peer_id,agent_id) VALUES (?1,?2)",
        rusqlite::params![peer, agent],
    )
    .unwrap();
}
