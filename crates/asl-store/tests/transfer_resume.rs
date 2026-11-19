#![cfg(windows)]

use std::{fs, path::PathBuf};

use asl_store::transfers::{DownloadBroker, DownloadRequest};
use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId},
    manifest::{Manifest, encode_manifest},
};
use rusqlite::Connection;
use tempfile::TempDir;

const WRITE_GRANT: Id128 = Id128([2; 16]);

struct Fixture {
    home: PathBuf,
    destination: PathBuf,
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
        seed_peer(&db, &peer);
        db.execute(
            "INSERT INTO write_grants(write_grant_id,kind,root_path,max_bytes,epoch,status)
             VALUES (?1,'inbox',?2,?3,1,'active')",
            rusqlite::params![
                hex::encode(WRITE_GRANT.0),
                destination.to_str().unwrap(),
                4 << 20
            ],
        )
        .unwrap();
        drop(db);
        Self {
            home,
            destination,
            peer,
            _temp: temp,
        }
    }

    fn open(&self) -> DownloadBroker {
        DownloadBroker::open(&self.home).unwrap()
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
            write_grant_id: WRITE_GRANT,
            destination_relative: PathBuf::from("item.bin"),
            sources: vec![self.peer.clone()],
            now_ms: 1_000,
        }
    }
}

#[test]
fn durable_chunks_survive_reopen_and_finish_after_missing_chunks_arrive() {
    let f = Fixture::new();
    let mut bytes = vec![7; 1_048_579];
    bytes[1_048_576..].copy_from_slice(&[9; 3]);
    let request = f.request(&bytes, *blake3::hash(&bytes).as_bytes());
    let mut broker = f.open();
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
fn restart_repairs_a_corrupted_durable_chunk_without_cooling_the_content() {
    let f = Fixture::new();
    let bytes = vec![7; 32];
    let request = f.request(&bytes, *blake3::hash(&bytes).as_bytes());
    let mut broker = f.open();
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
    let mut broker = f.open();
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
    let mut retry = f.open();
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
    let mut broker = f.open();
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

fn peer() -> PeerId {
    let mut bytes = vec![0, 36, 8, 1, 18, 32];
    bytes.extend_from_slice(&[1; 32]);
    PeerId::from_bytes(bytes).unwrap()
}

fn seed_peer(db: &Connection, peer: &PeerId) {
    let agent = bs58::encode(AgentId([3; 32]).0).into_string();
    let peer = bs58::encode(peer.as_bytes()).into_string();
    db.execute("INSERT INTO agents(agent_id) VALUES (?1)", [&agent])
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
