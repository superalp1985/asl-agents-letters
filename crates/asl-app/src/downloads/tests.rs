use super::*;
use crate::{FetchManifestDetails, identity::DeviceIdentity};
use asl_types::{
    ids::{AgentId, Hash32},
    manifest::{Manifest, content_id, encode_manifest},
};

fn manifest_event() -> VerifiedFetchManifest {
    let hash = *blake3::hash(b"direct").as_bytes();
    let manifest = Manifest {
        file_size: 6,
        file_hash: hash,
        chunk_hashes: vec![hash],
    };
    VerifiedFetchManifest(FetchManifestDetails {
        fetch_generation: 1,
        fetch_request_id: Id128([1; 16]),
        root_task_id: Id128([2; 16]),
        connection_id: [3; 16],
        agent_id: AgentId([4; 32]),
        peer_id: DeviceIdentity::generate().unwrap().peer_id(),
        content_id: Hash32(content_id(&encode_manifest(&manifest).unwrap())),
        lease_id: Hash32([5; 32]),
        expires_at_ms: unix_time_ms().unwrap() + 60_000,
        manifest,
    })
}

#[test]
fn maps_only_the_verified_content_peer_and_local_destination() {
    let event = manifest_event();
    let grant = Id128([6; 16]);
    let DownloadRequest {
        content_id,
        manifest,
        write_grant_id,
        destination_relative,
        sources,
        group,
    } = download_request(&[&event], grant, "local.bin", None).unwrap();
    assert_eq!(content_id, event.content_id);
    assert_eq!(manifest, encode_manifest(&event.manifest).unwrap());
    assert_eq!(write_grant_id, grant);
    assert_eq!(destination_relative, std::path::Path::new("local.bin"));
    assert_eq!(sources, std::slice::from_ref(&event.peer_id));
    assert!(group.is_none());
}

#[test]
fn rejects_elapsed_lease_and_mismatched_content() {
    let grant = Id128([6; 16]);
    let mut event = manifest_event();
    event.0.expires_at_ms = unix_time_ms().unwrap();
    assert!(matches!(
        download_request(&[&event], grant, "local.bin", None),
        Err(AslError::ExpiredMessage)
    ));
    let mut event = manifest_event();
    event.0.manifest.file_hash[0] ^= 1;
    assert!(matches!(
        download_request(&[&event], grant, "local.bin", None),
        Err(AslError::InvalidMessage)
    ));
}

#[test]
fn accepts_only_one_local_filename() {
    let event = manifest_event();
    for name in [
        "", ".", "..", "../x", "dir/x", r"dir\x", r"C:\x", "x:stream", "NUL.bin",
    ] {
        assert!(matches!(
            download_request(&[&event], Id128([6; 16]), name, None),
            Err(AslError::NotFound)
        ));
    }
}

#[cfg(windows)]
#[test]
fn missing_device_is_not_enrolled_and_approval_cannot_revive_a_lease() {
    use std::fs;

    use asl_store::resources::SnapshotBroker;
    use rusqlite::Connection;

    let temp = crate::transfer::tests::Fixture::new();
    let home = temp.path().join("home");
    let inbox = temp.path().join("inbox");
    let paths = AppPaths::open(&home).unwrap();
    fs::create_dir(&inbox).unwrap();
    let grant = SnapshotBroker::open(&home)
        .unwrap()
        .authorize_inbox_directory(&inbox, 1024)
        .unwrap();
    let mut downloads = LocalDownloads::open(&paths).unwrap();
    let mut event = manifest_event();
    assert!(matches!(
        downloads.request_download(&event, grant, "local.bin"),
        Err(AslError::NotFound)
    ));

    downloads.set_download_mode(DownloadMode::Ask).unwrap();
    event.0.expires_at_ms = unix_time_ms().unwrap();
    assert!(matches!(
        downloads.request_download(&event, grant, "local.bin"),
        Err(AslError::ExpiredMessage)
    ));
    assert!(matches!(
        downloads.begin_approved_download(&event, grant, "local.bin", Id128([7; 16])),
        Err(AslError::ExpiredMessage)
    ));
    let db = Connection::open(paths.state().join("asl.sqlite3")).unwrap();
    let counts: (i64, i64, i64) = db
        .query_row(
            "SELECT (SELECT count(*) FROM device_identities),
                    (SELECT count(*) FROM peers), (SELECT count(*) FROM reservations)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(counts, (0, 0, 0));
    assert_eq!(fs::read_dir(inbox).unwrap().count(), 0);
}

#[cfg(windows)]
#[test]
fn reopening_preserves_local_mode_and_does_not_create_prompts() {
    let temp = crate::transfer::tests::Fixture::new();
    let paths = AppPaths::open(&temp.path().join("home")).unwrap();
    let mut downloads = LocalDownloads::open(&paths).unwrap();
    assert_eq!(downloads.download_mode().unwrap(), DownloadMode::Automatic);
    downloads.set_download_mode(DownloadMode::Ask).unwrap();
    drop(downloads);

    let downloads = LocalDownloads::open(&paths).unwrap();
    assert_eq!(downloads.download_mode().unwrap(), DownloadMode::Ask);
    assert!(downloads.download_consents().unwrap().is_empty());
}
