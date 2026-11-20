#![cfg(windows)]

use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use asl_app::{libraries::LocalLibraries, paths::AppPaths};
use asl_policy::Audience;
use asl_store::resources::SnapshotBroker;
use asl_types::error::AslError;
use rusqlite::Connection;

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("asl-t11-app-{:032x}", rand::random::<u128>()));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let root = self.0.canonicalize().unwrap();
        let base = std::env::temp_dir().canonicalize().unwrap();
        assert_eq!(root.parent(), Some(base.as_path()));
        assert_eq!(root.file_name(), self.0.file_name());
        fs::remove_dir_all(root).unwrap();
    }
}

fn active(db: &Connection, name: &str) -> bool {
    db.query_row(
        "SELECT active FROM resources WHERE source_relative=?1",
        [name],
        |row| row.get(0),
    )
    .unwrap()
}

#[test]
fn local_cli_can_review_and_decide_while_the_download_broker_stays_open() {
    use asl_store::transfers::{DownloadBroker, DownloadRequest, DownloadStart};
    use asl_types::{
        ids::Hash32,
        manifest::{Manifest, content_id, encode_manifest},
    };
    let fixture = Fixture::new();
    let home = fixture.0.join("home");
    let _paths = AppPaths::open(&home).unwrap();
    let inbox = fixture.0.join("downloads");
    fs::create_dir(&inbox).unwrap();
    let grant = SnapshotBroker::open(&home)
        .unwrap()
        .authorize_inbox_directory(&inbox, 1024)
        .unwrap();
    let mut broker = DownloadBroker::open(&home).unwrap();
    let cli = |args: &[&str]| {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_asl-core"))
            .env("ASL_HOME", &home)
            .arg("--downloads")
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    assert_eq!(cli(&["mode", "ask"])["download_mode"], "ask");
    let manifest = encode_manifest(&Manifest {
        file_size: 0,
        file_hash: *blake3::hash(b"").as_bytes(),
        chunk_hashes: vec![],
    })
    .unwrap();
    let mut request = DownloadRequest {
        content_id: Hash32(content_id(&manifest)),
        manifest,
        write_grant_id: grant,
        destination_relative: "one.bin".into(),
        sources: vec![],
    };
    for (action, decision) in [("deny", false), ("approve", true)] {
        let DownloadStart::Pending(id) = broker.request_download(&request).unwrap() else {
            panic!("expected a pending local prompt");
        };
        let rows = cli(&["list"]);
        assert_eq!(rows.as_array().unwrap().len(), 1);
        assert_eq!(
            rows[0]["destination"],
            serde_json::json!(inbox.join(&request.destination_relative))
        );
        let id_text = rows[0]["id"].as_str().unwrap();
        assert_eq!(
            &cli(&[action, id_text])["state"],
            if decision { "approved" } else { "denied" }
        );
        assert!(fs::read_dir(&inbox).unwrap().next().is_none());
        let started = broker.begin_approved_download(&request, id);
        if decision {
            let task = started.unwrap();
            assert!(task.part_path.exists());
            let done = broker.complete(task.transfer_id).unwrap();
            assert_eq!(fs::read(done.destination_path).unwrap(), b"");
        } else {
            assert!(matches!(started, Err(AslError::PolicyDenied)));
        }
        assert_eq!(cli(&["list"]), serde_json::json!([]));
        request.destination_relative = "two.bin".into();
    }
}

fn wait_until(timeout: Duration, mut done: impl FnMut() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(
            start.elapsed() < timeout,
            "background reconciliation timed out"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

fn rewrite(path: &Path) {
    // Reconciliation briefly holds the source open without sharing writes.
    wait_until(Duration::from_secs(5), || match fs::write(path, b"new") {
        Ok(()) => true,
        Err(error) if error.raw_os_error() == Some(32) => false,
        Err(error) => panic!("rewrite failed: {error}"),
    });
}

#[test]
fn persisted_imports_reconcile_without_net_and_stop_cleanly() {
    let fixture = Fixture::new();
    let paths = AppPaths::open(&fixture.0.join("home")).unwrap();
    let source = fixture.0.join("library");
    fs::create_dir(&source).unwrap();
    for name in ["offline.md", "live.md", "keep.md", "not-imported.md"] {
        fs::write(source.join(name), b"old").unwrap();
    }
    let mut libraries = LocalLibraries::open(&paths).unwrap();
    let grant = libraries
        .authorize_directory(&source, &["md".into()], &Audience::Contacts, 1024)
        .unwrap();
    for name in ["offline.md", "live.md", "keep.md"] {
        libraries.import_source(&grant, Path::new(name)).unwrap();
    }
    drop(libraries);
    fs::remove_file(source.join("offline.md")).unwrap();

    let mut libraries = LocalLibraries::open(&paths).unwrap();
    let db = Connection::open(paths.state().join("asl.sqlite3")).unwrap();
    wait_until(Duration::from_secs(5), || !active(&db, "offline.md"));
    assert!(active(&db, "live.md"));
    rewrite(&source.join("live.md"));
    wait_until(Duration::from_secs(8), || !active(&db, "live.md"));
    assert!(active(&db, "keep.md"));
    let count: i64 = db
        .query_row("SELECT COUNT(*) FROM resources", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 3, "a rescan must never import a new source");
    libraries.revoke_directory(&grant).unwrap();
    assert!(!active(&db, "keep.md"));
    assert!(matches!(
        libraries.import_source(&grant, Path::new("keep.md")),
        Err(AslError::GrantRevoked)
    ));
    drop(db);
    let stop = Instant::now();
    drop(libraries);
    assert!(
        stop.elapsed() < Duration::from_secs(5),
        "stop waited for the next rescan"
    );
    fs::rename(paths.state(), paths.root().join("released-state")).unwrap();
}

#[test]
fn first_import_into_an_existing_empty_grant_wakes_the_worker() {
    let fixture = Fixture::new();
    let home = fixture.0.join("home");
    let paths = AppPaths::open(&home).unwrap();
    let empty = fixture.0.join("empty");
    let marker = fixture.0.join("marker");
    fs::create_dir(&empty).unwrap();
    fs::create_dir(&marker).unwrap();
    let mut broker = SnapshotBroker::open(&home).unwrap();
    let grant = broker
        .authorize_directory(&empty, &["md".into()], &Audience::Contacts, 1024)
        .unwrap();
    let old = broker
        .authorize_directory(&marker, &["md".into()], &Audience::Contacts, 1024)
        .unwrap();
    fs::write(marker.join("offline.md"), b"old").unwrap();
    broker.import_source(&old, Path::new("offline.md")).unwrap();
    fs::remove_file(marker.join("offline.md")).unwrap();
    let mut libraries = LocalLibraries::open(&paths).unwrap();
    let db = Connection::open(paths.state().join("asl.sqlite3")).unwrap();
    // The startup sweep is past the marker; its high-water mark cannot include
    // our next import, and no watch exists yet for this different directory.
    wait_until(Duration::from_secs(5), || !active(&db, "offline.md"));
    fs::write(empty.join("first.md"), b"old").unwrap();
    libraries
        .import_source(&grant, Path::new("first.md"))
        .unwrap();
    rewrite(&empty.join("first.md"));
    wait_until(Duration::from_secs(8), || !active(&db, "first.md"));

    // This second local import sends no app hint. Only the newly attached
    // native watch can schedule its check before the periodic sweep.
    fs::write(empty.join("second.md"), b"old").unwrap();
    broker
        .import_source(&grant, Path::new("second.md"))
        .unwrap();
    rewrite(&empty.join("second.md"));
    wait_until(Duration::from_secs(8), || !active(&db, "second.md"));
}

#[test]
#[ignore = "runs the production 30-second rescan timer"]
fn periodic_sweep_finds_a_change_outside_watched_roots_without_an_app_hint() {
    let fixture = Fixture::new();
    let home = fixture.0.join("home");
    let paths = AppPaths::open(&home).unwrap();
    let source = fixture.0.join("library");
    fs::create_dir(&source).unwrap();
    let mut broker = SnapshotBroker::open(&home).unwrap();
    let grant = broker
        .authorize_directory(&source, &["md".into()], &Audience::Contacts, 1024)
        .unwrap();
    fs::write(source.join("offline.md"), b"old").unwrap();
    broker
        .import_source(&grant, Path::new("offline.md"))
        .unwrap();
    fs::remove_file(source.join("offline.md")).unwrap();

    let _libraries = LocalLibraries::open(&paths).unwrap();
    let db = Connection::open(paths.state().join("asl.sqlite3")).unwrap();
    wait_until(Duration::from_secs(5), || !active(&db, "offline.md"));
    let late = fixture.0.join("unwatched");
    fs::create_dir(&late).unwrap();
    let new_grant = broker
        .authorize_directory(&late, &["md".into()], &Audience::Contacts, 1024)
        .unwrap();
    fs::write(late.join("late.md"), b"old").unwrap();
    broker
        .import_source(&new_grant, Path::new("late.md"))
        .unwrap();
    fs::remove_file(late.join("late.md")).unwrap();
    wait_until(Duration::from_secs(40), || !active(&db, "late.md"));
}

#[test]
fn failed_reconciliation_latches_closed_but_still_permits_revocation() {
    let fixture = Fixture::new();
    let home = fixture.0.join("home");
    let paths = AppPaths::open(&home).unwrap();
    let source = fixture.0.join("library");
    fs::create_dir(&source).unwrap();
    let mut broker = SnapshotBroker::open(&home).unwrap();
    let grant = broker
        .authorize_directory(&source, &["md".into()], &Audience::Contacts, 1024)
        .unwrap();
    fs::write(source.join("item.md"), b"abc").unwrap();
    broker.import_source(&grant, Path::new("item.md")).unwrap();
    drop(broker);
    let db = Connection::open(paths.state().join("asl.sqlite3")).unwrap();
    db.execute("UPDATE resources SET source_file_id='bad'", [])
        .unwrap();

    let mut libraries = LocalLibraries::open(&paths).unwrap();
    wait_until(Duration::from_secs(5), || {
        matches!(libraries.check_health(), Err(AslError::InvalidDatabase))
    });
    assert!(
        libraries
            .authorize_directory(&source, &["md".into()], &Audience::Public, 1024)
            .is_err()
    );
    assert!(
        libraries
            .import_source(&grant, Path::new("item.md"))
            .is_err()
    );
    libraries.revoke_directory(&grant).unwrap();
    assert!(!active(&db, "item.md"));
}
