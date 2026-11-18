#![cfg(windows)]

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{self, Command},
};

use asl_policy::Audience;
use asl_store::resources::SnapshotBroker;
use asl_types::{ids::Id128, task::GrantId};
use rusqlite::{Connection, OptionalExtension};
use tempfile::TempDir;

const CHILD_EXIT: i32 = 73;
const SRC: &str = "item.md";
const EXPIRE: &str =
    "UPDATE reservations SET expires_at_ms=0 WHERE kind='snapshot' AND state='held'";

struct Fixture {
    home: PathBuf,
    broker: SnapshotBroker,
    db: Connection,
    grant: GrantId,
    _dir: TempDir,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let source = dir.path().join("source");
        fs::create_dir_all(home.join("state")).unwrap();
        fs::create_dir(&source).unwrap();
        fs::write(source.join(SRC), vec![17; (1 << 20) + 1]).unwrap();
        let mut broker = SnapshotBroker::open(&home).unwrap();
        let grant = broker
            .authorize_directory(&source, &["md".into()], &Audience::Public, 16 << 20)
            .unwrap();
        let db = database(&home);
        Self {
            home,
            broker,
            db,
            grant,
            _dir: dir,
        }
    }

    fn crash(mut self) -> (Self, String) {
        // No parent connection or pinned home survives the child's abrupt exit.
        drop(self.broker);
        drop(self.db);
        let status = Command::new(env::current_exe().unwrap())
            .args(["--exact", "crash_child", "--ignored", "--nocapture"])
            .env("ASL_TEST_RECOVERY_HOME", &self.home)
            .env("ASL_TEST_RECOVERY_GRANT", hex::encode(self.grant.0.0))
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(CHILD_EXIT));
        self.broker = SnapshotBroker::open(&self.home).unwrap();
        self.db = database(&self.home);
        let id = intent(&self.db).unwrap();
        (self, id)
    }
}

fn database(home: &Path) -> Connection {
    Connection::open(home.join("state/asl.sqlite3")).unwrap()
}

fn intent(db: &Connection) -> Option<String> {
    db.query_row("SELECT install_content_id FROM snapshot_imports
        JOIN reservations USING(reservation_id) WHERE state='held' AND install_content_id IS NOT NULL",
        [], |r| r.get(0)).optional().unwrap()
}

fn count(db: &Connection, sql: &str) -> i64 {
    db.query_row(sql, [], |r| r.get(0)).unwrap()
}

fn objects(home: &Path, id: &str) -> [PathBuf; 2] {
    [
        home.join(format!("snapshots/{}/{id}.blob", &id[..2])),
        home.join(format!("manifests/{}/{id}.mnf", &id[..2])),
    ]
}

#[test]
#[ignore = "subprocess entry point"]
fn crash_child() {
    let home = PathBuf::from(env::var_os("ASL_TEST_RECOVERY_HOME").unwrap());
    let mut broker = SnapshotBroker::open(&home).unwrap();
    if env::var_os("ASL_TEST_CHECK_LIVE_OWNER").is_some() {
        let report = broker.recover_expired_imports().unwrap();
        assert_eq!((report.released, report.live_owners), (0, 1));
        return;
    }
    let grant = GrantId(Id128(
        hex::decode(env::var("ASL_TEST_RECOVERY_GRANT").unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    ));
    let db = database(&home);
    let mut install_callbacks = 0;
    broker
        .import_with_progress(&grant, Path::new(SRC), || {
            if intent(&db).is_some() {
                install_callbacks += 1;
                // The first install callback precedes opening the final blob;
                // the second follows writing/verifying its first chunk.
                if install_callbacks == 2 {
                    process::exit(CHILD_EXIT);
                }
            }
            Ok(())
        })
        .unwrap();
    panic!("import did not reach the crash point");
}

#[test]
fn restart_removes_partial_blob_only_after_expiry() {
    let (mut f, id) = Fixture::new().crash();
    let [blob, manifest] = objects(&f.home, &id);
    assert_eq!(fs::metadata(&blob).unwrap().len(), 1 << 20);
    assert!(!manifest.exists());
    assert_eq!(f.broker.recover_expired_imports().unwrap().released, 0);
    assert!(blob.exists());
    f.db.execute(EXPIRE, []).unwrap();
    let mut restarted = SnapshotBroker::open(&f.home).unwrap();
    assert!(!blob.exists());
    assert!(intent(&f.db).is_none());
    assert_eq!(
        count(
            &f.db,
            "SELECT count(*) FROM reservations WHERE state='released'"
        ),
        1
    );
    assert_eq!(
        count(&f.db, "SELECT count(*) FROM tasks WHERE state='failed'"),
        1
    );
    assert_eq!(restarted.recover_expired_imports().unwrap().released, 0);
    restarted.import_source(&f.grant, Path::new(SRC)).unwrap();
}

#[test]
fn restart_preserves_ready_dedup_objects() {
    let mut f = Fixture::new();
    f.broker.import_source(&f.grant, Path::new(SRC)).unwrap();
    let ready: String =
        f.db.query_row("SELECT content_id FROM snapshots", [], |r| r.get(0))
            .unwrap();
    let [blob, manifest] = objects(&f.home, &ready);
    let before = [fs::read(&blob).unwrap(), fs::read(&manifest).unwrap()];
    let (f, id) = f.crash();
    assert_eq!(id, ready);
    f.db.execute(EXPIRE, []).unwrap();
    let _restarted = SnapshotBroker::open(&f.home).unwrap();
    assert_eq!(
        [fs::read(blob).unwrap(), fs::read(manifest).unwrap()],
        before
    );
    assert_eq!(
        count(
            &f.db,
            "SELECT count(*) FROM reservations WHERE state='released'"
        ),
        1
    );
    assert_eq!(
        count(&f.db, "SELECT count(*) FROM snapshots WHERE state='ready'"),
        1
    );
}

#[test]
fn live_owner_survives_expiry_and_serializes_same_content() {
    let mut f = Fixture::new();
    let mut other = SnapshotBroker::open(&f.home).unwrap();
    let mut checked = false;
    let result = f.broker.import_with_progress(&f.grant,Path::new(SRC),|| {
        if !checked && intent(&f.db).is_some() {
            checked = true;
            let err = other.import_source(&f.grant,Path::new(SRC)).unwrap_err();
            assert!(matches!(err, asl_types::error::AslError::Io(e) if e.kind() == std::io::ErrorKind::WouldBlock));
            f.db.execute(EXPIRE, []).unwrap();
            let result = Command::new(env::current_exe().unwrap())
                .args(["--exact","crash_child","--ignored","--nocapture"])
                .env("ASL_TEST_RECOVERY_HOME",&f.home)
                .env("ASL_TEST_CHECK_LIVE_OWNER","1").status().unwrap();
            assert!(result.success());
            assert_eq!(count(&f.db,"SELECT count(*) FROM reservations WHERE state='held'"),1);
        }
        Ok(())
    });
    assert!(checked && result.is_err());
    assert_eq!(
        count(
            &f.db,
            "SELECT count(*) FROM reservations WHERE state='held'"
        ),
        0
    );
}

#[test]
fn blocked_orphan_cleanup_retains_quota_until_retry() {
    use std::os::windows::fs::OpenOptionsExt;
    let (mut f, id) = Fixture::new().crash();
    let [blob, _] = objects(&f.home, &id);
    let pin = fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(&blob)
        .unwrap();
    f.db.execute(EXPIRE, []).unwrap();
    let report = f.broker.recover_expired_imports().unwrap();
    assert_eq!((report.released, report.deferred), (0, 1));
    assert_eq!(intent(&f.db), Some(id));
    assert_eq!(
        count(&f.db, "SELECT count(*) FROM tasks WHERE state='queued'"),
        1
    );
    drop(pin);
    assert_eq!(f.broker.recover_expired_imports().unwrap().released, 1);
    assert!(!blob.exists());
}

#[test]
fn known_commit_failure_cleans_objects_and_releases_immediately() {
    let mut f = Fixture::new();
    f.db.execute_batch(
        "CREATE TABLE recovery_commit_test(grant_id TEXT REFERENCES grants(grant_id) DEFERRABLE INITIALLY DEFERRED);
         CREATE TRIGGER recovery_commit_failure AFTER INSERT ON resources BEGIN
            INSERT INTO recovery_commit_test VALUES ('absent'); END;"
    ).unwrap();
    let mut id = None;
    let result = f.broker.import_with_progress(&f.grant, Path::new(SRC), || {
        id = intent(&f.db);
        Ok(())
    });
    assert!(matches!(result, Err(asl_types::error::AslError::Io(_))));
    assert!(objects(&f.home, &id.unwrap()).iter().all(|p| !p.exists()));
    assert_eq!(count(&f.db, "SELECT count(*) FROM snapshots"), 0);
    assert_eq!(
        count(
            &f.db,
            "SELECT count(*) FROM reservations WHERE state='released'"
        ),
        1
    );
}

#[test]
fn unreferenced_preexisting_names_are_never_adopted_or_removed() {
    use asl_types::manifest::{CHUNK_SIZE, Manifest, content_id, encode_manifest};
    let bytes = vec![17; (1 << 20) + 1];
    let manifest = Manifest {
        file_size: bytes.len() as u64,
        file_hash: *blake3::hash(&bytes).as_bytes(),
        chunk_hashes: bytes
            .chunks(CHUNK_SIZE as usize)
            .map(|c| *blake3::hash(c).as_bytes())
            .collect(),
    };
    let encoded = encode_manifest(&manifest).unwrap();
    let id = hex::encode(content_id(&encoded));
    for (blob_before, manifest_before) in [
        (Some(&b"preexisting blob"[..]), None),
        (None, Some(&b"preexisting manifest"[..])),
        (
            Some(&b"preexisting blob"[..]),
            Some(&b"preexisting manifest"[..]),
        ),
        (Some(bytes.as_slice()), Some(encoded.as_slice())),
    ] {
        let mut f = Fixture::new();
        let names = objects(&f.home, &id);
        let expected = [blob_before, manifest_before];
        for (name, contents) in names.iter().zip(expected) {
            if let Some(contents) = contents {
                fs::create_dir_all(name.parent().unwrap()).unwrap();
                fs::write(name, contents).unwrap();
            }
        }
        assert!(
            f.broker
                .import_with_progress(&f.grant, Path::new(SRC), || {
                    assert!(
                        intent(&f.db).is_none(),
                        "a collision must never acquire a durable claim"
                    );
                    Ok(())
                })
                .is_err()
        );
        assert_eq!(
            count(
                &f.db,
                "SELECT count(*) FROM reservations WHERE state='released'"
            ),
            1
        );
        assert_eq!(
            count(
                &f.db,
                "SELECT count(*) FROM reservations WHERE state='held'"
            ),
            0
        );
        assert_eq!(count(&f.db, "SELECT count(*) FROM snapshots"), 0);
        let _restart = SnapshotBroker::open(&f.home).unwrap();
        for (name, contents) in names.iter().zip(expected) {
            match contents {
                Some(contents) => assert_eq!(fs::read(name).unwrap(), contents),
                None => assert!(!name.try_exists().unwrap()),
            }
        }
    }
}

#[test]
fn startup_cursor_passes_a_full_page_of_live_owners() {
    use asl_policy::snapshot_files::ImportOwner;
    let mut f = Fixture::new();
    let tx = f.db.transaction().unwrap();
    let mut owners = Vec::new();
    for index in 0..17u128 {
        let id = index.to_be_bytes();
        let key = hex::encode(id);
        tx.execute(
            "INSERT INTO tasks(task_id,direction,audience_json,state,created_at_ms,expires_at_ms)
            VALUES (?1,'local','{}','queued',0,0)",
            [&key],
        )
        .unwrap();
        tx.execute("INSERT INTO reservations(reservation_id,task_id,kind,bytes,state,progress_at_ms,expires_at_ms)
            VALUES (?1,?1,'snapshot',0,'held',0,0)",[&key]).unwrap();
        tx.execute(
            "INSERT INTO snapshot_imports(reservation_id,grant_id,grant_epoch,physical_bytes)
            VALUES (?1,?2,1,1)",
            rusqlite::params![key, hex::encode(f.grant.0.0)],
        )
        .unwrap();
        if index < 16 {
            owners.push(ImportOwner::try_acquire(&f.home, id).unwrap().unwrap());
        }
    }
    tx.commit().unwrap();
    assert_eq!(f.broker.recover_expired_imports().unwrap().live_owners, 16);
    let mut restarted = SnapshotBroker::open(&f.home).unwrap();
    assert_eq!(
        count(
            &f.db,
            "SELECT count(*) FROM reservations WHERE state='released'"
        ),
        1
    );
    drop(owners);
    assert_eq!(restarted.recover_expired_imports().unwrap().released, 16);
}
