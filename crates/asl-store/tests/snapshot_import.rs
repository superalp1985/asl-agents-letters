#![cfg(windows)]

use std::{
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

use asl_policy::{Audience, reconcile::ReconcileDriver};
use asl_store::resources::SnapshotBroker;
use asl_types::{error::AslError, task::GrantId};
use rusqlite::Connection;
use tempfile::TempDir;

struct Fixture {
    // Drop connections and pinned handles before the temporary directories.
    broker: SnapshotBroker,
    db: Connection,
    source: PathBuf,
    home: PathBuf,
    _temp: TempDir,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        fs::create_dir_all(home.join("state")).unwrap();
        let source = temp.path().join("source");
        fs::create_dir(&source).unwrap();
        Self {
            broker: SnapshotBroker::open(&home).unwrap(),
            db: Connection::open(home.join("state/asl.sqlite3")).unwrap(),
            source,
            home,
            _temp: temp,
        }
    }

    fn grant(&mut self, audience: Audience, bytes: u64) -> GrantId {
        self.broker
            .authorize_directory(&self.source, &["md".to_owned()], &audience, bytes)
            .unwrap()
    }

    fn count(&self, query: &str) -> i64 {
        self.db.query_row(query, [], |r| r.get(0)).unwrap()
    }
}

#[test]
fn equal_content_shares_objects_not_grants_and_reimport_is_idempotent() {
    let mut f = Fixture::new();
    fs::write(f.source.join("x.md"), b"hello").unwrap();
    let public = f.grant(Audience::Public, 1024);
    let contacts = f.grant(Audience::Contacts, 1024);
    let name = Path::new("x.md");
    let a = f.broker.import_source(&public, name).unwrap();
    let b = f.broker.import_source(&contacts, name).unwrap();
    assert_ne!(a, b);
    assert_eq!(a, f.broker.import_source(&public, name).unwrap());
    assert_eq!(
        f.count("SELECT count(*) FROM snapshots WHERE state='ready'"),
        1
    );
    assert_eq!(f.count("SELECT count(DISTINCT audience) FROM resources JOIN grants USING(grant_id) WHERE active=1"),2);
    let (blob, manifest, id): (String, String, String) =
        f.db.query_row(
            "SELECT blob_relative,manifest_relative,content_id FROM snapshots",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(fs::read(f.home.join(blob)).unwrap(), b"hello");
    let bytes = fs::read(f.home.join(manifest)).unwrap();
    let decoded =
        asl_types::manifest::decode_manifest(&bytes, asl_types::manifest::content_id(&bytes))
            .unwrap();
    assert_eq!(id, hex::encode(asl_types::manifest::content_id(&bytes)));
    assert_eq!(decoded.file_hash, *blake3::hash(b"hello").as_bytes());
    f.broker.revoke_directory(&public).unwrap();
    assert!(!f.broker.refresh_source(&a).unwrap());
    assert!(f.broker.refresh_source(&b).unwrap());
}

#[test]
fn quotas_precede_copy_and_include_concurrent_holds() {
    let mut f = Fixture::new();
    fs::write(f.source.join("small.md"), b"12345").unwrap();
    let grant = f.grant(Audience::Contacts, 1024);
    f.broker.set_snapshot_limits(189, 1024).unwrap();
    let name = Path::new("small.md");
    let run = f
        .broker
        .import_with_progress(&grant, name, || panic!("over-quota read"));
    assert!(matches!(run, Err(AslError::QuotaExceeded)));
    assert_eq!(f.count("SELECT count(*) FROM reservations"), 0);
    f.broker.set_snapshot_limits(190, 5).unwrap();
    let mut second = SnapshotBroker::open(&f.home).unwrap();
    let mut attempts = 0;
    f.broker
        .import_with_progress(&grant, name, || {
            if attempts == 0 {
                assert!(matches!(
                    second.import_with_progress(&grant, name, || panic!("double reservation")),
                    Err(AslError::QuotaExceeded)
                ));
            }
            attempts += 1;
            Ok(())
        })
        .unwrap();
    assert!(attempts > 0);
    assert_eq!(
        f.count("SELECT count(*) FROM reservations WHERE state='held'"),
        0
    );
}

#[test]
fn revoked_during_copy_and_failed_database_write_never_make_a_ready_resource() {
    let mut f = Fixture::new();
    fs::write(f.source.join("item.md"), vec![0x31; (1 << 20) + 1]).unwrap();
    let name = Path::new("item.md");
    let grant = f.grant(Audience::Public, 2 << 20);
    let mut other = SnapshotBroker::open(&f.home).unwrap();
    assert!(
        f.broker
            .import_with_progress(&grant, name, || other.revoke_directory(&grant))
            .is_err()
    );
    assert_eq!(f.count("SELECT count(*) FROM snapshots"), 0);
    assert_eq!(f.count("SELECT count(*) FROM resources"), 0);
    assert_eq!(
        f.count("SELECT count(*) FROM reservations WHERE state='released'"),
        1
    );
    let grant = f.grant(Audience::Public, 2 << 20);
    f.db.execute_batch("CREATE TRIGGER fail_resource BEFORE INSERT ON resources BEGIN SELECT RAISE(ABORT,'test failure'); END;").unwrap();
    assert!(f.broker.import_source(&grant, name).is_err());
    assert_eq!(f.count("SELECT count(*) FROM snapshots"), 0);
    assert_eq!(f.count("SELECT count(*) FROM resources"), 0);
    assert_eq!(
        f.count("SELECT count(*) FROM reservations WHERE state='released'"),
        2
    );
}

#[test]
fn lost_watcher_events_still_invalidate_deleted_and_same_size_changed_sources() {
    let mut f = Fixture::new();
    let grant = f.grant(Audience::Contacts, 1024);
    for name in ["changed.md", "deleted.md", "keep.md"] {
        fs::write(f.source.join(name), b"old").unwrap();
    }
    let changed = f
        .broker
        .import_source(&grant, Path::new("changed.md"))
        .unwrap();
    let removed = f
        .broker
        .import_source(&grant, Path::new("deleted.md"))
        .unwrap();
    let keep = f
        .broker
        .import_source(&grant, Path::new("keep.md"))
        .unwrap();
    let start = Instant::now();
    let mut driver = ReconcileDriver::new(start);
    driver.poll(start, &mut f.broker).unwrap();
    fs::write(f.source.join("changed.md"), b"new").unwrap();
    fs::remove_file(f.source.join("deleted.md")).unwrap();
    driver
        .poll(
            start + asl_policy::reconcile::RECONCILE_INTERVAL,
            &mut f.broker,
        )
        .unwrap();
    assert_eq!(f.count("SELECT count(*) FROM resources WHERE active=1"), 1);
    assert!(!f.broker.refresh_source(&changed).unwrap());
    assert!(!f.broker.refresh_source(&removed).unwrap());
    assert!(f.broker.refresh_source(&keep).unwrap());
    assert_ne!(
        changed,
        f.broker
            .import_source(&grant, Path::new("changed.md"))
            .unwrap()
    );
}

#[test]
fn missing_grant_wrong_extension_and_oversize_never_enter_copy() {
    let mut f = Fixture::new();
    fs::write(f.source.join("ignore.txt"), b"ignore").unwrap();
    let large = fs::File::create(f.source.join("large.md")).unwrap();
    large.set_len(8 << 20).unwrap();
    drop(large);
    let grant = f.grant(Audience::Contacts, 16 << 20);
    f.broker.set_snapshot_limits(1 << 20, 1 << 20).unwrap();
    for (id, path) in [
        (&grant, Path::new("ignore.txt")),
        (&grant, Path::new("large.md")),
        (
            &GrantId(asl_types::ids::Id128([0; 16])),
            Path::new("large.md"),
        ),
    ] {
        assert!(
            f.broker
                .import_with_progress(id, path, || panic!("denied before first read"))
                .is_err()
        );
    }
    assert_eq!(f.count("SELECT count(*) FROM tasks"), 0);
    assert_eq!(f.count("SELECT count(*) FROM reservations"), 0);
}

#[test]
fn lowered_budget_or_changed_epoch_discards_staged_content() {
    let mut f = Fixture::new();
    fs::write(f.source.join("item.md"), b"hello").unwrap();
    let grant = f.grant(Audience::Contacts, 1024);
    let mut other = SnapshotBroker::open(&f.home).unwrap();
    for lower_budget in [true, false] {
        other.set_snapshot_limits(2048, 1024).unwrap();
        let mut changed = false;
        let result = f
            .broker
            .import_with_progress(&grant, Path::new("item.md"), || {
                if !changed {
                    changed = true;
                    if lower_budget {
                        other.set_snapshot_limits(2048, 0)?;
                    } else {
                        f.db.execute(
                            "UPDATE grants SET epoch=epoch+1 WHERE grant_id=?1",
                            [hex::encode(grant.0.0)],
                        )
                        .unwrap();
                    }
                }
                Ok(())
            });
        assert!(changed && result.is_err());
        assert_eq!(f.count("SELECT count(*) FROM snapshots"), 0);
        assert_eq!(f.count("SELECT count(*) FROM resources"), 0);
        assert_eq!(
            f.count("SELECT count(*) FROM reservations WHERE state='held'"),
            0
        );
    }
}
