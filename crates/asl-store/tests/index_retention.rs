use asl_store::open_store;
use rusqlite::Connection;

fn count(db: &Connection, sql: &str) -> i64 {
    db.query_row(sql, [], |row| row.get(0)).unwrap()
}

fn indexed_keys(db: &Connection, sql: &str) -> Vec<String> {
    db.prepare(sql)
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

// Inspect the live FTS content and the inverted index, without a visibility join.
fn assert_index(db: &Connection, expected: &[String]) {
    let mut expected = expected.to_vec();
    expected.sort();
    for sql in [
        "SELECT resource_key FROM resource_fts ORDER BY resource_key",
        "SELECT resource_key FROM resource_fts WHERE resource_fts MATCH 'marker' ORDER BY resource_key",
    ] {
        assert_eq!(indexed_keys(db, sql), expected, "{sql}");
    }
}

fn legacy_db(path: &std::path::Path, version: i64) -> Connection {
    let db = Connection::open(path).unwrap();
    db.pragma_update(None, "foreign_keys", true).unwrap();
    db.execute_batch(include_str!("../../../specs/schema-v1.sql"))
        .unwrap();
    db.execute("INSERT INTO schema_migrations VALUES (1,0)", [])
        .unwrap();
    if version == 2 {
        db.execute_batch(include_str!("../../../specs/schema-v2.sql"))
            .unwrap();
        db.execute("INSERT INTO schema_migrations VALUES (2,0)", [])
            .unwrap();
    }
    db.execute_batch(
        "INSERT INTO snapshots VALUES (printf('%064x',1),printf('%064x',1),4,1,'blob','manifest','ready',0);
         INSERT INTO grants(grant_id,root_path,volume_id,root_file_id,extensions_json,audience,
             model_policy,max_snapshot_bytes,status,created_at_ms)
             VALUES (printf('%032x',1),'root','v','f','[]','contacts','never',1024,'active',0),
                    (printf('%032x',2),'root','v','f','[]','public','never',1024,'revoked',0);
         WITH refs(n,grant_no,origin,active) AS (VALUES
             (1,1,'local',1),(2,1,'local',0),(3,2,'local',1),(4,NULL,'remote',1),
             (6,1,'local',1),(7,1,'local',1))
         INSERT INTO resources(row_id,resource_key,grant_id,content_id,origin,active,title,summary,
             evidence_status,created_at_ms,updated_at_ms)
             SELECT n,printf('%032x',n),CASE WHEN grant_no IS NOT NULL THEN printf('%032x',grant_no) END,
                    printf('%064x',1),origin,active,'title','summary','source_backed',0,0 FROM refs;
         INSERT INTO resource_fts(rowid,resource_key,body_tokens)
             SELECT row_id,CASE WHEN row_id=6 THEN printf('%032x',99) ELSE resource_key END,'marker' FROM resources;
         INSERT INTO resource_fts(rowid,resource_key,body_tokens) VALUES (5,printf('%032x',5),'marker');",
    ).unwrap();
    if version == 2 {
        db.execute("UPDATE resources SET source_grant_epoch=CASE WHEN row_id=7 THEN 2 ELSE 1 END WHERE origin='local'", []).unwrap();
    }
    db
}

#[test]
fn upgrades_v1_and_v2_prune_stale_text_but_preserve_history_and_live_references() {
    for version in [1, 2] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("legacy.sqlite3");
        let db = legacy_db(&path, version);
        let remote = format!("{:032x}", 4);
        let expected = if version == 1 {
            vec![remote]
        } else {
            vec![format!("{:032x}", 1), remote]
        };
        for _ in 0..2 {
            let store = open_store(&path).unwrap();
            assert_index(&db, &expected);
            assert_eq!(store.schema_version(), 12);
            assert_eq!(count(&db, "SELECT count(*) FROM resources"), 6);
            assert_eq!(count(&db, "SELECT active FROM resources WHERE row_id=2"), 0);
        }
    }
}

#[test]
fn a_failed_v3_upgrade_restores_legacy_rows_and_can_retry() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("rollback.sqlite3");
    let db = legacy_db(&path, 2);
    let before = indexed_keys(
        &db,
        "SELECT resource_key FROM resource_fts ORDER BY resource_key",
    );
    assert_eq!(before.len(), 7);
    db.execute_batch(
        "CREATE TRIGGER fail_v3 BEFORE INSERT ON schema_migrations WHEN NEW.version=3
        BEGIN SELECT RAISE(ABORT,'reject version stamp'); END;",
    )
    .unwrap();
    assert!(open_store(&path).is_err());
    assert_index(&db, &before);
    assert_eq!(count(&db, "SELECT max(version) FROM schema_migrations"), 2);
    db.execute_batch("DROP TRIGGER fail_v3").unwrap();
    open_store(&path).unwrap();
    assert_index(&db, &[format!("{:032x}", 1), format!("{:032x}", 4)]);
}

#[cfg(windows)]
mod lifecycle {
    use super::*;
    use asl_policy::Audience;
    use asl_store::resources::SnapshotBroker;
    use asl_types::task::{GrantId, ResourceKey};
    use std::{fs, path::Path};
    use tempfile::TempDir;

    struct Fixture {
        broker: SnapshotBroker,
        db: Connection,
        temp: TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let home = temp.path().join("home");
            fs::create_dir_all(home.join("state")).unwrap();
            fs::create_dir(temp.path().join("source")).unwrap();
            Self {
                broker: SnapshotBroker::open(&home).unwrap(),
                db: Connection::open(home.join("state/asl.sqlite3")).unwrap(),
                temp,
            }
        }

        fn grant(&mut self, audience: Audience) -> GrantId {
            self.broker
                .authorize_directory(
                    &self.temp.path().join("source"),
                    &["txt".into()],
                    &audience,
                    65536,
                )
                .unwrap()
        }

        fn write(&self, text: &str) {
            fs::write(self.temp.path().join("source/item.txt"), text).unwrap();
        }

        fn import(&mut self, grant: &GrantId) -> ResourceKey {
            self.broker
                .import_source(grant, Path::new("item.txt"))
                .unwrap()
        }
    }

    fn key(reference: &ResourceKey) -> String {
        hex::encode(reference.0.0)
    }

    #[test]
    fn repeated_dedup_revoke_keeps_one_live_row_and_all_inactive_references() {
        let mut f = Fixture::new();
        f.write("shared marker");
        let public = f.grant(Audience::Public);
        let kept = key(&f.import(&public));
        for retired in 1..=8 {
            let grant = f.grant(Audience::Contacts);
            let transient = key(&f.import(&grant));
            assert_index(&f.db, &[kept.clone(), transient]);
            f.broker.revoke_directory(&grant).unwrap();
            assert_index(&f.db, std::slice::from_ref(&kept));
            assert_eq!(
                count(&f.db, "SELECT count(*) FROM resources WHERE active=0"),
                retired
            );
            assert_eq!(count(&f.db, "SELECT count(*) FROM snapshots"), 1);
        }
    }

    #[test]
    fn replacement_then_source_loss_retires_each_index_permanently() {
        let mut f = Fixture::new();
        let grant = f.grant(Audience::Public);
        f.write("marker previous");
        let old = f.import(&grant);
        f.write("marker replacement");
        let new = f.import(&grant);
        assert_ne!(old, new);
        assert_index(&f.db, &[key(&new)]);
        fs::remove_file(f.temp.path().join("source/item.txt")).unwrap();
        assert!(!f.broker.refresh_source(&new).unwrap());
        assert_index(&f.db, &[]);
        f.write("marker previous");
        let fresh = f.import(&grant);
        assert_ne!(fresh, old);
        assert_index(&f.db, &[key(&fresh)]);
        assert_eq!(
            count(&f.db, "SELECT count(*) FROM resources WHERE active=0"),
            2
        );
    }

    #[test]
    fn hard_delete_and_its_rollback_include_the_index() {
        let mut f = Fixture::new();
        f.write("shared marker");
        let a = f.grant(Audience::Public);
        let b = f.grant(Audience::Contacts);
        let a = key(&f.import(&a));
        let b = key(&f.import(&b));
        for commit in [false, true] {
            let tx = f.db.transaction().unwrap();
            assert_eq!(
                tx.execute("DELETE FROM resources WHERE resource_key=?1", [&a])
                    .unwrap(),
                1
            );
            assert_index(&tx, std::slice::from_ref(&b));
            if commit {
                tx.commit().unwrap();
                assert_index(&f.db, std::slice::from_ref(&b));
            } else {
                tx.rollback().unwrap();
                assert_index(&f.db, &[a.clone(), b.clone()]);
            }
        }
    }

    #[test]
    fn grant_status_change_removes_only_its_rows_before_commit() {
        let mut f = Fixture::new();
        f.write("shared marker");
        let a = f.grant(Audience::Contacts);
        let b = f.grant(Audience::Public);
        let removed = key(&f.import(&a));
        let kept = key(&f.import(&b));
        let tx = f.db.transaction().unwrap();
        tx.execute(
            "UPDATE grants SET status='revoked' WHERE grant_id=?1",
            [hex::encode(a.0.0)],
        )
        .unwrap();
        assert_index(&tx, std::slice::from_ref(&kept));
        tx.rollback().unwrap();
        assert_index(&f.db, &[removed, kept]);
    }

    #[test]
    fn failed_index_delete_does_not_commit_a_partial_revoke() {
        let mut f = Fixture::new();
        f.write("private marker");
        let grant = f.grant(Audience::Contacts);
        let live = key(&f.import(&grant));
        let revision = count(&f.db, "SELECT revision FROM policy_state");
        f.db.execute_batch(
            "CREATE TRIGGER fail_fts_delete BEFORE DELETE ON resource_fts_content
            BEGIN SELECT RAISE(ABORT,'index delete failed'); END;",
        )
        .unwrap();
        assert!(f.broker.revoke_directory(&grant).is_err());
        assert_index(&f.db, &[live]);
        assert_eq!(
            count(
                &f.db,
                "SELECT count(*) FROM grants WHERE status='active' AND epoch=1"
            ),
            1
        );
        assert_eq!(count(&f.db, "SELECT active FROM resources"), 1);
        assert_eq!(count(&f.db, "SELECT revision FROM policy_state"), revision);
        f.db.execute_batch("DROP TRIGGER fail_fts_delete").unwrap();
        f.broker.revoke_directory(&grant).unwrap();
        assert_index(&f.db, &[]);
    }
}
