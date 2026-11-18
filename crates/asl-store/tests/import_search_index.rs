#![cfg(windows)]

use std::{fs, path::Path};

use asl_policy::Audience;
use asl_store::{open_store, resources::SnapshotBroker, search::LocalIndexText};
use asl_types::{ids::Hash32, protocol::ConceptRef, task::GrantId};
use rusqlite::Connection;
use tempfile::TempDir;

struct Fixture {
    broker: SnapshotBroker,
    db: Connection,
    grant: GrantId,
    temp: TempDir,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let source = temp.path().join("source");
        fs::create_dir_all(home.join("state")).unwrap();
        fs::create_dir_all(source.join("privatefolder")).unwrap();
        let mut broker = SnapshotBroker::open(&home).unwrap();
        let extensions = ["md", "txt", "rs", "pdf", "bin"].map(str::to_owned);
        let grant = broker
            .authorize_directory(&source, &extensions, &Audience::Contacts, 8 << 20)
            .unwrap();
        let db = Connection::open(home.join("state/asl.sqlite3")).unwrap();
        Self {
            broker,
            db,
            grant,
            temp,
        }
    }

    fn write(&self, name: &str, bytes: &[u8]) {
        fs::write(self.temp.path().join("source").join(name), bytes).unwrap();
    }

    fn import(&mut self, name: &str) -> String {
        hex::encode(
            self.broker
                .import_source(&self.grant, Path::new(name))
                .unwrap()
                .0
                .0,
        )
    }

    fn hits(&self, key: &str, query: &str) -> i64 {
        self.db
            .query_row(
                "SELECT count(*) FROM resource_fts WHERE resource_key=?1 AND resource_fts MATCH ?2",
                [key, query],
                |r| r.get(0),
            )
            .unwrap()
    }
}

#[test]
fn indexes_basename_and_only_the_bounded_utf8_prefix() {
    let mut f = Fixture::new();
    let name = "privatefolder/Notebook.MD";
    let mut bytes = b"headmarker ".to_vec();
    bytes.resize(32767 - b"edgemarker ".len(), b' ');
    bytes.extend_from_slice(b"edgemarker ");
    bytes.extend_from_slice("\u{1f4d6} overflowmarker".as_bytes());
    bytes.resize(1 << 20, b' ');
    bytes.extend_from_slice(b" nextchunkmarker");
    f.write(name, &bytes);
    let key = f.import(name);
    assert_eq!(f.hits(&key, "title_tokens:notebook"), 1);
    for term in ["headmarker", "edgemarker"] {
        assert_eq!(f.hits(&key, &format!("body_tokens:{term}")), 1);
    }
    for term in ["privatefolder", "overflowmarker", "nextchunkmarker"] {
        assert_eq!(f.hits(&key, term), 0);
    }
    let metadata: (String, String, String) =
        f.db.query_row(
            "SELECT title,summary,tags_json FROM resources WHERE resource_key=?1",
            [&key],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(metadata, ("Notebook.MD".into(), String::new(), "[]".into()));
}

#[test]
fn title_limit_counts_characters_and_uses_the_original_extension_for_body() {
    let mut f = Fixture::new();
    let prefix = "\u{e9}".repeat(159);
    let name = format!("{prefix}ab.rs");
    f.write(&name, b"sourceword");
    let key = f.import(&name);
    let title: String =
        f.db.query_row(
            "SELECT title FROM resources WHERE resource_key=?1",
            [&key],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(title, format!("{prefix}a"));
    assert_eq!(f.hits(&key, "body_tokens:sourceword"), 1);
    assert_eq!(f.hits(&key, "tag_tokens:v1c101"), 1);
}

#[test]
fn nontext_and_invalid_text_are_title_only() {
    let mut f = Fixture::new();
    for (name, bytes) in [
        ("paper.pdf", b"%PDF-1.7 secretphrase".as_slice()),
        ("unknown.bin", b"secretphrase"),
        ("invalid.txt", b"secretphrase \xff"),
        ("incomplete.txt", b"secretphrase \xe2\x82"),
        ("binary.md", b"secretphrase\0rest"),
        ("control.txt", b"secretphrase\x01rest"),
        ("disguised.txt", b"%PDF-1.7 secretphrase"),
        ("empty.txt", b""),
    ] {
        f.write(name, bytes);
        let key = f.import(name);
        assert_eq!(
            f.hits(
                &key,
                &format!("title_tokens:{}", name.split('.').next().unwrap())
            ),
            1,
            "{name}"
        );
        assert_eq!(f.hits(&key, "secretphrase"), 0, "{name}");
    }
}

#[test]
fn reimport_backfills_an_unindexed_t11_row_and_leaves_enriched_data_alone() {
    let mut f = Fixture::new();
    let name = "legacy.txt";
    f.write(name, b"originalbody");
    let key = f.import(name);
    f.db.execute("DELETE FROM resource_fts WHERE resource_key=?1", [&key])
        .unwrap();
    f.db.execute(
        "UPDATE resources SET title='' WHERE resource_key=?1",
        [&key],
    )
    .unwrap();
    assert_eq!(f.import(name), key);
    assert_eq!(f.hits(&key, "body_tokens:originalbody"), 1);
    let resource = f.broker.import_source(&f.grant, Path::new(name)).unwrap();
    let content: String =
        f.db.query_row(
            "SELECT content_id FROM resources WHERE resource_key=?1",
            [&key],
            |r| r.get(0),
        )
        .unwrap();
    let content = Hash32(hex::decode(content).unwrap().try_into().unwrap());
    let mut store = open_store(&f.temp.path().join("home/state/asl.sqlite3")).unwrap();
    store
        .index_local_text(
            &resource,
            content,
            LocalIndexText {
                title: "Edited",
                summary: "Curated",
                body: "enriched",
                concepts: &[ConceptRef {
                    vocabulary_id: 1,
                    concept_id: 100,
                }],
            },
        )
        .unwrap();
    assert_eq!(f.import(name), key);
    assert_eq!(f.hits(&key, "enriched"), 1);
    assert_eq!(f.hits(&key, "originalbody"), 0);
    let metadata: (String, String, String) =
        f.db.query_row(
            "SELECT title,summary,tags_json FROM resources WHERE resource_key=?1",
            [&key],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        metadata,
        ("Edited".into(), "Curated".into(), "[[1,100]]".into())
    );
}

#[test]
fn failed_index_write_rolls_back_the_snapshot_and_resource() {
    let mut f = Fixture::new();
    f.write("atomic.txt", b"must not be published");
    f.db.execute_batch(
        "CREATE TRIGGER fail_index BEFORE INSERT ON resource_fts_content
        BEGIN SELECT RAISE(ABORT, 'index write failed'); END;",
    )
    .unwrap();
    assert!(
        f.broker
            .import_source(&f.grant, Path::new("atomic.txt"))
            .is_err()
    );
    for sql in [
        "SELECT count(*) FROM snapshots",
        "SELECT count(*) FROM resources",
        "SELECT count(*) FROM reservations WHERE state='held'",
    ] {
        assert_eq!(f.db.query_row(sql, [], |r| r.get::<_, i64>(0)).unwrap(), 0);
    }
    f.db.execute_batch("DROP TRIGGER fail_index").unwrap();
    let key = f.import("atomic.txt");
    assert_eq!(f.hits(&key, "published"), 1);
}
