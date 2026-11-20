use std::{collections::HashSet, path::Path};

use asl_policy::{
    AccessOperation, Audience, AuthenticatedDevice, GrantPolicy, ModelPolicy, PolicyEngine,
    PolicyRevision, PolicyService, PolicySnapshot, ResourceOrigin, ResourcePolicy,
};
use asl_store::{
    Store, open_store,
    search::{LocalIndexText, direct::DirectRequester},
};
use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId},
    protocol::ConceptRef,
    task::{GrantId, ResourceKey},
};
use rusqlite::{Connection, params};
use tempfile::TempDir;

const STRANGER: u8 = 41;
const CONTACT: u8 = 42;
const LIMIT: u32 = 8;
const RUST: ConceptRef = ConceptRef {
    vocabulary_id: 1,
    concept_id: 101,
};
const PRIVATE: ConceptRef = ConceptRef {
    vocabulary_id: 1,
    concept_id: 103,
};

#[derive(Clone, Copy)]
struct Document {
    id: u8,
    content: u8,
    name: &'static str,
    title: &'static str,
    summary: &'static str,
    body: &'static str,
    concepts: &'static [ConceptRef],
}

const PUBLIC: Document = Document {
    id: 1,
    content: 11,
    name: "borrow.rs",
    title: "Rust notes",
    summary: "Ownership example",
    body: "A borrowchecker example for Rust",
    concepts: &[RUST],
};
const PDF: Document = Document {
    id: 2,
    content: 22,
    name: "handbook.pdf",
    title: "Rust 维护手册",
    summary: "联系人内部演练",
    body: "请在交接前更新密码并记录检查结果。",
    concepts: &[RUST, PRIVATE],
};
const ALIAS: Document = Document {
    id: 3,
    title: "Restricted annotation",
    summary: "Contact-only commentary",
    concepts: &[PRIVATE],
    ..PUBLIC
};
const INBOX: u8 = 4;

fn key(id: u8) -> ResourceKey {
    ResourceKey(Id128([id; 16]))
}
fn grant(id: u8) -> GrantId {
    GrantId(Id128([id + 16; 16]))
}
fn hash(id: u8) -> Hash32 {
    Hash32([id; 32])
}
fn agent(id: u8) -> AgentId {
    AgentId([id; 32])
}
fn agent_text(id: u8) -> String {
    bs58::encode(agent(id).as_bytes()).into_string()
}

fn peer(id: u8) -> PeerId {
    let mut bytes = vec![0, 36, 8, 1, 18, 32];
    bytes.extend_from_slice(&[id; 32]);
    PeerId::from_bytes(bytes).unwrap()
}

struct Fixture {
    store: Store,
    db: Connection,
    engine: PolicyEngine,
    _temp: TempDir,
}

impl Fixture {
    fn new(docs: &[Document], inbox: bool) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("search.sqlite3");
        let mut store = open_store(&path).unwrap();
        let db = Connection::open(&path).unwrap();
        db.pragma_update(None, "foreign_keys", true).unwrap();
        let mut snapshot = PolicySnapshot::default();
        db.execute("UPDATE policy_state SET revision=7 WHERE singleton=1", [])
            .unwrap();
        for id in [STRANGER, CONTACT] {
            db.execute(
                "INSERT INTO agents(agent_id,identity_state) VALUES (?1,'verified')",
                [agent_text(id)],
            )
            .unwrap();
            snapshot.devices.insert(
                peer(id),
                AuthenticatedDevice {
                    agent_id: agent(id),
                    active: true,
                    chain_valid_until_ms: i64::MAX as u64,
                    certificate_valid_until_ms: i64::MAX as u64,
                },
            );
        }
        db.execute(
            "INSERT INTO authorized_contacts(agent_id,authorized_at_ms,authorization_revision)
                    SELECT ?1,0,revision FROM policy_state WHERE singleton=1",
            [agent_text(CONTACT)],
        )
        .unwrap();
        db.execute(
            "INSERT INTO preferred_peers(agent_id,reason,last_used_ms) VALUES (?1,'fixture',0)",
            [agent_text(STRANGER)],
        )
        .unwrap();
        snapshot.contacts.insert(agent(CONTACT));

        for &doc in docs {
            let extension = Path::new(doc.name).extension().unwrap().to_str().unwrap();
            let public = doc.id == PUBLIC.id;
            let grant_id = grant(doc.id);
            let grant_text = hex::encode(grant_id.0.0);
            db.execute(
                "INSERT INTO grants(grant_id,root_path,volume_id,root_file_id,extensions_json,
                        audience,model_policy,max_snapshot_bytes,status,created_at_ms)
                        VALUES (?1,?2,'0000000000000001',?1,?3,?4,'never',4096,'active',0)",
                params![
                    grant_text,
                    temp.path().to_str().unwrap(),
                    serde_json::json!([extension]).to_string(),
                    if public { "public" } else { "contacts" }
                ],
            )
            .unwrap();
            let size = doc.body.len() as i64;
            seed_snapshot(&db, doc.content, size);
            db.execute("INSERT INTO resources(resource_key,content_id,grant_id,source_relative,source_file_id,
                        source_grant_epoch,origin,title,summary,evidence_status,created_at_ms,updated_at_ms)
                        VALUES (?1,?2,?3,?4,?5,1,'local','','','source_backed',0,0)",
                params![hex::encode(key(doc.id).0.0), hex::encode(hash(doc.content).0), grant_text, doc.name,
                    format!("0000000000000001:{}", hex::encode(key(doc.id).0.0))]).unwrap();
            snapshot.grants.insert(
                grant_id.clone(),
                GrantPolicy {
                    epoch: 1,
                    active: true,
                    audience: if public {
                        Audience::Public
                    } else {
                        Audience::Contacts
                    },
                    model_policy: ModelPolicy::Never,
                    extensions: HashSet::from([format!(".{extension}")]),
                    max_snapshot_bytes: 4096,
                    allowed_operations: HashSet::from([
                        AccessOperation::Search,
                        AccessOperation::ReadMetadata,
                    ]),
                    allow_derived_disclosure: false,
                },
            );
            snapshot.resources.insert(
                key(doc.id),
                ResourcePolicy {
                    content_id: hash(doc.content),
                    grant_id,
                    grant_epoch: 1,
                    active: true,
                    snapshot_ready: true,
                    file_size: size as u64,
                    extension: format!(".{extension}"),
                    retention_until_ms: None,
                    origin: ResourceOrigin::Local,
                },
            );
            store
                .index_local_text(
                    &key(doc.id),
                    hash(doc.content),
                    LocalIndexText {
                        title: doc.title,
                        summary: doc.summary,
                        body: doc.body,
                        concepts: doc.concepts,
                    },
                )
                .unwrap();
        }
        if inbox {
            seed_snapshot(&db, INBOX, 32);
            db.execute("INSERT INTO resources(resource_key,content_id,grant_id,origin,title,summary,
                        evidence_status,created_at_ms,updated_at_ms)
                        VALUES (?1,?2,NULL,'remote','Inbox note','Undisclosed inbox excerpt','source_backed',0,0)",
                params![hex::encode(key(INBOX).0.0), hex::encode(hash(INBOX).0)]).unwrap();
            // A local index can contain inbox text even though no read grant exists for it.
            db.execute("INSERT INTO resource_fts(rowid,resource_key,title_tokens,summary_tokens,body_tokens)
                        SELECT row_id,resource_key,title,summary,'inboxmarker rust 密码' FROM resources
                        WHERE resource_key=?1", [hex::encode(key(INBOX).0.0)]).unwrap();
        }
        snapshot.revision = PolicyRevision(store.policy_revision().unwrap());
        Self {
            store,
            db,
            engine: PolicyEngine::new(snapshot, 60_000).unwrap(),
            _temp: temp,
        }
    }
}

fn seed_snapshot(db: &Connection, id: u8, size: i64) {
    let content = hex::encode(hash(id).0);
    db.execute("INSERT INTO snapshots(content_id,file_hash,file_size,chunk_count,blob_relative,manifest_relative,
                state,created_at_ms) VALUES (?1,?1,?2,1,?3,?4,'ready',0) ON CONFLICT(content_id) DO NOTHING",
        params![content, size, format!("snapshots/{}/{content}.blob", &content[..2]),
            format!("manifests/{}/{content}.mnf", &content[..2])]).unwrap();
}

#[test]
fn durable_direct_search_requires_live_audience_at_disclosure() {
    use std::time::{SystemTime, UNIX_EPOCH};

    let fixture = Fixture::new(&[PUBLIC, PDF], true);
    fixture
        .db
        .execute_batch(
            "INSERT INTO chain_state_cache VALUES
            (1,zeroblob(20),zeroblob(32),0,zeroblob(32),zeroblob(32),zeroblob(32),x'',0);
         INSERT INTO identity_registry_states SELECT
            agent_id,1,zeroblob(20),zeroblob(32),1,'active',0,zeroblob(32),0 FROM agents;",
        )
        .unwrap();
    fixture
        .db
        .execute(
            "WITH RECURSIVE seq(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM seq WHERE i<4096)
         INSERT INTO resources(row_id,resource_key,content_id,grant_id,origin,title,summary,
            evidence_status,created_at_ms,updated_at_ms,active)
         SELECT -seq.i,printf('%032x',seq.i+100),r.content_id,r.grant_id,'local','','',
            'source_backed',0,0,0 FROM seq CROSS JOIN resources r WHERE r.row_id=1",
            [],
        )
        .unwrap();
    let until = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
        + 60_000;
    let requester = |id| DirectRequester {
        agent: agent(id),
        peer: peer(id),
        session_expires_at_ms: until,
        registry_sequence: 1,
        directory_commitment: [0; 32],
        controller: [0; 20],
    };
    let stranger = requester(STRANGER);
    let (snapshot, keys) = fixture.store.direct_search_snapshot(&stranger).unwrap();
    assert_keys(keys, &[PUBLIC.id]);
    assert!(snapshot.contacts.is_empty());

    let contact = requester(CONTACT);
    let (snapshot, keys) = fixture.store.direct_search_snapshot(&contact).unwrap();
    let revision = snapshot.revision;
    let engine = PolicyEngine::new(snapshot, 60_000).unwrap();
    let policy = engine.for_peer(contact.peer.clone());
    let hits = fixture
        .store
        .peer_search(&policy, contact.agent)
        .search_with_metadata_permits(&keys, &[PRIVATE], 1)
        .unwrap();
    let (hit, permit) = &hits[0];
    assert_eq!(hit.content_id, hash(PDF.content));
    assert_eq!(permit.file_size(), PDF.body.len() as u64);
    assert!(
        fixture
            .store
            .with_current_direct_authority(&contact, revision, Some(permit), || Ok(()))
            .is_ok()
    );
    assert!(
        fixture
            .store
            .with_current_direct_authority::<()>(&stranger, revision, Some(permit), || panic!(
                "wrong device"
            ))
            .is_err()
    );
    fixture
        .db
        .execute(
            "DELETE FROM authorized_contacts WHERE agent_id=?1",
            [agent_text(CONTACT)],
        )
        .unwrap();
    assert!(matches!(
        fixture
            .store
            .with_current_direct_authority(&contact, revision, Some(permit), || panic!(
                "revoked contact"
            )),
        Err::<(), _>(AslError::NotFound)
    ));
    fixture
        .db
        .execute(
            "UPDATE identity_registry_states SET sequence=2 WHERE agent_id=?1",
            [agent_text(STRANGER)],
        )
        .unwrap();
    assert!(matches!(
        fixture.store.direct_search_snapshot(&stranger),
        Err(AslError::NotFound)
    ));
    assert!(matches!(
        fixture
            .store
            .with_current_direct_authority(&stranger, revision, None, || Ok(())),
        Err(AslError::NotFound)
    ));
}

fn assert_keys(mut actual: Vec<ResourceKey>, expected: &[u8]) {
    actual.sort_by_key(|k| k.0.0);
    assert_eq!(
        actual,
        expected.iter().copied().map(key).collect::<Vec<_>>()
    );
}

fn no_disclosure<T>(result: Result<Vec<T>, AslError>) {
    match result {
        Ok(hits) => assert!(
            hits.is_empty(),
            "unexpectedly disclosed {} entries",
            hits.len()
        ),
        Err(AslError::NotFound | AslError::PolicyDenied | AslError::PolicyVersionConflict) => (),
        Err(err) => panic!("unexpected search error: {err}"),
    }
}

#[test]
fn only_a_contact_can_find_the_pdf_by_a_word_in_its_chinese_body() {
    let f = Fixture::new(&[PUBLIC, PDF], true);
    for id in [STRANGER, CONTACT] {
        let scope = f.engine.for_peer(peer(id));
        let search = f.store.peer_search(&scope, agent(id));
        let keys = search.visible_keys().unwrap();
        if id == CONTACT {
            assert_keys(keys.clone(), &[PUBLIC.id, PDF.id]);
        } else {
            assert_keys(keys.clone(), &[PUBLIC.id]);
        }
        let text = search.search_local_text(&keys, "密码", LIMIT).unwrap();
        let concepts = search.search_visible(&keys, &[PRIVATE], LIMIT).unwrap();
        for hits in [text, concepts] {
            if id == CONTACT {
                assert_eq!(hits.len(), 1);
                let hit = &hits[0];
                assert_eq!(hit.resource_key, key(PDF.id));
                assert_eq!(hit.content_id, hash(PDF.content));
                assert_eq!(hit.local_title, PDF.title);
                assert_eq!(hit.local_summary, PDF.summary);
                assert!(hit.local_concept_ids.contains(&PRIVATE));
            } else {
                assert!(hits.is_empty());
            }
        }
        assert!(
            search
                .search_local_text(&keys, "inboxmarker", LIMIT)
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn hidden_documents_do_not_change_public_counts_scores_or_snippets() {
    let baseline = Fixture::new(&[PUBLIC], false);
    let mixed = Fixture::new(&[PDF, PUBLIC], true);
    let left_scope = baseline.engine.for_peer(peer(STRANGER));
    let right_scope = mixed.engine.for_peer(peer(STRANGER));
    let left = baseline.store.peer_search(&left_scope, agent(STRANGER));
    let right = mixed.store.peer_search(&right_scope, agent(STRANGER));
    let a = left.visible_keys().unwrap();
    let b = right.visible_keys().unwrap();
    for limit in [1, LIMIT] {
        for (before, after) in [
            (
                left.search_local_text(&a, "rust", limit),
                right.search_local_text(&b, "rust", limit),
            ),
            (
                left.search_visible(&a, &[RUST], limit),
                right.search_visible(&b, &[RUST], limit),
            ),
        ] {
            let (before, after) = (before.unwrap(), after.unwrap());
            assert_eq!(before.len(), 1);
            assert_eq!(after.len(), 1);
            let (before, after) = (&before[0], &after[0]);
            assert_eq!(after.resource_key, key(PUBLIC.id));
            assert_eq!(after.content_id, hash(PUBLIC.content));
            assert_eq!(after.local_title, PUBLIC.title);
            assert_eq!(after.local_summary, PUBLIC.summary);
            assert_eq!(after.local_concept_ids.as_slice(), PUBLIC.concepts);
            assert_eq!(after.score, before.score);
        }
    }
}

#[test]
fn candidate_keys_and_a_claimed_agent_are_not_authority() {
    let f = Fixture::new(&[PUBLIC, PDF], true);
    let scope = f.engine.for_peer(peer(STRANGER));
    let forged = [key(PUBLIC.id), key(PDF.id), key(INBOX), key(99)];
    let stranger = f.store.peer_search(&scope, agent(STRANGER));
    no_disclosure(stranger.search_local_text(&forged, "密码", LIMIT));
    no_disclosure(stranger.search_visible(&forged, &[PRIVATE], LIMIT));
    no_disclosure(stranger.search_local_text(&forged, "inboxmarker", LIMIT));
    let impersonated = f.store.peer_search(&scope, agent(CONTACT));
    no_disclosure(impersonated.visible_keys());
    no_disclosure(impersonated.search_visible(&forged, &[RUST], LIMIT));
    no_disclosure(impersonated.search_local_text(&forged, "密码", LIMIT));

    let scope = f.engine.for_peer(peer(CONTACT));
    let contact = f.store.peer_search(&scope, agent(CONTACT));
    let only_public = [key(PUBLIC.id)];
    assert!(
        contact
            .search_visible(&only_public, &[PRIVATE], LIMIT)
            .unwrap()
            .is_empty()
    );
    assert!(
        contact
            .search_local_text(&only_public, "密码", LIMIT)
            .unwrap()
            .is_empty()
    );
    no_disclosure(contact.search_local_text(&forged, "inboxmarker", LIMIT));
}

#[test]
fn sql_and_match_syntax_cannot_turn_nonmatches_into_matches() {
    let f = Fixture::new(&[PUBLIC, PDF], true);
    let scope = f.engine.for_peer(peer(CONTACT));
    let search = f.store.peer_search(&scope, agent(CONTACT));
    let keys = search.visible_keys().unwrap();
    // If MATCH interprets '*' as a prefix operator it would return borrowchecker.
    for query in [
        "borrowchec*",
        "\"unlisted",
        "absent OR missing",
        "NEAR(missing absent, 2)",
        "SELECT title FROM resources WHERE summary = 'unlisted';",
    ] {
        match search.search_local_text(&keys, query, LIMIT) {
            Ok(hits) => assert!(hits.is_empty(), "unexpected match for {query:?}"),
            Err(AslError::InvalidMessage) => (),
            Err(err) => panic!("{query:?} escaped the literal query boundary: {err}"),
        }
    }
    let hits = search
        .search_local_text(&keys, "borrowchecker", LIMIT)
        .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].resource_key, key(PUBLIC.id));
}

#[test]
fn revision_drift_and_revocation_close_previously_visible_keys() {
    let f = Fixture::new(&[PUBLIC, PDF], true);
    let scope = f.engine.for_peer(peer(CONTACT));
    let search = f.store.peer_search(&scope, agent(CONTACT));
    let prior = search.visible_keys().unwrap();
    assert_keys(prior.clone(), &[PUBLIC.id, PDF.id]);
    assert_eq!(
        search
            .search_local_text(&prior, "密码", LIMIT)
            .unwrap()
            .len(),
        1
    );

    // The SQLite writer has advanced; the in-memory authority still has the old revision.
    let tx = f.db.unchecked_transaction().unwrap();
    tx.execute(
        "UPDATE grants SET status='revoked',epoch=epoch+1 WHERE grant_id=?1",
        [hex::encode(grant(PDF.id).0.0)],
    )
    .unwrap();
    tx.execute(
        "UPDATE resources SET active=0 WHERE grant_id=?1",
        [hex::encode(grant(PDF.id).0.0)],
    )
    .unwrap();
    tx.execute(
        "UPDATE policy_state SET revision=revision+1 WHERE singleton=1",
        [],
    )
    .unwrap();
    tx.commit().unwrap();
    no_disclosure(search.visible_keys());
    no_disclosure(search.search_visible(&prior, &[RUST], LIMIT));
    no_disclosure(search.search_local_text(&prior, "borrowchecker", LIMIT));

    assert_eq!(
        f.engine.revoke(grant(PDF.id), 1).unwrap(),
        PolicyRevision(f.store.policy_revision().unwrap())
    );
    let refreshed = f.store.peer_search(&scope, agent(CONTACT));
    assert_keys(refreshed.visible_keys().unwrap(), &[PUBLIC.id]);
    no_disclosure(refreshed.search_visible(&prior, &[PRIVATE], LIMIT));
    no_disclosure(refreshed.search_local_text(&prior, "密码", LIMIT));
}

#[test]
fn equal_content_does_not_merge_grant_scoped_annotations() {
    let f = Fixture::new(&[PUBLIC, ALIAS], false);
    let scope = f.engine.for_peer(peer(CONTACT));
    let contact = f.store.peer_search(&scope, agent(CONTACT));
    let both = contact.visible_keys().unwrap();
    assert_keys(both.clone(), &[PUBLIC.id, ALIAS.id]);
    let private = contact.search_visible(&both, &[PRIVATE], LIMIT).unwrap();
    assert_eq!(private.len(), 1);
    assert_eq!(private[0].resource_key, key(ALIAS.id));
    assert_eq!(private[0].content_id, hash(PUBLIC.content));
    assert_eq!(private[0].local_summary, ALIAS.summary);

    let scope = f.engine.for_peer(peer(STRANGER));
    let stranger = f.store.peer_search(&scope, agent(STRANGER));
    let public = stranger.visible_keys().unwrap();
    assert_keys(public.clone(), &[PUBLIC.id]);
    no_disclosure(stranger.search_visible(&both, &[PRIVATE], LIMIT));
    no_disclosure(stranger.search_local_text(&both, "annotation", LIMIT));
    let hits = stranger
        .search_local_text(&public, "borrowchecker", LIMIT)
        .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].resource_key, key(PUBLIC.id));
    assert_eq!(hits[0].local_summary, PUBLIC.summary);
}

#[test]
fn search_permission_is_not_permission_to_read_metadata() {
    let f = Fixture::new(&[PUBLIC], false);
    let mut next = f.engine.snapshot().unwrap();
    let old = next.revision;
    next.revision.0 += 1;
    let grant = next.grants.get_mut(&grant(PUBLIC.id)).unwrap();
    grant.epoch += 1;
    grant
        .allowed_operations
        .remove(&AccessOperation::ReadMetadata);
    next.resources.get_mut(&key(PUBLIC.id)).unwrap().grant_epoch += 1;
    f.db.execute_batch("BEGIN; UPDATE grants SET epoch=2; UPDATE resources SET source_grant_epoch=2; UPDATE policy_state SET revision=revision+1; COMMIT").unwrap();
    f.engine.replace_snapshot(old, next).unwrap();
    let scope = f.engine.for_peer(peer(STRANGER));
    let search = f.store.peer_search(&scope, agent(STRANGER));
    let keys = search.visible_keys().unwrap();
    assert_keys(keys.clone(), &[PUBLIC.id]);
    no_disclosure(search.search_visible(&keys, &[RUST], LIMIT));
}

#[test]
fn durable_identity_revocation_overrides_old_device_scope() {
    let f = Fixture::new(&[PUBLIC, PDF], false);
    let scope = f.engine.for_peer(peer(CONTACT));
    let search = f.store.peer_search(&scope, agent(CONTACT));
    let keys = search.visible_keys().unwrap();
    assert_eq!(
        search
            .search_local_text(&keys, "密码", LIMIT)
            .unwrap()
            .len(),
        1
    );
    f.db.execute_batch("INSERT INTO chain_state_cache VALUES(1,zeroblob(20),zeroblob(32),1,zeroblob(32),zeroblob(32),zeroblob(32),x'00',1)").unwrap();
    f.db.execute("INSERT INTO identity_registry_states VALUES(?1,1,zeroblob(20),zeroblob(32),2,'revoked',1,zeroblob(32),1)",[agent_text(CONTACT)]).unwrap();
    no_disclosure(search.visible_keys());
    no_disclosure(search.search_visible(&keys, &[PRIVATE], LIMIT));
    no_disclosure(search.search_local_text(&keys, "密码", LIMIT));
}

#[test]
fn replacing_an_index_is_atomic_and_bound_to_content() {
    let mut f = Fixture::new(&[PUBLIC], false);
    let replacement = || LocalIndexText {
        title: "replacement",
        summary: "",
        body: "needle",
        concepts: &[PRIVATE],
    };
    assert!(matches!(
        f.store
            .index_local_text(&key(PUBLIC.id), hash(99), replacement()),
        Err(AslError::NotFound)
    ));
    let scope = f.engine.for_peer(peer(STRANGER));
    let keys = [key(PUBLIC.id)];
    assert_eq!(
        f.store
            .peer_search(&scope, agent(STRANGER))
            .search_visible(&keys, &[RUST], LIMIT)
            .unwrap()
            .len(),
        1
    );
    f.store
        .index_local_text(&keys[0], hash(PUBLIC.content), replacement())
        .unwrap();
    let search = f.store.peer_search(&scope, agent(STRANGER));
    assert!(
        search
            .search_visible(&keys, &[RUST], LIMIT)
            .unwrap()
            .is_empty()
    );
    assert!(
        search
            .search_local_text(&keys, "borrowchecker", LIMIT)
            .unwrap()
            .is_empty()
    );
    let hits = search.search_local_text(&keys, "needle", LIMIT).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].local_title, "replacement");
}
