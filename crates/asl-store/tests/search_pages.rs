use std::collections::HashSet;

use asl_policy::{
    AccessOperation, Audience, AuthenticatedDevice, GrantPolicy, GroupPolicy, ModelPolicy,
    PolicyEngine, PolicySnapshot, ResourceOrigin, ResourcePolicy,
};
use asl_store::{
    Store, open_store,
    search::{LocalIndexText, ResourceSearch},
};
use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId},
    protocol::ConceptRef,
    task::{GrantId, GroupId, ResourceKey},
};
use rusqlite::{Connection, params};
use tempfile::TempDir;

const AGENT: AgentId = AgentId([7; 32]);
const CONTENT: Hash32 = Hash32([5; 32]);
const GRANT: GrantId = GrantId(Id128([3; 16]));
const TOPIC: ConceptRef = ConceptRef {
    vocabulary_id: 1,
    concept_id: 101,
};

fn peer() -> PeerId {
    let mut bytes = vec![0, 36, 8, 1, 18, 32];
    bytes.extend_from_slice(&[9; 32]);
    PeerId::from_bytes(bytes).unwrap()
}

fn key(n: u32) -> ResourceKey {
    ResourceKey(Id128(u128::from(n).to_be_bytes()))
}

struct Library {
    store: Store,
    db: Connection,
    facts: PolicySnapshot,
    _temp: TempDir,
}

impl Library {
    fn new(count: u32, permitted: impl IntoIterator<Item = u32>) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("pages.db");
        let store = open_store(&path).unwrap();
        let db = Connection::open(path).unwrap();
        db.pragma_update(None, "foreign_keys", true).unwrap();
        let agent_id = bs58::encode(AGENT.as_bytes()).into_string();
        let peer_id = bs58::encode(peer().as_bytes()).into_string();
        db.execute(
            "INSERT INTO agents(agent_id,identity_state) VALUES (?1,'verified')",
            [&agent_id],
        )
        .unwrap();
        db.execute(
            "INSERT INTO device_identities(peer_id,agent_id,public_key_hex,certificate_cbor,
            certificate_serial,certificate_expires_ms,created_at_ms) VALUES (?1,?2,?3,X'',1,?4,0)",
            params![peer_id, agent_id, hex::encode([9; 32]), i64::MAX],
        )
        .unwrap();
        db.execute(
            "INSERT INTO peers(peer_id,agent_id) VALUES (?1,?2)",
            params![peer_id, agent_id],
        )
        .unwrap();
        db.execute(
            "INSERT INTO snapshots(content_id,file_hash,file_size,chunk_count,blob_relative,
            manifest_relative,state,created_at_ms) VALUES (?1,?1,1,1,'blob','manifest','ready',0)",
            [hex::encode(CONTENT.0)],
        )
        .unwrap();
        db.execute(
            "INSERT INTO grants(grant_id,root_path,volume_id,root_file_id,extensions_json,
            audience,model_policy,max_snapshot_bytes,status,created_at_ms)
            VALUES (?1,'root','volume','file','[\"txt\"]','public','never',1,'active',0)",
            [hex::encode(GRANT.0.0)],
        )
        .unwrap();
        db.execute("WITH RECURSIVE seq(n) AS (SELECT 1 WHERE ?1>=1 UNION ALL SELECT n+1 FROM seq WHERE n<?1)
            INSERT INTO resources(resource_key,content_id,grant_id,source_grant_epoch,origin,title,
            summary,evidence_status,created_at_ms,updated_at_ms)
            SELECT printf('%032x',n),?2,?3,1,'local','','','source_backed',0,0 FROM seq",
            params![count, hex::encode(CONTENT.0), hex::encode(GRANT.0.0)]).unwrap();
        let mut facts = PolicySnapshot::default();
        facts.devices.insert(
            peer(),
            AuthenticatedDevice {
                agent_id: AGENT,
                active: true,
                chain_valid_until_ms: i64::MAX as u64,
                certificate_valid_until_ms: i64::MAX as u64,
            },
        );
        facts.grants.insert(
            GRANT,
            GrantPolicy {
                epoch: 1,
                active: true,
                audience: Audience::Public,
                model_policy: ModelPolicy::Never,
                extensions: HashSet::from([".txt".into()]),
                max_snapshot_bytes: 1,
                allowed_operations: HashSet::from([
                    AccessOperation::Search,
                    AccessOperation::ReadMetadata,
                ]),
                allow_derived_disclosure: false,
            },
        );
        for n in permitted {
            facts.resources.insert(
                key(n),
                ResourcePolicy {
                    content_id: CONTENT,
                    grant_id: GRANT,
                    grant_epoch: 1,
                    active: true,
                    snapshot_ready: true,
                    file_size: 1,
                    extension: ".txt".into(),
                    retention_until_ms: None,
                    origin: ResourceOrigin::Local,
                },
            );
        }
        Self {
            store,
            db,
            facts,
            _temp: temp,
        }
    }

    fn index_first(&mut self) {
        self.store
            .index_local_text(
                &key(1),
                CONTENT,
                LocalIndexText {
                    title: "fixture",
                    summary: "",
                    body: "",
                    concepts: &[TOPIC],
                },
            )
            .unwrap();
    }
}

#[test]
fn complete_scan_charges_denials_from_both_sql_and_policy() {
    let lib = Library::new(4097, [4097]);
    let engine = PolicyEngine::new(lib.facts, 60_000).unwrap();
    let scope = engine.for_peer(peer());
    let search = lib.store.peer_search(&scope, AGENT);
    assert!(matches!(
        search.visible_keys(),
        Err(AslError::QuotaExceeded)
    ));
    lib.db
        .execute("UPDATE resources SET active=0 WHERE row_id<4097", [])
        .unwrap();
    assert!(matches!(
        search.visible_keys(),
        Err(AslError::QuotaExceeded)
    ));
    lib.db
        .execute("DELETE FROM resources WHERE row_id=1", [])
        .unwrap();
    assert_eq!(search.visible_keys().unwrap(), [key(4097)]);
}

#[test]
fn local_pages_cover_a_large_library_without_skipping_empty_windows() {
    let lib = Library::new(4101, 4..=4101);
    lib.db
        .execute("UPDATE resources SET active=0 WHERE row_id=4099", [])
        .unwrap();
    let engine = PolicyEngine::new(lib.facts, 60_000).unwrap();
    let scope = engine.for_peer(peer());
    let search = lib.store.peer_search(&scope, AGENT);
    for invalid in [0, 4097, u32::MAX] {
        assert!(matches!(
            search.visible_keys_page(None, invalid),
            Err(AslError::QuotaExceeded)
        ));
    }
    let empty = search.visible_keys_page(None, 3).unwrap();
    assert!(empty.keys.is_empty());
    let cursor = empty.next.unwrap();
    let middle = search.visible_keys_page(Some(&cursor), 4096).unwrap();
    assert_eq!(middle.keys, (4..=4098).map(key).collect::<Vec<_>>());
    let tail = search.visible_keys_page(middle.next.as_ref(), 2).unwrap();
    assert_eq!(tail.keys, [key(4100), key(4101)]);
    assert!(tail.next.is_none());
}

#[test]
fn sparse_rowids_replay_in_order_and_stale_cursors_fail_closed() {
    let lib = Library::new(3, 1..=3);
    lib.db
        .execute("UPDATE resources SET row_id=?1 WHERE row_id=3", [i64::MIN])
        .unwrap();
    lib.db
        .execute("UPDATE resources SET row_id=?1 WHERE row_id=1", [i64::MAX])
        .unwrap();
    let engine = PolicyEngine::new(lib.facts, 60_000).unwrap();
    let scope = engine.for_peer(peer());
    let search = lib.store.peer_search(&scope, AGENT);
    assert_eq!(search.visible_keys().unwrap(), [key(1), key(2), key(3)]);
    let page = search.visible_keys_page(None, 2).unwrap();
    assert_eq!(page.keys, [key(3), key(2)]);
    let cursor = page.next.as_ref().unwrap();
    for _ in 0..2 {
        let last = search.visible_keys_page(Some(cursor), 1).unwrap();
        assert_eq!(last.keys, [key(1)]);
        assert!(last.next.is_none());
    }
    let other_scope = engine.for_peer(peer());
    let other = lib.store.peer_search(&other_scope, AGENT);
    assert!(matches!(
        other.visible_keys_page(Some(cursor), 1),
        Err(AslError::PolicyVersionConflict)
    ));
    lib.db
        .execute("UPDATE resources SET active=0 WHERE row_id=?1", [i64::MAX])
        .unwrap();
    assert!(matches!(
        search.visible_keys_page(Some(cursor), 1),
        Err(AslError::PolicyVersionConflict)
    ));
    let fresh = search.visible_keys_page(None, 2).unwrap().next.unwrap();
    lib.store.set_setting("test", "true", 0).unwrap();
    assert!(matches!(
        search.visible_keys_page(Some(&fresh), 1),
        Err(AslError::PolicyVersionConflict)
    ));
}

fn assert_visibility(search: &ResourceSearch<'_>, visible: bool) {
    let expected: Vec<_> = visible.then(|| key(1)).into_iter().collect();
    assert_eq!(search.visible_keys().unwrap(), expected);
    let page = search.visible_keys_page(None, 1).unwrap();
    assert_eq!(page.keys, expected);
    assert!(page.next.is_none());
    // Supplying the key directly must not bypass either authority.
    let hits = search
        .search_visible(&[key(1), key(1)], &[TOPIC], 2)
        .unwrap();
    assert_eq!(
        hits.into_iter()
            .map(|hit| hit.resource_key)
            .collect::<Vec<_>>(),
        expected
    );
}

#[test]
fn named_peers_need_both_the_db_allowlist_and_the_policy_allowlist() {
    let mut lib = Library::new(1, [1]);
    lib.index_first();
    lib.db
        .execute("UPDATE grants SET audience='peers'", [])
        .unwrap();
    let agent = bs58::encode(AGENT.as_bytes()).into_string();
    for policy_allows in [false, true] {
        lib.facts.grants.get_mut(&GRANT).unwrap().audience =
            Audience::Peers(policy_allows.then_some(AGENT).into_iter().collect());
        let engine = PolicyEngine::new(lib.facts.clone(), 60_000).unwrap();
        let scope = engine.for_peer(peer());
        let search = lib.store.peer_search(&scope, AGENT);
        assert_visibility(&search, false);
        lib.db
            .execute(
                "INSERT INTO grant_agents(grant_id,agent_id) VALUES (?1,?2)",
                params![hex::encode(GRANT.0.0), agent],
            )
            .unwrap();
        assert_visibility(&search, policy_allows);
        lib.db.execute("DELETE FROM grant_agents", []).unwrap();
    }
}

#[test]
fn group_binding_requires_matching_group_epoch_and_live_device_membership() {
    let mut lib = Library::new(1, [1]);
    lib.index_first();
    let target = GroupId(Id128([1; 16]));
    let other = GroupId(Id128([2; 16]));
    let peer_id = bs58::encode(peer().as_bytes()).into_string();
    for id in [&target, &other] {
        let text = hex::encode(id.0.0);
        lib.db.execute("INSERT INTO asl_groups(group_id,creator_peer_id,local_name,state,created_at_ms,updated_at_ms)
            VALUES (?1,?2,'group','active',0,0)", params![text, peer_id]).unwrap();
        lib.db.execute("INSERT INTO group_members(group_id,peer_id,role,state) VALUES (?1,?2,'creator','active')",
            params![text, peer_id]).unwrap();
        lib.facts.groups.insert(
            id.clone(),
            GroupPolicy {
                active: true,
                membership_epoch: 1,
                members: HashSet::from([peer()]),
            },
        );
    }
    lib.facts.grants.get_mut(&GRANT).unwrap().audience = Audience::Group(target.clone());
    let engine = PolicyEngine::new(lib.facts.clone(), 60_000).unwrap();
    let scope = engine.for_group(peer(), target.clone());
    let group = lib.store.peer_search(&scope, AGENT);
    let target_text = hex::encode(target.0.0);
    lib.db
        .execute(
            "UPDATE grants SET audience='group',group_id=?1",
            [hex::encode(other.0.0)],
        )
        .unwrap();
    assert_visibility(&group, false);
    lib.db
        .execute("UPDATE grants SET group_id=?1", [&target_text])
        .unwrap();
    assert_visibility(&group, true);
    assert_visibility(
        &lib.store.peer_search(&engine.for_peer(peer()), AGENT),
        false,
    );
    lib.facts.groups.get_mut(&target).unwrap().members.clear();
    let removed = PolicyEngine::new(lib.facts, 60_000).unwrap();
    assert_visibility(
        &lib.store
            .peer_search(&removed.for_group(peer(), target), AGENT),
        false,
    );
    lib.db
        .execute(
            "UPDATE asl_groups SET membership_epoch=2 WHERE group_id=?1",
            [&target_text],
        )
        .unwrap();
    assert_visibility(&group, false);
    lib.db
        .execute(
            "UPDATE asl_groups SET membership_epoch=1 WHERE group_id=?1",
            [&target_text],
        )
        .unwrap();
    lib.db
        .execute(
            "UPDATE group_members SET state='removed' WHERE group_id=?1",
            [&target_text],
        )
        .unwrap();
    assert_visibility(&group, false);
    // Even if SQL permits a public grant, the request itself still uses the group binding.
    lib.db
        .execute("UPDATE grants SET audience='public',group_id=NULL", [])
        .unwrap();
    assert_visibility(&group, false);
    lib.db
        .execute(
            "UPDATE group_members SET state='active' WHERE group_id=?1",
            [&target_text],
        )
        .unwrap();
    assert_visibility(&group, true);
}
