use std::{
    ffi::OsString,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use asl_agent::reputation::rank_authorized_contacts;
use asl_store::{
    evidence::{ContactEvidence, ContributionKind, TrustDimension, TrustOutcome},
    open_store,
};
use asl_types::{
    ids::{AgentId, Hash32, Id128},
    task::TaskId,
};
use rusqlite::{Connection, params};

const AGENT_A: AgentId = AgentId([1; 32]);
const AGENT_B: AgentId = AgentId([2; 32]);
const AGENT_C: AgentId = AgentId([3; 32]);

static NEXT_DATABASE_ID: AtomicU64 = AtomicU64::new(1);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let directory = std::env::var_os("ASL_TEST_FIXTURE_BASE")
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::temp_dir().join("asl-test-fs"))
            .join("asl-reputation");
        fs::create_dir_all(&directory).unwrap();
        let id = NEXT_DATABASE_ID.fetch_add(1, Ordering::Relaxed);
        let path = directory.join(format!("reputation-{}-{id}.sqlite3", std::process::id()));
        drop(open_store(&path).unwrap());
        for (agent, seed, authorized) in
            [(AGENT_A, 1, true), (AGENT_B, 2, true), (AGENT_C, 3, false)]
        {
            insert_agent(&path, agent, seed, authorized);
        }
        Self(path)
    }

    fn add_help(&self, index: u8, agent_id: AgentId, evidence_status: &str) -> (TaskId, Hash32) {
        let task_id = TaskId(Id128([index; 16]));
        let content_id = Hash32([index.wrapping_add(40); 32]);
        let resource_key = hex::encode([index; 16]);
        let content = hex::encode(content_id.0);
        let task = hex::encode(task_id.0.0);
        let agent = agent_text(agent_id);
        let peer = peer_text(match agent_id {
            AGENT_A => 1,
            AGENT_B => 2,
            _ => 3,
        });
        let db = Connection::open(&self.0).unwrap();
        db.execute(
            "INSERT INTO tasks(task_id,direction,agent_id,peer_id,audience_json,state,
                created_at_ms,expires_at_ms)
             VALUES (?1,'outgoing',?2,?3,'{\"kind\":\"private\"}','done',100,200)",
            params![task, agent, peer],
        )
        .unwrap();
        db.execute(
            "INSERT INTO snapshots(content_id,file_hash,file_size,chunk_count,blob_relative,
                manifest_relative,state,created_at_ms)
             VALUES (?1,?1,0,0,'unused','unused','ready',100)",
            [&content],
        )
        .unwrap();
        db.execute(
            "INSERT INTO resources(resource_key,content_id,origin,title,summary,evidence_status,
                active,created_at_ms,updated_at_ms,source_agent_id)
             VALUES (?1,?2,'remote','','',?3,1,100,100,?4)",
            params![resource_key, content, evidence_status, agent],
        )
        .unwrap();
        (task_id, content_id)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let mut path = OsString::from(self.0.as_os_str());
            path.push(suffix);
            let _ = fs::remove_file(PathBuf::from(path));
        }
    }
}

fn insert_agent(path: &std::path::Path, agent: AgentId, seed: u8, authorized: bool) {
    let peer = peer_text(seed);
    let agent = agent_text(agent);
    let db = Connection::open(path).unwrap();
    db.execute("PRAGMA foreign_keys=ON", []).unwrap();
    db.execute(
        "INSERT INTO agents(agent_id,identity_state) VALUES (?1,'verified')",
        [&agent],
    )
    .unwrap();
    db.execute(
        "INSERT INTO device_identities(peer_id,agent_id,public_key_hex,certificate_cbor,
            certificate_serial,certificate_expires_ms,created_at_ms)
         VALUES (?1,?2,?3,x'',1,100000,0)",
        params![peer, agent, hex::encode([seed; 32])],
    )
    .unwrap();
    db.execute(
        "INSERT INTO peers(peer_id,agent_id) VALUES (?1,?2)",
        params![peer, agent],
    )
    .unwrap();
    if authorized {
        db.execute(
            "INSERT INTO authorized_contacts(agent_id,authorized_at_ms,authorization_revision)
             VALUES (?1,0,1)",
            [&agent],
        )
        .unwrap();
    }
}

fn agent_text(agent: AgentId) -> String {
    bs58::encode(agent.as_bytes()).into_string()
}

fn peer_text(seed: u8) -> String {
    let key = libp2p_identity::Keypair::ed25519_from_bytes([seed; 32]).unwrap();
    key.public().to_peer_id().to_string()
}

#[test]
fn contribution_is_deduplicated_and_requires_a_locally_verified_resource() {
    let fixture = Fixture::new();
    let (task, content) = fixture.add_help(1, AGENT_A, "verified");
    let (junk_task, junk_content) = fixture.add_help(2, AGENT_A, "derived_unverified");
    let (wrong_source_task, wrong_source_content) = fixture.add_help(3, AGENT_B, "verified");
    let db = Connection::open(&fixture.0).unwrap();
    db.execute(
        "UPDATE resources SET source_agent_id=?1 WHERE content_id=?2",
        params![agent_text(AGENT_A), hex::encode(wrong_source_content.0)],
    )
    .unwrap();
    let mut store = open_store(&fixture.0).unwrap();

    assert!(
        store
            .record_contribution(AGENT_A, &task, content, ContributionKind::UsedFile, 1_000)
            .unwrap()
    );
    assert!(
        !store
            .record_contribution(AGENT_A, &task, content, ContributionKind::UsedFile, 1_001)
            .unwrap()
    );
    assert!(
        store
            .record_contribution(
                AGENT_A,
                &junk_task,
                junk_content,
                ContributionKind::UsedFile,
                1_000
            )
            .is_err()
    );
    assert!(
        store
            .record_contribution(AGENT_B, &task, content, ContributionKind::UsedFile, 1_002)
            .is_err()
    );
    assert!(
        store
            .record_contribution(
                AGENT_B,
                &wrong_source_task,
                wrong_source_content,
                ContributionKind::UsedFile,
                1_003
            )
            .is_err()
    );

    let evidence = store.authorized_contact_evidence().unwrap();
    assert_eq!(
        evidence
            .iter()
            .find(|entry| entry.agent_id == AGENT_A)
            .unwrap()
            .contributions,
        1
    );
}

#[test]
fn identity_changes_share_one_machine_wide_contribution_budget() {
    let fixture = Fixture::new();
    let mut store = open_store(&fixture.0).unwrap();

    for index in 1..=100 {
        let (task, content) = fixture.add_help(index, AGENT_A, "verified");
        assert!(
            store
                .record_contribution(AGENT_A, &task, content, ContributionKind::UsedFile, 10_000)
                .unwrap()
        );
    }
    let (task, content) = fixture.add_help(101, AGENT_B, "verified");
    assert!(matches!(
        store.record_contribution(AGENT_B, &task, content, ContributionKind::UsedFile, 10_001),
        Err(asl_types::error::AslError::QuotaExceeded)
    ));
}

#[test]
fn preferences_and_high_reputation_never_add_an_authorized_contact() {
    let fixture = Fixture::new();
    let mut store = open_store(&fixture.0).unwrap();
    store.set_preferred_peer(AGENT_C, 1_000).unwrap();
    store.set_preferred_peer(AGENT_B, 999).unwrap();
    store
        .record_trust_observation(
            AGENT_C,
            None,
            TrustDimension::Integrity,
            TrustOutcome::Positive,
            Hash32([8; 32]),
            1_000,
        )
        .unwrap();

    let authorized = store.authorized_contacts().unwrap();
    let preferred = store.preferred_agents().unwrap();
    let mut evidence = store.authorized_contact_evidence().unwrap();
    evidence.push(ContactEvidence {
        agent_id: AGENT_C,
        integrity: Default::default(),
        availability: Default::default(),
        evidence: Default::default(),
        promise: Default::default(),
        contributions: u32::MAX,
    });

    let ranked = rank_authorized_contacts(&authorized, &preferred, &evidence);
    assert_eq!(ranked.len(), 2);
    assert_eq!(ranked[0], AGENT_B);
    assert!(!ranked.contains(&AGENT_C));
    assert!(!store.authorized_contacts().unwrap().contains(&AGENT_C));
}

#[test]
fn availability_failures_remain_distinct_from_integrity_findings() {
    let fixture = Fixture::new();
    let mut store = open_store(&fixture.0).unwrap();
    store
        .record_trust_observation(
            AGENT_A,
            None,
            TrustDimension::Availability,
            TrustOutcome::Negative,
            Hash32([9; 32]),
            1_000,
        )
        .unwrap();

    let evidence = store.authorized_contact_evidence().unwrap();
    let agent = evidence
        .iter()
        .find(|entry| entry.agent_id == AGENT_A)
        .unwrap();
    assert_eq!(agent.availability.negative, 1);
    assert_eq!(agent.integrity.negative, 0);
}
