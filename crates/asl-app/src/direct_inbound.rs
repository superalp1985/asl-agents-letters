use std::{
    collections::HashMap,
    path::Path,
    time::{Duration, Instant},
};

use asl_agent::{
    INBOUND_DEDUP_WINDOW_MS,
    runner::{InboundMode, InboundRunner, InboundWork, Ingress, ResourceMatch},
};
use asl_policy::{Permit, PolicyEngine, PolicyRevision};
use asl_store::{
    Store,
    search::direct::{DirectRequester, open_direct_store},
};
use asl_types::{
    error::AslError,
    ids::AgentId,
    protocol::{Intent, MediaKind, ResultShape, WireFrame},
};

use crate::supervisor::unix_time_ms;

const MODE_KEY: &str = "agent.direct_inbound_mode_v1";
// Shared across identities and devices; creating more identities cannot raise
// the local FTS and SQLite write rate.
const MIN_QUERY_GAP: Duration = Duration::from_millis(250);
const MIN_AGENT_GAP: Duration = Duration::from_secs(1);

pub(crate) struct DirectInbound {
    store: Store,
    runner: InboundRunner,
    next_query: Option<Instant>,
    agent_cooldowns: HashMap<AgentId, Instant>,
}

pub(crate) struct PreparedReply {
    frame: WireFrame,
    requester: DirectRequester,
    revision: PolicyRevision,
    permit: Option<Permit>,
    root_task_id: asl_types::ids::Id128,
    expires_at_ms: u64,
}

impl DirectInbound {
    pub(crate) fn open(path: &Path) -> Result<Self, AslError> {
        Ok(Self {
            store: open_direct_store(path)?,
            runner: InboundRunner::default(),
            next_query: None,
            agent_cooldowns: HashMap::new(),
        })
    }

    pub(crate) fn prepare(
        &mut self,
        requester: DirectRequester,
        frame: WireFrame,
        now_ms: u64,
    ) -> Result<Option<PreparedReply>, AslError> {
        let WireFrame::Query(query) = frame else {
            return Ok(None);
        };
        if now_ms < query.created_at_ms || now_ms >= query.expires_at_ms {
            return Ok(None);
        }
        let now = Instant::now();
        self.agent_cooldowns.retain(|_, until| now < *until);
        if self.next_query.is_some_and(|next| now < next)
            || self.agent_cooldowns.contains_key(&requester.agent)
        {
            return Ok(None);
        }
        self.next_query = Some(now + MIN_QUERY_GAP);
        let mode = read_mode(&self.store)?;
        self.runner.set_mode(mode);
        let ingress = self.runner.receive(
            requester.agent,
            requester.peer.clone(),
            WireFrame::Query(query.clone()),
            now_ms,
        )?;
        let work = match ingress {
            Ingress::Observed if mode == InboundMode::BrowseOnly => {
                self.store.record_direct_inbound_observation(
                    requester.agent,
                    &requester.peer,
                    &query,
                    i64::try_from(now_ms).map_err(|_| AslError::InvalidMessage)?,
                )?;
                self.agent_cooldowns
                    .insert(requester.agent, now + MIN_AGENT_GAP);
                return Ok(None);
            }
            Ingress::Work(work) => *work,
            _ => return Ok(None),
        };
        self.agent_cooldowns
            .insert(requester.agent, now + MIN_AGENT_GAP);
        let result = self.prepare_work(&requester, work, now_ms);
        if !matches!(result, Ok(Some(_))) {
            self.runner.disconnect(&requester.peer);
        }
        result
    }

    fn prepare_work(
        &mut self,
        requester: &DirectRequester,
        work: InboundWork,
        now_ms: u64,
    ) -> Result<Option<PreparedReply>, AslError> {
        let query = work.query();
        let expires_at_ms = query.expires_at_ms;
        let root_task_id = query.root_task_id;
        if !self.store.claim_direct_inbound_query(
            requester.agent,
            query.root_task_id,
            query.message_id,
            now_ms as i64,
            (now_ms + INBOUND_DEDUP_WINDOW_MS) as i64,
        )? {
            return Ok(None);
        }
        let (snapshot, keys) = self.store.direct_search_snapshot(requester)?;
        let revision = snapshot.revision;
        let engine = PolicyEngine::new(snapshot, 10_000)?;
        let policy = engine.for_peer(requester.peer.clone());
        let mut hit = None;
        if query.constraints.is_empty()
            && matches!(
                query.intent_id,
                Intent::FindEvidence | Intent::LocateResource
            )
            && query.result_shape != ResultShape::Agents
            && let Some((found, permit)) = self
                .store
                .peer_search(&policy, requester.agent)
                .search_with_metadata_permits(&keys, &query.topics, 1)?
                .pop()
        {
            // Only matching topic IDs are disclosed; no other local tags are needed.
            let concepts = query
                .topics
                .iter()
                .copied()
                .filter(|topic| found.local_concept_ids.contains(topic))
                .take(16)
                .collect();
            let file_size = permit.file_size();
            hit = Some(ResourceMatch::new(
                permit,
                concepts,
                file_size,
                MediaKind::Other,
            )?);
        }
        let now_ms = unix_time_ms()?;
        let Some(reply) = self
            .runner
            .finish_without_model(work, hit, &policy, now_ms)?
        else {
            return Ok(None);
        };
        let permit = reply.permit().cloned();
        Ok(self
            .runner
            .take_reply(reply, &policy, now_ms)
            .map(|frame| PreparedReply {
                frame,
                requester: requester.clone(),
                revision,
                permit,
                root_task_id,
                expires_at_ms,
            }))
    }

    pub(crate) fn enqueue(
        &self,
        reply: PreparedReply,
        enqueue: impl FnOnce(WireFrame, u64) -> Result<(), AslError>,
    ) -> Result<(), AslError> {
        let result = self.store.with_current_direct_authority(
            &reply.requester,
            reply.revision,
            reply.permit.as_ref(),
            Some(reply.root_task_id),
            || {
                let expires_at_ms = reply
                    .expires_at_ms
                    .min(reply.requester.session_expires_at_ms)
                    .min(
                        reply
                            .permit
                            .as_ref()
                            .map_or(u64::MAX, Permit::expires_at_ms),
                    );
                if unix_time_ms()? < expires_at_ms && read_mode(&self.store)? == InboundMode::Answer
                {
                    return Ok(Some(enqueue(reply.frame, expires_at_ms)));
                }
                Ok(None)
            },
        );
        // Unavailable local authorization suppresses only this request. An IPC
        // failure reaches the supervisor so the sandbox lifecycle is preserved.
        if let Ok(Some(result)) = result {
            result?;
        }
        Ok(())
    }
}

pub(crate) fn read_mode(store: &Store) -> Result<InboundMode, AslError> {
    let value = store.get_setting(MODE_KEY)?;
    Ok(match value.as_deref() {
        Some("\"answer\"") => InboundMode::Answer,
        Some("\"browse_only\"") => InboundMode::BrowseOnly,
        _ => InboundMode::Disabled,
    })
}

/// Called only by the local CLI. There is no Net/Worker command for this setting.
pub(crate) fn configure(path: &Path, mode: &str) -> Result<(), AslError> {
    let value = match mode {
        "off" => "\"off\"",
        "browse" => "\"browse_only\"",
        "answer" => "\"answer\"",
        _ => return Err(AslError::InvalidMessage),
    };
    open_direct_store(path)?.set_setting(MODE_KEY, value, unix_time_ms()? as i64)
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use asl_types::{
        ids::{AgentId, Hash32, Id128},
        protocol::{AnswerStatus, ConceptRef, Query},
        task::ResourceKey,
    };
    use rusqlite::{Connection, params};

    use super::*;
    use crate::identity::DeviceIdentity;

    const AGENT: &str = "11111111111111111111111111111111";
    const CONTENT: Hash32 = Hash32([0xaa; 32]);
    const RESOURCE: ResourceKey = ResourceKey(Id128([0xbb; 16]));
    const PRIVATE_TOPIC: ConceptRef = ConceptRef {
        vocabulary_id: 1,
        concept_id: 102,
    };

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let dirname = libp2p_identity::PeerId::random().to_string();
            let temp = std::env::temp_dir().join(format!("asl-inbound-{dirname}"));
            fs::create_dir(&temp).unwrap();
            let f = Self(temp);
            let mut store = open_direct_store(&f.path()).unwrap();
            let db = Connection::open(f.path()).unwrap();
            db.execute(
                "INSERT INTO agents(agent_id,identity_state) VALUES (?1,'verified')",
                [AGENT],
            )
            .unwrap();
            db.execute_batch(
                "INSERT INTO chain_state_cache VALUES
                    (1,zeroblob(20),zeroblob(32),0,zeroblob(32),zeroblob(32),zeroblob(32),x'',0);
                 INSERT INTO identity_registry_states SELECT
                    agent_id,1,zeroblob(20),zeroblob(32),1,'active',0,zeroblob(32),0 FROM agents;",
            )
            .unwrap();
            let content = "aa".repeat(32);
            let resource = "bb".repeat(16);
            let grant = "cc".repeat(16);
            db.execute(
                "INSERT INTO grants(grant_id,root_path,volume_id,root_file_id,extensions_json,
                    audience,model_policy,max_snapshot_bytes,status,created_at_ms)
                 VALUES (?1,'unused','unused','unused','[\"RS\"]','public','never',128,'active',0)",
                [&grant],
            )
            .unwrap();
            db.execute(
                "INSERT INTO snapshots VALUES (?1,?1,42,1,'unused','unused','ready',0)",
                [&content],
            )
            .unwrap();
            db.execute(
                "INSERT INTO resources(resource_key,content_id,grant_id,source_relative,
                    source_grant_epoch,origin,title,summary,evidence_status,created_at_ms,updated_at_ms)
                 VALUES (?1,?2,?3,'local-only.RS',1,'local','','','source_backed',0,0)",
                params![resource, content, grant],
            ).unwrap();
            store
                .index_local_text(
                    &RESOURCE,
                    CONTENT,
                    asl_store::search::LocalIndexText {
                        title: "local-only title",
                        summary: "local-only summary",
                        body: "local-only body",
                        concepts: &[ConceptRef::RUST, PRIVATE_TOPIC],
                    },
                )
                .unwrap();
            f
        }

        fn path(&self) -> PathBuf {
            self.0.join("state.sqlite3")
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            for file in ["state.sqlite3", "state.sqlite3-wal", "state.sqlite3-shm"] {
                let _ = fs::remove_file(self.0.join(file));
            }
            let _ = fs::remove_dir(&self.0);
        }
    }

    fn requester(now: u64) -> DirectRequester {
        DirectRequester {
            agent: AgentId([0; 32]),
            peer: DeviceIdentity::generate().unwrap().peer_id(),
            session_expires_at_ms: now + 60_000,
            registry_sequence: 1,
            directory_commitment: [0; 32],
            controller: [0; 20],
        }
    }

    fn query(id: u8, now: u64) -> WireFrame {
        WireFrame::Query(Query {
            message_id: Id128([id; 16]),
            root_task_id: Id128([2; 16]),
            created_at_ms: now,
            expires_at_ms: now + 10_000,
            intent_id: Intent::LocateResource,
            topics: vec![ConceptRef::RUST],
            constraints: vec![],
            result_shape: ResultShape::Resources,
            budget: 1,
        })
    }

    #[test]
    fn local_opt_in_replies_once_across_restart_and_devices() {
        let fixture = Fixture::new();
        let now = unix_time_ms().unwrap();
        let sender = requester(now);
        let frame = query(1, now);
        for mode in [None, Some("browse"), Some("off")] {
            if let Some(mode) = mode {
                configure(&fixture.path(), mode).unwrap();
            }
            let mut core = DirectInbound::open(&fixture.path()).unwrap();
            assert!(
                core.prepare(sender.clone(), frame.clone(), now)
                    .unwrap()
                    .is_none()
            );
        }
        configure(&fixture.path(), "answer").unwrap();
        let mut core = DirectInbound::open(&fixture.path()).unwrap();
        let reply = core
            .prepare(sender.clone(), frame.clone(), now)
            .unwrap()
            .unwrap();
        let mut seen = false;
        core.enqueue(reply, |frame, _| {
            let WireFrame::Offer(offer) = frame else {
                panic!("expected offer")
            };
            assert_eq!(offer.content_id, CONTENT);
            assert_eq!(offer.file_size, 42);
            assert_eq!(offer.concepts, vec![ConceptRef::RUST]);
            assert_eq!(offer.root_task_id, Id128([2; 16]));
            seen = true;
            Ok(())
        })
        .unwrap();
        assert!(seen);
        for id in [3, 5] {
            std::thread::sleep(Duration::from_millis(1_050));
            let reply = core
                .prepare(sender.clone(), query(id, now), now)
                .unwrap()
                .unwrap();
            core.enqueue(reply, |_, _| Ok(())).unwrap();
        }
        drop(core);
        std::thread::sleep(Duration::from_millis(1_050));
        let mut after_restart = DirectInbound::open(&fixture.path()).unwrap();
        assert!(matches!(
            after_restart.prepare(sender.clone(), query(7, now), now),
            Err(AslError::QuotaExceeded)
        ));
        drop(after_restart);
        let mut restarted = DirectInbound::open(&fixture.path()).unwrap();
        assert!(
            restarted
                .prepare(requester(now), frame, now)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn browse_mode_records_structured_request_without_answering() {
        let fixture = Fixture::new();
        let now = unix_time_ms().unwrap();
        let sender = requester(now);
        configure(&fixture.path(), "browse").unwrap();

        let mut core = DirectInbound::open(&fixture.path()).unwrap();
        assert!(core.prepare(sender, query(9, now), now).unwrap().is_none());
        drop(core);

        let dashboard = asl_store::dashboard::Dashboard::load(&fixture.path()).unwrap();
        assert_eq!(dashboard.direct_observations.len(), 1);
        let observation = &dashboard.direct_observations[0];
        assert_eq!(observation.intent, 2);
        assert_eq!(observation.topic_ids, vec![(1, 101)]);
        assert_eq!(observation.constraint_count, 0);
        assert_eq!(observation.result_shape, 2);
    }

    #[test]
    fn disabling_and_revoking_after_preparation_suppresses_disclosure() {
        let fixture = Fixture::new();
        let now = unix_time_ms().unwrap();
        let sender = requester(now);
        configure(&fixture.path(), "answer").unwrap();
        let mut core = DirectInbound::open(&fixture.path()).unwrap();
        let reply = core
            .prepare(sender.clone(), query(1, now), now)
            .unwrap()
            .unwrap();
        configure(&fixture.path(), "browse").unwrap();
        core.enqueue(reply, |_, _| panic!("answering was disabled"))
            .unwrap();

        configure(&fixture.path(), "answer").unwrap();
        let mut core = DirectInbound::open(&fixture.path()).unwrap();
        let reply = core
            .prepare(sender.clone(), query(3, now), now)
            .unwrap()
            .unwrap();
        let db = Connection::open(fixture.path()).unwrap();
        db.execute("UPDATE grants SET status='revoked',epoch=epoch+1", [])
            .unwrap();
        core.enqueue(reply, |_, _| panic!("grant was revoked"))
            .unwrap();

        let mut core = DirectInbound::open(&fixture.path()).unwrap();
        let reply = core.prepare(sender, query(5, now), now).unwrap().unwrap();
        let mut seen = false;
        core.enqueue(reply, |frame, _| {
            let WireFrame::Answer(answer) = frame else {
                panic!("expected answer")
            };
            assert_eq!(answer.status, AnswerStatus::NoMatch);
            assert!(answer.claims.is_empty());
            seen = true;
            Ok(())
        })
        .unwrap();
        assert!(seen);
    }
}
