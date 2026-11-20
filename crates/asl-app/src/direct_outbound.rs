use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::Path,
    sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel},
};

use asl_agent::{OutgoingTask, QueryAction, QueryRouter, QueryScope, QueryStatus};
use asl_types::{
    error::{AslError, ErrorCode},
    ids::{AgentId, Id128, PeerId},
    protocol::{ResultShape, WireFrame},
    task::TaskId,
};

use crate::profile::AdmittedNetworkEvent;

const MAX_QUEUED_TASKS: usize = 16;
const MAX_ACTIVE_OUTGOING_TASKS: usize = 8;
const MAX_QUERY_EVENT_BACKLOG: usize = 512;
const QUERY_EVENT_CHANNEL_CAPACITY: usize = 128;

pub struct OutgoingQueryPort {
    tasks: SyncSender<OutgoingTask>,
    events: Receiver<OutgoingQueryEvent>,
}

impl OutgoingQueryPort {
    pub fn submit(&self, task: OutgoingTask) -> Result<(), AslError> {
        task.validate()?;
        if task.scope != QueryScope::ContactsOnly {
            return Err(AslError::PolicyDenied);
        }
        match self.tasks.try_send(task) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(AslError::QuotaExceeded),
            Err(TrySendError::Disconnected(_)) => Err(AslError::SandboxUnavailable),
        }
    }

    pub fn try_recv_event(&self) -> Result<Option<OutgoingQueryEvent>, AslError> {
        match self.events.try_recv() {
            Ok(event) => Ok(Some(event)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(AslError::SandboxUnavailable),
        }
    }
}

pub struct OutgoingQueryRuntime {
    tasks: Receiver<OutgoingTask>,
    events: SyncSender<OutgoingQueryEvent>,
}

pub fn outgoing_query_channel() -> (OutgoingQueryPort, OutgoingQueryRuntime) {
    let (task_sender, tasks) = sync_channel(MAX_QUEUED_TASKS);
    let (events, event_receiver) = sync_channel(QUERY_EVENT_CHANNEL_CAPACITY);
    (
        OutgoingQueryPort {
            tasks: task_sender,
            events: event_receiver,
        },
        OutgoingQueryRuntime { tasks, events },
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutgoingQueryEvent {
    TaskStarted {
        task_id: TaskId,
    },
    Response {
        task_id: TaskId,
        agent_id: AgentId,
        peer_id: PeerId,
        frame: Box<WireFrame>,
    },
    TaskFinished {
        task_id: TaskId,
        status: QueryStatus,
    },
    TaskFailed {
        code: ErrorCode,
    },
}

struct PendingRequest {
    task_id: TaskId,
    agent_id: AgentId,
    peer_id: PeerId,
    connection_id: [u8; 16],
    root_task_id: Id128,
    expires_at_ms: u64,
    result_shape: ResultShape,
}

pub(crate) struct DirectOutbound {
    store: asl_store::Store,
    tasks: Receiver<OutgoingTask>,
    events: SyncSender<OutgoingQueryEvent>,
    router: QueryRouter,
    active_tasks: HashSet<TaskId>,
    pending: HashMap<[u8; 16], PendingRequest>,
    buffered_events: VecDeque<OutgoingQueryEvent>,
}

impl DirectOutbound {
    pub(crate) fn open(path: &Path, runtime: OutgoingQueryRuntime) -> Result<Self, AslError> {
        Ok(Self {
            store: asl_store::open_store(path)?,
            tasks: runtime.tasks,
            events: runtime.events,
            router: QueryRouter::new(),
            active_tasks: HashSet::new(),
            pending: HashMap::new(),
            buffered_events: VecDeque::new(),
        })
    }

    pub(crate) fn poll(
        &mut self,
        connections: &[(AgentId, [u8; 16], PeerId)],
        now_ms: u64,
        mut send: impl FnMut([u8; 16], [u8; 16], WireFrame) -> Result<(), AslError>,
    ) -> Result<(), AslError> {
        self.flush_events();
        self.pending
            .retain(|_, request| now_ms < request.expires_at_ms);

        let authorized = self.store.authorized_contacts()?;
        let mut by_agent = HashMap::new();
        for (agent_id, connection_id, peer_id) in connections {
            by_agent
                .entry(*agent_id)
                .or_insert((*connection_id, peer_id.clone()));
        }
        let mut seen_peers = HashSet::new();
        let contacts = authorized
            .iter()
            .filter_map(|agent_id| {
                let (connection_id, peer_id) = by_agent.get(agent_id)?;
                seen_peers.insert(peer_id.clone()).then_some((
                    *agent_id,
                    *connection_id,
                    peer_id.clone(),
                ))
            })
            .collect::<Vec<_>>();
        self.router
            .set_contacts(contacts.iter().map(|(_, _, peer)| peer.clone()));

        while self.active_tasks.len() < MAX_ACTIVE_OUTGOING_TASKS
            && self.buffered_events.len()
                < MAX_QUERY_EVENT_BACKLOG
                    - MAX_ACTIVE_OUTGOING_TASKS * (asl_agent::MAX_QUERY_PEERS + 2)
        {
            let task = match self.tasks.try_recv() {
                Ok(task) => task,
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            };
            if task.scope != QueryScope::ContactsOnly {
                self.emit(OutgoingQueryEvent::TaskFailed {
                    code: ErrorCode::PolicyDenied,
                });
                continue;
            }
            match self.router.start_query(task) {
                Ok(task_id) => {
                    self.active_tasks.insert(task_id.clone());
                    self.emit(OutgoingQueryEvent::TaskStarted { task_id });
                }
                Err(error) => self.emit(OutgoingQueryEvent::TaskFailed {
                    code: error_code(&error),
                }),
            }
        }

        let task_ids = self.active_tasks.iter().cloned().collect::<Vec<_>>();
        for task_id in task_ids {
            for action in self.router.next_actions(&task_id, now_ms) {
                match action {
                    QueryAction::Contact {
                        task_id,
                        peer_id,
                        query,
                    } => {
                        let Some((agent_id, connection_id, _)) =
                            contacts.iter().find(|(_, _, peer)| *peer == peer_id)
                        else {
                            let _ = self.router.complete_peer(&task_id, &peer_id, now_ms);
                            continue;
                        };
                        let request_id = query.message_id.0;
                        let frame = WireFrame::Query(query.clone());
                        if send(*connection_id, request_id, frame).is_ok() {
                            self.pending.insert(
                                request_id,
                                PendingRequest {
                                    task_id,
                                    agent_id: *agent_id,
                                    peer_id,
                                    connection_id: *connection_id,
                                    root_task_id: query.root_task_id,
                                    expires_at_ms: query.expires_at_ms,
                                    result_shape: query.result_shape,
                                },
                            );
                        } else {
                            let _ = self.router.complete_peer(&task_id, &peer_id, now_ms);
                        }
                    }
                    QueryAction::DhtLookup { .. } => {
                        return Err(AslError::InvalidPolicyState);
                    }
                }
            }
            let Some(status) = self.router.status(&task_id) else {
                continue;
            };
            if status != QueryStatus::Active {
                self.pending.retain(|_, request| request.task_id != task_id);
                self.active_tasks.remove(&task_id);
                self.router.remove_terminal_task(&task_id);
                self.emit(OutgoingQueryEvent::TaskFinished { task_id, status });
            }
        }
        self.flush_events();
        Ok(())
    }

    pub(crate) fn handle_event(&mut self, event: &AdmittedNetworkEvent, now_ms: u64) {
        match event {
            AdmittedNetworkEvent::ControlResponse {
                connection_id,
                agent_id,
                request_id,
                response,
            } => {
                let Some(pending) = self.pending.get(request_id) else {
                    return;
                };
                if pending.connection_id != *connection_id
                    || pending.agent_id != *agent_id
                    || now_ms >= pending.expires_at_ms
                {
                    return;
                }
                let pending = self
                    .pending
                    .remove(request_id)
                    .expect("pending request exists");
                if response_matches(&pending, response, now_ms) {
                    self.emit(OutgoingQueryEvent::Response {
                        task_id: pending.task_id.clone(),
                        agent_id: pending.agent_id,
                        peer_id: pending.peer_id.clone(),
                        frame: Box::new(response.clone()),
                    });
                }
                let _ = self
                    .router
                    .complete_peer(&pending.task_id, &pending.peer_id, now_ms);
            }
            AdmittedNetworkEvent::RequestFailed {
                connection_id,
                agent_id,
                request_id,
                protocol: crate::ipc::NetworkProtocol::Control,
                ..
            } => {
                self.complete_failed_request(*connection_id, *agent_id, request_id, now_ms);
            }
            AdmittedNetworkEvent::PeerDisconnected {
                connection_id,
                agent_id: _,
            } => {
                let failed = self
                    .pending
                    .iter()
                    .filter_map(|(request_id, pending)| {
                        (pending.connection_id == *connection_id).then_some(*request_id)
                    })
                    .collect::<Vec<_>>();
                for request_id in failed {
                    if let Some(pending) = self.pending.remove(&request_id) {
                        let _ =
                            self.router
                                .complete_peer(&pending.task_id, &pending.peer_id, now_ms);
                    }
                }
            }
            _ => {}
        }
        self.finish_terminal_tasks(now_ms);
        self.flush_events();
    }

    fn complete_failed_request(
        &mut self,
        connection_id: [u8; 16],
        agent_id: AgentId,
        request_id: &[u8; 16],
        now_ms: u64,
    ) {
        let Some(pending) = self.pending.get(request_id) else {
            return;
        };
        if pending.connection_id != connection_id || pending.agent_id != agent_id {
            return;
        }
        let pending = self
            .pending
            .remove(request_id)
            .expect("pending request exists");
        let _ = self
            .router
            .complete_peer(&pending.task_id, &pending.peer_id, now_ms);
    }

    fn finish_terminal_tasks(&mut self, now_ms: u64) {
        let task_ids = self.active_tasks.iter().cloned().collect::<Vec<_>>();
        for task_id in task_ids {
            let _ = self.router.next_actions(&task_id, now_ms);
            let Some(status) = self.router.status(&task_id) else {
                continue;
            };
            if status != QueryStatus::Active {
                self.pending.retain(|_, request| request.task_id != task_id);
                self.active_tasks.remove(&task_id);
                self.router.remove_terminal_task(&task_id);
                self.emit(OutgoingQueryEvent::TaskFinished { task_id, status });
            }
        }
    }

    fn emit(&mut self, event: OutgoingQueryEvent) {
        if !self.buffered_events.is_empty() {
            self.buffered_events.push_back(event);
            return;
        }
        match self.events.try_send(event) {
            Ok(()) => {}
            Err(TrySendError::Full(event)) => self.buffered_events.push_back(event),
            Err(TrySendError::Disconnected(_)) => self.buffered_events.clear(),
        }
    }

    fn flush_events(&mut self) {
        while let Some(event) = self.buffered_events.pop_front() {
            match self.events.try_send(event) {
                Ok(()) => {}
                Err(TrySendError::Full(event)) => {
                    self.buffered_events.push_front(event);
                    break;
                }
                Err(TrySendError::Disconnected(_)) => {
                    self.buffered_events.clear();
                    break;
                }
            }
        }
    }
}

fn response_matches(pending: &PendingRequest, response: &WireFrame, now_ms: u64) -> bool {
    match response {
        WireFrame::Answer(answer) => {
            answer.root_task_id == pending.root_task_id
                && answer.created_at_ms <= now_ms
                && answer.expires_at_ms > now_ms
                && answer.expires_at_ms <= pending.expires_at_ms
        }
        WireFrame::Offer(offer) => {
            pending.result_shape == ResultShape::Resources
                && offer.root_task_id == pending.root_task_id
                && offer.expires_at_ms > now_ms
                && offer.expires_at_ms <= pending.expires_at_ms
        }
        WireFrame::Error(_) => true,
        _ => false,
    }
}

fn error_code(error: &AslError) -> ErrorCode {
    match error {
        AslError::PolicyDenied => ErrorCode::PolicyDenied,
        AslError::QuotaExceeded => ErrorCode::QuotaExceeded,
        AslError::ExpiredMessage => ErrorCode::Timeout,
        AslError::InvalidMessage => ErrorCode::InvalidMessage,
        AslError::IncompatibleVersion => ErrorCode::IncompatibleVersion,
        AslError::SandboxUnavailable => ErrorCode::SandboxUnavailable,
        _ => ErrorCode::InternalError,
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, time::SystemTime};

    use asl_agent::{OutgoingTask, QueryScope};
    use asl_types::{
        ids::{AgentId, Id128, PeerId},
        protocol::{Answer, AnswerStatus, ConceptRef, Intent, Query, ResultShape, ResultStatus},
    };
    use rusqlite::Connection;

    use super::*;
    const CONTACT: AgentId = AgentId([1; 32]);
    const UNAUTHORIZED: AgentId = AgentId([2; 32]);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let id = libp2p_identity::PeerId::random();
            let path = std::env::temp_dir().join(format!("asl-outbound-{id}.sqlite3"));
            let store = asl_store::open_store(&path).unwrap();
            drop(store);
            let db = Connection::open(&path).unwrap();
            for agent in [CONTACT, UNAUTHORIZED] {
                db.execute(
                    "INSERT INTO agents(agent_id,identity_state) VALUES (?1,'verified')",
                    [bs58::encode(agent.as_bytes()).into_string()],
                )
                .unwrap();
            }
            db.execute(
                "INSERT INTO authorized_contacts(agent_id,authorized_at_ms,authorization_revision)
                 VALUES (?1,1,1)",
                [bs58::encode(CONTACT.as_bytes()).into_string()],
            )
            .unwrap();
            Self(path)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
            let _ = fs::remove_file(self.0.with_extension("sqlite3-wal"));
            let _ = fs::remove_file(self.0.with_extension("sqlite3-shm"));
        }
    }

    fn peer(seed: u8) -> PeerId {
        let key = libp2p_identity::Keypair::ed25519_from_bytes([seed; 32]).unwrap();
        PeerId::from_bytes(key.public().to_peer_id().to_bytes()).unwrap()
    }

    fn task(now_ms: u64) -> OutgoingTask {
        OutgoingTask::new(
            now_ms,
            Intent::FindEvidence,
            vec![ConceptRef::RUST],
            vec![],
            ResultShape::Claims,
            3,
            QueryScope::ContactsOnly,
        )
    }

    fn response(query: &Query, now_ms: u64) -> WireFrame {
        WireFrame::Answer(Answer {
            message_id: Id128([8; 16]),
            root_task_id: query.root_task_id,
            created_at_ms: now_ms,
            expires_at_ms: query.expires_at_ms,
            status: AnswerStatus::NoMatch,
            claims: vec![],
            evidence_ids: vec![],
            result_status: ResultStatus::Unverified,
        })
    }

    #[test]
    fn query_targets_only_live_authorized_contacts_and_collects_structured_response() {
        let fixture = Fixture::new();
        let (port, runtime) = outgoing_query_channel();
        let mut runner = DirectOutbound::open(&fixture.0, runtime).unwrap();
        let now_ms = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        port.submit(task(now_ms)).unwrap();
        let contact_peer = peer(1);
        let unauthorized_peer = peer(2);
        let mut sent = Vec::new();
        runner
            .poll(
                &[
                    (UNAUTHORIZED, [2; 16], unauthorized_peer.clone()),
                    (CONTACT, [1; 16], contact_peer.clone()),
                ],
                now_ms,
                |connection_id, request_id, frame| {
                    sent.push((connection_id, request_id, frame));
                    Ok(())
                },
            )
            .unwrap();

        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, [1; 16]);
        let WireFrame::Query(query) = &sent[0].2 else {
            panic!("expected structured query")
        };
        assert_eq!(query.topics, vec![ConceptRef::RUST]);
        assert_eq!(query.constraints, vec![]);
        let task_id = TaskId(query.root_task_id);
        let request_id = sent[0].1;
        runner.handle_event(
            &AdmittedNetworkEvent::ControlResponse {
                connection_id: [1; 16],
                agent_id: CONTACT,
                request_id,
                response: response(query, now_ms),
            },
            now_ms,
        );
        assert_eq!(
            port.try_recv_event().unwrap(),
            Some(OutgoingQueryEvent::TaskStarted {
                task_id: task_id.clone()
            })
        );
        assert!(matches!(
            port.try_recv_event().unwrap(),
            Some(OutgoingQueryEvent::Response {
                task_id: received,
                agent_id: CONTACT,
                peer_id,
                frame,
            }) if received == task_id
                && peer_id == contact_peer
                && matches!(frame.as_ref(), WireFrame::Answer(_))
        ));
        assert_eq!(
            port.try_recv_event().unwrap(),
            Some(OutgoingQueryEvent::TaskFinished {
                task_id,
                status: QueryStatus::Complete
            })
        );
    }

    #[test]
    fn public_queries_are_not_accepted_until_dht_provider_dialing_is_connected() {
        let (port, _runtime) = outgoing_query_channel();
        let query = OutgoingTask::new(
            10,
            Intent::FindEvidence,
            vec![ConceptRef::RUST],
            vec![],
            ResultShape::Claims,
            3,
            QueryScope::Public,
        );
        assert!(matches!(port.submit(query), Err(AslError::PolicyDenied)));
    }

    #[test]
    fn stale_or_wrong_root_responses_complete_the_request_without_exposing_result() {
        let fixture = Fixture::new();
        let (port, runtime) = outgoing_query_channel();
        let mut runner = DirectOutbound::open(&fixture.0, runtime).unwrap();
        let now_ms = 10_000;
        port.submit(task(now_ms)).unwrap();
        let contact_peer = peer(3);
        let mut sent = Vec::new();
        runner
            .poll(
                &[(CONTACT, [3; 16], contact_peer)],
                now_ms,
                |connection_id, request_id, frame| {
                    sent.push((connection_id, request_id, frame));
                    Ok(())
                },
            )
            .unwrap();
        let WireFrame::Query(query) = &sent[0].2 else {
            panic!("expected query")
        };
        let mut wrong = response(query, now_ms);
        let WireFrame::Answer(answer) = &mut wrong else {
            unreachable!()
        };
        answer.root_task_id = Id128([9; 16]);
        runner.handle_event(
            &AdmittedNetworkEvent::ControlResponse {
                connection_id: [3; 16],
                agent_id: CONTACT,
                request_id: sent[0].1,
                response: wrong,
            },
            now_ms,
        );
        assert!(matches!(
            port.try_recv_event().unwrap(),
            Some(OutgoingQueryEvent::TaskStarted { .. })
        ));
        assert!(matches!(
            port.try_recv_event().unwrap(),
            Some(OutgoingQueryEvent::TaskFinished {
                status: QueryStatus::Complete,
                ..
            })
        ));
    }
}
