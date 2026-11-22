use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::SocketAddr,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
        mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel},
    },
};

use asl_agent::{
    OutgoingTask, QueryAction, QueryRouter, QueryScope, QueryStatus,
    reputation::rank_authorized_contacts,
};
use asl_net::{dht::concept_key, transport::TransportKind};
use asl_store::evidence::{TrustDimension, TrustOutcome};
use asl_types::{
    error::{AslError, ErrorCode},
    ids::{AgentId, Hash32, Id128, PeerId},
    protocol::{ConceptRef, Query, ResultShape, WireFrame},
    task::TaskId,
};
use rand::{TryRng, rngs::SysRng};

use crate::{network::LocalNetworkObservation, profile::AdmittedNetworkEvent};

const MAX_QUEUED_TASKS: usize = 16;
const MAX_ACTIVE_OUTGOING_TASKS: usize = 8;
const MAX_PARALLEL_OUTGOING_PEERS: usize = 4;
const MAX_QUEUED_PEER_ACTIONS: usize = MAX_ACTIVE_OUTGOING_TASKS * asl_agent::MAX_QUERY_PEERS;
const MAX_QUERY_EVENT_BACKLOG: usize = 512;
const QUERY_EVENT_CHANNEL_CAPACITY: usize = 128;
// One start, at most one response per routed peer, and one terminal event.
const SCOPED_EVENT_CAPACITY: usize = asl_agent::MAX_QUERY_PEERS + 2;

pub struct OutgoingQueryPort {
    tasks: SyncSender<QueuedQuery>,
    scoped: SyncSender<ScopedSubmission>,
    events: Receiver<OutgoingQueryEvent>,
    network_generation: Arc<AtomicU64>,
}

type QueuedQuery = (u64, OutgoingTask);
type ScopedSubmission = (QueuedQuery, SyncSender<OutgoingQueryEvent>);

struct QuerySubmission {
    generation: u64,
    task: OutgoingTask,
    events: Option<SyncSender<OutgoingQueryEvent>>,
}

pub struct OutgoingQueryTicket {
    events: Option<Receiver<OutgoingQueryEvent>>,
}

impl OutgoingQueryTicket {
    /// Returns only this submission's events, in order, through its terminal event.
    pub fn try_recv_event(&mut self) -> Result<Option<OutgoingQueryEvent>, AslError> {
        let Some(events) = &self.events else {
            return Ok(None);
        };
        let event = try_recv_event(events)?;
        if matches!(
            event,
            Some(OutgoingQueryEvent::TaskFinished { .. } | OutgoingQueryEvent::TaskFailed { .. })
        ) {
            self.events = None;
        }
        Ok(event)
    }
}

impl OutgoingQueryPort {
    pub fn submit(&self, task: OutgoingTask) -> Result<(), AslError> {
        task.validate()?;
        enqueue(&self.tasks, self.tag(task))
    }

    /// Submit without publishing this task or its results to the shared stream.
    pub fn submit_scoped(&self, task: OutgoingTask) -> Result<OutgoingQueryTicket, AslError> {
        task.validate()?;
        let (events, receipt) = sync_channel(SCOPED_EVENT_CAPACITY);
        enqueue(&self.scoped, (self.tag(task), events))?;
        Ok(OutgoingQueryTicket {
            events: Some(receipt),
        })
    }

    pub fn try_recv_event(&self) -> Result<Option<OutgoingQueryEvent>, AslError> {
        try_recv_event(&self.events)
    }

    fn tag(&self, task: OutgoingTask) -> QueuedQuery {
        (self.network_generation.load(Ordering::Acquire), task)
    }
}

fn enqueue<T>(queue: &SyncSender<T>, value: T) -> Result<(), AslError> {
    match queue.try_send(value) {
        Ok(()) => Ok(()),
        Err(TrySendError::Full(_)) => Err(AslError::QuotaExceeded),
        Err(TrySendError::Disconnected(_)) => Err(AslError::SandboxUnavailable),
    }
}

fn try_recv_event(
    events: &Receiver<OutgoingQueryEvent>,
) -> Result<Option<OutgoingQueryEvent>, AslError> {
    match events.try_recv() {
        Ok(event) => Ok(Some(event)),
        Err(TryRecvError::Empty) => Ok(None),
        Err(TryRecvError::Disconnected) => Err(AslError::SandboxUnavailable),
    }
}

pub struct OutgoingQueryRuntime {
    tasks: Receiver<QueuedQuery>,
    scoped: Receiver<ScopedSubmission>,
    events: SyncSender<OutgoingQueryEvent>,
    network_generation: Arc<AtomicU64>,
}

pub fn outgoing_query_channel() -> (OutgoingQueryPort, OutgoingQueryRuntime) {
    let (task_sender, tasks) = sync_channel(MAX_QUEUED_TASKS);
    let (scoped_sender, scoped) = sync_channel(MAX_QUEUED_TASKS);
    let (events, event_receiver) = sync_channel(QUERY_EVENT_CHANNEL_CAPACITY);
    let network_generation = Arc::new(AtomicU64::new(0));
    (
        OutgoingQueryPort {
            tasks: task_sender,
            scoped: scoped_sender,
            events: event_receiver,
            network_generation: Arc::clone(&network_generation),
        },
        OutgoingQueryRuntime {
            tasks,
            scoped,
            events,
            network_generation,
        },
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

struct PendingDhtLookup {
    task_id: TaskId,
    concept: ConceptRef,
    expires_at_ms: u64,
}

struct PendingPeerQuery {
    task_id: TaskId,
    peer_id: PeerId,
    query: Query,
}

struct ProviderRoute {
    endpoint: Option<(TransportKind, SocketAddr)>,
    relay_route_available: bool,
}

struct PendingProviderDial {
    operation_id: Option<[u8; 16]>,
    queries: Vec<PendingPeerQuery>,
}

pub(crate) struct DirectOutbound {
    store: asl_store::Store,
    tasks: Receiver<QueuedQuery>,
    scoped: Receiver<ScopedSubmission>,
    prefer_scoped: bool,
    events: SyncSender<OutgoingQueryEvent>,
    scoped_events: HashMap<TaskId, SyncSender<OutgoingQueryEvent>>,
    router: QueryRouter,
    active_tasks: HashSet<TaskId>,
    task_scopes: HashMap<TaskId, QueryScope>,
    pending: HashMap<[u8; 16], PendingRequest>,
    pending_lookups: HashMap<[u8; 16], PendingDhtLookup>,
    provider_routes: HashMap<(TaskId, PeerId), ProviderRoute>,
    pending_provider_dials: HashMap<PeerId, PendingProviderDial>,
    queued_peer_actions: VecDeque<PendingPeerQuery>,
    buffered_events: VecDeque<OutgoingQueryEvent>,
    network_generation: Arc<AtomicU64>,
}

impl DirectOutbound {
    pub(crate) fn open(path: &Path, runtime: OutgoingQueryRuntime) -> Result<Self, AslError> {
        Ok(Self {
            store: asl_store::open_store(path)?,
            tasks: runtime.tasks,
            scoped: runtime.scoped,
            prefer_scoped: true,
            events: runtime.events,
            scoped_events: HashMap::new(),
            router: QueryRouter::new(),
            active_tasks: HashSet::new(),
            task_scopes: HashMap::new(),
            pending: HashMap::new(),
            pending_lookups: HashMap::new(),
            provider_routes: HashMap::new(),
            pending_provider_dials: HashMap::new(),
            queued_peer_actions: VecDeque::new(),
            buffered_events: VecDeque::new(),
            network_generation: runtime.network_generation,
        })
    }

    pub(crate) fn poll(
        &mut self,
        connections: &[(AgentId, [u8; 16], PeerId)],
        connecting_peers: &[PeerId],
        now_ms: u64,
        mut send: impl FnMut([u8; 16], [u8; 16], WireFrame) -> Result<(), AslError>,
        mut find_providers: impl FnMut([u8; 16], [u8; 32]) -> Result<(), AslError>,
        mut dial_provider: impl FnMut(
            [u8; 16],
            PeerId,
            Option<(TransportKind, SocketAddr)>,
            bool,
        ) -> Result<(), AslError>,
    ) -> Result<(), AslError> {
        let current_generation = self.update_generation(false);
        self.flush_events();
        let expired_requests = self
            .pending
            .iter()
            .filter_map(|(request_id, request)| {
                (now_ms >= request.expires_at_ms).then_some(*request_id)
            })
            .collect::<Vec<_>>();
        for request_id in expired_requests {
            if let Some(request) = self.pending.remove(&request_id) {
                self.record_availability(
                    request.agent_id,
                    &request_id,
                    TrustOutcome::Negative,
                    now_ms,
                )?;
                let _ = self
                    .router
                    .complete_peer(&request.task_id, &request.peer_id, now_ms);
            }
        }
        let expired_lookups = self
            .pending_lookups
            .iter()
            .filter_map(|(lookup_id, lookup)| {
                (now_ms >= lookup.expires_at_ms).then_some(*lookup_id)
            })
            .collect::<Vec<_>>();
        for lookup_id in expired_lookups {
            if let Some(lookup) = self.pending_lookups.remove(&lookup_id) {
                let _ = self
                    .router
                    .record_dht_result(&lookup.task_id, lookup.concept, [], now_ms);
            }
        }

        let authorized = self.store.authorized_contacts()?;
        let preferred = self.store.preferred_agents()?;
        let evidence = self.store.authorized_contact_evidence()?;
        let authorized = rank_authorized_contacts(&authorized, &preferred, &evidence);
        let mut by_agent = HashMap::new();
        let mut by_peer = HashMap::new();
        for (agent_id, connection_id, peer_id) in connections {
            by_agent
                .entry(*agent_id)
                .or_insert((*connection_id, peer_id.clone()));
            by_peer
                .entry(peer_id.clone())
                .or_insert((*agent_id, *connection_id));
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

        while self.active_tasks.len() < MAX_ACTIVE_OUTGOING_TASKS {
            let Some(QuerySubmission {
                generation,
                task,
                events,
            }) = self.next_submission()
            else {
                break;
            };
            if generation != current_generation {
                let event = offline_event(&task, now_ms);
                if let Some(scoped) = events {
                    let _ = scoped.try_send(event);
                } else {
                    self.emit(event);
                }
                continue;
            }
            let scope = task.scope;
            match self.router.start_query(task) {
                Ok(task_id) => {
                    self.active_tasks.insert(task_id.clone());
                    self.task_scopes.insert(task_id.clone(), scope);
                    if let Some(events) = events {
                        self.scoped_events.insert(task_id.clone(), events);
                    }
                    self.emit(OutgoingQueryEvent::TaskStarted { task_id });
                }
                Err(error) => {
                    let failed = OutgoingQueryEvent::TaskFailed {
                        code: error_code(&error),
                    };
                    if let Some(events) = events {
                        let _ = events.try_send(failed);
                    } else {
                        self.emit(failed);
                    }
                }
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
                        if self.queued_peer_actions.len() < MAX_QUEUED_PEER_ACTIONS {
                            self.queued_peer_actions.push_back(PendingPeerQuery {
                                task_id,
                                peer_id,
                                query,
                            });
                        } else {
                            let _ = self.router.complete_peer(&task_id, &peer_id, now_ms);
                        }
                    }
                    QueryAction::DhtLookup { task_id, concept } => {
                        let key = match concept_key(concept) {
                            Ok(key) => match <[u8; 32]>::try_from(key.as_ref()) {
                                Ok(key) => key,
                                Err(_) => {
                                    let _ = self.router.record_dht_result(
                                        &task_id,
                                        concept,
                                        [],
                                        now_ms,
                                    );
                                    continue;
                                }
                            },
                            Err(_) => {
                                let _ =
                                    self.router.record_dht_result(&task_id, concept, [], now_ms);
                                continue;
                            }
                        };
                        let lookup_id = fresh_operation_id(
                            &self.pending_lookups,
                            &self.pending_provider_dials,
                        )?;
                        if find_providers(lookup_id, key).is_ok() {
                            let expires_at_ms =
                                self.router.expires_at_ms(&task_id).unwrap_or(now_ms);
                            self.pending_lookups.insert(
                                lookup_id,
                                PendingDhtLookup {
                                    task_id,
                                    concept,
                                    expires_at_ms,
                                },
                            );
                        } else {
                            let _ = self.router.record_dht_result(&task_id, concept, [], now_ms);
                        }
                    }
                }
            }
        }

        let pending_peers = self
            .pending_provider_dials
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        for peer_id in pending_peers {
            let Some((agent_id, connection_id)) = by_peer.get(&peer_id).copied() else {
                continue;
            };
            if self.pending_for_peer(&peer_id)
                || self.active_outgoing_peers(&by_peer) >= MAX_PARALLEL_OUTGOING_PEERS
            {
                continue;
            }
            let query = self
                .pending_provider_dials
                .get_mut(&peer_id)
                .and_then(|pending| pending.queries.pop());
            if let Some(query) = query {
                self.dispatch_query(query, agent_id, connection_id, now_ms, &mut send);
            }
            if self
                .pending_provider_dials
                .get(&peer_id)
                .is_some_and(|pending| pending.queries.is_empty())
            {
                self.pending_provider_dials.remove(&peer_id);
            }
        }

        let queued_count = self.queued_peer_actions.len();
        for _ in 0..queued_count {
            if self.active_outgoing_peers(&by_peer) >= MAX_PARALLEL_OUTGOING_PEERS {
                break;
            }
            let Some(action) = self.queued_peer_actions.pop_front() else {
                break;
            };
            if self.router.status(&action.task_id) != Some(QueryStatus::Active)
                || now_ms >= action.query.expires_at_ms
            {
                let _ = self
                    .router
                    .complete_peer(&action.task_id, &action.peer_id, now_ms);
                continue;
            }
            let scope = self
                .task_scopes
                .get(&action.task_id)
                .copied()
                .unwrap_or(QueryScope::ContactsOnly);

            if let Some((agent_id, connection_id)) = by_peer.get(&action.peer_id).copied() {
                self.provider_routes
                    .remove(&(action.task_id.clone(), action.peer_id.clone()));
                if self.pending_for_peer(&action.peer_id) {
                    self.queued_peer_actions.push_back(action);
                    continue;
                }
                if scope == QueryScope::Public
                    || contacts.iter().any(|(_, _, peer)| *peer == action.peer_id)
                {
                    self.dispatch_query(action, agent_id, connection_id, now_ms, &mut send);
                } else {
                    let _ = self
                        .router
                        .complete_peer(&action.task_id, &action.peer_id, now_ms);
                }
                continue;
            }

            if scope != QueryScope::Public {
                self.provider_routes
                    .remove(&(action.task_id.clone(), action.peer_id.clone()));
                let _ = self
                    .router
                    .complete_peer(&action.task_id, &action.peer_id, now_ms);
                continue;
            }

            let route_key = (action.task_id.clone(), action.peer_id.clone());
            if self.pending_provider_dials.contains_key(&action.peer_id) {
                self.provider_routes.remove(&route_key);
                let pending = self
                    .pending_provider_dials
                    .get_mut(&action.peer_id)
                    .expect("provider dial remains present");
                pending.queries.push(action);
                continue;
            }

            if connecting_peers.contains(&action.peer_id) {
                if self.active_outgoing_peers(&by_peer) >= MAX_PARALLEL_OUTGOING_PEERS {
                    self.queued_peer_actions.push_front(action);
                    break;
                }
                self.provider_routes
                    .remove(&(action.task_id.clone(), action.peer_id.clone()));
                self.pending_provider_dials.insert(
                    action.peer_id.clone(),
                    PendingProviderDial {
                        operation_id: None,
                        queries: vec![action],
                    },
                );
                continue;
            }

            if self.active_outgoing_peers(&by_peer) >= MAX_PARALLEL_OUTGOING_PEERS {
                self.queued_peer_actions.push_front(action);
                break;
            }
            let Some(route) = self
                .provider_routes
                .remove(&(action.task_id.clone(), action.peer_id.clone()))
            else {
                let _ = self
                    .router
                    .complete_peer(&action.task_id, &action.peer_id, now_ms);
                continue;
            };
            if route.endpoint.is_none() && !route.relay_route_available {
                let _ = self
                    .router
                    .complete_peer(&action.task_id, &action.peer_id, now_ms);
                continue;
            }
            let operation_id =
                fresh_operation_id(&self.pending_lookups, &self.pending_provider_dials)?;
            if dial_provider(
                operation_id,
                action.peer_id.clone(),
                route.endpoint,
                route.relay_route_available,
            )
            .is_ok()
            {
                self.pending_provider_dials.insert(
                    action.peer_id.clone(),
                    PendingProviderDial {
                        operation_id: Some(operation_id),
                        queries: vec![action],
                    },
                );
            } else {
                let _ = self
                    .router
                    .complete_peer(&action.task_id, &action.peer_id, now_ms);
            }
        }

        self.finish_terminal_tasks();
        self.flush_events();
        Ok(())
    }

    fn next_submission(&mut self) -> Option<QuerySubmission> {
        let shared = || {
            if self.buffered_events.len()
                >= MAX_QUERY_EVENT_BACKLOG - MAX_ACTIVE_OUTGOING_TASKS * SCOPED_EVENT_CAPACITY
            {
                return None;
            }
            self.tasks
                .try_recv()
                .ok()
                .map(|(generation, task)| QuerySubmission {
                    generation,
                    task,
                    events: None,
                })
        };
        let scoped = || {
            self.scoped
                .try_recv()
                .ok()
                .map(|((generation, task), events)| QuerySubmission {
                    generation,
                    task,
                    events: Some(events),
                })
        };
        let submission = if self.prefer_scoped {
            scoped().or_else(shared)
        } else {
            shared().or_else(scoped)
        }?;
        self.prefer_scoped = submission.events.is_none();
        Some(submission)
    }

    pub(crate) fn poll_paused(&mut self, now_ms: u64) {
        self.update_generation(true);
        for task_id in std::mem::take(&mut self.active_tasks) {
            let event = OutgoingQueryEvent::TaskFailed {
                code: ErrorCode::Offline,
            };
            if let Some(scoped) = self.scoped_events.remove(&task_id) {
                let _ = scoped.try_send(event);
            } else {
                self.emit(event);
            }
        }
        self.router = QueryRouter::new();
        self.task_scopes.clear();
        self.pending.clear();
        self.pending_lookups.clear();
        self.provider_routes.clear();
        self.pending_provider_dials.clear();
        self.queued_peer_actions.clear();
        self.poll_offline(now_ms);
        self.flush_events();
        for _ in 0..MAX_QUEUED_TASKS {
            if self.buffered_events.len() >= MAX_QUERY_EVENT_BACKLOG {
                break;
            }
            let Ok((_, task)) = self.tasks.try_recv() else {
                break;
            };
            self.emit(offline_event(&task, now_ms));
        }
    }

    fn update_generation(&self, paused: bool) -> u64 {
        // Odd epochs are paused. A queued request from either side of that
        // boundary stays stale even when the shared event stream is full.
        let generation = self.network_generation.load(Ordering::Relaxed);
        if (generation & 1 != 0) == paused {
            generation
        } else {
            let next = generation.wrapping_add(1);
            self.network_generation.store(next, Ordering::Release);
            next
        }
    }

    pub(crate) fn poll_offline(&mut self, now_ms: u64) {
        for _ in 0..MAX_QUEUED_TASKS {
            let Ok(((_, task), events)) = self.scoped.try_recv() else {
                break;
            };
            let _ = events.try_send(offline_event(&task, now_ms));
        }
        for task_id in self.scoped_events.keys() {
            if self
                .router
                .expires_at_ms(task_id)
                .is_some_and(|expires| expires <= now_ms)
            {
                self.router.next_actions(task_id, now_ms);
            }
        }
        self.finish_terminal_tasks();
    }

    fn pending_for_peer(&self, peer_id: &PeerId) -> bool {
        self.pending
            .values()
            .any(|pending| &pending.peer_id == peer_id)
    }

    fn active_outgoing_peers(
        &self,
        admitted_peers: &HashMap<PeerId, (AgentId, [u8; 16])>,
    ) -> usize {
        let mut peers = self
            .pending
            .values()
            .map(|pending| pending.peer_id.clone())
            .collect::<HashSet<_>>();
        peers.extend(
            self.pending_provider_dials
                .keys()
                .filter(|peer_id| !admitted_peers.contains_key(*peer_id))
                .cloned(),
        );
        peers.len()
    }

    fn dispatch_query(
        &mut self,
        pending_query: PendingPeerQuery,
        agent_id: AgentId,
        connection_id: [u8; 16],
        now_ms: u64,
        send: &mut impl FnMut([u8; 16], [u8; 16], WireFrame) -> Result<(), AslError>,
    ) {
        if self.router.status(&pending_query.task_id) != Some(QueryStatus::Active)
            || now_ms >= pending_query.query.expires_at_ms
        {
            let _ =
                self.router
                    .complete_peer(&pending_query.task_id, &pending_query.peer_id, now_ms);
            return;
        }
        let request_id = pending_query.query.message_id.0;
        if send(
            connection_id,
            request_id,
            WireFrame::Query(pending_query.query.clone()),
        )
        .is_ok()
        {
            self.pending.insert(
                request_id,
                PendingRequest {
                    task_id: pending_query.task_id,
                    agent_id,
                    peer_id: pending_query.peer_id,
                    connection_id,
                    root_task_id: pending_query.query.root_task_id,
                    expires_at_ms: pending_query.query.expires_at_ms,
                    result_shape: pending_query.query.result_shape,
                },
            );
        } else {
            let _ =
                self.router
                    .complete_peer(&pending_query.task_id, &pending_query.peer_id, now_ms);
        }
    }

    pub(crate) fn handle_local_observation(
        &mut self,
        observation: LocalNetworkObservation,
        now_ms: u64,
    ) {
        let LocalNetworkObservation::DhtProviders {
            lookup_id,
            status: _,
            providers,
        } = observation
        else {
            return;
        };
        let Some(lookup) = self.pending_lookups.remove(&lookup_id) else {
            return;
        };
        if now_ms >= lookup.expires_at_ms
            || self.router.status(&lookup.task_id) != Some(QueryStatus::Active)
        {
            return;
        }

        let routes = providers
            .into_iter()
            .map(|provider| {
                (
                    provider.peer_id.clone(),
                    ProviderRoute {
                        endpoint: provider.endpoint,
                        relay_route_available: provider.relay_route_available,
                    },
                )
            })
            .collect::<HashMap<_, _>>();
        let selected = self.router.record_dht_result(
            &lookup.task_id,
            lookup.concept,
            routes.keys().cloned(),
            now_ms,
        );
        if let Ok(selected) = selected {
            for peer_id in selected {
                if let Some(route) = routes.get(&peer_id) {
                    self.provider_routes.insert(
                        (lookup.task_id.clone(), peer_id),
                        ProviderRoute {
                            endpoint: route.endpoint,
                            relay_route_available: route.relay_route_available,
                        },
                    );
                }
            }
        }
        self.finish_terminal_tasks();
        self.flush_events();
    }

    pub(crate) fn handle_event(
        &mut self,
        event: &AdmittedNetworkEvent,
        now_ms: u64,
    ) -> Result<(), AslError> {
        match event {
            AdmittedNetworkEvent::ControlResponse {
                connection_id,
                agent_id,
                request_id,
                response,
            } => {
                let Some(pending) = self.pending.get(request_id) else {
                    return Ok(());
                };
                if pending.connection_id != *connection_id
                    || pending.agent_id != *agent_id
                    || now_ms >= pending.expires_at_ms
                {
                    return Ok(());
                }
                let pending = self
                    .pending
                    .remove(request_id)
                    .expect("pending request exists");
                if response_matches(&pending, response, now_ms) {
                    self.record_availability(
                        pending.agent_id,
                        request_id,
                        TrustOutcome::Positive,
                        now_ms,
                    )?;
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
                self.complete_failed_request(*connection_id, *agent_id, request_id, now_ms)?;
            }
            AdmittedNetworkEvent::PeerDisconnected {
                connection_id,
                peer_id,
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
                        self.record_availability(
                            pending.agent_id,
                            &request_id,
                            TrustOutcome::Negative,
                            now_ms,
                        )?;
                        let _ =
                            self.router
                                .complete_peer(&pending.task_id, &pending.peer_id, now_ms);
                    }
                }
                if let Some(peer_id) = peer_id {
                    if let Some(pending) = self.pending_provider_dials.remove(peer_id) {
                        for query in pending.queries {
                            let _ =
                                self.router
                                    .complete_peer(&query.task_id, &query.peer_id, now_ms);
                        }
                    }
                    self.provider_routes
                        .retain(|(_, candidate), _| candidate != peer_id);
                }
            }
            AdmittedNetworkEvent::OperationFailed {
                operation_id,
                code: _,
            } => {
                if let Some(lookup) = self.pending_lookups.remove(operation_id) {
                    let _ =
                        self.router
                            .record_dht_result(&lookup.task_id, lookup.concept, [], now_ms);
                }
                let failed_peer =
                    self.pending_provider_dials
                        .iter()
                        .find_map(|(peer_id, pending)| {
                            (pending.operation_id == Some(*operation_id)).then_some(peer_id.clone())
                        });
                if let Some(peer_id) = failed_peer
                    && let Some(pending) = self.pending_provider_dials.remove(&peer_id)
                {
                    for query in pending.queries {
                        let _ = self
                            .router
                            .complete_peer(&query.task_id, &query.peer_id, now_ms);
                    }
                }
            }
            _ => {}
        }
        self.finish_terminal_tasks();
        self.flush_events();
        Ok(())
    }

    fn complete_failed_request(
        &mut self,
        connection_id: [u8; 16],
        agent_id: AgentId,
        request_id: &[u8; 16],
        now_ms: u64,
    ) -> Result<(), AslError> {
        let Some(pending) = self.pending.get(request_id) else {
            return Ok(());
        };
        if pending.connection_id != connection_id || pending.agent_id != agent_id {
            return Ok(());
        }
        let pending = self
            .pending
            .remove(request_id)
            .expect("pending request exists");
        self.record_availability(pending.agent_id, request_id, TrustOutcome::Negative, now_ms)?;
        let _ = self
            .router
            .complete_peer(&pending.task_id, &pending.peer_id, now_ms);
        Ok(())
    }

    fn record_availability(
        &mut self,
        agent_id: AgentId,
        request_id: &[u8; 16],
        outcome: TrustOutcome,
        now_ms: u64,
    ) -> Result<(), AslError> {
        self.store.record_trust_observation(
            agent_id,
            None,
            TrustDimension::Availability,
            outcome,
            Hash32(*blake3::hash(request_id).as_bytes()),
            now_ms,
        )?;
        Ok(())
    }

    fn finish_terminal_tasks(&mut self) {
        let task_ids = self.active_tasks.iter().cloned().collect::<Vec<_>>();
        for task_id in task_ids {
            let Some(status) = self.router.status(&task_id) else {
                continue;
            };
            if status != QueryStatus::Active {
                self.pending.retain(|_, request| request.task_id != task_id);
                self.pending_lookups
                    .retain(|_, lookup| lookup.task_id != task_id);
                self.queued_peer_actions
                    .retain(|action| action.task_id != task_id);
                for pending in self.pending_provider_dials.values_mut() {
                    pending.queries.retain(|query| query.task_id != task_id);
                }
                self.pending_provider_dials
                    .retain(|_, pending| !pending.queries.is_empty());
                self.provider_routes
                    .retain(|(candidate_task, _), _| candidate_task != &task_id);
                self.active_tasks.remove(&task_id);
                self.task_scopes.remove(&task_id);
                self.router.remove_terminal_task(&task_id);
                self.emit(OutgoingQueryEvent::TaskFinished {
                    task_id: task_id.clone(),
                    status,
                });
                self.scoped_events.remove(&task_id);
            }
        }
    }

    fn emit(&mut self, event: OutgoingQueryEvent) {
        let task_id = match &event {
            OutgoingQueryEvent::TaskStarted { task_id }
            | OutgoingQueryEvent::Response { task_id, .. }
            | OutgoingQueryEvent::TaskFinished { task_id, .. } => Some(task_id),
            OutgoingQueryEvent::TaskFailed { .. } => None,
        };
        if let Some(events) = task_id.and_then(|id| self.scoped_events.get(id)) {
            // A task emits at most one start, one response per routed peer,
            // and one terminal event. Keep them private even if the host exits.
            let _ = events.try_send(event);
            return;
        }
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

fn offline_event(task: &OutgoingTask, now_ms: u64) -> OutgoingQueryEvent {
    let code = if task.expires_at_ms <= now_ms {
        ErrorCode::Timeout
    } else {
        ErrorCode::Offline
    };
    OutgoingQueryEvent::TaskFailed { code }
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

fn fresh_operation_id(
    lookups: &HashMap<[u8; 16], PendingDhtLookup>,
    dials: &HashMap<PeerId, PendingProviderDial>,
) -> Result<[u8; 16], AslError> {
    for _ in 0..8 {
        let mut id = [0; 16];
        SysRng
            .try_fill_bytes(&mut id)
            .map_err(|_| AslError::InvalidIdentity)?;
        if id != [0; 16]
            && !lookups.contains_key(&id)
            && !dials
                .values()
                .any(|pending| pending.operation_id == Some(id))
        {
            return Ok(id);
        }
    }
    Err(AslError::QuotaExceeded)
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
        task_with_scope(now_ms, QueryScope::ContactsOnly)
    }

    fn task_with_scope(now_ms: u64, scope: QueryScope) -> OutgoingTask {
        OutgoingTask::new(
            now_ms,
            Intent::FindEvidence,
            vec![ConceptRef::RUST],
            vec![],
            ResultShape::Claims,
            3,
            scope,
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
        let mut ticket = port.submit_scoped(task(now_ms)).unwrap();
        let contact_peer = peer(1);
        let unauthorized_peer = peer(2);
        let mut sent = Vec::new();
        runner
            .poll(
                &[
                    (UNAUTHORIZED, [2; 16], unauthorized_peer.clone()),
                    (CONTACT, [1; 16], contact_peer.clone()),
                ],
                &[],
                now_ms,
                |connection_id, request_id, frame| {
                    sent.push((connection_id, request_id, frame));
                    Ok(())
                },
                |_, _| Ok(()),
                |_, _, _, _| Ok(()),
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
        runner
            .handle_event(
                &AdmittedNetworkEvent::ControlResponse {
                    connection_id: [1; 16],
                    agent_id: CONTACT,
                    request_id,
                    response: response(query, now_ms),
                },
                now_ms,
            )
            .unwrap();
        assert_eq!(
            ticket.try_recv_event().unwrap(),
            Some(OutgoingQueryEvent::TaskStarted {
                task_id: task_id.clone()
            })
        );
        assert!(matches!(
            ticket.try_recv_event().unwrap(),
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
            ticket.try_recv_event().unwrap(),
            Some(OutgoingQueryEvent::TaskFinished {
                task_id,
                status: QueryStatus::Complete
            })
        );
        assert_eq!(ticket.try_recv_event().unwrap(), None);
        assert_eq!(port.try_recv_event().unwrap(), None);
    }

    #[test]
    fn concurrent_scoped_queries_deliver_only_their_own_events() {
        let fixture = Fixture::new();
        let (port, runtime) = outgoing_query_channel();
        let mut runner = DirectOutbound::open(&fixture.0, runtime).unwrap();
        let now = 10_000;
        let first = port.submit_scoped(task(now)).unwrap();
        let second = port.submit_scoped(task(now)).unwrap();
        runner
            .poll(
                &[],
                &[],
                now,
                |_, _, _| panic!("contacts-only query has no live contacts"),
                |_, _| panic!("contacts-only query has no DHT lookup"),
                |_, _, _, _| panic!("contacts-only query cannot dial"),
            )
            .unwrap();

        let drain = |mut ticket: OutgoingQueryTicket| {
            let Some(OutgoingQueryEvent::TaskStarted { task_id }) =
                ticket.try_recv_event().unwrap()
            else {
                panic!("expected task start");
            };
            assert_eq!(
                ticket.try_recv_event().unwrap(),
                Some(OutgoingQueryEvent::TaskFinished {
                    task_id: task_id.clone(),
                    status: QueryStatus::Complete,
                })
            );
            assert_eq!(ticket.try_recv_event().unwrap(), None);
            task_id
        };
        assert_ne!(drain(first), drain(second));
        assert_eq!(port.try_recv_event().unwrap(), None);
    }

    #[test]
    fn scoped_query_runs_while_shared_events_are_backpressured() {
        let fixture = Fixture::new();
        let (port, runtime) = outgoing_query_channel();
        let mut runner = DirectOutbound::open(&fixture.0, runtime).unwrap();
        let now = 10_000;
        let shared_event = OutgoingQueryEvent::TaskFailed {
            code: ErrorCode::Busy,
        };
        for _ in 0..QUERY_EVENT_CHANNEL_CAPACITY {
            runner.events.try_send(shared_event.clone()).unwrap();
        }
        runner
            .buffered_events
            .resize(MAX_QUERY_EVENT_BACKLOG - 1, shared_event);
        port.submit(task(now)).unwrap();
        let mut ticket = port.submit_scoped(task(now)).unwrap();
        runner
            .poll(
                &[],
                &[],
                now,
                |_, _, _| panic!("no live contacts"),
                |_, _| panic!("no DHT lookup"),
                |_, _, _, _| panic!("no dial"),
            )
            .unwrap();

        assert!(matches!(
            ticket.try_recv_event().unwrap(),
            Some(OutgoingQueryEvent::TaskStarted { .. })
        ));
        assert!(matches!(
            ticket.try_recv_event().unwrap(),
            Some(OutgoingQueryEvent::TaskFinished { .. })
        ));
        assert_eq!(runner.buffered_events.len(), MAX_QUERY_EVENT_BACKLOG - 1);
        assert!(runner.tasks.try_recv().is_ok());
    }

    #[test]
    fn offline_query_tick_terminates_new_and_expired_active_scoped_tasks() {
        let fixture = Fixture::new();
        let (port, runtime) = outgoing_query_channel();
        let mut runner = DirectOutbound::open(&fixture.0, runtime).unwrap();
        let now = 10_000;
        let query = task(now);
        let deadline = query.expires_at_ms;
        let mut active = port.submit_scoped(query).unwrap();
        runner
            .poll(
                &[(CONTACT, [1; 16], peer(1))],
                &[],
                now,
                |_, _, _| Ok(()),
                |_, _| panic!("no DHT lookup"),
                |_, _, _, _| panic!("no dial"),
            )
            .unwrap();
        let Some(OutgoingQueryEvent::TaskStarted { task_id }) = active.try_recv_event().unwrap()
        else {
            panic!("expected active query");
        };
        let mut offline = port.submit_scoped(task(deadline)).unwrap();
        runner.poll_offline(deadline);
        assert_eq!(
            active.try_recv_event().unwrap(),
            Some(OutgoingQueryEvent::TaskFinished {
                task_id,
                status: QueryStatus::Expired,
            })
        );
        assert_eq!(
            offline.try_recv_event().unwrap(),
            Some(OutgoingQueryEvent::TaskFailed {
                code: ErrorCode::Offline,
            })
        );
        assert_eq!(port.try_recv_event().unwrap(), None);
    }

    #[test]
    fn paused_queries_fail_without_replaying_previous_requests() {
        let fixture = Fixture::new();
        let (port, runtime) = outgoing_query_channel();
        let mut runner = DirectOutbound::open(&fixture.0, runtime).unwrap();
        let now = 10_000;
        let mut active = port.submit_scoped(task(now)).unwrap();
        let connections = [(CONTACT, [1; 16], peer(1))];
        runner
            .poll(
                &connections,
                &[],
                now,
                |_, _, _| Ok(()),
                |_, _| unreachable!(),
                |_, _, _, _| unreachable!(),
            )
            .unwrap();
        assert!(matches!(
            active.try_recv_event().unwrap(),
            Some(OutgoingQueryEvent::TaskStarted { .. })
        ));

        let mut waiting = port.submit_scoped(task(now)).unwrap();
        runner.poll_paused(now + 1);
        for ticket in [&mut active, &mut waiting] {
            assert_eq!(
                ticket.try_recv_event().unwrap(),
                Some(OutgoingQueryEvent::TaskFailed {
                    code: ErrorCode::Offline
                })
            );
        }
        runner
            .poll(
                &connections,
                &[],
                now + 2,
                |_, _, _| unreachable!(),
                |_, _| unreachable!(),
                |_, _, _, _| unreachable!(),
            )
            .unwrap();
    }

    #[test]
    fn paused_shared_submissions_do_not_replay_behind_event_backpressure() {
        let fixture = Fixture::new();
        let (port, runtime) = outgoing_query_channel();
        let mut runner = DirectOutbound::open(&fixture.0, runtime).unwrap();
        let now = 10_000;
        let offline = OutgoingQueryEvent::TaskFailed {
            code: ErrorCode::Offline,
        };
        for _ in 0..QUERY_EVENT_CHANNEL_CAPACITY {
            runner.events.try_send(offline.clone()).unwrap();
        }
        runner
            .buffered_events
            .resize(MAX_QUERY_EVENT_BACKLOG, offline.clone());
        port.submit(task(now)).unwrap();
        runner.poll_paused(now + 1);
        port.submit(task(now + 1)).unwrap();
        let mut scoped = port.submit_scoped(task(now + 1)).unwrap();

        runner.buffered_events.clear();
        while port.try_recv_event().unwrap().is_some() {}
        runner
            .poll(
                &[(CONTACT, [1; 16], peer(1))],
                &[],
                now + 2,
                |_, _, _| panic!("stale query must not be sent"),
                |_, _| panic!("stale query must not start discovery"),
                |_, _, _, _| panic!("stale query must not dial"),
            )
            .unwrap();
        assert_eq!(scoped.try_recv_event().unwrap(), Some(offline.clone()));
        assert_eq!(port.try_recv_event().unwrap(), Some(offline.clone()));
        assert_eq!(port.try_recv_event().unwrap(), Some(offline));
        assert_eq!(port.try_recv_event().unwrap(), None);
    }

    #[test]
    fn public_provider_query_is_sent_only_after_admitted_connection() {
        use asl_net::transport::{DhtLookupStatus, DhtProviderCandidate, TransportKind};

        let fixture = Fixture::new();
        let (port, runtime) = outgoing_query_channel();
        let mut runner = DirectOutbound::open(&fixture.0, runtime).unwrap();
        let now_ms = 100;
        port.submit(task_with_scope(now_ms, QueryScope::Public))
            .unwrap();

        let mut lookups = Vec::new();
        runner
            .poll(
                &[],
                &[],
                now_ms,
                |_, _, _| panic!("no peer is admitted yet"),
                |lookup_id, key| {
                    lookups.push((lookup_id, key));
                    Ok(())
                },
                |_, _, _, _| panic!("provider lookup has not returned yet"),
            )
            .unwrap();
        assert_eq!(lookups.len(), 1);

        let provider = peer(4);
        let endpoint = "192.168.1.44:4044".parse().unwrap();
        runner.handle_local_observation(
            LocalNetworkObservation::DhtProviders {
                lookup_id: lookups[0].0,
                status: DhtLookupStatus::Completed,
                providers: vec![DhtProviderCandidate {
                    peer_id: provider.clone(),
                    endpoint: Some((TransportKind::Tcp, endpoint)),
                    relay_route_available: false,
                }],
            },
            now_ms + 1,
        );

        let mut dials = Vec::new();
        let mut sent = Vec::new();
        runner
            .poll(
                &[],
                &[],
                now_ms + 2,
                |connection_id, request_id, frame| {
                    sent.push((connection_id, request_id, frame));
                    Ok(())
                },
                |_, _| Ok(()),
                |operation_id, peer_id, address, relay| {
                    dials.push((operation_id, peer_id, address, relay));
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(dials.len(), 1);
        assert_eq!(dials[0].1, provider);
        assert_eq!(dials[0].2, Some((TransportKind::Tcp, endpoint)));
        assert!(!dials[0].3);
        assert!(sent.is_empty());

        runner
            .poll(
                &[],
                std::slice::from_ref(&provider),
                now_ms + 3,
                |connection_id, request_id, frame| {
                    sent.push((connection_id, request_id, frame));
                    Ok(())
                },
                |_, _| Ok(()),
                |_, _, _, _| panic!("the provider dial is already pending"),
            )
            .unwrap();
        assert!(sent.is_empty());

        runner
            .poll(
                &[(UNAUTHORIZED, [7; 16], provider.clone())],
                std::slice::from_ref(&provider),
                now_ms + 4,
                |connection_id, request_id, frame| {
                    sent.push((connection_id, request_id, frame));
                    Ok(())
                },
                |_, _| Ok(()),
                |_, _, _, _| panic!("the provider is already connected"),
            )
            .unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, [7; 16]);

        let WireFrame::Query(query) = &sent[0].2 else {
            panic!("expected structured query")
        };
        let task_id = TaskId(query.root_task_id);
        runner
            .handle_event(
                &AdmittedNetworkEvent::ControlResponse {
                    connection_id: [7; 16],
                    agent_id: UNAUTHORIZED,
                    request_id: sent[0].1,
                    response: response(query, now_ms + 4),
                },
                now_ms + 4,
            )
            .unwrap();
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
                agent_id: UNAUTHORIZED,
                peer_id,
                frame,
            }) if received == task_id
                && peer_id == provider
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
                &[],
                now_ms,
                |connection_id, request_id, frame| {
                    sent.push((connection_id, request_id, frame));
                    Ok(())
                },
                |_, _| Ok(()),
                |_, _, _, _| Ok(()),
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
        runner
            .handle_event(
                &AdmittedNetworkEvent::ControlResponse {
                    connection_id: [3; 16],
                    agent_id: CONTACT,
                    request_id: sent[0].1,
                    response: wrong,
                },
                now_ms,
            )
            .unwrap();
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
