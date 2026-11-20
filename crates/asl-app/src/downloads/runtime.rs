//! Bounded, in-process handoff between the trusted caller, Core and the disk owner.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        Arc, OnceLock,
        mpsc::{Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError, sync_channel},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use asl_net::{codec::BulkRequest, transport::REQUEST_TIMEOUT};
use asl_policy::WriteGrant;
use asl_transfer::scheduler::MAX_ACTIVE_SOURCES;
use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId},
    protocol::FetchRequest,
    task::TransferId,
};

use super::{DownloadInfo, LocalDownloads};
use crate::{
    ipc::NetworkProtocol, paths::AppPaths, profile::AdmittedNetworkEvent, supervisor::unix_time_ms,
};

mod job;

const LOCAL_QUEUE: usize = 8;
const NETWORK_EVENTS: usize = 32;
const TRACKED_REQUESTS: usize = 16;
const WORKER_POLL: Duration = Duration::from_millis(100);
const BULK_TIMEOUT_MS: u64 = REQUEST_TIMEOUT.as_millis() as u64;
const FETCH_TIMEOUT_MS: u64 = 2 * BULK_TIMEOUT_MS + 1_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DownloadSource {
    pub agent_id: AgentId,
    pub peer_id: PeerId,
}

#[derive(Debug)]
pub struct DownloadSelection {
    pub content_id: Hash32,
    pub inbox_grant: Id128,
    pub filename: String,
    pub sources: Vec<DownloadSource>,
}

#[derive(Debug)]
pub enum DownloadJob {
    Fetch(DownloadSelection),
    Resume {
        transfer_id: TransferId,
        sources: Vec<DownloadSource>,
    },
}

#[derive(Debug)]
pub enum DownloadEvent {
    AwaitingApproval(Id128),
    Started(DownloadInfo),
    Completed(DownloadInfo),
    Failed(AslError),
}

pub struct DownloadTicket(Receiver<DownloadEvent>);
pub struct DownloadPort {
    jobs: SyncSender<QueuedJob>,
    initialization_error: Arc<OnceLock<AslError>>,
}
pub struct DownloadRuntime {
    jobs: Receiver<QueuedJob>,
    initialization_error: Arc<OnceLock<AslError>>,
}

struct QueuedJob {
    job: DownloadJob,
    events: SyncSender<DownloadEvent>,
}

impl DownloadTicket {
    pub fn try_recv(&self) -> Result<Option<DownloadEvent>, AslError> {
        recv(&self.0)
    }
}

impl DownloadPort {
    /// Reports a failed asynchronous initialization, including owner contention.
    pub fn initialization_error(&self) -> Option<&AslError> {
        self.initialization_error.get()
    }

    /// Only for trusted in-process callers. The application chooses the
    /// destination and sources; this is not an Offer or raw model-output API.
    pub fn submit(&self, job: DownloadJob) -> Result<DownloadTicket, AslError> {
        let sources = match &job {
            DownloadJob::Fetch(selection) => {
                WriteGrant::filename(Path::new(&selection.filename))?;
                &selection.sources
            }
            DownloadJob::Resume { sources, .. } => sources,
        };
        if sources.is_empty()
            || sources.len() > MAX_ACTIVE_SOURCES
            || sources.iter().enumerate().any(|(index, source)| {
                sources[..index]
                    .iter()
                    .any(|other| other.peer_id == source.peer_id)
            })
        {
            return Err(AslError::InvalidMessage);
        }
        // A job reports at most one consent, one start and one terminal outcome.
        let (events, receiver) = sync_channel(3);
        send(&self.jobs, QueuedJob { job, events })?;
        Ok(DownloadTicket(receiver))
    }
}

pub fn download_channel() -> (DownloadPort, DownloadRuntime) {
    let (port, runtime) = sync_channel(LOCAL_QUEUE);
    let initialization_error = Arc::new(OnceLock::new());
    (
        DownloadPort {
            jobs: port,
            initialization_error: Arc::clone(&initialization_error),
        },
        DownloadRuntime {
            jobs: runtime,
            initialization_error,
        },
    )
}

fn send<T>(sender: &SyncSender<T>, value: T) -> Result<(), AslError> {
    sender.try_send(value).map_err(|err| match err {
        TrySendError::Full(_) => AslError::QuotaExceeded,
        TrySendError::Disconnected(_) => AslError::SandboxUnavailable,
    })
}

fn recv<T>(receiver: &Receiver<T>) -> Result<Option<T>, AslError> {
    match receiver.try_recv() {
        Ok(value) => Ok(Some(value)),
        Err(TryRecvError::Empty) => Ok(None),
        Err(TryRecvError::Disconnected) => Err(AslError::SandboxUnavailable),
    }
}

pub(crate) enum WorkerRequest {
    Fetch {
        source: DownloadSource,
        request: FetchRequest,
    },
    Bulk {
        source: DownloadSource,
        connection_id: [u8; 16],
        request: BulkRequest,
    },
}

type Receipt = Result<Option<[u8; 16]>, AslError>;
type Outbound = (WorkerRequest, SyncSender<Receipt>);
type RequestKey = (Id128, bool); // true for Fetch, false for bulk

pub(crate) struct DownloadBridge {
    // Disconnect both directions before joining: the disk owner might be
    // waiting for Core to accept an outbound request.
    ingress: Option<SyncSender<AdmittedNetworkEvent>>,
    outgoing: Option<Receiver<Outbound>>,
    worker: Option<JoinHandle<()>>,
    tracked: HashMap<RequestKey, ([u8; 16], u64)>,
    recent_sources: HashMap<[u8; 16], u64>,
}

impl DownloadBridge {
    pub(crate) fn spawn(home: PathBuf, runtime: DownloadRuntime) -> Result<Self, AslError> {
        let (ingress, network) = sync_channel(NETWORK_EVENTS);
        let (outbound, outgoing) = sync_channel(1);
        let worker = thread::Builder::new()
            .name("asl-downloads".into())
            .spawn(move || {
                let local =
                    match AppPaths::open(&home).and_then(|paths| LocalDownloads::open(&paths)) {
                        Ok(local) => local,
                        Err(error) => {
                            eprintln!("ASL download worker could not start: {error}");
                            let _ = runtime.initialization_error.set(error);
                            return;
                        }
                    };
                if let Err(error) = run(local, &runtime, network, outbound) {
                    eprintln!("ASL download worker stopped: {error}");
                }
            })?;
        Ok(Self {
            ingress: Some(ingress),
            outgoing: Some(outgoing),
            worker: Some(worker),
            tracked: HashMap::new(),
            recent_sources: HashMap::new(),
        })
    }

    pub(crate) fn poll(&mut self, now: u64, mut send: impl FnMut(WorkerRequest) -> Receipt) {
        self.tracked.retain(|_, (_, deadline)| *deadline > now);
        self.recent_sources.retain(|_, expires| *expires > now);
        let Some(Ok((request, reply))) = self.outgoing.as_ref().map(Receiver::try_recv) else {
            return;
        };
        let (key, timeout) = match &request {
            WorkerRequest::Fetch { request, .. } => ((request.message_id, true), FETCH_TIMEOUT_MS),
            WorkerRequest::Bulk { request, .. } => ((request.request_id, false), BULK_TIMEOUT_MS),
        };
        let result = if self.tracked.len() >= TRACKED_REQUESTS || self.tracked.contains_key(&key) {
            Ok(None)
        } else {
            send(request)
        };
        if let Ok(Some(connection)) = result {
            self.tracked
                .insert(key, (connection, now.saturating_add(timeout)));
        }
        let _ = reply.try_send(result);
    }

    pub(crate) fn forward(&mut self, event: &AdmittedNetworkEvent) {
        use AdmittedNetworkEvent::*;
        let (key, connection) = match event {
            FetchManifestReceived(manifest) => {
                ((manifest.fetch_request_id, true), manifest.connection_id)
            }
            BulkTransferResponse(response) => {
                ((response.request.request_id, false), response.connection_id)
            }
            ControlResponse {
                request_id,
                connection_id,
                ..
            } => ((Id128(*request_id), true), *connection_id),
            RequestFailed {
                request_id,
                connection_id,
                protocol,
                ..
            } => {
                let fetch = match protocol {
                    NetworkProtocol::Control => true,
                    NetworkProtocol::Bulk => false,
                    _ => return,
                };
                ((Id128(*request_id), fetch), *connection_id)
            }
            PeerDisconnected { connection_id, .. } => {
                let before = self.tracked.len();
                self.tracked
                    .retain(|_, (connection, _)| connection != connection_id);
                let leased = self.recent_sources.remove(connection_id).is_some();
                if leased || self.tracked.len() != before {
                    self.deliver(event);
                }
                return;
            }
            _ => return,
        };
        if self
            .tracked
            .get(&key)
            .is_some_and(|(expected, _)| *expected == connection)
        {
            self.tracked.remove(&key);
            if let FetchManifestReceived(manifest) = event
                && (self.recent_sources.contains_key(&connection)
                    || self.recent_sources.len() < TRACKED_REQUESTS)
            {
                self.recent_sources
                    .insert(connection, manifest.expires_at_ms);
            }
            self.deliver(event);
        }
    }

    fn deliver(&self, event: &AdmittedNetworkEvent) {
        if let Some(ingress) = &self.ingress {
            // When disk is stalled, the request timeout reclaims undelivered
            // work. Never make Core wait for storage to accept a payload.
            let _ = ingress.try_send(event.clone());
        }
    }
}

impl Drop for DownloadBridge {
    fn drop(&mut self) {
        self.outgoing.take();
        self.ingress.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn exchange(outbound: &SyncSender<Outbound>, request: WorkerRequest) -> Receipt {
    let (reply, receive) = sync_channel(1);
    outbound
        .send((request, reply))
        .map_err(|_| AslError::SandboxUnavailable)?;
    receive.recv().map_err(|_| AslError::SandboxUnavailable)?
}

fn run(
    mut local: LocalDownloads,
    runtime: &DownloadRuntime,
    network: Receiver<AdmittedNetworkEvent>,
    outbound: SyncSender<Outbound>,
) -> Result<(), AslError> {
    let mut active: Option<job::ActiveJob> = None;
    let send = |request| exchange(&outbound, request);
    loop {
        let now = unix_time_ms()?;
        if active.is_none()
            && let Ok(Some(queued)) = recv(&runtime.jobs)
        {
            active = job::ActiveJob::start(queued, &mut local, now);
        }
        let event = match network.recv_timeout(WORKER_POLL) {
            Ok(event) => Some(event),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => return Ok(()),
        };
        let now = unix_time_ms()?;
        let routed = event
            .as_ref()
            .map_or(Ok(()), |event| local.handle_chunk_event(event));
        if let Some(job) = &mut active {
            let result = routed.and_then(|()| job.step(&mut local, event.as_ref(), now, &send));
            if job.report_terminal(result) {
                local.pause_chunks()?;
                active = None;
            }
        } else {
            routed?;
            local.poll_chunks(|_| Ok(false))?;
        }
    }
}

#[cfg(all(test, windows))]
mod loopback;
#[cfg(all(test, windows))]
mod tests;
