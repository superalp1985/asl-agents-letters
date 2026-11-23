//! Explicit avatar pulls share the wire protocol, not the file download queue.
use std::{
    path::Path,
    thread,
    time::{Duration, Instant},
};

use asl_net::codec::{BulkOperation, BulkRequest, BulkStatus};
use asl_store::{Store, avatar_receipts::AvatarDownload, open_store};
use asl_types::{
    error::AslError,
    ids::{Hash32, Id128, PeerId},
    manifest::Manifest,
    protocol::{FetchPending, FetchRequest, WireFrame},
};

use super::{
    AdmittedNetworkEvent as Event, NetworkAdmissionStatus, NetworkCommand, Supervisor,
    TransferService,
};
use crate::{
    documents::MAX_AVATAR_BYTES,
    profile::fresh_id,
    transfer::{FETCH_TIMEOUT_MS, ReceivedBulk},
};

const POLL_MS: u64 = 1_000;
const MAX_FETCHES: u8 = 12;

pub(super) struct Receiver {
    store: Store,
    session: Option<Session>,
    next_poll: Instant,
    // Keep the slot even after cancellation until the previous Extractor exits.
    worker: Option<(Id128, thread::JoinHandle<Option<Vec<u8>>>)>,
}

struct Session {
    intent: AvatarDownload,
    connection: [u8; 16],
    peer: PeerId,
    attempts: u8,
    deadline: u64,
    phase: Phase,
}

enum Phase {
    Ready(u64),
    Fetch(Id128),
    Manifest {
        fetch: Id128,
        bulk: Id128,
        lease: Hash32,
    },
    Chunk {
        request: BulkRequest,
        manifest: Manifest,
    },
    Cleaning,
}

impl Session {
    fn outstanding(&self) -> Option<Id128> {
        match &self.phase {
            Phase::Fetch(id) | Phase::Manifest { bulk: id, .. } => Some(*id),
            Phase::Chunk { request, .. } => Some(request.request_id),
            _ => None,
        }
    }

    fn forget(&self, transfers: &mut TransferService) {
        match &self.phase {
            Phase::Fetch(id) => {
                transfers.fail_control_request(self.connection, self.intent.owner, &self.peer, id.0)
            }
            Phase::Manifest { bulk, .. } => transfers.cancel_bulk_request(bulk.0),
            Phase::Chunk { request, .. } => transfers.cancel_bulk_request(request.request_id.0),
            _ => {}
        }
    }

    fn admitted(&self, core: &mut Supervisor, now: u64) -> bool {
        core.network_admission_status == NetworkAdmissionStatus::Active
            && core.net.is_running()
            && core
                .admission
                .as_mut()
                .and_then(|admission| admission.admitted_peer_identity(self.connection, now).ok())
                .is_some_and(|(owner, peer)| owner == self.intent.owner && peer == self.peer)
    }

    fn retry(&mut self, pending: &FetchPending, now: u64) -> bool {
        let at = pending.retry_at_ms.max(now.saturating_add(POLL_MS));
        let until = self.intent.expires_at_ms.min(pending.expires_at_ms);
        if pending.content_id != self.intent.content || self.attempts >= MAX_FETCHES || at >= until
        {
            return false;
        }
        self.phase = Phase::Ready(at);
        self.deadline = until;
        true
    }

    fn owns(&self, event: &Event) -> bool {
        let Some(expected) = self.outstanding() else {
            return false;
        };
        let protocol = if matches!(self.phase, Phase::Fetch(_)) {
            super::NetworkProtocol::Control
        } else {
            super::NetworkProtocol::Bulk
        };
        match event {
            Event::ControlResponse {
                connection_id,
                agent_id,
                request_id,
                ..
            } => {
                matches!(self.phase, Phase::Fetch(_))
                    && *connection_id == self.connection
                    && *agent_id == self.intent.owner
                    && *request_id == expected.0
            }
            Event::BulkResponse {
                connection_id,
                agent_id,
                peer_id,
                request_id,
                ..
            } => {
                protocol == super::NetworkProtocol::Bulk
                    && *connection_id == self.connection
                    && *agent_id == self.intent.owner
                    && *peer_id == self.peer
                    && *request_id == expected.0
            }
            Event::RequestFailed {
                connection_id,
                agent_id,
                peer_id,
                request_id,
                protocol: failed_protocol,
                ..
            } => {
                protocol == *failed_protocol
                    && *connection_id == self.connection
                    && *agent_id == self.intent.owner
                    && *peer_id == self.peer
                    && *request_id == expected.0
            }
            _ => false,
        }
    }
}

impl Receiver {
    pub(super) fn open(database: &Path) -> Result<Self, AslError> {
        Ok(Self {
            store: open_store(database)?,
            session: None,
            next_poll: Instant::now(),
            worker: None,
        })
    }

    fn stop(&mut self, transfers: &mut TransferService, now: u64) -> Result<(), AslError> {
        if let Some(session) = self.session.take() {
            session.forget(transfers);
            self.store
                .finish_avatar_download(&session.intent, None, now)?;
        }
        Ok(())
    }

    pub(super) fn poll(
        &mut self,
        core: &mut Supervisor,
        transfers: &mut TransferService,
        now: u64,
    ) -> Result<(), AslError> {
        let tick = Instant::now();
        if tick < self.next_poll {
            return Ok(());
        }
        self.next_poll = tick + Duration::from_millis(POLL_MS);
        let pending = self.store.pending_avatar_download(now)?;
        if self.session.as_ref().is_some_and(|s| {
            pending.as_ref() != Some(&s.intent) || now >= s.deadline || !s.admitted(core, now)
        }) {
            self.stop(transfers, now)?;
            return Ok(());
        }
        if self
            .worker
            .as_ref()
            .is_some_and(|(_, worker)| worker.is_finished())
        {
            let (id, worker) = self.worker.take().expect("finished worker");
            let bytes = worker.join().ok().flatten();
            if let Some(session) = self
                .session
                .as_ref()
                .filter(|s| s.intent.id == id && matches!(s.phase, Phase::Cleaning))
            {
                self.store
                    .finish_avatar_download(&session.intent, bytes.as_deref(), now)?;
                self.session = None;
            }
            return Ok(());
        }
        if self.session.is_none() && self.worker.is_none() {
            let Some(intent) = pending.filter(|_| {
                core.net.is_running()
                    && core.network_admission_status == NetworkAdmissionStatus::Active
            }) else {
                return Ok(());
            };
            let Some((_, connection, peer)) = core.admission.as_ref().and_then(|admission| {
                admission
                    .admitted_connections(now)
                    .into_iter()
                    .find(|(owner, _, _)| *owner == intent.owner)
            }) else {
                return Ok(());
            };
            self.session = Some(Session {
                deadline: intent.expires_at_ms,
                intent,
                connection,
                peer,
                attempts: 0,
                phase: Phase::Ready(now),
            });
        }
        let Some(session) = self.session.as_mut() else {
            return Ok(());
        };
        if matches!(session.phase, Phase::Ready(at) if at <= now) {
            let id = Id128(fresh_id()?);
            let command = NetworkCommand::SendControl {
                connection_id: session.connection,
                request_id: id.0,
                request: WireFrame::FetchRequest(FetchRequest {
                    message_id: id,
                    root_task_id: session.intent.id,
                    content_id: session.intent.content,
                }),
            };
            if send(
                &mut self.store,
                &session.intent,
                core,
                transfers,
                command,
                now,
            ) {
                session.phase = Phase::Fetch(id);
                session.attempts += 1;
                session.deadline = session.deadline.min(now.saturating_add(FETCH_TIMEOUT_MS));
            } else {
                self.stop(transfers, now)?;
            }
        }
        Ok(())
    }

    pub(super) fn route(
        &mut self,
        core: &mut Supervisor,
        transfers: &mut TransferService,
        event: Event,
        now: u64,
    ) -> Result<Option<Event>, AslError> {
        let Some(s) = self.session.as_ref() else {
            return Ok(Some(event));
        };
        if matches!(&event, Event::PeerDisconnected { connection_id, .. } if *connection_id == s.connection)
        {
            self.stop(transfers, now)?;
            return Ok(Some(event)); // ordinary downloads must also see the disconnect
        }
        if !s.owns(&event) {
            return Ok(Some(event));
        }
        if now >= s.deadline
            || self.store.pending_avatar_download(now)?.as_ref() != Some(&s.intent)
            || !s.admitted(core, now)
        {
            self.stop(transfers, now)?;
            return Ok(None);
        }
        if !self.advance(core, transfers, event, now)? {
            self.stop(transfers, now)?;
        }
        Ok(None)
    }

    fn advance(
        &mut self,
        core: &mut Supervisor,
        transfers: &mut TransferService,
        event: Event,
        now: u64,
    ) -> Result<bool, AslError> {
        let s = self.session.as_mut().expect("routed session");
        match (&s.phase, event) {
            (
                Phase::Fetch(_),
                Event::ControlResponse {
                    response: WireFrame::FetchPending(pending),
                    ..
                },
            ) => {
                s.forget(transfers);
                Ok(s.retry(&pending, now))
            }
            (
                Phase::Fetch(id),
                Event::ControlResponse {
                    response: WireFrame::FetchGrant(grant),
                    ..
                },
            ) if grant.content_id == s.intent.content
                && (1..=MAX_AVATAR_BYTES as u64).contains(&grant.file_size) =>
            {
                let Some(admission) = core.admission.as_mut() else {
                    return Ok(false);
                };
                let Some(source) = admission.direct_requester(s.connection, s.intent.owner) else {
                    return Ok(false);
                };
                let Ok(Some((bulk, command))) = transfers.prepare_manifest_request(
                    admission,
                    s.connection,
                    &source,
                    id.0,
                    &grant,
                    now,
                ) else {
                    return Ok(false);
                };
                s.phase = Phase::Manifest {
                    fetch: *id,
                    bulk,
                    lease: grant.lease_id,
                };
                s.deadline = s
                    .intent
                    .expires_at_ms
                    .min(grant.expires_at_ms)
                    .min(now.saturating_add(FETCH_TIMEOUT_MS));
                let message = command.into_ipc()?;
                self.store
                    .with_avatar_download(&s.intent, now, || core.net.try_send(&message))
            }
            (
                _,
                Event::BulkResponse {
                    request_id,
                    response,
                    ..
                },
            ) => {
                let Some(matched) = transfers.accept_bulk_response(
                    s.connection,
                    s.intent.owner,
                    &s.peer,
                    request_id,
                    response,
                    now,
                ) else {
                    return Ok(false);
                };
                match (&s.phase, matched) {
                    (Phase::Manifest { fetch, lease, .. }, ReceivedBulk::Manifest(m))
                        if m.fetch_request_id == *fetch
                            && m.root_task_id == s.intent.id
                            && m.content_id == s.intent.content
                            && m.lease_id == *lease
                            && m.expires_at_ms > now
                            && m.connection_id == s.connection
                            && m.agent_id == s.intent.owner
                            && m.peer_id == s.peer
                            && m.manifest.chunk_hashes.len() == 1
                            && (1..=MAX_AVATAR_BYTES as u64).contains(&m.manifest.file_size) =>
                    {
                        let request = BulkRequest {
                            operation: BulkOperation::Chunk,
                            request_id: Id128(fresh_id()?),
                            content_id: m.content_id,
                            lease_id: m.lease_id,
                            chunk_index: 0,
                        };
                        let command = NetworkCommand::SendBulk {
                            connection_id: s.connection,
                            request: request.clone(),
                        };
                        if !send(&mut self.store, &s.intent, core, transfers, command, now) {
                            return Ok(false);
                        }
                        s.phase = Phase::Chunk {
                            request,
                            manifest: m.manifest.clone(),
                        };
                        s.deadline = s
                            .intent
                            .expires_at_ms
                            .min(m.expires_at_ms)
                            .min(now.saturating_add(FETCH_TIMEOUT_MS));
                        Ok(true)
                    }
                    (Phase::Chunk { request, manifest }, ReceivedBulk::Raw(chunk))
                        if chunk.request == *request
                            && chunk.response.status == BulkStatus::Success
                            && chunk.response.payload.len() as u64 == manifest.file_size
                            && self.worker.is_none() =>
                    {
                        let manifest = manifest.clone();
                        let content = s.intent.content;
                        let bytes = chunk.response.payload;
                        let launcher = core.launcher.clone();
                        let worker = thread::Builder::new()
                            .name("asl-avatar-receive".into())
                            .spawn(move || {
                                crate::avatar::sanitize_verified(
                                    &launcher, content, &manifest, &bytes,
                                )
                                .ok()
                            })?;
                        self.worker = Some((s.intent.id, worker));
                        s.phase = Phase::Cleaning;
                        Ok(true)
                    }
                    _ => Ok(false),
                }
            }
            _ => Ok(false),
        }
    }
}

fn send(
    store: &mut Store,
    intent: &AvatarDownload,
    core: &mut Supervisor,
    transfers: &mut TransferService,
    command: NetworkCommand,
    now: u64,
) -> bool {
    core.send_tracked_with(transfers, command, now, |net, message| {
        store.with_avatar_download(intent, now, || net.try_send(message))
    })
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        identity::DeviceIdentity,
        ipc::{NetworkErrorCode, NetworkProtocol},
    };
    use asl_types::ids::AgentId;

    fn session() -> Session {
        Session {
            intent: AvatarDownload {
                owner: AgentId([3; 32]),
                content: Hash32([4; 32]),
                id: Id128([5; 16]),
                expires_at_ms: 20_000,
            },
            connection: [1; 16],
            peer: DeviceIdentity::generate().unwrap().peer_id(),
            attempts: 1,
            deadline: 10_000,
            phase: Phase::Fetch(Id128([6; 16])),
        }
    }

    #[test]
    fn avatar_reply_matches_device_connection_owner_operation_and_channel() {
        let s = session();
        let failed = |peer: PeerId, conn, owner, request, protocol| Event::RequestFailed {
            connection_id: conn,
            agent_id: owner,
            peer_id: peer,
            request_id: request,
            protocol,
            code: NetworkErrorCode::Capacity,
        };
        let id = [6; 16];
        let control = NetworkProtocol::Control;
        let peer = s.peer.clone();
        let owner = s.intent.owner;
        assert!(s.owns(&failed(peer.clone(), s.connection, owner, id, control)));
        for wrong in [
            failed(
                DeviceIdentity::generate().unwrap().peer_id(),
                s.connection,
                owner,
                id,
                control,
            ),
            failed(peer.clone(), [2; 16], owner, id, control),
            failed(peer.clone(), s.connection, AgentId([7; 32]), id, control),
            failed(peer.clone(), s.connection, owner, [8; 16], control),
            failed(peer, s.connection, owner, id, NetworkProtocol::Bulk),
        ] {
            assert!(!s.owns(&wrong));
        }
    }

    #[test]
    fn avatar_pending_is_paced_and_cannot_renew_local_authority() {
        let mut s = session();
        let mut pending = FetchPending {
            message_id: Id128([7; 16]),
            content_id: s.intent.content,
            retry_at_ms: 5_000,
            expires_at_ms: 60_000,
        };
        assert!(s.retry(&pending, 100));
        assert!(matches!(s.phase, Phase::Ready(5_000)));
        assert_eq!(s.deadline, 20_000);
        pending.retry_at_ms = 100;
        assert!(s.retry(&pending, 500));
        assert!(matches!(s.phase, Phase::Ready(1_500)));
        assert!(!s.retry(&pending, 19_500));
        pending.content_id = Hash32([0; 32]);
        assert!(!s.retry(&pending, 100));
        pending.content_id = s.intent.content;
        s.attempts = MAX_FETCHES;
        assert!(!s.retry(&pending, 100));
    }
}
