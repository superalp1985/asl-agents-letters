use asl_store::transfers::DOWNLOAD_IDLE_MS;
use asl_transfer::bulk::MAX_INLINE_BYTES;
use asl_transfer::scheduler::MAX_ACTIVE_SOURCES;
use asl_types::protocol::WireFrame;

use super::{
    AdmittedNetworkEvent, AslError, DownloadEvent, DownloadInfo, DownloadJob, DownloadSource,
    FETCH_TIMEOUT_MS, FetchRequest, Hash32, Id128, LocalDownloads, NetworkProtocol, QueuedJob,
    Receipt, SyncSender, TransferId, WorkerRequest,
};
use crate::{
    VerifiedFetchManifest,
    downloads::{DownloadStart, InlineDownload},
    ipc::NetworkErrorCode,
    network::NetworkCommand,
};

const RETRY_MS: [u64; 3] = [1_000, 5_000, 30_000];
const NO_CONNECTION_POLL_MS: u64 = 1_000;
const APPROVAL_POLL_MS: u64 = 1_000;

pub(super) struct ActiveJob {
    root: Id128,
    content: Hash32,
    sources: Vec<Source>,
    group: Option<asl_store::transfers::GroupTransferBinding>,
    group_route: Option<(Hash32, Hash32)>,
    state: State,
    events: SyncSender<DownloadEvent>,
    context_ref: Option<asl_types::protocol::SemanticContextRef>,
    host_resume: Option<(TransferId, [u8; 32])>,
}

enum State {
    Selecting {
        grant: Id128,
        filename: String,
        deadline: u64,
        approval: Option<Approval>,
    },
    Chunks,
    Inline {
        transfer: TransferId,
        pending: Option<(usize, InlineDownload, u64)>,
    },
}

struct Approval {
    id: Id128,
    approved: bool,
    next_poll: u64,
}

struct Source {
    identity: DownloadSource,
    registered: bool,
    fetch: Option<PendingFetch>,
    next_fetch: u64,
    failures: usize,
    inline_failures: usize,
    approval_wait_until: Option<u64>,
    manifest: Option<VerifiedFetchManifest>,
}

struct PendingFetch {
    id: Id128,
    connection: [u8; 16],
    deadline: u64,
}

impl ActiveJob {
    pub(super) fn start(queued: QueuedJob, local: &mut LocalDownloads, now: u64) -> Option<Self> {
        let result = (|| {
            let (job, host_resume) = match queued.job {
                DownloadJob::ResumeForHost {
                    transfer_id,
                    subject,
                } => {
                    let selected = local.broker.recovery_sources(
                        &transfer_id,
                        &subject,
                        (MAX_ACTIVE_SOURCES + 1) as i64,
                    )?;
                    let Some(selected) = selected else {
                        let info = local.broker.info(&transfer_id)?;
                        let _ = queued.events.try_send(DownloadEvent::Completed(info));
                        return Ok(None);
                    };
                    if selected.is_empty() || selected.len() > MAX_ACTIVE_SOURCES {
                        return Err(AslError::PolicyDenied);
                    }
                    let sources = selected
                        .into_iter()
                        .map(|(agent_id, peer_id)| DownloadSource { agent_id, peer_id })
                        .collect();
                    let binding = (transfer_id.clone(), subject);
                    (
                        DownloadJob::Resume {
                            transfer_id,
                            sources,
                        },
                        Some(binding),
                    )
                }
                job => (job, None),
            };
            let resume_schedule = match &job {
                DownloadJob::Resume { transfer_id, .. } => {
                    Some(local.broker.schedule(transfer_id)?)
                }
                DownloadJob::Fetch(_) => None,
                DownloadJob::ResumeForHost { .. } => unreachable!("resolved host job"),
            };
            let group = match &job {
                DownloadJob::Fetch(selection) => selection.group.clone(),
                DownloadJob::Resume { .. } => resume_schedule
                    .as_ref()
                    .and_then(|schedule| schedule.group.clone()),
                DownloadJob::ResumeForHost { .. } => unreachable!("resolved host job"),
            };
            let group_route = match &job {
                DownloadJob::Fetch(selection) => selection
                    .group_logical_id
                    .zip(selection.group_source_room_id),
                DownloadJob::Resume { .. } | DownloadJob::ResumeForHost { .. } => None,
            };
            let selected = match &job {
                DownloadJob::Fetch(selection) => {
                    local.broker.ensure_retry_allowed(
                        selection.content_id,
                        i64::try_from(now).map_err(|_| AslError::InvalidPolicyState)?,
                    )?;
                    &selection.sources
                }
                DownloadJob::Resume { sources, .. } => sources,
                DownloadJob::ResumeForHost { .. } => unreachable!("resolved host job"),
            };
            let sources = selected
                .iter()
                .cloned()
                .map(|source| {
                    let registered = local.broker.source_is_current(
                        source.agent_id,
                        &source.peer_id,
                        group.as_ref(),
                    )?;
                    Ok(Source::new(source, registered))
                })
                .collect::<Result<_, AslError>>()?;
            let context_ref = match &job {
                DownloadJob::Fetch(selection) => selection.context_ref,
                DownloadJob::Resume { .. } | DownloadJob::ResumeForHost { .. } => None,
            };
            let (content, state) = match job {
                DownloadJob::Fetch(selection) => (
                    selection.content_id,
                    State::Selecting {
                        grant: selection.inbox_grant,
                        filename: selection.filename,
                        deadline: now.saturating_add(DOWNLOAD_IDLE_MS as u64),
                        approval: None,
                    },
                ),
                DownloadJob::Resume {
                    transfer_id,
                    sources,
                } => {
                    let info = local.broker.info(&transfer_id)?;
                    if info.state == "complete" {
                        let _ = queued.events.try_send(DownloadEvent::Completed(info));
                        return Ok(None);
                    }
                    let schedule = resume_schedule.ok_or(AslError::InvalidPolicyState)?;
                    if sources
                        .iter()
                        .any(|source| !schedule.sources.contains(&source.peer_id))
                    {
                        return Err(AslError::PolicyDenied);
                    }
                    let content = info.content_id;
                    let state = begin(local, &queued.events, info)?;
                    (content, state)
                }
                DownloadJob::ResumeForHost { .. } => unreachable!("resolved host job"),
            };
            Ok(Some(Self {
                root: Id128(rand::random()),
                content,
                sources,
                group,
                group_route,
                state,
                events: queued.events.clone(),
                context_ref,
                host_resume,
            }))
        })();
        match result {
            Ok(job) => job,
            Err(error) => {
                let _ = queued.events.try_send(DownloadEvent::Failed(error));
                None
            }
        }
    }

    pub(super) fn check_host_resume(&self, local: &LocalDownloads) -> Result<(), AslError> {
        if let Some((transfer, subject)) = &self.host_resume {
            local.broker.check_recovery_download(transfer, subject)?;
            if let Some(group) = &self.group {
                for source in &self.sources {
                    if !local.broker.source_is_current(
                        source.identity.agent_id,
                        &source.identity.peer_id,
                        Some(group),
                    )? {
                        return Err(AslError::PolicyDenied);
                    }
                }
            }
        }
        Ok(())
    }

    pub(super) fn step(
        &mut self,
        local: &mut LocalDownloads,
        event: Option<&AdmittedNetworkEvent>,
        now: u64,
        send: &impl Fn(WorkerRequest) -> Receipt,
    ) -> Result<Option<DownloadInfo>, AslError> {
        if let Some(AdmittedNetworkEvent::FetchManifestCorrupt(manifest)) = event
            && manifest.root_task_id == self.root
            && manifest.content_id == self.content
            && manifest.expires_at_ms > now
            && !matches!(&self.state, State::Selecting { deadline, .. } if *deadline <= now)
            && self.sources.iter().any(|source| {
                source.identity.agent_id == manifest.agent_id
                    && source.identity.peer_id == manifest.peer_id
                    && source.fetch.as_ref().is_some_and(|fetch| {
                        fetch.id == manifest.fetch_request_id
                            && fetch.connection == manifest.connection_id
                            && fetch.deadline > now
                    })
            })
        {
            local.broker.record_corrupt_manifest(
                self.content,
                i64::try_from(now).map_err(|_| AslError::InvalidPolicyState)?,
            )?;
            return Err(AslError::InvalidMessage);
        }
        for source in &mut self.sources {
            source.observe(self.root, self.content, event, now);
        }
        let group = self.group.clone();
        if let State::Selecting {
            grant,
            filename,
            deadline,
            approval,
        } = &mut self.state
        {
            if *deadline <= now {
                return Err(AslError::ExpiredMessage);
            }
            local.broker.ensure_active_inbox(*grant)?;
            if let Some(approval) = approval
                && now >= approval.next_poll
            {
                let consents = local.download_consents()?;
                let decision = consents
                    .iter()
                    .find(|decision| decision.approval_id == approval.id)
                    .ok_or(AslError::PolicyDenied)?;
                *deadline =
                    u64::try_from(decision.expires_at_ms).map_err(|_| AslError::InvalidDatabase)?;
                approval.approved = decision.approved;
                approval.next_poll = now.saturating_add(APPROVAL_POLL_MS);
            }
            if approval.as_ref().is_some_and(|a| !a.approved) {
                local.poll_chunks(|_| Ok(false))?;
                return Ok(None);
            }
            for source in &mut self.sources {
                source.ensure_manifest(
                    self.root,
                    self.content,
                    group.as_ref(),
                    self.group_route,
                    now,
                    send,
                )?;
            }
            let manifest = self
                .sources
                .iter()
                .find_map(|source| source.live_manifest(now));
            let all_registered = self.sources.iter().all(|source| source.registered);
            let Some(manifest) = manifest.filter(|_| all_registered) else {
                if self.sources.iter().all(|source| source.exhausted(now))
                    || self
                        .sources
                        .iter()
                        .any(|source| !source.registered && source.exhausted(now))
                {
                    return Err(AslError::NotFound);
                }
                local.poll_chunks(|_| Ok(false))?;
                return Ok(None);
            };
            let sources: Vec<_> = self
                .sources
                .iter()
                .map(|source| source.identity.clone())
                .collect();
            let info = match local.request_selected_download(
                manifest,
                &sources,
                *grant,
                filename,
                approval.as_ref().map(|a| a.id),
                group.clone(),
            ) {
                Err(AslError::ExpiredMessage) => return Ok(None),
                Ok(DownloadStart::Started(info)) => info,
                Ok(DownloadStart::Pending {
                    approval_id,
                    transfer_id,
                }) => {
                    *approval = Some(Approval {
                        id: approval_id,
                        approved: false,
                        next_poll: now,
                    });
                    // The persisted consent window starts when it is
                    // created, not when manifest discovery began.
                    *deadline = now.saturating_add(DOWNLOAD_IDLE_MS as u64);
                    let _ = self.events.try_send(DownloadEvent::AwaitingApproval {
                        approval_id,
                        transfer_id,
                    });
                    return Ok(None);
                }
                Err(error) => return Err(error),
            };
            let state = begin(local, &self.events, info)?;
            if matches!(state, State::Chunks) {
                for manifest in self
                    .sources
                    .iter()
                    .filter_map(|source| source.live_manifest(now))
                {
                    match local.attach_chunk_source(manifest) {
                        Ok(()) | Err(AslError::ExpiredMessage) => {}
                        Err(error) => return Err(error),
                    }
                }
            }
            self.state = state;
        }

        match &mut self.state {
            State::Chunks => {
                if local.chunks.is_none() {
                    return Err(AslError::ExpiredMessage);
                }
                for source in &mut self.sources {
                    if local.chunk_source(&source.identity.peer_id, now) != Some(false) {
                        continue;
                    }
                    if let Some(manifest) = source.live_manifest(now)
                        && matches!(event, Some(AdmittedNetworkEvent::FetchManifestReceived(new))
                            if new.fetch_request_id == manifest.fetch_request_id)
                    {
                        match local.attach_chunk_source(manifest) {
                            Ok(()) | Err(AslError::ExpiredMessage) => {}
                            Err(error) => return Err(error),
                        }
                    } else {
                        source.manifest = None;
                        source.ensure_manifest(
                            self.root,
                            self.content,
                            group.as_ref(),
                            self.group_route,
                            now,
                            send,
                        )?;
                    }
                }
                let completed = local.poll_chunks(|command| {
                    send_bulk(send, command, |connection| {
                        self.sources.iter().find_map(|source| {
                            source
                                .live_manifest(now)
                                .filter(|manifest| manifest.connection_id == connection)
                                .map(|_| source.identity.clone())
                        })
                    })
                })?;
                if completed.is_none() && local.chunks.is_none() {
                    return Err(AslError::ExpiredMessage);
                }
                Ok(completed)
            }
            State::Inline { transfer, pending } => {
                if let Some((index, inline, receipt_deadline)) = pending {
                    if let Some(AdmittedNetworkEvent::BulkTransferResponse(response)) = event {
                        match inline.receive(local, response) {
                            Ok(Some(info)) => return Ok(Some(info)),
                            Ok(None) => {}
                            Err(AslError::NotFound | AslError::ExpiredMessage) => {
                                *receipt_deadline = now;
                            }
                            Err(error) => return Err(error),
                        }
                    }
                    let failed = event.filter(|event| inline.failed_by(event));
                    if failed.is_some() || now >= *receipt_deadline {
                        if !matches!(
                            failed,
                            Some(AdmittedNetworkEvent::RequestFailed {
                                code: NetworkErrorCode::Capacity,
                                ..
                            })
                        ) {
                            self.sources[*index].failed_inline(now);
                        }
                        *pending = None;
                    }
                }
                if let Some(info) = inline_tick(transfer, local, now)? {
                    return Ok(Some(info));
                }
                if pending.is_none() {
                    for (index, source) in self.sources.iter_mut().enumerate() {
                        if source.inline_failures > RETRY_MS.len() {
                            continue;
                        }
                        source.ensure_manifest(
                            self.root,
                            self.content,
                            group.as_ref(),
                            self.group_route,
                            now,
                            send,
                        )?;
                        if let Some(manifest) = source.live_manifest(now) {
                            let (inline, command) = match local.prepare_inline(transfer, manifest) {
                                Err(AslError::ExpiredMessage) => {
                                    source.manifest = None;
                                    continue;
                                }
                                result => result?,
                            };
                            match send_bulk(send, command, |_| Some(source.identity.clone())) {
                                Ok(true) => {
                                    *pending = Some((
                                        index,
                                        inline,
                                        now.saturating_add(super::BULK_TIMEOUT_MS),
                                    ));
                                    break;
                                }
                                Ok(false) => break,
                                Err(
                                    AslError::InvalidIdentity
                                    | AslError::InvalidDeviceCertificate
                                    | AslError::PolicyDenied
                                    | AslError::ExpiredMessage,
                                ) => {
                                    source.failed_inline(now);
                                }
                                Err(error) => return Err(error),
                            }
                        }
                    }
                }
                Ok(None)
            }
            State::Selecting { .. } => unreachable!("selection returns until started"),
        }
    }

    pub(super) fn report_terminal(
        &self,
        local: &mut LocalDownloads,
        result: Result<Option<DownloadInfo>, AslError>,
        now_ms: u64,
    ) -> bool {
        let event = match result {
            Ok(None) => return false,
            Ok(Some(info)) => {
                if let Some(reference) = self.context_ref {
                    let stored = i64::try_from(now_ms)
                        .ok()
                        .and_then(|now| {
                            local
                                .broker
                                .cache_downloaded_semantic_context(
                                    &info.transfer_id,
                                    reference,
                                    now,
                                )
                                .ok()
                        })
                        .unwrap_or(false);
                    let _ = self
                        .events
                        .try_send(DownloadEvent::ContextCandidate { reference, stored });
                }
                DownloadEvent::Completed(info)
            }
            Err(error) => DownloadEvent::Failed(error),
        };
        let _ = self.events.try_send(event);
        true
    }
}

fn begin(
    local: &mut LocalDownloads,
    events: &SyncSender<DownloadEvent>,
    info: DownloadInfo,
) -> Result<State, AslError> {
    let transfer = info.transfer_id.clone();
    let state = if info.file_size > MAX_INLINE_BYTES {
        local.resume_chunks(&transfer)?;
        State::Chunks
    } else {
        State::Inline {
            transfer,
            pending: None,
        }
    };
    let _ = events.try_send(DownloadEvent::Started(info));
    Ok(state)
}

fn inline_tick(
    transfer: &TransferId,
    local: &mut LocalDownloads,
    now: u64,
) -> Result<Option<DownloadInfo>, AslError> {
    let deadline = local.broker.expire_idle_download(
        transfer,
        i64::try_from(now).map_err(|_| AslError::InvalidPolicyState)?,
    )?;
    if deadline.is_none() {
        return Err(AslError::ExpiredMessage);
    }
    local.poll_chunks(|_| Ok(false))?;
    let info = local.broker.info(transfer)?;
    if info.file_size != 0 && info.durable_bytes == info.file_size {
        return local.broker.complete(transfer.clone()).map(Some);
    }
    Ok(None)
}

fn send_bulk(
    send: &impl Fn(WorkerRequest) -> Receipt,
    command: NetworkCommand,
    source_for: impl FnOnce([u8; 16]) -> Option<DownloadSource>,
) -> Result<bool, AslError> {
    let NetworkCommand::SendBulk {
        connection_id,
        request,
    } = command
    else {
        return Err(AslError::InvalidMessage);
    };
    send(WorkerRequest::Bulk {
        source: source_for(connection_id).ok_or(AslError::InvalidIdentity)?,
        connection_id,
        request,
    })
    .map(|receipt| receipt.is_some())
}

impl Source {
    fn new(identity: DownloadSource, registered: bool) -> Self {
        Self {
            identity,
            registered,
            fetch: None,
            next_fetch: 0,
            failures: 0,
            inline_failures: 0,
            approval_wait_until: None,
            manifest: None,
        }
    }

    fn live_manifest(&self, now: u64) -> Option<&VerifiedFetchManifest> {
        self.manifest
            .as_ref()
            .filter(|manifest| manifest.expires_at_ms > now)
    }

    fn exhausted(&self, now: u64) -> bool {
        self.approval_wait_until.is_some_and(|until| until <= now) || self.failures > RETRY_MS.len()
    }

    fn failed(&mut self, now: u64) {
        self.fetch = None;
        self.manifest = None;
        self.next_fetch = now.saturating_add(RETRY_MS.get(self.failures).copied().unwrap_or(0));
        self.failures = self.failures.saturating_add(1);
    }

    fn failed_inline(&mut self, now: u64) {
        self.manifest = None;
        self.next_fetch =
            now.saturating_add(RETRY_MS.get(self.inline_failures).copied().unwrap_or(0));
        self.inline_failures += 1;
    }

    fn observe(
        &mut self,
        root: Id128,
        content: Hash32,
        event: Option<&AdmittedNetworkEvent>,
        now: u64,
    ) {
        if let Some(AdmittedNetworkEvent::PeerDisconnected { connection_id, .. }) = event {
            if self
                .fetch
                .as_ref()
                .is_some_and(|fetch| fetch.connection == *connection_id)
            {
                self.fetch = None;
            }
            if self
                .manifest
                .as_ref()
                .is_some_and(|manifest| manifest.connection_id == *connection_id)
            {
                self.manifest = None;
            }
        }
        let Some(fetch) = self.fetch.as_ref() else {
            return;
        };
        if fetch.deadline <= now {
            self.failed(now);
            return;
        }
        match event {
            Some(AdmittedNetworkEvent::FetchManifestReceived(manifest))
                if manifest.fetch_request_id == fetch.id
                    && manifest.connection_id == fetch.connection
                    && manifest.agent_id == self.identity.agent_id
                    && manifest.peer_id == self.identity.peer_id
                    && manifest.root_task_id == root
                    && manifest.content_id == content
                    && manifest.expires_at_ms > now =>
            {
                self.fetch = None;
                self.failures = 0;
                self.approval_wait_until = None;
                self.registered = true;
                self.manifest = Some(manifest.clone());
            }
            Some(AdmittedNetworkEvent::ControlResponse {
                connection_id,
                agent_id,
                request_id,
                response: WireFrame::FetchPending(pending),
            }) if *connection_id == fetch.connection
                && *agent_id == self.identity.agent_id
                && *request_id == fetch.id.0
                && pending.content_id == content
                && pending.expires_at_ms > now
                && pending.retry_at_ms <= pending.expires_at_ms =>
            {
                self.fetch = None;
                self.manifest = None;
                self.failures = 0;
                self.approval_wait_until = Some(pending.expires_at_ms);
                self.next_fetch = pending
                    .retry_at_ms
                    .max(now.saturating_add(1_000))
                    .min(pending.expires_at_ms);
            }
            Some(AdmittedNetworkEvent::ControlResponse {
                connection_id,
                agent_id,
                request_id,
                response: WireFrame::Error(_),
            }) if *connection_id == fetch.connection
                && *agent_id == self.identity.agent_id
                && *request_id == fetch.id.0 =>
            {
                self.failed(now);
            }
            Some(AdmittedNetworkEvent::RequestFailed {
                connection_id,
                agent_id,
                peer_id,
                request_id,
                protocol: NetworkProtocol::Control,
                code,
            }) if *connection_id == fetch.connection
                && *agent_id == self.identity.agent_id
                && *peer_id == self.identity.peer_id
                && *request_id == fetch.id.0 =>
            {
                if *code == NetworkErrorCode::Capacity {
                    self.fetch = None;
                } else {
                    self.failed(now);
                }
            }
            _ => {}
        }
    }

    fn ensure_manifest(
        &mut self,
        root: Id128,
        content: Hash32,
        group: Option<&asl_store::transfers::GroupTransferBinding>,
        group_route: Option<(Hash32, Hash32)>,
        now: u64,
        send: &impl Fn(WorkerRequest) -> Receipt,
    ) -> Result<(), AslError> {
        if self.fetch.is_some()
            || self.live_manifest(now).is_some()
            || now < self.next_fetch
            || self.exhausted(now)
        {
            return Ok(());
        }
        let id = Id128(rand::random());
        let request = FetchRequest {
            message_id: id,
            root_task_id: root,
            content_id: content,
            logical_group_id: group_route.map(|(logical, _)| logical),
            source_room_id: group_route.map(|(_, source)| source),
        };
        match send(WorkerRequest::Fetch {
            source: self.identity.clone(),
            group: group.cloned(),
            request,
        }) {
            Ok(Some(connection)) => {
                self.fetch = Some(PendingFetch {
                    id,
                    connection,
                    deadline: now.saturating_add(FETCH_TIMEOUT_MS),
                });
            }
            Ok(None) => {}
            Err(AslError::NotFound | AslError::InvalidIdentity | AslError::ExpiredMessage) => {
                self.next_fetch = now.saturating_add(NO_CONNECTION_POLL_MS);
            }
            Err(error) => return Err(error),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use asl_types::{
        ids::{AgentId, Hash32, Id128, PeerId},
        protocol::{FetchPending, WireFrame},
    };

    use super::*;

    fn source() -> (Source, AgentId, [u8; 16], Id128, Hash32, Id128) {
        let mut peer_bytes = vec![0, 36, 8, 1, 18, 32];
        peer_bytes.extend_from_slice(&[7; 32]);
        let agent = AgentId([1; 32]);
        let peer = PeerId::from_bytes(peer_bytes).unwrap();
        let connection = [2; 16];
        let request = Id128([3; 16]);
        let content = Hash32([4; 32]);
        let root = Id128([5; 16]);
        (
            Source::new(
                DownloadSource {
                    agent_id: agent,
                    peer_id: peer,
                },
                true,
            ),
            agent,
            connection,
            request,
            content,
            root,
        )
    }

    #[test]
    fn fetch_pending_waits_until_retry_time_then_retries_the_same_content() {
        let (mut source, agent, connection, request, content, root) = source();
        source.fetch = Some(PendingFetch {
            id: request,
            connection,
            deadline: 10_000,
        });
        let event = AdmittedNetworkEvent::ControlResponse {
            connection_id: connection,
            agent_id: agent,
            request_id: request.0,
            response: WireFrame::FetchPending(FetchPending {
                message_id: Id128([6; 16]),
                content_id: content,
                retry_at_ms: 7_000,
                expires_at_ms: 12_000,
            }),
        };
        source.observe(root, content, Some(&event), 5_000);
        assert!(source.fetch.is_none());
        assert_eq!(source.approval_wait_until, Some(12_000));
        assert_eq!(source.next_fetch, 7_000);
        assert!(!source.exhausted(11_999));

        let sends = Cell::new(0);
        source
            .ensure_manifest(root, content, None, None, 6_999, &|_| {
                sends.set(sends.get() + 1);
                Ok(Some(connection))
            })
            .unwrap();
        assert_eq!(sends.get(), 0);
        source
            .ensure_manifest(root, content, None, None, 7_000, &|request| {
                sends.set(sends.get() + 1);
                let WorkerRequest::Fetch { request, .. } = request else {
                    panic!("expected a Fetch retry")
                };
                assert_eq!(request.content_id, content);
                assert_eq!(request.root_task_id, root);
                Ok(Some(connection))
            })
            .unwrap();
        assert_eq!(sends.get(), 1);
        assert!(source.fetch.is_some());
    }

    #[test]
    fn fetch_pending_expiry_stops_further_retries() {
        let (mut source, agent, connection, request, content, root) = source();
        source.fetch = Some(PendingFetch {
            id: request,
            connection,
            deadline: 10_000,
        });
        let event = AdmittedNetworkEvent::ControlResponse {
            connection_id: connection,
            agent_id: agent,
            request_id: request.0,
            response: WireFrame::FetchPending(FetchPending {
                message_id: Id128([6; 16]),
                content_id: content,
                retry_at_ms: 7_000,
                expires_at_ms: 12_000,
            }),
        };
        source.observe(root, content, Some(&event), 5_000);
        assert!(source.exhausted(12_000));

        let sends = Cell::new(0);
        source
            .ensure_manifest(root, content, None, None, 12_000, &|_| {
                sends.set(sends.get() + 1);
                Ok(Some(connection))
            })
            .unwrap();
        assert_eq!(sends.get(), 0);
    }
}
