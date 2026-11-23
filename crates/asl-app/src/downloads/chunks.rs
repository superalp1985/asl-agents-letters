use std::collections::HashMap;

use asl_net::codec::{BulkOperation, BulkRequest, BulkStatus};
use asl_store::transfers::{DOWNLOAD_IDLE_MS, DownloadBroker};
use asl_transfer::{
    bulk::MAX_INLINE_BYTES,
    scheduler::{ChunkScheduler, FailureKind, Scheduler},
};
use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId},
    manifest::{content_id, encode_manifest},
    task::TransferId,
};

use super::{DownloadInfo, LocalDownloads};
use crate::{
    MatchedBulkResponse, VerifiedFetchManifest,
    ipc::{NetworkErrorCode, NetworkProtocol},
    network::NetworkCommand,
    profile::AdmittedNetworkEvent,
    supervisor::unix_time_ms,
};

const IDLE_SWEEP_INTERVAL_MS: u64 = 1_000;
const FILE_PRUNE_INTERVAL_MS: u64 = 60_000;

pub(super) struct ChunkDownload {
    transfer: TransferId,
    content: Hash32,
    scheduler: Scheduler,
    remaining: usize,
    idle_deadline_ms: u64,
    allowed: Vec<PeerId>,
    leases: HashMap<PeerId, SourceLease>,
    pending: HashMap<Id128, PendingChunk>,
}

struct SourceLease {
    fetch_generation: u64,
    connection: [u8; 16],
    agent: AgentId,
    lease: Hash32,
    expires_at_ms: u64,
    usable: bool,
}

pub(super) struct PendingChunk {
    peer: PeerId,
    connection: [u8; 16],
    agent: AgentId,
    request: BulkRequest,
    deadline_ms: u64,
    receipt_deadline_ms: u64,
    retired: bool,
}

impl PendingChunk {
    fn matches_response(&self, matched: &MatchedBulkResponse) -> bool {
        self.connection == matched.connection_id
            && self.agent == matched.agent_id
            && self.peer == matched.peer_id
            && self.request == matched.request
            && self.request.request_id == matched.response.request_id
    }

    fn matches_failure(
        &self,
        connection: [u8; 16],
        agent: AgentId,
        peer: &PeerId,
        request: Id128,
    ) -> bool {
        self.connection == connection
            && self.agent == agent
            && &self.peer == peer
            && self.request.request_id == request
    }

    fn acknowledged_by(&self, event: &AdmittedNetworkEvent) -> bool {
        match event {
            AdmittedNetworkEvent::BulkTransferResponse(response) => self.matches_response(response),
            AdmittedNetworkEvent::RequestFailed {
                connection_id,
                agent_id,
                peer_id,
                request_id,
                protocol: NetworkProtocol::Bulk,
                ..
            } => self.matches_failure(*connection_id, *agent_id, peer_id, Id128(*request_id)),
            AdmittedNetworkEvent::PeerDisconnected { connection_id, .. } => {
                self.connection == *connection_id
            }
            _ => false,
        }
    }
}

impl LocalDownloads {
    /// Start or resume an existing authorized task. The caller must supply
    /// current verified leases again; no credentials are restored from disk.
    /// A local owner schedules one chunked transfer at a time.
    pub fn resume_chunks(&mut self, transfer: &TransferId) -> Result<(), AslError> {
        if self.chunks.is_some() {
            return Err(AslError::InvalidPolicyState);
        }
        let schedule = self.broker.schedule(transfer)?;
        if schedule.manifest.file_size <= MAX_INLINE_BYTES {
            return Err(AslError::InvalidPolicyState);
        }
        let manifest =
            encode_manifest(&schedule.manifest).map_err(|_| AslError::InvalidDatabase)?;
        let chunk_count = schedule.manifest.chunk_hashes.len();
        let scheduler = Scheduler::from_durable(
            schedule.manifest.file_size,
            schedule.manifest.chunk_hashes,
            schedule.sources.iter().cloned(),
            &schedule.durable_indexes,
        )?;
        let remaining = chunk_count - scheduler.durable_count();
        self.broker.reset_chunk_assignments(transfer)?;
        self.chunks = Some(ChunkDownload {
            transfer: transfer.clone(),
            content: Hash32(content_id(&manifest)),
            scheduler,
            remaining,
            idle_deadline_ms: stored_deadline(schedule.expires_at_ms)?,
            allowed: schedule.sources,
            leases: HashMap::new(),
            pending: HashMap::new(),
        });
        Ok(())
    }

    /// Only a fresh verified lease for an originally authorized source can
    /// replace its connection or make it eligible again after a failure.
    pub fn attach_chunk_source(&mut self, event: &VerifiedFetchManifest) -> Result<(), AslError> {
        self.chunks
            .as_mut()
            .ok_or(AslError::NotFound)?
            .attach_source(&mut self.broker, event)
    }

    pub(super) fn chunk_source(&self, peer: &PeerId, now: u64) -> Option<bool> {
        let download = self.chunks.as_ref()?;
        download.allowed.contains(peer).then(|| {
            download
                .leases
                .get(peer)
                .is_some_and(|lease| lease.usable && lease.expires_at_ms > now)
        })
    }

    /// Submit requests through the admitted Core sender. `false` means local
    /// backpressure: the unqueued assignments are released for the next poll.
    /// Returns completed info once. Polling may perform disk I/O.
    pub fn poll_chunks(
        &mut self,
        enqueue: impl FnMut(NetworkCommand) -> Result<bool, AslError>,
    ) -> Result<Option<DownloadInfo>, AslError> {
        self.poll_chunks_at(unix_time_ms()?, enqueue)
    }

    fn poll_chunks_at(
        &mut self,
        now_ms: u64,
        enqueue: impl FnMut(NetworkCommand) -> Result<bool, AslError>,
    ) -> Result<Option<DownloadInfo>, AslError> {
        if now_ms >= self.next_idle_sweep_ms {
            self.broker.sweep_idle_downloads(broker_time(now_ms)?)?;
            self.next_idle_sweep_ms = now_ms.saturating_add(IDLE_SWEEP_INTERVAL_MS);
        }
        if now_ms >= self.next_file_prune_ms {
            self.next_file_prune_ms = now_ms.saturating_add(FILE_PRUNE_INTERVAL_MS);
            let now = broker_time(now_ms)?;
            if self.broker.prune_failed_parts(now).is_err() {
                eprintln!("ASL failed-part retention failed");
            }
            if self.broker.prune_received_files(now).is_err() {
                eprintln!("ASL inbox retention failed");
            }
        }
        self.expire_idle_chunks(now_ms)?;
        self.retired_chunks
            .retain(|_, request| request.receipt_deadline_ms > now_ms);
        if !self.retired_chunks.is_empty() {
            return Ok(None);
        }
        let Some(download) = &mut self.chunks else {
            return Ok(None);
        };
        let result = download.poll_at(&mut self.broker, now_ms, enqueue);
        match &result {
            Ok(Some(_)) => {
                self.detach_chunks();
            }
            Err(_) => self.pause_chunks()?,
            Ok(None) => {}
        }
        result
    }

    /// Consumes matching network events only. Writing a verified block may
    /// perform disk I/O; call from the same local owner that polls downloads.
    pub fn handle_chunk_event(&mut self, event: &AdmittedNetworkEvent) -> Result<(), AslError> {
        self.handle_chunk_event_at(event, unix_time_ms()?)
    }

    fn handle_chunk_event_at(
        &mut self,
        event: &AdmittedNetworkEvent,
        now_ms: u64,
    ) -> Result<(), AslError> {
        self.expire_idle_chunks(now_ms)?;
        self.retired_chunks
            .retain(|_, request| !request.acknowledged_by(event));
        let Some(download) = &mut self.chunks else {
            return Ok(());
        };
        let result = download.handle_event_at(&mut self.broker, event, now_ms);
        if result.is_err() {
            self.pause_chunks()?;
        }
        result
    }

    pub fn pause_chunks(&mut self) -> Result<(), AslError> {
        if let Some(transfer) = self.detach_chunks() {
            self.broker.reset_chunk_assignments(&transfer)?;
        }
        Ok(())
    }

    fn expire_idle_chunks(&mut self, now_ms: u64) -> Result<(), AslError> {
        let Some(download) = &mut self.chunks else {
            return Ok(());
        };
        if now_ms >= download.idle_deadline_ms {
            match self
                .broker
                .expire_idle_download(&download.transfer, broker_time(now_ms)?)?
            {
                Some(deadline) => download.idle_deadline_ms = stored_deadline(deadline)?,
                None => {
                    self.detach_chunks();
                }
            }
        }
        Ok(())
    }

    fn detach_chunks(&mut self) -> Option<TransferId> {
        let download = self.chunks.take()?;
        self.retired_chunks.extend(download.pending);
        Some(download.transfer)
    }
}

fn broker_time(now_ms: u64) -> Result<i64, AslError> {
    i64::try_from(now_ms).map_err(|_| AslError::InvalidPolicyState)
}

fn stored_deadline(deadline: i64) -> Result<u64, AslError> {
    u64::try_from(deadline).map_err(|_| AslError::InvalidDatabase)
}

impl ChunkDownload {
    fn attach_source(
        &mut self,
        broker: &mut DownloadBroker,
        event: &VerifiedFetchManifest,
    ) -> Result<(), AslError> {
        if self.content != event.content_id
            || !self.allowed.contains(&event.peer_id)
            || self.scheduler.disabled_peers().contains(&event.peer_id)
        {
            return Err(AslError::PolicyDenied);
        }
        if event.expires_at_ms <= unix_time_ms()? {
            return Err(AslError::ExpiredMessage);
        }
        if let Some(previous) = self.leases.get(&event.peer_id) {
            if previous.lease == event.lease_id {
                return Ok(());
            }
            if event.fetch_generation <= previous.fetch_generation {
                return Err(AslError::ExpiredMessage);
            }
            self.clear_peer(broker, &event.peer_id, FailureKind::Cancelled)?;
        }
        self.leases.insert(
            event.peer_id.clone(),
            SourceLease {
                fetch_generation: event.fetch_generation,
                connection: event.connection_id,
                agent: event.agent_id,
                lease: event.lease_id,
                expires_at_ms: event.expires_at_ms,
                usable: true,
            },
        );
        Ok(())
    }

    fn poll_at(
        &mut self,
        broker: &mut DownloadBroker,
        now_ms: u64,
        mut enqueue: impl FnMut(NetworkCommand) -> Result<bool, AslError>,
    ) -> Result<Option<DownloadInfo>, AslError> {
        if self.remaining == 0 {
            return broker.complete(self.transfer.clone()).map(Some);
        }
        let timed_out: Vec<_> = self
            .pending
            .values()
            .filter(|pending| !pending.retired && pending.deadline_ms <= now_ms)
            .map(|pending| pending.peer.clone())
            .collect();
        for peer in timed_out {
            self.suspend_peer(broker, &peer, FailureKind::Timeout)?;
        }
        self.pending
            .retain(|_, pending| !pending.retired || pending.receipt_deadline_ms > now_ms);
        let pending = &self.pending;
        let eligible = |peer: &PeerId| {
            self.leases
                .get(peer)
                .is_some_and(|lease| lease.usable && lease.expires_at_ms > now_ms)
                && !pending
                    .values()
                    .any(|request| request.retired && &request.peer == peer)
        };
        let mut queue_full = false;
        for assignment in self.scheduler.next_where(now_ms, eligible) {
            let peer = assignment.peer_id;
            let index = assignment.index;
            if queue_full || !self.leases[&peer].usable {
                self.scheduler.failed(&peer, index, FailureKind::Cancelled);
                continue;
            }
            let source = &self.leases[&peer];
            let request = BulkRequest {
                operation: BulkOperation::Chunk,
                request_id: Id128(rand::random()),
                content_id: self.content,
                lease_id: source.lease,
                chunk_index: index,
            };
            let connection_id = source.connection;
            let agent = source.agent;
            let deadline_ms = assignment.deadline_ms.min(source.expires_at_ms);
            let receipt_deadline_ms =
                now_ms.saturating_add(asl_net::transport::REQUEST_TIMEOUT.as_millis() as u64);
            broker.assign_chunk(self.transfer.clone(), &peer, index)?;
            match enqueue(NetworkCommand::SendBulk {
                connection_id,
                request: request.clone(),
            }) {
                Ok(true) => {
                    self.pending.insert(
                        request.request_id,
                        PendingChunk {
                            peer,
                            connection: connection_id,
                            agent,
                            request,
                            deadline_ms,
                            receipt_deadline_ms,
                            retired: false,
                        },
                    );
                }
                Ok(false) => {
                    broker.unassign_chunk(&self.transfer, &peer, index)?;
                    self.scheduler.failed(&peer, index, FailureKind::Cancelled);
                    queue_full = true;
                }
                Err(
                    AslError::InvalidIdentity
                    | AslError::InvalidDeviceCertificate
                    | AslError::PolicyDenied
                    | AslError::ExpiredMessage,
                ) => {
                    broker.unassign_chunk(&self.transfer, &peer, index)?;
                    self.scheduler.failed(&peer, index, FailureKind::Cancelled);
                    self.suspend_peer(broker, &peer, FailureKind::Cancelled)?;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(None)
    }

    fn handle_event_at(
        &mut self,
        broker: &mut DownloadBroker,
        event: &AdmittedNetworkEvent,
        now_ms: u64,
    ) -> Result<(), AslError> {
        match event {
            AdmittedNetworkEvent::BulkTransferResponse(response) => {
                self.receive(broker, response, now_ms)
            }
            AdmittedNetworkEvent::RequestFailed {
                connection_id,
                agent_id,
                peer_id,
                request_id,
                protocol: NetworkProtocol::Bulk,
                code,
            } => {
                let id = Id128(*request_id);
                let Some(pending) = self.pending.get(&id).filter(|pending| {
                    pending.matches_failure(*connection_id, *agent_id, peer_id, id)
                }) else {
                    return Ok(());
                };
                if !pending.retired {
                    if *code == NetworkErrorCode::Capacity {
                        self.unassign(broker, id, FailureKind::Cancelled)?;
                    } else {
                        self.suspend_peer(broker, peer_id, FailureKind::Cancelled)?;
                    }
                }
                self.pending.remove(&id);
                Ok(())
            }
            AdmittedNetworkEvent::PeerDisconnected { connection_id, .. } => {
                let peer = self
                    .leases
                    .iter()
                    .find(|(_, lease)| lease.connection == *connection_id)
                    .map(|(peer, _)| peer.clone());
                if let Some(peer) = peer {
                    self.suspend_peer(broker, &peer, FailureKind::Disconnected)?;
                }
                self.pending
                    .retain(|_, pending| pending.connection != *connection_id);
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn receive(
        &mut self,
        broker: &mut DownloadBroker,
        matched: &MatchedBulkResponse,
        now_ms: u64,
    ) -> Result<(), AslError> {
        let id = matched.response.request_id;
        let Some(pending) = self.pending.get(&id) else {
            return Ok(());
        };
        if !pending.matches_response(matched) {
            return Ok(());
        }
        let peer = &matched.peer_id;
        if pending.retired
            || pending.deadline_ms <= now_ms
            || matched.response.status != BulkStatus::Success
        {
            if !pending.retired {
                let reason = if pending.deadline_ms <= now_ms {
                    FailureKind::Timeout
                } else {
                    FailureKind::Cancelled
                };
                self.suspend_peer(broker, peer, reason)?;
            }
            self.pending.remove(&id);
            return Ok(());
        }
        let index = pending.request.chunk_index;
        self.pending.remove(&id);
        let bytes = &matched.response.payload;
        match self.scheduler.verify_and_buffer(peer, index, bytes) {
            Ok(_) => {
                broker.write_chunk(self.transfer.clone(), peer, index, bytes)?;
                self.scheduler.mark_durable(&[index])?;
                self.remaining -= 1;
                self.idle_deadline_ms = now_ms.saturating_add(DOWNLOAD_IDLE_MS as u64);
                Ok(())
            }
            Err(AslError::InvalidMessage) => {
                match broker.write_chunk(self.transfer.clone(), peer, index, bytes) {
                    Err(AslError::InvalidMessage) => {}
                    Err(error) => return Err(error),
                    Ok(()) => return Err(AslError::InvalidPolicyState),
                }
                // The broker resets all of this source's assigned blocks on
                // corrupt data. Invalidate the sibling request IDs as well.
                self.scheduler.failed(peer, index, FailureKind::BadHash);
                self.clear_peer(broker, peer, FailureKind::Cancelled)?;
                if !broker.chunk_source_available(&self.transfer, peer)? {
                    self.leases.remove(peer);
                    self.allowed.retain(|allowed| allowed != peer);
                }
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn suspend_peer(
        &mut self,
        broker: &mut DownloadBroker,
        peer: &PeerId,
        reason: FailureKind,
    ) -> Result<(), AslError> {
        self.clear_peer(broker, peer, reason)?;
        if let Some(lease) = self.leases.get_mut(peer) {
            lease.usable = false;
        }
        Ok(())
    }

    fn clear_peer(
        &mut self,
        broker: &mut DownloadBroker,
        peer: &PeerId,
        reason: FailureKind,
    ) -> Result<(), AslError> {
        let requests: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, pending)| !pending.retired && &pending.peer == peer)
            .map(|(&id, _)| id)
            .collect();
        for id in requests {
            self.unassign(broker, id, reason)?;
        }
        Ok(())
    }

    fn unassign(
        &mut self,
        broker: &mut DownloadBroker,
        id: Id128,
        reason: FailureKind,
    ) -> Result<(), AslError> {
        let pending = self.pending.get_mut(&id).ok_or(AslError::NotFound)?;
        let peer = &pending.peer;
        let index = pending.request.chunk_index;
        broker.unassign_chunk(&self.transfer, peer, index)?;
        self.scheduler.failed(peer, index, reason);
        // Keep the local receipt until acknowledgment or cleanup; Net owns
        // the actual network slot, independently of this scheduler.
        pending.retired = true;
        Ok(())
    }
}

#[cfg(all(test, windows))]
mod tests;
