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
    MatchedBulkResponse, VerifiedFetchManifest, ipc::NetworkProtocol, network::NetworkCommand,
    profile::AdmittedNetworkEvent, supervisor::unix_time_ms,
};

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
    connection: [u8; 16],
    agent: AgentId,
    lease: Hash32,
    expires_at_ms: u64,
    usable: bool,
}

struct PendingChunk {
    peer: PeerId,
    connection: [u8; 16],
    agent: AgentId,
    request: BulkRequest,
    deadline_ms: u64,
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
        self.expire_idle_chunks(now_ms)?;
        let Some(download) = &mut self.chunks else {
            return Ok(None);
        };
        let result = download.poll_at(&mut self.broker, now_ms, enqueue);
        match &result {
            Ok(Some(_)) => self.chunks = None,
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
        if let Some(download) = self.chunks.take() {
            self.broker.reset_chunk_assignments(&download.transfer)?;
        }
        Ok(())
    }

    fn expire_idle_chunks(&mut self, now_ms: u64) -> Result<(), AslError> {
        let Some(download) = &mut self.chunks else {
            return Ok(());
        };
        if now_ms >= download.idle_deadline_ms {
            let now = i64::try_from(now_ms).map_err(|_| AslError::InvalidPolicyState)?;
            match self.broker.expire_idle_download(&download.transfer, now)? {
                Some(deadline) => download.idle_deadline_ms = stored_deadline(deadline)?,
                None => self.chunks = None,
            }
        }
        Ok(())
    }
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
            if event.expires_at_ms <= previous.expires_at_ms {
                return Err(AslError::ExpiredMessage);
            }
            self.clear_peer(broker, &event.peer_id, FailureKind::Cancelled)?;
        }
        self.leases.insert(
            event.peer_id.clone(),
            SourceLease {
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
            .filter(|pending| pending.deadline_ms <= now_ms)
            .map(|pending| pending.peer.clone())
            .collect();
        for peer in timed_out {
            self.suspend_peer(broker, &peer, FailureKind::Timeout)?;
        }
        let eligible = |peer: &PeerId| {
            self.leases
                .get(peer)
                .is_some_and(|lease| lease.usable && lease.expires_at_ms > now_ms)
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
                ..
            } if self
                .pending
                .get(&Id128(*request_id))
                .is_some_and(|pending| {
                    pending.connection == *connection_id
                        && pending.agent == *agent_id
                        && pending.peer == *peer_id
                }) =>
            {
                self.suspend_peer(broker, peer_id, FailureKind::Cancelled)
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
        if pending.connection != matched.connection_id
            || pending.agent != matched.agent_id
            || pending.peer != matched.peer_id
            || pending.request != matched.request
        {
            return Ok(());
        }
        let peer = &matched.peer_id;
        if pending.deadline_ms <= now_ms {
            return self.suspend_peer(broker, peer, FailureKind::Timeout);
        }
        if matched.response.status != BulkStatus::Success {
            return self.suspend_peer(broker, peer, FailureKind::Cancelled);
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
            .filter(|(_, pending)| &pending.peer == peer)
            .map(|(&id, pending)| (id, pending.request.chunk_index))
            .collect();
        for (id, index) in requests {
            broker.unassign_chunk(&self.transfer, peer, index)?;
            self.scheduler.failed(peer, index, reason);
            self.pending.remove(&id);
        }
        Ok(())
    }
}

#[cfg(all(test, windows))]
mod tests;
