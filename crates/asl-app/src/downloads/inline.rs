use asl_net::codec::{BulkOperation, BulkRequest, BulkStatus};
use asl_transfer::bulk::MAX_INLINE_BYTES;
use asl_types::{
    error::AslError,
    ids::{AgentId, Id128, PeerId},
    task::TransferId,
};

use super::{DownloadInfo, LocalDownloads};
use crate::{
    MatchedBulkResponse, VerifiedFetchManifest, network::NetworkCommand, supervisor::unix_time_ms,
};

/// Retained only by the local handler while its inline request is in flight.
/// A failed send or disconnect can simply drop it: no chunk was assigned.
pub struct InlineDownload {
    transfer: TransferId,
    connection: [u8; 16],
    agent: AgentId,
    peer: PeerId,
    expected: Option<BulkRequest>,
    expires_at_ms: u64,
    file_size: u64,
}

impl LocalDownloads {
    /// The returned command goes through the same admitted handler as any
    /// other bulk request. No Offer, consent ID or manifest alone can start it.
    pub fn prepare_inline(
        &self,
        transfer: &TransferId,
        source: &VerifiedFetchManifest,
    ) -> Result<(InlineDownload, NetworkCommand), AslError> {
        if source.manifest.file_size > MAX_INLINE_BYTES {
            return Err(AslError::QuotaExceeded);
        }
        let schedule = self.broker.schedule(transfer)?;
        if schedule.manifest != source.manifest
            || !schedule.sources.contains(&source.peer_id)
            || !schedule.durable_indexes.is_empty()
        {
            return Err(AslError::PolicyDenied);
        }
        let now = unix_time_ms()?;
        if source.expires_at_ms <= now {
            return Err(AslError::ExpiredMessage);
        }
        let request = BulkRequest {
            operation: BulkOperation::Inline,
            request_id: Id128(rand::random()),
            content_id: source.content_id,
            lease_id: source.lease_id,
            chunk_index: 0,
        };
        Ok((
            InlineDownload {
                transfer: transfer.clone(),
                connection: source.connection_id,
                agent: source.agent_id,
                peer: source.peer_id.clone(),
                expected: Some(request.clone()),
                expires_at_ms: source.expires_at_ms.min(
                    now.saturating_add(asl_net::transport::REQUEST_TIMEOUT.as_millis() as u64),
                ),
                file_size: source.manifest.file_size,
            },
            NetworkCommand::SendBulk {
                connection_id: source.connection_id,
                request,
            },
        ))
    }
}

impl InlineDownload {
    pub(super) fn failed_by(&self, event: &crate::profile::AdmittedNetworkEvent) -> bool {
        use crate::{ipc::NetworkProtocol, profile::AdmittedNetworkEvent};
        match event {
            AdmittedNetworkEvent::PeerDisconnected { connection_id, .. } => {
                *connection_id == self.connection
            }
            AdmittedNetworkEvent::RequestFailed {
                connection_id,
                agent_id,
                peer_id,
                request_id,
                protocol: NetworkProtocol::Bulk,
                ..
            } => {
                *connection_id == self.connection
                    && *agent_id == self.agent
                    && *peer_id == self.peer
                    && self
                        .expected
                        .as_ref()
                        .is_some_and(|request| request.request_id.0 == *request_id)
            }
            _ => false,
        }
    }

    /// Unrelated responses leave this ticket intact. A matching response is
    /// consumed once even when the server declines or integrity checks fail.
    pub fn receive(
        &mut self,
        downloads: &mut LocalDownloads,
        matched: &MatchedBulkResponse,
    ) -> Result<Option<DownloadInfo>, AslError> {
        let Some(request) = &self.expected else {
            return Ok(None);
        };
        if self.connection != matched.connection_id
            || self.agent != matched.agent_id
            || self.peer != matched.peer_id
            || request != &matched.request
            || request.request_id != matched.response.request_id
        {
            return Ok(None);
        }
        self.expected.take();
        if self.expires_at_ms <= unix_time_ms()? {
            return Err(AslError::ExpiredMessage);
        }
        if matched.response.status != BulkStatus::Success {
            return Err(AslError::NotFound);
        }
        let payload = &matched.response.payload;
        let broker = &mut downloads.broker;
        if self.file_size == 0 {
            if !payload.is_empty() {
                return Err(AslError::InvalidMessage);
            }
            // Empty files have no chunk assignment to recheck the grant and source.
            let schedule = broker.schedule(&self.transfer)?;
            if !schedule.sources.contains(&self.peer) {
                return Err(AslError::PolicyDenied);
            }
        } else {
            broker.assign_chunk(self.transfer.clone(), &self.peer, 0)?;
            if let Err(err) = broker.write_chunk(self.transfer.clone(), &self.peer, 0, payload) {
                broker.unassign_chunk(&self.transfer, &self.peer, 0)?;
                return Err(err);
            }
        }
        broker.complete(self.transfer.clone()).map(Some)
    }
}

#[cfg(all(test, windows))]
mod tests;
