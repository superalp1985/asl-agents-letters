//! Core-local entry point for [`AdmittedNetworkEvent::FetchManifestReceived`].
//! The caller supplies an existing inbox grant and a filename chosen locally.
//! Nothing here accepts offers or enrolls devices. File requests go through
//! the admitted bulk channel after the download has started.
//!
//! [`AdmittedNetworkEvent::FetchManifestReceived`]: crate::profile::AdmittedNetworkEvent::FetchManifestReceived

use std::path::Path;

use asl_policy::WriteGrant;
use asl_store::transfers::{DownloadBroker, DownloadRequest};
pub use asl_store::transfers::{DownloadConsent, DownloadInfo, DownloadMode, DownloadStart};
use asl_transfer::scheduler::MAX_ACTIVE_SOURCES;
use asl_types::{
    error::AslError,
    ids::Id128,
    manifest::{content_id, encode_manifest},
};

use crate::{VerifiedFetchManifest, paths::AppPaths, supervisor::unix_time_ms};

mod chunks;
mod inline;
pub use inline::InlineDownload;

pub enum DownloadDriverEvent<'a> {
    Network(&'a crate::profile::AdmittedNetworkEvent),
    Tick,
}

pub type DownloadEnqueue<'a> =
    dyn FnMut(crate::network::NetworkCommand) -> Result<bool, AslError> + 'a;

pub struct LocalDownloads {
    broker: DownloadBroker,
    chunks: Option<chunks::ChunkDownload>,
}

impl LocalDownloads {
    /// Open once at startup for the local handler: opening recovers transfers.
    /// Reuse this instance for queries and decisions. The store's mode is
    /// preserved; its default is automatic only within an authorized inbox.
    pub fn open(paths: &AppPaths) -> Result<Self, AslError> {
        Ok(Self {
            broker: DownloadBroker::open(paths.dos_root())?,
            chunks: None,
        })
    }

    pub fn download_mode(&self) -> Result<DownloadMode, AslError> {
        self.broker.download_mode()
    }

    pub fn set_download_mode(&mut self, mode: DownloadMode) -> Result<(), AslError> {
        self.broker.set_download_mode(mode)
    }

    /// The store's bounded list of live local decisions, including approvals
    /// awaiting a matching request after restart. These entries contain no lease.
    pub fn download_consents(&self) -> Result<Vec<DownloadConsent>, AslError> {
        self.broker.download_consents()
    }

    /// Submit only a download already selected by the local caller. In Ask
    /// mode, return the pending ID without making a decision on the user's behalf.
    pub fn request_download(
        &mut self,
        event: &VerifiedFetchManifest,
        inbox_grant: Id128,
        filename: &str,
    ) -> Result<DownloadStart, AslError> {
        self.request_download_from(&[event], inbox_grant, filename)
    }

    pub fn request_download_from(
        &mut self,
        sources: &[&VerifiedFetchManifest],
        inbox_grant: Id128,
        filename: &str,
    ) -> Result<DownloadStart, AslError> {
        self.broker
            .request_download(&download_request(sources, inbox_grant, filename)?)
    }

    /// Record the local user's decision. Approval alone does not start a transfer.
    pub fn decide_download(&mut self, id: Id128, approve: bool) -> Result<(), AslError> {
        self.broker.decide_download(id, approve)
    }

    /// Present a still-live manifest and the same local destination again.
    /// The broker checks the approval binding; an expired lease must be renewed.
    pub fn begin_approved_download(
        &mut self,
        event: &VerifiedFetchManifest,
        inbox_grant: Id128,
        filename: &str,
        id: Id128,
    ) -> Result<DownloadInfo, AslError> {
        self.begin_approved_download_from(&[event], inbox_grant, filename, id)
    }

    pub fn begin_approved_download_from(
        &mut self,
        sources: &[&VerifiedFetchManifest],
        inbox_grant: Id128,
        filename: &str,
        id: Id128,
    ) -> Result<DownloadInfo, AslError> {
        self.broker
            .begin_approved_download(&download_request(sources, inbox_grant, filename)?, id)
    }
}

fn download_request(
    sources: &[&VerifiedFetchManifest],
    inbox_grant: Id128,
    filename: &str,
) -> Result<DownloadRequest, AslError> {
    let &[event, ..] = sources else {
        return Err(AslError::NotFound);
    };
    if sources.len() > MAX_ACTIVE_SOURCES {
        return Err(AslError::QuotaExceeded);
    }
    let filename = WriteGrant::filename(Path::new(filename))?;
    let manifest = encode_manifest(&event.manifest).map_err(|_| AslError::InvalidMessage)?;
    if content_id(&manifest) != event.content_id.0 {
        return Err(AslError::InvalidMessage);
    }
    let now_ms = unix_time_ms()?;
    let mut peers = Vec::with_capacity(sources.len());
    for source in sources {
        if source.content_id != event.content_id
            || source.manifest != event.manifest
            || peers.contains(&source.peer_id)
        {
            return Err(AslError::InvalidMessage);
        }
        if source.expires_at_ms <= now_ms {
            return Err(AslError::ExpiredMessage);
        }
        peers.push(source.peer_id.clone());
    }
    Ok(DownloadRequest {
        content_id: event.content_id,
        manifest,
        write_grant_id: inbox_grant,
        destination_relative: filename.into(),
        sources: peers,
    })
}

#[cfg(all(test, windows))]
mod test_inbox;
#[cfg(test)]
mod tests;
