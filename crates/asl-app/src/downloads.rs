//! Core-local entry point for [`AdmittedNetworkEvent::FetchManifestReceived`].
//! The caller supplies an existing inbox grant and a filename chosen locally.
//! Nothing here accepts offers or enrolls devices. Small files can be requested
//! explicitly over the admitted bulk channel after the download has started.
//!
//! [`AdmittedNetworkEvent::FetchManifestReceived`]: crate::profile::AdmittedNetworkEvent::FetchManifestReceived

use std::path::Path;

use asl_policy::WriteGrant;
use asl_store::transfers::{DownloadBroker, DownloadRequest};
pub use asl_store::transfers::{DownloadConsent, DownloadInfo, DownloadMode, DownloadStart};
use asl_types::{
    error::AslError,
    ids::Id128,
    manifest::{content_id, encode_manifest},
};

use crate::{VerifiedFetchManifest, paths::AppPaths, supervisor::unix_time_ms};

mod inline;
pub use inline::InlineDownload;

pub struct LocalDownloads {
    broker: DownloadBroker,
}

impl LocalDownloads {
    /// Open once at startup for the local handler: opening recovers transfers.
    /// Reuse this instance for queries and decisions. The store's mode is
    /// preserved; its default is automatic only within an authorized inbox.
    pub fn open(paths: &AppPaths) -> Result<Self, AslError> {
        Ok(Self {
            broker: DownloadBroker::open(paths.dos_root())?,
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
        let request = direct_request(event, inbox_grant, filename)?;
        self.broker.request_download(&request)
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
        let request = direct_request(event, inbox_grant, filename)?;
        self.broker.begin_approved_download(&request, id)
    }
}

fn direct_request(
    event: &VerifiedFetchManifest,
    inbox_grant: Id128,
    filename: &str,
) -> Result<DownloadRequest, AslError> {
    let filename = WriteGrant::filename(Path::new(filename))?;
    let manifest = encode_manifest(&event.manifest).map_err(|_| AslError::InvalidMessage)?;
    if content_id(&manifest) != event.content_id.0 {
        return Err(AslError::InvalidMessage);
    }
    if event.expires_at_ms <= unix_time_ms()? {
        return Err(AslError::ExpiredMessage);
    }
    Ok(DownloadRequest {
        content_id: event.content_id,
        manifest,
        write_grant_id: inbox_grant,
        destination_relative: filename.into(),
        sources: vec![event.peer_id.clone()],
    })
}

#[cfg(test)]
mod tests;
