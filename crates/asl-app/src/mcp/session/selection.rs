use super::*;

impl Task {
    pub(super) fn select_download(
        &mut self,
        port: &DownloadPort,
        inbox: Option<Id128>,
        ids: Vec<Id128>,
    ) -> Result<&mut Download, ErrorCode> {
        let offers = ids
            .iter()
            .map(|id| {
                self.offers
                    .iter()
                    .find(|entry| entry.id == *id)
                    .ok_or(ErrorCode::NotFound)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let first = offers.first().ok_or(ErrorCode::InvalidMessage)?;
        let inbox_grant = inbox.ok_or(ErrorCode::PolicyDenied)?;
        let content_id = first.offer.content_id;
        let size = first.offer.file_size;
        // One content-addressed destination per query. A retry can change
        // argument order, but not the set the download was submitted with.
        if let Some(index) = self
            .downloads
            .iter()
            .position(|d| d.content_id == content_id)
        {
            let download = &mut self.downloads[index];
            return if ids.len() == download.offer_ids.len()
                && ids.iter().all(|id| download.offer_ids.contains(id))
            {
                Ok(download)
            } else {
                Err(ErrorCode::PolicyDenied)
            };
        }
        let now = unix_time_ms().map_err(error_code)?;
        let mut sources = Vec::<DownloadSource>::with_capacity(offers.len());
        for entry in offers {
            if entry.offer.expires_at_ms <= now {
                return Err(ErrorCode::Timeout);
            }
            if entry.offer.content_id != content_id
                || entry.offer.file_size != size
                || sources.iter().any(|s| s.peer_id == entry.source.peer_id)
            {
                return Err(ErrorCode::InvalidMessage);
            }
            sources.push(entry.source.clone());
        }
        let ticket = port
            .submit(DownloadJob::Fetch(DownloadSelection {
                content_id,
                inbox_grant,
                filename: format!("asl-{}.bin", hex::encode(content_id.0)),
                sources,
                group: None,
                context_ref: None,
            }))
            .map_err(error_code)?;
        Ok(self.downloads.push_mut(Download {
            notices: VecDeque::new(),
            content_id,
            offer_ids: ids,
            ticket: Some(ticket),
            state: DownloadState::Queued,
            context_ref: None,
            context_candidate_stored: None,
        }))
    }
}
