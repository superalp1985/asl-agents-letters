use super::*;
use crate::{agent_mail::MailPort, mcp::inbox::Inbox};

impl Session<'_> {
    pub(in crate::mcp) fn check_task_offer(&mut self, args: &FetchArgs) -> Result<(), ErrorCode> {
        let ids = args.offer_ids()?;
        let task = find_task(&mut self.tasks, &args.task_id)?;
        task.poll();
        let now = unix_time_ms().map_err(error_code)?;
        for id in ids {
            if !task
                .offers
                .iter()
                .any(|o| o.id == id && now < o.offer.expires_at_ms)
            {
                return Err(ErrorCode::NotFound);
            }
        }
        Ok(())
    }

    pub(in crate::mcp) fn watch(&mut self, inbox: &mut Inbox) {
        for task in &mut self.tasks {
            task.poll();
            let id = hex::encode(task.id.0);
            for answer in &task.answers[task.notified_answers..] {
                inbox.push(json!({"kind":"answer","details":{"task_id":id,"answer":answer}}));
            }
            task.notified_answers = task.answers.len();
            for offer in &task.offers[task.notified_offers..] {
                let mut details = offer.value();
                details["task_id"] = json!(id);
                details["inbox_permission_required"] = json!(self.inbox.is_none());
                inbox.push(json!({"kind":"task_file_offer","details":details}));
            }
            task.notified_offers = task.offers.len();
            for download in &mut task.downloads {
                for notice in download.notices.drain(..) {
                    inbox.push(notice);
                }
            }
        }
        for download in &mut self.received {
            download.poll();
            for notice in download.notices.drain(..) {
                inbox.push(notice);
            }
        }
    }

    pub(in crate::mcp) async fn receive_offer(
        &mut self,
        mail: &MailPort,
        id: Id128,
        inbox: Id128,
    ) -> Result<Value, ErrorCode> {
        if let Some(download) = self.received.iter_mut().find(|d| d.offer_ids.contains(&id)) {
            download.poll();
            return Ok(download.value());
        }
        if self.received.len() >= MAX_TASKS {
            let index = self
                .received
                .iter()
                .position(|d| d.ticket.is_none() && d.notices.is_empty())
                .ok_or(ErrorCode::QuotaExceeded)?;
            self.received.remove(index);
        }
        let selection = mail
            .claim_offer(id, inbox, self.scope)
            .await
            .map_err(error_code)?;
        let content_id = selection.content_id;
        let context_ref = selection.context_ref;
        let ticket = self
            .downloads
            .submit(DownloadJob::Fetch(selection))
            .map_err(error_code)?;
        let download = Download {
            content_id,
            offer_ids: vec![id],
            ticket: Some(ticket),
            state: DownloadState::Queued,
            notices: VecDeque::new(),
            context_ref,
            context_candidate_stored: None,
        };
        let result = download.value();
        self.received.push_back(download);
        Ok(result)
    }
}

impl Download {
    pub(super) fn remember_notice(&mut self) {
        let kind = match self.state {
            DownloadState::AwaitingApproval(_) => "file_approval_required",
            DownloadState::Completed(_) => "file_received",
            DownloadState::Failed(..) => "file_failed",
            _ => return,
        };
        self.notices
            .push_back(json!({"kind":kind,"details":self.value()}));
    }
}
