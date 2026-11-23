use std::{cell::RefCell, collections::HashMap, path::Path};

use asl_agent::QueryScope;
use asl_store::{
    Store,
    mcp_recovery::{RecoveryReservation, RecoverySubmission, State},
    open_store,
    transfers::RecoveryDownload,
};
use asl_types::{
    error::{AslError, ErrorCode},
    ids::Id128,
    task::TransferId,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    downloads::{DownloadEvent, DownloadJob, DownloadPort, DownloadTicket},
    supervisor::unix_time_ms,
};

use super::{
    contract::{RecoveryDownloadArgs, parse_id},
    grant::HostGrant,
    session::error_code,
};

pub(crate) struct Recovery {
    store: Store,
    subject: [u8; 32],
    retain_results: bool,
    download_attempts: RefCell<HashMap<TransferId, DownloadAttempt>>,
}

const MAX_DOWNLOAD_ATTEMPTS: usize = 16;

enum DownloadAttempt {
    Queued(DownloadTicket),
    Started(DownloadTicket),
    Failed(ErrorCode),
}

#[derive(Serialize)]
pub(super) struct ResultSnapshot<'a> {
    pub answers: &'a [Value],
    pub answers_truncated: bool,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredSnapshot {
    answers: Vec<Value>,
    answers_truncated: bool,
}

impl Recovery {
    pub fn configure(database: &Path, grant: Option<&HostGrant>) -> Result<Option<Self>, AslError> {
        let subject = grant.and_then(|grant| {
            let key = grant.recovery_key.as_deref()?;
            let scope = match grant.scope {
                QueryScope::ContactsOnly => b"contacts_only".as_slice(),
                QueryScope::Public => b"public".as_slice(),
            };
            let mut hash = blake3::Hasher::new_derive_key("ASL local MCP recovery subject v1");
            hash.update(key);
            hash.update(scope);
            Some(*hash.finalize().as_bytes())
        });
        let store = open_store(database)?;
        store.configure_mcp_recovery(subject.as_ref(), now()?)?;
        let retain_results = grant.is_some_and(|grant| grant.recovery_results);
        if let Some(subject) = subject.as_ref()
            && !retain_results
        {
            store.clear_recovery_results(subject)?;
        }
        Ok(subject.map(|subject| Self {
            store,
            subject,
            retain_results,
            download_attempts: RefCell::default(),
        }))
    }

    pub(super) fn start(&self, id: Id128) -> Result<(), ErrorCode> {
        self.store
            .start_recovery_task(&self.subject, id, now().map_err(error_code)?)
            .map_err(error_code)
    }

    pub(super) fn reserve(
        &self,
        id: Id128,
        submission: &RecoverySubmission,
        can_start: bool,
    ) -> Result<RecoveryReservation, ErrorCode> {
        self.store
            .reserve_recovery_submission(
                &self.subject,
                id,
                submission,
                can_start,
                now().map_err(error_code)?,
            )
            .map_err(error_code)
    }

    pub(super) fn update(&self, id: Id128, state: State) -> Result<(), AslError> {
        self.store
            .update_recovery_task(&self.subject, id, state, now()?)
    }

    pub(super) fn retains_results(&self) -> bool {
        self.retain_results
    }

    pub(super) fn save_result(
        &self,
        id: Id128,
        state: State,
        snapshot: ResultSnapshot<'_>,
    ) -> Result<(), AslError> {
        if !self.retain_results {
            return Err(AslError::PolicyDenied);
        }
        let bytes = serde_json::to_vec(&snapshot).map_err(std::io::Error::other)?;
        self.store
            .update_recovery_snapshot(&self.subject, id, state, Some(&bytes), now()?)
    }

    pub(super) fn interrupt(&self) -> Result<(), ErrorCode> {
        self.store
            .interrupt_recovery_tasks(&self.subject, now().map_err(error_code)?)
            .map_err(error_code)
    }

    pub(super) fn task(&self, id: &str) -> Result<Value, ErrorCode> {
        let task_id = parse_id(id)?;
        let status = self
            .store
            .recovery_task(&self.subject, task_id, now().map_err(error_code)?)
            .map_err(error_code)?;
        Ok(json!({"task_id": alloy_primitives::hex::encode(task_id.0), "status":status}))
    }

    pub(super) fn result(&self, id: &str) -> Result<Value, ErrorCode> {
        if !self.retain_results {
            return Err(ErrorCode::PolicyDenied);
        }
        let task_id = parse_id(id)?;
        let result = self
            .store
            .recovery_result(&self.subject, task_id, now().map_err(error_code)?)
            .map_err(error_code)?;
        let recorded = result.snapshot.is_some();
        let snapshot = result
            .snapshot
            .as_deref()
            .map(serde_json::from_slice::<StoredSnapshot>)
            .transpose()
            .map_err(|_| ErrorCode::InternalError)?
            .unwrap_or_default();
        Ok(json!({
            "task_id": alloy_primitives::hex::encode(task_id.0),
            "status": result.status,
            "answers": snapshot.answers,
            "answers_truncated": snapshot.answers_truncated,
            "recorded": recorded,
        }))
    }

    pub(super) fn events(&self, after: i64) -> Result<Value, ErrorCode> {
        if after < 0 {
            return Err(ErrorCode::InvalidMessage);
        }
        let page = self
            .store
            .recovery_events(&self.subject, after, now().map_err(error_code)?)
            .map_err(error_code)?;
        serde_json::to_value(page).map_err(|_| ErrorCode::InternalError)
    }

    pub(super) fn download_decision(&self, id: &str) -> Result<Value, ErrorCode> {
        let approval = parse_id(id)?;
        let decision = self
            .store
            .recovery_download_decision(approval, &self.subject)
            .map_err(error_code)?;
        Ok(json!({
            "approval_id": alloy_primitives::hex::encode(approval.0),
            "transfer_id": alloy_primitives::hex::encode(decision.transfer_id.0.0),
            "state": decision.state,
            "expires_at_ms": decision.expires_at_ms,
        }))
    }

    pub(super) fn download(
        &self,
        port: &DownloadPort,
        args: RecoveryDownloadArgs,
    ) -> Result<Value, ErrorCode> {
        let transfer = TransferId(parse_id(&args.transfer_id)?);
        let mut attempts = self.download_attempts.borrow_mut();
        attempts.retain(|id, attempt| {
            !matches!(
                self.store.recovery_download(id, &self.subject),
                Err(AslError::NotFound | AslError::PolicyDenied | AslError::ExpiredMessage)
            ) && attempt.poll()
        });
        let state = self
            .store
            .recovery_download(&transfer, &self.subject)
            .map_err(error_code)?;
        let (status, bytes, error) = match state {
            RecoveryDownload::Complete => {
                attempts.remove(&transfer);
                ("completed", None, None)
            }
            RecoveryDownload::Resumable { durable_bytes } => {
                if args.resume
                    && !matches!(
                        attempts.get(&transfer),
                        Some(DownloadAttempt::Queued(_) | DownloadAttempt::Started(_))
                    )
                {
                    if !attempts.contains_key(&transfer) && attempts.len() == MAX_DOWNLOAD_ATTEMPTS
                    {
                        return Err(ErrorCode::QuotaExceeded);
                    }
                    let ticket = port
                        .submit(DownloadJob::ResumeForHost {
                            transfer_id: transfer.clone(),
                            subject: self.subject,
                        })
                        .map_err(error_code)?;
                    attempts.insert(transfer.clone(), DownloadAttempt::Queued(ticket));
                }
                let (status, error) = match attempts.get(&transfer) {
                    Some(DownloadAttempt::Queued(_)) => ("queued", None),
                    Some(DownloadAttempt::Started(_)) => ("started", None),
                    Some(DownloadAttempt::Failed(error)) => ("failed", Some(*error)),
                    None => ("resumable", None),
                };
                (status, Some(durable_bytes), error)
            }
        };
        Ok(json!({
            "transfer_id": alloy_primitives::hex::encode(transfer.0.0),
            "status": status,
            "durable_bytes": bytes,
            "error": error,
        }))
    }
}

impl DownloadAttempt {
    fn poll(&mut self) -> bool {
        match self {
            Self::Queued(ticket) | Self::Started(ticket) => match ticket.try_recv() {
                Ok(Some(DownloadEvent::Started(_))) => {
                    let previous = std::mem::replace(self, Self::Failed(ErrorCode::InternalError));
                    if let Self::Queued(ticket) | Self::Started(ticket) = previous {
                        *self = Self::Started(ticket);
                    }
                }
                Ok(Some(DownloadEvent::Completed(_))) => return false,
                Ok(Some(DownloadEvent::Failed(error))) | Err(error) => {
                    *self = Self::Failed(error_code(error));
                }
                Ok(Some(DownloadEvent::AwaitingApproval { .. })) => {
                    *self = Self::Failed(ErrorCode::InternalError);
                }
                Ok(None) => {}
            },
            Self::Failed(_) => {}
        }
        true
    }
}

fn now() -> Result<i64, AslError> {
    i64::try_from(unix_time_ms()?).map_err(|_| AslError::InvalidMessage)
}
