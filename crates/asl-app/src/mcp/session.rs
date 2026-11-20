use std::{collections::VecDeque, time::Duration};

use alloy_primitives::hex;
use asl_agent::{MAX_QUERY_PEERS, OutgoingTask, QUERY_WINDOW_MS, QueryScope, QueryStatus};
use asl_types::{
    error::{AslError, ErrorCode},
    ids::Id128,
    protocol::{
        Answer, AnswerStatus, Claim, ConceptRef, MediaKind, Offer, ResultStatus, TypedValue,
        WireFrame,
    },
    task::{TaskId, TransferId},
};
use rand::{TryRng, rngs::SysRng};
use serde_json::{Value, json};
use tokio::time::{Instant, sleep_until};

use crate::{
    direct_outbound::{OutgoingQueryEvent, OutgoingQueryPort, OutgoingQueryTicket},
    downloads::{
        DownloadEvent, DownloadJob, DownloadPort, DownloadSelection, DownloadSource, DownloadTicket,
    },
    supervisor::unix_time_ms,
};

use super::contract::{FetchArgs, QueryArgs, Request};

const MAX_TASKS: usize = 16;
const MAX_TERMS: usize = 12;
const QUERY_BUDGET: u8 = 3;
// MCP sends both the structured object and a JSON text copy in the same reply.
const MAX_ANSWER_BYTES: usize = 12 * 1024;
const FETCH_WAIT: Duration = Duration::from_secs(1);
const FETCH_POLL: Duration = Duration::from_millis(25);

pub(super) struct Session<'a> {
    queries: &'a OutgoingQueryPort,
    downloads: &'a DownloadPort,
    scope: QueryScope,
    inbox: Option<Id128>,
    tasks: VecDeque<Task>,
}

impl<'a> Session<'a> {
    pub(super) fn new(
        queries: &'a OutgoingQueryPort,
        downloads: &'a DownloadPort,
        scope: QueryScope,
        inbox: Option<Id128>,
    ) -> Self {
        Self {
            queries,
            downloads,
            scope,
            inbox,
            tasks: VecDeque::new(),
        }
    }

    pub(super) async fn call(&mut self, request: Request) -> Result<Value, ErrorCode> {
        match request {
            Request::Query(args) => self.query(args),
            Request::TaskStatus(args) => self.report(&args.task_id, false),
            Request::Fetch(args) => self.fetch(args).await,
            Request::Result(args) => self.report(&args.task_id, true),
        }
    }

    fn query(&mut self, args: QueryArgs) -> Result<Value, ErrorCode> {
        if !(1..=MAX_TERMS).contains(&args.terms.len())
            || !(1..=QUERY_WINDOW_MS).contains(&args.deadline_ms)
        {
            return Err(ErrorCode::InvalidMessage);
        }
        let scope = args.audience.into();
        if self.scope == QueryScope::ContactsOnly && scope == QueryScope::Public {
            return Err(ErrorCode::PolicyDenied);
        }
        let now = unix_time_ms().map_err(error_code)?;
        let task = OutgoingTask::new(
            now,
            args.query.intent.into(),
            args.terms
                .into_iter()
                .map(|(vocabulary_id, concept_id)| ConceptRef {
                    vocabulary_id,
                    concept_id,
                })
                .collect(),
            Vec::new(),
            args.query.result_shape.into(),
            QUERY_BUDGET,
            scope,
        )
        .with_expiry(now.saturating_add(args.deadline_ms));
        task.validate().map_err(error_code)?;

        let replace = if self.tasks.len() == MAX_TASKS {
            Some(
                self.tasks
                    .iter_mut()
                    .position(|task| {
                        task.poll();
                        task.can_evict(now)
                    })
                    .ok_or(ErrorCode::QuotaExceeded)?,
            )
        } else {
            None
        };
        let id = fresh_id(|id| self.tasks.iter().any(|task| task.id == id))?;
        let ticket = self.queries.submit_scoped(task).map_err(error_code)?;
        if let Some(index) = replace {
            self.tasks.remove(index);
        }
        self.tasks.push_back(Task::new(id, ticket));
        Ok(json!({ "task_id": hex::encode(id.0) }))
    }

    fn report(&mut self, id: &str, final_result: bool) -> Result<Value, ErrorCode> {
        let task = find_task(&mut self.tasks, id)?;
        task.poll();
        if final_result && task.query.is_some() {
            return Err(ErrorCode::Busy);
        }
        Ok(task.report(unix_time_ms().map_err(error_code)?, final_result))
    }

    async fn fetch(&mut self, args: FetchArgs) -> Result<Value, ErrorCode> {
        let task = find_task(&mut self.tasks, &args.task_id)?;
        let offer_id = parse_id(&args.offer_id)?;
        task.poll();
        let offer = task
            .offers
            .iter_mut()
            .find(|offer| offer.id == offer_id)
            .ok_or(ErrorCode::NotFound)?;
        let inbox = self.inbox.ok_or(ErrorCode::PolicyDenied)?;
        let download = offer.select(self.downloads, inbox)?;
        download.wait_for_reference(offer_id).await
    }
}

struct Task {
    id: Id128,
    query: Option<OutgoingQueryTicket>,
    state: QueryState,
    offers: Vec<LocalOffer>,
    answers: Vec<Value>,
    answer_bytes: usize,
    answers_truncated: bool,
}

enum QueryState {
    Queued,
    Active(TaskId),
    Complete,
    Expired,
    Failed(ErrorCode),
}

impl Task {
    fn new(id: Id128, ticket: OutgoingQueryTicket) -> Self {
        Self {
            id,
            query: Some(ticket),
            state: QueryState::Queued,
            offers: Vec::new(),
            answers: Vec::new(),
            answer_bytes: 0,
            answers_truncated: false,
        }
    }

    fn poll(&mut self) {
        while let Some(ticket) = &mut self.query {
            match ticket.try_recv_event() {
                Ok(Some(event)) => self.accept(event),
                Ok(None) => break,
                Err(error) => self.finish(QueryState::Failed(error_code(error))),
            }
        }
        for download in self
            .offers
            .iter_mut()
            .filter_map(|offer| offer.download.as_mut())
        {
            download.poll();
        }
    }

    fn accept(&mut self, event: OutgoingQueryEvent) {
        match event {
            OutgoingQueryEvent::TaskStarted { task_id }
                if matches!(self.state, QueryState::Queued) =>
            {
                self.state = QueryState::Active(task_id);
            }
            OutgoingQueryEvent::Response {
                task_id,
                agent_id,
                peer_id,
                frame,
            } if matches!(&self.state, QueryState::Active(id) if id == &task_id) => {
                let source = DownloadSource { agent_id, peer_id };
                match *frame {
                    WireFrame::Answer(answer) if answer.root_task_id == task_id.0 => {
                        self.record_answer(&source, answer);
                    }
                    WireFrame::Offer(offer)
                        if offer.root_task_id == task_id.0
                            && self.offers.len() < MAX_QUERY_PEERS =>
                    {
                        match fresh_id(|id| self.offers.iter().any(|offer| offer.id == id)) {
                            Ok(id) => self.offers.push(LocalOffer {
                                id,
                                offer,
                                source,
                                download: None,
                            }),
                            Err(code) => self.finish(QueryState::Failed(code)),
                        }
                    }
                    _ => {}
                }
            }
            OutgoingQueryEvent::TaskFinished { task_id, status } => {
                let state = if matches!(&self.state, QueryState::Active(id) if id == &task_id) {
                    match status {
                        QueryStatus::Complete => QueryState::Complete,
                        QueryStatus::Expired => QueryState::Expired,
                        QueryStatus::Active => QueryState::Failed(ErrorCode::InternalError),
                    }
                } else {
                    QueryState::Failed(ErrorCode::InternalError)
                };
                self.finish(state);
            }
            OutgoingQueryEvent::TaskFailed { code } => self.finish(QueryState::Failed(code)),
            _ => {}
        }
    }

    fn finish(&mut self, state: QueryState) {
        self.state = state;
        self.query = None;
    }

    fn can_evict(&self, now: u64) -> bool {
        self.query.is_none()
            && self.offers.iter().all(|entry| {
                entry.offer.expires_at_ms <= now
                    && !entry
                        .download
                        .as_ref()
                        .is_some_and(|download| download.ticket.is_some())
            })
    }

    fn record_answer(&mut self, source: &DownloadSource, answer: Answer) {
        let status = match answer.status {
            AnswerStatus::Answered => "answered",
            AnswerStatus::NoMatch => "no_match",
            AnswerStatus::Declined => "declined",
            AnswerStatus::Unsupported => "unsupported",
        };
        let result_status = match answer.result_status {
            ResultStatus::Complete => "complete",
            ResultStatus::Partial => "partial",
            ResultStatus::Unverified => "unverified",
        };
        let mut result = json!({
            "source": source_value(source),
            "status": status,
            "result_status": result_status,
            "created_at_ms": answer.created_at_ms,
            "expires_at_ms": answer.expires_at_ms,
            "evidence_ids": answer.evidence_ids.iter().map(|id| hex::encode(id.0)).collect::<Vec<_>>(),
            "claims": [],
        });
        if self.answers.len() == MAX_QUERY_PEERS || !self.charge_answer(&result) {
            self.answers_truncated = true;
            return;
        }
        let mut claims = Vec::new();
        for claim in answer.claims {
            let value = claim_value(claim);
            if !self.charge_answer(&value) {
                self.answers_truncated = true;
                break;
            }
            claims.push(value);
        }
        result["claims"] = Value::Array(claims);
        self.answers.push(result);
    }

    fn charge_answer(&mut self, value: &Value) -> bool {
        let Ok(bytes) = serde_json::to_vec(value) else {
            return false;
        };
        let cost = bytes.len() + 1; // Include a possible array separator.
        if self.answer_bytes + cost > MAX_ANSWER_BYTES {
            return false;
        }
        self.answer_bytes += cost;
        true
    }

    fn report(&self, now: u64, final_result: bool) -> Value {
        let (status, error) = match self.state {
            QueryState::Queued => ("queued", None),
            QueryState::Active(_) => ("active", None),
            QueryState::Complete => ("complete", None),
            QueryState::Expired => ("expired", None),
            QueryState::Failed(code) => ("failed", Some(code)),
        };
        let offers = self
            .offers
            .iter()
            .filter(|entry| now < entry.offer.expires_at_ms)
            .map(LocalOffer::value)
            .collect::<Vec<_>>();
        let downloads = self
            .offers
            .iter()
            .filter_map(|entry| Some(entry.download.as_ref()?.value(entry.id)))
            .collect::<Vec<_>>();
        let mut value = json!({
            "task_id": hex::encode(self.id.0),
            "status": status,
            "error": error,
            "answer_count": self.answers.len(),
            "offers": offers,
            "downloads": downloads,
        });
        if final_result {
            value["answers"] = Value::Array(self.answers.clone());
            value["answers_truncated"] = json!(self.answers_truncated);
        }
        value
    }
}

struct LocalOffer {
    id: Id128,
    offer: Offer,
    source: DownloadSource,
    download: Option<Download>,
}

impl LocalOffer {
    fn select(&mut self, port: &DownloadPort, inbox: Id128) -> Result<&mut Download, ErrorCode> {
        if self.download.is_none() {
            if self.offer.expires_at_ms <= unix_time_ms().map_err(error_code)? {
                return Err(ErrorCode::Timeout);
            }
            let content_id = self.offer.content_id;
            let ticket = port
                .submit(DownloadJob::Fetch(DownloadSelection {
                    content_id,
                    inbox_grant: inbox,
                    filename: format!("asl-{}.bin", hex::encode(content_id.0)),
                    sources: vec![self.source.clone()],
                }))
                .map_err(error_code)?;
            // Keep the accepted job even if the caller times out before it has a transfer ID.
            self.download = Some(Download {
                ticket: Some(ticket),
                state: DownloadState::Queued,
            });
        }
        self.download.as_mut().ok_or(ErrorCode::InternalError)
    }

    fn value(&self) -> Value {
        let media_kind = match self.offer.media_kind {
            MediaKind::Other => "other",
            MediaKind::Document => "document",
            MediaKind::Image => "image",
            MediaKind::Audio => "audio",
            MediaKind::Video => "video",
            MediaKind::Archive => "archive",
            MediaKind::StructuredData => "structured_data",
        };
        json!({
            "offer_id": hex::encode(self.id.0),
            "source": source_value(&self.source),
            "content_id": hex::encode(self.offer.content_id.0),
            "file_size": self.offer.file_size,
            "media_kind": media_kind,
            "concepts": self.offer.concepts.iter().copied().map(concept_pair).collect::<Vec<_>>(),
            "expires_at_ms": self.offer.expires_at_ms,
        })
    }
}

struct Download {
    ticket: Option<DownloadTicket>,
    state: DownloadState,
}

enum DownloadState {
    Queued,
    AwaitingApproval(TransferId),
    Started(TransferId),
    Completed(TransferId),
    Failed(Option<TransferId>, ErrorCode),
}

impl Download {
    fn poll(&mut self) {
        while let Some(ticket) = &self.ticket {
            match ticket.try_recv() {
                Ok(Some(event)) => self.accept(event),
                Ok(None) => break,
                Err(error) => self.fail(error_code(error)),
            }
        }
    }

    fn accept(&mut self, event: DownloadEvent) {
        let next = match event {
            DownloadEvent::AwaitingApproval { transfer_id, .. } => {
                DownloadState::AwaitingApproval(transfer_id)
            }
            DownloadEvent::Started(info) => DownloadState::Started(info.transfer_id),
            DownloadEvent::Completed(info) => DownloadState::Completed(info.transfer_id),
            DownloadEvent::Failed(error) => {
                self.fail(error_code(error));
                return;
            }
        };
        if self
            .state
            .transfer_id()
            .is_some_and(|id| next.transfer_id() != Some(id))
        {
            self.fail(ErrorCode::InternalError);
            return;
        }
        if matches!(next, DownloadState::Completed(_)) {
            self.ticket = None;
        }
        self.state = next;
    }

    fn fail(&mut self, code: ErrorCode) {
        self.state = DownloadState::Failed(self.state.transfer_id().cloned(), code);
        self.ticket = None;
    }

    async fn wait_for_reference(&mut self, offer_id: Id128) -> Result<Value, ErrorCode> {
        let deadline = Instant::now() + FETCH_WAIT;
        loop {
            self.poll();
            match self.state {
                DownloadState::Queued => {}
                DownloadState::Failed(_, code) => return Err(code),
                _ => return Ok(self.value(offer_id)),
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(ErrorCode::Timeout);
            }
            sleep_until((now + FETCH_POLL).min(deadline)).await;
        }
    }

    fn value(&self, offer_id: Id128) -> Value {
        let (status, error) = match self.state {
            DownloadState::Queued => ("queued", None),
            DownloadState::AwaitingApproval(_) => ("awaiting_approval", None),
            DownloadState::Started(_) => ("started", None),
            DownloadState::Completed(_) => ("completed", None),
            DownloadState::Failed(_, code) => ("failed", Some(code)),
        };
        json!({
            "offer_id": hex::encode(offer_id.0),
            "transfer_id": self.state.transfer_id().map(|id| hex::encode(id.0.as_bytes())),
            "status": status,
            "error": error,
        })
    }
}

impl DownloadState {
    fn transfer_id(&self) -> Option<&TransferId> {
        match self {
            Self::Queued => None,
            Self::AwaitingApproval(id) | Self::Started(id) | Self::Completed(id) => Some(id),
            Self::Failed(id, _) => id.as_ref(),
        }
    }
}

fn find_task<'a>(tasks: &'a mut VecDeque<Task>, id: &str) -> Result<&'a mut Task, ErrorCode> {
    let id = parse_id(id)?;
    tasks
        .iter_mut()
        .find(|task| task.id == id)
        .ok_or(ErrorCode::NotFound)
}

fn parse_id(id: &str) -> Result<Id128, ErrorCode> {
    if id.len() != Id128::LENGTH * 2 {
        return Err(ErrorCode::InvalidMessage);
    }
    let mut bytes = [0; Id128::LENGTH];
    hex::decode_to_slice(id, &mut bytes).map_err(|_| ErrorCode::InvalidMessage)?;
    Ok(Id128(bytes))
}

fn fresh_id(exists: impl Fn(Id128) -> bool) -> Result<Id128, ErrorCode> {
    for _ in 0..8 {
        let mut bytes = [0; Id128::LENGTH];
        SysRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| ErrorCode::InternalError)?;
        if bytes != [0; Id128::LENGTH] && !exists(Id128(bytes)) {
            return Ok(Id128(bytes));
        }
    }
    Err(ErrorCode::InternalError)
}

fn source_value(source: &DownloadSource) -> Value {
    json!({
        "agent_id": hex::encode(source.agent_id.0),
        "peer_id": hex::encode(source.peer_id.as_bytes()),
    })
}

fn concept_pair(concept: ConceptRef) -> (u16, u32) {
    (concept.vocabulary_id, concept.concept_id)
}

fn claim_value(claim: Claim) -> Value {
    json!({
        "subject": typed_value(claim.subject),
        "predicate": concept_pair(claim.predicate),
        "object": typed_value(claim.object),
        "evidence": claim.evidence.map(|hash| hex::encode(hash.0)),
    })
}

fn typed_value(value: TypedValue) -> Value {
    match value {
        TypedValue::Integer(value) => json!({ "type": "integer", "value": value }),
        TypedValue::Boolean(value) => json!({ "type": "boolean", "value": value }),
        TypedValue::Null => json!({ "type": "null", "value": null }),
        TypedValue::Hash(value) => json!({ "type": "hash", "value": hex::encode(value.0) }),
        TypedValue::Agent(value) => json!({ "type": "agent", "value": hex::encode(value.0) }),
        TypedValue::Concept(value) => json!({ "type": "concept", "value": concept_pair(value) }),
        TypedValue::Quantity(value, unit) => {
            json!({ "type": "quantity", "value": value, "unit": concept_pair(unit) })
        }
        TypedValue::Concepts(values) => json!({
            "type": "concepts",
            "value": values.into_iter().map(concept_pair).collect::<Vec<_>>(),
        }),
    }
}

fn error_code(error: AslError) -> ErrorCode {
    match error {
        AslError::InvalidMessage => ErrorCode::InvalidMessage,
        AslError::IncompatibleVersion => ErrorCode::IncompatibleVersion,
        AslError::ExpiredMessage => ErrorCode::Timeout,
        AslError::PolicyDenied => ErrorCode::PolicyDenied,
        AslError::GrantRevoked => ErrorCode::GrantRevoked,
        AslError::QuotaExceeded => ErrorCode::QuotaExceeded,
        AslError::NotFound => ErrorCode::NotFound,
        AslError::SandboxUnavailable => ErrorCode::SandboxUnavailable,
        AslError::Io(error) if error.kind() == std::io::ErrorKind::StorageFull => {
            ErrorCode::DiskFull
        }
        _ => ErrorCode::InternalError,
    }
}

#[cfg(test)]
mod tests;
