//! Authenticated local host to Core. Only Core resolves destinations and file offers.
use std::collections::{HashMap, VecDeque};

use alloy_primitives::hex;
use asl_agent::QueryScope;
use asl_store::transfers::GroupTransferBinding;
use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128},
    protocol::{Expression, Offer, WireFrame},
};
use serde_json::{Value, json};
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, mpsc, oneshot};

use crate::{
    downloads::{DownloadSelection, DownloadSource},
    profile::fresh_id,
};

const EVENT_LIMIT: usize = 32;
const HANDLE_LIMIT: usize = 32;
const REPLAY_LIMIT: usize = 256;
const MAIL_TTL_MS: u64 = 60_000;
pub(crate) type InboxDecision = oneshot::Receiver<Result<Id128, AslError>>;

#[derive(Clone, Debug)]
pub(crate) struct MailEvent {
    pub(crate) kind: &'static str,
    pub(crate) details: Value,
}

#[derive(Clone, Copy)]
pub(crate) enum Target {
    Agent(AgentId),
    Group(Hash32),
}

impl Target {
    fn parse(target: &str) -> Result<Self, AslError> {
        let (kind, id) = target.split_once(':').ok_or(AslError::InvalidMessage)?;
        let id: [u8; 32] = hex::decode_to_array(id).map_err(|_| AslError::InvalidMessage)?;
        match kind {
            "agent" => Ok(Self::Agent(AgentId(id))),
            "group" => Ok(Self::Group(Hash32(id))),
            _ => Err(AslError::InvalidMessage),
        }
    }
}

pub(crate) enum MailCommand {
    Send {
        target: Target,
        scope: QueryScope,
        root: Option<Id128>,
        expression: Expression,
        reply: oneshot::Sender<Result<Id128, AslError>>,
    },
    Claim {
        handle: Id128,
        inbox: Id128,
        scope: QueryScope,
        reply: oneshot::Sender<Result<DownloadSelection, AslError>>,
    },
    RequestInbox {
        handle: Id128,
        scope: QueryScope,
        reply: oneshot::Sender<Result<InboxDecision, AslError>>,
    },
    RequestTaskInbox {
        reply: oneshot::Sender<Result<InboxDecision, AslError>>,
    },
}

#[derive(Clone)]
pub(crate) struct MailPort {
    commands: mpsc::Sender<MailCommand>,
    events: broadcast::Sender<MailEvent>,
}

impl MailPort {
    pub(crate) async fn request_task_inbox(&self) -> Result<InboxDecision, AslError> {
        let (reply, result) = oneshot::channel();
        self.submit(MailCommand::RequestTaskInbox { reply })?;
        result.await.map_err(|_| AslError::SandboxUnavailable)?
    }
    pub(crate) async fn request_inbox(
        &self,
        handle: Id128,
        scope: QueryScope,
    ) -> Result<InboxDecision, AslError> {
        let (reply, result) = oneshot::channel();
        self.submit(MailCommand::RequestInbox {
            handle,
            scope,
            reply,
        })?;
        result.await.map_err(|_| AslError::SandboxUnavailable)?
    }
    pub(crate) fn subscribe(&self) -> broadcast::Receiver<MailEvent> {
        self.events.subscribe()
    }

    fn submit(&self, command: MailCommand) -> Result<(), AslError> {
        self.commands
            .try_send(command)
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => AslError::QuotaExceeded,
                mpsc::error::TrySendError::Closed(_) => AslError::SandboxUnavailable,
            })
    }

    pub(crate) async fn send_expression(
        &self,
        scope: QueryScope,
        target: String,
        root: Option<Id128>,
        expression: Expression,
    ) -> Result<Id128, AslError> {
        let (reply, result) = oneshot::channel();
        self.submit(MailCommand::Send {
            target: Target::parse(&target)?,
            scope,
            root,
            expression,
            reply,
        })?;
        result.await.map_err(|_| AslError::SandboxUnavailable)?
    }

    pub(crate) async fn claim_offer(
        &self,
        handle: Id128,
        inbox: Id128,
        scope: QueryScope,
    ) -> Result<DownloadSelection, AslError> {
        let (reply, result) = oneshot::channel();
        self.submit(MailCommand::Claim {
            handle,
            inbox,
            scope,
            reply,
        })?;
        result.await.map_err(|_| AslError::SandboxUnavailable)?
    }
}

pub(crate) struct HeldOffer {
    pub(crate) source: DownloadSource,
    pub(crate) connection: [u8; 16],
    pub(crate) room: Option<(Hash32, u64, GroupTransferBinding)>,
    content: Hash32,
    expires: u64,
}

impl HeldOffer {
    pub(crate) fn selection(self, inbox_grant: Id128) -> DownloadSelection {
        DownloadSelection {
            content_id: self.content,
            inbox_grant,
            filename: format!("asl-{}.bin", hex::encode(self.content.0)),
            sources: vec![self.source],
            group: self.room.map(|(_, _, binding)| binding),
        }
    }
}

pub(crate) struct Mailbox {
    pub(crate) port: MailPort,
    pub(crate) commands: mpsc::Receiver<MailCommand>,
    offers: HashMap<Id128, HeldOffer>,
    seen: VecDeque<(AgentId, Id128, u64)>,
    recent: VecDeque<u64>,
    permission: Option<InboxWaiter>,
}

struct InboxWaiter {
    request: Id128,
    next_check: Instant,
    decision: oneshot::Sender<Result<Id128, AslError>>,
}

impl Default for Mailbox {
    fn default() -> Self {
        let (commands, receiver) = mpsc::channel(8);
        Self {
            port: MailPort {
                commands,
                events: broadcast::channel(EVENT_LIMIT).0,
            },
            commands: receiver,
            offers: HashMap::new(),
            seen: VecDeque::new(),
            recent: VecDeque::new(),
            permission: None,
        }
    }
}

impl Mailbox {
    pub(crate) fn request_inbox_binding(
        &mut self,
        store: &asl_store::Store,
        now: u64,
    ) -> Result<InboxDecision, AslError> {
        if self.permission.is_some() {
            return Err(AslError::QuotaExceeded);
        }
        let request = Id128(fresh_id()?);
        store.request_host_inbox(request, now)?;
        let (decision, result) = oneshot::channel();
        self.permission = Some(InboxWaiter {
            request,
            next_check: Instant::now(),
            decision,
        });
        Ok(result)
    }

    pub(crate) fn poll_inbox_binding(&mut self, store: &asl_store::Store) {
        let Some(waiter) = self.permission.as_mut() else {
            return;
        };
        let now = Instant::now();
        if now < waiter.next_check {
            return;
        }
        waiter.next_check = now + Duration::from_millis(500);
        let result = crate::supervisor::unix_time_ms().and_then(|ms| {
            if waiter.decision.is_closed() {
                let _ = store.decide_host_inbox(waiter.request, None, ms);
                return Err(AslError::PolicyDenied);
            }
            store.host_inbox_decision(waiter.request, ms)
        });
        let decision = match result {
            Ok(None) => return,
            Ok(Some(grant)) => Ok(grant),
            Err(error) => Err(error),
        };
        let waiter = self.permission.take().unwrap();
        let _ = waiter.decision.send(decision);
    }

    pub(crate) fn interested(&self) -> bool {
        self.port.events.receiver_count() != 0
    }

    // The global budget is shared by all identities and rooms. Duplicates
    // consume neither a host notification nor a new pending file selection.
    fn admit(&mut self, agent: AgentId, id: Id128, expires: u64, now: u64) -> bool {
        self.seen.retain(|(_, _, expiry)| *expiry > now);
        self.recent.retain(|at| now.saturating_sub(*at) < 1000);
        if !self.interested()
            || now >= expires
            || self.recent.len() >= 8
            || self.seen.len() >= REPLAY_LIMIT
            || self
                .seen
                .iter()
                .any(|(source, message, _)| *source == agent && *message == id)
        {
            return false;
        }
        self.recent.push_back(now);
        self.seen
            .push_back((agent, id, expires.min(now.saturating_add(MAIL_TTL_MS))));
        true
    }

    pub(crate) fn observe(
        &mut self,
        source: DownloadSource,
        connection: [u8; 16],
        room: Option<(Hash32, u64, GroupTransferBinding)>,
        frame: &WireFrame,
        now: u64,
    ) -> bool {
        let (kind, id, root, created, expiry) = match frame {
            WireFrame::Expression(e) => (
                "expression",
                e.message_id,
                e.root_task_id,
                e.created_at_ms,
                e.expires_at_ms,
            ),
            WireFrame::Query(q) => (
                "query",
                q.message_id,
                q.root_task_id,
                q.created_at_ms,
                q.expires_at_ms,
            ),
            WireFrame::Offer(o) => (
                "file_offer",
                o.message_id,
                o.root_task_id,
                0,
                o.expires_at_ms,
            ),
            WireFrame::Answer(a) => (
                "answer",
                a.message_id,
                a.root_task_id,
                a.created_at_ms,
                a.expires_at_ms,
            ),
            _ => return false,
        };
        if created > now || !self.admit(source.agent_id, id, expiry, now) {
            return false;
        }
        let mut details = json!({
            "agent": format!("agent:{}", hex::encode(source.agent_id.0)),
            "room": room.as_ref().map(|(id,_,_)| format!("group:{}", hex::encode(id.0))),
            "message_id": hex::encode(id.0), "root_task_id": hex::encode(root.0), "expires_at_ms": expiry,
        });
        match frame {
            WireFrame::Expression(e) => details["expression"] = e.expression.to_json(),
            WireFrame::Offer(Offer {
                content_id,
                file_size,
                ..
            }) => {
                self.offers.retain(|_, offer| offer.expires > now);
                if self.offers.len() >= HANDLE_LIMIT {
                    return false;
                }
                let Ok(handle) = fresh_id().map(Id128) else {
                    return false;
                };
                details["offer_id"] = json!(hex::encode(handle.0));
                details["content_id"] = json!(hex::encode(content_id.0));
                details["file_size"] = json!(file_size);
                self.offers.insert(
                    handle,
                    HeldOffer {
                        source,
                        connection,
                        room,
                        content: *content_id,
                        expires: expiry.min(now.saturating_add(MAIL_TTL_MS)),
                    },
                );
            }
            WireFrame::Query(_) | WireFrame::Answer(_) => {
                // Exact, already typed ASL/1 payload; no re-interpretation as text.
                let Ok(bytes) = asl_types::protocol::encode_control(frame) else {
                    return false;
                };
                if bytes.len() > 12 * 1024 {
                    return false;
                }
                details["control_cbor_hex"] = json!(hex::encode(bytes));
            }
            _ => return false,
        }
        self.port.events.send(MailEvent { kind, details }).is_ok()
    }

    pub(crate) fn take_offer(&mut self, id: Id128, now: u64) -> Result<HeldOffer, AslError> {
        self.offers
            .remove(&id)
            .filter(|offer| now < offer.expires)
            .ok_or(AslError::NotFound)
    }
    pub(crate) fn live_offer(&self, id: Id128, now: u64) -> Result<&HeldOffer, AslError> {
        self.offers
            .get(&id)
            .filter(|offer| now < offer.expires)
            .ok_or(AslError::NotFound)
    }
}
