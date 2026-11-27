//! Authenticated local host to Core. Only Core resolves destinations and file offers.
use std::collections::{HashMap, VecDeque};

use alloy_primitives::hex;
use asl_agent::QueryScope;
use asl_store::transfers::GroupTransferBinding;
use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128},
    protocol::{
        Act, ContextAgreement, ContextAgreementStatus, ContextExpression, ContextOffer, Expression,
        Offer, SemanticContextRef, WireFrame,
    },
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
const CONTEXT_REQUEST_LIMIT: usize = 32;
const MAIL_TTL_MS: u64 = 10 * 60_000;
pub(crate) type InboxDecision = oneshot::Receiver<Result<Id128, AslError>>;

#[derive(Clone, Debug)]
pub(crate) struct MailEvent {
    pub(crate) kind: &'static str,
    pub(crate) details: Value,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
    ActHistorySearch {
        query: String,
        limit: u32,
        reply: oneshot::Sender<Result<Value, AslError>>,
    },
    Send {
        target: Target,
        scope: QueryScope,
        root: Option<Id128>,
        expression: Expression,
        reply: oneshot::Sender<Result<Id128, AslError>>,
    },
    SendContextExpression {
        target: Target,
        scope: QueryScope,
        root: Option<Id128>,
        expression: Expression,
        required_contexts: Vec<SemanticContextRef>,
        reply: oneshot::Sender<Result<Id128, AslError>>,
    },
    SendAct {
        room: Hash32,
        act: Act,
        reply: oneshot::Sender<Result<Id128, AslError>>,
    },
    SendFile {
        room: Hash32,
        content_id: Hash32,
        media_kind: asl_types::protocol::MediaKind,
        concepts: Vec<asl_types::protocol::ConceptRef>,
        reply: oneshot::Sender<Result<Value, AslError>>,
    },
    GroupMembers {
        room: Hash32,
        reply: oneshot::Sender<Result<Value, AslError>>,
    },
    GroupSetAccess {
        room: Hash32,
        update: GroupAccessUpdate,
        reply: oneshot::Sender<Result<Value, AslError>>,
    },
    GroupList {
        reply: oneshot::Sender<Result<Value, AslError>>,
    },
    GroupCreate {
        reply: oneshot::Sender<Result<Value, AslError>>,
    },
    GroupInvite {
        room: Hash32,
        agent: AgentId,
        reply: oneshot::Sender<Result<Value, AslError>>,
    },
    GroupInviteRequest {
        room: Hash32,
        owner: AgentId,
        reply: oneshot::Sender<Result<Value, AslError>>,
    },
    GroupRejectJoinRequest {
        room: Hash32,
        device: asl_types::ids::PeerId,
        reply: oneshot::Sender<Result<Value, AslError>>,
    },
    DirectOpen {
        agent: AgentId,
        reply: oneshot::Sender<Result<Value, AslError>>,
    },
    RenewActBudget {
        conversation_id: String,
        additional_messages: u32,
        window_ms: u64,
        reply: oneshot::Sender<Result<Value, AslError>>,
    },
    RenewResourceBudget {
        conversation_id: String,
        kind: asl_store::budgets::BudgetKind,
        additional: u64,
        window_ms: u64,
        reply: oneshot::Sender<Result<Value, AslError>>,
    },
    RequestContext {
        target: Target,
        scope: QueryScope,
        reference: SemanticContextRef,
        reply: oneshot::Sender<Result<Id128, AslError>>,
    },
    ConfirmContext {
        request_id: Id128,
        group: Option<(Hash32, AgentId)>,
        reply: oneshot::Sender<Result<(Id128, ContextAgreementStatus), AslError>>,
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

#[derive(Clone, Debug)]
pub struct GroupAccessUpdate {
    pub allow_member_text: bool,
    pub allow_member_files: bool,
    pub allow_member_invite: bool,
    pub admins: Vec<asl_types::ids::PeerId>,
    pub muted: Vec<asl_types::ids::PeerId>,
    pub owner: Option<asl_types::ids::PeerId>,
    pub file_policies: Option<Vec<asl_types::protocol::GroupFilePolicy>>,
    pub admin_capabilities: Option<Vec<asl_types::protocol::GroupAdminCapability>>,
}

#[derive(Clone)]
pub(crate) struct MailPort {
    commands: mpsc::Sender<MailCommand>,
    events: broadcast::Sender<MailEvent>,
}

impl MailPort {
    pub(crate) async fn act_history_search(
        &self,
        query: String,
        limit: u32,
    ) -> Result<Value, AslError> {
        let (reply, result) = oneshot::channel();
        self.submit(MailCommand::ActHistorySearch {
            query,
            limit,
            reply,
        })?;
        result.await.map_err(|_| AslError::SandboxUnavailable)?
    }

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

    pub(crate) async fn send_context_expression(
        &self,
        scope: QueryScope,
        target: String,
        root: Option<Id128>,
        expression: Expression,
        required_contexts: Vec<SemanticContextRef>,
    ) -> Result<Id128, AslError> {
        let (reply, result) = oneshot::channel();
        self.submit(MailCommand::SendContextExpression {
            target: Target::parse(&target)?,
            scope,
            root,
            expression,
            required_contexts,
            reply,
        })?;
        result.await.map_err(|_| AslError::SandboxUnavailable)?
    }

    pub(crate) async fn send_act(&self, room: Hash32, act: Act) -> Result<Id128, AslError> {
        let (reply, result) = oneshot::channel();
        self.submit(MailCommand::SendAct { room, act, reply })?;
        result.await.map_err(|_| AslError::SandboxUnavailable)?
    }

    pub(crate) async fn send_file(
        &self,
        room: Hash32,
        content_id: Hash32,
        media_kind: asl_types::protocol::MediaKind,
        concepts: Vec<asl_types::protocol::ConceptRef>,
    ) -> Result<Value, AslError> {
        let (reply, result) = oneshot::channel();
        self.submit(MailCommand::SendFile {
            room,
            content_id,
            media_kind,
            concepts,
            reply,
        })?;
        result.await.map_err(|_| AslError::SandboxUnavailable)?
    }

    pub(crate) async fn group_members(&self, room: Hash32) -> Result<Value, AslError> {
        let (reply, result) = oneshot::channel();
        self.submit(MailCommand::GroupMembers { room, reply })?;
        result.await.map_err(|_| AslError::SandboxUnavailable)?
    }

    pub(crate) async fn group_set_access(
        &self,
        room: Hash32,
        update: GroupAccessUpdate,
    ) -> Result<Value, AslError> {
        let (reply, result) = oneshot::channel();
        self.submit(MailCommand::GroupSetAccess {
            room,
            update,
            reply,
        })?;
        result.await.map_err(|_| AslError::SandboxUnavailable)?
    }

    pub(crate) async fn group_list(&self) -> Result<Value, AslError> {
        let (reply, result) = oneshot::channel();
        self.submit(MailCommand::GroupList { reply })?;
        result.await.map_err(|_| AslError::SandboxUnavailable)?
    }

    pub(crate) async fn group_create(&self) -> Result<Value, AslError> {
        let (reply, result) = oneshot::channel();
        self.submit(MailCommand::GroupCreate { reply })?;
        result.await.map_err(|_| AslError::SandboxUnavailable)?
    }

    pub(crate) async fn group_invite(
        &self,
        room: Hash32,
        agent: AgentId,
    ) -> Result<Value, AslError> {
        let (reply, result) = oneshot::channel();
        self.submit(MailCommand::GroupInvite { room, agent, reply })?;
        result.await.map_err(|_| AslError::SandboxUnavailable)?
    }

    pub(crate) async fn group_invite_request(
        &self,
        room: Hash32,
        owner: AgentId,
    ) -> Result<Value, AslError> {
        let (reply, result) = oneshot::channel();
        self.submit(MailCommand::GroupInviteRequest { room, owner, reply })?;
        result.await.map_err(|_| AslError::SandboxUnavailable)?
    }

    pub(crate) async fn group_reject_join_request(
        &self,
        room: Hash32,
        device: asl_types::ids::PeerId,
    ) -> Result<Value, AslError> {
        let (reply, result) = oneshot::channel();
        self.submit(MailCommand::GroupRejectJoinRequest {
            room,
            device,
            reply,
        })?;
        result.await.map_err(|_| AslError::SandboxUnavailable)?
    }

    pub(crate) async fn direct_open(&self, agent: AgentId) -> Result<Value, AslError> {
        let (reply, result) = oneshot::channel();
        self.submit(MailCommand::DirectOpen { agent, reply })?;
        result.await.map_err(|_| AslError::SandboxUnavailable)?
    }

    pub(crate) async fn renew_act_budget(
        &self,
        conversation_id: String,
        additional_messages: u32,
        window_ms: u64,
    ) -> Result<Value, AslError> {
        let (reply, result) = oneshot::channel();
        self.submit(MailCommand::RenewActBudget {
            conversation_id,
            additional_messages,
            window_ms,
            reply,
        })?;
        result.await.map_err(|_| AslError::SandboxUnavailable)?
    }

    pub(crate) async fn renew_resource_budget(
        &self,
        conversation_id: String,
        kind: asl_store::budgets::BudgetKind,
        additional: u64,
        window_ms: u64,
    ) -> Result<Value, AslError> {
        let (reply, result) = oneshot::channel();
        self.submit(MailCommand::RenewResourceBudget {
            conversation_id,
            kind,
            additional,
            window_ms,
            reply,
        })?;
        result.await.map_err(|_| AslError::SandboxUnavailable)?
    }

    pub(crate) async fn request_context(
        &self,
        scope: QueryScope,
        target: String,
        reference: SemanticContextRef,
    ) -> Result<Id128, AslError> {
        let target = Target::parse(&target)?;
        let (reply, result) = oneshot::channel();
        self.submit(MailCommand::RequestContext {
            target,
            scope,
            reference,
            reply,
        })?;
        result.await.map_err(|_| AslError::SandboxUnavailable)?
    }

    pub(crate) async fn confirm_context(
        &self,
        request_id: Id128,
        group: Option<(Hash32, AgentId)>,
    ) -> Result<(Id128, ContextAgreementStatus), AslError> {
        let (reply, result) = oneshot::channel();
        self.submit(MailCommand::ConfirmContext {
            request_id,
            group,
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
    context_ref: Option<SemanticContextRef>,
}

impl HeldOffer {
    pub(crate) fn selection(self, inbox_grant: Id128) -> DownloadSelection {
        let extension = if self.context_ref.is_some() {
            "aslc"
        } else {
            "bin"
        };
        DownloadSelection {
            content_id: self.content,
            inbox_grant,
            filename: format!("asl-{}.{}", hex::encode(self.content.0), extension),
            sources: vec![self.source],
            group: self.room.map(|(_, _, binding)| binding),
            context_ref: self.context_ref,
        }
    }
}

pub(crate) struct Mailbox {
    pub(crate) port: MailPort,
    pub(crate) commands: mpsc::Receiver<MailCommand>,
    offers: HashMap<Id128, HeldOffer>,
    context_requests: HashMap<([u8; 16], [u8; 16]), PendingContextRequest>,
    group_context_requests: HashMap<(Hash32, [u8; 16]), PendingGroupContextRequest>,
    seen: VecDeque<(AgentId, Id128, u64)>,
    recent: VecDeque<u64>,
    permission: Option<InboxWaiter>,
}

#[derive(Clone)]
pub(crate) struct PendingContextRequest {
    pub(crate) source: DownloadSource,
    pub(crate) scope: QueryScope,
    pub(crate) reference: SemanticContextRef,
    expires: u64,
    offer: Option<Id128>,
}

struct PendingGroupContextRequest {
    reference: SemanticContextRef,
    expires: u64,
    offers: HashMap<AgentId, PendingGroupContextOffer>,
}

#[derive(Clone)]
pub(crate) struct PendingGroupContextOffer {
    pub(crate) source: DownloadSource,
    pub(crate) connection: [u8; 16],
    pub(crate) reference: SemanticContextRef,
    expires: u64,
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
            context_requests: HashMap::new(),
            group_context_requests: HashMap::new(),
            seen: VecDeque::new(),
            recent: VecDeque::new(),
            permission: None,
        }
    }
}

impl Mailbox {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn remember_context_request(
        &mut self,
        source: DownloadSource,
        scope: QueryScope,
        connection: [u8; 16],
        request: Id128,
        reference: SemanticContextRef,
        expires: u64,
        now: u64,
    ) -> Result<(), AslError> {
        self.context_requests
            .retain(|_, pending| pending.expires > now);
        let key = (connection, request.0);
        if request.0 == [0; 16]
            || expires <= now
            || self.context_requests.len() >= CONTEXT_REQUEST_LIMIT
            || self.context_requests.contains_key(&key)
        {
            return Err(AslError::QuotaExceeded);
        }
        self.context_requests.insert(
            key,
            PendingContextRequest {
                source,
                scope,
                reference,
                expires,
                offer: None,
            },
        );
        Ok(())
    }

    pub(crate) fn cancel_context_request(&mut self, connection: [u8; 16], request: Id128) {
        self.context_requests.remove(&(connection, request.0));
    }

    pub(crate) fn context_request_for_confirmation(
        &self,
        request_id: Id128,
        now: u64,
    ) -> Result<([u8; 16], PendingContextRequest), AslError> {
        self.context_requests
            .iter()
            .find(|((_, id), pending)| {
                *id == request_id.0 && pending.expires > now && pending.offer.is_some()
            })
            .map(|((connection, _), pending)| (*connection, pending.clone()))
            .ok_or(AslError::NotFound)
    }

    pub(crate) fn complete_context_request(&mut self, connection: [u8; 16], request: Id128) {
        self.context_requests.remove(&(connection, request.0));
    }

    pub(crate) fn remember_group_context_request(
        &mut self,
        room: Hash32,
        request: Id128,
        reference: SemanticContextRef,
        expires: u64,
        now: u64,
    ) -> Result<(), AslError> {
        self.group_context_requests
            .retain(|_, pending| pending.expires > now);
        let key = (room, request.0);
        if room.0 == [0; 32]
            || request.0 == [0; 16]
            || expires <= now
            || self.group_context_requests.len() >= CONTEXT_REQUEST_LIMIT
            || self.group_context_requests.contains_key(&key)
        {
            return Err(AslError::QuotaExceeded);
        }
        self.group_context_requests.insert(
            key,
            PendingGroupContextRequest {
                reference,
                expires,
                offers: HashMap::new(),
            },
        );
        Ok(())
    }

    pub(crate) fn cancel_group_context_request(&mut self, room: Hash32, request: Id128) {
        self.group_context_requests.remove(&(room, request.0));
    }

    pub(crate) fn group_context_offer_for_confirmation(
        &self,
        request_id: Id128,
        room: Hash32,
        sender: AgentId,
        now: u64,
    ) -> Result<PendingGroupContextOffer, AslError> {
        let pending = self
            .group_context_requests
            .get(&(room, request_id.0))
            .filter(|pending| pending.expires > now)
            .ok_or(AslError::NotFound)?;
        let offer = pending.offers.get(&sender).ok_or(AslError::NotFound)?;
        if offer.reference != pending.reference || offer.expires <= now {
            return Err(AslError::NotFound);
        }
        Ok(offer.clone())
    }

    pub(crate) fn complete_group_context_offer(
        &mut self,
        request_id: Id128,
        room: Hash32,
        sender: AgentId,
    ) {
        if let Some(pending) = self.group_context_requests.get_mut(&(room, request_id.0)) {
            pending.offers.remove(&sender);
        }
    }

    pub(crate) fn prune_context_requests(&mut self, now: u64) {
        self.context_requests
            .retain(|_, pending| pending.expires > now);
        self.group_context_requests
            .retain(|_, pending| pending.expires > now);
    }

    pub(crate) fn observe_context_offer(
        &mut self,
        source: DownloadSource,
        connection: [u8; 16],
        request_id: [u8; 16],
        frame: &WireFrame,
        now: u64,
    ) -> bool {
        let WireFrame::ContextOffer(offer) = frame else {
            return false;
        };
        let key = (connection, request_id);
        let Some(pending) = self.context_requests.get(&key) else {
            return false;
        };
        if pending.expires <= now
            || pending.offer.is_some()
            || pending.source != source
            || offer.request_id.0 != request_id
            || offer.reference != pending.reference
            || offer.expires_at_ms > pending.expires
            || offer.expires_at_ms <= now
            || !self.admit(source.agent_id, offer.message_id, offer.expires_at_ms, now)
        {
            return false;
        }
        self.offers.retain(|_, existing| existing.expires > now);
        if self.offers.len() >= HANDLE_LIMIT {
            return false;
        }
        let Ok(handle) = fresh_id().map(Id128) else {
            return false;
        };
        let details = json!({
            "agent": format!("agent:{}", hex::encode(source.agent_id.0)),
            "message_id": hex::encode(offer.message_id.0),
            "request_id": hex::encode(offer.request_id.0),
            "offer_id": hex::encode(handle.0),
            "context_ref": {
                "authority": hex::encode(offer.reference.authority.0),
                "namespace": offer.reference.namespace,
                "revision": offer.reference.revision,
                "digest": hex::encode(offer.reference.digest.0),
            },
            "content_id": hex::encode(offer.content_id.0),
            "file_size": offer.file_size,
            "expires_at_ms": offer.expires_at_ms,
        });
        self.offers.insert(
            handle,
            HeldOffer {
                source,
                connection,
                room: None,
                content: offer.content_id,
                expires: offer.expires_at_ms.min(now.saturating_add(MAIL_TTL_MS)),
                context_ref: Some(offer.reference),
            },
        );
        if let Some(pending) = self.context_requests.get_mut(&key) {
            pending.offer = Some(handle);
        }
        self.port
            .events
            .send(MailEvent {
                kind: "context_file_offer",
                details,
            })
            .is_ok()
    }

    pub(crate) fn observe_context_agreement(
        &mut self,
        source: DownloadSource,
        connection: [u8; 16],
        request_id: [u8; 16],
        frame: &WireFrame,
        now: u64,
    ) -> bool {
        let WireFrame::ContextAgreement(agreement) = frame else {
            return false;
        };
        let key = (connection, request_id);
        let Some(pending) = self.context_requests.get(&key) else {
            return false;
        };
        if pending.expires <= now
            || pending.source != source
            || agreement.request_id.0 != request_id
            || agreement.reference != pending.reference
            || !self.admit(source.agent_id, agreement.message_id, pending.expires, now)
        {
            return false;
        }
        let status = match agreement.status {
            ContextAgreementStatus::Conformant => 0,
            ContextAgreementStatus::Unresolved => 1,
            ContextAgreementStatus::Rejected => 2,
        };
        self.context_requests.remove(&key);
        self.port
            .events
            .send(MailEvent {
                kind: "context_agreement",
                details: json!({
                    "agent": format!("agent:{}", hex::encode(source.agent_id.0)),
                    "message_id": hex::encode(agreement.message_id.0),
                    "request_id": hex::encode(agreement.request_id.0),
                    "context_ref": {
                        "authority": hex::encode(agreement.reference.authority.0),
                        "namespace": agreement.reference.namespace,
                        "revision": agreement.reference.revision,
                        "digest": hex::encode(agreement.reference.digest.0),
                    },
                    "status": status,
                }),
            })
            .is_ok()
    }

    fn observe_group_context_offer(
        &mut self,
        source: DownloadSource,
        connection: [u8; 16],
        room: (Hash32, u64, GroupTransferBinding),
        offer: ContextOffer,
        now: u64,
    ) -> bool {
        let key = (room.0, offer.request_id.0);
        let Some(pending) = self.group_context_requests.get(&key) else {
            return false;
        };
        if pending.expires <= now
            || offer.expires_at_ms <= now
            || offer.expires_at_ms > pending.expires
            || offer.reference != pending.reference
            || pending.offers.contains_key(&source.agent_id)
            || !self.admit(source.agent_id, offer.message_id, offer.expires_at_ms, now)
        {
            return false;
        }
        self.offers.retain(|_, existing| existing.expires > now);
        if self.offers.len() >= HANDLE_LIMIT {
            return false;
        }
        let Ok(handle) = fresh_id().map(Id128) else {
            return false;
        };
        self.offers.insert(
            handle,
            HeldOffer {
                source: source.clone(),
                connection,
                room: Some(room.clone()),
                content: offer.content_id,
                expires: offer.expires_at_ms.min(now.saturating_add(MAIL_TTL_MS)),
                context_ref: Some(offer.reference),
            },
        );
        let Some(pending) = self.group_context_requests.get_mut(&key) else {
            self.offers.remove(&handle);
            return false;
        };
        pending.offers.insert(
            source.agent_id,
            PendingGroupContextOffer {
                source: source.clone(),
                connection,
                reference: offer.reference,
                expires: offer.expires_at_ms,
            },
        );
        self.port
            .events
            .send(MailEvent {
                kind: "context_file_offer",
                details: json!({
                    "room": format!("group:{}", hex::encode(room.0.0)),
                    "mls_epoch": room.1,
                    "connection_id": hex::encode(connection),
                    "agent": format!("agent:{}", hex::encode(source.agent_id.0)),
                    "sender": format!("agent:{}", hex::encode(source.agent_id.0)),
                    "peer_id": bs58::encode(source.peer_id.as_bytes()).into_string(),
                    "message_id": hex::encode(offer.message_id.0),
                    "request_id": hex::encode(offer.request_id.0),
                    "offer_id": hex::encode(handle.0),
                    "context_ref": {
                        "authority": hex::encode(offer.reference.authority.0),
                        "namespace": offer.reference.namespace,
                        "revision": offer.reference.revision,
                        "digest": hex::encode(offer.reference.digest.0),
                    },
                    "content_id": hex::encode(offer.content_id.0),
                    "file_size": offer.file_size,
                    "expires_at_ms": offer.expires_at_ms,
                    "state": "offer_received",
                }),
            })
            .is_ok()
    }

    fn observe_group_context_agreement(
        &mut self,
        source: DownloadSource,
        connection: [u8; 16],
        room: (Hash32, u64, GroupTransferBinding),
        agreement: ContextAgreement,
        now: u64,
    ) -> bool {
        let pending = self
            .group_context_requests
            .get(&(room.0, agreement.request_id.0));
        if pending.is_some_and(|pending| {
            pending.expires <= now || pending.reference != agreement.reference
        }) {
            return false;
        }
        let expires = pending
            .map(|pending| pending.expires)
            .unwrap_or_else(|| now.saturating_add(MAIL_TTL_MS));
        if !self.admit(source.agent_id, agreement.message_id, expires, now) {
            return false;
        }
        let status = match agreement.status {
            ContextAgreementStatus::Conformant => "conformant",
            ContextAgreementStatus::Unresolved => "unresolved",
            ContextAgreementStatus::Rejected => "rejected",
        };
        self.port
            .events
            .send(MailEvent {
                kind: "context_agreement",
                details: json!({
                    "room": format!("group:{}", hex::encode(room.0.0)),
                    "mls_epoch": room.1,
                    "connection_id": hex::encode(connection),
                    "agent": format!("agent:{}", hex::encode(source.agent_id.0)),
                    "sender": format!("agent:{}", hex::encode(source.agent_id.0)),
                    "peer_id": bs58::encode(source.peer_id.as_bytes()).into_string(),
                    "message_id": hex::encode(agreement.message_id.0),
                    "request_id": hex::encode(agreement.request_id.0),
                    "context_ref": {
                        "authority": hex::encode(agreement.reference.authority.0),
                        "namespace": agreement.reference.namespace,
                        "revision": agreement.reference.revision,
                        "digest": hex::encode(agreement.reference.digest.0),
                    },
                    "status": status,
                }),
            })
            .is_ok()
    }

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
        self.observe_with_evaluation(source, connection, room, frame, now, None)
    }

    pub(crate) fn observe_with_evaluation(
        &mut self,
        source: DownloadSource,
        connection: [u8; 16],
        room: Option<(Hash32, u64, GroupTransferBinding)>,
        frame: &WireFrame,
        now: u64,
        evaluation: Option<&crate::semantic_context::SemanticEvaluation>,
    ) -> bool {
        if let Some(room) = room.clone() {
            match frame {
                WireFrame::ContextOffer(offer) => {
                    return self.observe_group_context_offer(source, connection, room, *offer, now);
                }
                WireFrame::ContextAgreement(agreement) => {
                    return self.observe_group_context_agreement(
                        source, connection, room, *agreement, now,
                    );
                }
                _ => {}
            }
        }
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
            WireFrame::ContextRequest(request) => (
                "context_request",
                request.message_id,
                request.message_id,
                0,
                request.expires_at_ms,
            ),
            WireFrame::ContextExpression(e) => (
                "context_expression",
                e.message_id,
                e.root_task_id,
                e.created_at_ms,
                e.expires_at_ms,
            ),
            _ => return false,
        };
        if created > now || !self.admit(source.agent_id, id, expiry, now) {
            return false;
        }
        let mut details = json!({
            "agent": format!("agent:{}", hex::encode(source.agent_id.0)),
            "sender": format!("agent:{}", hex::encode(source.agent_id.0)),
            "peer_id": bs58::encode(source.peer_id.as_bytes()).into_string(),
            "room": room.as_ref().map(|(id,_,_)| format!("group:{}", hex::encode(id.0))),
            "connection_id": hex::encode(connection),
            "message_id": hex::encode(id.0), "root_task_id": hex::encode(root.0), "expires_at_ms": expiry,
        });
        match frame {
            WireFrame::Expression(e) => details["expression"] = e.expression.to_json(),
            WireFrame::ContextExpression(ContextExpression { .. }) => {
                let Ok(bytes) = asl_types::protocol::encode_control(frame) else {
                    return false;
                };
                if bytes.len() > asl_types::protocol::MAX_CONTROL_FRAME_BYTES {
                    return false;
                }
                details["control_cbor_hex"] = json!(hex::encode(bytes));
                if let Some(evaluation) = evaluation {
                    details["semantic_evaluation"] = evaluation.to_host_value();
                }
            }
            WireFrame::ContextRequest(_) => {
                let Ok(bytes) = asl_types::protocol::encode_control(frame) else {
                    return false;
                };
                details["request_id"] = json!(hex::encode(id.0));
                details["state"] = json!("request_received");
                if let WireFrame::ContextRequest(request) = frame {
                    details["context_ref"] = json!({
                        "authority": hex::encode(request.reference.authority.0),
                        "namespace": request.reference.namespace,
                        "revision": request.reference.revision,
                        "digest": hex::encode(request.reference.digest.0),
                    });
                }
                details["control_cbor_hex"] = json!(hex::encode(bytes));
            }
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
                        context_ref: None,
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

    pub(crate) fn observe_act(
        &mut self,
        source: DownloadSource,
        connection: [u8; 16],
        room: (Hash32, u64, GroupTransferBinding),
        act: &Act,
        now: u64,
    ) -> bool {
        let expires = act.expires_at_ms.unwrap_or(u64::MAX);
        if !self.admit(source.agent_id, act.message_id, expires, now) {
            return false;
        }
        let Ok(bytes) = act.encode() else {
            return false;
        };
        let mut details = json!({
            "agent": format!("agent:{}", hex::encode(source.agent_id.0)),
            "room": format!("group:{}", hex::encode(room.0.0)),
            "connection_id": hex::encode(connection),
            "mls_epoch": room.1,
            "conversation_id": hex::encode(act.conversation_id.0),
            "message_id": hex::encode(act.message_id.0),
            "causal_root": hex::encode(act.causal_root.0),
            "reply_to": act.reply_to.map(|id| hex::encode(id.0)),
            "act_type": act.act_type.as_str(),
            "hop": act.hop,
            "expires_at_ms": act.expires_at_ms,
            "attachments": act
                .attachments
                .iter()
                .map(|attachment| hex::encode(attachment.0))
                .collect::<Vec<_>>(),
            "act_cbor_hex": hex::encode(bytes),
        });
        if let Some(body) = &act.nl_body {
            details["untrusted_remote_data"] = json!({
                "kind": "act_nl_body",
                "text": body,
                "source_agent": format!("agent:{}", hex::encode(source.agent_id.0)),
                "conversation_id": hex::encode(act.conversation_id.0),
                "message_id": hex::encode(act.message_id.0),
            });
        }
        if let Some(action) = &act.action {
            details["action"] = json!({
                "id": [
                    action.action_id.vocabulary_id,
                    action.action_id.concept_id
                ],
                "arg_count": action.args.len(),
            });
        }
        self.port
            .events
            .send(MailEvent {
                kind: "act",
                details,
            })
            .is_ok()
    }

    pub(crate) fn observe_group_invite_request(
        &mut self,
        request: &asl_store::group_state::GroupInviteRequest,
        connection: [u8; 16],
    ) -> bool {
        self.port
            .events
            .send(MailEvent {
                kind: "group_invite_request",
                details: json!({
                    "request_id": hex::encode(request.request_id.0),
                    "room": format!("group:{}", hex::encode(request.wire_id.0)),
                    "agent": format!("agent:{}", hex::encode(request.requester.0)),
                    "device": bs58::encode(request.device.as_bytes()).into_string(),
                    "connection_id": hex::encode(connection),
                    "mls_epoch": request.mls_epoch,
                    "expires_at_ms": request.expires_at_ms,
                    "state": "pending_local_approval",
                }),
            })
            .is_ok()
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

#[cfg(test)]
mod context_offer_tests {
    use super::*;
    use crate::identity::DeviceIdentity;
    use asl_types::{
        protocol::{ContextAgreement, ContextAgreementStatus, ContextOffer, ContextRequest},
        task::GroupId,
    };

    #[test]
    fn only_a_correlated_context_offer_becomes_a_downloadable_inbox_event() {
        let mut mailbox = Mailbox::default();
        let mut events = mailbox.port.subscribe();
        let source = DownloadSource {
            agent_id: AgentId([3; 32]),
            peer_id: DeviceIdentity::generate().unwrap().peer_id(),
        };
        let reference = SemanticContextRef {
            authority: AgentId([7; 32]),
            namespace: 12,
            revision: 2,
            digest: Hash32([9; 32]),
        };
        let request_id = Id128([1; 16]);
        mailbox
            .remember_context_request(
                source.clone(),
                QueryScope::Public,
                [4; 16],
                request_id,
                reference,
                100,
                3,
            )
            .unwrap();

        let mismatched = WireFrame::ContextOffer(ContextOffer {
            message_id: Id128([2; 16]),
            request_id,
            reference: SemanticContextRef {
                digest: Hash32([10; 32]),
                ..reference
            },
            content_id: Hash32([11; 32]),
            file_size: 321,
            expires_at_ms: 90,
        });
        assert!(!mailbox.observe_context_offer(
            source.clone(),
            [4; 16],
            request_id.0,
            &mismatched,
            3,
        ));
        assert!(mailbox.observe_context_offer(
            source.clone(),
            [4; 16],
            request_id.0,
            &WireFrame::ContextOffer(ContextOffer {
                message_id: Id128([3; 16]),
                request_id,
                reference,
                content_id: Hash32([11; 32]),
                file_size: 321,
                expires_at_ms: 90,
            }),
            3,
        ));
        let event = events.try_recv().unwrap();
        assert_eq!(event.kind, "context_file_offer");
        let offer_id =
            hex::decode_to_array::<_, 16>(event.details["offer_id"].as_str().unwrap()).unwrap();
        assert_eq!(
            mailbox.live_offer(Id128(offer_id), 3).unwrap().context_ref,
            Some(reference)
        );
        let unavailable = WireFrame::ContextAgreement(ContextAgreement {
            message_id: Id128([4; 16]),
            request_id,
            reference,
            status: ContextAgreementStatus::Unresolved,
        });
        assert!(mailbox.observe_context_agreement(source, [4; 16], request_id.0, &unavailable, 4,));
    }

    #[test]
    fn group_context_offer_binds_request_room_and_sender_for_confirmation() {
        let mut mailbox = Mailbox::default();
        let mut events = mailbox.port.subscribe();
        let source = DownloadSource {
            agent_id: AgentId([3; 32]),
            peer_id: DeviceIdentity::generate().unwrap().peer_id(),
        };
        let room = Hash32([5; 32]);
        let request_id = Id128([1; 16]);
        let reference = SemanticContextRef {
            authority: AgentId([7; 32]),
            namespace: 12,
            revision: 2,
            digest: Hash32([9; 32]),
        };
        mailbox
            .remember_group_context_request(room, request_id, reference, 100, 3)
            .unwrap();
        let group = GroupTransferBinding {
            group_id: GroupId(Id128([6; 16])),
            membership_epoch: 8,
        };
        let offer = WireFrame::ContextOffer(ContextOffer {
            message_id: Id128([2; 16]),
            request_id,
            reference,
            content_id: Hash32([11; 32]),
            file_size: 321,
            expires_at_ms: 90,
        });
        assert!(mailbox.observe(source.clone(), [4; 16], Some((room, 9, group)), &offer, 3,));
        let event = events.try_recv().unwrap();
        assert_eq!(event.kind, "context_file_offer");
        assert_eq!(
            event.details["request_id"],
            json!(hex::encode(request_id.0))
        );
        assert_eq!(
            event.details["room"],
            json!(format!("group:{}", hex::encode(room.0)))
        );
        assert_eq!(
            event.details["agent"],
            json!(format!("agent:{}", hex::encode(source.agent_id.0)))
        );
        let pending = mailbox
            .group_context_offer_for_confirmation(request_id, room, source.agent_id, 3)
            .unwrap();
        assert_eq!(pending.connection, [4; 16]);
        assert_eq!(pending.reference, reference);
        mailbox.complete_group_context_offer(request_id, room, source.agent_id);
        assert!(
            mailbox
                .group_context_offer_for_confirmation(request_id, room, source.agent_id, 3)
                .is_err()
        );
    }

    #[test]
    fn incoming_group_context_request_is_a_structured_notification() {
        let mut mailbox = Mailbox::default();
        let mut events = mailbox.port.subscribe();
        let source = DownloadSource {
            agent_id: AgentId([3; 32]),
            peer_id: DeviceIdentity::generate().unwrap().peer_id(),
        };
        let room = Hash32([5; 32]);
        let request_id = Id128([1; 16]);
        let request = WireFrame::ContextRequest(ContextRequest {
            message_id: request_id,
            reference: SemanticContextRef {
                authority: AgentId([7; 32]),
                namespace: 12,
                revision: 2,
                digest: Hash32([9; 32]),
            },
            expires_at_ms: 90,
        });
        assert!(mailbox.observe(
            source,
            [4; 16],
            Some((
                room,
                9,
                GroupTransferBinding {
                    group_id: GroupId(Id128([6; 16])),
                    membership_epoch: 8,
                },
            )),
            &request,
            3,
        ));
        let event = events.try_recv().unwrap();
        assert_eq!(event.kind, "context_request");
        assert_eq!(
            event.details["request_id"],
            json!(hex::encode(request_id.0))
        );
        assert_eq!(
            event.details["room"],
            json!(format!("group:{}", hex::encode(room.0)))
        );
        assert!(event.details["control_cbor_hex"].as_str().is_some());
    }

    #[test]
    fn incoming_group_context_agreement_is_a_structured_notification() {
        let mut mailbox = Mailbox::default();
        let mut events = mailbox.port.subscribe();
        let source = DownloadSource {
            agent_id: AgentId([3; 32]),
            peer_id: DeviceIdentity::generate().unwrap().peer_id(),
        };
        let room = Hash32([5; 32]);
        let request_id = Id128([1; 16]);
        let agreement = WireFrame::ContextAgreement(ContextAgreement {
            message_id: Id128([2; 16]),
            request_id,
            reference: SemanticContextRef {
                authority: AgentId([7; 32]),
                namespace: 12,
                revision: 2,
                digest: Hash32([9; 32]),
            },
            status: ContextAgreementStatus::Conformant,
        });
        assert!(mailbox.observe(
            source,
            [4; 16],
            Some((
                room,
                9,
                GroupTransferBinding {
                    group_id: GroupId(Id128([6; 16])),
                    membership_epoch: 8,
                },
            )),
            &agreement,
            3,
        ));
        let event = events.try_recv().unwrap();
        assert_eq!(event.kind, "context_agreement");
        assert_eq!(
            event.details["request_id"],
            json!(hex::encode(request_id.0))
        );
        assert_eq!(event.details["status"], json!("conformant"));
        assert_eq!(
            event.details["room"],
            json!(format!("group:{}", hex::encode(room.0)))
        );
    }
}
