use std::collections::{HashMap, HashSet};

use asl_types::{
    error::AslError,
    ids::{Id128, PeerId},
    protocol::WireFrame,
    task::TaskId,
};

use crate::query::MAX_ACTIVE_TASKS;

pub const MAX_CONVERSATION_ROUNDS: u8 = 3;
pub const MAX_SEMANTIC_MESSAGES: u8 = 6;
pub const MAX_OUTBOX_RETRIES: u8 = 3;
pub const CONVERSATION_WINDOW_MS: u64 = 10 * 60 * 1_000;
pub const RETRY_DELAYS_MS: [u64; 3] = [1_000, 10_000, 60_000];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConversationMessageKind {
    Query,
    Answer,
    Offer,
    Error,
    Ack,
}

impl ConversationMessageKind {
    pub fn is_semantic(self) -> bool {
        matches!(self, Self::Query | Self::Answer | Self::Offer)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingDelivery {
    pub task_id: TaskId,
    pub peer_id: PeerId,
    pub frame: WireFrame,
    pub attempts: u8,
    pub next_attempt_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InboundDecision {
    Deliver {
        task_id: TaskId,
        frame: Box<WireFrame>,
    },
    Duplicate,
    Expired,
    Ignored,
}

struct ConversationTask {
    peer_id: PeerId,
    expires_at_ms: u64,
    rounds_used: u8,
    semantic_messages: u8,
    seen_messages: HashSet<Id128>,
}

pub struct Conversation {
    tasks: HashMap<TaskId, ConversationTask>,
    message_tasks: HashMap<Id128, TaskId>,
    outbox: HashMap<Id128, PendingDelivery>,
}

impl Default for Conversation {
    fn default() -> Self {
        Self::new()
    }
}

impl Conversation {
    pub fn new() -> Self {
        Self {
            tasks: HashMap::new(),
            message_tasks: HashMap::new(),
            outbox: HashMap::new(),
        }
    }

    pub fn start_query(
        &mut self,
        peer_id: PeerId,
        query: asl_types::protocol::Query,
        now_ms: u64,
    ) -> Result<TaskId, AslError> {
        let task_id = TaskId(query.root_task_id);
        if self.tasks.contains_key(&task_id)
            || self.message_tasks.contains_key(&query.message_id)
            || now_ms >= query.expires_at_ms
        {
            return Err(AslError::InvalidMessage);
        }
        if query.expires_at_ms < query.created_at_ms
            || query.expires_at_ms - query.created_at_ms > CONVERSATION_WINDOW_MS
        {
            return Err(AslError::InvalidMessage);
        }

        let expires_at_ms = now_ms.saturating_add(CONVERSATION_WINDOW_MS);
        let task = ConversationTask {
            peer_id: peer_id.clone(),
            expires_at_ms,
            rounds_used: 1,
            semantic_messages: 1,
            seen_messages: HashSet::from([query.message_id]),
        };
        self.insert_task(task_id.clone(), task, query.message_id)?;
        self.queue(task_id.clone(), peer_id, WireFrame::Query(query), now_ms)?;
        Ok(task_id)
    }

    pub fn accept_incoming(
        &mut self,
        peer_id: PeerId,
        frame: WireFrame,
        now_ms: u64,
    ) -> Result<InboundDecision, AslError> {
        let Some((message_id, root_task_id, kind, expires_at_ms)) = frame_metadata(&frame) else {
            return Ok(InboundDecision::Ignored);
        };
        if expires_at_ms <= now_ms {
            return Ok(InboundDecision::Expired);
        }

        let task_id = root_task_id
            .map(TaskId)
            .or_else(|| self.related_task_id(&frame))
            .ok_or(AslError::NotFound)?;
        let Some(task) = self.tasks.get_mut(&task_id) else {
            if kind != ConversationMessageKind::Query {
                return Err(AslError::NotFound);
            }
            let mut task = ConversationTask {
                peer_id: peer_id.clone(),
                expires_at_ms: now_ms.saturating_add(CONVERSATION_WINDOW_MS),
                rounds_used: 0,
                semantic_messages: 0,
                seen_messages: HashSet::new(),
            };
            observe_semantic(&mut task, kind, message_id)?;
            self.insert_task(task_id.clone(), task, message_id)?;
            return Ok(InboundDecision::Deliver {
                task_id,
                frame: Box::new(frame),
            });
        };

        if task.peer_id != peer_id {
            return Err(AslError::InvalidMessage);
        }
        if now_ms >= task.expires_at_ms {
            return Ok(InboundDecision::Expired);
        }
        if task.seen_messages.contains(&message_id) {
            return Ok(InboundDecision::Duplicate);
        }
        if self.message_tasks.contains_key(&message_id) {
            return Err(AslError::InvalidMessage);
        }
        if kind.is_semantic() {
            observe_semantic(task, kind, message_id)?;
        } else {
            task.seen_messages.insert(message_id);
        }
        self.message_tasks.insert(message_id, task_id.clone());
        Ok(InboundDecision::Deliver {
            task_id,
            frame: Box::new(frame),
        })
    }

    pub fn queue_outbound(
        &mut self,
        task_id: &TaskId,
        frame: WireFrame,
        now_ms: u64,
    ) -> Result<(), AslError> {
        let peer_id = self.record_outbound(task_id, &frame, now_ms)?;
        self.queue(task_id.clone(), peer_id, frame, now_ms)
    }

    pub(crate) fn record_outbound(
        &mut self,
        task_id: &TaskId,
        frame: &WireFrame,
        now_ms: u64,
    ) -> Result<PeerId, AslError> {
        let Some((message_id, root_task_id, kind, _)) = frame_metadata(frame) else {
            return Err(AslError::InvalidMessage);
        };
        if let Some(root_task_id) = root_task_id.map(TaskId)
            && &root_task_id != task_id
        {
            return Err(AslError::InvalidMessage);
        }
        let peer_id = {
            let task = self.tasks.get_mut(task_id).ok_or(AslError::NotFound)?;
            if now_ms >= task.expires_at_ms {
                return Err(AslError::ExpiredMessage);
            }
            if self.message_tasks.contains_key(&message_id) {
                return Err(AslError::InvalidMessage);
            }
            if kind.is_semantic() {
                observe_semantic(task, kind, message_id)?;
            }
            task.peer_id.clone()
        };
        self.message_tasks.insert(message_id, task_id.clone());
        Ok(peer_id)
    }

    pub(crate) fn prune_expired(&mut self, now_ms: u64) {
        self.tasks.retain(|_, task| now_ms < task.expires_at_ms);
        self.message_tasks
            .retain(|_, task_id| self.tasks.contains_key(task_id));
        self.outbox
            .retain(|_, pending| self.tasks.contains_key(&pending.task_id));
    }

    pub fn due_deliveries(&self, now_ms: u64) -> Vec<PendingDelivery> {
        self.outbox
            .values()
            .filter(|delivery| {
                delivery.next_attempt_ms <= now_ms && delivery.expires_at_ms > now_ms
            })
            .cloned()
            .collect()
    }

    pub fn mark_delivered(&mut self, message_id: Id128) -> Result<(), AslError> {
        self.outbox
            .remove(&message_id)
            .map(|_| ())
            .ok_or(AslError::NotFound)
    }

    pub fn mark_failed(
        &mut self,
        message_id: Id128,
        now_ms: u64,
    ) -> Result<Option<PendingDelivery>, AslError> {
        let delivery = self.outbox.get_mut(&message_id).ok_or(AslError::NotFound)?;
        if now_ms >= delivery.expires_at_ms {
            self.outbox.remove(&message_id);
            return Ok(None);
        }
        if delivery.attempts >= MAX_OUTBOX_RETRIES {
            self.outbox.remove(&message_id);
            return Ok(None);
        }
        let delay = RETRY_DELAYS_MS[usize::from(delivery.attempts)];
        delivery.attempts += 1;
        delivery.next_attempt_ms = now_ms.saturating_add(delay);
        Ok(Some(delivery.clone()))
    }

    pub fn task_count(&self) -> usize {
        self.tasks.len()
    }

    pub fn outbox_count(&self) -> usize {
        self.outbox.len()
    }

    fn related_task_id(&self, frame: &WireFrame) -> Option<TaskId> {
        let related_id = match frame {
            WireFrame::Error(value) => value.message_id,
            WireFrame::Ack(value) => value.received_id,
            _ => return None,
        };
        self.message_tasks.get(&related_id).cloned()
    }

    fn insert_task(
        &mut self,
        task_id: TaskId,
        task: ConversationTask,
        message_id: Id128,
    ) -> Result<(), AslError> {
        if self.tasks.len() >= MAX_ACTIVE_TASKS {
            return Err(AslError::QuotaExceeded);
        }
        self.tasks.insert(task_id.clone(), task);
        self.message_tasks.insert(message_id, task_id);
        Ok(())
    }

    fn queue(
        &mut self,
        task_id: TaskId,
        peer_id: PeerId,
        frame: WireFrame,
        now_ms: u64,
    ) -> Result<(), AslError> {
        let message_id = frame_message_id(&frame).ok_or(AslError::InvalidMessage)?;
        let expires_at_ms = self
            .tasks
            .get(&task_id)
            .ok_or(AslError::NotFound)?
            .expires_at_ms;
        self.outbox.insert(
            message_id,
            PendingDelivery {
                task_id,
                peer_id,
                frame,
                attempts: 0,
                next_attempt_ms: now_ms,
                expires_at_ms,
            },
        );
        Ok(())
    }
}

fn observe_semantic(
    task: &mut ConversationTask,
    kind: ConversationMessageKind,
    message_id: Id128,
) -> Result<(), AslError> {
    if task.semantic_messages >= MAX_SEMANTIC_MESSAGES {
        return Err(AslError::QuotaExceeded);
    }
    if kind == ConversationMessageKind::Query {
        if task.rounds_used >= MAX_CONVERSATION_ROUNDS {
            return Err(AslError::QuotaExceeded);
        }
        task.rounds_used += 1;
    }
    task.semantic_messages += 1;
    task.seen_messages.insert(message_id);
    Ok(())
}

fn frame_metadata(
    frame: &WireFrame,
) -> Option<(Id128, Option<Id128>, ConversationMessageKind, u64)> {
    match frame {
        WireFrame::Query(value) => Some((
            value.message_id,
            Some(value.root_task_id),
            ConversationMessageKind::Query,
            value.expires_at_ms,
        )),
        WireFrame::Answer(value) => Some((
            value.message_id,
            Some(value.root_task_id),
            ConversationMessageKind::Answer,
            value.expires_at_ms,
        )),
        WireFrame::Offer(value) => Some((
            value.message_id,
            Some(value.root_task_id),
            ConversationMessageKind::Offer,
            value.expires_at_ms,
        )),
        WireFrame::Error(value) => Some((
            value.message_id,
            None,
            ConversationMessageKind::Error,
            u64::MAX,
        )),
        WireFrame::Ack(value) => Some((
            value.message_id,
            None,
            ConversationMessageKind::Ack,
            u64::MAX,
        )),
        WireFrame::FetchRequest(_)
        | WireFrame::FetchGrant(_)
        | WireFrame::FetchPending(_)
        | WireFrame::Hello(_)
        | WireFrame::Profile(_)
        | WireFrame::IdentityProofRequest(_)
        | WireFrame::IdentityProof(_)
        | WireFrame::PairingInvite(_)
        | WireFrame::PairingExchange(_)
        | WireFrame::GroupEnvelope(_) => None,
    }
}

fn frame_message_id(frame: &WireFrame) -> Option<Id128> {
    frame_metadata(frame).map(|metadata| metadata.0)
}
