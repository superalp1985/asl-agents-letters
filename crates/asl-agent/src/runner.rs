//! Inbound scheduling over admitted direct sessions. Nothing here dials a peer.

use std::collections::HashMap;

use crate::{
    Conversation, InboundDecision, InboundQueryDecision, MAX_ACTIVE_TASKS, QueryRouter,
    query::fresh_id,
};
use asl_policy::{AccessOperation, Permit, PolicyService};
use asl_types::{
    error::{AslError, ErrorCode},
    ids::{AgentId, Id128, PeerId},
    protocol::{
        Answer, AnswerStatus, Claim, ConceptRef, Intent, MediaKind, Offer, Query, ResultShape,
        ResultStatus, TypedValue, WireFrame, encode_control,
    },
    task::TaskId,
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum InboundMode {
    #[default]
    Disabled,
    BrowseOnly,
    Answer,
}

#[derive(Debug)]
pub enum Ingress {
    Ignored,
    Observed,
    Duplicate,
    Expired,
    Busy,
    Work(Box<InboundWork>),
}

#[derive(Debug)]
pub struct InboundWork {
    agent_id: AgentId,
    peer_id: PeerId,
    query: Query,
}

impl InboundWork {
    pub fn agent_id(&self) -> AgentId {
        self.agent_id
    }

    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    pub fn query(&self) -> &Query {
        &self.query
    }
}

struct Running {
    peer_id: PeerId,
    message_id: Id128,
    expires_at_ms: u64,
}

/// Metadata from the local index. The permit must bind this exact snapshot
/// and the admitted recipient; a search hit alone is not enough.
pub struct ResourceMatch {
    permit: Permit,
    concepts: Vec<ConceptRef>,
    file_size: u64,
    media_kind: MediaKind,
}

impl ResourceMatch {
    pub fn new(
        permit: Permit,
        concepts: Vec<ConceptRef>,
        file_size: u64,
        media_kind: MediaKind,
    ) -> Result<Self, AslError> {
        if permit.operation() != AccessOperation::ReadMetadata {
            return Err(AslError::PolicyDenied);
        }
        if concepts.len() > 16
            || concepts
                .iter()
                .enumerate()
                .any(|(index, item)| !item.is_topic() || concepts[..index].contains(item))
        {
            return Err(AslError::InvalidMessage);
        }
        Ok(Self {
            permit,
            concepts,
            file_size,
            media_kind,
        })
    }
}

pub struct FallbackReply {
    frame: WireFrame,
    permit: Option<Permit>,
    expires_at_ms: u64,
    mode_epoch: u64,
    /// Local status only. A match is not a model-generated or verified conclusion.
    pub model_status: ErrorCode,
}

#[derive(Default)]
pub struct InboundRunner {
    mode: InboundMode,
    mode_epoch: u64,
    queries: QueryRouter,
    conversations: Conversation,
    pending: HashMap<AgentId, Running>,
}

impl InboundRunner {
    pub fn set_mode(&mut self, mode: InboundMode) {
        if self.mode != mode {
            self.pending.clear();
            self.mode_epoch = self.mode_epoch.wrapping_add(1);
        }
        self.mode = mode;
    }

    pub fn disconnect(&mut self, peer_id: &PeerId) {
        self.pending.retain(|_, task| &task.peer_id != peer_id);
    }

    pub fn receive(
        &mut self,
        agent_id: AgentId,
        peer_id: PeerId,
        frame: WireFrame,
        now_ms: u64,
    ) -> Result<Ingress, AslError> {
        if self.mode == InboundMode::Disabled {
            return Ok(Ingress::Ignored);
        }
        let WireFrame::Query(query) = frame else {
            return Ok(match frame {
                WireFrame::Answer(_)
                | WireFrame::Offer(_)
                | WireFrame::Ack(_)
                | WireFrame::Error(_) => Ingress::Observed,
                _ => Ingress::Ignored,
            });
        };
        if self.mode == InboundMode::BrowseOnly {
            return Ok(Ingress::Observed);
        }
        if now_ms < query.created_at_ms || now_ms >= query.expires_at_ms {
            return Ok(Ingress::Expired);
        }

        self.pending.retain(|_, task| now_ms < task.expires_at_ms);
        self.conversations.prune_expired(now_ms);
        if let Some(task) = self.pending.get(&agent_id) {
            return Ok(
                if task.message_id == query.message_id && task.peer_id == peer_id {
                    Ingress::Duplicate
                } else {
                    Ingress::Busy
                },
            );
        }
        if self.pending.len() >= MAX_ACTIVE_TASKS {
            return Ok(Ingress::Busy);
        }
        let query = match self
            .queries
            .accept_incoming(peer_id.clone(), query, now_ms)?
        {
            InboundQueryDecision::ExecuteLocally { query } => query,
            InboundQueryDecision::Duplicate => return Ok(Ingress::Duplicate),
            InboundQueryDecision::Expired => return Ok(Ingress::Expired),
        };
        match self.conversations.accept_incoming(
            peer_id.clone(),
            WireFrame::Query(query.clone()),
            now_ms,
        ) {
            Ok(InboundDecision::Deliver { .. }) => {}
            Ok(InboundDecision::Duplicate) => return Ok(Ingress::Duplicate),
            Ok(InboundDecision::Expired) => return Ok(Ingress::Expired),
            Ok(InboundDecision::Ignored) => return Ok(Ingress::Ignored),
            Err(AslError::QuotaExceeded) => return Ok(Ingress::Busy),
            Err(error) => return Err(error),
        }
        self.pending.insert(
            agent_id,
            Running {
                peer_id: peer_id.clone(),
                message_id: query.message_id,
                expires_at_ms: query.expires_at_ms,
            },
        );
        Ok(Ingress::Work(Box::new(InboundWork {
            agent_id,
            peer_id,
            query,
        })))
    }

    /// Responds to a single admitted request from current local evidence.
    /// The Core connection gate still must admit the response immediately before sending.
    pub fn finish_without_model(
        &mut self,
        work: InboundWork,
        hit: Option<ResourceMatch>,
        policy: &dyn PolicyService,
        now_ms: u64,
    ) -> Result<Option<FallbackReply>, AslError> {
        let Some(task) = self.pending.get(&work.agent_id) else {
            return Ok(None);
        };
        if task.peer_id != work.peer_id || task.message_id != work.query.message_id {
            return Ok(None);
        }
        self.pending.remove(&work.agent_id);
        if self.mode != InboundMode::Answer
            || now_ms < work.query.created_at_ms
            || now_ms >= work.query.expires_at_ms
        {
            return Ok(None);
        }
        let query = &work.query;
        let message_id = fresh_id()?;
        let hit = hit.filter(|hit| {
            hit.permit.requester_agent_id() == Some(work.agent_id)
                && hit.permit.authenticated_device_peer_id() == Some(&work.peer_id)
                && policy.revalidate(&hit.permit, now_ms).is_ok()
                && query
                    .topics
                    .iter()
                    .any(|topic| hit.concepts.contains(topic))
        });
        let (frame, permit) = if !query.constraints.is_empty()
            || !matches!(
                query.intent_id,
                Intent::FindEvidence | Intent::LocateResource
            )
            || query.result_shape == ResultShape::Agents
        {
            (
                answer(query, message_id, now_ms, AnswerStatus::Unsupported, vec![]),
                None,
            )
        } else {
            let frame = fallback(query, message_id, now_ms, hit.as_ref());
            (frame, hit.map(|hit| hit.permit))
        };
        encode_control(&frame)?;
        self.conversations
            .record_outbound(&TaskId(query.root_task_id), &frame, now_ms)?;
        Ok(Some(FallbackReply {
            frame,
            permit,
            expires_at_ms: query.expires_at_ms,
            mode_epoch: self.mode_epoch,
            model_status: ErrorCode::ModelUnavailable,
        }))
    }

    /// This consumes the reply. Use only when the original connection and response handle are live.
    pub fn take_reply(
        &self,
        reply: FallbackReply,
        policy: &dyn PolicyService,
        now_ms: u64,
    ) -> Option<WireFrame> {
        (self.mode == InboundMode::Answer
            && self.mode_epoch == reply.mode_epoch
            && now_ms < reply.expires_at_ms
            && reply
                .permit
                .as_ref()
                .is_none_or(|permit| policy.revalidate(permit, now_ms).is_ok()))
        .then_some(reply.frame)
    }
}

fn fallback(
    query: &Query,
    message_id: Id128,
    now_ms: u64,
    hit: Option<&ResourceMatch>,
) -> WireFrame {
    let Some(hit) = hit else {
        return answer(query, message_id, now_ms, AnswerStatus::NoMatch, vec![]);
    };
    let content_id = hit.permit.content_id();
    match query.result_shape {
        ResultShape::Resources => WireFrame::Offer(Offer {
            message_id,
            root_task_id: query.root_task_id,
            content_id,
            file_size: hit.file_size,
            media_kind: hit.media_kind,
            concepts: hit.concepts.clone(),
            expires_at_ms: query.expires_at_ms,
        }),
        _ => answer(
            query,
            message_id,
            now_ms,
            AnswerStatus::Answered,
            vec![Claim {
                subject: TypedValue::Hash(content_id),
                predicate: ConceptRef {
                    vocabulary_id: 1,
                    concept_id: 203,
                },
                object: TypedValue::Concepts(hit.concepts.clone()),
                evidence: Some(content_id),
            }],
        ),
    }
}

fn answer(
    query: &Query,
    message_id: Id128,
    now_ms: u64,
    status: AnswerStatus,
    claims: Vec<Claim>,
) -> WireFrame {
    WireFrame::Answer(Answer {
        message_id,
        root_task_id: query.root_task_id,
        created_at_ms: now_ms,
        expires_at_ms: query.expires_at_ms,
        status,
        claims,
        evidence_ids: vec![],
        result_status: ResultStatus::Unverified,
    })
}
