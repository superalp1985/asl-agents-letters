use std::{cmp::Ordering, collections::BTreeMap};

use asl_agent::{QueryScope, runner::InboundMode};
use asl_groups::GroupApplication;
use asl_store::{
    Store,
    act_history::{ActDirection, ActHistoryRanking, MAX_ACT_HISTORY_ROWS},
    budgets::BudgetKind,
    contact_bindings::ContactBindingActionKind,
    group_access::{GroupAccessKind, GroupAdminCapabilityKind, GroupFileAccessKind},
    group_state::{GROUP_INVITE_REQUEST_TTL_MS, GroupInboundPolicy},
    mailbox::ConversationBudgetRenewal,
    search::group::GroupRequester,
};
use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId},
    protocol::{
        Act, ContextAgreement, ContextAgreementStatus, ContextExpression, ContextRequest,
        Expression, ExpressionLetter, GroupBody, GroupMembership, GroupPacket, SemanticContextRef,
        WireFrame,
    },
};
use serde_json::{Value, json};

use super::{
    NetworkAdmissionStatus, NetworkCommand, Supervisor, groups::LocalGroupAction, unix_time_ms,
};
use crate::{
    agent_mail::{MailCommand, Target},
    direct_inbound::read_mode,
    downloads::{DownloadSelection, DownloadSource},
    profile::{AdmittedNetworkEvent, fresh_id},
    semantic_context::{
        AuthenticatedSemanticContextBundle, ConformanceReadySemanticContextBundle,
        SemanticEvaluation, authenticate_semantic_context, check_context_conformance,
        evaluate_semantic_expression,
    },
    transfer::TransferService,
};

const MAX_CONTEXT_GRAPH_ITEMS: usize = 256;
const HISTORY_CURSOR_VERSION: &str = "v1";
const HISTORY_CURSOR_BYTES: usize = 512;

struct HistorySearchHit {
    conversation_id: String,
    act_id: [u8; 32],
    mls_epoch: Option<u64>,
    direction: ActDirection,
    act_kind: u16,
    causal_root: Option<[u8; 32]>,
    reply_to: Option<[u8; 32]>,
    body: Option<String>,
    ranking: ActHistoryRanking,
    score: u32,
    received_at_ms: i64,
    expires_at_ms: i64,
    source: &'static str,
}

struct HistoryCursor {
    score: u32,
    term_weight: u32,
    received_at_ms: i64,
    conversation_id: String,
    act_id: [u8; 32],
}

fn compare_history_hits(left: &HistorySearchHit, right: &HistorySearchHit) -> Ordering {
    right
        .score
        .cmp(&left.score)
        .then_with(|| right.ranking.term_weight.cmp(&left.ranking.term_weight))
        .then_with(|| right.received_at_ms.cmp(&left.received_at_ms))
        .then_with(|| left.conversation_id.cmp(&right.conversation_id))
        .then_with(|| left.act_id.cmp(&right.act_id))
}

fn compare_history_key(hit: &HistorySearchHit, cursor: &HistoryCursor) -> Ordering {
    cursor
        .score
        .cmp(&hit.score)
        .then_with(|| cursor.term_weight.cmp(&hit.ranking.term_weight))
        .then_with(|| cursor.received_at_ms.cmp(&hit.received_at_ms))
        .then_with(|| hit.conversation_id.cmp(&cursor.conversation_id))
        .then_with(|| hit.act_id.cmp(&cursor.act_id))
}

fn page_history_hits(
    mut hits: Vec<HistorySearchHit>,
    query_hash: [u8; 16],
    requested: usize,
    cursor: Option<&HistoryCursor>,
) -> (Vec<HistorySearchHit>, bool, Option<String>) {
    hits.sort_by(compare_history_hits);
    if let Some(cursor) = cursor {
        hits.retain(|hit| compare_history_key(hit, cursor) == Ordering::Greater);
    }
    let has_more = hits.len() > requested;
    hits.truncate(requested);
    let next_cursor = has_more
        .then(|| {
            hits.last()
                .map(|hit| encode_history_cursor(query_hash, hit))
        })
        .flatten();
    (hits, has_more, next_cursor)
}

fn history_hit_json(hit: HistorySearchHit) -> Value {
    let coverage_ppm = if hit.ranking.query_terms == 0 {
        0
    } else {
        u32::from(hit.ranking.matched_terms).saturating_mul(1_000_000)
            / u32::from(hit.ranking.query_terms)
    };
    json!({
        "conversation_id": hit.conversation_id,
        "act_id": alloy_primitives::hex::encode(hit.act_id),
        "mls_epoch": hit.mls_epoch,
        "direction": hit.direction.as_str(),
        "act_kind": hit.act_kind,
        "causal_root": hit.causal_root.map(alloy_primitives::hex::encode),
        "reply_to": hit.reply_to.map(alloy_primitives::hex::encode),
        "body": hit.body,
        "lexical_score": hit.score,
        "semantic_score": hit.score,
        "ranking": {
            "kind": "lexical_overlap_v1",
            "matched_terms": hit.ranking.matched_terms,
            "query_terms": hit.ranking.query_terms,
            "term_weight": hit.ranking.term_weight,
            "coverage_ppm": coverage_ppm,
            "score_formula": "matched_terms*1000000+term_weight",
        },
        "received_at_ms": hit.received_at_ms,
        "expires_at_ms": hit.expires_at_ms,
        "source": hit.source,
    })
}

fn history_query_hash(query: &str) -> [u8; 16] {
    let normalized = query.trim().to_lowercase();
    let digest = blake3::hash(normalized.as_bytes());
    digest.as_bytes()[..16]
        .try_into()
        .expect("fixed digest prefix")
}

fn encode_history_cursor(query_hash: [u8; 16], hit: &HistorySearchHit) -> String {
    format!(
        "{HISTORY_CURSOR_VERSION}:{}:{:08x}:{:08x}:{}:{}:{}",
        alloy_primitives::hex::encode(query_hash),
        hit.score,
        hit.ranking.term_weight,
        hit.received_at_ms,
        alloy_primitives::hex::encode(hit.conversation_id.as_bytes()),
        alloy_primitives::hex::encode(hit.act_id),
    )
}

fn parse_history_cursor(
    value: &str,
    expected_query_hash: [u8; 16],
) -> Result<HistoryCursor, AslError> {
    if value.is_empty() || value.len() > HISTORY_CURSOR_BYTES {
        return Err(AslError::InvalidMessage);
    }
    let parts = value.split(':').collect::<Vec<_>>();
    if parts.len() != 7 || parts[0] != HISTORY_CURSOR_VERSION {
        return Err(AslError::InvalidMessage);
    }
    let query_hash = alloy_primitives::hex::decode_to_array::<_, 16>(parts[1])
        .map_err(|_| AslError::InvalidMessage)?;
    if query_hash != expected_query_hash {
        return Err(AslError::InvalidMessage);
    }
    let score = u32::from_str_radix(parts[2], 16).map_err(|_| AslError::InvalidMessage)?;
    let term_weight = u32::from_str_radix(parts[3], 16).map_err(|_| AslError::InvalidMessage)?;
    let received_at_ms = parts[4]
        .parse::<i64>()
        .ok()
        .filter(|value| *value >= 0)
        .ok_or(AslError::InvalidMessage)?;
    let conversation =
        alloy_primitives::hex::decode(parts[5]).map_err(|_| AslError::InvalidMessage)?;
    if conversation.is_empty() || conversation.len() > 128 {
        return Err(AslError::InvalidMessage);
    }
    let conversation_id = String::from_utf8(conversation).map_err(|_| AslError::InvalidMessage)?;
    let act_id = alloy_primitives::hex::decode_to_array::<_, 32>(parts[6])
        .map_err(|_| AslError::InvalidMessage)?;
    Ok(HistoryCursor {
        score,
        term_weight,
        received_at_ms,
        conversation_id,
        act_id,
    })
}

impl Supervisor {
    pub(super) fn observe_direct_mail(
        &mut self,
        event: &AdmittedNetworkEvent,
    ) -> Result<(), AslError> {
        let AdmittedNetworkEvent::ControlRequest {
            connection_id,
            agent_id,
            request,
            response_id,
        } = event
        else {
            return Ok(());
        };
        if !self.mailbox.interested()
            || !matches!(
                request,
                WireFrame::Expression(_)
                    | WireFrame::ContextExpression(_)
                    | WireFrame::ContextRequest(_)
                    | WireFrame::Offer(_)
                    | WireFrame::Query(_)
                    | WireFrame::Answer(_)
            )
        {
            return Ok(());
        }
        let Some(admission) = &mut self.admission else {
            return Ok(());
        };
        if matches!(request, WireFrame::Expression(_))
            && !admission.peer_supports_expression(*connection_id)
        {
            return Ok(());
        }
        if matches!(request, WireFrame::ContextExpression(_))
            && !admission.peer_supports_contexts(*connection_id)
        {
            return Ok(());
        }
        if matches!(request, WireFrame::ContextRequest(_))
            && !admission.peer_supports_contexts(*connection_id)
        {
            return Ok(());
        }
        let Some(requester) = admission.direct_requester(*connection_id, *agent_id) else {
            return Ok(());
        };
        let store = self.network_report.store();
        if read_mode(store)? == InboundMode::Disabled || store.network_pause_requested()? {
            return Ok(());
        }
        let now = unix_time_ms()?;
        let evaluation = match request {
            WireFrame::ContextExpression(expression) => Some(evaluate_incoming_context_expression(
                self.network_report.store(),
                admission,
                expression,
                now,
            )),
            _ => None,
        };
        let accepted = self.mailbox.observe_with_evaluation(
            DownloadSource {
                agent_id: requester.agent,
                peer_id: requester.peer,
            },
            *connection_id,
            None,
            request,
            now,
            evaluation.as_ref(),
        );
        let (received_id, received_expires_at_ms) = match request {
            WireFrame::Expression(expression) => {
                (Some(expression.message_id), expression.expires_at_ms)
            }
            WireFrame::ContextExpression(expression) => {
                (Some(expression.message_id), expression.expires_at_ms)
            }
            _ => (None, 0),
        };
        if accepted && let Some(received_id) = received_id {
            store
                .with_mail_dispatch(|| {
                    if read_mode(store)? == InboundMode::Answer
                        && !store.network_pause_requested()?
                        && unix_time_ms()? < received_expires_at_ms
                    {
                        let ack = WireFrame::Ack(asl_types::protocol::Ack {
                            message_id: Id128(fresh_id()?),
                            received_id,
                        });
                        if let Ok(command) = admission.authorize_control_reply(
                            *connection_id,
                            *response_id,
                            ack,
                            unix_time_ms()?,
                        ) {
                            self.net.try_send(&command.into_ipc()?)?;
                        }
                    }
                    Ok(())
                })
                .or_else(|error| match error {
                    AslError::PolicyVersionConflict | AslError::InvalidDatabase => Ok(()),
                    error => Err(error),
                })?;
        }
        Ok(())
    }

    pub(super) fn poll_mail(&mut self) {
        self.mailbox.poll_inbox_binding(self.network_report.store());
        if let Ok(now) = unix_time_ms() {
            self.mailbox.prune_context_requests(now);
        }
        let Ok(command) = self.mailbox.commands.try_recv() else {
            return;
        };
        match command {
            MailCommand::ContactLookup { agent, reply } if !reply.is_closed() => {
                let _ = reply.send(self.contact_lookup(agent));
            }
            MailCommand::ContactStatus { reply } if !reply.is_closed() => {
                let _ = reply.send(self.contact_status());
            }
            MailCommand::ActHistorySearch {
                query,
                limit,
                cursor,
                reply,
            } if !reply.is_closed() => {
                let _ = reply.send(self.search_act_history(query, limit, cursor));
            }
            MailCommand::RequestTaskInbox { reply } if !reply.is_closed() => {
                let _ = reply.send(unix_time_ms().and_then(|now| {
                    self.mailbox
                        .request_inbox_binding(self.network_report.store(), now)
                }));
            }
            MailCommand::Send {
                target,
                scope,
                root,
                expression,
                reply,
            } if !reply.is_closed() => {
                let _ = reply.send(self.send_letter(target, scope, root, expression));
            }
            MailCommand::SendContextExpression {
                target,
                scope,
                root,
                expression,
                required_contexts,
                reply,
            } if !reply.is_closed() => {
                let _ = reply.send(self.send_context_letter(
                    target,
                    scope,
                    root,
                    expression,
                    required_contexts,
                ));
            }
            MailCommand::SendAct { room, act, reply } if !reply.is_closed() => {
                let _ = reply.send(self.send_group_act(room, act));
            }
            MailCommand::SendShardAnnouncement { root, act, reply } if !reply.is_closed() => {
                let _ = reply.send(self.send_shard_announcement(root, act));
            }
            MailCommand::SendFile {
                room,
                content_id,
                media_kind,
                concepts,
                reply,
            } if !reply.is_closed() => {
                let _ = reply.send(self.send_group_file(room, content_id, media_kind, concepts));
            }
            MailCommand::GroupMembers { room, reply } if !reply.is_closed() => {
                let _ = reply.send(self.group_members(room));
            }
            MailCommand::GroupSetAccess {
                room,
                update,
                reply,
            } if !reply.is_closed() => {
                let _ = reply.send(self.set_group_access(room, update));
            }
            MailCommand::GroupList { reply } if !reply.is_closed() => {
                let _ = reply
                    .send(unix_time_ms().and_then(|now| {
                        self.apply_local_group_action(LocalGroupAction::List, now)
                    }));
            }
            MailCommand::GroupCreate { reply } if !reply.is_closed() => {
                let _ =
                    reply.send(unix_time_ms().and_then(|now| {
                        self.apply_local_group_action(LocalGroupAction::Create, now)
                    }));
            }
            MailCommand::GroupInvite { room, agent, reply } if !reply.is_closed() => {
                let _ = reply.send(self.invite_group_agent(room, agent));
            }
            MailCommand::GroupInviteRequest { room, owner, reply } if !reply.is_closed() => {
                let _ = reply.send(self.request_group_join(room, owner));
            }
            MailCommand::GroupRejectJoinRequest {
                room,
                device,
                reply,
            } if !reply.is_closed() => {
                let _ = reply.send(self.reject_group_join_request(room, &device));
            }
            MailCommand::DirectOpen { agent, reply } if !reply.is_closed() => {
                let _ = reply.send(self.open_direct_room(agent));
            }
            MailCommand::RenewActBudget {
                conversation_id,
                additional_messages,
                window_ms,
                reply,
            } if !reply.is_closed() => {
                let _ = reply.send(self.renew_act_budget(
                    conversation_id,
                    additional_messages,
                    window_ms,
                ));
            }
            MailCommand::RenewResourceBudget {
                conversation_id,
                kind,
                additional,
                window_ms,
                reply,
            } if !reply.is_closed() => {
                let _ = reply.send(self.renew_resource_budget(
                    conversation_id,
                    kind,
                    additional,
                    window_ms,
                ));
            }
            MailCommand::RequestContext {
                target,
                scope,
                reference,
                reply,
            } if !reply.is_closed() => {
                let _ = reply.send(self.send_context_request(target, scope, reference));
            }
            MailCommand::ConfirmContext {
                request_id,
                group,
                reply,
            } if !reply.is_closed() => {
                let _ = reply.send(self.confirm_context_request(request_id, group));
            }
            MailCommand::Claim {
                handle,
                inbox,
                scope,
                reply,
            } if !reply.is_closed() => {
                let _ = reply.send(self.claim_mail_offer(handle, inbox, scope));
            }
            MailCommand::RequestInbox {
                handle,
                scope,
                reply,
            } if !reply.is_closed() => {
                let _ = reply.send((|| {
                    let now = unix_time_ms()?;
                    let held = self.mailbox.live_offer(handle, now)?;
                    let store = self.network_report.store();
                    if store.network_pause_requested()?
                        || (scope == QueryScope::ContactsOnly
                            && !store.authorized_contacts()?.contains(&held.source.agent_id))
                    {
                        return Err(AslError::PolicyDenied);
                    }
                    if let Some((room, epoch, group)) = &held.room {
                        if !GroupInboundPolicy::load(store)?.browse_enabled
                            || !self
                                .current_group_requester(
                                    held.connection,
                                    &held.source.peer_id,
                                    *room,
                                    *epoch,
                                )
                                .is_some_and(|r| {
                                    r.direct.agent == held.source.agent_id
                                        && r.membership_epoch == group.membership_epoch
                                })
                        {
                            return Err(AslError::PolicyDenied);
                        }
                    } else if read_mode(store)? == InboundMode::Disabled {
                        return Err(AslError::PolicyDenied);
                    }
                    self.mailbox.request_inbox_binding(store, now)
                })());
            }
            _ => {}
        }
    }

    fn send_letter(
        &mut self,
        target: Target,
        scope: QueryScope,
        root: Option<Id128>,
        expression: Expression,
    ) -> Result<Id128, AslError> {
        let now = unix_time_ms()?;
        let store = self.network_report.store();
        if !self.net.is_running()
            || self.network_admission_status != NetworkAdmissionStatus::Active
            || store.network_pause_requested()?
        {
            return Err(AslError::PolicyDenied);
        }
        let local = &self.device_peer_id;
        let check_target = || check_letter_target(store, local, scope, target);
        // A host without send authority must not learn which peers are online.
        check_target()?;
        let id = Id128(fresh_id()?);
        let letter = ExpressionLetter {
            message_id: id,
            root_task_id: root.unwrap_or(id),
            created_at_ms: now,
            expires_at_ms: now + 10_000,
            expression,
        };
        let admission = self.admission.as_mut().ok_or(AslError::NotFound)?;
        match target {
            Target::Agent(agent) => {
                let mut routes = admission
                    .admitted_connections(now)
                    .into_iter()
                    .filter(|(a, _, _)| *a == agent)
                    .peekable();
                if routes.peek().is_none() {
                    return Err(AslError::NotFound);
                }
                let (_, connection, _) = routes
                    .find(|(_, connection, _)| admission.peer_supports_expression(*connection))
                    .ok_or(AslError::IncompatibleVersion)?;
                let cmd = admission
                    .authorize_control_command(
                        connection,
                        id.0,
                        WireFrame::Expression(letter),
                        now,
                    )?
                    .into_ipc()?;
                store.with_mail_dispatch(|| {
                    check_target()?;
                    if store.network_pause_requested()? {
                        return Err(AslError::PolicyDenied);
                    }
                    if !self.net.try_send(&cmd)? {
                        return Err(AslError::QuotaExceeded);
                    }
                    Ok(())
                })?;
            }
            Target::Group(room) => {
                let groups = self.groups.as_mut().ok_or(AslError::NotFound)?;
                groups.dispatch_letter(admission, local, room, letter, now, |cmd| {
                    check_target()?;
                    if store.network_pause_requested()? {
                        return Err(AslError::PolicyDenied);
                    }
                    if !self.net.try_send(&cmd.into_ipc()?)? {
                        return Err(AslError::QuotaExceeded);
                    }
                    Ok(())
                })?;
            }
        }
        Ok(id)
    }

    fn send_context_letter(
        &mut self,
        target: Target,
        scope: QueryScope,
        root: Option<Id128>,
        expression: Expression,
        required_contexts: Vec<SemanticContextRef>,
    ) -> Result<Id128, AslError> {
        let now = unix_time_ms()?;
        let store = self.network_report.store();
        if !self.net.is_running()
            || self.network_admission_status != NetworkAdmissionStatus::Active
            || store.network_pause_requested()?
        {
            return Err(AslError::PolicyDenied);
        }
        check_letter_target(store, &self.device_peer_id, scope, target)?;
        let contexts = load_conformance_ready_contexts(
            store,
            self.admission.as_mut().ok_or(AslError::NotFound)?,
            &required_contexts,
            now,
        )?;
        if matches!(
            evaluate_semantic_expression(&expression, &contexts),
            SemanticEvaluation::Unresolved | SemanticEvaluation::Invalid
        ) {
            return Err(AslError::InvalidMessage);
        }

        let id = Id128(fresh_id()?);
        let letter = ContextExpression {
            message_id: id,
            root_task_id: root.unwrap_or(id),
            created_at_ms: now,
            expires_at_ms: now.saturating_add(10_000),
            required_contexts,
            expression,
        };
        match target {
            Target::Agent(agent) => {
                let admission = self.admission.as_mut().ok_or(AslError::NotFound)?;
                let (_, connection, _) = admission
                    .admitted_connections(now)
                    .into_iter()
                    .filter(|(candidate, _, _)| *candidate == agent)
                    .find(|(_, connection, _)| admission.peer_supports_contexts(*connection))
                    .ok_or(AslError::IncompatibleVersion)?;
                let command = admission
                    .authorize_control_command(
                        connection,
                        id.0,
                        WireFrame::ContextExpression(letter),
                        now,
                    )?
                    .into_ipc()?;
                store.with_mail_dispatch(|| {
                    check_letter_target(store, &self.device_peer_id, scope, Target::Agent(agent))?;
                    if store.network_pause_requested()? {
                        return Err(AslError::PolicyDenied);
                    }
                    if !self.net.try_send(&command)? {
                        return Err(AslError::QuotaExceeded);
                    }
                    Ok(())
                })?;
            }
            Target::Group(room) => {
                self.send_group_context_broadcast(
                    room,
                    GroupApplication::ContextExpression(letter),
                    now,
                )?;
            }
        }
        Ok(id)
    }

    pub(super) fn observe_context_response(
        &mut self,
        event: &AdmittedNetworkEvent,
    ) -> Result<(), AslError> {
        let AdmittedNetworkEvent::ControlResponse {
            connection_id,
            agent_id,
            request_id,
            response,
        } = event
        else {
            return Ok(());
        };
        let Some(admission) = self.admission.as_ref() else {
            return Ok(());
        };
        if !admission.peer_supports_contexts(*connection_id) {
            return Ok(());
        }
        let Some(requester) = admission.direct_requester(*connection_id, *agent_id) else {
            return Ok(());
        };
        let source = DownloadSource {
            agent_id: requester.agent,
            peer_id: requester.peer,
        };
        let request_id = *request_id;
        let connection = *connection_id;
        let now = unix_time_ms()?;
        match response {
            WireFrame::ContextOffer(_) => {
                self.mailbox
                    .observe_context_offer(source, connection, request_id, response, now);
            }
            WireFrame::ContextAgreement(_) => {
                self.mailbox
                    .observe_context_agreement(source, connection, request_id, response, now);
            }
            _ => {}
        }
        Ok(())
    }

    pub(super) fn handle_context_request(
        &mut self,
        transfers: &mut TransferService,
        event: AdmittedNetworkEvent,
    ) -> Result<(), AslError> {
        self.observe_direct_mail(&event)?;
        let AdmittedNetworkEvent::ControlRequest {
            connection_id,
            agent_id,
            response_id,
            request: WireFrame::ContextRequest(request),
        } = event
        else {
            return Ok(());
        };
        let now = unix_time_ms()?;
        let Some(admission) = self.admission.as_mut() else {
            return Ok(());
        };
        if !admission.peer_supports_contexts(connection_id)
            || read_mode(self.network_report.store())? != InboundMode::Answer
            || self.network_report.store().network_pause_requested()?
        {
            return Ok(());
        }
        let Some(requester) = admission.direct_requester(connection_id, agent_id) else {
            return Ok(());
        };
        let context_valid = load_conformance_ready_contexts(
            self.network_report.store(),
            admission,
            &[request.reference],
            now,
        )
        .is_ok();
        let found = if context_valid && request.expires_at_ms > now {
            transfers
                .context_offer(
                    &requester,
                    request.message_id,
                    request.reference,
                    request.expires_at_ms,
                    now,
                )
                .ok()
                .flatten()
        } else {
            None
        };
        let (response, authority) = match found {
            Some((revision, permit, offer)) => {
                (WireFrame::ContextOffer(offer), Some((revision, permit)))
            }
            None => (
                WireFrame::ContextAgreement(ContextAgreement {
                    message_id: Id128(fresh_id()?),
                    request_id: request.message_id,
                    reference: request.reference,
                    status: ContextAgreementStatus::Unresolved,
                }),
                None,
            ),
        };
        let net = &self.net;
        let enqueue = || {
            let Some(admission) = self.admission.as_mut() else {
                return Ok(());
            };
            let command = match admission.authorize_control_reply(
                connection_id,
                response_id,
                response.clone(),
                unix_time_ms()?,
            ) {
                Ok(command) => command,
                Err(_) => return Ok(()),
            };
            if !net.try_send(&command.into_ipc()?)? {
                return Err(AslError::QuotaExceeded);
            }
            Ok(())
        };
        if let Some((revision, permit)) = authority {
            transfers
                .with_current_context_authority(&requester, revision, &permit, || {
                    self.network_report.store().with_mail_dispatch(enqueue)
                })
                .or_else(|error| match error {
                    AslError::NotFound
                    | AslError::PolicyVersionConflict
                    | AslError::PolicyDenied
                    | AslError::GrantRevoked => Ok(()),
                    error => Err(error),
                })?;
        } else {
            self.network_report.store().with_mail_dispatch(enqueue)?;
        }
        Ok(())
    }

    fn send_context_request(
        &mut self,
        target: Target,
        scope: QueryScope,
        reference: SemanticContextRef,
    ) -> Result<Id128, AslError> {
        let now = unix_time_ms()?;
        let store = self.network_report.store();
        if !self.net.is_running()
            || self.network_admission_status != NetworkAdmissionStatus::Active
            || store.network_pause_requested()?
            || read_mode(store)? == InboundMode::Disabled
        {
            return Err(AslError::PolicyDenied);
        }
        check_letter_target(store, &self.device_peer_id, scope, target)?;
        let request_id = Id128(fresh_id()?);
        let expires_at_ms = now.saturating_add(10_000);
        let request = ContextRequest {
            message_id: request_id,
            reference,
            expires_at_ms,
        };
        match target {
            Target::Agent(target) => {
                let admission = self.admission.as_mut().ok_or(AslError::NotFound)?;
                let (_, connection, peer) = admission
                    .admitted_connections(now)
                    .into_iter()
                    .find(|(agent, _, _)| *agent == target)
                    .ok_or(AslError::NotFound)?;
                if !admission.peer_supports_contexts(connection) {
                    return Err(AslError::IncompatibleVersion);
                }
                let command = admission
                    .authorize_control_command(
                        connection,
                        request_id.0,
                        WireFrame::ContextRequest(request),
                        now,
                    )?
                    .into_ipc()?;
                let pending = DownloadSource {
                    agent_id: target,
                    peer_id: peer,
                };
                store.with_mail_dispatch(|| {
                    check_letter_target(store, &self.device_peer_id, scope, Target::Agent(target))?;
                    if store.network_pause_requested()? {
                        return Err(AslError::PolicyDenied);
                    }
                    self.mailbox.remember_context_request(
                        pending,
                        scope,
                        connection,
                        request_id,
                        reference,
                        expires_at_ms,
                        unix_time_ms()?,
                    )?;
                    if !self.net.try_send(&command)? {
                        self.mailbox.cancel_context_request(connection, request_id);
                        return Err(AslError::QuotaExceeded);
                    }
                    Ok(())
                })?;
            }
            Target::Group(room) => {
                self.mailbox.remember_group_context_request(
                    room,
                    request_id,
                    reference,
                    expires_at_ms,
                    now,
                )?;
                if let Err(error) = self.send_group_context_broadcast(
                    room,
                    GroupApplication::ContextRequest(request),
                    now,
                ) {
                    self.mailbox.cancel_group_context_request(room, request_id);
                    return Err(error);
                }
            }
        }
        Ok(request_id)
    }

    fn confirm_context_request(
        &mut self,
        request_id: Id128,
        group: Option<(Hash32, AgentId)>,
    ) -> Result<(Id128, ContextAgreementStatus), AslError> {
        if let Some((room, sender)) = group {
            return self.confirm_group_context_request(request_id, room, sender);
        }
        let now = unix_time_ms()?;
        let (connection, pending) = self
            .mailbox
            .context_request_for_confirmation(request_id, now)?;
        let store = self.network_report.store();
        if store.network_pause_requested()?
            || (pending.scope == QueryScope::ContactsOnly
                && !store
                    .authorized_contacts()?
                    .contains(&pending.source.agent_id))
        {
            return Err(AslError::PolicyDenied);
        }
        let admission = self.admission.as_mut().ok_or(AslError::NotFound)?;
        if admission.admitted_peer_identity(connection, now)?
            != (pending.source.agent_id, pending.source.peer_id.clone())
        {
            return Err(AslError::InvalidIdentity);
        }
        let status =
            match load_conformance_ready_contexts(store, admission, &[pending.reference], now) {
                Ok(_) => ContextAgreementStatus::Conformant,
                Err(
                    AslError::NotFound
                    | AslError::ExpiredMessage
                    | AslError::IncompatibleVersion
                    | AslError::PolicyVersionConflict
                    | AslError::GrantRevoked,
                ) => ContextAgreementStatus::Unresolved,
                Err(_) => ContextAgreementStatus::Rejected,
            };
        let agreement = ContextAgreement {
            message_id: Id128(fresh_id()?),
            request_id,
            reference: pending.reference,
            status,
        };
        let command = admission
            .authorize_control_command(
                connection,
                agreement.message_id.0,
                WireFrame::ContextAgreement(agreement),
                now,
            )?
            .into_ipc()?;
        if !self.net.try_send(&command)? {
            return Err(AslError::QuotaExceeded);
        }
        self.mailbox
            .complete_context_request(connection, request_id);
        Ok((agreement.message_id, status))
    }

    fn confirm_group_context_request(
        &mut self,
        request_id: Id128,
        room: Hash32,
        sender: AgentId,
    ) -> Result<(Id128, ContextAgreementStatus), AslError> {
        let now = unix_time_ms()?;
        if !self.net.is_running()
            || self.network_admission_status != NetworkAdmissionStatus::Active
            || self.network_report.store().network_pause_requested()?
        {
            return Err(AslError::PolicyDenied);
        }
        let pending = self
            .mailbox
            .group_context_offer_for_confirmation(request_id, room, sender, now)?;
        let current = self
            .groups
            .as_ref()
            .ok_or(AslError::NotFound)?
            .store
            .mls_room_snapshot(room)?
            .ok_or(AslError::NotFound)?;
        let requester = self
            .current_group_requester(
                pending.connection,
                &pending.source.peer_id,
                room,
                current.version.mls_epoch,
            )
            .ok_or(AslError::PolicyDenied)?;
        if requester.direct.agent != sender {
            return Err(AslError::InvalidIdentity);
        }
        let store = self.network_report.store();
        let status = match load_conformance_ready_contexts(
            store,
            self.admission.as_mut().ok_or(AslError::NotFound)?,
            &[pending.reference],
            now,
        ) {
            Ok(_) => ContextAgreementStatus::Conformant,
            Err(
                AslError::NotFound
                | AslError::ExpiredMessage
                | AslError::IncompatibleVersion
                | AslError::PolicyVersionConflict
                | AslError::GrantRevoked,
            ) => ContextAgreementStatus::Unresolved,
            Err(_) => ContextAgreementStatus::Rejected,
        };
        let agreement = ContextAgreement {
            message_id: Id128(fresh_id()?),
            request_id,
            reference: pending.reference,
            status,
        };
        self.send_group_context_target(
            room,
            pending.connection,
            GroupApplication::ContextAgreement(agreement),
            now,
        )?;
        self.mailbox
            .complete_group_context_offer(request_id, room, sender);
        Ok((agreement.message_id, status))
    }

    pub(super) fn handle_group_context_request(
        &mut self,
        transfers: &mut TransferService,
        requester: &GroupRequester,
        connection: [u8; 16],
        room: Hash32,
        request: &ContextRequest,
        now: u64,
    ) -> Result<(), AslError> {
        if request.expires_at_ms <= now
            || !GroupInboundPolicy::load(self.network_report.store())?.answer_enabled
        {
            return Ok(());
        }
        let found = transfers.group_context_offer(
            requester,
            request.message_id,
            request.reference,
            request.expires_at_ms,
            now,
        )?;
        match found {
            Some((revision, permit, offer)) => transfers
                .with_current_group_context_authority(requester, revision, &permit, || {
                    self.send_group_context_target(
                        room,
                        connection,
                        GroupApplication::ContextOffer(offer),
                        now,
                    )
                })
                .or_else(|error| match error {
                    AslError::NotFound
                    | AslError::PolicyVersionConflict
                    | AslError::PolicyDenied
                    | AslError::GrantRevoked => Ok(()),
                    error => Err(error),
                })?,
            None => {
                let agreement = ContextAgreement {
                    message_id: Id128(fresh_id()?),
                    request_id: request.message_id,
                    reference: request.reference,
                    status: ContextAgreementStatus::Unresolved,
                };
                self.send_group_context_target(
                    room,
                    connection,
                    GroupApplication::ContextAgreement(agreement),
                    now,
                )?;
            }
        }
        Ok(())
    }

    fn send_group_context_broadcast(
        &mut self,
        room: Hash32,
        application: GroupApplication,
        now: u64,
    ) -> Result<(), AslError> {
        if !self.net.is_running()
            || self.network_admission_status != NetworkAdmissionStatus::Active
            || self.network_report.store().network_pause_requested()?
        {
            return Err(AslError::PolicyDenied);
        }
        let groups = self.groups.as_mut().ok_or(AslError::NotFound)?;
        let snapshot = groups
            .store
            .mls_room_snapshot(room)?
            .ok_or(AslError::NotFound)?;
        if groups
            .store
            .mls_room_progress(room)?
            .is_none_or(|(state, _)| state != "active")
            || !groups.store.group_can_send(
                &snapshot.local_id,
                &self.device_peer_id,
                GroupAccessKind::Text,
            )?
        {
            return Err(AslError::PolicyDenied);
        }
        let admission = self.admission.as_mut().ok_or(AslError::NotFound)?;
        let forwarded_application = application.clone();
        let sent = admission.send_loopback_mls_application_with_gossip(
            &mut groups.store,
            room,
            application,
            now,
            |command| {
                if self.net.try_send(&command.into_ipc()?)? {
                    Ok(())
                } else {
                    Err(AslError::SandboxUnavailable)
                }
            },
        )?;
        let _ = self.mailbox_wire.persist_group_packet(
            &mut groups.store,
            room,
            self.agent_identity.agent_id(),
            &sent.packet,
            now,
        );
        let _ = super::group_routing::publish_packet(
            &self.net,
            &groups.store,
            room,
            &self.device_peer_id,
            &sent.packet,
        );
        let _ = super::groups::forward_application_to_logical_shards(
            &mut groups.store,
            admission,
            &self.net,
            &self.agent_identity,
            &self.device_peer_id,
            room,
            &forwarded_application,
            self.agent_identity.agent_id(),
            &self.device_peer_id,
            sent.packet.epoch,
            now,
        );
        Ok(())
    }

    fn send_group_context_target(
        &mut self,
        room: Hash32,
        connection: [u8; 16],
        application: GroupApplication,
        now: u64,
    ) -> Result<(), AslError> {
        if !self.net.is_running()
            || self.network_admission_status != NetworkAdmissionStatus::Active
            || self.network_report.store().network_pause_requested()?
        {
            return Err(AslError::PolicyDenied);
        }
        let groups = self.groups.as_mut().ok_or(AslError::NotFound)?;
        let snapshot = groups
            .store
            .mls_room_snapshot(room)?
            .ok_or(AslError::NotFound)?;
        if groups
            .store
            .mls_room_progress(room)?
            .is_none_or(|(state, _)| state != "active")
            || !groups.store.group_can_send(
                &snapshot.local_id,
                &self.device_peer_id,
                GroupAccessKind::Text,
            )?
        {
            return Err(AslError::PolicyDenied);
        }
        let admission = self.admission.as_mut().ok_or(AslError::NotFound)?;
        let sent = admission.send_loopback_mls_application_to_connection(
            &mut groups.store,
            crate::profile::MlsApplicationSendToConnection {
                wire_id: room,
                connection_id: connection,
                envelope_id: Id128(fresh_id()?),
                application,
                now_ms: now,
            },
            |command| {
                if self.net.try_send(&command.into_ipc()?)? {
                    Ok(())
                } else {
                    Err(AslError::SandboxUnavailable)
                }
            },
        )?;
        if sent.queued == 0 {
            return Err(AslError::NotFound);
        }
        let _ = self.mailbox_wire.persist_group_packet(
            &mut groups.store,
            room,
            self.agent_identity.agent_id(),
            &sent.packet,
            now,
        );
        Ok(())
    }

    pub(super) fn send_group_act(&mut self, room: Hash32, act: Act) -> Result<Id128, AslError> {
        self.send_group_act_inner(room, act, true)
    }

    pub(super) fn send_group_act_inner(
        &mut self,
        room: Hash32,
        mut act: Act,
        forward_to_shards: bool,
    ) -> Result<Id128, AslError> {
        let now = unix_time_ms()?;
        if !self.net.is_running()
            || self.network_admission_status != NetworkAdmissionStatus::Active
            || self.network_report.store().network_pause_requested()?
            || act.expires_at_ms.is_some_and(|expires| expires <= now)
        {
            return Err(AslError::PolicyDenied);
        }
        let groups = self.groups.as_mut().ok_or(AslError::NotFound)?;
        let snapshot = groups
            .store
            .mls_room_snapshot(room)?
            .ok_or(AslError::NotFound)?;
        let local_group_id = snapshot.local_id.clone();
        let (state, _) = groups
            .store
            .mls_room_progress(room)?
            .ok_or(AslError::NotFound)?;
        if state != "active" {
            return Err(AslError::PolicyDenied);
        }
        if !groups.store.group_can_send(
            &snapshot.local_id,
            &self.device_peer_id,
            GroupAccessKind::Text,
        )? {
            return Err(AslError::PolicyDenied);
        }
        if act.message_id.0 == [0; 16] {
            act.message_id = Id128(fresh_id()?);
        }
        if act.conversation_id.0 == [0; 16] {
            act.conversation_id = snapshot.local_id.0;
        } else if snapshot.local_id.0 != act.conversation_id {
            return Err(AslError::PolicyDenied);
        }
        if act.causal_root.0 == [0; 16] {
            act.causal_root = act.message_id;
        }
        let admission = self.admission.as_mut().ok_or(AslError::NotFound)?;
        let conversation_id = alloy_primitives::hex::encode(snapshot.local_id.0.0);
        let message_bytes =
            u64::try_from(act.encode()?.len()).map_err(|_| AslError::InvalidMessage)?;
        let reservation = groups
            .store
            .reserve_budget(
                &conversation_id,
                1,
                &[(BudgetKind::MessageBytes, message_bytes)],
                now,
            )?
            .ok_or(AslError::QuotaExceeded)?;
        let message_id = act.message_id;
        let history_act = act.clone();
        let mut dispatched = false;
        let dispatch_result = admission.send_loopback_mls_application_with_gossip(
            &mut groups.store,
            room,
            GroupApplication::Act(act),
            now,
            |command| {
                if self.net.try_send(&command.into_ipc()?)? {
                    dispatched = true;
                    Ok(())
                } else {
                    Err(AslError::SandboxUnavailable)
                }
            },
        );
        let sent = match dispatch_result {
            Ok(sent) => sent,
            Err(error) => {
                if !dispatched {
                    groups.store.refund_budget_reservation(reservation, now)?;
                }
                return Err(error);
            }
        };
        let _ = super::groups::record_act_history(
            &mut groups.store,
            &local_group_id,
            sent.packet.epoch,
            ActDirection::Out,
            &history_act,
            now,
        );
        let _ = self.mailbox_wire.persist_group_packet(
            &mut groups.store,
            room,
            self.agent_identity.agent_id(),
            &sent.packet,
            now,
        );
        let _ = super::group_routing::publish_packet(
            &self.net,
            &groups.store,
            room,
            &self.device_peer_id,
            &sent.packet,
        );
        if forward_to_shards {
            let forwarded_application = GroupApplication::Act(history_act.clone());
            let _ = super::groups::forward_application_to_logical_shards(
                &mut groups.store,
                admission,
                &self.net,
                &self.agent_identity,
                &self.device_peer_id,
                room,
                &forwarded_application,
                self.agent_identity.agent_id(),
                &self.device_peer_id,
                sent.packet.epoch,
                now,
            );
        }
        Ok(message_id)
    }

    fn send_group_file(
        &mut self,
        room: Hash32,
        content_id: Hash32,
        media_kind: asl_types::protocol::MediaKind,
        concepts: Vec<asl_types::protocol::ConceptRef>,
    ) -> Result<Value, AslError> {
        let now = unix_time_ms()?;
        if !self.net.is_running()
            || self.network_admission_status != NetworkAdmissionStatus::Active
            || self.network_report.store().network_pause_requested()?
        {
            return Err(AslError::PolicyDenied);
        }
        if concepts.len() > 16 || concepts.iter().any(|concept| !concept.is_topic()) {
            return Err(AslError::InvalidMessage);
        }
        let snapshot = self.libraries.open_snapshot(content_id)?;
        let file_size = snapshot.manifest().file_size;
        let groups = self.groups.as_mut().ok_or(AslError::NotFound)?;
        let room_state = groups.store.mls_room_progress(room)?;
        if room_state.is_none_or(|(state, _)| state != "active") {
            return Err(AslError::PolicyDenied);
        }
        let local_group_id = groups
            .store
            .mls_room_snapshot(room)?
            .ok_or(AslError::NotFound)?
            .local_id;
        if !groups.store.group_can_access_file(
            &local_group_id,
            &self.device_peer_id,
            &content_id,
            GroupFileAccessKind::Send,
        )? {
            return Err(AslError::PolicyDenied);
        }
        let expires_at_ms = now.saturating_add(10 * 60 * 1_000);
        let offer = asl_types::protocol::Offer {
            message_id: Id128(fresh_id()?),
            root_task_id: Id128(fresh_id()?),
            content_id,
            file_size,
            media_kind,
            concepts,
            expires_at_ms,
            logical_group_id: Some(groups.store.mls_logical_root(room)?),
            source_room_id: Some(room),
        };
        let admission = self.admission.as_mut().ok_or(AslError::NotFound)?;
        let sent = admission.send_loopback_mls_application_with_gossip(
            &mut groups.store,
            room,
            GroupApplication::Offer(offer.clone()),
            now,
            |command| {
                if self.net.try_send(&command.into_ipc()?)? {
                    Ok(())
                } else {
                    Err(AslError::SandboxUnavailable)
                }
            },
        )?;
        let _ = self.mailbox_wire.persist_group_packet(
            &mut groups.store,
            room,
            self.agent_identity.agent_id(),
            &sent.packet,
            now,
        );
        let _ = super::group_routing::publish_packet(
            &self.net,
            &groups.store,
            room,
            &self.device_peer_id,
            &sent.packet,
        );
        let forwarded_application = GroupApplication::Offer(offer.clone());
        let _ = super::groups::forward_application_to_logical_shards(
            &mut groups.store,
            admission,
            &self.net,
            &self.agent_identity,
            &self.device_peer_id,
            room,
            &forwarded_application,
            self.agent_identity.agent_id(),
            &self.device_peer_id,
            sent.packet.epoch,
            now,
        );
        Ok(json!({
            "room": alloy_primitives::hex::encode(room.0),
            "offer_id": alloy_primitives::hex::encode(offer.message_id.0),
            "content_id": alloy_primitives::hex::encode(content_id.0),
            "file_size": file_size,
            "queued": sent.queued,
            "available": sent.available,
            "expires_at_ms": expires_at_ms,
        }))
    }

    fn invite_group_agent(&mut self, room: Hash32, agent: AgentId) -> Result<Value, AslError> {
        let now = unix_time_ms()?;
        let groups = self.groups.as_ref().ok_or(AslError::NotFound)?;
        let room = groups.store.mls_logical_root(room)?;
        let snapshot = groups
            .store
            .mls_room_snapshot(room)?
            .ok_or(AslError::NotFound)?;
        if !groups.store.group_can_send(
            &snapshot.local_id,
            &self.device_peer_id,
            GroupAccessKind::Invite,
        )? {
            return Err(AslError::PolicyDenied);
        }
        let policy = groups.store.group_access_policy(&snapshot.local_id)?;
        if policy.admins.contains(&self.device_peer_id)
            && !groups.store.group_admin_has_capability(
                &snapshot.local_id,
                &self.device_peer_id,
                GroupAdminCapabilityKind::ManageInvites,
            )?
        {
            return Err(AslError::PolicyDenied);
        }
        let owner = groups
            .store
            .group_access_owner(room)?
            .ok_or(AslError::NotFound)?;
        if owner != self.device_peer_id {
            return Ok(json!({
                "room": alloy_primitives::hex::encode(room.0),
                "agent": format!("agent:{}", alloy_primitives::hex::encode(agent.0)),
                "state": "owner_action_required",
                "error_code": "delegated_invite_requires_logical_owner",
                "owner_peer": bs58::encode(owner.as_bytes()).into_string(),
                "owner_agent": groups.store.mls_peer_agent(&owner)?.map(|agent| {
                    format!("agent:{}", alloy_primitives::hex::encode(agent.0))
                }),
                "queued": 0,
            }));
        }
        let connections = self
            .admission
            .as_ref()
            .ok_or(AslError::NotFound)?
            .admitted_connections(now)
            .into_iter()
            .filter(|(candidate, _, _)| *candidate == agent)
            .map(|(_, connection, _)| connection)
            .collect::<Vec<_>>();
        if connections.is_empty() {
            return Err(AslError::NotFound);
        }
        let mut queued = 0_u64;
        let mut invitations = Vec::with_capacity(connections.len());
        for connection_id in connections {
            let result = self.apply_local_group_action(
                LocalGroupAction::Invite {
                    room,
                    connection_id,
                },
                now,
            )?;
            if result
                .get("queued")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                queued += 1;
            }
            invitations.push(result);
        }
        Ok(json!({
            "room": alloy_primitives::hex::encode(room.0),
            "agent": format!("agent:{}", alloy_primitives::hex::encode(agent.0)),
            "queued": queued,
            "invitations": invitations,
        }))
    }

    pub(super) fn request_group_join(
        &mut self,
        room: Hash32,
        owner: AgentId,
    ) -> Result<Value, AslError> {
        if room.0 == [0; 32] || owner.0 == [0; 32] {
            return Err(AslError::InvalidMessage);
        }
        let now = unix_time_ms()?;
        if self.network_admission_status != NetworkAdmissionStatus::Active {
            return Err(AslError::InvalidIdentity);
        }
        let connections = self
            .admission
            .as_ref()
            .ok_or(AslError::InvalidIdentity)?
            .admitted_connections(now)
            .into_iter()
            .filter(|(agent, _, _)| *agent == owner)
            .map(|(_, connection, _)| connection)
            .collect::<Vec<_>>();
        if connections.is_empty() {
            return Err(AslError::NotFound);
        }
        let expires_at_ms = now.saturating_add(GROUP_INVITE_REQUEST_TTL_MS);
        let deadline_ms =
            now.saturating_add(asl_net::transport::REQUEST_TIMEOUT.as_millis() as u64);
        let mut queued = 0_u64;
        let mut delivery_error = None;
        for connection_id in connections {
            let request = GroupPacket {
                message_id: Id128(fresh_id()?),
                group_id: room,
                epoch: 0,
                body: GroupBody::Membership(GroupMembership::InviteRequest {
                    agent: self.agent_id(),
                    device: self.device_peer_id.clone(),
                    expires_at_ms,
                }),
            };
            let command = NetworkCommand::SendGroup {
                connection_id,
                request_handle: fresh_id()?,
                deadline_ms,
                request,
            };
            match self.net.try_send(&command.into_ipc()?) {
                Ok(true) => queued += 1,
                Ok(false) => delivery_error = Some(AslError::SandboxUnavailable),
                Err(error) => delivery_error = Some(error),
            }
        }
        if queued == 0 {
            return Err(delivery_error.unwrap_or(AslError::NotFound));
        }
        Ok(json!({
            "room": alloy_primitives::hex::encode(room.0),
            "owner": format!("agent:{}", alloy_primitives::hex::encode(owner.0)),
            "queued": queued,
            "expires_at_ms": expires_at_ms,
        }))
    }

    fn contact_lookup(&self, agent: AgentId) -> Result<Value, AslError> {
        if agent.0 == [0; 32] || agent == self.agent_id() {
            return Err(AslError::PolicyDenied);
        }
        let now = unix_time_ms()?;
        let store = asl_store::open_store(&self.state_database)?;
        store.enqueue_contact_binding_action(
            ContactBindingActionKind::Lookup,
            Some(asl_types::record::short_code(agent)),
            Some(agent),
            None,
            now,
        )?;
        Ok(json!({
            "agent": format!("agent:{}", alloy_primitives::hex::encode(agent.0)),
            "state": "queued",
            "network_ready": self.network_admission_status == NetworkAdmissionStatus::Active,
        }))
    }

    fn contact_status(&self) -> Result<Value, AslError> {
        let store = asl_store::open_store_read_only(&self.state_database)?;
        let policy = store.contact_request_policy()?;
        let candidates = store
            .contact_binding_candidates()?
            .into_iter()
            .map(|candidate| {
                json!({
                    "agent": format!("agent:{}", alloy_primitives::hex::encode(candidate.agent_id.0)),
                    "peer_id": candidate.peer_id,
                    "code": format!("{:016}", candidate.code),
                    "first_seen_ms": candidate.first_seen_ms,
                    "dismissed": candidate.dismissed,
                })
            })
            .collect::<Vec<_>>();
        Ok(json!({
            "request_mode": policy.mode.as_str(),
            "shared_group_auto_accept": policy.shared_group_auto_accept,
            "recent_interaction_ttl_ms": policy.recent_interaction_ttl_ms,
            "policy_revision": policy.revision,
            "revoked": policy.revoked,
            "policy_sync_authorized": store.contact_policy_sync_authorized()?,
            "bindings": store.recent_contact_bindings()?,
            "candidates": candidates,
        }))
    }

    fn search_act_history(
        &self,
        query: String,
        limit: u32,
        cursor: Option<String>,
    ) -> Result<Value, AslError> {
        let now = i64::try_from(unix_time_ms()?).map_err(|_| AslError::InvalidPolicyState)?;
        let store = asl_store::open_store_read_only(&self.state_database)?;
        let archive_rows = store.search_act_history_archive(now, &query, MAX_ACT_HISTORY_ROWS)?;
        let live_rows = store.search_act_history(now, &query, MAX_ACT_HISTORY_ROWS)?;
        let query_hash = history_query_hash(&query);
        let cursor = cursor
            .as_deref()
            .map(|value| parse_history_cursor(value, query_hash))
            .transpose()?;
        let mut hits = BTreeMap::new();
        for row in archive_rows {
            hits.insert(
                (row.conversation_id.clone(), row.act_id),
                HistorySearchHit {
                    conversation_id: row.conversation_id,
                    act_id: row.act_id,
                    mls_epoch: None,
                    direction: row.direction,
                    act_kind: row.act_kind,
                    causal_root: None,
                    reply_to: None,
                    body: None,
                    ranking: row.ranking,
                    score: row.score,
                    received_at_ms: row.received_at_ms,
                    expires_at_ms: row.expires_at_ms,
                    source: "semantic_index",
                },
            );
        }
        for row in live_rows {
            hits.insert(
                (row.conversation_id.clone(), row.act_id),
                HistorySearchHit {
                    conversation_id: row.conversation_id,
                    act_id: row.act_id,
                    mls_epoch: Some(row.mls_epoch),
                    direction: row.direction,
                    act_kind: row.act_kind,
                    causal_root: Some(row.causal_root),
                    reply_to: row.reply_to,
                    body: row.body,
                    ranking: row.ranking,
                    score: row.score,
                    received_at_ms: row.created_at_ms,
                    expires_at_ms: row.expires_at_ms,
                    source: "live_history",
                },
            );
        }
        let hits = hits.into_values().collect::<Vec<_>>();
        let requested = usize::try_from(limit).map_err(|_| AslError::InvalidMessage)?;
        let (hits, has_more, next_cursor) =
            page_history_hits(hits, query_hash, requested, cursor.as_ref());
        let entries = hits.into_iter().map(history_hit_json).collect::<Vec<_>>();
        Ok(json!({
            "query": query,
            "limit": limit,
            "ranking": "lexical_overlap_v1",
            "has_more": has_more,
            "next_cursor": next_cursor,
            "entries": entries,
        }))
    }

    fn reject_group_join_request(
        &mut self,
        room: Hash32,
        device: &PeerId,
    ) -> Result<Value, AslError> {
        let now = unix_time_ms()?;
        let groups = self.groups.as_mut().ok_or(AslError::NotFound)?;
        let room_state = groups
            .store
            .mls_room_for_reconciliation(room)?
            .ok_or(AslError::NotFound)?;
        if room_state.creator != self.device_peer_id {
            return Err(AslError::PolicyDenied);
        }
        if !groups
            .store
            .finish_group_invite_request(room, device, false, now)?
        {
            return Err(AslError::NotFound);
        }
        Ok(json!({
            "room": alloy_primitives::hex::encode(room.0),
            "device": bs58::encode(device.as_bytes()).into_string(),
            "state": "rejected"
        }))
    }

    fn open_direct_room(&mut self, agent: AgentId) -> Result<Value, AslError> {
        let now = unix_time_ms()?;
        let created = self.apply_local_group_action(LocalGroupAction::Create, now)?;
        let room = created
            .get("room")
            .and_then(Value::as_str)
            .ok_or(AslError::InvalidPolicyState)?;
        let room = Hash32(
            alloy_primitives::hex::decode_to_array(room)
                .map_err(|_| AslError::InvalidPolicyState)?,
        );
        let invite = self.invite_group_agent(room, agent)?;
        Ok(json!({
            "room": alloy_primitives::hex::encode(room.0),
            "agent": format!("agent:{}", alloy_primitives::hex::encode(agent.0)),
            "invite": invite,
        }))
    }

    fn renew_act_budget(
        &mut self,
        conversation_id: String,
        additional_messages: u32,
        window_ms: u64,
    ) -> Result<Value, AslError> {
        let groups = self.groups.as_mut().ok_or(AslError::NotFound)?;
        let now = i64::try_from(unix_time_ms()?).map_err(|_| AslError::InvalidMessage)?;
        let parent = groups
            .store
            .latest_active_conversation_budget(&conversation_id, now)?
            .ok_or(AslError::NotFound)?;
        let requested_expiry = now
            .checked_add(i64::try_from(window_ms).map_err(|_| AslError::InvalidMessage)?)
            .ok_or(AslError::InvalidMessage)?;
        let expires_at_ms = requested_expiry.max(parent.expires_at_ms);
        let first = fresh_id()?;
        let second = fresh_id()?;
        let mut grant_id = [0; 32];
        grant_id[..16].copy_from_slice(&first);
        grant_id[16..].copy_from_slice(&second);
        groups
            .store
            .renew_conversation_budget(ConversationBudgetRenewal {
                conversation_id: &conversation_id,
                grant_id,
                renewed_from: parent.grant_id,
                additional_messages,
                now_ms: now,
                expires_at_ms,
            })?;
        Ok(json!({
            "conversation_id": conversation_id,
            "grant_id": alloy_primitives::hex::encode(grant_id),
            "additional_messages": additional_messages,
            "expires_at_ms": expires_at_ms,
        }))
    }

    fn renew_resource_budget(
        &mut self,
        conversation_id: String,
        kind: BudgetKind,
        additional: u64,
        window_ms: u64,
    ) -> Result<Value, AslError> {
        let now = unix_time_ms()?;
        let expires_at_ms = now.saturating_add(window_ms);
        let groups = self.groups.as_mut().ok_or(AslError::NotFound)?;
        if !groups.store.renew_resource_budget(
            &conversation_id,
            kind,
            additional,
            expires_at_ms,
            now,
        )? {
            return Err(AslError::NotFound);
        }
        Ok(json!({
            "conversation_id": conversation_id,
            "kind": match kind {
                BudgetKind::MessageBytes => "message_bytes",
                BudgetKind::ModelCalls => "model_calls",
                BudgetKind::CpuMs => "cpu_ms",
                BudgetKind::MailboxBytes => "mailbox_bytes",
            },
            "additional": additional,
            "expires_at_ms": expires_at_ms,
        }))
    }

    fn claim_mail_offer(
        &mut self,
        handle: Id128,
        inbox: Id128,
        scope: QueryScope,
    ) -> Result<DownloadSelection, AslError> {
        let now = unix_time_ms()?;
        let held = self.mailbox.take_offer(handle, now)?;
        let store = self.network_report.store();
        if store.network_pause_requested()?
            || (scope == QueryScope::ContactsOnly
                && !store.authorized_contacts()?.contains(&held.source.agent_id))
        {
            return Err(AslError::PolicyDenied);
        }
        if let Some((room, epoch, binding)) = &held.room {
            let connection = if held.connection != [0; 16] {
                held.connection
            } else {
                self.admission
                    .as_ref()
                    .ok_or(AslError::NotFound)?
                    .admitted_connections(now)
                    .into_iter()
                    .find(|(agent, _, peer)| {
                        *agent == held.source.agent_id && *peer == held.source.peer_id
                    })
                    .map(|(_, connection, _)| connection)
                    .ok_or(AslError::NotFound)?
            };
            let member = self
                .current_group_requester(connection, &held.source.peer_id, *room, *epoch)
                .ok_or(AslError::PolicyDenied)?;
            if !GroupInboundPolicy::load(store)?.browse_enabled
                || member.direct.agent != held.source.agent_id
                || member.group_id != binding.group_id
                || member.membership_epoch != binding.membership_epoch
            {
                return Err(AslError::PolicyDenied);
            }
        } else {
            let admission = self.admission.as_mut().ok_or(AslError::NotFound)?;
            if read_mode(store)? == InboundMode::Disabled
                || admission.admitted_peer_identity(held.connection, now)?
                    != (held.source.agent_id, held.source.peer_id.clone())
            {
                return Err(AslError::PolicyDenied);
            }
        }
        Ok(held.selection(inbox))
    }
}

fn load_conformance_ready_contexts(
    store: &Store,
    admission: &mut crate::profile::CoreAdmission,
    roots: &[SemanticContextRef],
    now_ms: u64,
) -> Result<Vec<ConformanceReadySemanticContextBundle>, AslError> {
    if roots.is_empty() {
        return Err(AslError::InvalidMessage);
    }
    let mut pending = roots.to_vec();
    let mut authenticated = BTreeMap::<ContextKey, AuthenticatedSemanticContextBundle>::new();
    while let Some(reference) = pending.pop() {
        let key = ContextKey::from(reference);
        if authenticated.contains_key(&key) {
            continue;
        }
        if authenticated.len() >= MAX_CONTEXT_GRAPH_ITEMS {
            return Err(AslError::QuotaExceeded);
        }
        let bytes = store
            .semantic_context_candidate(reference)?
            .ok_or(AslError::NotFound)?;
        let signed = asl_types::protocol::SignedSemanticContextBundle::decode(&bytes)?;
        if signed.bundle.context_ref()? != reference {
            return Err(AslError::InvalidIdentity);
        }
        let controller = admission.verified_controller(reference.authority, now_ms)?;
        let package = authenticate_semantic_context(signed, reference.authority, controller)?;
        pending.extend(package.bundle().dependencies.iter().copied());
        authenticated.insert(key, package);
    }

    let packages = authenticated.into_values().collect::<Vec<_>>();
    packages
        .iter()
        .map(|package| {
            let dependencies = packages
                .iter()
                .filter(|dependency| dependency.context_ref() != package.context_ref())
                .cloned()
                .collect();
            check_context_conformance(package.clone(), dependencies)
        })
        .collect()
}

fn evaluate_incoming_context_expression(
    store: &Store,
    admission: &mut crate::profile::CoreAdmission,
    expression: &ContextExpression,
    now_ms: u64,
) -> SemanticEvaluation {
    let Ok(contexts) =
        load_conformance_ready_contexts(store, admission, &expression.required_contexts, now_ms)
    else {
        return SemanticEvaluation::Unresolved;
    };
    evaluate_semantic_expression(&expression.expression, &contexts)
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ContextKey {
    authority: [u8; 32],
    namespace: u32,
    revision: u16,
    digest: [u8; 32],
}

impl From<SemanticContextRef> for ContextKey {
    fn from(reference: SemanticContextRef) -> Self {
        Self {
            authority: reference.authority.0,
            namespace: reference.namespace,
            revision: reference.revision,
            digest: reference.digest.0,
        }
    }
}

fn check_letter_target(
    store: &asl_store::Store,
    local: &PeerId,
    scope: QueryScope,
    target: Target,
) -> Result<(), AslError> {
    match target {
        Target::Agent(agent) => {
            if read_mode(store)? != InboundMode::Answer
                || (scope == QueryScope::ContactsOnly
                    && !store.authorized_contacts()?.contains(&agent))
            {
                return Err(AslError::PolicyDenied);
            }
        }
        Target::Group(room) => {
            if !GroupInboundPolicy::load(store)?.answer_enabled {
                return Err(AslError::PolicyDenied);
            }
            if scope == QueryScope::ContactsOnly {
                let roster = store
                    .mls_room_for_reconciliation(room)?
                    .ok_or(AslError::PolicyDenied)?;
                let contacts = store.authorized_contacts()?;
                for peer in roster.members.iter().filter(|peer| *peer != local) {
                    if !store
                        .mls_peer_agent(peer)?
                        .is_some_and(|a| contacts.contains(&a))
                    {
                        return Err(AslError::PolicyDenied);
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(
        score: u32,
        term_weight: u32,
        received_at_ms: i64,
        name: &str,
        id: u8,
    ) -> HistorySearchHit {
        HistorySearchHit {
            conversation_id: name.into(),
            act_id: [id; 32],
            mls_epoch: None,
            direction: ActDirection::In,
            act_kind: 1,
            causal_root: None,
            reply_to: None,
            body: None,
            ranking: ActHistoryRanking {
                matched_terms: 2,
                query_terms: 2,
                term_weight,
            },
            score,
            received_at_ms,
            expires_at_ms: received_at_ms + 1_000,
            source: "semantic_index",
        }
    }

    fn sample_hits() -> Vec<HistorySearchHit> {
        vec![
            hit(1_000_004, 4, 100, "a", 1),
            hit(3_000_013, 13, 300, "c", 3),
            hit(2_000_013, 13, 200, "b", 2),
        ]
    }

    fn key(hit: &HistorySearchHit) -> (String, [u8; 32]) {
        (hit.conversation_id.clone(), hit.act_id)
    }

    #[test]
    fn history_cursor_pages_are_stable_and_do_not_repeat_entries() {
        let query_hash = [9; 16];
        let (first_page, has_more, next_cursor) =
            page_history_hits(sample_hits(), query_hash, 2, None);
        assert!(has_more);
        assert_eq!(
            first_page
                .iter()
                .map(|hit| hit.conversation_id.as_str())
                .collect::<Vec<_>>(),
            ["c", "b"]
        );
        let next_cursor = next_cursor.unwrap();
        assert!(parse_history_cursor(&next_cursor, [8; 16]).is_err());
        let cursor = parse_history_cursor(&next_cursor, query_hash).unwrap();
        let (second_page, has_more, next_cursor) =
            page_history_hits(sample_hits(), query_hash, 2, Some(&cursor));
        assert!(!has_more);
        assert!(next_cursor.is_none());
        assert_eq!(second_page.len(), 1);
        assert_eq!(second_page[0].conversation_id, "a");

        let first_keys = first_page.iter().map(key).collect::<Vec<_>>();
        assert!(
            second_page
                .iter()
                .map(key)
                .all(|key| !first_keys.contains(&key))
        );
    }
}
