use std::collections::BTreeMap;

use asl_agent::{QueryScope, runner::InboundMode};
use asl_groups::GroupApplication;
use asl_store::{
    Store,
    act_history::ActDirection,
    group_access::GroupAccessKind,
    group_state::{GROUP_INVITE_REQUEST_TTL_MS, GroupInboundPolicy},
    mailbox::ConversationBudgetRenewal,
};
use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId},
    protocol::{
        Act, ContextAgreement, ContextAgreementStatus, ContextExpression, ContextRequest,
        Expression, ExpressionLetter, GroupBody, GroupMembership, GroupPacket, SemanticContextRef,
        WireFrame, encode_frame,
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
            MailCommand::ActHistorySearch {
                query,
                limit,
                reply,
            } if !reply.is_closed() => {
                let _ = reply.send(self.search_act_history(query, limit));
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
            MailCommand::RequestContext {
                target,
                scope,
                reference,
                reply,
            } if !reply.is_closed() => {
                let _ = reply.send(self.send_context_request(target, scope, reference));
            }
            MailCommand::ConfirmContext { request_id, reply } if !reply.is_closed() => {
                let _ = reply.send(self.confirm_context_request(request_id));
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
        let Target::Agent(agent) = target else {
            return Err(AslError::InvalidMessage);
        };
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
        let admission = self.admission.as_mut().ok_or(AslError::NotFound)?;
        let (_, connection, _) = admission
            .admitted_connections(now)
            .into_iter()
            .filter(|(candidate, _, _)| *candidate == agent)
            .find(|(_, connection, _)| admission.peer_supports_contexts(*connection))
            .ok_or(AslError::IncompatibleVersion)?;
        let command = admission
            .authorize_control_command(connection, id.0, WireFrame::ContextExpression(letter), now)?
            .into_ipc()?;
        store.with_mail_dispatch(|| {
            check_letter_target(store, &self.device_peer_id, scope, target)?;
            if store.network_pause_requested()? {
                return Err(AslError::PolicyDenied);
            }
            if !self.net.try_send(&command)? {
                return Err(AslError::QuotaExceeded);
            }
            Ok(())
        })?;
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
        target: asl_types::ids::AgentId,
        scope: QueryScope,
        reference: SemanticContextRef,
    ) -> Result<Id128, AslError> {
        let now = unix_time_ms()?;
        let store = self.network_report.store();
        if !self.net.is_running()
            || self.network_admission_status != NetworkAdmissionStatus::Active
            || store.network_pause_requested()?
            || read_mode(store)? == InboundMode::Disabled
            || (scope == QueryScope::ContactsOnly
                && !store.authorized_contacts()?.contains(&target))
        {
            return Err(AslError::PolicyDenied);
        }
        let admission = self.admission.as_mut().ok_or(AslError::NotFound)?;
        let (_, connection, peer) = admission
            .admitted_connections(now)
            .into_iter()
            .find(|(agent, _, _)| *agent == target)
            .ok_or(AslError::NotFound)?;
        if !admission.peer_supports_contexts(connection) {
            return Err(AslError::IncompatibleVersion);
        }
        let request_id = Id128(fresh_id()?);
        let expires_at_ms = now.saturating_add(10_000);
        let request = ContextRequest {
            message_id: request_id,
            reference,
            expires_at_ms,
        };
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
            if store.network_pause_requested()?
                || (scope == QueryScope::ContactsOnly
                    && !store.authorized_contacts()?.contains(&target))
            {
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
        Ok(request_id)
    }

    fn confirm_context_request(
        &mut self,
        request_id: Id128,
    ) -> Result<(Id128, ContextAgreementStatus), AslError> {
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

    fn send_group_act(&mut self, room: Hash32, mut act: Act) -> Result<Id128, AslError> {
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
        let conversation_id = alloy_primitives::hex::encode(act.conversation_id.0);
        let now_i64 = i64::try_from(now).map_err(|_| AslError::InvalidMessage)?;
        if !groups
            .store
            .conversation_budget_available(&conversation_id, 1, now_i64)?
        {
            return Err(AslError::QuotaExceeded);
        }
        let admission = self.admission.as_mut().ok_or(AslError::NotFound)?;
        let message_id = act.message_id;
        let history_act = act.clone();
        let sent = admission.send_loopback_mls_application_with_gossip(
            &mut groups.store,
            room,
            GroupApplication::Act(act),
            now,
            |command| {
                if self.net.try_send(&command.into_ipc()?)? {
                    Ok(())
                } else {
                    Err(AslError::SandboxUnavailable)
                }
            },
        )?;
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
        groups
            .store
            .consume_conversation_budget(&conversation_id, 1, now_i64)?;
        let envelope = sent.packet.into_envelope()?;
        let payload = encode_frame(&WireFrame::GroupEnvelope(envelope))?;
        let _ = self.net.try_send(
            &NetworkCommand::GossipPublish {
                operation_id: fresh_id()?,
                key: room.0,
                payload,
            }
            .into_ipc()?,
        );
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
        if !groups.store.group_can_send(
            &local_group_id,
            &self.device_peer_id,
            GroupAccessKind::Files,
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
        let envelope = sent.packet.into_envelope()?;
        let payload = encode_frame(&WireFrame::GroupEnvelope(envelope))?;
        let _ = self.net.try_send(
            &NetworkCommand::GossipPublish {
                operation_id: fresh_id()?,
                key: room.0,
                payload,
            }
            .into_ipc()?,
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
        for connection_id in connections {
            let result = self.apply_local_group_action(
                LocalGroupAction::Invite {
                    room,
                    connection_id,
                },
                now,
            )?;
            queued += result.get("queued").and_then(Value::as_u64).unwrap_or(0);
        }
        Ok(json!({
            "room": alloy_primitives::hex::encode(room.0),
            "agent": format!("agent:{}", alloy_primitives::hex::encode(agent.0)),
            "queued": queued,
        }))
    }

    fn request_group_join(&mut self, room: Hash32, owner: AgentId) -> Result<Value, AslError> {
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

    fn search_act_history(&self, query: String, limit: u32) -> Result<Value, AslError> {
        let now = i64::try_from(unix_time_ms()?).map_err(|_| AslError::InvalidPolicyState)?;
        let store = asl_store::open_store_read_only(&self.state_database)?;
        let entries = store
            .search_act_history(now, &query, limit)?
            .into_iter()
            .map(|row| {
                json!({
                    "conversation_id": row.conversation_id,
                    "act_id": alloy_primitives::hex::encode(row.act_id),
                    "mls_epoch": row.mls_epoch,
                    "direction": row.direction.as_str(),
                    "act_kind": row.act_kind,
                    "causal_root": alloy_primitives::hex::encode(row.causal_root),
                    "reply_to": row.reply_to.map(alloy_primitives::hex::encode),
                    "body": row.body,
                    "received_at_ms": row.created_at_ms,
                    "expires_at_ms": row.expires_at_ms,
                })
            })
            .collect::<Vec<_>>();
        Ok(json!({
            "query": query,
            "limit": limit,
            "entries": entries,
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
