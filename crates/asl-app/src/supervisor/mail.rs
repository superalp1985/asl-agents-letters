use asl_agent::{QueryScope, runner::InboundMode};
use asl_store::group_state::GroupInboundPolicy;
use asl_types::{
    error::AslError,
    ids::{Id128, PeerId},
    protocol::{Expression, ExpressionLetter, WireFrame},
};

use super::{NetworkAdmissionStatus, Supervisor, unix_time_ms};
use crate::{
    agent_mail::{MailCommand, Target},
    direct_inbound::read_mode,
    downloads::{DownloadSelection, DownloadSource},
    profile::{AdmittedNetworkEvent, fresh_id},
};

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
        let Some(requester) = admission.direct_requester(*connection_id, *agent_id) else {
            return Ok(());
        };
        let store = self.network_report.store();
        if read_mode(store)? == InboundMode::Disabled || store.network_pause_requested()? {
            return Ok(());
        }
        let now = unix_time_ms()?;
        let accepted = self.mailbox.observe(
            DownloadSource {
                agent_id: requester.agent,
                peer_id: requester.peer,
            },
            *connection_id,
            None,
            request,
            now,
        );
        if accepted && let WireFrame::Expression(e) = request {
            store
                .with_mail_dispatch(|| {
                    if read_mode(store)? == InboundMode::Answer
                        && !store.network_pause_requested()?
                        && unix_time_ms()? < e.expires_at_ms
                    {
                        let ack = WireFrame::Ack(asl_types::protocol::Ack {
                            message_id: Id128(fresh_id()?),
                            received_id: e.message_id,
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
        let Ok(command) = self.mailbox.commands.try_recv() else {
            return;
        };
        match command {
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
                groups.dispatch_letter(admission, room, letter, now, |cmd| {
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
            let member = self
                .current_group_requester(held.connection, &held.source.peer_id, *room, *epoch)
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
