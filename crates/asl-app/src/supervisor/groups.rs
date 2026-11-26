use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::SocketAddr,
    path::Path,
    sync::mpsc::{Receiver, SyncSender, TryRecvError},
    time::{Duration, Instant},
};

use alloy_primitives::hex;
use asl_agent::runner::{InboundMode, InboundRunner, Ingress, ResourceMatch};
use asl_groups::GroupApplication;
use asl_policy::PolicyEngine;
use asl_store::{
    Store,
    act_history::{ActDirection, ActHistoryRecord},
    group_access::{GroupAccessKind, GroupMemberAccess},
    group_state::{GroupInboundPolicy, MlsIncomingInvite, open_mls_runtime_store},
    mailbox::{
        ConversationBudgetGrant, MAX_BUDGET_MESSAGES, MAX_BUDGET_RENEWALS, MAX_BUDGET_WINDOW_MS,
        MailboxPut,
    },
    search::group::GroupRequester,
};
use asl_types::{
    error::AslError,
    ids::{Hash32, Id128, PeerId},
    protocol::{
        Act, ActType, GROUP_ALLOW_MEMBER_FILES, GROUP_ALLOW_MEMBER_INVITE, GROUP_ALLOW_MEMBER_TEXT,
        GroupControl, GroupPacket, Intent, MediaKind, ResultShape, WireFrame, decode_frame,
        encode_frame,
    },
    task::GroupId,
};
use serde_json::{Value, json};

use crate::{
    agent_mail::GroupAccessUpdate,
    model_endpoint_access::ModelEndpointAccess,
    network::{NetworkCommand, NetworkEvent},
    profile::{MlsInviteSend, MlsJoinSend, MlsNetworkOutcome, fresh_id},
    transfer::TransferService,
};

use super::{
    AppPaths, NetRuntime, NetworkAdmissionStatus, Supervisor, TransportKind, configured_root,
    unix_time_ms,
};

mod operator;
#[cfg(test)]
mod process_tests;

const PRUNE_INTERVAL: Duration = Duration::from_secs(30);
const SYNC_PROBE_INTERVAL: Duration = Duration::from_secs(15);
const INVITE_LIFETIME_MS: u64 = 5 * 60 * 1_000;
const MAX_JOIN_DIAGNOSTICS: usize = 5;
const MAX_RECENT_ROOMS: usize = 32;
const MAX_PENDING_GROUP_TRANSFERS: usize = 64;

pub enum LocalGroupAction {
    List,
    Room(Hash32),
    Peers,
    Create,
    Approve(Id128),
    Retry(Id128),
    Reject(Id128),
    Invite {
        room: Hash32,
        connection_id: [u8; 16],
    },
    Remove {
        room: Hash32,
        peer: PeerId,
    },
    /// Trusted in-process callers only; not parsed by the local console.
    /// Sending an expression requires an explicit action through this path.
    SendApplication {
        room: Hash32,
        application: Box<GroupApplication>,
    },
    SetAccess {
        room: Hash32,
        update: GroupAccessUpdate,
    },
    ConfigureInbound {
        browse_enabled: bool,
        answer_enabled: bool,
    },
    Dial {
        address: SocketAddr,
        peer: PeerId,
    },
}

/// Local console only. There is no corresponding agent, worker or P2P command.
pub struct LocalGroupCommand {
    pub action: LocalGroupAction,
    /// Provide a reply channel with room for one response.
    pub reply: SyncSender<Result<Value, AslError>>,
}

pub(super) struct LoopbackGroups {
    pub(super) store: Store,
    next_prune: Instant,
    next_review: Instant,
    operator_view: Option<asl_store::group_state::operator::AdminSnapshot>,
    cleanup_failed: bool,
    join_diagnostics: VecDeque<(Id128, &'static str)>,
    recent_applications: VecDeque<ReceivedApplication>,
    next_sync_probe: Instant,
    sync_cursor: Option<(Hash32, PeerId)>,
    pending_transfers: VecDeque<PendingGroupTransfer>,
    gossip_subscriptions: HashSet<Hash32>,
}

struct ReceivedApplication {
    room: Hash32,
    epoch: u64,
    sender: PeerId,
    message: Id128,
    kind: &'static str,
}

struct PendingGroupTransfer {
    connection_id: [u8; 16],
    wire_id: Hash32,
    epoch: u64,
    envelope_id: Id128,
    sender: PeerId,
    application: GroupApplication,
}

impl LoopbackGroups {
    pub(super) fn dispatch_letter(
        &mut self,
        admission: &mut crate::profile::CoreAdmission,
        local_peer: &PeerId,
        room: Hash32,
        letter: asl_types::protocol::ExpressionLetter,
        now: u64,
        enqueue: impl FnMut(NetworkCommand) -> Result<(), AslError>,
    ) -> Result<(), AslError> {
        if self.cleanup_failed || !GroupInboundPolicy::load(&self.store)?.answer_enabled {
            return Err(AslError::PolicyDenied);
        }
        let snapshot = self
            .store
            .mls_room_snapshot(room)?
            .ok_or(AslError::NotFound)?;
        if !self
            .store
            .group_can_send(&snapshot.local_id, local_peer, GroupAccessKind::Text)?
        {
            return Err(AslError::PolicyDenied);
        }
        let sent = admission.send_loopback_mls_application(
            &mut self.store,
            room,
            GroupApplication::Expression(letter),
            now,
            enqueue,
        )?;
        if sent.queued == 0 {
            return Err(AslError::PolicyDenied);
        }
        Ok(())
    }

    pub(super) fn open(path: &Path, now_ms: u64) -> Result<Self, AslError> {
        let mut store = open_mls_runtime_store(path)?;
        store.prune_mls_expired(now_ms)?;
        Ok(Self {
            store,
            next_prune: Instant::now() + PRUNE_INTERVAL,
            next_review: Instant::now(),
            operator_view: None,
            cleanup_failed: false,
            join_diagnostics: VecDeque::new(),
            recent_applications: VecDeque::new(),
            next_sync_probe: Instant::now() + SYNC_PROBE_INTERVAL,
            sync_cursor: None,
            pending_transfers: VecDeque::new(),
            gossip_subscriptions: HashSet::new(),
        })
    }
}

impl Supervisor {
    pub(super) fn configure_group_admission(&mut self) {
        if self.groups.is_some()
            && let Some(admission) = &mut self.admission
        {
            admission.enable_loopback_mls_directories();
        }
    }

    pub(super) fn group_members(&self, room: Hash32) -> Result<Value, AslError> {
        let groups = self.groups.as_ref().ok_or(AslError::NotFound)?;
        let snapshot = groups
            .store
            .mls_room_snapshot(room)?
            .ok_or(AslError::NotFound)?;
        let policy = groups.store.group_access_policy(&snapshot.local_id)?;
        let mut members = groups.store.group_members(&snapshot.local_id)?;
        members.sort_by(|left, right| {
            left.role
                .as_str()
                .cmp(right.role.as_str())
                .then_with(|| left.peer.as_bytes().cmp(right.peer.as_bytes()))
        });
        Ok(json!({
            "room": hex::encode(room.0),
            "conversation_id": hex::encode(snapshot.local_id.0.0),
            "policy_revision": policy.revision,
            "allow_member_text": policy.permissions & GROUP_ALLOW_MEMBER_TEXT != 0,
            "allow_member_files": policy.permissions & GROUP_ALLOW_MEMBER_FILES != 0,
            "allow_member_invite": policy.permissions & GROUP_ALLOW_MEMBER_INVITE != 0,
            "members": members.iter().map(member_view).collect::<Vec<_>>(),
        }))
    }

    pub(super) fn set_group_access(
        &mut self,
        room: Hash32,
        update: GroupAccessUpdate,
    ) -> Result<Value, AslError> {
        let now = unix_time_ms()?;
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
        let owner = groups
            .store
            .group_access_owner(room)?
            .ok_or(AslError::NotFound)?;
        if owner != self.device_peer_id {
            return Err(AslError::PolicyDenied);
        }
        let current = groups.store.group_access_policy(&snapshot.local_id)?;
        let mut permissions = 0;
        if update.allow_member_text {
            permissions |= GROUP_ALLOW_MEMBER_TEXT;
        }
        if update.allow_member_files {
            permissions |= GROUP_ALLOW_MEMBER_FILES;
        }
        if update.allow_member_invite {
            permissions |= GROUP_ALLOW_MEMBER_INVITE;
        }
        let control = GroupControl {
            message_id: Id128(fresh_id()?),
            policy_revision: current
                .revision
                .checked_add(1)
                .ok_or(AslError::QuotaExceeded)?,
            permissions,
            admins: update.admins,
            muted: update.muted,
        };
        groups.store.apply_group_control(
            &snapshot.local_id,
            &self.device_peer_id,
            &control,
            now,
        )?;
        let admission = self.admission.as_mut().ok_or(AslError::NotFound)?;
        let sent = admission.send_loopback_mls_application_with_gossip(
            &mut groups.store,
            room,
            GroupApplication::Policy(control.clone()),
            now,
            |command| {
                if self.net.try_send(&command.into_ipc()?)? {
                    Ok(())
                } else {
                    Err(AslError::SandboxUnavailable)
                }
            },
        )?;
        let payload = encode_frame(&WireFrame::GroupEnvelope(sent.packet.into_envelope()?))?;
        let _ = self.net.try_send(
            &NetworkCommand::GossipPublish {
                operation_id: fresh_id()?,
                key: room.0,
                payload,
            }
            .into_ipc()?,
        );
        Ok(json!({
            "room": hex::encode(room.0),
            "policy_revision": control.policy_revision,
            "permissions": control.permissions,
            "admins": control.admins.iter().map(peer_text).collect::<Vec<_>>(),
            "muted": control.muted.iter().map(peer_text).collect::<Vec<_>>(),
            "queued": sent.queued,
            "available": sent.available,
        }))
    }

    pub(super) fn route_group_event(&mut self, event: NetworkEvent, now_ms: u64) {
        if let NetworkEvent::GossipReceived { key, payload, .. } = &event {
            let _ = self.handle_group_gossip(Hash32(*key), payload, now_ms);
            return;
        }
        let (Some(groups), Some(admission), auto_reply, libraries, home) = (
            &mut self.groups,
            &mut self.admission,
            &mut self.auto_reply,
            &self.libraries,
            &self.home,
        ) else {
            return;
        };
        if groups.cleanup_failed {
            return;
        }
        let net = &self.net;
        let joined_route = match &event {
            NetworkEvent::UnverifiedGroupResponse {
                connection_id,
                response,
                ..
            } => Some((*connection_id, response.group_id)),
            _ => None,
        };
        // Room state and invitations are already durable. Neither raw frames
        // nor protocol errors should reach the generic Agent handler.
        let invite = admission.mls_reply_invite(&event, now_ms);
        let result = admission.handle_mls_network_event(
            &mut groups.store,
            event,
            &HashMap::new(),
            now_ms,
            |command| enqueue(net, command),
        );
        if let Ok(Some(MlsNetworkOutcome::ApplicationReceived {
            connection_id,
            wire_id,
            epoch,
            envelope_id,
            sender,
            application,
        })) = &result
        {
            if let GroupApplication::Policy(control) = application.as_ref() {
                let _ = apply_group_policy(&mut groups.store, *wire_id, sender, control, now_ms);
                return;
            }
            if GroupInboundPolicy::load(&groups.store).is_ok_and(|policy| policy.browse_enabled) {
                groups
                    .recent_applications
                    .retain(|entry| entry.room != *wire_id);
                if groups.recent_applications.len() == MAX_RECENT_ROOMS {
                    groups.recent_applications.pop_front();
                }
                groups.recent_applications.push_back(ReceivedApplication {
                    room: *wire_id,
                    epoch: *epoch,
                    sender: sender.clone(),
                    message: application.message_id(),
                    kind: application.kind(),
                });
            }
            let requester = groups
                .store
                .mls_peer_agent(sender)
                .ok()
                .flatten()
                .and_then(|agent| {
                    let direct = admission.direct_requester(*connection_id, agent)?;
                    let snapshot = groups.store.mls_room_snapshot(*wire_id).ok().flatten()?;
                    let (state, _) = groups.store.mls_room_progress(*wire_id).ok().flatten()?;
                    (state == "active").then_some(GroupRequester {
                        direct,
                        wire_id: *wire_id,
                        group_id: snapshot.local_id,
                        membership_epoch: snapshot.version.membership_epoch,
                    })
                });
            let member_allowed =
                requester
                    .as_ref()
                    .is_none_or(|member| match application.as_ref() {
                        GroupApplication::Act(_)
                        | GroupApplication::Query(_)
                        | GroupApplication::Expression(_) => groups
                            .store
                            .group_can_send(&member.group_id, sender, GroupAccessKind::Text)
                            .unwrap_or(false),
                        GroupApplication::Offer(_) => groups
                            .store
                            .group_can_send(&member.group_id, sender, GroupAccessKind::Files)
                            .unwrap_or(false),
                        _ => true,
                    });
            if member_allowed && let GroupApplication::Act(act) = application.as_ref() {
                if let Some(member) = requester.as_ref()
                    && GroupInboundPolicy::load(&groups.store)
                        .is_ok_and(|policy| policy.browse_enabled)
                {
                    let _ = record_act_history(
                        &mut groups.store,
                        &member.group_id,
                        *epoch,
                        ActDirection::In,
                        act,
                        now_ms,
                    );
                }
                if GroupInboundPolicy::load(&groups.store).is_ok_and(|policy| policy.answer_enabled)
                {
                    let evidence = requester.as_ref().and_then(|member| {
                        let paths = AppPaths::open_existing(home).ok()?;
                        let provider = ModelEndpointAccess::new(&paths)
                            .first_authorized_config()
                            .ok()
                            .flatten()?;
                        let provider_local =
                            provider.mode == asl_agent::gateway::ProviderMode::Local;
                        super::auto_reply_evidence::select_auto_reply_evidence(
                            &groups.store,
                            libraries,
                            member,
                            provider.id,
                            provider_local,
                            act.nl_body.as_deref()?,
                        )
                        .ok()
                    });
                    super::auto_reply::queue_auto_reply(auto_reply, *wire_id, act, evidence);
                }
            }
            if member_allowed
                && self.mailbox.interested()
                && let Some(member) = requester.as_ref()
                && GroupInboundPolicy::load(&groups.store).is_ok_and(|policy| policy.browse_enabled)
            {
                if let GroupApplication::Act(act) = application.as_ref() {
                    let group = asl_store::transfers::GroupTransferBinding {
                        group_id: member.group_id.clone(),
                        membership_epoch: member.membership_epoch,
                    };
                    self.mailbox.observe_act(
                        crate::downloads::DownloadSource {
                            agent_id: member.direct.agent,
                            peer_id: sender.clone(),
                        },
                        *connection_id,
                        (*wire_id, *epoch, group),
                        act,
                        now_ms,
                    );
                }
                let frame = match application.as_ref() {
                    GroupApplication::Query(q) => Some(WireFrame::Query(q.clone())),
                    GroupApplication::Answer(a) => Some(WireFrame::Answer(a.clone())),
                    GroupApplication::Offer(o) => Some(WireFrame::Offer(o.clone())),
                    GroupApplication::Expression(e) => Some(WireFrame::Expression(e.clone())),
                    _ => None,
                };
                if let Some(frame) = frame {
                    let group = asl_store::transfers::GroupTransferBinding {
                        group_id: member.group_id.clone(),
                        membership_epoch: member.membership_epoch,
                    };
                    self.mailbox.observe(
                        crate::downloads::DownloadSource {
                            agent_id: member.direct.agent,
                            peer_id: sender.clone(),
                        },
                        *connection_id,
                        Some((*wire_id, *epoch, group)),
                        &frame,
                        now_ms,
                    );
                }
            }
            if matches!(
                application.as_ref(),
                GroupApplication::FetchRequest(_)
                    | GroupApplication::FetchGrant(_)
                    | GroupApplication::FetchPending(_)
                    | GroupApplication::Error(_)
            ) {
                if groups.pending_transfers.len() == MAX_PENDING_GROUP_TRANSFERS {
                    groups.pending_transfers.pop_front();
                }
                groups.pending_transfers.push_back(PendingGroupTransfer {
                    connection_id: *connection_id,
                    wire_id: *wire_id,
                    epoch: *epoch,
                    envelope_id: *envelope_id,
                    sender: sender.clone(),
                    application: application.as_ref().clone(),
                });
            }
            match groups.prepare_application_reply(
                *wire_id,
                &self.device_peer_id,
                sender,
                application,
                requester.as_ref(),
                now_ms,
            ) {
                Ok(Some(reply)) => {
                    let _ = admission.send_group_query_reply(
                        &mut groups.store,
                        *wire_id,
                        reply,
                        now_ms,
                        |command| enqueue(net, command),
                    );
                }
                Ok(None) => {}
                Err(_) => {}
            }
        }
        if matches!(&result, Ok(Some(MlsNetworkOutcome::Joined { .. })))
            && let Some((connection_id, wire_id)) = joined_route
            && let Ok(sync_now_ms) = unix_time_ms()
        {
            let _ = admission.start_mls_sync(
                &groups.store,
                connection_id,
                wire_id,
                &HashMap::new(),
                sync_now_ms,
                |command| enqueue(net, command),
            );
        }
        if let Some(id) = invite {
            match result {
                Ok(Some(MlsNetworkOutcome::Joined { .. })) => {
                    groups
                        .join_diagnostics
                        .retain(|(previous, _)| *previous != id);
                }
                Err(error) => {
                    groups
                        .join_diagnostics
                        .retain(|(previous, _)| *previous != id);
                    if groups.join_diagnostics.len() == MAX_JOIN_DIAGNOSTICS {
                        groups.join_diagnostics.pop_front();
                    }
                    groups
                        .join_diagnostics
                        .push_back((id, describe_join_failure(error)));
                }
                _ => {}
            }
        }
    }

    pub(super) fn handle_group_gossip(
        &mut self,
        key: Hash32,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<(), AslError> {
        let envelope = match decode_frame(payload)? {
            WireFrame::GroupEnvelope(envelope) => envelope,
            _ => return Err(AslError::InvalidMessage),
        };
        let packet = GroupPacket::from_envelope(envelope)?;
        if packet.group_id != key {
            return Err(AslError::InvalidMessage);
        }
        let directories = HashMap::new();
        let (Some(groups), Some(admission)) = (self.groups.as_mut(), self.admission.as_mut())
        else {
            return Ok(());
        };
        let mailbox = &mut self.mailbox;
        let auto_reply = &mut self.auto_reply;
        let Some((application, agent, peer)) =
            admission.apply_mls_gossip(&mut groups.store, &packet, &directories, now_ms)?
        else {
            return Ok(());
        };
        let snapshot = groups
            .store
            .mls_room_snapshot(key)?
            .ok_or(AslError::NotFound)?;
        let local_group_id = snapshot.local_id.clone();
        let binding = asl_store::transfers::GroupTransferBinding {
            group_id: local_group_id.clone(),
            membership_epoch: snapshot.version.membership_epoch,
        };
        if let GroupApplication::Policy(control) = &application {
            let _ = apply_group_policy(&mut groups.store, key, &peer, control, now_ms);
            return Ok(());
        }
        let member_allowed = match &application {
            GroupApplication::Act(_)
            | GroupApplication::Query(_)
            | GroupApplication::Expression(_) => groups
                .store
                .group_can_send(&local_group_id, &peer, GroupAccessKind::Text)
                .unwrap_or(false),
            GroupApplication::Offer(_) => groups
                .store
                .group_can_send(&local_group_id, &peer, GroupAccessKind::Files)
                .unwrap_or(false),
            _ => true,
        };
        if !member_allowed {
            return Ok(());
        }
        if let GroupApplication::Act(act) = &application
            && GroupInboundPolicy::load(&groups.store).is_ok_and(|policy| policy.browse_enabled)
        {
            let _ = record_act_history(
                &mut groups.store,
                &local_group_id,
                packet.epoch,
                ActDirection::In,
                act,
                now_ms,
            );
        }
        if let GroupApplication::Act(act) = &application
            && GroupInboundPolicy::load(&groups.store).is_ok_and(|policy| policy.answer_enabled)
        {
            super::auto_reply::queue_auto_reply(auto_reply, key, act, None);
        }
        if let GroupApplication::Act(act) = &application
            && mailbox.interested()
            && GroupInboundPolicy::load(&groups.store).is_ok_and(|policy| policy.browse_enabled)
        {
            mailbox.observe_act(
                crate::downloads::DownloadSource {
                    agent_id: agent,
                    peer_id: peer.clone(),
                },
                [0; 16],
                (key, packet.epoch, binding.clone()),
                act,
                now_ms,
            );
        }
        let frame = match application {
            GroupApplication::Query(query) => Some(WireFrame::Query(query)),
            GroupApplication::Answer(answer) => Some(WireFrame::Answer(answer)),
            GroupApplication::Offer(offer) => Some(WireFrame::Offer(offer)),
            GroupApplication::Expression(expression) => Some(WireFrame::Expression(expression)),
            _ => None,
        };
        if let Some(frame) = frame
            && mailbox.interested()
            && GroupInboundPolicy::load(&groups.store).is_ok_and(|policy| policy.browse_enabled)
        {
            mailbox.observe(
                crate::downloads::DownloadSource {
                    agent_id: agent,
                    peer_id: peer,
                },
                [0; 16],
                Some((key, packet.epoch, binding)),
                &frame,
                now_ms,
            );
        }
        Ok(())
    }

    pub(super) fn poll_group_transfers(
        &mut self,
        transfers: &mut TransferService,
        mut deliver: impl FnMut(
            &mut Self,
            &mut TransferService,
            crate::profile::AdmittedNetworkEvent,
        ) -> Result<(), AslError>,
    ) -> Result<(), AslError> {
        loop {
            let Some(pending) = self
                .groups
                .as_mut()
                .and_then(|groups| groups.pending_transfers.pop_front())
            else {
                return Ok(());
            };
            let now_ms = unix_time_ms()?;
            let Some(requester) = self.current_group_requester(
                pending.connection_id,
                &pending.sender,
                pending.wire_id,
                pending.epoch,
            ) else {
                continue;
            };
            match pending.application {
                GroupApplication::FetchRequest(request) => {
                    let prepared = match transfers.prepare_group_fetch(requester, &request, now_ms)
                    {
                        Ok(prepared) => prepared,
                        Err(_) => continue,
                    };
                    let Some(groups) = self.groups.as_mut() else {
                        continue;
                    };
                    let Some(admission) = self.admission.as_mut() else {
                        continue;
                    };
                    let net = &self.net;
                    let result = transfers.finish_group_fetch(
                        prepared,
                        now_ms,
                        |response, envelope_id, _| {
                            let application = match response {
                                WireFrame::FetchGrant(grant) => GroupApplication::FetchGrant(grant),
                                WireFrame::FetchPending(pending) => {
                                    GroupApplication::FetchPending(pending)
                                }
                                WireFrame::Error(error) => GroupApplication::Error(error),
                                _ => return Err(AslError::InvalidMessage),
                            };
                            let dispatched = admission
                                .send_loopback_mls_application_to_connection(
                                    &mut groups.store,
                                    crate::profile::MlsApplicationSendToConnection {
                                        wire_id: pending.wire_id,
                                        connection_id: pending.connection_id,
                                        envelope_id,
                                        application,
                                        now_ms: unix_time_ms()?,
                                    },
                                    |command| enqueue(net, command),
                                )?;
                            if dispatched.queued == 0 {
                                return Err(AslError::NotFound);
                            }
                            Ok(())
                        },
                    );
                    if matches!(
                        result,
                        Err(AslError::NotFound
                            | AslError::PolicyDenied
                            | AslError::ExpiredMessage
                            | AslError::PolicyVersionConflict)
                    ) {
                        continue;
                    }
                    result?;
                }
                reply @ (GroupApplication::FetchGrant(_)
                | GroupApplication::FetchPending(_)
                | GroupApplication::Error(_)) => {
                    if !transfers.matches_group_reply(
                        pending.envelope_id,
                        pending.connection_id,
                        &requester,
                        now_ms,
                    ) {
                        continue;
                    }
                    let response = match reply {
                        GroupApplication::FetchGrant(grant) => WireFrame::FetchGrant(grant),
                        GroupApplication::FetchPending(wait) => WireFrame::FetchPending(wait),
                        GroupApplication::Error(error) => WireFrame::Error(error),
                        _ => unreachable!(),
                    };
                    let event = crate::profile::AdmittedNetworkEvent::ControlResponse {
                        connection_id: pending.connection_id,
                        agent_id: requester.direct.agent,
                        request_id: pending.envelope_id.0,
                        response,
                    };
                    if let Some(event) = Self::route_matched_transfer(
                        self.admission.as_mut(),
                        transfers,
                        event,
                        now_ms,
                        |command| self.net.try_send(&command.into_ipc()?),
                    )? {
                        deliver(self, transfers, event)?;
                    }
                }
                GroupApplication::Query(_)
                | GroupApplication::Answer(_)
                | GroupApplication::Offer(_)
                | GroupApplication::Expression(_)
                | GroupApplication::Act(_)
                | GroupApplication::Policy(_) => {}
            }
        }
    }

    pub(super) fn current_group_requester(
        &self,
        connection_id: [u8; 16],
        sender: &PeerId,
        wire_id: Hash32,
        epoch: u64,
    ) -> Option<GroupRequester> {
        let groups = self.groups.as_ref()?;
        let admission = self.admission.as_ref()?;
        let agent = groups.store.mls_peer_agent(sender).ok().flatten()?;
        let direct = admission.direct_requester(connection_id, agent)?;
        let snapshot = groups.store.mls_room_snapshot(wire_id).ok().flatten()?;
        let (state, _) = groups.store.mls_room_progress(wire_id).ok().flatten()?;
        (state == "active"
            && snapshot.version.mls_epoch == epoch
            && groups.store.has_mls_sync_member(wire_id, sender).ok()?)
        .then_some(GroupRequester {
            direct,
            wire_id,
            group_id: snapshot.local_id,
            membership_epoch: snapshot.version.membership_epoch,
        })
    }

    pub(super) fn send_group_fetch(
        &mut self,
        transfers: &mut TransferService,
        source: &crate::downloads::DownloadSource,
        group: &asl_store::transfers::GroupTransferBinding,
        request: &asl_types::protocol::FetchRequest,
    ) -> Result<Option<[u8; 16]>, AslError> {
        let now_ms = unix_time_ms()?;
        let groups = self.groups.as_mut().ok_or(AslError::PolicyDenied)?;
        let wire_id = groups
            .store
            .mls_room_wire_id(&group.group_id)?
            .ok_or(AslError::NotFound)?;
        let snapshot = groups
            .store
            .mls_room_snapshot(wire_id)?
            .ok_or(AslError::NotFound)?;
        let (state, _) = groups
            .store
            .mls_room_progress(wire_id)?
            .ok_or(AslError::NotFound)?;
        if state != "active"
            || snapshot.local_id != group.group_id
            || snapshot.version.membership_epoch != group.membership_epoch
        {
            return Ok(None);
        }
        let admission = self.admission.as_mut().ok_or(AslError::InvalidIdentity)?;
        let (agent_id, connection_id, _) = admission
            .admitted_connections(now_ms)
            .into_iter()
            .find(|(agent, _, peer)| *agent == source.agent_id && *peer == source.peer_id)
            .ok_or(AslError::NotFound)?;
        let requester = admission
            .direct_requester(connection_id, agent_id)
            .ok_or(AslError::InvalidIdentity)?;
        transfers.expect_group_fetch_response(
            connection_id,
            &requester,
            request,
            (wire_id, group.membership_epoch),
            now_ms,
        )?;
        let net = &self.net;
        let sent = admission.send_loopback_mls_application_to_connection(
            &mut groups.store,
            crate::profile::MlsApplicationSendToConnection {
                wire_id,
                connection_id,
                envelope_id: request.message_id,
                application: GroupApplication::FetchRequest(request.clone()),
                now_ms,
            },
            |command| enqueue(net, command),
        );
        match sent {
            Ok(dispatched) if dispatched.queued > 0 => Ok(Some(connection_id)),
            Ok(_) | Err(_) => {
                transfers.fail_control_request(
                    connection_id,
                    requester.agent,
                    &requester.peer,
                    request.message_id.0,
                );
                Ok(None)
            }
        }
    }

    pub(super) fn clear_group_transport(&mut self) {
        if let Some(groups) = &mut self.groups {
            groups.pending_transfers.clear();
            groups.operator_view = None;
        }
    }

    pub(super) fn poll_local_groups(&mut self) -> Result<(), AslError> {
        if let Some(groups) = &mut self.groups {
            let now = Instant::now();
            if now >= groups.next_prune {
                groups.next_prune = now + PRUNE_INTERVAL;
                groups.cleanup_failed = groups.store.prune_mls_expired(unix_time_ms()?).is_err();
            }
            if self.net.is_running()
                && self.network_admission_status == NetworkAdmissionStatus::Active
                && !groups.cleanup_failed
            {
                for (wire_id, _) in groups.store.list_mls_room_ids()? {
                    if groups.gossip_subscriptions.insert(wire_id) {
                        let command = NetworkCommand::GossipSubscribe {
                            operation_id: fresh_id()?,
                            key: wire_id.0,
                        };
                        if enqueue(&self.net, command).is_err() {
                            groups.gossip_subscriptions.remove(&wire_id);
                        }
                    }
                }
            }
            if self.net.is_running()
                && self.network_admission_status == NetworkAdmissionStatus::Active
                && !groups.cleanup_failed
                && let Some(admission) = &mut self.admission
            {
                groups.poll_sync(admission, &self.net, now, unix_time_ms()?);
            }
        }
        self.poll_group_review();
        let Some(controls) = &self.group_controls else {
            return Ok(());
        };
        match controls.try_recv() {
            Ok(command) => {
                let result = self.apply_local_group_action(command.action, unix_time_ms()?);
                let _ = command.reply.try_send(result);
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => self.group_controls = None,
        }
        Ok(())
    }

    fn poll_group_review(&mut self) {
        use asl_store::group_state::invite_review::{Choice, Outcome};
        let agent = self.agent_id();
        let Some(groups) = self.groups.as_mut() else {
            return;
        };
        let now = Instant::now();
        if now < groups.next_review || groups.cleanup_failed {
            return;
        }
        groups.next_review = now + Duration::from_secs(1);
        let Ok(now_ms) = unix_time_ms() else { return };
        self.poll_group_operator(now_ms);
        let Some(groups) = self.groups.as_mut() else {
            return;
        };
        let Ok(Some(d)) = groups
            .store
            .claim_group_decision(agent, &self.device_peer_id, now_ms)
        else {
            return;
        };
        let action = match d.choice {
            Choice::Approve => LocalGroupAction::Approve(d.invite),
            Choice::Reject => LocalGroupAction::Reject(d.invite),
            Choice::Retry => LocalGroupAction::Retry(d.invite),
        };
        let outcome = match self.apply_local_group_action(action, now_ms) {
            Ok(_) if d.choice == Choice::Reject => Outcome::Declined,
            Ok(view) if view["queued"] == true => Outcome::JoinQueued,
            Ok(_) => Outcome::ApprovedNotSent,
            Err(_) => Outcome::Failed,
        };
        if let Some(groups) = &mut self.groups {
            let _ = groups.store.finish_group_decision(&d, outcome, now_ms);
        }
    }

    pub(super) fn apply_local_group_action(
        &mut self,
        action: LocalGroupAction,
        now_ms: u64,
    ) -> Result<Value, AslError> {
        let local_agent = self.agent_id();
        let groups = self.groups.as_mut().ok_or(AslError::PolicyDenied)?;
        if groups.cleanup_failed {
            return Err(AslError::InvalidPolicyState);
        }
        let store = &mut groups.store;
        let local_peer = &self.device_peer_id;
        let pending =
            |store: &mut Store| store.list_pending_mls_invites(local_agent, local_peer, now_ms);
        let approved = |store: &mut Store| store.recover_mls_joins(local_agent, local_peer, now_ms);
        match action {
            LocalGroupAction::List => {
                let approved = approved(store)?
                    .iter()
                    .map(|invite| {
                        let mut view = invite_view(store, invite)?;
                        if let Some((_, reason)) = groups
                            .join_diagnostics
                            .iter()
                            .find(|(id, _)| *id == invite.id)
                        {
                            view["last_result"] = json!(reason);
                        }
                        Ok(view)
                    })
                    .collect::<Result<Vec<_>, AslError>>()?;
                let pending = pending(store)?
                    .iter()
                    .map(|invite| invite_view(store, invite))
                    .collect::<Result<Vec<_>, _>>()?;
                let rooms = store
                    .list_mls_room_ids()?
                    .into_iter()
                    .map(|(wire_id, local_id)| {
                        let (state, epoch) = store
                            .mls_room_progress(wire_id)?
                            .ok_or(AslError::NotFound)?;
                        Ok(json!({
                            "room": hex::encode(wire_id.0),
                            "conversation_id": hex::encode(local_id.0.0),
                            "state": state,
                            "mls_epoch": epoch,
                        }))
                    })
                    .collect::<Result<Vec<_>, AslError>>()?;
                return Ok(json!({
                    "rooms": rooms,
                    "pending": pending,
                    "approved": approved
                }));
            }
            LocalGroupAction::Room(id) => {
                let (state, epoch) = store.mls_room_progress(id)?.ok_or(AslError::NotFound)?;
                let mut view = json!({
                    "room": hex::encode(id.0),
                    "state": state,
                    "mls_epoch": epoch
                });
                if let Some(saved) = store.mls_room_for_reconciliation(id)? {
                    view["creator"] = json!(peer_text(&saved.creator));
                    view["stored_members"] =
                        json!(saved.members.iter().map(peer_text).collect::<Vec<_>>());
                }
                if let Some(entry) = groups
                    .recent_applications
                    .iter()
                    .find(|entry| entry.room == id && entry.epoch == epoch)
                {
                    view["last_received"] = json!({
                        "sender": peer_text(&entry.sender),
                        "message_id": hex::encode(entry.message.0),
                        "kind": entry.kind
                    });
                }
                let policy = GroupInboundPolicy::load(store)?;
                view["browse_enabled"] = json!(policy.browse_enabled);
                view["answer_enabled"] = json!(policy.answer_enabled);
                return Ok(view);
            }
            LocalGroupAction::ConfigureInbound {
                browse_enabled,
                answer_enabled,
            } => {
                let policy = GroupInboundPolicy {
                    browse_enabled,
                    answer_enabled,
                };
                policy.save(store, now_ms)?;
                return Ok(json!({
                    "browse_enabled": policy.browse_enabled,
                    "answer_enabled": policy.answer_enabled
                }));
            }
            LocalGroupAction::Reject(id) => {
                let invite = select_invite(pending(store)?, id)?;
                if !store.reject_mls_invite(&invite, now_ms)? {
                    return Err(AslError::NotFound);
                }
                return Ok(json!({"state": "rejected"}));
            }
            _ => {}
        }

        if self.network_admission_status != NetworkAdmissionStatus::Active {
            return Err(AslError::InvalidIdentity);
        }
        let admission = self.admission.as_mut().ok_or(AslError::InvalidIdentity)?;
        let net = &self.net;
        let directories = HashMap::new();
        match action {
            LocalGroupAction::Peers => {
                let peers: Vec<_> = admission
                    .admitted_connections(now_ms)
                    .into_iter()
                    .map(|(agent, connection, peer)| {
                        json!({
                            "agent": hex::encode(agent.0),
                            "peer": peer_text(&peer),
                            "connection": hex::encode(connection)
                        })
                    })
                    .collect();
                Ok(json!({
                    "local_agent": hex::encode(local_agent.0),
                    "local_peer": peer_text(local_peer),
                    "connections": peers
                }))
            }
            LocalGroupAction::Create => {
                let id = GroupId(Id128(fresh_id()?));
                let (wire_id, _) = admission.create_local_mls_room(
                    store,
                    &self.agent_identity,
                    &id,
                    "Group",
                    now_ms,
                )?;
                grant_act_budget(store, id.0, now_ms)?;
                Ok(json!({"room": hex::encode(wire_id.0), "state": "active"}))
            }
            LocalGroupAction::Approve(id) | LocalGroupAction::Retry(id) => {
                let is_approval = matches!(action, LocalGroupAction::Approve(_));
                let invites = if is_approval {
                    pending(store)?
                } else {
                    approved(store)?
                };
                let invite = select_invite(invites, id)?;
                let connection_id = admission
                    .admitted_connections(now_ms)
                    .into_iter()
                    .find(|(agent, _, peer)| {
                        *agent == invite.inviter && *peer == invite.inviter_device
                    })
                    .map(|(_, connection, _)| connection)
                    .ok_or(AslError::NotFound)?;
                let local_id = GroupId(Id128(fresh_id()?));
                if is_approval
                    && !admission.approve_targeted_mls_invite(
                        store,
                        &self.agent_identity,
                        connection_id,
                        &invite,
                        &directories,
                        now_ms,
                    )?
                {
                    return Err(AslError::PolicyVersionConflict);
                }
                let send = admission.send_approved_mls_join(
                    store,
                    MlsJoinSend {
                        connection_id,
                        invite: &invite,
                        local_id: &local_id,
                        local_name: "Group",
                    },
                    &directories,
                    now_ms,
                    |command| enqueue(net, command),
                );
                match send {
                    Ok(_) => {
                        grant_act_budget(store, local_id.0, now_ms)?;
                        groups
                            .join_diagnostics
                            .retain(|(previous, _)| *previous != id);
                        Ok(json!({"state": "approved", "queued": true}))
                    }
                    Err(error) if is_approval => Ok(
                        json!({"state": "approved", "queued": false, "send_error": error.to_string()}),
                    ),
                    Err(error) => Err(error),
                }
            }
            LocalGroupAction::Invite {
                room,
                connection_id,
            } => {
                admission.send_targeted_mls_invite(
                    store,
                    MlsInviteSend {
                        connection_id,
                        wire_id: room,
                        expires_at_ms: now_ms.saturating_add(INVITE_LIFETIME_MS),
                    },
                    &directories,
                    now_ms,
                    |command| enqueue(net, command),
                )?;
                Ok(json!({"queued": true}))
            }
            LocalGroupAction::Remove { room, peer } => {
                let version =
                    admission.remove_local_mls_member(store, room, &peer, &directories, now_ms)?;
                Ok(json!({
                    "room": hex::encode(room.0),
                    "removed": peer_text(&peer),
                    "state": "needs_sync",
                    "mls_epoch": version.mls_epoch
                }))
            }
            LocalGroupAction::SendApplication { room, application } => {
                let sent = admission.send_loopback_mls_application(
                    store,
                    room,
                    *application,
                    now_ms,
                    |command| enqueue(net, command),
                )?;
                Ok(json!({
                    "message_id": hex::encode(sent.message_id.0),
                    "queued": sent.queued,
                    "available": sent.available
                }))
            }
            LocalGroupAction::SetAccess { room, update } => self.set_group_access(room, update),
            LocalGroupAction::Dial { address, peer } => {
                if !address.ip().is_loopback() {
                    return Err(AslError::PolicyDenied);
                }
                enqueue(
                    net,
                    NetworkCommand::Dial {
                        operation_id: fresh_id()?,
                        kind: TransportKind::Tcp,
                        address,
                        peer_id: peer,
                    },
                )?;
                Ok(json!({"queued": true}))
            }
            LocalGroupAction::List
            | LocalGroupAction::Room(_)
            | LocalGroupAction::Reject(_)
            | LocalGroupAction::ConfigureInbound { .. } => unreachable!(),
        }
    }
}

impl LoopbackGroups {
    fn prepare_application_reply(
        &mut self,
        wire_id: Hash32,
        local_peer: &PeerId,
        sender: &PeerId,
        application: &GroupApplication,
        requester: Option<&GroupRequester>,
        now_ms: u64,
    ) -> Result<Option<GroupApplication>, AslError> {
        let GroupApplication::Query(query) = application else {
            return Ok(None);
        };
        if requester.is_none() || !GroupInboundPolicy::load(&self.store)?.answer_enabled {
            return Ok(None);
        }
        let Some(agent) = self.store.mls_peer_agent(sender)? else {
            return Ok(None);
        };
        let mut inbound = InboundRunner::default();
        inbound.set_mode(InboundMode::Answer);
        let Ingress::Work(work) = inbound.receive(
            agent,
            sender.clone(),
            WireFrame::Query(query.clone()),
            now_ms,
        )?
        else {
            return Ok(None);
        };
        if !self.store.claim_group_inbound_query(
            wire_id,
            agent,
            query.root_task_id,
            query.message_id,
            now_ms as i64,
            query.expires_at_ms as i64,
        )? {
            return Ok(None);
        }
        let requester = requester.ok_or(AslError::PolicyDenied)?;
        let (snapshot, keys) = self.store.group_search_snapshot(requester)?;
        let revision = snapshot.revision;
        let engine = PolicyEngine::new(snapshot, 10_000)?;
        let policy = engine.for_group(requester.direct.peer.clone(), requester.group_id.clone());
        let mut hit = None;
        if query.constraints.is_empty()
            && matches!(
                query.intent_id,
                Intent::FindEvidence | Intent::LocateResource
            )
            && query.result_shape != ResultShape::Agents
            && let Some((found, permit)) = self
                .store
                .peer_search(&policy, requester.direct.agent)
                .search_with_metadata_permits(&keys, &query.topics, 1)?
                .pop()
        {
            let concepts = query
                .topics
                .iter()
                .copied()
                .filter(|topic| found.local_concept_ids.contains(topic))
                .take(16)
                .collect();
            let file_size = permit.file_size();
            hit = Some(ResourceMatch::new(
                permit,
                concepts,
                file_size,
                MediaKind::Other,
            )?);
        }
        let Some(reply) = inbound.finish_without_model(*work, hit, &policy, now_ms)? else {
            return Ok(None);
        };
        let permit = reply.permit().cloned();
        let Some(frame) = inbound.take_reply(reply, &policy, now_ms) else {
            return Ok(None);
        };
        if matches!(&frame, WireFrame::Offer(_))
            && !self.store.group_can_send(
                &requester.group_id,
                local_peer,
                GroupAccessKind::Files,
            )?
        {
            return Ok(None);
        }
        self.store.with_current_group_authority(
            requester,
            revision,
            permit.as_ref(),
            Some(query.root_task_id),
            || Ok(()),
        )?;
        match frame {
            WireFrame::Answer(answer) => Ok(Some(GroupApplication::Answer(answer))),
            WireFrame::Offer(offer) => Ok(Some(GroupApplication::Offer(offer))),
            _ => Err(AslError::InvalidMessage),
        }
    }

    fn poll_sync(
        &mut self,
        admission: &mut crate::profile::CoreAdmission,
        net: &NetRuntime,
        now: Instant,
        now_ms: u64,
    ) {
        let directories = HashMap::new();
        let _ = admission.poll_mls_sync(&self.store, &directories, now_ms, |command| {
            enqueue(net, command)
        });
        if now < self.next_sync_probe {
            return;
        }
        self.next_sync_probe = now + SYNC_PROBE_INTERVAL;
        let mut next: Option<(Hash32, PeerId, [u8; 16])> = None;
        for (_, connection, peer) in admission.admitted_connections(now_ms) {
            let after = self
                .sync_cursor
                .as_ref()
                .map(|(room, last)| (*room, peer.as_bytes() > last.as_bytes()));
            let Ok(Some(room)) = self.store.next_mls_sync_room(&peer, after) else {
                continue;
            };
            if next.as_ref().is_none_or(|(current, current_peer, _)| {
                (room.as_bytes(), peer.as_bytes()) < (current.as_bytes(), current_peer.as_bytes())
            }) {
                next = Some((room, peer, connection));
            }
        }
        self.sync_cursor = next.as_ref().map(|(room, peer, _)| (*room, peer.clone()));
        if let Some((room, _, connection)) = next {
            let _ = admission.start_mls_sync(
                &self.store,
                connection,
                room,
                &directories,
                now_ms,
                |command| enqueue(net, command),
            );
        }
    }
}

pub fn run_with_local_groups_from_environment(
    controls: Receiver<LocalGroupCommand>,
) -> Result<(), AslError> {
    let root = configured_root(std::env::var_os("ASL_HOME"))?;
    let mut supervisor = Supervisor::start(AppPaths::open(&root)?)?;
    if supervisor.groups.is_none() {
        return Err(AslError::PolicyDenied);
    }
    supervisor.group_controls = Some(controls);
    supervisor.run()
}

fn enqueue(net: &NetRuntime, command: NetworkCommand) -> Result<(), AslError> {
    if net.try_send(&command.into_ipc()?)? {
        Ok(())
    } else {
        Err(AslError::QuotaExceeded)
    }
}

fn select_invite(
    invites: impl IntoIterator<Item = MlsIncomingInvite>,
    id: Id128,
) -> Result<MlsIncomingInvite, AslError> {
    invites
        .into_iter()
        .find(|invite| invite.id == id)
        .ok_or(AslError::NotFound)
}

fn peer_text(peer: &PeerId) -> String {
    libp2p_identity::PeerId::from_bytes(peer.as_bytes())
        .map_or_else(|_| hex::encode(peer.as_bytes()), |peer| peer.to_base58())
}

pub(super) fn record_act_history(
    store: &mut Store,
    group_id: &GroupId,
    epoch: u64,
    direction: ActDirection,
    act: &Act,
    now_ms: u64,
) -> Result<(), AslError> {
    let conversation_id = hex::encode(group_id.0.as_bytes());
    store.record_act_history(ActHistoryRecord {
        conversation_id: &conversation_id,
        message_id: act.message_id,
        mls_epoch: epoch,
        direction,
        act_kind: match act.act_type {
            ActType::Inform => 0,
            ActType::Ask => 1,
            ActType::Request => 2,
            ActType::Propose => 3,
            ActType::Accept => 4,
            ActType::Reject => 5,
            ActType::Commit => 6,
            ActType::Cancel => 7,
            ActType::Ack => 8,
            ActType::Clarify => 9,
        },
        reply_to: act.reply_to,
        causal_root: act.causal_root,
        body: act.nl_body.as_deref(),
        now_ms,
        expires_at_ms: now_ms.saturating_add(asl_store::group_state::MLS_SYNC_RETENTION_MS),
    })
}

fn apply_group_policy(
    store: &mut Store,
    wire_id: Hash32,
    sender: &PeerId,
    control: &asl_types::protocol::GroupControl,
    now_ms: u64,
) -> Result<(), AslError> {
    let owner = store
        .group_access_owner(wire_id)?
        .ok_or(AslError::NotFound)?;
    if &owner != sender {
        return Err(AslError::PolicyDenied);
    }
    let snapshot = store
        .mls_room_snapshot(wire_id)?
        .ok_or(AslError::NotFound)?;
    store.apply_group_control(&snapshot.local_id, sender, control, now_ms)?;
    Ok(())
}

fn member_view(member: &GroupMemberAccess) -> Value {
    json!({
        "peer": peer_text(&member.peer),
        "role": member.role.as_str(),
        "muted": member.muted,
        "can_send_text": member.can_send_text,
        "can_send_files": member.can_send_files,
        "can_invite": member.can_invite,
    })
}

fn invite_view(store: &Store, invite: &MlsIncomingInvite) -> Result<Value, AslError> {
    Ok(json!({
        "id": hex::encode(invite.id.0),
        "room": hex::encode(invite.wire_id.0),
        "inviter": hex::encode(invite.inviter.0),
        "device": peer_text(&invite.inviter_device),
        "kind": if store.mls_room_progress(invite.wire_id)?.is_some() { "rejoin" } else { "join" },
        "base_epoch": invite.base_epoch,
        "expires_at_ms": invite.expires_at_ms
    }))
}

fn grant_act_budget(
    store: &mut Store,
    conversation_id: Id128,
    now_ms: u64,
) -> Result<(), AslError> {
    let now_ms = i64::try_from(now_ms).map_err(|_| AslError::InvalidMessage)?;
    let first = fresh_id()?;
    let second = fresh_id()?;
    let mut grant_id = [0; 32];
    grant_id[..16].copy_from_slice(&first);
    grant_id[16..].copy_from_slice(&second);
    let inserted = store.grant_conversation_budget(ConversationBudgetGrant {
        conversation_id: &hex::encode(conversation_id.0),
        grant_id,
        messages_granted: MAX_BUDGET_MESSAGES,
        max_renewals: MAX_BUDGET_RENEWALS,
        now_ms,
        expires_at_ms: now_ms.saturating_add(MAX_BUDGET_WINDOW_MS),
    })?;
    if matches!(inserted, MailboxPut::Inserted | MailboxPut::Duplicate) {
        Ok(())
    } else {
        Err(AslError::InvalidPolicyState)
    }
}

fn describe_join_failure(error: AslError) -> &'static str {
    match error {
        AslError::InvalidIdentity
        | AslError::InvalidDeviceCertificate
        | AslError::ExpiredMessage => "identity_evidence_unavailable",
        AslError::InvalidDatabase
        | AslError::InvalidPolicyState
        | AslError::PolicyVersionConflict
        | AslError::Io(_) => "local_state_changed_or_unavailable",
        _ => "welcome_rejected",
    }
}
