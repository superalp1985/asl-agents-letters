use std::{
    collections::{HashMap, VecDeque},
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
    group_state::{GroupInboundPolicy, MlsIncomingInvite, open_mls_runtime_store},
    search::group::GroupRequester,
};
use asl_types::{
    error::AslError,
    ids::{Hash32, Id128, PeerId},
    protocol::{Intent, MediaKind, ResultShape, WireFrame},
    task::GroupId,
};
use serde_json::{Value, json};

use crate::{
    network::{NetworkCommand, NetworkEvent},
    profile::{MlsInviteSend, MlsJoinSend, MlsNetworkOutcome, fresh_id},
    transfer::TransferService,
};

use super::{
    AppPaths, NetRuntime, NetworkAdmissionStatus, Supervisor, TransportKind, configured_root,
    unix_time_ms,
};

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
    SendApplication {
        room: Hash32,
        application: Box<GroupApplication>,
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
    store: Store,
    next_prune: Instant,
    cleanup_failed: bool,
    join_diagnostics: VecDeque<(Id128, &'static str)>,
    recent_applications: VecDeque<ReceivedApplication>,
    next_sync_probe: Instant,
    sync_cursor: Option<(Hash32, PeerId)>,
    pending_transfers: VecDeque<PendingGroupTransfer>,
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
    pub(super) fn open(path: &Path, now_ms: u64) -> Result<Self, AslError> {
        let mut store = open_mls_runtime_store(path)?;
        store.prune_mls_expired(now_ms)?;
        Ok(Self {
            store,
            next_prune: Instant::now() + PRUNE_INTERVAL,
            cleanup_failed: false,
            join_diagnostics: VecDeque::new(),
            recent_applications: VecDeque::new(),
            next_sync_probe: Instant::now() + SYNC_PROBE_INTERVAL,
            sync_cursor: None,
            pending_transfers: VecDeque::new(),
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

    pub(super) fn route_group_event(&mut self, event: NetworkEvent, now_ms: u64) {
        let (Some(groups), Some(admission)) = (&mut self.groups, &mut self.admission) else {
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
                | GroupApplication::Offer(_) => {}
            }
        }
    }

    fn current_group_requester(
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
                && let Some(admission) = &mut self.admission
            {
                groups.poll_sync(admission, &self.net, now, unix_time_ms()?);
            }
        }
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

    fn apply_local_group_action(
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
                return Ok(json!({
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
            | LocalGroupAction::ConfigureInbound { .. } => {
                unreachable!()
            }
        }
    }
}

impl LoopbackGroups {
    fn prepare_application_reply(
        &mut self,
        wire_id: Hash32,
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
