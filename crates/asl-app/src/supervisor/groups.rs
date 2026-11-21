use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    path::Path,
    sync::mpsc::{Receiver, SyncSender, TryRecvError},
    time::{Duration, Instant},
};

use alloy_primitives::hex;
use asl_groups::GroupApplication;
use asl_store::{
    Store,
    group_state::{MlsIncomingInvite, open_mls_runtime_store},
};
use asl_types::{
    error::AslError,
    ids::{Hash32, Id128, PeerId},
    task::GroupId,
};
use serde_json::{Value, json};

use crate::{
    network::{NetworkCommand, NetworkEvent},
    profile::{MlsInviteSend, MlsJoinSend, MlsNetworkOutcome, fresh_id},
};

use super::{
    AppPaths, NetRuntime, NetworkAdmissionStatus, Supervisor, TransportKind, configured_root,
    unix_time_ms,
};

const PRUNE_INTERVAL: Duration = Duration::from_secs(30);
const SYNC_PROBE_INTERVAL: Duration = Duration::from_secs(15);
const INVITE_LIFETIME_MS: u64 = 5 * 60 * 1_000;
const MAX_JOIN_DIAGNOSTICS: usize = 5;
const MAX_RECENT_ROOMS: usize = 32;

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
}

struct ReceivedApplication {
    room: Hash32,
    epoch: u64,
    sender: PeerId,
    message: Id128,
    kind: &'static str,
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
            wire_id,
            epoch,
            sender,
            application,
        })) = &result
        {
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
                kind: match application.as_ref() {
                    GroupApplication::Query(_) => "query",
                    GroupApplication::Answer(_) => "answer",
                    GroupApplication::Offer(_) => "offer",
                },
            });
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

    pub(super) fn poll_local_groups(&mut self) -> Result<(), AslError> {
        if let Some(groups) = &mut self.groups {
            let now = Instant::now();
            if now >= groups.next_prune {
                groups.next_prune = now + PRUNE_INTERVAL;
                groups.cleanup_failed = groups.store.prune_mls_expired(unix_time_ms()?).is_err();
            }
            if self.network_admission_status == NetworkAdmissionStatus::Active
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
                return Ok(view);
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
                Ok(json!({"room": hex::encode(wire_id.0), "state": "needs_sync"}))
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
            LocalGroupAction::List | LocalGroupAction::Room(_) | LocalGroupAction::Reject(_) => {
                unreachable!()
            }
        }
    }
}

impl LoopbackGroups {
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
