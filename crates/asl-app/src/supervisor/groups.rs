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
    budgets::{
        BudgetKind, DEFAULT_CPU_BUDGET_MS, DEFAULT_MAILBOX_BYTE_BUDGET,
        DEFAULT_MESSAGE_BYTE_BUDGET, DEFAULT_MODEL_CALL_BUDGET,
    },
    group_access::{
        GroupAccessKind, GroupAdminCapabilityKind, GroupFileAccessKind, GroupMemberAccess,
    },
    group_state::{
        GroupInboundPolicy, MAX_SHARD_FORWARD_OUTBOX_BATCH, MlsIncomingInvite,
        PendingShardForwardOutbox, SHARD_FORWARD_OUTBOX_RETRY_BASE_MS,
        SHARD_FORWARD_OUTBOX_RETRY_MAX_MS, ShardForwardOutboxKind, open_mls_runtime_store,
    },
    group_topology::MAX_LAYERED_GROUP_MEMBERS,
    mailbox::{
        ConversationBudgetGrant, MAX_BUDGET_MESSAGES, MAX_BUDGET_RENEWALS, MAX_BUDGET_WINDOW_MS,
        MailboxPut,
    },
    search::group::GroupRequester,
};
use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId, Signature65},
    protocol::{
        Act, ActType, GROUP_ALLOW_MEMBER_FILES, GROUP_ALLOW_MEMBER_INVITE, GROUP_ALLOW_MEMBER_TEXT,
        GROUP_REMOVAL_REQUEST_TTL_MS, GroupControl, GroupPacket, GroupRemovalRequest, Intent,
        MAX_GROUP_MEMBERS, MAX_SHARD_BINDING_LIFETIME_MS, MAX_SHARD_FORWARD_HOP,
        MAX_SHARD_FORWARD_LIFETIME_MS, MediaKind, ResultShape, ShardBinding, ShardForward,
        WireFrame, decode_frame,
    },
    task::GroupId,
};
use serde_json::{Value, json};

use crate::{
    agent_mail::GroupAccessUpdate,
    identity::{AgentIdentity, verify_root_signature},
    model_endpoint_access::ModelEndpointAccess,
    network::{NetworkCommand, NetworkEvent},
    profile::{CoreAdmission, MlsInviteSend, MlsJoinSend, MlsNetworkOutcome, fresh_id},
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
const MAX_PENDING_ACKS: usize = 128;
const MAX_ACKED_ACTS: usize = 512;
const ACK_RETRY_DELAY: Duration = Duration::from_secs(5);
const MAX_ACK_ATTEMPTS: u8 = 5;
const SHARD_FORWARD_RETRY_INTERVAL: Duration = Duration::from_secs(5);
const LOCAL_GROUP_CONNECTION: [u8; 16] = [0; 16];

pub enum LocalGroupAction {
    List,
    Room(Hash32),
    Peers,
    Create,
    CreateShard(Hash32),
    Approve(Id128),
    Retry(Id128),
    Reject(Id128),
    Invite {
        room: Hash32,
        connection_id: [u8; 16],
    },
    InviteShard {
        root: Hash32,
        connection_id: [u8; 16],
    },
    Remove {
        room: Hash32,
        peer: PeerId,
    },
    ProposeRemove {
        room: Hash32,
        peer: PeerId,
    },
    ReviewRemoval {
        room: Hash32,
        request: Id128,
        approve: bool,
    },
    RejectJoinRequest {
        room: Hash32,
        device: PeerId,
    },
    RequestJoin {
        room: Hash32,
        owner: AgentId,
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
    RenewResourceBudget {
        room: Hash32,
        kind: String,
        additional: u64,
        window_hours: u32,
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
    next_migration_rejoin: Instant,
    next_shard_forward_retry: Instant,
    sync_cursor: Option<(Hash32, PeerId)>,
    pending_transfers: VecDeque<PendingGroupTransfer>,
    gossip_subscriptions: HashSet<Hash32>,
    pending_acks: VecDeque<PendingAck>,
    acked_acts: HashSet<Id128>,
    acked_order: VecDeque<Id128>,
}

struct ReceivedApplication {
    room: Hash32,
    epoch: u64,
    sender: PeerId,
    message: Id128,
    kind: &'static str,
}

struct AcceptedShardForward {
    root: Hash32,
    source_agent: AgentId,
    source_peer: PeerId,
    application: GroupApplication,
}

struct PendingGroupTransfer {
    connection_id: [u8; 16],
    wire_id: Hash32,
    epoch: u64,
    envelope_id: Id128,
    sender: PeerId,
    requester: Option<GroupRequester>,
    application: GroupApplication,
}

struct PendingAck {
    room: Hash32,
    act: Act,
    attempts: u8,
    next_attempt: Instant,
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
            next_migration_rejoin: Instant::now(),
            next_shard_forward_retry: Instant::now(),
            sync_cursor: None,
            pending_transfers: VecDeque::new(),
            gossip_subscriptions: HashSet::new(),
            pending_acks: VecDeque::new(),
            acked_acts: HashSet::new(),
            acked_order: VecDeque::new(),
        })
    }

    fn queue_ack(&mut self, room: Hash32, act: &Act, now_ms: u64) -> Result<(), AslError> {
        if act.act_type == ActType::Ack
            || self.acked_acts.contains(&act.message_id)
            || self.pending_acks.len() >= MAX_PENDING_ACKS
        {
            return Ok(());
        }
        if self.acked_acts.len() >= MAX_ACKED_ACTS
            && let Some(oldest) = self.acked_order.pop_front()
        {
            self.acked_acts.remove(&oldest);
        }
        self.acked_acts.insert(act.message_id);
        self.acked_order.push_back(act.message_id);
        self.pending_acks.push_back(PendingAck {
            room,
            act: Act {
                message_id: Id128([0; 16]),
                conversation_id: act.conversation_id,
                act_type: ActType::Ack,
                reply_to: Some(act.message_id),
                nl_body: None,
                action: None,
                attachments: Vec::new(),
                causal_root: act.causal_root,
                hop: act.hop.saturating_add(1),
                expires_at_ms: Some(now_ms.saturating_add(10 * 60 * 1_000)),
            },
            attempts: 0,
            next_attempt: Instant::now(),
        });
        Ok(())
    }

    fn take_due_acks(&mut self, now: Instant) -> Vec<PendingAck> {
        let mut due = Vec::new();
        let mut waiting = VecDeque::new();
        for pending in self.pending_acks.drain(..) {
            if now >= pending.next_attempt {
                due.push(pending);
            } else {
                waiting.push_back(pending);
            }
        }
        self.pending_acks = waiting;
        due
    }

    fn retry_ack(&mut self, mut pending: PendingAck) {
        if pending.attempts >= MAX_ACK_ATTEMPTS {
            self.acked_acts
                .remove(&pending.act.reply_to.unwrap_or(Id128([0; 16])));
            self.acked_order
                .retain(|id| *id != pending.act.reply_to.unwrap_or(Id128([0; 16])));
            return;
        }
        pending.attempts = pending.attempts.saturating_add(1);
        pending.next_attempt = Instant::now() + ACK_RETRY_DELAY;
        self.pending_acks.push_back(pending);
    }
}

impl Supervisor {
    pub(super) fn send_shard_announcement(
        &mut self,
        root: Hash32,
        act: Act,
    ) -> Result<Value, AslError> {
        if act.act_type != ActType::Inform
            || act.action.is_some()
            || !act.attachments.is_empty()
            || act.reply_to.is_some()
            || act.conversation_id != Id128([0; 16])
        {
            return Err(AslError::InvalidMessage);
        }
        let groups = self.groups.as_ref().ok_or(AslError::NotFound)?;
        let mut shards = groups.store.mls_room_shards(root)?;
        if shards.is_empty() {
            return Err(AslError::NotFound);
        }
        shards.insert(0, root);
        for room in &shards {
            if groups.store.group_access_owner(*room)?.as_ref() != Some(&self.device_peer_id) {
                return Err(AslError::PolicyDenied);
            }
        }
        let mut outcomes = Vec::with_capacity(shards.len());
        for room in shards {
            let report = match self.send_group_act_inner(room, act.clone(), false) {
                Ok(id) => json!({"room": hex::encode(room.0), "message_id": hex::encode(id.0),
                    "state": "submitted"}),
                Err(error) => {
                    let code = match error {
                        AslError::QuotaExceeded => "quota_exceeded",
                        AslError::PolicyDenied => "policy_denied",
                        AslError::NotFound => "not_found",
                        _ => "unavailable",
                    };
                    json!({"room": hex::encode(room.0), "state": "failed", "error_code": code})
                }
            };
            outcomes.push(report);
        }
        Ok(json!({"rooms": outcomes}))
    }

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
        let topology_members = groups.store.group_topology_members(&snapshot.local_id)?;
        let sharded = topology_members.len() > asl_groups::topology::MAX_DIRECT_SHARD_MEMBERS;
        let topology = if sharded {
            let plan = asl_groups::topology::plan_group_shards(
                topology_members,
                asl_groups::topology::MAX_DIRECT_SHARD_MEMBERS,
            )?;
            json!({
                "mode": "layered",
                "shard_count": plan.shards.len(),
                "shards": plan.shards.iter().map(|shard| json!({
                    "index": shard.index,
                    "bridge": peer_text(&shard.bridge),
                    "members": shard.members.len(),
                })).collect::<Vec<_>>(),
            })
        } else {
            json!({"mode": "direct", "shard_count": 1})
        };
        let mut members = if sharded {
            Vec::new()
        } else {
            groups.store.group_members(&snapshot.local_id)?
        };
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
            "file_policies": policy.file_policies.iter().map(|policy| json!({
                "content_id": hex::encode(policy.content_id.0),
                "permissions": policy.permissions,
            })).collect::<Vec<_>>(),
            "admin_capabilities": policy.admin_capabilities.iter().map(|capability| json!({
                "peer": peer_text(&capability.peer),
                "capabilities": capability.capabilities,
            })).collect::<Vec<_>>(),
            "topology": topology,
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
        let (root, shards, owner, current) = {
            let groups = self.groups.as_ref().ok_or(AslError::NotFound)?;
            let root = groups.store.mls_logical_root(room)?;
            let snapshot = groups
                .store
                .mls_room_snapshot(root)?
                .ok_or(AslError::NotFound)?;
            (
                root,
                groups.store.mls_room_shards(root)?,
                groups
                    .store
                    .group_access_owner(root)?
                    .ok_or(AslError::NotFound)?,
                groups.store.group_access_policy(&snapshot.local_id)?,
            )
        };
        if shards.is_empty() || owner != self.device_peer_id {
            return self.set_group_access_single(room, update, now);
        }

        let target_owner = update
            .owner
            .clone()
            .or_else(|| current.owner.clone())
            .unwrap_or_else(|| owner.clone());
        let mut rooms = shards;
        rooms.push(root);
        if target_owner != owner {
            let groups = self.groups.as_ref().ok_or(AslError::NotFound)?;
            let mut missing = Vec::new();
            for room in &rooms {
                if !groups.store.has_mls_sync_member(*room, &target_owner)? {
                    missing.push(json!({
                        "room": hex::encode(room.0),
                        "state": "blocked",
                        "error_code": "owner_not_member",
                    }));
                }
            }
            if !missing.is_empty() {
                return Ok(json!({
                    "root": hex::encode(root.0),
                    "state": "blocked_owner_transfer",
                    "owner": peer_text(&target_owner),
                    "rooms": missing,
                }));
            }
        }

        let file_policies = update
            .file_policies
            .clone()
            .unwrap_or_else(|| current.file_policies.clone());
        let admin_capabilities = update
            .admin_capabilities
            .clone()
            .unwrap_or_else(|| current.admin_capabilities.clone());
        let mut outcomes = Vec::with_capacity(rooms.len());
        let mut child_failed = false;
        for target in rooms {
            if target == root && child_failed {
                outcomes.push(json!({
                    "room": hex::encode(root.0),
                    "state": "not_applied",
                    "error_code": "child_policy_failed",
                }));
                continue;
            }
            let (projected, omitted_admins, omitted_muted) = if target == root {
                (update.clone(), 0, 0)
            } else {
                let members = {
                    let groups = self.groups.as_ref().ok_or(AslError::NotFound)?;
                    let snapshot = groups
                        .store
                        .mls_room_snapshot(target)?
                        .ok_or(AslError::NotFound)?;
                    groups.store.group_topology_members(&snapshot.local_id)?
                };
                let admins = update
                    .admins
                    .iter()
                    .filter(|peer| members.contains(peer))
                    .cloned()
                    .collect::<Vec<_>>();
                let muted = update
                    .muted
                    .iter()
                    .filter(|peer| members.contains(peer))
                    .cloned()
                    .collect::<Vec<_>>();
                let capabilities = admin_capabilities
                    .iter()
                    .filter(|capability| admins.contains(&capability.peer))
                    .cloned()
                    .collect::<Vec<_>>();
                let omitted_admins = update.admins.len().saturating_sub(admins.len());
                let omitted_muted = update.muted.len().saturating_sub(muted.len());
                (
                    GroupAccessUpdate {
                        allow_member_text: update.allow_member_text,
                        allow_member_files: update.allow_member_files,
                        allow_member_invite: update.allow_member_invite,
                        admins,
                        muted,
                        owner: Some(target_owner.clone()),
                        file_policies: Some(file_policies.clone()),
                        admin_capabilities: Some(capabilities),
                    },
                    omitted_admins,
                    omitted_muted,
                )
            };
            match self.set_group_access_single(target, projected, now) {
                Ok(mut outcome) => {
                    outcome["omitted_inactive_admins"] = json!(omitted_admins);
                    outcome["omitted_inactive_muted"] = json!(omitted_muted);
                    outcomes.push(outcome);
                }
                Err(error) => {
                    if target != root {
                        child_failed = true;
                    }
                    outcomes.push(json!({
                        "room": hex::encode(target.0),
                        "state": "failed",
                        "error_code": group_operation_error_code(&error),
                    }));
                }
            }
        }
        let complete = outcomes
            .iter()
            .all(|outcome| outcome.get("state").and_then(Value::as_str) == Some("applied"));
        Ok(json!({
            "root": hex::encode(root.0),
            "state": if complete { "applied" } else { "partial" },
            "rooms": outcomes,
        }))
    }

    fn set_group_access_single(
        &mut self,
        room: Hash32,
        update: GroupAccessUpdate,
        now: u64,
    ) -> Result<Value, AslError> {
        let groups = self.groups.as_mut().ok_or(AslError::NotFound)?;
        let snapshot = groups
            .store
            .mls_room_snapshot(room)?
            .ok_or(AslError::NotFound)?;
        let owner = groups
            .store
            .group_access_owner(room)?
            .ok_or(AslError::NotFound)?;
        let current = groups.store.group_access_policy(&snapshot.local_id)?;
        let delegated = owner != self.device_peer_id;
        if delegated {
            let current_text = current.permissions & GROUP_ALLOW_MEMBER_TEXT != 0;
            let current_files = current.permissions & GROUP_ALLOW_MEMBER_FILES != 0;
            let current_invite = current.permissions & GROUP_ALLOW_MEMBER_INVITE != 0;
            let members_changed = update.muted != current.muted;
            let files_changed = update
                .file_policies
                .as_ref()
                .is_some_and(|policies| policies != &current.file_policies);
            if update.allow_member_text != current_text
                || update.allow_member_files != current_files
                || update.allow_member_invite != current_invite
                || update.admins != current.admins
                || update.owner.as_ref().is_some_and(|owner| {
                    current
                        .owner
                        .as_ref()
                        .is_some_and(|current| current != owner)
                })
                || update
                    .admin_capabilities
                    .as_ref()
                    .is_some_and(|capabilities| capabilities != &current.admin_capabilities)
                || (members_changed
                    && !groups.store.group_admin_has_capability(
                        &snapshot.local_id,
                        &self.device_peer_id,
                        GroupAdminCapabilityKind::ManageMembers,
                    )?)
                || (files_changed
                    && !groups.store.group_admin_has_capability(
                        &snapshot.local_id,
                        &self.device_peer_id,
                        GroupAdminCapabilityKind::ManageFiles,
                    )?)
                || (!members_changed && !files_changed)
            {
                return Err(AslError::PolicyDenied);
            }
        }
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
        let file_policies = if delegated
            && !update
                .file_policies
                .as_ref()
                .is_some_and(|policies| policies != &current.file_policies)
        {
            current.file_policies.clone()
        } else {
            update
                .file_policies
                .unwrap_or_else(|| current.file_policies.clone())
        };
        let admin_capabilities = if delegated {
            current.admin_capabilities.clone()
        } else {
            update
                .admin_capabilities
                .unwrap_or_else(|| current.admin_capabilities.clone())
        };
        let admins = if delegated {
            current.admins.clone()
        } else {
            update.admins
        };
        let owner = if delegated {
            current.owner.clone()
        } else {
            update.owner
        };
        let control = GroupControl {
            message_id: Id128(fresh_id()?),
            policy_revision: if delegated {
                current.revision
            } else {
                current
                    .revision
                    .checked_add(1)
                    .ok_or(AslError::QuotaExceeded)?
            },
            permissions,
            admins,
            muted: update.muted,
            owner,
            file_policies,
            admin_capabilities,
        };
        if delegated {
            groups.store.apply_group_moderation(
                &snapshot.local_id,
                &self.device_peer_id,
                &control,
                now,
            )?;
        } else {
            groups.store.apply_group_control(
                &snapshot.local_id,
                &self.device_peer_id,
                &control,
                now,
            )?;
        }
        let admission = self.admission.as_mut().ok_or(AslError::NotFound)?;
        let sent = match admission.send_loopback_mls_application_with_gossip(
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
        ) {
            Ok(sent) => sent,
            Err(error) => {
                return Ok(json!({
                    "room": hex::encode(room.0),
                    "state": "local_applied_delivery_failed",
                    "policy_revision": control.policy_revision,
                    "error_code": group_operation_error_code(&error),
                    "queued": 0,
                    "available": 0,
                    "delegated": delegated,
                }));
            }
        };
        let gossip = super::group_routing::publish_packet(
            &self.net,
            &groups.store,
            room,
            &self.device_peer_id,
            &sent.packet,
        );
        Ok(json!({
            "room": hex::encode(room.0),
            "state": if gossip.is_ok() { "applied" } else { "applied_delivery_partial" },
            "policy_revision": control.policy_revision,
            "permissions": control.permissions,
            "admins": control.admins.iter().map(peer_text).collect::<Vec<_>>(),
            "muted": control.muted.iter().map(peer_text).collect::<Vec<_>>(),
            "queued": sent.queued,
            "available": sent.available,
            "delegated": delegated,
            "gossip_error_code": gossip.err().as_ref().map(group_operation_error_code),
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
        if let Ok(Some(MlsNetworkOutcome::InviteRequested {
            request,
            connection_id,
        })) = &result
        {
            let _ = self
                .mailbox
                .observe_group_invite_request(request, *connection_id);
        }
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
            if let GroupApplication::RemovalRequest(request) = application.as_ref() {
                if groups
                    .store
                    .record_group_removal_request(
                        *wire_id,
                        &self.device_peer_id,
                        sender,
                        request,
                        now_ms,
                    )
                    .is_ok()
                    && admission
                        .remove_local_mls_member(
                            &mut groups.store,
                            *wire_id,
                            &request.target,
                            &HashMap::new(),
                            now_ms,
                        )
                        .is_ok()
                {
                    let _ = groups
                        .store
                        .forget_group_removal(*wire_id, request.message_id);
                }
                return;
            }
            if let GroupApplication::ShardBinding(binding) = application.as_ref() {
                let _ = accept_shard_binding(
                    &mut groups.store,
                    admission,
                    *wire_id,
                    sender,
                    binding,
                    now_ms,
                );
                return;
            }
            if let GroupApplication::ShardForward(forward) = application.as_ref() {
                let Some(forwarded) = accept_shard_forward(
                    &mut groups.store,
                    admission,
                    *wire_id,
                    sender,
                    forward,
                    now_ms,
                )
                .ok()
                .flatten() else {
                    return;
                };
                let snapshot = match groups.store.mls_room_snapshot(*wire_id) {
                    Ok(Some(snapshot)) => snapshot,
                    _ => return,
                };
                let local_group_id = snapshot.local_id.clone();
                let binding = asl_store::transfers::GroupTransferBinding {
                    group_id: local_group_id.clone(),
                    membership_epoch: snapshot.version.membership_epoch,
                };
                let mut forwarded_application = forwarded.application;
                if matches!(
                    forwarded_application,
                    GroupApplication::FetchRequest(_)
                        | GroupApplication::FetchGrant(_)
                        | GroupApplication::FetchPending(_)
                ) {
                    let is_request =
                        matches!(&forwarded_application, GroupApplication::FetchRequest(_));
                    let (pending_connection, transfer_sender, requester) = if is_request {
                        (
                            *connection_id,
                            forwarded.source_peer.clone(),
                            groups
                                .store
                                .cached_group_requester(
                                    forwarded.root,
                                    forwarded.source_agent,
                                    &forwarded.source_peer,
                                    now_ms,
                                )
                                .ok()
                                .flatten(),
                        )
                    } else {
                        let Some((source_connection, source_requester)) =
                            forwarded_source_requester(
                                &groups.store,
                                admission,
                                *wire_id,
                                forwarded.source_agent,
                                &forwarded.source_peer,
                                now_ms,
                            )
                        else {
                            return;
                        };
                        (
                            source_connection,
                            forwarded.source_peer.clone(),
                            Some(source_requester),
                        )
                    };
                    if groups.pending_transfers.len() == MAX_PENDING_GROUP_TRANSFERS {
                        groups.pending_transfers.pop_front();
                    }
                    groups.pending_transfers.push_back(PendingGroupTransfer {
                        connection_id: pending_connection,
                        wire_id: *wire_id,
                        epoch: *epoch,
                        envelope_id: forward.message_id,
                        sender: transfer_sender,
                        requester,
                        application: forwarded_application,
                    });
                    return;
                }
                if let GroupApplication::Act(act) = &mut forwarded_application {
                    act.conversation_id = local_group_id.0;
                    let _ = groups.store.record_contact_interaction_evidence(
                        forwarded.source_agent,
                        &forwarded.source_peer,
                        act.message_id,
                        Some((*wire_id, *epoch)),
                        now_ms,
                    );
                    if GroupInboundPolicy::load(&groups.store)
                        .is_ok_and(|policy| policy.browse_enabled || policy.answer_enabled)
                    {
                        let _ = groups.queue_ack(*wire_id, act, now_ms);
                    }
                    if GroupInboundPolicy::load(&groups.store)
                        .is_ok_and(|policy| policy.browse_enabled)
                    {
                        let _ = record_act_history(
                            &mut groups.store,
                            &local_group_id,
                            *epoch,
                            ActDirection::In,
                            act,
                            now_ms,
                        );
                    }
                    if GroupInboundPolicy::load(&groups.store)
                        .is_ok_and(|policy| policy.answer_enabled)
                    {
                        super::auto_reply::queue_auto_reply(
                            auto_reply,
                            *wire_id,
                            act,
                            None,
                            &groups.store,
                            now_ms,
                        );
                    }
                    if self.mailbox.interested()
                        && GroupInboundPolicy::load(&groups.store)
                            .is_ok_and(|policy| policy.browse_enabled)
                    {
                        self.mailbox.observe_act(
                            crate::downloads::DownloadSource {
                                agent_id: forwarded.source_agent,
                                peer_id: forwarded.source_peer.clone(),
                            },
                            [0; 16],
                            (*wire_id, *epoch, binding.clone()),
                            act,
                            now_ms,
                        );
                    }
                }
                if self.mailbox.interested()
                    && GroupInboundPolicy::load(&groups.store)
                        .is_ok_and(|policy| policy.browse_enabled)
                {
                    let frame = match forwarded_application {
                        GroupApplication::Query(query) => Some(WireFrame::Query(query)),
                        GroupApplication::Answer(answer) => Some(WireFrame::Answer(answer)),
                        GroupApplication::Offer(offer) => Some(WireFrame::Offer(offer)),
                        GroupApplication::Expression(expression) => {
                            Some(WireFrame::Expression(expression))
                        }
                        GroupApplication::ContextRequest(request) => {
                            Some(WireFrame::ContextRequest(request))
                        }
                        GroupApplication::ContextOffer(offer) => {
                            Some(WireFrame::ContextOffer(offer))
                        }
                        GroupApplication::ContextAgreement(agreement) => {
                            Some(WireFrame::ContextAgreement(agreement))
                        }
                        GroupApplication::ContextExpression(expression) => {
                            Some(WireFrame::ContextExpression(expression))
                        }
                        _ => None,
                    };
                    if let Some(frame) = frame {
                        self.mailbox.observe(
                            crate::downloads::DownloadSource {
                                agent_id: forwarded.source_agent,
                                peer_id: forwarded.source_peer.clone(),
                            },
                            [0; 16],
                            Some((*wire_id, *epoch, binding)),
                            &frame,
                            now_ms,
                        );
                    }
                }
                if GroupInboundPolicy::load(&groups.store).is_ok_and(|policy| policy.browse_enabled)
                {
                    groups
                        .recent_applications
                        .retain(|entry| entry.room != forwarded.root);
                    if groups.recent_applications.len() == MAX_RECENT_ROOMS {
                        groups.recent_applications.pop_front();
                    }
                    groups.recent_applications.push_back(ReceivedApplication {
                        room: forwarded.root,
                        epoch: *epoch,
                        sender: forwarded.source_peer,
                        message: forward.message_id,
                        kind: "shard_forward",
                    });
                }
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
                    .is_some_and(|member| match application.as_ref() {
                        GroupApplication::Act(_)
                        | GroupApplication::Query(_)
                        | GroupApplication::Expression(_)
                        | GroupApplication::ContextRequest(_)
                        | GroupApplication::ContextOffer(_)
                        | GroupApplication::ContextAgreement(_)
                        | GroupApplication::ContextExpression(_) => groups
                            .store
                            .group_can_send(&member.group_id, sender, GroupAccessKind::Text)
                            .unwrap_or(false),
                        GroupApplication::Offer(offer) => groups
                            .store
                            .group_can_access_file(
                                &member.group_id,
                                sender,
                                &offer.content_id,
                                GroupFileAccessKind::Send,
                            )
                            .unwrap_or(false),
                        _ => true,
                    });
            if member_allowed && let GroupApplication::Act(act) = application.as_ref() {
                if let Some(member) = requester.as_ref() {
                    let _ = groups.store.record_contact_interaction_evidence(
                        member.direct.agent,
                        &member.direct.peer,
                        act.message_id,
                        Some((*wire_id, member.membership_epoch)),
                        now_ms,
                    );
                }
                if GroupInboundPolicy::load(&groups.store)
                    .is_ok_and(|policy| policy.browse_enabled || policy.answer_enabled)
                {
                    let _ = groups.queue_ack(*wire_id, act, now_ms);
                }
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
                        select_auto_reply_evidence(&groups.store, libraries, home, member, act)
                    });
                    super::auto_reply::queue_auto_reply(
                        auto_reply,
                        *wire_id,
                        act,
                        evidence,
                        &groups.store,
                        now_ms,
                    );
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
                    GroupApplication::ContextRequest(r) => Some(WireFrame::ContextRequest(*r)),
                    GroupApplication::ContextOffer(o) => Some(WireFrame::ContextOffer(*o)),
                    GroupApplication::ContextAgreement(a) => Some(WireFrame::ContextAgreement(*a)),
                    GroupApplication::ContextExpression(e) => {
                        Some(WireFrame::ContextExpression(e.clone()))
                    }
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
            let context_reply_requested =
                matches!(application.as_ref(), GroupApplication::ContextRequest(_))
                    && GroupInboundPolicy::load(&groups.store)
                        .is_ok_and(|policy| policy.answer_enabled);
            if matches!(
                application.as_ref(),
                GroupApplication::FetchRequest(_)
                    | GroupApplication::FetchGrant(_)
                    | GroupApplication::FetchPending(_)
                    | GroupApplication::Error(_)
            ) || context_reply_requested
            {
                if groups.pending_transfers.len() == MAX_PENDING_GROUP_TRANSFERS {
                    groups.pending_transfers.pop_front();
                }
                groups.pending_transfers.push_back(PendingGroupTransfer {
                    connection_id: *connection_id,
                    wire_id: *wire_id,
                    epoch: *epoch,
                    envelope_id: *envelope_id,
                    sender: sender.clone(),
                    requester: None,
                    application: application.as_ref().clone(),
                });
            }
            let forward_application = application.clone();
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
            if member_allowed
                && let Some(source_agent) = groups.store.mls_peer_agent(sender).ok().flatten()
                && groups
                    .store
                    .mls_room_snapshot(*wire_id)
                    .ok()
                    .flatten()
                    .is_some()
            {
                if matches!(
                    forward_application.as_ref(),
                    GroupApplication::FetchGrant(_) | GroupApplication::FetchPending(_)
                ) {
                    let _ = forward_fetch_response_to_requester(
                        &mut groups.store,
                        admission,
                        net,
                        &self.agent_identity,
                        &self.device_peer_id,
                        *wire_id,
                        forward_application.as_ref(),
                        *envelope_id,
                        source_agent,
                        sender,
                        *epoch,
                        *connection_id,
                        now_ms,
                        &mut groups.pending_transfers,
                    );
                } else {
                    let _ = forward_application_to_logical_shards(
                        &mut groups.store,
                        admission,
                        net,
                        &self.agent_identity,
                        &self.device_peer_id,
                        *wire_id,
                        &forward_application,
                        source_agent,
                        sender,
                        *epoch,
                        now_ms,
                    );
                }
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
        let groups = self.groups.as_ref().ok_or(AslError::NotFound)?;
        let incoming = super::group_routing::decode_incoming(
            &groups.store,
            key,
            payload,
            &self.device_peer_id,
        )?;
        let key = incoming.room;
        let packet = incoming.packet;
        let forward = incoming.forward;
        let directories = HashMap::new();
        let net = &self.net;
        let (Some(groups), Some(admission), libraries, home) = (
            self.groups.as_mut(),
            self.admission.as_mut(),
            &self.libraries,
            &self.home,
        ) else {
            return Ok(());
        };
        let mailbox = &mut self.mailbox;
        let auto_reply = &mut self.auto_reply;
        let Some((application, agent, peer)) =
            admission.apply_mls_gossip(&mut groups.store, &packet, &directories, now_ms)?
        else {
            return Ok(());
        };
        if let Some((topic, payload)) = forward {
            let _ = super::group_routing::forward_packet(net, topic, payload);
        }
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
        if let GroupApplication::RemovalRequest(request) = &application {
            groups.store.record_group_removal_request(
                key,
                &self.device_peer_id,
                &peer,
                request,
                now_ms,
            )?;
            if admission
                .remove_local_mls_member(
                    &mut groups.store,
                    key,
                    &request.target,
                    &directories,
                    now_ms,
                )
                .is_ok()
            {
                let _ = groups.store.forget_group_removal(key, request.message_id);
            }
            return Ok(());
        }
        if let GroupApplication::ShardBinding(binding) = &application {
            let _ = accept_shard_binding(&mut groups.store, admission, key, &peer, binding, now_ms);
            return Ok(());
        }
        if let GroupApplication::ShardForward(forward) = &application {
            let Some(forwarded) =
                accept_shard_forward(&mut groups.store, admission, key, &peer, forward, now_ms)?
            else {
                return Ok(());
            };
            let snapshot = groups
                .store
                .mls_room_snapshot(key)?
                .ok_or(AslError::NotFound)?;
            let local_group_id = snapshot.local_id.clone();
            let transferred = asl_store::transfers::GroupTransferBinding {
                group_id: local_group_id.clone(),
                membership_epoch: snapshot.version.membership_epoch,
            };
            let mut forwarded_application = forwarded.application;
            if matches!(
                forwarded_application,
                GroupApplication::FetchRequest(_)
                    | GroupApplication::FetchGrant(_)
                    | GroupApplication::FetchPending(_)
            ) {
                let is_request =
                    matches!(&forwarded_application, GroupApplication::FetchRequest(_));
                let (pending_connection, transfer_sender, requester) = if is_request {
                    (
                        [0; 16],
                        forwarded.source_peer.clone(),
                        groups
                            .store
                            .cached_group_requester(
                                forward.logical_root,
                                forwarded.source_agent,
                                &forwarded.source_peer,
                                now_ms,
                            )
                            .ok()
                            .flatten(),
                    )
                } else {
                    let Some((source_connection, source_requester)) = forwarded_source_requester(
                        &groups.store,
                        admission,
                        key,
                        forwarded.source_agent,
                        &forwarded.source_peer,
                        now_ms,
                    ) else {
                        return Ok(());
                    };
                    (
                        source_connection,
                        forwarded.source_peer.clone(),
                        Some(source_requester),
                    )
                };
                if groups.pending_transfers.len() == MAX_PENDING_GROUP_TRANSFERS {
                    groups.pending_transfers.pop_front();
                }
                groups.pending_transfers.push_back(PendingGroupTransfer {
                    connection_id: pending_connection,
                    wire_id: key,
                    epoch: packet.epoch,
                    envelope_id: forward.message_id,
                    sender: transfer_sender,
                    requester,
                    application: forwarded_application,
                });
                return Ok(());
            }
            if let GroupApplication::Act(act) = &mut forwarded_application {
                act.conversation_id = local_group_id.0;
                let _ = groups.store.record_contact_interaction_evidence(
                    forwarded.source_agent,
                    &forwarded.source_peer,
                    act.message_id,
                    Some((key, packet.epoch)),
                    now_ms,
                );
                if GroupInboundPolicy::load(&groups.store)
                    .is_ok_and(|policy| policy.browse_enabled || policy.answer_enabled)
                {
                    groups.queue_ack(key, act, now_ms)?;
                }
                if GroupInboundPolicy::load(&groups.store).is_ok_and(|policy| policy.browse_enabled)
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
                if GroupInboundPolicy::load(&groups.store).is_ok_and(|policy| policy.answer_enabled)
                {
                    super::auto_reply::queue_auto_reply(
                        auto_reply,
                        key,
                        act,
                        None,
                        &groups.store,
                        now_ms,
                    );
                }
                if mailbox.interested()
                    && GroupInboundPolicy::load(&groups.store)
                        .is_ok_and(|policy| policy.browse_enabled)
                {
                    mailbox.observe_act(
                        crate::downloads::DownloadSource {
                            agent_id: forwarded.source_agent,
                            peer_id: forwarded.source_peer.clone(),
                        },
                        [0; 16],
                        (key, packet.epoch, transferred.clone()),
                        act,
                        now_ms,
                    );
                }
            }
            if mailbox.interested()
                && GroupInboundPolicy::load(&groups.store).is_ok_and(|policy| policy.browse_enabled)
            {
                let frame = match forwarded_application {
                    GroupApplication::Query(query) => Some(WireFrame::Query(query)),
                    GroupApplication::Answer(answer) => Some(WireFrame::Answer(answer)),
                    GroupApplication::Offer(offer) => Some(WireFrame::Offer(offer)),
                    GroupApplication::Expression(expression) => {
                        Some(WireFrame::Expression(expression))
                    }
                    GroupApplication::ContextRequest(request) => {
                        Some(WireFrame::ContextRequest(request))
                    }
                    GroupApplication::ContextOffer(offer) => Some(WireFrame::ContextOffer(offer)),
                    GroupApplication::ContextAgreement(agreement) => {
                        Some(WireFrame::ContextAgreement(agreement))
                    }
                    GroupApplication::ContextExpression(expression) => {
                        Some(WireFrame::ContextExpression(expression))
                    }
                    _ => None,
                };
                if let Some(frame) = frame {
                    mailbox.observe(
                        crate::downloads::DownloadSource {
                            agent_id: forwarded.source_agent,
                            peer_id: forwarded.source_peer.clone(),
                        },
                        [0; 16],
                        Some((key, packet.epoch, transferred)),
                        &frame,
                        now_ms,
                    );
                }
            }
            return Ok(());
        }
        let member_allowed = match &application {
            GroupApplication::Act(_)
            | GroupApplication::Query(_)
            | GroupApplication::Expression(_)
            | GroupApplication::ContextRequest(_)
            | GroupApplication::ContextOffer(_)
            | GroupApplication::ContextAgreement(_)
            | GroupApplication::ContextExpression(_) => groups
                .store
                .group_can_send(&local_group_id, &peer, GroupAccessKind::Text)
                .unwrap_or(false),
            GroupApplication::Offer(offer) => groups
                .store
                .group_can_access_file(
                    &local_group_id,
                    &peer,
                    &offer.content_id,
                    GroupFileAccessKind::Send,
                )
                .unwrap_or(false),
            _ => true,
        };
        if !member_allowed {
            return Ok(());
        }
        if let GroupApplication::Act(act) = &application {
            let _ = groups.store.record_contact_interaction_evidence(
                agent,
                &peer,
                act.message_id,
                Some((key, packet.epoch)),
                now_ms,
            );
        }
        if let GroupApplication::Act(act) = &application
            && GroupInboundPolicy::load(&groups.store)
                .is_ok_and(|policy| policy.browse_enabled || policy.answer_enabled)
        {
            groups.queue_ack(key, act, now_ms)?;
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
            let evidence = groups
                .store
                .cached_group_requester(key, agent, &peer, now_ms)
                .ok()
                .flatten()
                .and_then(|member| {
                    select_auto_reply_evidence(&groups.store, libraries, home, &member, act)
                });
            super::auto_reply::queue_auto_reply(
                auto_reply,
                key,
                act,
                evidence,
                &groups.store,
                now_ms,
            );
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
        let frame = match application.clone() {
            GroupApplication::Query(query) => Some(WireFrame::Query(query)),
            GroupApplication::Answer(answer) => Some(WireFrame::Answer(answer)),
            GroupApplication::Offer(offer) => Some(WireFrame::Offer(offer)),
            GroupApplication::Expression(expression) => Some(WireFrame::Expression(expression)),
            GroupApplication::ContextRequest(request) => Some(WireFrame::ContextRequest(request)),
            GroupApplication::ContextOffer(offer) => Some(WireFrame::ContextOffer(offer)),
            GroupApplication::ContextAgreement(agreement) => {
                Some(WireFrame::ContextAgreement(agreement))
            }
            GroupApplication::ContextExpression(expression) => {
                Some(WireFrame::ContextExpression(expression))
            }
            _ => None,
        };
        if let Some(frame) = frame
            && mailbox.interested()
            && GroupInboundPolicy::load(&groups.store).is_ok_and(|policy| policy.browse_enabled)
        {
            mailbox.observe(
                crate::downloads::DownloadSource {
                    agent_id: agent,
                    peer_id: peer.clone(),
                },
                [0; 16],
                Some((key, packet.epoch, binding.clone())),
                &frame,
                now_ms,
            );
        }
        if member_allowed
            && let Some(source_agent) = groups.store.mls_peer_agent(&peer).ok().flatten()
        {
            if matches!(
                &application,
                GroupApplication::FetchGrant(_) | GroupApplication::FetchPending(_)
            ) {
                let _ = forward_fetch_response_to_requester(
                    &mut groups.store,
                    admission,
                    net,
                    &self.agent_identity,
                    &self.device_peer_id,
                    key,
                    &application,
                    packet.message_id,
                    source_agent,
                    &peer,
                    packet.epoch,
                    [0; 16],
                    now_ms,
                    &mut groups.pending_transfers,
                );
            } else {
                let _ = forward_application_to_logical_shards(
                    &mut groups.store,
                    admission,
                    net,
                    &self.agent_identity,
                    &self.device_peer_id,
                    key,
                    &application,
                    source_agent,
                    &peer,
                    packet.epoch,
                    now_ms,
                );
            }
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
            let Some(requester) = pending.requester.clone().or_else(|| {
                self.current_group_requester(
                    pending.connection_id,
                    &pending.sender,
                    pending.wire_id,
                    pending.epoch,
                )
            }) else {
                continue;
            };
            match pending.application {
                GroupApplication::FetchRequest(request) => {
                    if let (Some(logical), Some(source_room)) =
                        (request.logical_group_id, request.source_room_id)
                    {
                        let current_root =
                            match self.groups.as_ref().and_then(|groups| {
                                groups.store.mls_logical_root(pending.wire_id).ok()
                            }) {
                                Some(root) => root,
                                None => continue,
                            };
                        if source_room != pending.wire_id || logical != current_root {
                            continue;
                        }
                    }
                    let file_allowed = self.groups.as_ref().is_some_and(|groups| {
                        groups
                            .store
                            .group_can_access_file(
                                &requester.group_id,
                                &requester.direct.peer,
                                &request.content_id,
                                GroupFileAccessKind::Fetch,
                            )
                            .unwrap_or(false)
                    });
                    if !file_allowed {
                        continue;
                    }
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
                GroupApplication::ContextRequest(request) => {
                    self.handle_group_context_request(
                        transfers,
                        &requester,
                        pending.connection_id,
                        pending.wire_id,
                        &request,
                        now_ms,
                    )?;
                }
                reply @ (GroupApplication::FetchGrant(_)
                | GroupApplication::FetchPending(_)
                | GroupApplication::Error(_)) => {
                    let mut reply_requester = requester.clone();
                    if pending.requester.is_some()
                        && let Some(source_agent) = self.groups.as_ref().and_then(|groups| {
                            groups.store.mls_peer_agent(&pending.sender).ok().flatten()
                        })
                        && let Some(source_requester) =
                            self.admission.as_ref().and_then(|admission| {
                                admission.direct_requester(pending.connection_id, source_agent)
                            })
                    {
                        reply_requester.direct = source_requester.clone();
                        transfers.rebind_group_fetch_response(
                            pending.envelope_id,
                            pending.connection_id,
                            &source_requester,
                            now_ms,
                        );
                    }
                    if !transfers.matches_group_reply(
                        pending.envelope_id,
                        pending.connection_id,
                        &reply_requester,
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
                        agent_id: reply_requester.direct.agent,
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
                | GroupApplication::Policy(_)
                | GroupApplication::RemovalRequest(_)
                | GroupApplication::ShardBinding(_)
                | GroupApplication::ShardForward(_)
                | GroupApplication::ContextOffer(_)
                | GroupApplication::ContextAgreement(_)
                | GroupApplication::ContextExpression(_) => {}
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
        if !groups.store.group_can_access_file(
            &snapshot.local_id,
            &self.device_peer_id,
            &request.content_id,
            GroupFileAccessKind::Read,
        )? {
            return Err(AslError::PolicyDenied);
        }
        let cross_shard = request
            .source_room_id
            .is_some_and(|source_room| source_room != wire_id);
        let admission = self.admission.as_mut().ok_or(AslError::InvalidIdentity)?;
        let net = &self.net;
        if cross_shard {
            let source_room = request.source_room_id.ok_or(AslError::InvalidMessage)?;
            if !admission
                .admitted_connections(now_ms)
                .into_iter()
                .any(|(agent, _, peer)| agent == source.agent_id && peer == source.peer_id)
            {
                return Ok(None);
            }
            let logical_root = groups.store.mls_logical_root(wire_id)?;
            let owner = groups
                .store
                .group_access_owner(wire_id)?
                .ok_or(AslError::PolicyDenied)?;
            if owner == self.device_peer_id {
                let requester = groups
                    .store
                    .cached_group_requester(
                        wire_id,
                        self.agent_identity.agent_id(),
                        &self.device_peer_id,
                        now_ms,
                    )?
                    .ok_or(AslError::InvalidIdentity)?;
                transfers.expect_group_fetch_response(
                    LOCAL_GROUP_CONNECTION,
                    &requester.direct,
                    request,
                    (wire_id, group.membership_epoch),
                    now_ms,
                )?;
                let forwarded = forward_application_to_logical_shards(
                    &mut groups.store,
                    admission,
                    net,
                    &self.agent_identity,
                    &self.device_peer_id,
                    wire_id,
                    &GroupApplication::FetchRequest(request.clone()),
                    self.agent_identity.agent_id(),
                    &self.device_peer_id,
                    snapshot.version.mls_epoch,
                    now_ms,
                );
                if forwarded.is_err() {
                    transfers.fail_control_request(
                        LOCAL_GROUP_CONNECTION,
                        requester.direct.agent,
                        &requester.direct.peer,
                        request.message_id.0,
                    );
                    return Ok(None);
                }
                return Ok(Some(LOCAL_GROUP_CONNECTION));
            }
            let route = admission
                .admitted_connections(now_ms)
                .into_iter()
                .find(|(_, _, peer)| peer == &owner);
            if route.is_none()
                && groups.store.has_pending_owner_relay(
                    wire_id,
                    source_room,
                    request.content_id,
                    now_ms,
                )?
            {
                return Ok(None);
            }
            let (packet, outbox_id) = admission.prepare_mls_owner_relay_application(
                &mut groups.store,
                wire_id,
                snapshot.version,
                GroupApplication::FetchRequest(request.clone()),
                logical_root,
                source_room,
                now_ms,
            )?;
            let Some((owner_agent, connection_id, _)) = route else {
                return Ok(None);
            };
            let requester = admission
                .direct_requester(connection_id, owner_agent)
                .ok_or(AslError::InvalidIdentity)?;
            transfers.expect_group_fetch_response(
                connection_id,
                &requester,
                request,
                (wire_id, group.membership_epoch),
                now_ms,
            )?;
            let dispatched = match admission.dispatch_prepared_loopback_mls_shard_forward(
                &mut groups.store,
                &packet,
                now_ms.saturating_add(MAX_SHARD_FORWARD_LIFETIME_MS),
                now_ms,
                |command| enqueue(net, command),
            ) {
                Ok(dispatched) => dispatched,
                Err(_) => {
                    transfers.fail_control_request(
                        connection_id,
                        requester.agent,
                        &requester.peer,
                        request.message_id.0,
                    );
                    return Ok(None);
                }
            };
            if dispatched.queued > 0 {
                let _ = groups.store.complete_shard_forward_outbox(outbox_id);
            }
            return Ok(Some(connection_id));
        }
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
        match admission
            .send_loopback_mls_application_to_connection(
                &mut groups.store,
                crate::profile::MlsApplicationSendToConnection {
                    wire_id,
                    connection_id,
                    envelope_id: request.message_id,
                    application: GroupApplication::FetchRequest(request.clone()),
                    now_ms,
                },
                |command| enqueue(net, command),
            )
            .map(|dispatched| dispatched.queued > 0)
        {
            Ok(true) => Ok(Some(connection_id)),
            Ok(false) | Err(_) => {
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
                let now_ms = unix_time_ms()?;
                groups.cleanup_failed = groups
                    .store
                    .prune_mls_expired(now_ms)
                    .and_then(|()| {
                        groups
                            .store
                            .prune_expired_group_invite_requests(now_ms)
                            .map(|_| ())
                    })
                    .and_then(|()| groups.store.prune_fetch_relays(now_ms).map(|_| ()))
                    .and_then(|()| groups.store.prune_shard_forward_outbox(now_ms).map(|_| ()))
                    .is_err();
            }
            if self.net.is_running()
                && self.network_admission_status == NetworkAdmissionStatus::Active
                && !groups.cleanup_failed
            {
                for (wire_id, _) in groups.store.list_mls_room_ids()? {
                    let topics = super::group_routing::topics_for_room(
                        &groups.store,
                        wire_id,
                        &self.device_peer_id,
                    )
                    .unwrap_or_else(|_| vec![wire_id]);
                    for topic in topics {
                        if groups.gossip_subscriptions.insert(topic) {
                            let command = NetworkCommand::GossipSubscribe {
                                operation_id: fresh_id()?,
                                key: topic.0,
                            };
                            if enqueue(&self.net, command).is_err() {
                                groups.gossip_subscriptions.remove(&topic);
                            }
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
        if self.net.is_running()
            && self.network_admission_status == NetworkAdmissionStatus::Active
            && self
                .groups
                .as_ref()
                .is_some_and(|groups| !groups.cleanup_failed)
        {
            self.poll_shard_forward_outbox(unix_time_ms()?)?;
        }
        let acks = self
            .groups
            .as_mut()
            .map(|groups| groups.take_due_acks(Instant::now()))
            .unwrap_or_default();
        for pending in acks {
            let room = pending.room;
            let act = pending.act.clone();
            if self.send_group_act(room, act).is_err()
                && let Some(groups) = self.groups.as_mut()
            {
                groups.retry_ack(pending);
            }
        }
        self.poll_group_review();
        self.poll_migration_group_rejoin();
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

    fn poll_shard_forward_outbox(&mut self, now_ms: u64) -> Result<(), AslError> {
        let Some(groups) = self.groups.as_mut() else {
            return Ok(());
        };
        let now = Instant::now();
        if now < groups.next_shard_forward_retry {
            return Ok(());
        }
        groups.next_shard_forward_retry = now + SHARD_FORWARD_RETRY_INTERVAL;
        let due = groups
            .store
            .due_shard_forward_outbox(now_ms, MAX_SHARD_FORWARD_OUTBOX_BATCH)?;
        if due.is_empty() {
            return Ok(());
        }
        let Some(admission) = self.admission.as_mut() else {
            return Ok(());
        };
        let Some(groups) = self.groups.as_mut() else {
            return Ok(());
        };
        for entry in due {
            retry_shard_forward_outbox_entry(
                &mut groups.store,
                admission,
                &self.net,
                &self.device_peer_id,
                entry,
                now_ms,
            )?;
        }
        Ok(())
    }

    fn poll_migration_group_rejoin(&mut self) {
        let Some(groups) = self.groups.as_mut() else {
            return;
        };
        let instant = Instant::now();
        if instant < groups.next_migration_rejoin
            || groups.cleanup_failed
            || !self.net.is_running()
            || self.network_admission_status != NetworkAdmissionStatus::Active
        {
            return;
        }
        groups.next_migration_rejoin = instant + Duration::from_secs(15);
        if !matches!(groups.store.get_setting("mls.migration_rejoin.v1"), Ok(Some(value)) if value == "true")
            || !matches!(groups.store.network_pause_requested(), Ok(false))
        {
            return;
        }
        let Ok(paths) = AppPaths::open_existing(&self.home) else {
            return;
        };
        if !matches!(crate::migration::status(&paths), Ok(Some(status))
            if status.phase == crate::migration::IdentityMigrationPhaseV1::ReadyToJoin)
        {
            return;
        }
        let Ok(now_ms) = unix_time_ms() else {
            return;
        };
        let Some(admission) = self.admission.as_ref() else {
            return;
        };
        let connections = admission.admitted_connections(now_ms);
        let Ok(hints) = groups.store.migration_group_hints() else {
            return;
        };
        let selected = hints.into_iter().find_map(|hint| {
            if !connections.iter().any(|(agent, _, _)| *agent == hint.owner) {
                return None;
            }
            let room = Hash32(hint.wire_id);
            let key = format!("mls.migration_rejoin_sent.{}", hex::encode(room.0));
            let previous = groups.store.get_setting(&key).ok().flatten();
            if previous
                .as_deref()
                .and_then(|value| value.parse::<u64>().ok())
                .is_some_and(|sent| now_ms.saturating_sub(sent) < 60 * 60 * 1_000)
            {
                return None;
            }
            Some((room, hint.owner, key))
        });
        let Some((room, owner, key)) = selected else {
            return;
        };
        if self.request_group_join(room, owner).is_ok()
            && let Some(groups) = self.groups.as_ref()
            && let Ok(now) = i64::try_from(now_ms)
        {
            let _ = groups.store.set_setting(&key, &now_ms.to_string(), now);
        }
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
                let invite_requests = store
                    .list_group_invite_requests(local_peer, now_ms, 100)?
                    .into_iter()
                    .map(|request| {
                        json!({
                            "request": hex::encode(request.request_id.0),
                            "room": hex::encode(request.wire_id.0),
                            "agent": format!(
                                "agent:{}",
                                hex::encode(request.requester.0)
                            ),
                            "device": peer_text(&request.device),
                            "mls_epoch": request.mls_epoch,
                            "expires_at_ms": request.expires_at_ms
                        })
                    })
                    .collect::<Vec<_>>();
                let migration_group_hints = store
                    .migration_group_hints()?
                    .into_iter()
                    .map(|hint| {
                        json!({
                            "room": hex::encode(hint.wire_id),
                            "name": hint.local_name,
                            "owner": format!("agent:{}", hex::encode(hint.owner.0)),
                            "last_epoch": hint.last_epoch,
                            "state": "needs_rejoin"
                        })
                    })
                    .collect::<Vec<_>>();
                return Ok(json!({
                    "rooms": rooms,
                    "pending": pending,
                    "approved": approved,
                    "invite_requests": invite_requests,
                    "migration_group_hints": migration_group_hints
                }));
            }
            LocalGroupAction::Room(id) => {
                let (state, epoch) = store.mls_room_progress(id)?.ok_or(AslError::NotFound)?;
                let mut view = json!({
                    "room": hex::encode(id.0),
                    "state": state,
                    "mls_epoch": epoch,
                    "shards": store.mls_room_shards(id)?.iter()
                        .map(|room| hex::encode(room.0)).collect::<Vec<_>>(),
                    "removal_requests": store.group_removal_requests(id, local_peer, now_ms)?
                        .into_iter().map(|request| json!({
                            "request_id": hex::encode(request.id.0),
                            "requester": peer_text(&request.requester),
                            "target": peer_text(&request.target),
                            "expires_at_ms": request.expires_at_ms,
                        })).collect::<Vec<_>>(),
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
            LocalGroupAction::RejectJoinRequest { room, device } => {
                if !store.finish_group_invite_request(room, &device, false, now_ms)? {
                    return Err(AslError::NotFound);
                }
                return Ok(json!({"state": "rejected"}));
            }
            LocalGroupAction::RenewResourceBudget {
                room,
                kind,
                additional,
                window_hours,
            } => {
                let snapshot = store.mls_room_snapshot(room)?.ok_or(AslError::NotFound)?;
                let kind = resource_budget_kind(&kind)?;
                let conversation = hex::encode(snapshot.local_id.0.0);
                let expires_at_ms =
                    now_ms.saturating_add(u64::from(window_hours).saturating_mul(60 * 60 * 1_000));
                if !store.renew_resource_budget(
                    &conversation,
                    kind,
                    additional,
                    expires_at_ms,
                    now_ms,
                )? {
                    return Err(AslError::NotFound);
                }
                return Ok(json!({
                    "room": hex::encode(room.0),
                    "conversation_id": conversation,
                    "kind": kind_name(kind),
                    "additional": additional,
                    "expires_at_ms": expires_at_ms,
                }));
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
            LocalGroupAction::CreateShard(root) => {
                let root = store.mls_logical_root(root)?;
                let id = GroupId(Id128(fresh_id()?));
                let (wire_id, _) = admission.create_local_mls_room_linked(
                    store,
                    &self.agent_identity,
                    &id,
                    "Group shard",
                    now_ms,
                    Some(root),
                )?;
                grant_act_budget(store, id.0, now_ms)?;
                let (_, shard_index) = store
                    .mls_shard_parent(wire_id)?
                    .ok_or(AslError::InvalidPolicyState)?;
                ensure_local_shard_binding(
                    store,
                    &self.agent_identity,
                    local_peer,
                    root,
                    shard_index,
                    wire_id,
                    now_ms,
                )?;
                Ok(json!({"root": hex::encode(root.0), "room": hex::encode(wire_id.0)}))
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
                let root = store.mls_logical_root(room)?;
                let (agent, device) = admission.admitted_peer_identity(connection_id, now_ms)?;
                let owner = store.group_access_owner(root)?.ok_or(AslError::NotFound)?;
                if owner != *local_peer {
                    return Ok(json!({
                        "root": hex::encode(root.0),
                        "state": "owner_action_required",
                        "error_code": "delegated_invite_requires_logical_owner",
                        "owner_peer": peer_text(&owner),
                        "queued": false,
                    }));
                }
                if store.logical_group_has_agent(root, agent)? {
                    return Ok(json!({
                        "root": hex::encode(root.0),
                        "state": "already_member",
                        "created_shard": false,
                        "queued": false,
                    }));
                }
                if store.logical_group_member_count(root)? >= MAX_LAYERED_GROUP_MEMBERS {
                    return Err(AslError::QuotaExceeded);
                }
                let (room, created_shard) = choose_or_create_mls_shard(
                    admission,
                    store,
                    &self.agent_identity,
                    root,
                    local_peer,
                    &device,
                    now_ms,
                )?;
                if store.has_mls_sync_member(room, &device)? {
                    return Ok(json!({
                        "root": hex::encode(root.0),
                        "room": hex::encode(room.0),
                        "state": "already_member",
                        "created_shard": created_shard,
                        "queued": false,
                    }));
                }
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
                let _ = store.finish_group_invite_request(root, &device, true, now_ms);
                Ok(json!({
                    "root": hex::encode(root.0),
                    "room": hex::encode(room.0),
                    "state": "queued",
                    "created_shard": created_shard,
                    "queued": true,
                }))
            }
            LocalGroupAction::InviteShard {
                root,
                connection_id,
            } => {
                let root = store.mls_logical_root(root)?;
                let (agent, device) = admission.admitted_peer_identity(connection_id, now_ms)?;
                if store.logical_group_has_agent(root, agent)? {
                    return Ok(json!({
                        "root": hex::encode(root.0),
                        "state": "already_member",
                        "created_shard": false,
                        "queued": false,
                    }));
                }
                if store.logical_group_member_count(root)? >= MAX_LAYERED_GROUP_MEMBERS {
                    return Err(AslError::QuotaExceeded);
                }
                let (room, created_shard) = choose_or_create_mls_shard(
                    admission,
                    store,
                    &self.agent_identity,
                    root,
                    local_peer,
                    &device,
                    now_ms,
                )?;
                if store.has_mls_sync_member(room, &device)? {
                    return Ok(json!({
                        "root": hex::encode(root.0),
                        "room": hex::encode(room.0),
                        "state": "already_member",
                        "created_shard": created_shard,
                        "queued": false,
                    }));
                }
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
                let _ = store.finish_group_invite_request(root, &device, true, now_ms);
                Ok(json!({
                    "root": hex::encode(root.0),
                    "room": hex::encode(room.0),
                    "state": "queued",
                    "created_shard": created_shard,
                    "queued": true,
                }))
            }
            LocalGroupAction::Remove { room, peer } => {
                let owner = store
                    .group_access_owner(room)?
                    .ok_or(AslError::PolicyDenied)?;
                if owner == peer || &owner != local_peer {
                    return Err(AslError::PolicyDenied);
                }
                let snapshot = store.mls_room_snapshot(room)?.ok_or(AslError::NotFound)?;
                let policy = store.group_access_policy(&snapshot.local_id)?;
                if policy.admins.contains(local_peer)
                    && !store.group_admin_has_capability(
                        &snapshot.local_id,
                        local_peer,
                        GroupAdminCapabilityKind::ManageMembers,
                    )?
                {
                    return Err(AslError::PolicyDenied);
                }
                let version =
                    admission.remove_local_mls_member(store, room, &peer, &directories, now_ms)?;
                Ok(json!({
                    "room": hex::encode(room.0),
                    "removed": peer_text(&peer),
                    "state": "needs_sync",
                    "mls_epoch": version.mls_epoch
                }))
            }
            LocalGroupAction::ProposeRemove { room, peer } => {
                let (owner, _, _) = store.check_group_removal_request(room, local_peer, &peer)?;
                if &owner == local_peer {
                    return Err(AslError::PolicyDenied);
                }
                let connection_id = admission
                    .admitted_connections(now_ms)
                    .into_iter()
                    .find_map(|(_, id, candidate)| (candidate == owner).then_some(id))
                    .ok_or(AslError::NotFound)?;
                let request_id = Id128(fresh_id()?);
                let dispatch = admission.send_loopback_mls_application_to_connection(
                    store,
                    crate::profile::MlsApplicationSendToConnection {
                        wire_id: room,
                        connection_id,
                        envelope_id: request_id,
                        application: GroupApplication::RemovalRequest(GroupRemovalRequest {
                            message_id: request_id,
                            target: peer,
                            expires_at_ms: now_ms.saturating_add(GROUP_REMOVAL_REQUEST_TTL_MS),
                        }),
                        now_ms,
                    },
                    |command| enqueue(net, command),
                )?;
                if dispatch.queued == 0 {
                    return Err(AslError::QuotaExceeded);
                }
                Ok(json!({"request_id": hex::encode(request_id.0), "state": "queued"}))
            }
            LocalGroupAction::ReviewRemoval {
                room,
                request,
                approve,
            } => {
                let target = store.review_group_removal(room, request, local_peer, now_ms)?;
                let epoch = if approve {
                    Some(
                        admission
                            .remove_local_mls_member(store, room, &target, &directories, now_ms)?
                            .mls_epoch,
                    )
                } else {
                    None
                };
                store.forget_group_removal(room, request)?;
                Ok(
                    json!({"state": if approve { "committed" } else { "rejected" }, "mls_epoch": epoch}),
                )
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
            LocalGroupAction::RequestJoin { room, owner } => self.request_group_join(room, owner),
            LocalGroupAction::Dial { address, peer } => {
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
            | LocalGroupAction::RejectJoinRequest { .. }
            | LocalGroupAction::RenewResourceBudget { .. }
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
            && !match &frame {
                WireFrame::Offer(offer) => self.store.group_can_access_file(
                    &requester.group_id,
                    local_peer,
                    &offer.content_id,
                    GroupFileAccessKind::Send,
                )?,
                _ => false,
            }
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

fn verify_shard_binding(
    admission: &mut CoreAdmission,
    binding: &ShardBinding,
    now_ms: u64,
) -> Result<(), AslError> {
    binding.validate_at(now_ms)?;
    let controller = admission.verified_controller(binding.owner_agent, now_ms)?;
    verify_root_signature(&binding.signing_preimage()?, binding.signature, controller)
}

fn accept_shard_binding(
    store: &mut Store,
    admission: &mut CoreAdmission,
    room: Hash32,
    sender: &PeerId,
    binding: &ShardBinding,
    now_ms: u64,
) -> Result<bool, AslError> {
    if binding.child != room
        || store.group_access_owner(room)?.as_ref() != Some(sender)
        || store.mls_peer_agent(sender)? != Some(binding.owner_agent)
    {
        return Err(AslError::PolicyDenied);
    }
    verify_shard_binding(admission, binding, now_ms)?;
    store.store_shard_binding(binding, sender, now_ms)
}

fn forwarded_source_requester(
    store: &Store,
    admission: &CoreAdmission,
    wire_id: Hash32,
    source_agent: AgentId,
    source_peer: &PeerId,
    now_ms: u64,
) -> Option<([u8; 16], GroupRequester)> {
    let (_, connection_id, _) = admission
        .admitted_connections(now_ms)
        .into_iter()
        .find(|(agent, _, peer)| *agent == source_agent && peer == source_peer)?;
    let direct = admission.direct_requester(connection_id, source_agent)?;
    let snapshot = store.mls_room_snapshot(wire_id).ok().flatten()?;
    Some((
        connection_id,
        GroupRequester {
            direct,
            wire_id,
            group_id: snapshot.local_id,
            membership_epoch: snapshot.version.membership_epoch,
        },
    ))
}

fn accept_shard_forward(
    store: &mut Store,
    admission: &mut CoreAdmission,
    room: Hash32,
    outer_sender: &PeerId,
    forward: &ShardForward,
    now_ms: u64,
) -> Result<Option<AcceptedShardForward>, AslError> {
    forward.validate_at(now_ms)?;
    if forward.target_child != room
        || store.group_access_owner(room)?.as_ref() != Some(outer_sender)
        || store.mls_peer_agent(outer_sender)? != Some(forward.attestor_agent)
    {
        return Err(AslError::PolicyDenied);
    }
    let controller = admission.verified_controller(forward.attestor_agent, now_ms)?;
    verify_root_signature(&forward.signing_preimage()?, forward.signature, controller)?;
    if let Some(binding) = &forward.target_binding {
        if binding.logical_root != forward.logical_root
            || binding.child != room
            || binding.owner_agent != forward.attestor_agent
            || &binding.owner_peer != outer_sender
        {
            return Err(AslError::PolicyDenied);
        }
        accept_shard_binding(store, admission, room, outer_sender, binding, now_ms)?;
    } else if room != forward.logical_root {
        return Err(AslError::PolicyDenied);
    }
    if !store.claim_shard_forward(forward, outer_sender, now_ms)? {
        return Ok(None);
    }
    let application = GroupApplication::decode(&forward.payload)?;
    if !matches!(
        application,
        GroupApplication::Act(_)
            | GroupApplication::Query(_)
            | GroupApplication::Answer(_)
            | GroupApplication::Offer(_)
            | GroupApplication::FetchRequest(_)
            | GroupApplication::FetchGrant(_)
            | GroupApplication::FetchPending(_)
            | GroupApplication::Expression(_)
            | GroupApplication::ContextRequest(_)
            | GroupApplication::ContextOffer(_)
            | GroupApplication::ContextAgreement(_)
            | GroupApplication::ContextExpression(_)
    ) {
        return Err(AslError::PolicyDenied);
    }
    Ok(Some(AcceptedShardForward {
        root: forward.logical_root,
        source_agent: forward.source_agent,
        source_peer: forward.source_peer.clone(),
        application,
    }))
}

fn shard_forward_allows(
    store: &Store,
    source_room: Hash32,
    source_peer: &PeerId,
    application: &GroupApplication,
) -> bool {
    let Ok(Some(snapshot)) = store.mls_room_snapshot(source_room) else {
        return false;
    };
    match application {
        GroupApplication::Act(_)
        | GroupApplication::Query(_)
        | GroupApplication::Answer(_)
        | GroupApplication::Expression(_)
        | GroupApplication::ContextRequest(_)
        | GroupApplication::ContextOffer(_)
        | GroupApplication::ContextAgreement(_)
        | GroupApplication::ContextExpression(_) => store
            .group_can_send(&snapshot.local_id, source_peer, GroupAccessKind::Text)
            .unwrap_or(false),
        GroupApplication::Offer(offer) => store
            .group_can_access_file(
                &snapshot.local_id,
                source_peer,
                &offer.content_id,
                GroupFileAccessKind::Send,
            )
            .unwrap_or(false),
        GroupApplication::FetchRequest(request) => store
            .group_can_access_file(
                &snapshot.local_id,
                source_peer,
                &request.content_id,
                GroupFileAccessKind::Fetch,
            )
            .unwrap_or(false),
        GroupApplication::FetchGrant(grant) => store
            .group_can_access_file(
                &snapshot.local_id,
                source_peer,
                &grant.content_id,
                GroupFileAccessKind::Read,
            )
            .unwrap_or(false),
        GroupApplication::FetchPending(pending) => store
            .group_can_access_file(
                &snapshot.local_id,
                source_peer,
                &pending.content_id,
                GroupFileAccessKind::Read,
            )
            .unwrap_or(false),
        _ => false,
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn forward_application_to_logical_shards(
    store: &mut Store,
    admission: &mut CoreAdmission,
    net: &NetRuntime,
    identity: &AgentIdentity,
    local_peer: &PeerId,
    source_room: Hash32,
    application: &GroupApplication,
    source_agent: AgentId,
    source_peer: &PeerId,
    source_epoch: u64,
    now_ms: u64,
) -> Result<Value, AslError> {
    if !matches!(
        application,
        GroupApplication::Act(_)
            | GroupApplication::Query(_)
            | GroupApplication::Answer(_)
            | GroupApplication::Offer(_)
            | GroupApplication::FetchRequest(_)
            | GroupApplication::Expression(_)
            | GroupApplication::ContextRequest(_)
            | GroupApplication::ContextOffer(_)
            | GroupApplication::ContextAgreement(_)
            | GroupApplication::ContextExpression(_)
    ) {
        return Ok(json!({"state": "not_forwardable", "rooms": []}));
    }
    let root = store.mls_logical_root(source_room)?;
    let shards = store.mls_room_shards(root)?;
    if shards.is_empty() || store.group_access_owner(root)?.as_ref() != Some(local_peer) {
        return Ok(json!({"state": "single_room", "rooms": []}));
    }
    let source = store
        .mls_room_snapshot(source_room)?
        .ok_or(AslError::NotFound)?;
    if store.mls_peer_agent(source_peer)? != Some(source_agent)
        || !shard_forward_allows(store, source_room, source_peer, application)
    {
        return Err(AslError::PolicyDenied);
    }
    let payload = application.clone().encode()?;
    let (_, source_expires) = application.time_bounds();
    let expires_at_ms = source_expires.min(
        now_ms
            .checked_add(MAX_SHARD_FORWARD_LIFETIME_MS)
            .ok_or(AslError::InvalidMessage)?,
    );
    if expires_at_ms <= now_ms {
        return Err(AslError::ExpiredMessage);
    }
    let fetch_source = match application {
        GroupApplication::FetchRequest(request) => {
            let Some(target) = request.source_room_id else {
                return Ok(json!({"state": "not_forwardable", "rooms": []}));
            };
            if request.logical_group_id != Some(root) || store.mls_logical_root(target)? != root {
                return Err(AslError::PolicyDenied);
            }
            if target == source_room {
                return Ok(json!({"state": "single_room", "rooms": []}));
            }
            store.record_fetch_relay(
                request.message_id,
                root,
                source_room,
                target,
                source_agent,
                source_peer,
                request.content_id,
                now_ms,
                expires_at_ms,
            )?;
            Some(target)
        }
        _ => None,
    };
    let mut targets = fetch_source.map_or_else(
        || {
            let mut targets = shards;
            targets.push(root);
            targets
        },
        |target| vec![target],
    );
    targets.retain(|target| *target != source_room);
    let mut outcomes = Vec::with_capacity(targets.len());
    for target in targets {
        if !store.has_mls_sync_member(target, local_peer)? {
            outcomes.push(json!({
                "room": hex::encode(target.0),
                "state": "skipped",
                "error_code": "owner_not_member",
            }));
            continue;
        }
        let target_binding = if target == root {
            None
        } else {
            let (_, shard_index) = store
                .mls_shard_parent(target)?
                .ok_or(AslError::InvalidPolicyState)?;
            Some(ensure_local_shard_binding(
                store,
                identity,
                local_peer,
                root,
                shard_index,
                target,
                now_ms,
            )?)
        };
        let mut forward = ShardForward {
            message_id: Id128(fresh_id()?),
            logical_root: root,
            source_child: source_room,
            target_child: target,
            source_agent,
            source_peer: source_peer.clone(),
            source_mls_epoch: source_epoch,
            source_membership_epoch: source.version.membership_epoch,
            source_message_id: application.message_id(),
            hop: MAX_SHARD_FORWARD_HOP,
            observed_at_ms: now_ms,
            expires_at_ms,
            payload: payload.clone(),
            target_binding,
            attestor_agent: identity.agent_id(),
            attestor_peer: local_peer.clone(),
            signature: Signature65([0; 65]),
        };
        forward.signature = identity.sign_domain_message(&forward.signing_preimage()?)?;
        let target_snapshot = store.mls_room_snapshot(target)?.ok_or(AslError::NotFound)?;
        let bytes = u64::try_from(forward.encode()?.len()).map_err(|_| AslError::InvalidMessage)?;
        let reservation = store
            .reserve_budget(
                &hex::encode(target_snapshot.local_id.0.0),
                0,
                &[(BudgetKind::MessageBytes, bytes)],
                now_ms,
            )?
            .ok_or(AslError::QuotaExceeded)?;
        let forward_id = forward.message_id;
        let prepared = admission.prepare_mls_shard_forward(store, target, forward, now_ms);
        match prepared {
            Ok(packet) => {
                let direct = admission.dispatch_prepared_loopback_mls_shard_forward(
                    store,
                    &packet,
                    expires_at_ms,
                    now_ms,
                    |command| {
                        if net.try_send(&command.into_ipc()?)? {
                            Ok(())
                        } else {
                            Err(AslError::SandboxUnavailable)
                        }
                    },
                );
                let (queued, available, error_code) = match &direct {
                    Ok(sent) => (sent.queued, sent.available, None),
                    Err(error) => (0, 0, Some(group_operation_error_code(error))),
                };
                let published =
                    super::group_routing::publish_packet(net, store, target, local_peer, &packet)
                        .is_ok();
                if queued > 0 && store.complete_shard_forward_outbox(forward_id).is_ok() {
                    outcomes.push(json!({
                        "room": hex::encode(target.0),
                        "state": "queued",
                        "queued": queued,
                        "available": available,
                        "published": published,
                    }));
                } else {
                    outcomes.push(json!({
                        "room": hex::encode(target.0),
                        "state": "pending",
                        "persisted": true,
                        "queued": queued,
                        "available": available,
                        "published": published,
                        "error_code": error_code.unwrap_or("retry_pending"),
                    }));
                }
            }
            Err(error) => {
                let _ = store.refund_budget_reservation(reservation, now_ms);
                outcomes.push(json!({
                    "room": hex::encode(target.0),
                    "state": "failed",
                    "error_code": group_operation_error_code(&error),
                }));
            }
        }
    }
    Ok(json!({"root": hex::encode(root.0), "rooms": outcomes}))
}

#[allow(clippy::too_many_arguments)]
fn forward_fetch_response_to_requester(
    store: &mut Store,
    admission: &mut CoreAdmission,
    net: &NetRuntime,
    identity: &AgentIdentity,
    local_peer: &PeerId,
    source_room: Hash32,
    application: &GroupApplication,
    request_id: Id128,
    source_agent: AgentId,
    source_peer: &PeerId,
    source_epoch: u64,
    source_connection: [u8; 16],
    now_ms: u64,
    pending_transfers: &mut VecDeque<PendingGroupTransfer>,
) -> Result<(), AslError> {
    if !matches!(
        application,
        GroupApplication::FetchGrant(_) | GroupApplication::FetchPending(_)
    ) {
        return Err(AslError::InvalidMessage);
    }
    let response_content_id = match application {
        GroupApplication::FetchGrant(grant) => grant.content_id,
        GroupApplication::FetchPending(pending) => pending.content_id,
        _ => return Err(AslError::InvalidMessage),
    };
    let Some(relay) = store.fetch_relay(source_room, request_id, now_ms)? else {
        return Ok(());
    };
    let root = store.mls_logical_root(source_room)?;
    if relay.logical_root != root
        || relay.source_room != source_room
        || relay.content_id != response_content_id
        || store.group_access_owner(root)?.as_ref() != Some(local_peer)
        || store.mls_peer_agent(source_peer)? != Some(source_agent)
        || store.mls_peer_agent(&relay.requester_peer)? != Some(relay.requester_agent)
        || !shard_forward_allows(store, source_room, source_peer, application)
        || !store.has_mls_sync_member(relay.requester_room, &relay.requester_peer)?
    {
        return Err(AslError::PolicyDenied);
    }
    let source = store
        .mls_room_snapshot(source_room)?
        .ok_or(AslError::NotFound)?;
    let target = store
        .mls_room_snapshot(relay.requester_room)?
        .ok_or(AslError::NotFound)?;
    if relay.requester_peer == *local_peer {
        let requester = store
            .cached_group_requester(
                relay.requester_room,
                relay.requester_agent,
                &relay.requester_peer,
                now_ms,
            )?
            .ok_or(AslError::PolicyDenied)?;
        if pending_transfers.len() == MAX_PENDING_GROUP_TRANSFERS {
            pending_transfers.pop_front();
        }
        pending_transfers.push_back(PendingGroupTransfer {
            connection_id: source_connection,
            wire_id: relay.requester_room,
            epoch: target.version.mls_epoch,
            envelope_id: request_id,
            sender: source_peer.clone(),
            requester: Some(requester),
            application: application.clone(),
        });
        return Ok(());
    }
    let (_, source_expires) = application.time_bounds();
    let expires_at_ms = source_expires.min(relay.expires_at_ms).min(
        now_ms
            .checked_add(MAX_SHARD_FORWARD_LIFETIME_MS)
            .ok_or(AslError::InvalidMessage)?,
    );
    if expires_at_ms <= now_ms {
        return Err(AslError::ExpiredMessage);
    }
    let target_binding = if relay.requester_room == root {
        None
    } else {
        let (_, shard_index) = store
            .mls_shard_parent(relay.requester_room)?
            .ok_or(AslError::InvalidPolicyState)?;
        Some(ensure_local_shard_binding(
            store,
            identity,
            local_peer,
            root,
            shard_index,
            relay.requester_room,
            now_ms,
        )?)
    };
    let payload = application.clone().encode()?;
    let mut forward = ShardForward {
        message_id: Id128(fresh_id()?),
        logical_root: root,
        source_child: source_room,
        target_child: relay.requester_room,
        source_agent,
        source_peer: source_peer.clone(),
        source_mls_epoch: source_epoch,
        source_membership_epoch: source.version.membership_epoch,
        source_message_id: application.message_id(),
        hop: MAX_SHARD_FORWARD_HOP,
        observed_at_ms: now_ms,
        expires_at_ms,
        payload,
        target_binding,
        attestor_agent: identity.agent_id(),
        attestor_peer: local_peer.clone(),
        signature: Signature65([0; 65]),
    };
    forward.signature = identity.sign_domain_message(&forward.signing_preimage()?)?;
    let bytes = u64::try_from(forward.encode()?.len()).map_err(|_| AslError::InvalidMessage)?;
    let reservation = store
        .reserve_budget(
            &hex::encode(target.local_id.0.0),
            0,
            &[(BudgetKind::MessageBytes, bytes)],
            now_ms,
        )?
        .ok_or(AslError::QuotaExceeded)?;
    let forward_id = forward.message_id;
    let packet = match admission.prepare_mls_owner_reply_forward(
        store,
        relay.requester_room,
        forward,
        &relay.requester_peer,
        relay.content_id,
        now_ms,
    ) {
        Ok(packet) => packet,
        Err(error) => {
            let _ = store.refund_budget_reservation(reservation, now_ms);
            return Err(error);
        }
    };
    let dispatched = admission.dispatch_prepared_loopback_mls_shard_forward_to_peer(
        store,
        &packet,
        &relay.requester_peer,
        expires_at_ms,
        now_ms,
        |command| {
            if net.try_send(&command.into_ipc()?)? {
                Ok(())
            } else {
                Err(AslError::SandboxUnavailable)
            }
        },
    );
    if matches!(&dispatched, Ok(sent) if sent.queued > 0) {
        let _ = store.complete_shard_forward_outbox(forward_id);
    }
    Ok(())
}

fn retry_shard_forward_outbox_entry(
    store: &mut Store,
    admission: &mut CoreAdmission,
    net: &NetRuntime,
    local_peer: &PeerId,
    entry: PendingShardForwardOutbox,
    now_ms: u64,
) -> Result<(), AslError> {
    let route = &entry.route;
    if now_ms >= route.expires_at_ms {
        return store.terminate_shard_forward_outbox(route.forward_id, "expired", now_ms);
    }
    let packet = match decode_frame(&entry.frame) {
        Ok(WireFrame::GroupEnvelope(envelope)) => GroupPacket::from_envelope(envelope),
        _ => Err(AslError::InvalidMessage),
    };
    let packet = match packet {
        Ok(packet)
            if (route.kind == ShardForwardOutboxKind::Forward
                && packet.group_id == route.target_child)
                || (route.kind == ShardForwardOutboxKind::OwnerRelay
                    && packet.group_id == route.source_child)
                || (route.kind == ShardForwardOutboxKind::OwnerReply
                    && packet.group_id == route.target_child) =>
        {
            packet
        }
        _ => {
            return store.terminate_shard_forward_outbox(route.forward_id, "invalid_frame", now_ms);
        }
    };
    if route.kind == ShardForwardOutboxKind::OwnerReply {
        let Some(target_peer) = route.target_peer.as_ref() else {
            return store.terminate_shard_forward_outbox(
                route.forward_id,
                "requester_missing",
                now_ms,
            );
        };
        let Some(target_snapshot) = store.mls_room_snapshot(route.target_child)? else {
            return store.terminate_shard_forward_outbox(
                route.forward_id,
                "target_missing",
                now_ms,
            );
        };
        let Some((target_state, _)) = store.mls_room_progress(route.target_child)? else {
            return store.terminate_shard_forward_outbox(
                route.forward_id,
                "target_missing",
                now_ms,
            );
        };
        if target_state != "active"
            || packet.epoch != target_snapshot.version.mls_epoch
            || !store.has_mls_sync_member(route.target_child, target_peer)?
        {
            return store.terminate_shard_forward_outbox(
                route.forward_id,
                "requester_not_member",
                now_ms,
            );
        }
        let source_root = store.mls_logical_root(route.source_child)?;
        let target_root = store.mls_logical_root(route.target_child)?;
        if source_root != route.logical_root || target_root != route.logical_root {
            return store.terminate_shard_forward_outbox(
                route.forward_id,
                "logical_root_changed",
                now_ms,
            );
        }
        if store.group_access_owner(route.logical_root)?.as_ref() != Some(local_peer)
            || !store.has_mls_sync_member(route.target_child, local_peer)?
        {
            return store.terminate_shard_forward_outbox(
                route.forward_id,
                "owner_not_available",
                now_ms,
            );
        }
        let direct = admission.dispatch_prepared_loopback_mls_shard_forward_to_peer(
            store,
            &packet,
            target_peer,
            route.expires_at_ms,
            now_ms,
            |command| {
                if net.try_send(&command.into_ipc()?)? {
                    Ok(())
                } else {
                    Err(AslError::SandboxUnavailable)
                }
            },
        );
        if matches!(&direct, Ok(sent) if sent.queued > 0) {
            return store.complete_shard_forward_outbox(route.forward_id);
        }
        let error = direct.err().unwrap_or(AslError::NotFound);
        let terminal_reason = match &error {
            AslError::ExpiredMessage => Some("expired"),
            AslError::PolicyVersionConflict => Some("target_epoch_changed"),
            AslError::PolicyDenied => Some("requester_not_member"),
            AslError::InvalidMessage => Some("invalid_frame"),
            AslError::IncompatibleVersion => Some("requester_incompatible"),
            _ => None,
        };
        if let Some(reason) = terminal_reason {
            return store.terminate_shard_forward_outbox(route.forward_id, reason, now_ms);
        }
        let attempts = entry.attempts.saturating_add(1);
        let delay = SHARD_FORWARD_OUTBOX_RETRY_BASE_MS
            .saturating_mul(1_u64 << attempts.min(7))
            .min(SHARD_FORWARD_OUTBOX_RETRY_MAX_MS);
        let next_attempt_ms = now_ms
            .saturating_add(delay)
            .min(route.expires_at_ms.saturating_sub(1));
        if next_attempt_ms <= now_ms {
            return store.terminate_shard_forward_outbox(route.forward_id, "expired", now_ms);
        }
        return store.reschedule_shard_forward_outbox(route, attempts, next_attempt_ms);
    }
    if route.kind == ShardForwardOutboxKind::OwnerRelay {
        let Some(_target_snapshot) = store.mls_room_snapshot(route.target_child)? else {
            return store.terminate_shard_forward_outbox(
                route.forward_id,
                "target_missing",
                now_ms,
            );
        };
        let Some((target_state, _)) = store.mls_room_progress(route.target_child)? else {
            return store.terminate_shard_forward_outbox(
                route.forward_id,
                "target_missing",
                now_ms,
            );
        };
        let source_root = store.mls_logical_root(route.source_child)?;
        let target_root = store.mls_logical_root(route.target_child)?;
        if source_root != route.logical_root || target_root != route.logical_root {
            return store.terminate_shard_forward_outbox(
                route.forward_id,
                "logical_root_changed",
                now_ms,
            );
        }
        if target_state != "active" {
            return store.terminate_shard_forward_outbox(
                route.forward_id,
                "target_not_active",
                now_ms,
            );
        }
        let Some(owner) = store.group_access_owner(route.source_child)? else {
            return store.terminate_shard_forward_outbox(route.forward_id, "owner_missing", now_ms);
        };
        if owner == *local_peer {
            return store.terminate_shard_forward_outbox(
                route.forward_id,
                "owner_is_sender",
                now_ms,
            );
        }
        if !store.has_mls_sync_member(route.source_child, local_peer)?
            || !store.has_mls_sync_member(route.source_child, &owner)?
        {
            return store.terminate_shard_forward_outbox(
                route.forward_id,
                "owner_not_available",
                now_ms,
            );
        }
        let direct = admission.dispatch_prepared_loopback_mls_shard_forward(
            store,
            &packet,
            route.expires_at_ms,
            now_ms,
            |command| {
                if net.try_send(&command.into_ipc()?)? {
                    Ok(())
                } else {
                    Err(AslError::SandboxUnavailable)
                }
            },
        );
        if matches!(&direct, Ok(sent) if sent.queued > 0) {
            return store.complete_shard_forward_outbox(route.forward_id);
        }
        let error = direct.err().unwrap_or(AslError::NotFound);
        let terminal_reason = match &error {
            AslError::ExpiredMessage => Some("expired"),
            AslError::PolicyVersionConflict => Some("epoch_changed"),
            AslError::PolicyDenied => Some("policy_denied"),
            AslError::InvalidMessage => Some("invalid_frame"),
            AslError::IncompatibleVersion => Some("owner_incompatible"),
            _ => None,
        };
        if let Some(reason) = terminal_reason {
            return store.terminate_shard_forward_outbox(route.forward_id, reason, now_ms);
        }
        let attempts = entry.attempts.saturating_add(1);
        let delay = SHARD_FORWARD_OUTBOX_RETRY_BASE_MS
            .saturating_mul(1_u64 << attempts.min(7))
            .min(SHARD_FORWARD_OUTBOX_RETRY_MAX_MS);
        let next_attempt_ms = now_ms
            .saturating_add(delay)
            .min(route.expires_at_ms.saturating_sub(1));
        if next_attempt_ms <= now_ms {
            return store.terminate_shard_forward_outbox(route.forward_id, "expired", now_ms);
        }
        return store.reschedule_shard_forward_outbox(route, attempts, next_attempt_ms);
    }
    let Some(target_snapshot) = store.mls_room_snapshot(route.target_child)? else {
        return store.terminate_shard_forward_outbox(route.forward_id, "target_missing", now_ms);
    };
    let Some((state, _)) = store.mls_room_progress(route.target_child)? else {
        return store.terminate_shard_forward_outbox(route.forward_id, "target_missing", now_ms);
    };
    if state != "active" || packet.epoch != target_snapshot.version.mls_epoch {
        return store.terminate_shard_forward_outbox(
            route.forward_id,
            "target_epoch_changed",
            now_ms,
        );
    }
    let logical_root = match (
        store.mls_logical_root(route.source_child),
        store.mls_logical_root(route.target_child),
    ) {
        (Ok(source_root), Ok(target_root))
            if source_root == route.logical_root && target_root == route.logical_root =>
        {
            target_root
        }
        _ => {
            return store.terminate_shard_forward_outbox(
                route.forward_id,
                "logical_root_changed",
                now_ms,
            );
        }
    };
    if route.target_child == logical_root {
        if route.target_binding_revision != 0
            || store.mls_shard_parent(route.target_child)?.is_some()
        {
            return store.terminate_shard_forward_outbox(
                route.forward_id,
                "target_binding_changed",
                now_ms,
            );
        }
    } else {
        let Some(binding) = store.shard_binding(route.target_child, now_ms)? else {
            return store.terminate_shard_forward_outbox(
                route.forward_id,
                "target_binding_missing",
                now_ms,
            );
        };
        if binding.logical_root != route.logical_root
            || binding.revision != route.target_binding_revision
        {
            return store.terminate_shard_forward_outbox(
                route.forward_id,
                "target_binding_changed",
                now_ms,
            );
        }
    }
    if store.group_access_owner(logical_root)?.as_ref() != Some(local_peer)
        || !store.has_mls_sync_member(route.target_child, local_peer)?
    {
        return store.terminate_shard_forward_outbox(
            route.forward_id,
            "owner_not_available",
            now_ms,
        );
    }
    let direct = admission.dispatch_prepared_loopback_mls_shard_forward(
        store,
        &packet,
        route.expires_at_ms,
        now_ms,
        |command| {
            if net.try_send(&command.into_ipc()?)? {
                Ok(())
            } else {
                Err(AslError::SandboxUnavailable)
            }
        },
    );
    let _ =
        super::group_routing::publish_packet(net, store, route.target_child, local_peer, &packet);
    if matches!(&direct, Ok(sent) if sent.queued > 0) {
        return store.complete_shard_forward_outbox(route.forward_id);
    }
    let error = direct.err().unwrap_or(AslError::NotFound);
    let terminal_reason = match &error {
        AslError::ExpiredMessage => Some("expired"),
        AslError::PolicyVersionConflict => Some("target_epoch_changed"),
        AslError::PolicyDenied => Some("policy_denied"),
        AslError::InvalidMessage => Some("invalid_frame"),
        AslError::IncompatibleVersion => Some("target_incompatible"),
        _ => None,
    };
    if let Some(reason) = terminal_reason {
        return store.terminate_shard_forward_outbox(route.forward_id, reason, now_ms);
    }
    let attempts = entry.attempts.saturating_add(1);
    let delay = SHARD_FORWARD_OUTBOX_RETRY_BASE_MS
        .saturating_mul(1_u64 << attempts.min(7))
        .min(SHARD_FORWARD_OUTBOX_RETRY_MAX_MS);
    let next_attempt_ms = now_ms
        .saturating_add(delay)
        .min(route.expires_at_ms.saturating_sub(1));
    if next_attempt_ms <= now_ms {
        return store.terminate_shard_forward_outbox(route.forward_id, "expired", now_ms);
    }
    store.reschedule_shard_forward_outbox(route, attempts, next_attempt_ms)
}

fn local_mls_member_limit(store: &Store, now_ms: u64) -> Result<usize, AslError> {
    let profile = crate::capacity::latest_local_capacity(store)?;
    let measured = profile
        .as_ref()
        .filter(|profile| {
            crate::capacity::profile_readiness(Some(profile), now_ms)
                == crate::capacity::ProfileReadiness::Ready
        })
        .and_then(|profile| crate::capacity::profile_range(profile).ok())
        .and_then(|range| {
            range
                .extended_budget
                .or(range.direct_budget)
                .map(|range| range.max)
        })
        .unwrap_or(MAX_GROUP_MEMBERS);
    Ok(measured.clamp(1, MAX_GROUP_MEMBERS))
}

fn ensure_local_shard_binding(
    store: &mut Store,
    identity: &AgentIdentity,
    owner_peer: &PeerId,
    logical_root: Hash32,
    shard_index: u16,
    child: Hash32,
    now_ms: u64,
) -> Result<ShardBinding, AslError> {
    if store.group_access_owner(logical_root)?.as_ref() != Some(owner_peer)
        || store.mls_peer_agent(owner_peer)? != Some(identity.agent_id())
        || !store.has_mls_sync_member(logical_root, owner_peer)?
    {
        return Err(AslError::PolicyDenied);
    }
    if let Some(binding) = store.shard_binding(child, now_ms)?
        && binding.logical_root == logical_root
        && binding.shard_index == shard_index
        && binding.owner_agent == identity.agent_id()
        && &binding.owner_peer == owner_peer
    {
        return Ok(binding);
    }
    let root_snapshot = store
        .mls_room_snapshot(logical_root)?
        .ok_or(AslError::NotFound)?;
    let policy_revision = store
        .group_access_policy(&root_snapshot.local_id)?
        .revision
        .max(1);
    let revision = store
        .shard_binding_revision(child)?
        .map_or(policy_revision, |previous| {
            previous.saturating_add(1).max(policy_revision)
        });
    let mut binding = ShardBinding {
        message_id: Id128(fresh_id()?),
        logical_root,
        child,
        shard_index,
        owner_agent: identity.agent_id(),
        owner_peer: owner_peer.clone(),
        revision,
        issued_at_ms: now_ms,
        expires_at_ms: now_ms
            .checked_add(MAX_SHARD_BINDING_LIFETIME_MS)
            .ok_or(AslError::InvalidMessage)?,
        signature: Signature65([0; 65]),
    };
    binding.signature = identity.sign_domain_message(&binding.signing_preimage()?)?;
    store.store_shard_binding(&binding, owner_peer, now_ms)?;
    Ok(binding)
}

fn choose_or_create_mls_shard(
    admission: &mut CoreAdmission,
    store: &mut Store,
    identity: &AgentIdentity,
    root: Hash32,
    creator: &PeerId,
    recipient: &PeerId,
    now_ms: u64,
) -> Result<(Hash32, bool), AslError> {
    let member_limit = local_mls_member_limit(store, now_ms)?;
    match store.choose_mls_shard(root, creator, recipient, member_limit, now_ms) {
        Ok(room) => Ok((room, false)),
        Err(AslError::QuotaExceeded) => {
            let id = GroupId(Id128(fresh_id()?));
            let (room, _) = admission.create_local_mls_room_linked(
                store,
                identity,
                &id,
                "Group shard",
                now_ms,
                Some(root),
            )?;
            grant_act_budget(store, id.0, now_ms)?;
            let (_, shard_index) = store
                .mls_shard_parent(room)?
                .ok_or(AslError::InvalidPolicyState)?;
            ensure_local_shard_binding(store, identity, creator, root, shard_index, room, now_ms)?;
            Ok((room, true))
        }
        Err(error) => Err(error),
    }
}

fn group_operation_error_code(error: &AslError) -> &'static str {
    match error {
        AslError::PolicyDenied => "policy_denied",
        AslError::PolicyVersionConflict => "policy_version_conflict",
        AslError::QuotaExceeded => "quota_exceeded",
        AslError::NotFound => "not_found",
        AslError::SandboxUnavailable => "sandbox_unavailable",
        AslError::InvalidIdentity => "invalid_identity",
        _ => "unavailable",
    }
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

fn select_auto_reply_evidence(
    store: &Store,
    libraries: &crate::libraries::LocalLibraries,
    home: &Path,
    requester: &GroupRequester,
    act: &Act,
) -> Option<super::auto_reply_evidence::AutoReplyEvidenceContext> {
    let paths = AppPaths::open_existing(home).ok()?;
    let provider = ModelEndpointAccess::new(&paths)
        .first_authorized_config()
        .ok()
        .flatten()?;
    let provider_local = provider.mode == asl_agent::gateway::ProviderMode::Local;
    super::auto_reply_evidence::select_auto_reply_evidence(
        store,
        libraries,
        requester,
        provider.id,
        provider_local,
        act.nl_body.as_deref()?,
    )
    .ok()
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
    let snapshot = store
        .mls_room_snapshot(wire_id)?
        .ok_or(AslError::NotFound)?;
    if &owner == sender {
        store.apply_group_control(&snapshot.local_id, sender, control, now_ms)?;
    } else {
        store.apply_group_moderation(&snapshot.local_id, sender, control, now_ms)?;
    }
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
        "inviter": format!("agent:{}", hex::encode(invite.inviter.0)),
        "device": peer_text(&invite.inviter_device),
        "kind": if store.mls_room_progress(invite.wire_id)?.is_some() { "rejoin" } else { "join" },
        "base_epoch": invite.base_epoch,
        "expires_at_ms": invite.expires_at_ms
    }))
}

fn resource_budget_kind(kind: &str) -> Result<BudgetKind, AslError> {
    match kind {
        "message_bytes" => Ok(BudgetKind::MessageBytes),
        "model_calls" => Ok(BudgetKind::ModelCalls),
        "cpu_ms" => Ok(BudgetKind::CpuMs),
        "mailbox_bytes" => Ok(BudgetKind::MailboxBytes),
        _ => Err(AslError::InvalidMessage),
    }
}

fn kind_name(kind: BudgetKind) -> &'static str {
    match kind {
        BudgetKind::MessageBytes => "message_bytes",
        BudgetKind::ModelCalls => "model_calls",
        BudgetKind::CpuMs => "cpu_ms",
        BudgetKind::MailboxBytes => "mailbox_bytes",
    }
}

fn grant_act_budget(
    store: &mut Store,
    conversation_id: Id128,
    now_ms: u64,
) -> Result<(), AslError> {
    let now_raw = now_ms;
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
    if !matches!(inserted, MailboxPut::Inserted | MailboxPut::Duplicate) {
        return Err(AslError::InvalidPolicyState);
    }
    let expires_at_ms = now_raw
        .saturating_add(u64::try_from(MAX_BUDGET_WINDOW_MS).map_err(|_| AslError::InvalidMessage)?);
    let conversation = hex::encode(conversation_id.0);
    for (kind, granted) in [
        (BudgetKind::MessageBytes, DEFAULT_MESSAGE_BYTE_BUDGET),
        (BudgetKind::ModelCalls, DEFAULT_MODEL_CALL_BUDGET),
        (BudgetKind::CpuMs, DEFAULT_CPU_BUDGET_MS),
        (BudgetKind::MailboxBytes, DEFAULT_MAILBOX_BYTE_BUDGET),
    ] {
        store.grant_resource_budget(&conversation, kind, granted, expires_at_ms, now_raw)?;
    }
    Ok(())
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
