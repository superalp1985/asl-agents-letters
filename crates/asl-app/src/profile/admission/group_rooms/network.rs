use std::{collections::HashMap, time::Instant};

use asl_groups::GroupApplication;
use asl_net::transport::REQUEST_TIMEOUT;
use asl_store::{
    Store,
    group_state::{MlsIncomingInvite, RoomVersion},
};
use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId},
    protocol::{GroupBody, GroupMembership, GroupPacket},
    task::GroupId,
};

use super::{ApprovedMlsWelcome, CoreAdmission, sync::SyncClock};
use crate::{
    network::{NetworkCommand, NetworkEvent},
    profile::admission::fresh_id,
};

const MAX_PENDING_JOINS: usize = 5;

pub struct MlsInviteSend {
    pub connection_id: [u8; 16],
    pub wire_id: Hash32,
    pub expires_at_ms: u64,
}

pub struct MlsJoinSend<'a> {
    pub connection_id: [u8; 16],
    pub invite: &'a MlsIncomingInvite,
    pub local_id: &'a GroupId,
    pub local_name: &'a str,
}

#[derive(Debug, Eq, PartialEq)]
pub enum MlsNetworkOutcome {
    InviteForApproval(MlsIncomingInvite),
    Joined {
        local_id: GroupId,
        version: RoomVersion,
    },
    SyncAdvanced {
        wire_id: Hash32,
        version: RoomVersion,
    },
    SyncHead {
        wire_id: Hash32,
        version: RoomVersion,
    },
    SyncStopped {
        wire_id: Hash32,
    },
    ApplicationReceived {
        wire_id: Hash32,
        epoch: u64,
        sender: PeerId,
        application: Box<GroupApplication>,
    },
}

#[derive(Default)]
pub(in crate::profile::admission) struct MlsJoinAttempts {
    pending: HashMap<[u8; 16], PendingJoin>,
}

struct PendingJoin {
    connection_id: [u8; 16],
    invite: MlsIncomingInvite,
    request: GroupPacket,
    local_id: GroupId,
    local_name: String,
    rejoin_base: Option<RoomVersion>,
    expires_at_ms: u64,
    deadline: Instant,
}

impl MlsJoinAttempts {
    pub(in crate::profile::admission) fn expire(&mut self, now_ms: u64) {
        let now = Instant::now();
        self.pending
            .retain(|_, attempt| now_ms < attempt.expires_at_ms && now < attempt.deadline);
    }

    pub(in crate::profile::admission) fn disconnect(&mut self, connection_id: [u8; 16]) {
        self.pending
            .retain(|_, attempt| attempt.connection_id != connection_id);
    }

    pub(in crate::profile::admission) fn fail(
        &mut self,
        connection_id: [u8; 16],
        request_handle: [u8; 16],
    ) {
        if self
            .pending
            .get(&request_handle)
            .is_some_and(|attempt| attempt.connection_id == connection_id)
        {
            self.pending.remove(&request_handle);
        }
    }
}

impl CoreAdmission {
    /// Local diagnostics may identify an invitation only for a live attempt
    /// on the same IPC handle and authenticated connection.
    pub(crate) fn mls_reply_invite(&mut self, event: &NetworkEvent, now_ms: u64) -> Option<Id128> {
        let NetworkEvent::UnverifiedGroupResponse {
            connection_id,
            request_handle,
            ..
        } = event
        else {
            return None;
        };
        self.mls_joins.expire(now_ms);
        let attempt = self.mls_joins.pending.get(request_handle)?;
        (attempt.connection_id == *connection_id).then_some(attempt.invite.id)
    }

    /// Persist a targeted invitation and enqueue it on the exact admitted
    /// connection. This entry point is for trusted Core callers only.
    pub fn send_targeted_mls_invite(
        &mut self,
        store: &mut Store,
        send: MlsInviteSend,
        directories: &HashMap<AgentId, Vec<u8>>,
        now_ms: u64,
        enqueue: impl FnOnce(NetworkCommand) -> Result<(), AslError>,
    ) -> Result<(), AslError> {
        let request = self.issue_targeted_mls_invite(
            store,
            send.connection_id,
            send.wire_id,
            send.expires_at_ms,
            directories,
            now_ms,
        )?;
        self.admitted_peer_identity(send.connection_id, now_ms)?;
        let GroupBody::Membership(GroupMembership::Invite { expires_at_ms, .. }) = &request.body
        else {
            return Err(AslError::InvalidPolicyState);
        };
        enqueue(NetworkCommand::SendGroup {
            connection_id: send.connection_id,
            request_handle: fresh_id()?,
            deadline_ms: queue_deadline(now_ms, *expires_at_ms),
            request,
        })
    }

    /// Track a Welcome only once the Core-to-Net enqueue succeeds. This
    /// never generates an approval, and an approved package is not a send.
    pub fn send_approved_mls_join(
        &mut self,
        store: &mut Store,
        send: MlsJoinSend<'_>,
        directories: &HashMap<AgentId, Vec<u8>>,
        now_ms: u64,
        enqueue: impl FnOnce(NetworkCommand) -> Result<(), AslError>,
    ) -> Result<[u8; 16], AslError> {
        self.mls_joins.expire(now_ms);
        if self.mls_joins.pending.len() >= MAX_PENDING_JOINS
            || self
                .mls_joins
                .pending
                .values()
                .any(|attempt| attempt.invite.wire_id == send.invite.wire_id)
        {
            return Err(AslError::QuotaExceeded);
        }
        let request = self.prepare_approved_mls_join(
            store,
            send.connection_id,
            send.invite,
            directories,
            now_ms,
        )?;
        // Take the old snapshot version before sending. A Welcome cannot
        // switch a new join into a rejoin or overwrite a concurrent advance.
        let (local_id, rejoin_base) = match store.mls_room_snapshot(send.invite.wire_id)? {
            Some(saved) if send.invite.base_epoch > saved.version.mls_epoch => {
                (saved.local_id, Some(saved.version))
            }
            Some(_) => return Err(AslError::PolicyVersionConflict),
            None => (send.local_id.clone(), None),
        };
        let request_handle = fresh_id()?;
        if self.mls_joins.pending.contains_key(&request_handle) {
            return Err(AslError::QuotaExceeded);
        }
        let deadline = Instant::now() + REQUEST_TIMEOUT;
        let deadline_ms = queue_deadline(now_ms, send.invite.expires_at_ms);
        enqueue(NetworkCommand::SendGroup {
            connection_id: send.connection_id,
            request_handle,
            deadline_ms,
            request: request.clone(),
        })?;
        self.mls_joins.pending.insert(
            request_handle,
            PendingJoin {
                connection_id: send.connection_id,
                invite: send.invite.clone(),
                request,
                local_id,
                local_name: send.local_name.to_owned(),
                rejoin_base,
                expires_at_ms: deadline_ms,
                deadline,
            },
        );
        Ok(request_handle)
    }

    /// Handle group-only events on the trusted Core/Net path. Callers
    /// still pass disconnect and request failure through `handle_event`.
    /// Generic Agent handlers never receive the raw packets or send handle.
    pub fn handle_mls_network_event(
        &mut self,
        store: &mut Store,
        event: NetworkEvent,
        directories: &HashMap<AgentId, Vec<u8>>,
        now_ms: u64,
        enqueue: impl FnOnce(NetworkCommand) -> Result<(), AslError>,
    ) -> Result<Option<MlsNetworkOutcome>, AslError> {
        let started = Instant::now();
        self.mls_joins.expire(now_ms);
        match event {
            NetworkEvent::UnverifiedGroupRequest {
                connection_id,
                response_id,
                deadline_ms,
                request,
            } => {
                if now_ms >= deadline_ms {
                    return Err(AslError::ExpiredMessage);
                }
                if matches!(&request.body, GroupBody::Application(_)) {
                    let (sender, application) = self.receive_loopback_mls_application(
                        store,
                        connection_id,
                        &request,
                        deadline_ms,
                        now_ms,
                    )?;
                    let response = GroupPacket {
                        body: GroupBody::Membership(GroupMembership::Receipt),
                        ..request
                    };
                    let outcome = MlsNetworkOutcome::ApplicationReceived {
                        wire_id: response.group_id,
                        epoch: response.epoch,
                        sender,
                        application: Box::new(application),
                    };
                    // The event is committed even if the receipt cannot be queued.
                    let _ = enqueue(NetworkCommand::ReplyGroup {
                        connection_id,
                        response_id,
                        response,
                    });
                    return Ok(Some(outcome));
                }
                if matches!(
                    &request.body,
                    GroupBody::Membership(GroupMembership::SyncRequest { .. })
                ) {
                    let clock = SyncClock::inbound(now_ms, deadline_ms);
                    let response = self.serve_mls_sync_step(
                        store,
                        connection_id,
                        &request,
                        directories,
                        &clock,
                    )?;
                    self.admitted_peer_identity(connection_id, clock.now_ms()?)?;
                    enqueue(NetworkCommand::ReplyGroup {
                        connection_id,
                        response_id,
                        response,
                    })?;
                    return Ok(None);
                }
                let (response, outcome) = match &request.body {
                    GroupBody::Membership(GroupMembership::Invite { .. }) => {
                        let invite = self.receive_targeted_mls_invite(
                            store,
                            connection_id,
                            &request,
                            directories,
                            now_ms,
                        )?;
                        let receipt = GroupPacket {
                            body: GroupBody::Membership(GroupMembership::Receipt),
                            ..request
                        };
                        (receipt, invite.map(MlsNetworkOutcome::InviteForApproval))
                    }
                    GroupBody::Membership(GroupMembership::KeyPackage { .. }) => (
                        self.answer_mls_key_package(
                            store,
                            connection_id,
                            &request,
                            directories,
                            now_ms,
                        )?,
                        None,
                    ),
                    // Standalone membership updates are not accepted.
                    _ => return Err(AslError::PolicyDenied),
                };
                self.admitted_peer_identity(connection_id, now_ms)?;
                let sent = enqueue(NetworkCommand::ReplyGroup {
                    connection_id,
                    response_id,
                    response,
                });
                // An already-durable prompt must still be surfaced if the
                // receipt cannot be queued: retry will not create it again.
                if outcome.is_none() {
                    sent?;
                }
                Ok(outcome)
            }
            NetworkEvent::UnverifiedGroupResponse {
                connection_id,
                request_handle,
                response,
            } => {
                if matches!(
                    &response.body,
                    GroupBody::Membership(
                        GroupMembership::SyncCommit(_)
                            | GroupMembership::AtHead { .. }
                            | GroupMembership::SyncUnavailable
                    )
                ) {
                    return self.receive_mls_sync_reply(
                        store,
                        connection_id,
                        request_handle,
                        &response,
                        directories,
                        now_ms,
                    );
                }
                let Some(attempt) = self.mls_joins.pending.get(&request_handle) else {
                    return Ok(None);
                };
                if attempt.connection_id != connection_id {
                    return Ok(None);
                }
                attempt.request.match_reply(&response)?;
                let attempt = self
                    .mls_joins
                    .pending
                    .remove(&request_handle)
                    .ok_or(AslError::InvalidPolicyState)?;
                let clock =
                    SyncClock::response(now_ms, started, attempt.expires_at_ms, attempt.deadline);
                let version = self.finish_approved_mls_welcome(
                    store,
                    ApprovedMlsWelcome {
                        connection_id,
                        invite: &attempt.invite,
                        reply: &response,
                        local_id: &attempt.local_id,
                        local_name: &attempt.local_name,
                        rejoin_base: attempt.rejoin_base,
                        directories,
                    },
                    &clock,
                )?;
                if attempt.rejoin_base.is_some() {
                    self.mls_sync.forget_room(response.group_id);
                }
                Ok(Some(MlsNetworkOutcome::Joined {
                    local_id: attempt.local_id,
                    version,
                }))
            }
            _ => Err(AslError::InvalidMessage),
        }
    }
}

fn queue_deadline(now_ms: u64, expiry: u64) -> u64 {
    expiry.min(now_ms.saturating_add(REQUEST_TIMEOUT.as_millis() as u64))
}
