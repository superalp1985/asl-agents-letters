use super::{LocalGroupAction, NetworkAdmissionStatus, Supervisor, fresh_id};
use crate::agent_mail::GroupAccessUpdate;
use alloy_primitives::hex;
use asl_store::group_state::operator::{
    AdminCapacity, AdminJoinRequest, AdminOutcome, AdminPeer, AdminRequest, AdminRoom,
    AdminSnapshot, SNAPSHOT_WINDOW_MS,
};
use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId},
    protocol::{GroupAdminCapability, GroupFilePolicy},
};

const JOIN_REQUEST_VIEW_LIMIT: u32 = 100;
const PEER_VIEW_LIMIT: usize = 200;

impl Supervisor {
    pub(super) fn poll_group_operator(&mut self, now: u64) {
        let agent = self.agent_id();
        let Some(groups) = self.groups.as_mut() else {
            return;
        };
        let Ok(Some(ticket)) = groups
            .store
            .claim_group_admin(agent, &self.device_peer_id, now)
        else {
            return;
        };
        // Local storage transports requests; only the running Core owns the selectable view.
        let issued = groups.operator_view.take();
        let applied = self.apply_group_operator(&ticket.request, issued, now);
        #[cfg(test)]
        if let Err(error) = &applied {
            eprintln!("group operator failed: {error:?}");
        }
        let (outcome, view) = applied.unwrap_or((AdminOutcome::Failed, None));
        if let Some(groups) = &mut self.groups
            && groups
                .store
                .finish_group_admin(&ticket, outcome, view.as_ref(), now)
                .is_ok()
        {
            groups.operator_view = view;
        }
    }

    fn apply_group_operator(
        &mut self,
        request: &AdminRequest,
        issued: Option<AdminSnapshot>,
        now: u64,
    ) -> Result<(AdminOutcome, Option<AdminSnapshot>), AslError> {
        let groups = self.groups.as_ref().ok_or(AslError::PolicyDenied)?;
        if !self.net.is_running()
            || groups.store.network_pause_requested()?
            || self.network_admission_status != NetworkAdmissionStatus::Active
        {
            return Err(AslError::PolicyDenied);
        }
        let admission = self.admission.as_ref().ok_or(AslError::InvalidIdentity)?;
        let peers = || {
            admission
                .admitted_connections(now)
                .into_iter()
                .map(|(a, c, d)| peer_option(a, c, &d))
        };
        if let AdminRequest::RequestJoin { room, owner } = request {
            self.apply_local_group_action(
                LocalGroupAction::RequestJoin {
                    room: wire_id(room)?,
                    owner: agent_from_text(owner)?,
                },
                now,
            )?;
            return Ok((AdminOutcome::RequestJoinQueued, None));
        }
        if request == &AdminRequest::Refresh {
            let rooms = groups.store.managed_mls_rooms(&self.device_peer_id)?;
            let peers = peers().take(PEER_VIEW_LIMIT).collect::<Vec<_>>();
            let profile = crate::capacity::latest_local_capacity(&groups.store)?;
            let report = crate::capacity::report_capacity_observations(profile.as_ref(), now);
            let resources = asl_policy::local_resource_sample(&self.home).ok();
            let capacity =
                report
                    .measured_at_ms
                    .zip(report.member_range)
                    .map(|(measured_at_ms, range)| {
                        let direct = range.direct_budget.map_or(0, |range| range.max);
                        AdminCapacity {
                            measured_at_ms,
                            planner_direct_members: direct,
                            planner_extended_members: range
                                .extended_budget
                                .map_or(direct, |range| range.max),
                            fresh: report.readiness == crate::capacity::ProfileReadiness::Ready,
                            process_working_set_bytes: resources
                                .map(|sample| sample.working_set_bytes),
                            available_memory_bytes: resources
                                .map(|sample| sample.available_memory_bytes),
                            available_disk_bytes: resources
                                .map(|sample| sample.available_disk_bytes),
                        }
                    });
            let join_requests = groups
                .store
                .list_group_invite_requests(&self.device_peer_id, now, JOIN_REQUEST_VIEW_LIMIT)?
                .into_iter()
                .map(|request| {
                    let agent = bs58::encode(request.requester.as_bytes()).into_string();
                    let device = bs58::encode(request.device.as_bytes()).into_string();
                    let connection = peers
                        .iter()
                        .find(|peer| peer.agent == agent && peer.device == device)
                        .map(|peer| peer.connection.clone());
                    AdminJoinRequest {
                        room: hex::encode(request.wire_id.0),
                        agent,
                        device,
                        connection,
                        expires_ms: request.expires_at_ms,
                    }
                })
                .collect();
            return Ok((
                AdminOutcome::Ready,
                Some(AdminSnapshot {
                    tag: hex::encode(fresh_id()?),
                    rooms,
                    peers,
                    join_requests,
                    capacity,
                    expires_ms: now.saturating_add(SNAPSHOT_WINDOW_MS),
                }),
            ));
        }
        let issued = issued
            .filter(|v| v.permits_selection(request, now))
            .ok_or(AslError::PolicyVersionConflict)?;
        let (action, outcome) = match request {
            AdminRequest::Create { .. } => (LocalGroupAction::Create, AdminOutcome::Created),
            AdminRequest::Invite {
                room, connection, ..
            } => {
                let current_rooms = groups.store.managed_mls_rooms(&self.device_peer_id)?;
                let current_peers = peers();
                let action =
                    resolve_invite(&issued, room, connection, &current_rooms, current_peers)?;
                (action, AdminOutcome::InviteQueued)
            }
            AdminRequest::Remove { room, device, .. } => {
                let live = groups.store.managed_mls_rooms(&self.device_peer_id)?;
                let selected = current_room(&issued, room, &live)?;
                let member = selected
                    .members
                    .iter()
                    .find(|m| !m.creator && m.device == *device)
                    .ok_or(AslError::PolicyVersionConflict)?;
                let peer: libp2p_identity::PeerId = member
                    .device
                    .parse()
                    .map_err(|_| AslError::InvalidDatabase)?;
                let room = wire_id(&selected.room)?;
                let peer =
                    PeerId::from_bytes(peer.to_bytes()).map_err(|_| AslError::InvalidDatabase)?;
                let saved = groups
                    .store
                    .mls_room_for_reconciliation(room)?
                    .ok_or(AslError::NotFound)?;
                if saved.creator == self.device_peer_id {
                    (
                        LocalGroupAction::Remove { room, peer },
                        AdminOutcome::MemberRemoved,
                    )
                } else {
                    (
                        LocalGroupAction::ProposeRemove { room, peer },
                        AdminOutcome::RemovalRequested,
                    )
                }
            }
            AdminRequest::ReviewRemoval {
                room,
                request,
                approve,
                ..
            } => {
                let mut id = [0; 16];
                hex::decode_to_slice(request, &mut id).map_err(|_| AslError::InvalidMessage)?;
                (
                    LocalGroupAction::ReviewRemoval {
                        room: wire_id(room)?,
                        request: Id128(id),
                        approve: *approve,
                    },
                    if *approve {
                        AdminOutcome::MemberRemoved
                    } else {
                        AdminOutcome::RemovalRejected
                    },
                )
            }
            AdminRequest::RejectJoinRequest { room, device, .. } => {
                let live = groups.store.managed_mls_rooms(&self.device_peer_id)?;
                let selected = current_room(&issued, room, &live)?;
                (
                    LocalGroupAction::RejectJoinRequest {
                        room: wire_id(&selected.room)?,
                        device: peer_from_text(device)?,
                    },
                    AdminOutcome::JoinRequestRejected,
                )
            }
            AdminRequest::SetAccess {
                room,
                policy_revision,
                allow_member_text,
                allow_member_files,
                allow_member_invite,
                admins,
                muted,
                details,
                ..
            } => {
                let live = groups.store.managed_mls_rooms(&self.device_peer_id)?;
                let selected = current_room(&issued, room, &live)?;
                if selected.policy_revision != *policy_revision {
                    return Err(AslError::PolicyVersionConflict);
                }
                let mut admins = admins
                    .iter()
                    .map(|peer| peer_from_text(peer))
                    .collect::<Result<Vec<_>, _>>()?;
                admins.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
                admins.dedup();
                let mut muted = muted
                    .iter()
                    .map(|peer| peer_from_text(peer))
                    .collect::<Result<Vec<_>, _>>()?;
                muted.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
                muted.dedup();
                let owner = details
                    .as_ref()
                    .and_then(|details| details.owner.as_deref())
                    .map(peer_from_text)
                    .transpose()?;
                let file_policies = details
                    .as_ref()
                    .map(|details| {
                        details
                            .file_policies
                            .iter()
                            .map(|policy| {
                                Ok(GroupFilePolicy {
                                    content_id: wire_id(&policy.content_id)?,
                                    permissions: policy.permissions,
                                })
                            })
                            .collect::<Result<Vec<_>, AslError>>()
                    })
                    .transpose()?;
                let admin_capabilities = details
                    .as_ref()
                    .map(|details| {
                        details
                            .admin_capabilities
                            .iter()
                            .map(|capability| {
                                Ok(GroupAdminCapability {
                                    peer: peer_from_text(&capability.peer)?,
                                    capabilities: capability.capabilities,
                                })
                            })
                            .collect::<Result<Vec<_>, AslError>>()
                    })
                    .transpose()?;
                (
                    LocalGroupAction::SetAccess {
                        room: wire_id(&selected.room)?,
                        update: GroupAccessUpdate {
                            allow_member_text: *allow_member_text,
                            allow_member_files: *allow_member_files,
                            allow_member_invite: *allow_member_invite,
                            admins,
                            muted,
                            owner,
                            file_policies,
                            admin_capabilities,
                        },
                    },
                    AdminOutcome::AccessUpdated,
                )
            }
            AdminRequest::RenewResourceBudget {
                room,
                kind,
                additional,
                window_hours,
                ..
            } => {
                let live = groups.store.managed_mls_rooms(&self.device_peer_id)?;
                let selected = current_room(&issued, room, &live)?;
                (
                    LocalGroupAction::RenewResourceBudget {
                        room: wire_id(&selected.room)?,
                        kind: kind.clone(),
                        additional: *additional,
                        window_hours: *window_hours,
                    },
                    AdminOutcome::BudgetUpdated,
                )
            }
            AdminRequest::Refresh => unreachable!(),
            AdminRequest::RequestJoin { .. } => unreachable!(),
        };
        let applied = self.apply_local_group_action(action, now)?;
        let outcome = if outcome == AdminOutcome::AccessUpdated {
            match applied.get("state").and_then(serde_json::Value::as_str) {
                Some("partial") => AdminOutcome::AccessPartiallyUpdated,
                Some("blocked_owner_transfer") => AdminOutcome::OwnerTransferBlocked,
                _ => outcome,
            }
        } else if outcome == AdminOutcome::InviteQueued
            && applied.get("state").and_then(serde_json::Value::as_str)
                == Some("owner_action_required")
        {
            AdminOutcome::InviteOwnerRequired
        } else {
            outcome
        };
        Ok((outcome, None))
    }
}

fn peer_option(agent: AgentId, connection: [u8; 16], device: &PeerId) -> AdminPeer {
    AdminPeer {
        agent: bs58::encode(agent.as_bytes()).into_string(),
        device: bs58::encode(device.as_bytes()).into_string(),
        connection: hex::encode(connection),
    }
}

fn resolve_invite(
    issued: &AdminSnapshot,
    room: &str,
    connection: &str,
    current_rooms: &[AdminRoom],
    mut current_peers: impl Iterator<Item = AdminPeer>,
) -> Result<LocalGroupAction, AslError> {
    let room = current_room(issued, room, current_rooms)?;
    let peer = issued
        .peers
        .iter()
        .find(|p| p.connection == connection)
        .filter(|p| current_peers.any(|live| &live == *p))
        .ok_or(AslError::NotFound)?;
    let mut conn = [0; 16];
    hex::decode_to_slice(&peer.connection, &mut conn).map_err(|_| AslError::InvalidDatabase)?;
    Ok(LocalGroupAction::Invite {
        room: wire_id(&room.room)?,
        connection_id: conn,
    })
}

fn current_room<'a>(
    issued: &'a AdminSnapshot,
    room: &str,
    live: &[AdminRoom],
) -> Result<&'a AdminRoom, AslError> {
    issued
        .rooms
        .iter()
        .find(|r| {
            r.room == room
                && live.iter().any(|current| {
                    current.room == r.room
                        && current.epoch == r.epoch
                        && current.membership_epoch == r.membership_epoch
                        && current.policy_revision == r.policy_revision
                        && current.members == r.members
                        && current.file_policies == r.file_policies
                        && current.admin_capabilities == r.admin_capabilities
                })
        })
        .ok_or(AslError::PolicyVersionConflict)
}

fn wire_id(text: &str) -> Result<Hash32, AslError> {
    let mut wire = [0; 32];
    hex::decode_to_slice(text, &mut wire).map_err(|_| AslError::InvalidDatabase)?;
    Ok(Hash32(wire))
}

fn peer_from_text(text: &str) -> Result<PeerId, AslError> {
    let peer: libp2p_identity::PeerId = text.parse().map_err(|_| AslError::InvalidDatabase)?;
    PeerId::from_bytes(peer.to_bytes()).map_err(|_| AslError::InvalidDatabase)
}

fn agent_from_text(text: &str) -> Result<AgentId, AslError> {
    let bytes = bs58::decode(text)
        .into_vec()
        .map_err(|_| AslError::InvalidDatabase)?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| AslError::InvalidDatabase)?;
    Ok(AgentId(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_admin_never_retargets_a_changed_device_connection_or_epoch() {
        let room = AdminRoom {
            room: hex::encode([1; 32]),
            name: "Group".into(),
            epoch: 4,
            membership_epoch: 8,
            policy_revision: 1,
            allow_member_text: true,
            allow_member_files: true,
            allow_member_invite: false,
            members: vec![],
            budgets: vec![],
            file_policies: vec![],
            admin_capabilities: vec![],
            removal_requests: vec![],
        };
        let peer = AdminPeer {
            agent: "agent".into(),
            device: "device".into(),
            connection: hex::encode([2; 16]),
        };
        let view = AdminSnapshot {
            tag: "view".into(),
            rooms: vec![room.clone()],
            peers: vec![peer.clone()],
            join_requests: vec![],
            capacity: None,
            expires_ms: 30,
        };
        let resolve = |r: &AdminRoom, p: Option<AdminPeer>| {
            resolve_invite(
                &view,
                &room.room,
                &peer.connection,
                std::slice::from_ref(r),
                p.into_iter(),
            )
        };
        assert!(resolve(&room, Some(peer.clone())).is_ok());
        assert!(resolve(&room, None).is_err());
        for replaced in [
            AdminPeer {
                device: "replacement".into(),
                ..peer.clone()
            },
            AdminPeer {
                connection: hex::encode([3; 16]),
                ..peer.clone()
            },
            AdminPeer {
                agent: "new identity".into(),
                ..peer.clone()
            },
        ] {
            assert!(resolve(&room, Some(replaced)).is_err());
        }
        assert!(
            resolve(
                &AdminRoom {
                    membership_epoch: 9,
                    ..room.clone()
                },
                Some(peer.clone())
            )
            .is_err()
        );
        assert!(
            resolve(
                &AdminRoom {
                    epoch: 5,
                    ..room.clone()
                },
                Some(peer.clone())
            )
            .is_err()
        );
    }
}
