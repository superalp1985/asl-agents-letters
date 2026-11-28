use std::collections::HashMap;

use asl_groups::{
    GroupApplication, encrypt_application,
    local_state::{RoomBinding, seal_with_history},
    open_application, open_application_with_sender,
};
use asl_net::transport::REQUEST_TIMEOUT;
use asl_store::{
    Store,
    group_state::{
        MlsApplicationAuthority, MlsJournalEntry, MlsJournalKind, MlsMemberEvidence, MlsRoomUpdate,
        RoomVersion, ShardForwardOutboxKind, ShardForwardOutboxRecord, ShardForwardOutboxRoute,
    },
};
use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId},
    protocol::{
        GroupBody, GroupPacket, MAX_SHARD_FORWARD_LIFETIME_MS, ShardForward, WireFrame,
        encode_frame,
    },
};
use openmls::prelude::CredentialWithKey;

use super::{CoreAdmission, LocalRoomCandidate, sync::SyncClock};
use crate::profile::{admission::fresh_id, group_credential};

pub struct MlsApplicationReceive<'a> {
    pub connection_id: [u8; 16],
    pub expected: RoomVersion,
    pub packet: &'a GroupPacket,
    pub deadline_ms: u64,
}

struct ApplicationSource<'a> {
    kind: &'static str,
    connection_id: [u8; 16],
    key: &'a CredentialWithKey,
    device: &'a PeerId,
}

enum ApplicationOrigin<'a> {
    Direct(ApplicationSource<'a>),
    Roster {
        kind: &'static str,
        key: &'a CredentialWithKey,
        member: &'a MlsMemberEvidence,
    },
}

impl<'a> ApplicationOrigin<'a> {
    fn kind(&self) -> &'static str {
        match self {
            Self::Direct(source) => source.kind,
            Self::Roster { kind, .. } => kind,
        }
    }

    fn device(&self) -> &PeerId {
        match self {
            Self::Direct(source) => source.device,
            Self::Roster { member, .. } => &member.certificate.peer_id,
        }
    }
}

impl CoreAdmission {
    /// Prepare ciphertext for an explicitly selected local snapshot. This
    /// performs no network I/O and does not establish current group authority.
    pub fn commit_mls_application_send(
        &mut self,
        store: &mut Store,
        wire_id: Hash32,
        expected: RoomVersion,
        application: GroupApplication,
        directories: &HashMap<AgentId, Vec<u8>>,
        now_ms: u64,
    ) -> Result<GroupPacket, AslError> {
        let (created, expires) = application_times(&application);
        let clock = SyncClock::inbound(
            now_ms,
            expires.min(now_ms.saturating_add(REQUEST_TIMEOUT.as_millis() as u64)),
        );
        let time = clock.now_ms()?;
        check_application_creation(created, time)?;
        let mut candidate =
            self.load_mls_application_base(store, wire_id, expected, directories, time)?;
        self.prepare_mls_application(
            store,
            &mut candidate,
            Id128(fresh_id()?),
            application,
            &clock,
        )
        .map(|(packet, _)| packet)
    }

    /// Prepare and durably enqueue one already-signed shard forward in the
    /// same transaction that advances the target shard ratchet. The outbox
    /// contains only the encoded MLS control frame and routing metadata.
    pub fn prepare_mls_shard_forward(
        &mut self,
        store: &mut Store,
        wire_id: Hash32,
        forward: ShardForward,
        now_ms: u64,
    ) -> Result<GroupPacket, AslError> {
        self.prepare_mls_routed_shard_forward(
            store,
            wire_id,
            forward,
            ShardForwardOutboxKind::Forward,
            None,
            None,
            now_ms,
        )
    }

    pub fn prepare_mls_owner_reply_forward(
        &mut self,
        store: &mut Store,
        wire_id: Hash32,
        forward: ShardForward,
        target_peer: &PeerId,
        content_id: Hash32,
        now_ms: u64,
    ) -> Result<GroupPacket, AslError> {
        self.prepare_mls_routed_shard_forward(
            store,
            wire_id,
            forward,
            ShardForwardOutboxKind::OwnerReply,
            Some(content_id),
            Some(target_peer),
            now_ms,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_mls_routed_shard_forward(
        &mut self,
        store: &mut Store,
        wire_id: Hash32,
        forward: ShardForward,
        kind: ShardForwardOutboxKind,
        content_id: Option<Hash32>,
        target_peer: Option<&PeerId>,
        now_ms: u64,
    ) -> Result<GroupPacket, AslError> {
        if forward.target_child != wire_id {
            return Err(AslError::InvalidMessage);
        }
        let (created, expires) = (Some(forward.observed_at_ms), forward.expires_at_ms);
        let clock = SyncClock::inbound(
            now_ms,
            expires.min(now_ms.saturating_add(REQUEST_TIMEOUT.as_millis() as u64)),
        );
        let now = clock.now_ms()?;
        check_application_creation(created, now)?;
        forward.validate_at(now)?;
        let saved = store
            .mls_room_snapshot(wire_id)?
            .ok_or(AslError::NotFound)?;
        let (state, _) = store
            .mls_room_progress(wire_id)?
            .ok_or(AslError::NotFound)?;
        if state != "active" {
            return Err(AslError::PolicyDenied);
        }
        if wire_id != forward.logical_root {
            let binding = store
                .shard_binding(wire_id, now)?
                .ok_or(AslError::PolicyDenied)?;
            if forward.target_binding.as_ref() != Some(&binding)
                || binding.logical_root != forward.logical_root
            {
                return Err(AslError::PolicyVersionConflict);
            }
        } else if forward.target_binding.is_some() || store.mls_shard_parent(wire_id)?.is_some() {
            return Err(AslError::InvalidMessage);
        }
        let route = ShardForwardOutboxRoute {
            kind,
            content_id,
            target_peer: target_peer.cloned(),
            forward_id: forward.message_id,
            source_message_id: forward.source_message_id,
            logical_root: forward.logical_root,
            source_child: forward.source_child,
            target_child: forward.target_child,
            target_binding_revision: forward
                .target_binding
                .as_ref()
                .map_or(0, |binding| binding.revision),
            observed_at_ms: forward.observed_at_ms,
            expires_at_ms: forward.expires_at_ms,
        };
        let mut candidate =
            self.load_mls_application_base(store, wire_id, saved.version, &HashMap::new(), now)?;
        self.prepare_mls_application_inner(
            store,
            &mut candidate,
            Id128(fresh_id()?),
            GroupApplication::ShardForward(Box::new(forward)),
            &clock,
            Some(&route),
        )
        .map(|(packet, _)| packet)
    }

    /// Prepare a Fetch control frame that must first reach the current logical
    /// owner. The exact encrypted frame is persisted before any transport I/O,
    /// so a temporary owner outage can be retried without advancing the MLS
    /// sender ratchet again.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_mls_owner_relay_application(
        &mut self,
        store: &mut Store,
        wire_id: Hash32,
        expected: RoomVersion,
        application: GroupApplication,
        logical_root: Hash32,
        target_child: Hash32,
        now_ms: u64,
    ) -> Result<(GroupPacket, Id128), AslError> {
        if !matches!(application, GroupApplication::FetchRequest(_)) || target_child == wire_id {
            return Err(AslError::InvalidMessage);
        }
        let saved = store
            .mls_room_snapshot(wire_id)?
            .ok_or(AslError::NotFound)?;
        let (state, _) = store
            .mls_room_progress(wire_id)?
            .ok_or(AslError::NotFound)?;
        if state != "active" || saved.version != expected {
            return Err(AslError::PolicyVersionConflict);
        }
        if store.mls_logical_root(wire_id)? != logical_root
            || store.mls_logical_root(target_child)? != logical_root
        {
            return Err(AslError::PolicyDenied);
        }
        let content_id = match &application {
            GroupApplication::FetchRequest(request) => request.content_id,
            _ => return Err(AslError::InvalidMessage),
        };
        let expires_at_ms = now_ms
            .checked_add(MAX_SHARD_FORWARD_LIFETIME_MS)
            .ok_or(AslError::InvalidMessage)?;
        let route = ShardForwardOutboxRoute {
            kind: ShardForwardOutboxKind::OwnerRelay,
            content_id: Some(content_id),
            target_peer: None,
            forward_id: Id128(fresh_id()?),
            source_message_id: application.message_id(),
            logical_root,
            source_child: wire_id,
            target_child,
            target_binding_revision: 0,
            observed_at_ms: now_ms,
            expires_at_ms,
        };
        let clock = SyncClock::inbound(now_ms, expires_at_ms);
        let mut candidate =
            self.load_mls_application_base(store, wire_id, expected, &HashMap::new(), now_ms)?;
        let outbox_id = route.forward_id;
        self.prepare_mls_application_inner(
            store,
            &mut candidate,
            Id128(fresh_id()?),
            application,
            &clock,
            Some(&route),
        )
        .map(|(packet, _)| (packet, outbox_id))
    }

    pub(super) fn prepare_mls_application(
        &mut self,
        store: &mut Store,
        candidate: &mut LocalRoomCandidate,
        envelope_id: Id128,
        application: GroupApplication,
        clock: &SyncClock,
    ) -> Result<(GroupPacket, RoomVersion), AslError> {
        self.prepare_mls_application_inner(store, candidate, envelope_id, application, clock, None)
    }

    fn prepare_mls_application_inner(
        &mut self,
        store: &mut Store,
        candidate: &mut LocalRoomCandidate,
        envelope_id: Id128,
        application: GroupApplication,
        clock: &SyncClock,
        outbox_route: Option<&ShardForwardOutboxRoute>,
    ) -> Result<(GroupPacket, RoomVersion), AslError> {
        let (created, _) = application_times(&application);
        check_application_creation(created, clock.now_ms()?)?;
        let message_id = application.message_id();
        let packet = encrypt_application(
            &mut candidate.base.group,
            &candidate.base.provider,
            &candidate.base.signer,
            envelope_id,
            application,
        )?;
        let outbox = match outbox_route {
            Some(route) => Some(ShardForwardOutboxRecord {
                route: route.clone(),
                frame: encode_frame(&WireFrame::GroupEnvelope(packet.clone().into_envelope()?))?,
            }),
            None => None,
        };
        let (version, _) = self.persist_mls_application(
            store,
            candidate,
            &packet,
            message_id,
            None,
            outbox.as_ref(),
            || clock.now_ms(),
        )?;
        Ok((packet, version))
    }

    /// Return structured plaintext only after the receive ratchet and replay
    /// record commit. `None` means an expression was received while local
    /// browsing was disabled. Callers still establish group freshness.
    pub fn commit_mls_application_receive(
        &mut self,
        store: &mut Store,
        receive: MlsApplicationReceive<'_>,
        directories: &HashMap<AgentId, Vec<u8>>,
        now_ms: u64,
    ) -> Result<Option<GroupApplication>, AslError> {
        let clock = SyncClock::inbound(now_ms, receive.deadline_ms);
        self.apply_mls_application(store, receive, directories, &clock)
    }

    pub(super) fn apply_mls_application(
        &mut self,
        store: &mut Store,
        receive: MlsApplicationReceive<'_>,
        directories: &HashMap<AgentId, Vec<u8>>,
        clock: &SyncClock,
    ) -> Result<Option<GroupApplication>, AslError> {
        let packet = receive.packet;
        let now = clock.now_ms()?;
        packet.validate_request()?;
        if !matches!(packet.body, GroupBody::Application(_))
            || packet.epoch != receive.expected.mls_epoch
        {
            return Err(AslError::InvalidMessage);
        }
        let (agent, peer) = self.admitted_peer_identity(receive.connection_id, now)?;
        let mut candidate = self.load_mls_application_base(
            store,
            packet.group_id,
            receive.expected,
            directories,
            now,
        )?;
        let sender = candidate
            .leaves
            .iter()
            .find(|leaf| leaf.certificate.peer_id == peer && leaf.certificate.agent_id == agent)
            .filter(|leaf| leaf.member.index != candidate.group.own_leaf_index())
            .ok_or(AslError::PolicyDenied)?;
        let sender_key = CredentialWithKey::from(&sender.member);
        let sender_index = sender.member.index;
        self.verify_admitted_group_leaf(receive.connection_id, packet.group_id, &sender_key, now)?;
        let application = open_application(
            &mut candidate.base.group,
            &candidate.base.provider,
            sender_index,
            packet,
        )?;
        if matches!(application, GroupApplication::Expression(_))
            && !self.peer_supports_expression(receive.connection_id)
        {
            return Err(AslError::IncompatibleVersion);
        }
        if matches!(application, GroupApplication::Act(_))
            && !self.peer_supports_act(receive.connection_id)
        {
            return Err(AslError::IncompatibleVersion);
        }
        if matches!(
            application,
            GroupApplication::ShardBinding(_) | GroupApplication::ShardForward(_)
        ) && !self.peer_supports_shard_forward(receive.connection_id)
        {
            return Err(AslError::IncompatibleVersion);
        }
        let (created, expires) = application_times(&application);
        check_application_creation(created, clock.now_ms()?)?;
        let (_, browse_enabled) = self.persist_mls_application(
            store,
            &candidate,
            packet,
            application.message_id(),
            Some(ApplicationOrigin::Direct(ApplicationSource {
                kind: application.kind(),
                connection_id: receive.connection_id,
                key: &sender_key,
                device: &peer,
            })),
            None,
            || {
                let now = clock.now_ms()?;
                if now >= expires {
                    return Err(AslError::ExpiredMessage);
                }
                Ok(now)
            },
        )?;
        Ok((!matches!(
            application,
            GroupApplication::Expression(_) | GroupApplication::Act(_)
        ) || browse_enabled)
            .then_some(application))
    }

    pub fn apply_mls_gossip(
        &mut self,
        store: &mut Store,
        packet: &GroupPacket,
        directories: &HashMap<AgentId, Vec<u8>>,
        now: u64,
    ) -> Result<Option<(GroupApplication, AgentId, PeerId)>, AslError> {
        packet.validate_request()?;
        if !matches!(packet.body, GroupBody::Application(_)) {
            return Err(AslError::InvalidMessage);
        }
        let snapshot = store
            .mls_room_snapshot(packet.group_id)?
            .ok_or(AslError::PolicyDenied)?;
        let (state, _) = store
            .mls_room_progress(packet.group_id)?
            .ok_or(AslError::PolicyDenied)?;
        if state != "active" || packet.epoch != snapshot.version.mls_epoch {
            return Err(AslError::PolicyVersionConflict);
        }
        let mut candidate = self.load_mls_application_base(
            store,
            packet.group_id,
            snapshot.version,
            directories,
            now,
        )?;
        let (application, sender_index) = open_application_with_sender(
            &mut candidate.base.group,
            &candidate.base.provider,
            packet,
        )?;
        if sender_index == candidate.group.own_leaf_index() {
            return Err(AslError::PolicyDenied);
        }
        let sender_leaf = candidate
            .leaves
            .iter()
            .find(|leaf| leaf.member.index == sender_index)
            .ok_or(AslError::PolicyDenied)?;
        let member = candidate
            .roster
            .members
            .iter()
            .find(|member| {
                member.certificate.peer_id == sender_leaf.certificate.peer_id
                    && member.certificate.agent_id == sender_leaf.certificate.agent_id
            })
            .ok_or(AslError::PolicyDenied)?;
        let sender_key = CredentialWithKey::from(&sender_leaf.member);
        group_credential::verify_binding(
            packet.group_id,
            &sender_key,
            &member.certificate,
            member.controller,
        )?;
        let (created, expires) = application_times(&application);
        check_application_creation(created, now)?;
        if now >= expires {
            return Err(AslError::ExpiredMessage);
        }
        let (_, browse_enabled) = self.persist_mls_application(
            store,
            &candidate,
            packet,
            application.message_id(),
            Some(ApplicationOrigin::Roster {
                kind: application.kind(),
                key: &sender_key,
                member,
            }),
            None,
            || Ok(now),
        )?;
        let visible = browse_enabled
            || !matches!(
                application,
                GroupApplication::Expression(_) | GroupApplication::Act(_)
            );
        Ok(visible.then_some((
            application,
            member.certificate.agent_id,
            member.certificate.peer_id.clone(),
        )))
    }

    pub(super) fn load_mls_application_base(
        &mut self,
        store: &Store,
        wire_id: Hash32,
        expected: RoomVersion,
        directories: &HashMap<AgentId, Vec<u8>>,
        now: u64,
    ) -> Result<LocalRoomCandidate, AslError> {
        if !self.local_is_current(now) {
            return Err(AslError::InvalidIdentity);
        }
        let candidate = self
            .room_evidence(directories, now)
            .load_candidate(store, wire_id)?
            .ok_or(AslError::PolicyDenied)?;
        if candidate.version != expected {
            return Err(AslError::PolicyVersionConflict);
        }
        Ok(candidate)
    }

    #[allow(clippy::too_many_arguments)]
    fn persist_mls_application(
        &mut self,
        store: &mut Store,
        candidate: &LocalRoomCandidate,
        packet: &GroupPacket,
        message_id: Id128,
        incoming: Option<ApplicationOrigin<'_>>,
        outbox: Option<&ShardForwardOutboxRecord>,
        current_time: impl Fn() -> Result<u64, AslError>,
    ) -> Result<(RoomVersion, bool), AslError> {
        let GroupBody::Application(ciphertext) = &packet.body else {
            return Err(AslError::InvalidMessage);
        };
        let local = self.local_hello.peer_id.clone();
        let binding = RoomBinding {
            local_id: &candidate.local_id,
            wire_id: packet.group_id,
            device: &local,
        };
        let revision = candidate
            .version
            .revision
            .checked_add(1)
            .ok_or(AslError::QuotaExceeded)?;
        let snapshot = seal_with_history(
            &binding,
            revision,
            &candidate.group,
            &candidate.provider,
            &candidate.history,
        )?;
        let roster = &candidate.roster;
        let members: Vec<_> = roster
            .members
            .iter()
            .map(|member| member.certificate.peer_id.clone())
            .collect();
        let chain_id = self.resolver.deployment().chain_id;
        store.commit_verified_mls_application(
            MlsRoomUpdate {
                local_id: &candidate.local_id,
                wire_id: packet.group_id,
                expected: candidate.version,
                mls_epoch: packet.epoch,
                sealed_snapshot: &snapshot,
                members: &members,
                event: Some(MlsJournalEntry {
                    sender: incoming.as_ref().map_or(&local, ApplicationOrigin::device),
                    kind: incoming
                        .as_ref()
                        .map_or(MlsJournalKind::Application(message_id), |source| {
                            MlsJournalKind::ReceivedApplication(message_id, source.kind())
                        }),
                    ciphertext,
                }),
            },
            MlsApplicationAuthority {
                creator: &roster.creator,
                members: &roster.members,
                chain_id,
            },
            outbox,
            || {
                // Chain freshness is evaluated in whole seconds. If a check
                // spans that boundary, retry at the new time rather than use a
                // possibly expired proof. Millisecond authorities have their
                // exact deadline compared against the post-check sample.
                for _ in 0..2 {
                    let now = current_time()?;
                    let session_expiry = match &incoming {
                        Some(ApplicationOrigin::Direct(source)) => {
                            self.verify_admitted_group_leaf(
                                source.connection_id,
                                packet.group_id,
                                source.key,
                                now,
                            )?;
                            self.peers
                                .get(&source.connection_id)
                                .and_then(|peer| peer.session.admission_facts())
                                .ok_or(AslError::InvalidIdentity)?
                                .1
                        }
                        Some(ApplicationOrigin::Roster { key, member, .. }) => {
                            group_credential::verify_binding(
                                packet.group_id,
                                key,
                                &member.certificate,
                                member.controller,
                            )?;
                            member.certificate.expires_at_ms
                        }
                        None => {
                            if !self.local_is_current(now) {
                                return Err(AslError::InvalidIdentity);
                            }
                            u64::MAX
                        }
                    };
                    let directory_expiry =
                        roster.require_current_directories(&mut self.resolver, now)?;
                    let checked = current_time()?;
                    if checked >= session_expiry.min(directory_expiry) {
                        return Err(AslError::ExpiredMessage);
                    }
                    if checked / 1_000 == now / 1_000 {
                        return Ok(checked);
                    }
                }
                Err(AslError::ExpiredMessage)
            },
        )
    }
}

pub(super) fn application_times(application: &GroupApplication) -> (Option<u64>, u64) {
    application.time_bounds()
}

fn check_application_creation(created: Option<u64>, now: u64) -> Result<(), AslError> {
    if created.is_some_and(|created| now < created) {
        return Err(AslError::ExpiredMessage);
    }
    Ok(())
}
