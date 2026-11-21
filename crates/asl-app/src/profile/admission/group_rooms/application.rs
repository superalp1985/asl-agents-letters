use std::collections::HashMap;

use asl_groups::{
    GroupApplication, encrypt_application,
    local_state::{RoomBinding, seal_with_history},
    open_application,
};
use asl_net::transport::REQUEST_TIMEOUT;
use asl_store::{
    Store,
    group_state::{
        MlsApplicationAuthority, MlsJournalEntry, MlsJournalKind, MlsRoomUpdate, RoomVersion,
    },
};
use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId},
    protocol::{GroupBody, GroupPacket},
};
use openmls::prelude::CredentialWithKey;

use super::{CoreAdmission, LocalRoomCandidate, sync::SyncClock};
use crate::profile::admission::fresh_id;

pub struct MlsApplicationReceive<'a> {
    pub connection_id: [u8; 16],
    pub expected: RoomVersion,
    pub packet: &'a GroupPacket,
    pub deadline_ms: u64,
}

struct ApplicationSource<'a> {
    connection_id: [u8; 16],
    key: &'a CredentialWithKey,
    device: &'a PeerId,
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
        self.prepare_mls_application(store, &mut candidate, application, &clock)
            .map(|(packet, _)| packet)
    }

    pub(super) fn prepare_mls_application(
        &mut self,
        store: &mut Store,
        candidate: &mut LocalRoomCandidate,
        application: GroupApplication,
        clock: &SyncClock,
    ) -> Result<(GroupPacket, RoomVersion), AslError> {
        let (created, _) = application_times(&application);
        check_application_creation(created, clock.now_ms()?)?;
        let message_id = application.message_id();
        let packet = encrypt_application(
            &mut candidate.base.group,
            &candidate.base.provider,
            &candidate.base.signer,
            Id128(fresh_id()?),
            application,
        )?;
        let version =
            self.persist_mls_application(store, candidate, &packet, message_id, None, || {
                clock.now_ms()
            })?;
        Ok((packet, version))
    }

    /// Return structured plaintext only after the receive ratchet and replay
    /// record commit. A future delivery caller must separately establish
    /// group freshness for the supplied snapshot.
    pub fn commit_mls_application_receive(
        &mut self,
        store: &mut Store,
        receive: MlsApplicationReceive<'_>,
        directories: &HashMap<AgentId, Vec<u8>>,
        now_ms: u64,
    ) -> Result<GroupApplication, AslError> {
        let clock = SyncClock::inbound(now_ms, receive.deadline_ms);
        self.apply_mls_application(store, receive, directories, &clock)
    }

    pub(super) fn apply_mls_application(
        &mut self,
        store: &mut Store,
        receive: MlsApplicationReceive<'_>,
        directories: &HashMap<AgentId, Vec<u8>>,
        clock: &SyncClock,
    ) -> Result<GroupApplication, AslError> {
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
        let (created, expires) = application_times(&application);
        check_application_creation(created, clock.now_ms()?)?;
        self.persist_mls_application(
            store,
            &candidate,
            packet,
            application.message_id(),
            Some(ApplicationSource {
                connection_id: receive.connection_id,
                key: &sender_key,
                device: &peer,
            }),
            || {
                let now = clock.now_ms()?;
                if now >= expires {
                    return Err(AslError::ExpiredMessage);
                }
                Ok(now)
            },
        )?;
        Ok(application)
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

    fn persist_mls_application(
        &mut self,
        store: &mut Store,
        candidate: &LocalRoomCandidate,
        packet: &GroupPacket,
        message_id: Id128,
        incoming: Option<ApplicationSource<'_>>,
        current_time: impl Fn() -> Result<u64, AslError>,
    ) -> Result<RoomVersion, AslError> {
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
                    sender: incoming.as_ref().map_or(&local, |source| source.device),
                    kind: MlsJournalKind::Application(message_id),
                    ciphertext,
                }),
            },
            MlsApplicationAuthority {
                creator: &roster.creator,
                members: &roster.members,
                chain_id,
            },
            || {
                // Chain freshness is evaluated in whole seconds. If a check
                // spans that boundary, retry at the new time rather than use a
                // possibly expired proof. Millisecond authorities have their
                // exact deadline compared against the post-check sample.
                for _ in 0..2 {
                    let now = current_time()?;
                    let session_expiry = if let Some(source) = &incoming {
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
                    } else {
                        if !self.local_is_current(now) {
                            return Err(AslError::InvalidIdentity);
                        }
                        u64::MAX
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
    match application {
        GroupApplication::Query(query) => (Some(query.created_at_ms), query.expires_at_ms),
        GroupApplication::Answer(answer) => (Some(answer.created_at_ms), answer.expires_at_ms),
        GroupApplication::Offer(offer) => (None, offer.expires_at_ms),
    }
}

fn check_application_creation(created: Option<u64>, now: u64) -> Result<(), AslError> {
    if created.is_some_and(|created| now < created) {
        return Err(AslError::ExpiredMessage);
    }
    Ok(())
}
