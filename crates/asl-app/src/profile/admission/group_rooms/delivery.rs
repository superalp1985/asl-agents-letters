use std::{collections::HashMap, time::Instant};

use asl_groups::GroupApplication;
use asl_net::transport::REQUEST_TIMEOUT;
use asl_store::{Store, group_state::MlsApplicationAuthority};
use asl_types::{
    error::AslError,
    ids::{Hash32, Id128, PeerId},
    protocol::GroupPacket,
};
use openmls::prelude::CredentialWithKey;

use super::{
    CoreAdmission, MlsApplicationReceive, application::application_times, sync::SyncClock,
};
use crate::{network::NetworkCommand, profile::admission::fresh_id};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MlsApplicationDispatch {
    pub message_id: Id128,
    /// Recipients whose command entered Core's local Net queue, not receipts.
    pub queued: usize,
    pub available: usize,
}

impl CoreAdmission {
    /// Trusted Core caller only. A creator fans out against its durable head;
    /// a non-creator may only address the creator, which checks its own head.
    /// Nothing is forwarded, retried or queued for offline devices.
    pub fn send_loopback_mls_application(
        &mut self,
        store: &mut Store,
        wire_id: Hash32,
        application: GroupApplication,
        now_ms: u64,
        mut enqueue: impl FnMut(NetworkCommand) -> Result<(), AslError>,
    ) -> Result<MlsApplicationDispatch, AslError> {
        if self.group_directories.is_none() {
            return Err(AslError::PolicyDenied);
        }
        let (_, expires) = application_times(&application);
        let deadline_ms = expires.min(now_ms.saturating_add(REQUEST_TIMEOUT.as_millis() as u64));
        let clock = SyncClock::inbound(now_ms, deadline_ms);
        let saved = store
            .mls_room_snapshot(wire_id)?
            .ok_or(AslError::NotFound)?;
        let mut candidate = self.load_mls_application_base(
            store,
            wire_id,
            saved.version,
            &HashMap::new(),
            clock.now_ms()?,
        )?;
        let local = self.local_hello.peer_id.clone();
        let mut routes = Vec::new();
        for (agent, connection, peer) in self.admitted_connections(clock.now_ms()?) {
            if peer == local
                || !creator_edge(&local, &peer, &candidate.creator)
                || routes.iter().any(|(device, _, _)| *device == peer)
            {
                continue;
            }
            if let Some(leaf) = candidate
                .leaves
                .iter()
                .find(|leaf| leaf.certificate.peer_id == peer && leaf.certificate.agent_id == agent)
            {
                let key = CredentialWithKey::from(&leaf.member);
                if self
                    .verify_admitted_group_leaf(connection, wire_id, &key, clock.now_ms()?)
                    .is_ok()
                {
                    routes.push((peer, connection, key));
                }
            }
        }
        if routes.is_empty() {
            return Err(AslError::NotFound);
        }
        let message_id = application.message_id();
        let (packet, version) =
            self.prepare_mls_application(store, &mut candidate, application, &clock)?;
        let mut result = MlsApplicationDispatch {
            message_id,
            queued: 0,
            available: routes.len(),
        };
        let chain_id = self.resolver.deployment().chain_id;
        store.with_mls_application_dispatch(
            wire_id,
            version,
            MlsApplicationAuthority {
                creator: &candidate.creator,
                members: &candidate.roster.members,
                chain_id,
            },
            clock.now_ms()?,
            || {
                for (_, connection, leaf) in routes {
                    let Ok(current) = clock.now_ms() else {
                        break;
                    };
                    if self
                        .verify_admitted_group_leaf(connection, wire_id, &leaf, current)
                        .is_err()
                    {
                        continue;
                    }
                    let Ok(request_handle) = fresh_id() else {
                        break;
                    };
                    if clock.now_ms().is_err() {
                        break;
                    }
                    if enqueue(NetworkCommand::SendGroup {
                        connection_id: connection,
                        request_handle,
                        deadline_ms,
                        request: packet.clone(),
                    })
                    .is_ok()
                    {
                        result.queued += 1;
                    }
                }
                result
            },
        )
    }

    pub(super) fn receive_loopback_mls_application(
        &mut self,
        store: &mut Store,
        connection_id: [u8; 16],
        packet: &GroupPacket,
        deadline_ms: u64,
        now_ms: u64,
    ) -> Result<(PeerId, GroupApplication), AslError> {
        if self.group_directories.is_none() {
            return Err(AslError::PolicyDenied);
        }
        let started = Instant::now();
        let clock = SyncClock::inbound(now_ms, deadline_ms);
        let (_, peer) = self.admitted_peer_identity(connection_id, clock.now_ms()?)?;
        if !store.has_mls_sync_member(packet.group_id, &peer)? {
            return Err(AslError::PolicyDenied);
        }
        if !self.mls_application_budget.try_acquire(started) {
            return Err(AslError::QuotaExceeded);
        }
        let saved = store
            .mls_room_for_reconciliation(packet.group_id)?
            .ok_or(AslError::PolicyDenied)?;
        if peer == self.local_hello.peer_id
            || !creator_edge(&self.local_hello.peer_id, &peer, &saved.creator)
        {
            return Err(AslError::PolicyDenied);
        }
        let application = self.apply_mls_application(
            store,
            MlsApplicationReceive {
                connection_id,
                expected: saved.snapshot.version,
                packet,
                deadline_ms,
            },
            &HashMap::new(),
            &clock,
        )?;
        Ok((peer, application))
    }
}

fn creator_edge(local: &PeerId, remote: &PeerId, creator: &PeerId) -> bool {
    local == creator || remote == creator
}
