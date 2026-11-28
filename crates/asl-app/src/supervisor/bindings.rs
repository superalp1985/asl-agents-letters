use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use asl_net::{
    dht::{agent_lookup_key, handle_key},
    transport::{DhtLookupStatus, DhtProviderCandidate},
};
use asl_store::{
    Store,
    contact_bindings::{ContactBindingAction, ContactBindingActionKind},
    contact_policy::ContactRequestMode,
    open_store,
};
use asl_types::{
    error::AslError,
    ids::{AgentId, PeerId},
    record::{RecordKind, RecordPayload, decode_record, short_code},
};
use rand::{TryRng, rngs::SysRng};

use crate::{
    network::{LocalNetworkObservation, NetworkCommand},
    profile::AdmittedNetworkEvent,
};

use super::{NetworkAdmissionStatus, Supervisor, unix_time_ms};

const MAX_BINDING_LOOKUPS: usize = 8;
const MAX_PROVIDERS_PER_LOOKUP: usize = 20;
const MAX_PENDING_BINDING_PEERS: usize = MAX_BINDING_LOOKUPS * MAX_PROVIDERS_PER_LOOKUP;
const MAX_CODES_PER_BINDING_PEER: usize = MAX_BINDING_LOOKUPS;
const BINDING_LOOKUP_LIFETIME_MS: u64 = 15_000;
const PUBLICATION_RETRY_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Default)]
pub(super) struct ContactBindingRuntime {
    initialized: bool,
    published: bool,
    pending_lookups: HashMap<[u8; 16], PendingLookup>,
    pending_peers: HashMap<PeerId, Vec<PendingPeer>>,
    publication_operations: HashMap<[u8; 16], bool>,
    publication_retry_at: Option<Instant>,
}

struct PendingLookup {
    action_id: i64,
    code: u64,
    expected_agent: Option<AgentId>,
    expires_at_ms: u64,
}

struct PendingPeer {
    code: u64,
    expected_agent: Option<AgentId>,
    expires_at_ms: u64,
}

impl Supervisor {
    pub(super) fn reset_binding_transport(&mut self) -> Result<(), AslError> {
        let store = open_store(&self.state_database)?;
        let initialized = self.contact_bindings.initialized;
        let old = std::mem::take(&mut self.contact_bindings);
        self.contact_bindings.initialized = initialized;
        for pending in old.pending_lookups.into_values() {
            store.finish_contact_binding_action(pending.action_id, Err("unavailable"))?;
        }
        Ok(())
    }

    pub(super) fn poll_contact_bindings(&mut self) -> Result<(), AslError> {
        let mut store = open_store(&self.state_database)?;
        if !self.contact_bindings.initialized {
            store.resume_contact_binding_actions()?;
            let revoked = store.revoked_contact_bindings()?;
            let commands = self.admission.as_mut().map(|admission| {
                revoked
                    .into_iter()
                    .flat_map(|agent_id| admission.block_agent(agent_id).commands)
                    .collect::<Vec<_>>()
            });
            if let Some(commands) = commands {
                for command in commands {
                    self.send_network_command(command)?;
                }
            }
            self.contact_bindings.initialized = true;
        }

        let now_ms = unix_time_ms()?;
        self.expire_contact_binding_work(&mut store, now_ms)?;
        self.synchronize_binding_publication(&store)?;

        for action in store.claim_contact_binding_actions()? {
            self.process_contact_binding_action(&mut store, action, now_ms)?;
        }
        Ok(())
    }

    pub(super) fn observe_contact_binding_network(
        &mut self,
        observation: LocalNetworkObservation,
    ) -> Result<(), AslError> {
        let LocalNetworkObservation::DhtProviders {
            lookup_id,
            status,
            providers,
        } = observation
        else {
            return Ok(());
        };
        let Some(lookup) = self.contact_bindings.pending_lookups.remove(&lookup_id) else {
            return Ok(());
        };
        let now_ms = unix_time_ms()?;
        if now_ms >= lookup.expires_at_ms {
            let store = open_store(&self.state_database)?;
            store.finish_contact_binding_action(lookup.action_id, Err("expired"))?;
            return Ok(());
        }
        if status != DhtLookupStatus::Completed {
            let store = open_store(&self.state_database)?;
            store.finish_contact_binding_action(lookup.action_id, Err("lookup_failed"))?;
            return Ok(());
        }

        let admitted = self
            .admission
            .as_mut()
            .filter(|_| self.network_admission_status == NetworkAdmissionStatus::Active)
            .map(|admission| admission.admitted_connections(now_ms))
            .unwrap_or_default();
        let connecting = self
            .admission
            .as_ref()
            .map(|admission| admission.connecting_peers())
            .unwrap_or_default();
        let store = open_store(&self.state_database)?;
        let mut dial_count = 0;
        let mut found = false;

        for provider in providers.into_iter().take(MAX_PROVIDERS_PER_LOOKUP) {
            if let Some((agent_id, _, _)) = admitted
                .iter()
                .find(|(_, _, peer_id)| *peer_id == provider.peer_id)
            {
                if lookup
                    .expected_agent
                    .is_some_and(|expected| expected != *agent_id)
                {
                    continue;
                }
                found |= store.record_contact_binding_candidate(
                    *agent_id,
                    &provider.peer_id,
                    lookup.code,
                    now_ms,
                )?;
                continue;
            }

            if !self.track_binding_peer(
                &provider.peer_id,
                lookup.code,
                lookup.expected_agent,
                lookup.expires_at_ms,
            ) {
                continue;
            }
            if connecting.contains(&provider.peer_id) {
                dial_count += 1;
                continue;
            }
            let Some(command) = binding_provider_dial(provider, fresh_id()?) else {
                continue;
            };
            if self.send_network_command(command).is_ok() {
                dial_count += 1;
            }
        }

        store.finish_contact_binding_action(
            lookup.action_id,
            Ok(if found {
                "candidates_found"
            } else if dial_count > 0 {
                "searching"
            } else {
                "no_candidates"
            }),
        )?;
        Ok(())
    }

    pub(crate) fn observe_contact_binding_event(
        &mut self,
        event: &AdmittedNetworkEvent,
    ) -> Result<(), AslError> {
        match event {
            AdmittedNetworkEvent::DhtRecordAvailable {
                agent_id,
                kind: RecordKind::DeviceDirectory,
                record,
                ..
            } => {
                let signed = decode_record(record)?;
                let RecordPayload::DeviceDirectory(directory) = signed.record.payload else {
                    return Err(AslError::InvalidIdentity);
                };
                if &directory.agent_id != agent_id {
                    return Err(AslError::InvalidIdentity);
                }
                let store = open_store(&self.state_database)?;
                if let Some(devices) =
                    store.rebind_verified_contact_device(&directory, unix_time_ms()?)?
                {
                    self.mailbox
                        .observe_contact_device_change(*agent_id, &devices.0, &devices.1);
                }
            }
            AdmittedNetworkEvent::OperationAccepted { operation_id } => {
                if let Some(target_state) = self
                    .contact_bindings
                    .publication_operations
                    .remove(operation_id)
                {
                    self.contact_bindings.published = target_state;
                    self.contact_bindings.publication_retry_at = None;
                }
            }
            AdmittedNetworkEvent::PeerAdmitted {
                peer_id, agent_id, ..
            } => {
                let Some(pending) = self.contact_bindings.pending_peers.remove(peer_id) else {
                    return Ok(());
                };
                let now_ms = unix_time_ms()?;
                let store = open_store(&self.state_database)?;
                for request in pending {
                    if now_ms < request.expires_at_ms
                        && request
                            .expected_agent
                            .is_none_or(|expected| expected == *agent_id)
                    {
                        store.record_contact_binding_candidate(
                            *agent_id,
                            peer_id,
                            request.code,
                            now_ms,
                        )?;
                    }
                }
            }
            AdmittedNetworkEvent::OperationFailed { operation_id, .. } => {
                if self
                    .contact_bindings
                    .publication_operations
                    .remove(operation_id)
                    .is_some()
                {
                    self.contact_bindings.publication_retry_at =
                        Some(Instant::now() + PUBLICATION_RETRY_INTERVAL);
                } else if let Some(lookup) =
                    self.contact_bindings.pending_lookups.remove(operation_id)
                {
                    let store = open_store(&self.state_database)?;
                    store.finish_contact_binding_action(lookup.action_id, Err("lookup_failed"))?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn process_contact_binding_action(
        &mut self,
        store: &mut Store,
        action: ContactBindingAction,
        now_ms: u64,
    ) -> Result<(), AslError> {
        let result = match action.kind {
            ContactBindingActionKind::Lookup => {
                let code = action.code.ok_or(AslError::InvalidMessage)?;
                if action
                    .agent_id
                    .is_some_and(|agent| short_code(agent) != code)
                {
                    return Err(AslError::InvalidMessage);
                }
                if !self.net.is_running()
                    || self.network_admission_status != NetworkAdmissionStatus::Active
                    || self.contact_bindings.pending_lookups.len() >= MAX_BINDING_LOOKUPS
                {
                    Err("unavailable")
                } else {
                    let lookup_id = fresh_id()?;
                    let key = match action.agent_id {
                        Some(agent) => agent_lookup_key(agent),
                        None => handle_key(code)?,
                    };
                    let key: [u8; 32] = key
                        .as_ref()
                        .try_into()
                        .map_err(|_| AslError::InvalidMessage)?;
                    match self
                        .send_network_command(NetworkCommand::FindProviders { lookup_id, key })
                    {
                        Ok(()) => {
                            self.contact_bindings.pending_lookups.insert(
                                lookup_id,
                                PendingLookup {
                                    action_id: action.id,
                                    code,
                                    expected_agent: action.agent_id,
                                    expires_at_ms: now_ms
                                        .saturating_add(BINDING_LOOKUP_LIFETIME_MS),
                                },
                            );
                            return Ok(());
                        }
                        Err(_) => Err("unavailable"),
                    }
                }
            }
            ContactBindingActionKind::Approve => {
                let (Some(agent_id), Some(peer_id), Some(code)) =
                    (action.agent_id, action.peer_id.as_ref(), action.code)
                else {
                    return Err(AslError::InvalidMessage);
                };
                let currently_admitted = self
                    .admission
                    .as_mut()
                    .filter(|_| self.network_admission_status == NetworkAdmissionStatus::Active)
                    .is_some_and(|admission| {
                        admission.admitted_connections(now_ms).iter().any(
                            |(candidate_agent, _, candidate_peer)| {
                                *candidate_agent == agent_id && candidate_peer == peer_id
                            },
                        )
                    });
                if !currently_admitted {
                    Err("identity_unavailable")
                } else {
                    match store.approve_contact_binding(agent_id, peer_id, code, now_ms) {
                        Ok(()) => {
                            if let Some(admission) = &mut self.admission {
                                admission.unblock_agent(agent_id);
                            }
                            Ok("approved")
                        }
                        Err(_) => Err("candidate_expired"),
                    }
                }
            }
            ContactBindingActionKind::Dismiss => {
                let (Some(agent_id), Some(peer_id)) = (action.agent_id, action.peer_id.as_ref())
                else {
                    return Err(AslError::InvalidMessage);
                };
                match store.dismiss_contact_binding_candidate(agent_id, peer_id) {
                    Ok(()) => Ok("dismissed"),
                    Err(_) => Err("candidate_expired"),
                }
            }
            ContactBindingActionKind::Revoke => {
                let agent_id = action.agent_id.ok_or(AslError::InvalidMessage)?;
                match store.revoke_contact_binding(agent_id, now_ms) {
                    Ok(()) => {
                        let commands = self
                            .admission
                            .as_mut()
                            .map(|admission| admission.block_agent(agent_id).commands)
                            .unwrap_or_default();
                        for command in commands {
                            self.send_network_command(command)?;
                        }
                        Ok("revoked")
                    }
                    Err(_) => Err("not_found"),
                }
            }
            ContactBindingActionKind::Forget => {
                let agent_id = action.agent_id.ok_or(AslError::InvalidMessage)?;
                store.forget_contact_binding(agent_id)?;
                if let Some(admission) = &mut self.admission {
                    admission.unblock_agent(agent_id);
                }
                Ok("forgotten")
            }
            ContactBindingActionKind::PublishCode => {
                store.set_binding_code_public(true, now_ms)?;
                Ok("enabled")
            }
            ContactBindingActionKind::UnpublishCode => {
                store.set_binding_code_public(false, now_ms)?;
                Ok("disabled")
            }
            ContactBindingActionKind::SetRequestReview => {
                store.set_contact_request_mode(ContactRequestMode::Review, now_ms)?;
                Ok("review")
            }
            ContactBindingActionKind::SetRequestAutoAccept => {
                store.set_contact_request_mode(ContactRequestMode::AutoAccept, now_ms)?;
                Ok("auto_accept")
            }
            ContactBindingActionKind::SetRequestReject => {
                store.set_contact_request_mode(ContactRequestMode::Reject, now_ms)?;
                Ok("reject")
            }
            ContactBindingActionKind::EnableSharedGroupAutoAccept => {
                store.set_shared_group_auto_accept(true, now_ms)?;
                Ok("enabled")
            }
            ContactBindingActionKind::DisableSharedGroupAutoAccept => {
                store.set_shared_group_auto_accept(false, now_ms)?;
                Ok("disabled")
            }
            ContactBindingActionKind::SetRecentInteractionTtl => {
                let ttl_ms = action.code.ok_or(AslError::InvalidMessage)?;
                store.set_recent_interaction_ttl(ttl_ms, now_ms)?;
                Ok("updated")
            }
        };

        store.finish_contact_binding_action(action.id, result)
    }

    fn synchronize_binding_publication(&mut self, store: &Store) -> Result<(), AslError> {
        let enabled = store.binding_code_public()?;
        let should_publish = enabled
            && self.net.is_running()
            && self.network_admission_status == NetworkAdmissionStatus::Active
            && self.admission.is_some();
        if should_publish == self.contact_bindings.published {
            self.contact_bindings.publication_retry_at = None;
            return Ok(());
        }
        if !self.contact_bindings.publication_operations.is_empty()
            || self
                .contact_bindings
                .publication_retry_at
                .is_some_and(|retry_at| Instant::now() < retry_at)
        {
            return Ok(());
        }

        let operation_id = fresh_id()?;
        let key = agent_lookup_key(self.agent_identity.agent_id());
        let key: [u8; 32] = key
            .as_ref()
            .try_into()
            .map_err(|_| AslError::InvalidMessage)?;
        let command = if should_publish {
            NetworkCommand::StartProviding { operation_id, key }
        } else {
            NetworkCommand::StopProviding { operation_id, key }
        };
        if self.net.try_send(&command.into_ipc()?)? {
            self.contact_bindings
                .publication_operations
                .insert(operation_id, should_publish);
        }
        Ok(())
    }

    fn expire_contact_binding_work(
        &mut self,
        store: &mut Store,
        now_ms: u64,
    ) -> Result<(), AslError> {
        let expired_lookups = self
            .contact_bindings
            .pending_lookups
            .iter()
            .filter_map(|(id, pending)| (now_ms >= pending.expires_at_ms).then_some(*id))
            .collect::<Vec<_>>();
        for id in expired_lookups {
            if let Some(pending) = self.contact_bindings.pending_lookups.remove(&id) {
                store.finish_contact_binding_action(pending.action_id, Err("expired"))?;
            }
        }
        self.contact_bindings.pending_peers.retain(|_, requests| {
            requests.retain(|request| now_ms < request.expires_at_ms);
            !requests.is_empty()
        });
        Ok(())
    }

    fn track_binding_peer(
        &mut self,
        peer_id: &PeerId,
        code: u64,
        expected_agent: Option<AgentId>,
        expires_at_ms: u64,
    ) -> bool {
        if !self.contact_bindings.pending_peers.contains_key(peer_id)
            && self.contact_bindings.pending_peers.len() >= MAX_PENDING_BINDING_PEERS
        {
            return false;
        }
        let requests = self
            .contact_bindings
            .pending_peers
            .entry(peer_id.clone())
            .or_default();
        if requests
            .iter()
            .any(|request| request.code == code && request.expected_agent == expected_agent)
        {
            return true;
        }
        if requests.len() >= MAX_CODES_PER_BINDING_PEER {
            return false;
        }
        requests.push(PendingPeer {
            code,
            expected_agent,
            expires_at_ms,
        });
        true
    }
}

fn binding_provider_dial(
    provider: DhtProviderCandidate,
    operation_id: [u8; 16],
) -> Option<NetworkCommand> {
    match provider.endpoint {
        Some((kind, address)) => Some(NetworkCommand::Dial {
            operation_id,
            kind,
            address,
            peer_id: provider.peer_id,
        }),
        None if provider.relay_route_available => Some(NetworkCommand::DialViaRelays {
            operation_id,
            peer_id: provider.peer_id,
        }),
        None => None,
    }
}

fn fresh_id() -> Result<[u8; 16], AslError> {
    for _ in 0..8 {
        let mut id = [0; 16];
        SysRng
            .try_fill_bytes(&mut id)
            .map_err(|_| AslError::InvalidIdentity)?;
        if id != [0; 16] {
            return Ok(id);
        }
    }
    Err(AslError::InvalidIdentity)
}
