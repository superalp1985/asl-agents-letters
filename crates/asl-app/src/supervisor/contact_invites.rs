use std::collections::{HashMap, HashSet};

use asl_net::{
    dht::contact_invite_key,
    transport::{DhtLookupStatus, DhtProviderCandidate},
};
use asl_store::{
    contact_bindings::ContactBindingState, contact_invites::ContactInvitePromptState,
    contact_policy::ContactRequestMode, open_store,
};
use asl_types::{
    contact_invite::ContactInviteV1,
    error::AslError,
    ids::{Id128, PeerId},
    protocol::{PairingExchange, PairingInvite},
    record::short_code,
};

use crate::{
    contact_invite,
    network::{LocalNetworkObservation, NetworkCommand},
    pairing::PairingAuthorization,
    profile::AdmittedNetworkEvent,
};

use super::{Supervisor, fresh_id, unix_time_ms};

const MAX_IMPORT_LOOKUPS: usize = 4;
const MAX_IMPORT_PROVIDERS: usize = 12;
const MAX_TRACKED_CONNECTIONS: usize = 32;
const LOOKUP_LIFETIME_MS: u64 = 20_000;

#[derive(Default)]
pub(super) struct ContactInviteRuntime {
    initialized: bool,
    published: HashMap<Id128, Id128>,
    publishing: HashMap<[u8; 16], (Id128, bool)>,
    lookups: HashMap<[u8; 16], ImportLookup>,
    dialing: HashMap<PeerId, DialAttempt>,
    outgoing: HashMap<[u8; 16], OutgoingAttempt>,
    prompts: HashMap<Id128, PendingPrompt>,
}

struct ImportLookup {
    action_id: i64,
    source: ImportSource,
    expires_at_ms: u64,
}

#[derive(Clone)]
enum ImportSource {
    Discovery(ContactInviteV1),
    ShortCode {
        token: Id128,
        expected_inviter: asl_types::ids::AgentId,
        expected_peer: PeerId,
    },
}

struct DialAttempt {
    source: ImportSource,
    operation_id: [u8; 16],
    expires_at_ms: u64,
}

struct OutgoingAttempt {
    invite: PairingInvite,
    connection_id: [u8; 16],
    expires_at_ms: u64,
}

#[derive(Clone)]
struct PendingPrompt {
    connection_id: [u8; 16],
    response_id: [u8; 16],
    pairing: PairingInvite,
    discovery_invite_id: Id128,
    expires_at_ms: u64,
}

impl Supervisor {
    pub(super) fn reset_contact_invite_transport(&mut self) -> Result<(), AslError> {
        let now_ms = unix_time_ms()?;
        let prompt_ids = self
            .contact_invites
            .prompts
            .keys()
            .copied()
            .collect::<Vec<_>>();
        if !prompt_ids.is_empty() {
            let mut store = open_store(&self.state_database)?;
            for prompt_id in prompt_ids {
                let _ = store.decide_contact_invite_prompt(prompt_id, now_ms, false);
            }
        }
        self.contact_invites = ContactInviteRuntime::default();
        Ok(())
    }

    pub(super) fn poll_contact_invites(&mut self) -> Result<(), AslError> {
        let now_ms = unix_time_ms()?;
        let mut store = open_store(&self.state_database)?;
        if !self.contact_invites.initialized {
            store.cleanup_expired_contact_invites(now_ms)?;
            for prompt in store.list_contact_invite_prompts(now_ms)? {
                let _ = store.decide_contact_invite_prompt(prompt.prompt_id, now_ms, false);
            }
            self.contact_invites.initialized = true;
        }
        let expired_lookups = self
            .contact_invites
            .lookups
            .iter()
            .filter_map(|(lookup_id, lookup)| {
                (lookup.expires_at_ms <= now_ms).then_some(*lookup_id)
            })
            .collect::<Vec<_>>();
        for lookup_id in expired_lookups {
            if let Some(lookup) = self.contact_invites.lookups.remove(&lookup_id) {
                store.finish_contact_invite_action(lookup.action_id, Err("expired"))?;
            }
        }
        self.contact_invites
            .dialing
            .retain(|_, attempt| attempt.expires_at_ms > now_ms);
        self.contact_invites
            .outgoing
            .retain(|_, attempt| attempt.expires_at_ms > now_ms);
        self.sync_contact_invite_publications(&store, now_ms)?;
        self.process_contact_invite_actions(&mut store, now_ms)?;
        self.process_contact_invite_decisions(&mut store, now_ms)?;
        Ok(())
    }

    pub(super) fn observe_contact_invite_network(
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
        let Some(lookup) = self.contact_invites.lookups.remove(&lookup_id) else {
            return Ok(());
        };
        let now_ms = unix_time_ms()?;
        let store = open_store(&self.state_database)?;
        if now_ms >= lookup.expires_at_ms || status != DhtLookupStatus::Completed {
            store.finish_contact_invite_action(
                lookup.action_id,
                if now_ms >= lookup.expires_at_ms {
                    Err("expired")
                } else {
                    Err("lookup_failed")
                },
            )?;
            return Ok(());
        }

        let mut dialed = 0;
        for provider in providers.into_iter().take(MAX_IMPORT_PROVIDERS) {
            if self.contact_invites.dialing.len() >= MAX_TRACKED_CONNECTIONS {
                break;
            }
            if match &lookup.source {
                ImportSource::ShortCode { expected_peer, .. } => *expected_peer != provider.peer_id,
                ImportSource::Discovery(_) => false,
            } {
                continue;
            }
            let peer_id = provider.peer_id.clone();
            let operation_id = fresh_id()?;
            let Some(command) = invite_provider_dial(provider, operation_id) else {
                continue;
            };
            if self.send_network_command(command).is_ok() {
                dialed += 1;
                self.contact_invites.dialing.insert(
                    peer_id,
                    DialAttempt {
                        source: lookup.source.clone(),
                        operation_id,
                        expires_at_ms: lookup.expires_at_ms,
                    },
                );
            }
        }
        store.finish_contact_invite_action(
            lookup.action_id,
            Ok(if dialed > 0 {
                "searching"
            } else {
                "no_candidates"
            }),
        )?;
        Ok(())
    }

    pub(super) fn observe_contact_invite_operation(&mut self, event: &AdmittedNetworkEvent) {
        match event {
            AdmittedNetworkEvent::OperationAccepted { operation_id } => {
                self.contact_invites.publishing.remove(operation_id);
            }
            AdmittedNetworkEvent::OperationFailed { operation_id, .. } => {
                if let Some((invite_id, true)) =
                    self.contact_invites.publishing.remove(operation_id)
                {
                    self.contact_invites.published.remove(&invite_id);
                }
                self.contact_invites
                    .dialing
                    .retain(|_, attempt| attempt.operation_id != *operation_id);
            }
            _ => {}
        }
    }

    pub(super) fn handle_contact_invite_event(
        &mut self,
        event: &AdmittedNetworkEvent,
        now_ms: u64,
    ) -> Result<Option<NetworkCommand>, AslError> {
        match event {
            AdmittedNetworkEvent::PeerAdmitted {
                connection_id,
                peer_id,
                agent_id,
            } => {
                let Some(attempt) = self.contact_invites.dialing.remove(peer_id) else {
                    return Ok(None);
                };
                let source = attempt.source;
                let controller = self
                    .admission
                    .as_mut()
                    .ok_or(AslError::InvalidIdentity)?
                    .verified_controller(*agent_id, now_ms)?;
                let invite = match source {
                    ImportSource::Discovery(discovery) => {
                        if *agent_id != discovery.inviter {
                            return Ok(Some(NetworkCommand::CloseConnection {
                                connection_id: *connection_id,
                            }));
                        }
                        contact_invite::verify(&discovery, now_ms, controller)?;
                        contact_invite::target_invite(
                            &self.agent_identity,
                            *agent_id,
                            "Contact request.",
                            &discovery,
                            now_ms,
                        )?
                    }
                    ImportSource::ShortCode {
                        token,
                        expected_inviter,
                        expected_peer,
                    } => {
                        if *agent_id != expected_inviter || *peer_id != expected_peer {
                            return Ok(Some(NetworkCommand::CloseConnection {
                                connection_id: *connection_id,
                            }));
                        }
                        contact_invite::target_invite_for_token(
                            &self.agent_identity,
                            *agent_id,
                            "Contact request.",
                            token,
                            now_ms,
                        )?
                    }
                };
                let request_id = fresh_id()?;
                self.contact_invites.outgoing.insert(
                    request_id,
                    OutgoingAttempt {
                        invite: invite.clone(),
                        connection_id: *connection_id,
                        expires_at_ms: invite.expires_at_ms,
                    },
                );
                Ok(Some(NetworkCommand::RequestPairing {
                    connection_id: *connection_id,
                    request_id,
                    invite,
                }))
            }
            AdmittedNetworkEvent::PairingInviteReceived {
                connection_id,
                agent_id,
                response_id,
                invite,
            } => {
                let mut store = open_store(&self.state_database)?;
                let active = store.active_contact_invites(now_ms)?;
                let discovery = active.into_iter().find(|candidate| {
                    candidate.agent_id == self.agent_identity.agent_id()
                        && contact_invite::token_hash(candidate.token) == invite.nonce
                });
                let Some(discovery) = discovery else {
                    return Ok(Some(NetworkCommand::CloseConnection {
                        connection_id: *connection_id,
                    }));
                };
                let controller = self
                    .admission
                    .as_mut()
                    .ok_or(AslError::InvalidIdentity)?
                    .verified_controller(*agent_id, now_ms)?;
                crate::pairing::validate_incoming_invite(
                    invite,
                    *agent_id,
                    self.agent_identity.agent_id(),
                    now_ms,
                    controller,
                    Some(invite.nonce),
                )?;
                let request_mode = store.contact_request_mode()?;
                if request_mode == ContactRequestMode::Reject {
                    return Ok(Some(NetworkCommand::CloseConnection {
                        connection_id: *connection_id,
                    }));
                }
                if !store.allow_pairing_prompt(*agent_id, invite.invite_id, now_ms)? {
                    return Ok(Some(NetworkCommand::CloseConnection {
                        connection_id: *connection_id,
                    }));
                }
                if request_mode == ContactRequestMode::AutoAccept {
                    let (remote_agent, remote_peer) = self
                        .admission
                        .as_mut()
                        .ok_or(AslError::InvalidIdentity)?
                        .admitted_peer_identity(*connection_id, now_ms)?;
                    if remote_agent != *agent_id
                        || store.is_contact_binding_revoked(remote_agent)?
                    {
                        return Ok(Some(NetworkCommand::CloseConnection {
                            connection_id: *connection_id,
                        }));
                    }
                    self.answer_pairing_invite(
                        *connection_id,
                        *response_id,
                        invite.clone(),
                        PairingAuthorization::Approve,
                        now_ms,
                    )?;
                    store.consume_contact_invite(discovery.invite_id, now_ms, true)?;
                    bind_verified_contact(&mut store, remote_agent, &remote_peer, now_ms)?;
                    return Ok(None);
                }
                let prompt_id = Id128(fresh_id()?);
                let tag = alloy_primitives::hex::encode(invite.invite_id.0);
                let note = if invite.note.is_empty() {
                    "Contact request."
                } else {
                    invite.note.as_str()
                };
                let note = note.chars().take(80).collect::<String>();
                store.upsert_contact_invite_prompt(
                    prompt_id,
                    &tag,
                    invite.invite_id,
                    *agent_id,
                    &note,
                    invite.expires_at_ms,
                    now_ms,
                )?;
                if !self.pending_pairing_prompts.insert(
                    *connection_id,
                    *response_id,
                    invite.clone(),
                ) {
                    let _ = store.decide_contact_invite_prompt(prompt_id, now_ms, false);
                    return Ok(Some(NetworkCommand::CloseConnection {
                        connection_id: *connection_id,
                    }));
                }
                self.contact_invites.prompts.insert(
                    prompt_id,
                    PendingPrompt {
                        connection_id: *connection_id,
                        response_id: *response_id,
                        pairing: invite.clone(),
                        discovery_invite_id: discovery.invite_id,
                        expires_at_ms: invite.expires_at_ms,
                    },
                );
                Ok(None)
            }
            AdmittedNetworkEvent::PairingExchangeReceived {
                connection_id,
                agent_id,
                request_id,
                invite,
                exchange,
            } => {
                let Some(attempt) = self.contact_invites.outgoing.remove(request_id) else {
                    return Ok(Some(NetworkCommand::CloseConnection {
                        connection_id: *connection_id,
                    }));
                };
                let sent_invite = attempt.invite;
                if sent_invite != *invite || exchange.agent_id != *agent_id {
                    return Ok(Some(NetworkCommand::CloseConnection {
                        connection_id: *connection_id,
                    }));
                }
                verify_exchange(self, *connection_id, invite, exchange, now_ms)?;
                Ok(None)
            }
            AdmittedNetworkEvent::PeerDisconnected {
                connection_id,
                peer_id,
                ..
            } => {
                if let Some(peer_id) = peer_id {
                    self.contact_invites.dialing.remove(peer_id);
                }
                self.contact_invites
                    .outgoing
                    .retain(|_, attempt| attempt.connection_id != *connection_id);
                let prompt_ids = self
                    .contact_invites
                    .prompts
                    .iter()
                    .filter_map(|(prompt_id, prompt)| {
                        (prompt.connection_id == *connection_id).then_some(*prompt_id)
                    })
                    .collect::<Vec<_>>();
                if !prompt_ids.is_empty() {
                    let mut store = open_store(&self.state_database)?;
                    for prompt_id in prompt_ids {
                        self.contact_invites.prompts.remove(&prompt_id);
                        let _ = store.decide_contact_invite_prompt(prompt_id, now_ms, false);
                    }
                }
                Ok(None)
            }
            AdmittedNetworkEvent::RequestFailed {
                request_id,
                protocol: crate::ipc::NetworkProtocol::Pairing,
                ..
            } => {
                self.contact_invites.outgoing.remove(request_id);
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    fn sync_contact_invite_publications(
        &mut self,
        store: &asl_store::Store,
        now_ms: u64,
    ) -> Result<(), AslError> {
        let active = store.active_contact_invites(now_ms)?;
        let active_ids = active
            .iter()
            .map(|invite| invite.invite_id)
            .collect::<HashSet<_>>();
        for invite in &active {
            if self
                .contact_invites
                .published
                .contains_key(&invite.invite_id)
                || self
                    .contact_invites
                    .publishing
                    .values()
                    .any(|(id, _)| *id == invite.invite_id)
            {
                continue;
            }
            let operation_id = fresh_id()?;
            let key: [u8; 32] = contact_invite_key(invite.token)?
                .as_ref()
                .try_into()
                .map_err(|_| AslError::InvalidMessage)?;
            if self
                .send_network_command(NetworkCommand::StartProviding { operation_id, key })
                .is_ok()
            {
                self.contact_invites
                    .publishing
                    .insert(operation_id, (invite.invite_id, true));
                self.contact_invites
                    .published
                    .insert(invite.invite_id, invite.token);
            }
        }
        for (invite_id, token) in self
            .contact_invites
            .published
            .iter()
            .map(|(id, token)| (*id, *token))
            .collect::<Vec<_>>()
        {
            if active_ids.contains(&invite_id) {
                continue;
            }
            let operation_id = fresh_id()?;
            let key: [u8; 32] = contact_invite_key(token)?
                .as_ref()
                .try_into()
                .map_err(|_| AslError::InvalidMessage)?;
            if self
                .send_network_command(NetworkCommand::StopProviding { operation_id, key })
                .is_ok()
            {
                self.contact_invites
                    .publishing
                    .insert(operation_id, (invite_id, false));
                self.contact_invites.published.remove(&invite_id);
            }
        }
        Ok(())
    }

    fn process_contact_invite_actions(
        &mut self,
        store: &mut asl_store::Store,
        now_ms: u64,
    ) -> Result<(), AslError> {
        store.resume_contact_invite_actions()?;
        if self.contact_invites.lookups.len() >= MAX_IMPORT_LOOKUPS {
            return Ok(());
        }
        for action in store.claim_contact_invite_actions()? {
            let result = match (action.kind, action.payload) {
                (
                    asl_store::contact_invites::ContactInviteActionKind::Import,
                    asl_store::contact_invites::ContactInviteActionPayload::Envelope(envelope),
                ) => self.begin_contact_invite_import(action.action_id, Some(&envelope), now_ms),
                (
                    asl_store::contact_invites::ContactInviteActionKind::Decide,
                    asl_store::contact_invites::ContactInviteActionPayload::Prompt(_),
                ) => Ok("decision_pending"),
                (
                    asl_store::contact_invites::ContactInviteActionKind::Add,
                    asl_store::contact_invites::ContactInviteActionPayload::Envelope(_),
                ) => Ok("managed_by_supervisor"),
                _ => Err("invalid_action"),
            };
            store.finish_contact_invite_action(action.action_id, result)?;
        }
        Ok(())
    }

    fn begin_contact_invite_import(
        &mut self,
        action_id: i64,
        envelope: Option<&[u8]>,
        now_ms: u64,
    ) -> Result<&'static str, &'static str> {
        let envelope = envelope
            .and_then(|value| std::str::from_utf8(value).ok())
            .ok_or("invalid_envelope")?;
        let source = if let Ok(invite) = ContactInviteV1::from_envelope(envelope, now_ms) {
            if invite.inviter == self.agent_identity.agent_id() {
                return Err("self_invite");
            }
            let controller = self
                .admission
                .as_mut()
                .ok_or("identity_unavailable")?
                .verified_controller(invite.inviter, now_ms)
                .map_err(|_| "identity_unavailable")?;
            contact_invite::verify(&invite, now_ms, controller).map_err(|_| "invalid_signature")?;
            ImportSource::Discovery(invite)
        } else {
            let (expected_inviter, expected_peer, token) =
                contact_invite::parse_short_code_envelope(envelope)
                    .map_err(|_| "invalid_envelope")?;
            ImportSource::ShortCode {
                token,
                expected_inviter,
                expected_peer,
            }
        };
        let token = match &source {
            ImportSource::Discovery(invite) => invite.token,
            ImportSource::ShortCode { token, .. } => *token,
        };
        let lookup_id = fresh_id().map_err(|_| "unavailable")?;
        let key: [u8; 32] = contact_invite_key(token)
            .map_err(|_| "invalid_envelope")?
            .as_ref()
            .try_into()
            .map_err(|_| "invalid_envelope")?;
        self.send_network_command(NetworkCommand::FindProviders { lookup_id, key })
            .map_err(|_| "unavailable")?;
        self.contact_invites.lookups.insert(
            lookup_id,
            ImportLookup {
                action_id,
                source,
                expires_at_ms: now_ms.saturating_add(LOOKUP_LIFETIME_MS),
            },
        );
        Ok("searching")
    }

    fn process_contact_invite_decisions(
        &mut self,
        store: &mut asl_store::Store,
        now_ms: u64,
    ) -> Result<(), AslError> {
        let prompts = self
            .contact_invites
            .prompts
            .iter()
            .map(|(id, prompt)| (*id, prompt.expires_at_ms))
            .collect::<Vec<_>>();
        for (prompt_id, expires_at_ms) in prompts {
            if now_ms >= expires_at_ms {
                self.contact_invites.prompts.remove(&prompt_id);
                continue;
            }
            let Some(prompt) = store.contact_invite_prompt(prompt_id, now_ms)? else {
                continue;
            };
            let (mut authorization, mut accepted) = match prompt.state {
                ContactInvitePromptState::Pending => continue,
                ContactInvitePromptState::Approved => (PairingAuthorization::Approve, true),
                ContactInvitePromptState::Rejected => (PairingAuthorization::Reject, false),
                ContactInvitePromptState::Expired => {
                    self.contact_invites.prompts.remove(&prompt_id);
                    continue;
                }
            };
            let Some(pending) = self.contact_invites.prompts.get(&prompt_id).cloned() else {
                continue;
            };
            let (remote_agent, remote_peer) = self
                .admission
                .as_mut()
                .ok_or(AslError::InvalidIdentity)?
                .admitted_peer_identity(pending.connection_id, now_ms)?;
            if remote_agent != pending.pairing.inviter {
                return Err(AslError::InvalidIdentity);
            }
            if accepted && store.is_contact_binding_revoked(remote_agent)? {
                authorization = PairingAuthorization::Reject;
                accepted = false;
            }
            self.answer_pairing_invite(
                pending.connection_id,
                pending.response_id,
                pending.pairing.clone(),
                authorization,
                now_ms,
            )?;
            self.pending_pairing_prompts
                .complete(pending.pairing.invite_id.0);
            self.contact_invites.prompts.remove(&prompt_id);
            store.consume_contact_invite(pending.discovery_invite_id, now_ms, accepted)?;
            if accepted {
                bind_verified_contact(store, remote_agent, &remote_peer, now_ms)?;
            }
        }
        Ok(())
    }
}

fn bind_verified_contact(
    store: &mut asl_store::Store,
    agent_id: asl_types::ids::AgentId,
    peer_id: &PeerId,
    now_ms: u64,
) -> Result<(), AslError> {
    if store.is_contact_binding_revoked(agent_id)? {
        return Err(AslError::PolicyDenied);
    }
    if store.contact_binding_state(agent_id)? == Some(ContactBindingState::Bound) {
        return Ok(());
    }
    let code = short_code(agent_id);
    if store.record_contact_binding_candidate(agent_id, peer_id, code, now_ms)? {
        store.approve_contact_binding(agent_id, peer_id, code, now_ms)?;
    }
    Ok(())
}

fn verify_exchange(
    supervisor: &mut Supervisor,
    connection_id: [u8; 16],
    invite: &PairingInvite,
    exchange: &PairingExchange,
    now_ms: u64,
) -> Result<(), AslError> {
    let admission = supervisor
        .admission
        .as_mut()
        .ok_or(AslError::InvalidIdentity)?;
    let mut store = open_store(&supervisor.state_database)?;
    crate::pairing::verify_signed_exchange(
        &supervisor.agent_identity,
        admission,
        &mut store,
        &supervisor.device_peer_id,
        connection_id,
        invite,
        exchange,
        now_ms,
    )?;
    Ok(())
}

fn invite_provider_dial(
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

#[cfg(test)]
mod tests {
    use super::*;
    use asl_types::ids::AgentId;

    fn peer(seed: u8) -> PeerId {
        let key = libp2p_identity::Keypair::ed25519_from_bytes([seed; 32]).unwrap();
        PeerId::from_bytes(key.public().to_peer_id().to_bytes()).unwrap()
    }

    #[test]
    fn accepted_request_creates_binding_without_contact_access() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = open_store(&directory.path().join("asl.sqlite3")).unwrap();
        let agent = AgentId([41; 32]);
        let peer = peer(42);

        bind_verified_contact(&mut store, agent, &peer, 100).unwrap();

        assert_eq!(
            store.contact_binding_state(agent).unwrap(),
            Some(ContactBindingState::Bound)
        );
        assert!(!store.authorized_contacts().unwrap().contains(&agent));
        store.revoke_contact_binding(agent, 101).unwrap();
        assert!(matches!(
            bind_verified_contact(&mut store, agent, &peer, 102),
            Err(AslError::PolicyDenied)
        ));
    }
}
