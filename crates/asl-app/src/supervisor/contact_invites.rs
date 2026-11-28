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
    ids::{Hash32, Id128, PeerId},
    protocol::{
        ContactProvenance, PairingExchange, PairingInvite, PakeAnswer, PakeConfirm, PakeReceipt,
        PakeStart, WireFrame,
    },
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
    PakeCode {
        token: Id128,
        expected_inviter: asl_types::ids::AgentId,
        expected_peer: PeerId,
        invite_id: Id128,
        code_digits: u8,
        expires_at_ms: u64,
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

#[derive(Clone, Copy)]
enum RequestSource {
    Manual,
    SharedGroup {
        group_id: Hash32,
        membership_epoch: u64,
    },
    RecentInteraction {
        interaction_id: Id128,
        expires_at_ms: u64,
    },
    SignedRemote(ContactProvenance),
}

impl RequestSource {
    fn allows(
        self,
        store: &asl_store::Store,
        agent_id: asl_types::ids::AgentId,
        peer_id: &PeerId,
        now_ms: u64,
    ) -> Result<bool, AslError> {
        match self {
            Self::Manual => Ok(true),
            Self::SharedGroup {
                group_id,
                membership_epoch,
            } => Ok(store
                .shared_active_group_evidence(agent_id, peer_id)?
                .is_some_and(|(current_group, current_epoch)| {
                    current_epoch >= membership_epoch
                        && (current_group == group_id
                            || store
                                .mls_logical_root(group_id)
                                .is_ok_and(|root| root == current_group))
                })),
            Self::RecentInteraction {
                interaction_id,
                expires_at_ms,
            } => {
                let policy = store.contact_request_policy()?;
                Ok(policy.recent_interaction_ttl_ms > 0
                    && now_ms < expires_at_ms
                    && store
                        .recent_contact_interaction_evidence(agent_id, peer_id, now_ms)?
                        .is_some_and(|evidence| {
                            evidence.interaction_id == interaction_id
                                && evidence.expires_at_ms > now_ms
                        }))
            }
            Self::SignedRemote(provenance) => match provenance {
                ContactProvenance::SharedGroup {
                    group_id,
                    membership_epoch,
                } => Ok(store
                    .shared_active_group_evidence(agent_id, peer_id)?
                    .is_some_and(|(current_group, current_epoch)| {
                        current_epoch >= membership_epoch
                            && (current_group == group_id
                                || store
                                    .mls_logical_root(group_id)
                                    .is_ok_and(|root| root == current_group))
                    })),
                ContactProvenance::RecentInteraction {
                    interaction_id,
                    expires_at_ms,
                } => {
                    let policy = store.contact_request_policy()?;
                    Ok(policy.recent_interaction_ttl_ms > 0
                        && now_ms < expires_at_ms
                        && store
                            .recent_contact_interaction_evidence(agent_id, peer_id, now_ms)?
                            .is_some_and(|evidence| {
                                evidence.interaction_id == interaction_id
                                    && evidence.expires_at_ms > now_ms
                            }))
                }
            },
        }
    }
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
        self.pake = crate::pairing::PakeRuntime::default();
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
        for expired in self.pake.expire(now_ms) {
            let (connection_id, exchange_id) = expired;
            if let Some(exchange_id) = exchange_id {
                let mut store = open_store(&self.state_database)?;
                let _ = store.consume_contact_invite(exchange_id, now_ms, false);
                self.pake.clear_connection(connection_id);
            }
            self.queue_disconnect(connection_id)?;
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
                ImportSource::PakeCode { expected_peer, .. } => *expected_peer != provider.peer_id,
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

    pub(super) fn handle_pake_event(
        &mut self,
        event: &AdmittedNetworkEvent,
        now_ms: u64,
    ) -> Result<bool, AslError> {
        let connection_id = match event {
            AdmittedNetworkEvent::ControlRequest {
                connection_id,
                request: WireFrame::PakeStart(_) | WireFrame::PakeConfirm(_),
                ..
            }
            | AdmittedNetworkEvent::ControlResponse {
                connection_id,
                response: WireFrame::PakeAnswer(_) | WireFrame::PakeReceipt(_),
                ..
            } => Some(*connection_id),
            _ => None,
        };
        let Some(connection_id) = connection_id else {
            return Ok(false);
        };
        let result = match event {
            AdmittedNetworkEvent::ControlRequest {
                connection_id,
                agent_id,
                response_id,
                request: WireFrame::PakeStart(start),
            } => self.accept_pake_start(*connection_id, *agent_id, *response_id, start, now_ms),
            AdmittedNetworkEvent::ControlRequest {
                connection_id,
                agent_id,
                response_id,
                request: WireFrame::PakeConfirm(confirm),
            } => self.accept_pake_confirm(*connection_id, *agent_id, *response_id, confirm, now_ms),
            AdmittedNetworkEvent::ControlResponse {
                connection_id,
                agent_id,
                request_id,
                response: WireFrame::PakeAnswer(answer),
            } => self.accept_pake_answer(*connection_id, *agent_id, *request_id, answer, now_ms),
            AdmittedNetworkEvent::ControlResponse {
                connection_id,
                agent_id,
                request_id,
                response: WireFrame::PakeReceipt(receipt),
            } => self.accept_pake_receipt(*connection_id, *agent_id, *request_id, receipt, now_ms),
            _ => Ok(()),
        };
        if result.is_err() {
            if let AdmittedNetworkEvent::ControlRequest {
                request: WireFrame::PakeConfirm(confirm),
                ..
            } = event
            {
                let mut store = open_store(&self.state_database)?;
                let _ = store.consume_contact_invite(confirm.exchange_id, now_ms, false);
            }
            self.queue_disconnect(connection_id)?;
        }
        Ok(true)
    }

    fn accept_pake_start(
        &mut self,
        connection_id: [u8; 16],
        agent_id: asl_types::ids::AgentId,
        response_id: [u8; 16],
        start: &PakeStart,
        now_ms: u64,
    ) -> Result<(), AslError> {
        if start.owner != self.agent_identity.agent_id()
            || start.joiner != agent_id
            || start.owner_peer != self.device_peer_id
            || start.expires_at_ms <= now_ms
        {
            return Err(AslError::InvalidIdentity);
        }
        let mut store = open_store(&self.state_database)?;
        let invite = store
            .find_active_contact_invite_by_id(start.exchange_id, now_ms)?
            .ok_or(AslError::InvalidMessage)?;
        if invite.agent_id != self.agent_identity.agent_id()
            || invite.expires_at_ms != start.expires_at_ms
        {
            return Err(AslError::InvalidMessage);
        }
        let (digits, code) = contact_invite::pake_token_parts(invite.token)?;
        if digits != start.code_digits {
            return Err(AslError::InvalidMessage);
        }
        let (remote_agent, remote_peer) = self
            .admission
            .as_mut()
            .ok_or(AslError::InvalidIdentity)?
            .admitted_peer_identity(connection_id, now_ms)?;
        if remote_agent != agent_id || remote_peer != start.joiner_peer {
            return Err(AslError::InvalidIdentity);
        }
        if !store.claim_contact_invite_attempt(start.exchange_id, now_ms)? {
            return Err(AslError::PolicyDenied);
        }
        let controller = self
            .admission
            .as_mut()
            .ok_or(AslError::InvalidIdentity)?
            .verified_controller(agent_id, now_ms)?;
        let code = format!("{:0width$}", code, width = usize::from(digits));
        let (session, answer) = crate::pairing::PakeOwner::start(
            &self.agent_identity,
            start,
            &code,
            controller,
            now_ms,
        )?;
        self.pake.insert_owner(
            start.exchange_id,
            crate::pairing::OwnerAttempt {
                connection_id,
                response_id,
                session,
            },
        )?;
        if let Err(error) = self.send_admitted_network_command(
            NetworkCommand::ReplyControl {
                connection_id,
                response_id,
                response: WireFrame::PakeAnswer(answer),
            },
            now_ms,
        ) {
            self.pake.take_owner(start.exchange_id);
            return Err(error);
        }
        Ok(())
    }

    fn accept_pake_confirm(
        &mut self,
        connection_id: [u8; 16],
        agent_id: asl_types::ids::AgentId,
        response_id: [u8; 16],
        confirm: &PakeConfirm,
        now_ms: u64,
    ) -> Result<(), AslError> {
        let attempt = self
            .pake
            .take_owner(confirm.exchange_id)
            .ok_or(AslError::InvalidMessage)?;
        if attempt.connection_id != connection_id
            || attempt.session.binding().joiner != agent_id
            || confirm.owner != self.agent_identity.agent_id()
        {
            return Err(AslError::InvalidIdentity);
        }
        let controller = self
            .admission
            .as_mut()
            .ok_or(AslError::InvalidIdentity)?
            .verified_controller(agent_id, now_ms)?;
        attempt
            .session
            .finish_confirm(confirm, controller, now_ms)?;
        let (_, remote_peer) = self
            .admission
            .as_mut()
            .ok_or(AslError::InvalidIdentity)?
            .admitted_peer_identity(connection_id, now_ms)?;
        let mut store = open_store(&self.state_database)?;
        let accepted = !store.is_contact_binding_revoked(agent_id)?;
        if accepted {
            if !store.consume_contact_invite(confirm.exchange_id, now_ms, true)? {
                return Err(AslError::InvalidMessage);
            }
            bind_verified_contact(&mut store, agent_id, &remote_peer, now_ms)?;
        } else {
            if !store.consume_contact_invite(confirm.exchange_id, now_ms, false)? {
                return Err(AslError::InvalidMessage);
            }
        }
        let receipt = attempt.session.receipt(&self.agent_identity, accepted)?;
        self.send_admitted_network_command(
            NetworkCommand::ReplyControl {
                connection_id,
                response_id,
                response: WireFrame::PakeReceipt(receipt),
            },
            now_ms,
        )
    }

    fn accept_pake_answer(
        &mut self,
        connection_id: [u8; 16],
        agent_id: asl_types::ids::AgentId,
        request_id: [u8; 16],
        answer: &PakeAnswer,
        now_ms: u64,
    ) -> Result<(), AslError> {
        let mut attempt = self
            .pake
            .take_joiner(request_id)
            .ok_or(AslError::InvalidMessage)?;
        if attempt.connection_id != connection_id || attempt.session.binding().owner != agent_id {
            return Err(AslError::InvalidIdentity);
        }
        let controller = self
            .admission
            .as_mut()
            .ok_or(AslError::InvalidIdentity)?
            .verified_controller(agent_id, now_ms)?;
        let confirm =
            attempt
                .session
                .finish_answer(&self.agent_identity, answer, controller, now_ms)?;
        let next_request_id = fresh_id()?;
        let connection_id = attempt.connection_id;
        self.pake
            .insert_joiner(next_request_id, connection_id, attempt.session)?;
        self.send_admitted_network_command(
            NetworkCommand::SendControl {
                connection_id,
                request_id: next_request_id,
                request: WireFrame::PakeConfirm(confirm),
            },
            now_ms,
        )
    }

    fn accept_pake_receipt(
        &mut self,
        connection_id: [u8; 16],
        agent_id: asl_types::ids::AgentId,
        request_id: [u8; 16],
        receipt: &PakeReceipt,
        now_ms: u64,
    ) -> Result<(), AslError> {
        let attempt = self
            .pake
            .take_joiner(request_id)
            .ok_or(AslError::InvalidMessage)?;
        if attempt.connection_id != connection_id || attempt.session.binding().owner != agent_id {
            return Err(AslError::InvalidIdentity);
        }
        let controller = self
            .admission
            .as_mut()
            .ok_or(AslError::InvalidIdentity)?
            .verified_controller(agent_id, now_ms)?;
        if attempt.session.finish_receipt(receipt, controller)? {
            let (_, remote_peer) = self
                .admission
                .as_mut()
                .ok_or(AslError::InvalidIdentity)?
                .admitted_peer_identity(connection_id, now_ms)?;
            let mut store = open_store(&self.state_database)?;
            bind_verified_contact(
                &mut store,
                attempt.session.binding().owner,
                &remote_peer,
                now_ms,
            )?;
        }
        Ok(())
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
                if let ImportSource::PakeCode {
                    token,
                    expected_inviter,
                    expected_peer,
                    invite_id,
                    code_digits,
                    expires_at_ms,
                } = &source
                {
                    if *agent_id != *expected_inviter
                        || *peer_id != *expected_peer
                        || *expires_at_ms <= now_ms
                    {
                        return Ok(Some(NetworkCommand::CloseConnection {
                            connection_id: *connection_id,
                        }));
                    }
                    let code = contact_invite::pake_token_parts(*token)
                        .and_then(|(digits, code)| {
                            if digits != *code_digits {
                                return Err(AslError::InvalidMessage);
                            }
                            Ok(format!("{:0width$}", code, width = usize::from(digits)))
                        })
                        .map_err(|_| AslError::InvalidMessage)?;
                    let (joiner, start) = crate::pairing::PakeJoiner::start(
                        &self.agent_identity,
                        *invite_id,
                        *agent_id,
                        self.agent_identity.agent_id(),
                        peer_id.clone(),
                        self.device_peer_id.clone(),
                        *expires_at_ms,
                        *code_digits,
                        &code,
                        now_ms,
                    )?;
                    let request_id = fresh_id()?;
                    self.pake
                        .insert_joiner(request_id, *connection_id, joiner)?;
                    return Ok(Some(NetworkCommand::SendControl {
                        connection_id: *connection_id,
                        request_id,
                        request: WireFrame::PakeStart(start),
                    }));
                }
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
                    ImportSource::PakeCode { .. } => unreachable!("handled above"),
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
                let request_policy = store.contact_request_policy()?;
                if request_policy.mode == ContactRequestMode::Reject {
                    return Ok(Some(NetworkCommand::CloseConnection {
                        connection_id: *connection_id,
                    }));
                }
                if !store.allow_pairing_prompt(*agent_id, invite.invite_id, now_ms)? {
                    return Ok(Some(NetworkCommand::CloseConnection {
                        connection_id: *connection_id,
                    }));
                }
                let (remote_agent, remote_peer) = self
                    .admission
                    .as_mut()
                    .ok_or(AslError::InvalidIdentity)?
                    .admitted_peer_identity(*connection_id, now_ms)?;
                if remote_agent != *agent_id || store.is_contact_binding_revoked(remote_agent)? {
                    return Ok(Some(NetworkCommand::CloseConnection {
                        connection_id: *connection_id,
                    }));
                }
                let source = if request_policy.mode == ContactRequestMode::AutoAccept {
                    Some(RequestSource::Manual)
                } else if request_policy.mode == ContactRequestMode::Review {
                    let remote_source = invite.provenance.and_then(|provenance| match provenance {
                        ContactProvenance::SharedGroup { .. }
                            if request_policy.shared_group_auto_accept =>
                        {
                            Some(RequestSource::SignedRemote(provenance))
                        }
                        ContactProvenance::RecentInteraction { .. }
                            if request_policy.recent_interaction_ttl_ms > 0 =>
                        {
                            Some(RequestSource::SignedRemote(provenance))
                        }
                        _ => None,
                    });
                    let remote_source = match remote_source {
                        Some(source)
                            if source.allows(&store, remote_agent, &remote_peer, now_ms)? =>
                        {
                            Some(source)
                        }
                        _ => None,
                    };
                    let mut source = if let Some(source) = remote_source {
                        Some(source)
                    } else if request_policy.shared_group_auto_accept {
                        store
                            .shared_active_group_evidence(remote_agent, &remote_peer)?
                            .map(|(group_id, membership_epoch)| RequestSource::SharedGroup {
                                group_id,
                                membership_epoch,
                            })
                    } else {
                        None
                    };
                    if source.is_none() {
                        source = if request_policy.recent_interaction_ttl_ms > 0 {
                            store
                                .recent_contact_interaction_evidence(
                                    remote_agent,
                                    &remote_peer,
                                    now_ms,
                                )?
                                .map(|evidence| RequestSource::RecentInteraction {
                                    interaction_id: evidence.interaction_id,
                                    expires_at_ms: evidence.expires_at_ms,
                                })
                        } else {
                            None
                        };
                    }
                    /*
                     * A remote provenance claim is signed by the inviter but
                     * is not proof by itself. `SignedRemote::allows` still
                     * rechecks the local group/epoch or interaction evidence.
                     */
                    source
                } else {
                    None
                };
                if let Some(source) = source {
                    self.answer_pairing_invite(
                        *connection_id,
                        *response_id,
                        invite.clone(),
                        PairingAuthorization::Approve,
                        now_ms,
                    )?;
                    if !source.allows(&store, remote_agent, &remote_peer, now_ms)? {
                        return Err(AslError::PolicyVersionConflict);
                    }
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
                store.upsert_contact_invite_prompt_with_provenance(
                    prompt_id,
                    &tag,
                    invite.invite_id,
                    *agent_id,
                    &note,
                    invite.expires_at_ms,
                    invite.provenance,
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
                self.pake.clear_connection(*connection_id);
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
        let source = if let Ok(pake) = contact_invite::parse_pake_code_envelope(envelope) {
            if pake.inviter == self.agent_identity.agent_id() {
                return Err("self_invite");
            }
            if pake.expires_at_ms <= now_ms {
                return Err("expired");
            }
            ImportSource::PakeCode {
                token: pake.token,
                expected_inviter: pake.inviter,
                expected_peer: pake.inviter_peer,
                invite_id: pake.invite_id,
                code_digits: pake.code_digits,
                expires_at_ms: pake.expires_at_ms,
            }
        } else if let Ok(invite) = ContactInviteV1::from_envelope(envelope, now_ms) {
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
            ImportSource::PakeCode { token, .. } => *token,
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
