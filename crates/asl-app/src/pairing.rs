use asl_store::Store;
use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId, Signature65},
    protocol::{PairingExchange, PairingInvite, validate_pairing_note},
};
use rand::{TryRng, rngs::SysRng};
use std::collections::HashMap;

use crate::{
    identity::{AgentIdentity, verify_root_signature},
    profile::CoreAdmission,
};

const INVITE_DOMAIN: &[u8] = b"ASL-PAIR-INVITE-v1\0";
const ACCEPT_DOMAIN: &[u8] = b"ASL-PAIR-DECISION-v1\0";
const INVITE_LIFETIME_MS: u64 = 3 * 60 * 1_000;
const MAX_INVITE_LIFETIME_MS: u64 = 5 * 60 * 1_000;
#[cfg(test)]
pub(crate) const MAX_PENDING_PAIRING_PROMPTS: usize = 5;

#[derive(Default)]
pub(crate) struct PendingPairingPrompts {
    entries: HashMap<[u8; 16], PendingPairingPrompt>,
}

struct PendingPairingPrompt {
    connection_id: [u8; 16],
    response_id: [u8; 16],
    invite: PairingInvite,
}

impl PendingPairingPrompts {
    #[cfg(test)]
    pub(crate) fn can_insert(&self, invite_id: [u8; 16]) -> bool {
        self.entries.len() < MAX_PENDING_PAIRING_PROMPTS && !self.entries.contains_key(&invite_id)
    }

    #[cfg(test)]
    pub(crate) fn insert(
        &mut self,
        connection_id: [u8; 16],
        response_id: [u8; 16],
        invite: PairingInvite,
    ) -> bool {
        if !self.can_insert(invite.invite_id.0) {
            return false;
        }
        self.entries.insert(
            invite.invite_id.0,
            PendingPairingPrompt {
                connection_id,
                response_id,
                invite,
            },
        );
        true
    }

    pub(crate) fn authorizes(
        &self,
        connection_id: [u8; 16],
        response_id: [u8; 16],
        invite: &PairingInvite,
    ) -> bool {
        self.entries
            .get(&invite.invite_id.0)
            .is_some_and(|pending| {
                pending.connection_id == connection_id
                    && pending.response_id == response_id
                    && pending.invite == *invite
            })
    }

    pub(crate) fn complete(&mut self, invite_id: [u8; 16]) {
        self.entries.remove(&invite_id);
    }

    pub(crate) fn remove_connection(&mut self, connection_id: [u8; 16]) {
        self.entries
            .retain(|_, pending| pending.connection_id != connection_id);
    }

    pub(crate) fn expire(&mut self, now_ms: u64) {
        self.entries
            .retain(|_, pending| pending.invite.expires_at_ms > now_ms);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingAuthorization {
    Approve,
    Reject,
}

/// Creates a target-specific, single-use invitation signed by the local
/// identity root. The random nonce is not a password or authentication secret.
pub fn issue_signed_invite(
    identity: &AgentIdentity,
    target: AgentId,
    note: &str,
    now_ms: u64,
) -> Result<PairingInvite, AslError> {
    if target == identity.agent_id() || now_ms > i64::MAX as u64 {
        return Err(AslError::InvalidMessage);
    }
    validate_pairing_note(note)?;
    let expires_at_ms = now_ms
        .checked_add(INVITE_LIFETIME_MS)
        .filter(|expires| *expires <= i64::MAX as u64)
        .ok_or(AslError::InvalidMessage)?;
    let mut random = [0; 16 + 32];
    SysRng
        .try_fill_bytes(&mut random)
        .map_err(|_| AslError::InvalidIdentity)?;
    let invite_id = Id128(
        random[..16]
            .try_into()
            .map_err(|_| AslError::InvalidIdentity)?,
    );
    let nonce = Hash32(
        random[16..]
            .try_into()
            .map_err(|_| AslError::InvalidIdentity)?,
    );
    if invite_id.0 == [0; 16] || nonce.0 == [0; 32] {
        return Err(AslError::InvalidIdentity);
    }
    let mut invite = PairingInvite {
        invite_id,
        inviter: identity.agent_id(),
        target,
        expires_at_ms,
        nonce,
        note: note.to_owned(),
        signature: Signature65([0; Signature65::LENGTH]),
    };
    invite.signature = identity.sign_domain_message(&invite_signing_bytes(&invite)?)?;
    Ok(invite)
}

/// Answers an invitation only after local authorization and verifies its
/// sender against current finalized chain state before consuming the invite.
#[allow(clippy::too_many_arguments)]
pub fn answer_signed_invite(
    identity: &AgentIdentity,
    admission: &mut CoreAdmission,
    store: &mut Store,
    local_peer: &PeerId,
    connection_id: [u8; 16],
    invite: &PairingInvite,
    authorization: PairingAuthorization,
    now_ms: u64,
) -> Result<PairingExchange, AslError> {
    let (remote_agent, remote_peer) = admission.admitted_peer_identity(connection_id, now_ms)?;
    let remote_controller = admission.verified_controller(remote_agent, now_ms)?;
    validate_invite(
        invite,
        remote_agent,
        identity.agent_id(),
        now_ms,
        remote_controller,
    )?;
    let exchange = signed_exchange(
        identity,
        local_peer,
        invite,
        &remote_peer,
        authorization == PairingAuthorization::Approve,
    )?;
    if !store.consume_pairing_invite(
        remote_agent,
        invite.invite_id,
        invite.expires_at_ms,
        now_ms,
        exchange.accepted,
    )? {
        return Err(AslError::InvalidMessage);
    }
    Ok(exchange)
}

fn signed_exchange(
    identity: &AgentIdentity,
    local_peer: &PeerId,
    invite: &PairingInvite,
    remote_peer: &PeerId,
    accepted: bool,
) -> Result<PairingExchange, AslError> {
    let transcript = asl_net::pairing::transcript_hash(invite, remote_peer, local_peer)?;
    let mut exchange = PairingExchange {
        exchange_id: invite.invite_id,
        agent_id: identity.agent_id(),
        peer_id: local_peer.clone(),
        attempt: 1,
        accepted,
        signature: Signature65([0; Signature65::LENGTH]),
        transcript_hash: transcript,
    };
    exchange.signature = identity.sign_domain_message(&acceptance_signing_bytes(&exchange)?)?;
    Ok(exchange)
}

/// Verifies an accepted or rejected response and persists a local AgentId pin
/// only for acceptance. The PeerId is session-bound, not persisted.
#[allow(clippy::too_many_arguments)]
pub fn verify_signed_exchange(
    identity: &AgentIdentity,
    admission: &mut CoreAdmission,
    store: &mut Store,
    local_peer: &PeerId,
    connection_id: [u8; 16],
    invite: &PairingInvite,
    exchange: &PairingExchange,
    now_ms: u64,
) -> Result<bool, AslError> {
    let (remote_agent, remote_peer) = admission.admitted_peer_identity(connection_id, now_ms)?;
    validate_invite(
        invite,
        identity.agent_id(),
        remote_agent,
        now_ms,
        identity.controller_address(),
    )?;
    let remote_controller = admission.verified_controller(remote_agent, now_ms)?;
    let transcript = asl_net::pairing::transcript_hash(invite, local_peer, &remote_peer)?;
    if exchange.exchange_id != invite.invite_id
        || exchange.agent_id != remote_agent
        || exchange.peer_id != remote_peer
        || exchange.attempt != 1
        || exchange.transcript_hash != transcript
    {
        return Err(AslError::InvalidIdentity);
    }
    verify_root_signature(
        &acceptance_signing_bytes(exchange)?,
        exchange.signature,
        remote_controller,
    )?;
    if !store.consume_pairing_invite(
        remote_agent,
        invite.invite_id,
        invite.expires_at_ms,
        now_ms,
        exchange.accepted,
    )? {
        return Err(AslError::InvalidMessage);
    }
    Ok(exchange.accepted)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_signed_acceptance(
    identity: &AgentIdentity,
    admission: &mut CoreAdmission,
    store: &mut Store,
    local_peer: &PeerId,
    connection_id: [u8; 16],
    invite: &PairingInvite,
    exchange: &PairingExchange,
    now_ms: u64,
) -> Result<(), AslError> {
    if verify_signed_exchange(
        identity,
        admission,
        store,
        local_peer,
        connection_id,
        invite,
        exchange,
        now_ms,
    )? {
        Ok(())
    } else {
        Err(AslError::PolicyDenied)
    }
}

fn validate_invite(
    invite: &PairingInvite,
    authenticated_inviter: AgentId,
    expected_target: AgentId,
    now_ms: u64,
    controller: [u8; 20],
) -> Result<(), AslError> {
    if invite.inviter != authenticated_inviter
        || invite.target != expected_target
        || invite.inviter == invite.target
        || invite.invite_id.0 == [0; 16]
        || invite.nonce.0 == [0; 32]
        || invite.expires_at_ms <= now_ms
        || invite.expires_at_ms - now_ms > MAX_INVITE_LIFETIME_MS
    {
        return Err(if invite.expires_at_ms <= now_ms {
            AslError::ExpiredMessage
        } else {
            AslError::InvalidIdentity
        });
    }
    verify_root_signature(&invite_signing_bytes(invite)?, invite.signature, controller)
}

fn invite_signing_bytes(invite: &PairingInvite) -> Result<Vec<u8>, AslError> {
    if invite.invite_id.0 == [0; 16] || invite.inviter == invite.target || invite.nonce.0 == [0; 32]
    {
        return Err(AslError::InvalidMessage);
    }
    validate_pairing_note(&invite.note)?;
    let note_length = u16::try_from(invite.note.len()).map_err(|_| AslError::InvalidMessage)?;
    let mut bytes =
        Vec::with_capacity(INVITE_DOMAIN.len() + 16 + 32 + 32 + 8 + 32 + 2 + invite.note.len());
    bytes.extend_from_slice(INVITE_DOMAIN);
    bytes.extend_from_slice(invite.invite_id.as_bytes());
    bytes.extend_from_slice(invite.inviter.as_bytes());
    bytes.extend_from_slice(invite.target.as_bytes());
    bytes.extend_from_slice(&invite.expires_at_ms.to_be_bytes());
    bytes.extend_from_slice(invite.nonce.as_bytes());
    bytes.extend_from_slice(&note_length.to_be_bytes());
    bytes.extend_from_slice(invite.note.as_bytes());
    Ok(bytes)
}

fn acceptance_signing_bytes(exchange: &PairingExchange) -> Result<Vec<u8>, AslError> {
    if exchange.attempt != 1 {
        return Err(AslError::InvalidMessage);
    }
    let peer = exchange.peer_id.as_bytes();
    let peer_len = u16::try_from(peer.len()).map_err(|_| AslError::InvalidMessage)?;
    let mut bytes = Vec::with_capacity(ACCEPT_DOMAIN.len() + 16 + 32 + 2 + peer.len() + 1 + 32);
    bytes.extend_from_slice(ACCEPT_DOMAIN);
    bytes.extend_from_slice(exchange.exchange_id.as_bytes());
    bytes.extend_from_slice(exchange.agent_id.as_bytes());
    bytes.extend_from_slice(&peer_len.to_be_bytes());
    bytes.extend_from_slice(peer);
    bytes.push(exchange.attempt);
    bytes.push(u8::from(exchange.accepted));
    bytes.extend_from_slice(exchange.transcript_hash.as_bytes());
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::DeviceIdentity;
    use libp2p_identity::Keypair;

    fn peer(seed: u8) -> PeerId {
        let key = Keypair::ed25519_from_bytes([seed; 32]).unwrap();
        PeerId::from_bytes(key.public().to_peer_id().to_bytes()).unwrap()
    }

    #[test]
    fn invite_and_acceptance_signatures_bind_target_devices_and_nonce() {
        let inviter = AgentIdentity::generate().unwrap();
        let target = AgentIdentity::generate().unwrap();
        let inviter_peer = DeviceIdentity::generate().unwrap().peer_id();
        let target_peer = DeviceIdentity::generate().unwrap().peer_id();
        let invite =
            issue_signed_invite(&inviter, target.agent_id(), "Please pair.", 10_000).unwrap();

        validate_invite(
            &invite,
            inviter.agent_id(),
            target.agent_id(),
            11_000,
            inviter.controller_address(),
        )
        .unwrap();
        let transcript =
            asl_net::pairing::transcript_hash(&invite, &inviter_peer, &target_peer).unwrap();
        let mut exchange = PairingExchange {
            exchange_id: invite.invite_id,
            agent_id: target.agent_id(),
            peer_id: target_peer.clone(),
            attempt: 1,
            accepted: true,
            signature: Signature65([0; Signature65::LENGTH]),
            transcript_hash: transcript,
        };
        exchange.signature = target
            .sign_domain_message(&acceptance_signing_bytes(&exchange).unwrap())
            .unwrap();
        verify_root_signature(
            &acceptance_signing_bytes(&exchange).unwrap(),
            exchange.signature,
            target.controller_address(),
        )
        .unwrap();

        let wrong_peer = peer(100);
        assert_ne!(
            asl_net::pairing::transcript_hash(&invite, &inviter_peer, &wrong_peer).unwrap(),
            exchange.transcript_hash
        );

        let mut declined = exchange.clone();
        declined.accepted = false;
        assert_ne!(
            acceptance_signing_bytes(&declined).unwrap(),
            acceptance_signing_bytes(&exchange).unwrap()
        );
    }

    #[test]
    fn invite_is_target_specific_short_lived_and_signed() {
        let inviter = AgentIdentity::generate().unwrap();
        let target = AgentIdentity::generate().unwrap();
        let other = AgentIdentity::generate().unwrap();
        let invite =
            issue_signed_invite(&inviter, target.agent_id(), "Pair with me?", 50_000).unwrap();

        assert!(
            validate_invite(
                &invite,
                inviter.agent_id(),
                other.agent_id(),
                51_000,
                inviter.controller_address(),
            )
            .is_err()
        );
        assert!(matches!(
            validate_invite(
                &invite,
                inviter.agent_id(),
                target.agent_id(),
                invite.expires_at_ms,
                inviter.controller_address(),
            ),
            Err(AslError::ExpiredMessage)
        ));

        let mut forged = invite.clone();
        forged.nonce.0[0] ^= 1;
        assert!(
            validate_invite(
                &forged,
                inviter.agent_id(),
                target.agent_id(),
                51_000,
                inviter.controller_address(),
            )
            .is_err()
        );
    }

    #[test]
    fn invite_note_is_limited_to_one_short_sentence_and_is_signed() {
        let inviter = AgentIdentity::generate().unwrap();
        let target = AgentIdentity::generate().unwrap();
        let invite =
            issue_signed_invite(&inviter, target.agent_id(), "Please pair.", 50_000).unwrap();
        let mut changed = invite.clone();
        changed.note = "Please share files?".into();
        assert!(
            validate_invite(
                &changed,
                inviter.agent_id(),
                target.agent_id(),
                51_000,
                inviter.controller_address(),
            )
            .is_err()
        );
        assert!(
            issue_signed_invite(
                &inviter,
                target.agent_id(),
                &"x".repeat(asl_types::protocol::MAX_PAIRING_NOTE_CHARS + 1),
                50_000,
            )
            .is_err()
        );
        assert!(
            issue_signed_invite(
                &inviter,
                target.agent_id(),
                "First sentence. Second sentence.",
                50_000,
            )
            .is_err()
        );
        assert!(
            issue_signed_invite(&inviter, target.agent_id(), "No\nnew lines.", 50_000,).is_err()
        );
    }

    #[test]
    fn pending_prompts_are_capped_and_bound_to_the_original_request() {
        let identity = AgentIdentity::generate().unwrap();
        let mut pending = PendingPairingPrompts::default();
        let mut first_invite = None;
        for index in 0..MAX_PENDING_PAIRING_PROMPTS {
            let invite =
                issue_signed_invite(&identity, AgentId([index as u8 + 1; 32]), "Pair?", 50_000)
                    .unwrap();
            if index == 0 {
                first_invite = Some(invite.clone());
            }
            assert!(pending.insert([index as u8; 16], [index as u8 + 1; 16], invite,));
        }
        assert!(!pending.can_insert([99; 16]));
        let first_invite = first_invite.unwrap();
        assert!(pending.authorizes([0; 16], [1; 16], &first_invite));
        assert!(!pending.authorizes([1; 16], [1; 16], &first_invite));
        let mut changed = first_invite.clone();
        changed.note = "Different request.".into();
        assert!(!pending.authorizes([0; 16], [1; 16], &changed));

        pending.remove_connection([0; 16]);
        assert!(pending.can_insert([99; 16]));
        let next_invite =
            issue_signed_invite(&identity, AgentId([99; 32]), "Pair?", 50_000).unwrap();
        assert!(pending.insert([99; 16], [100; 16], next_invite.clone()));
        pending.complete(next_invite.invite_id.0);
        pending.expire(50_000 + INVITE_LIFETIME_MS);
        assert_eq!(pending.entries.len(), 0);
    }
}
