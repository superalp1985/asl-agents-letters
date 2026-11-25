use asl_types::{
    contact_invite::{ContactInviteV1, MAX_CONTACT_INVITE_LIFETIME_MS},
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId, Signature65},
    protocol::PairingInvite,
};
use rand::{TryRng, rngs::SysRng};

use crate::{
    identity::{AgentIdentity, verify_root_signature},
    pairing,
};

const TOKEN_HASH_DOMAIN: &[u8] = b"ASL-CONTACT-INVITE-TOKEN-v1\0";
const SHORT_CODE_LIMIT: u64 = 10_000_000_000_000_000;
const SHORT_CODE_SCHEME: &str = "ASL-CONTACT-INVITE-CODE:1:";

pub fn issue(
    identity: &AgentIdentity,
    note: &str,
    now_ms: u64,
    lifetime_ms: u64,
) -> Result<ContactInviteV1, AslError> {
    if lifetime_ms == 0 || lifetime_ms > MAX_CONTACT_INVITE_LIFETIME_MS {
        return Err(AslError::InvalidMessage);
    }
    let expires_at_ms = now_ms
        .checked_add(lifetime_ms)
        .filter(|expires| *expires <= i64::MAX as u64)
        .ok_or(AslError::InvalidMessage)?;
    let mut random = [0; 32];
    SysRng
        .try_fill_bytes(&mut random)
        .map_err(|_| AslError::InvalidIdentity)?;
    let short_code = u64::from_be_bytes(
        random[24..]
            .try_into()
            .map_err(|_| AslError::InvalidIdentity)?,
    ) % SHORT_CODE_LIMIT;
    if short_code == 0 {
        return Err(AslError::InvalidIdentity);
    }
    let mut token = [0; 16];
    token[8..].copy_from_slice(&short_code.to_be_bytes());
    let mut invite = ContactInviteV1 {
        version: asl_types::contact_invite::CONTACT_INVITE_VERSION,
        invite_id: Id128(
            random[..16]
                .try_into()
                .map_err(|_| AslError::InvalidIdentity)?,
        ),
        token: Id128(token),
        inviter: identity.agent_id(),
        created_at_ms: now_ms,
        expires_at_ms,
        note: note.to_owned(),
        signature: Signature65([0; Signature65::LENGTH]),
    };
    invite.validate(now_ms)?;
    invite.signature = identity.sign_domain_message(&invite.signing_preimage(now_ms)?)?;
    Ok(invite)
}

pub fn verify(invite: &ContactInviteV1, now_ms: u64, controller: [u8; 20]) -> Result<(), AslError> {
    invite.validate(now_ms)?;
    verify_root_signature(
        &invite.signing_preimage(now_ms)?,
        invite.signature,
        controller,
    )
}

pub fn token_hash(token: Id128) -> Hash32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(TOKEN_HASH_DOMAIN);
    hasher.update(token.as_bytes());
    Hash32(*hasher.finalize().as_bytes())
}

pub fn short_code(invite: &ContactInviteV1) -> String {
    let code = invite.token.0[8..]
        .try_into()
        .map(u64::from_be_bytes)
        .unwrap_or_default();
    format!("{code:016}")
}

pub fn short_code_envelope(inviter: AgentId, device: &PeerId, invite: &ContactInviteV1) -> String {
    format!(
        "{SHORT_CODE_SCHEME}{}:{}:{}",
        bs58::encode(inviter.as_bytes()).into_string(),
        bs58::encode(device.as_bytes()).into_string(),
        short_code(invite)
    )
}

pub fn parse_short_code_envelope(value: &str) -> Result<(AgentId, PeerId, Id128), AslError> {
    let payload = value
        .strip_prefix(SHORT_CODE_SCHEME)
        .ok_or(AslError::InvalidMessage)?;
    let mut fields = payload.split(':');
    let agent = fields.next().ok_or(AslError::InvalidMessage)?;
    let device = fields.next().ok_or(AslError::InvalidMessage)?;
    let code = fields.next().ok_or(AslError::InvalidMessage)?;
    if fields.next().is_some() {
        return Err(AslError::InvalidMessage);
    }
    let bytes = bs58::decode(agent)
        .into_vec()
        .map_err(|_| AslError::InvalidMessage)?;
    if bs58::encode(&bytes).into_string() != agent {
        return Err(AslError::InvalidMessage);
    }
    let agent = AgentId(bytes.try_into().map_err(|_| AslError::InvalidMessage)?);
    let device: libp2p_identity::PeerId = device.parse().map_err(|_| AslError::InvalidMessage)?;
    let device = PeerId::from_bytes(device.to_bytes()).map_err(|_| AslError::InvalidMessage)?;
    Ok((agent, device, token_from_short_code(code)?))
}

pub fn token_from_short_code(value: &str) -> Result<Id128, AslError> {
    let value = value.trim();
    if value.len() != 16 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(AslError::InvalidMessage);
    }
    let code = value.parse::<u64>().map_err(|_| AslError::InvalidMessage)?;
    if code == 0 || code >= SHORT_CODE_LIMIT {
        return Err(AslError::InvalidMessage);
    }
    let mut token = [0; 16];
    token[8..].copy_from_slice(&code.to_be_bytes());
    Ok(Id128(token))
}

pub fn target_invite_for_token(
    identity: &AgentIdentity,
    inviter: AgentId,
    note: &str,
    token: Id128,
    now_ms: u64,
) -> Result<PairingInvite, AslError> {
    if inviter == identity.agent_id() {
        return Err(AslError::InvalidIdentity);
    }
    let expires_at_ms = now_ms
        .checked_add(pairing::INVITE_LIFETIME_MS)
        .ok_or(AslError::InvalidMessage)?;
    pairing::issue_signed_invite_with_nonce(
        identity,
        inviter,
        note,
        now_ms,
        expires_at_ms,
        token_hash(token),
    )
}

pub fn target_invite(
    identity: &AgentIdentity,
    inviter: AgentId,
    note: &str,
    discovery: &ContactInviteV1,
    now_ms: u64,
) -> Result<PairingInvite, AslError> {
    if discovery.inviter != inviter || inviter == identity.agent_id() {
        return Err(AslError::InvalidIdentity);
    }
    let expires_at_ms = now_ms
        .checked_add(pairing::INVITE_LIFETIME_MS)
        .ok_or(AslError::InvalidMessage)?
        .min(discovery.expires_at_ms);
    pairing::issue_signed_invite_with_nonce(
        identity,
        inviter,
        note,
        now_ms,
        expires_at_ms,
        token_hash(discovery.token),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issued_discovery_invites_are_signed_bounded_and_token_bound() {
        let inviter = AgentIdentity::generate().unwrap();
        let receiver = AgentIdentity::generate().unwrap();
        let now = 1_800_000_000_000;
        let mut invite = issue(&inviter, "Please add me.", now, 60_000).unwrap();
        verify(&invite, now + 1, inviter.controller_address()).unwrap();
        assert_eq!(token_hash(invite.token), token_hash(invite.token));
        assert_eq!(
            token_from_short_code(&short_code(&invite)).unwrap(),
            invite.token
        );
        let device = crate::identity::DeviceIdentity::generate()
            .unwrap()
            .peer_id();
        let code_envelope = short_code_envelope(inviter.agent_id(), &device, &invite);
        assert_eq!(
            parse_short_code_envelope(&code_envelope).unwrap(),
            (inviter.agent_id(), device, invite.token)
        );
        let short_target = target_invite_for_token(
            &receiver,
            inviter.agent_id(),
            "Please add me.",
            invite.token,
            now + 1,
        )
        .unwrap();
        assert_eq!(short_target.nonce, token_hash(invite.token));
        crate::pairing::validate_incoming_invite(
            &short_target,
            receiver.agent_id(),
            inviter.agent_id(),
            now + 2,
            receiver.controller_address(),
            Some(token_hash(invite.token)),
        )
        .unwrap();

        invite.note = "Different note.".into();
        assert!(verify(&invite, now + 1, inviter.controller_address()).is_err());

        let targeted = target_invite(
            &receiver,
            inviter.agent_id(),
            "Please add me.",
            &invite,
            now + 1,
        )
        .unwrap();
        assert_eq!(targeted.inviter, receiver.agent_id());
        assert_eq!(targeted.target, inviter.agent_id());
        assert_eq!(targeted.nonce, token_hash(invite.token));
        crate::pairing::validate_incoming_invite(
            &targeted,
            receiver.agent_id(),
            inviter.agent_id(),
            now + 2,
            receiver.controller_address(),
            Some(token_hash(invite.token)),
        )
        .unwrap();
        assert!(
            crate::pairing::validate_incoming_invite(
                &targeted,
                receiver.agent_id(),
                inviter.agent_id(),
                now + 2,
                receiver.controller_address(),
                Some(token_hash(Id128([9; 16]))),
            )
            .is_err()
        );
        assert!(
            target_invite(
                &receiver,
                inviter.agent_id(),
                "Please add me.",
                &invite,
                invite.expires_at_ms,
            )
            .is_err()
        );
    }
}
