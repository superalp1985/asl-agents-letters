use std::collections::HashMap;

use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId, Signature65},
    protocol::{
        MAX_PAKE_CODE_DIGITS, MAX_PAKE_LIFETIME_MS, MIN_PAKE_CODE_DIGITS, PAKE_SHARE_BYTES,
        PakeAnswer, PakeConfirm, PakeReceipt, PakeStart,
    },
};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use zeroize::Zeroizing;

use crate::identity::{AgentIdentity, verify_root_signature};

const START_DOMAIN: &[u8] = b"ASL-PAKE-START-v1\0";
const ANSWER_DOMAIN: &[u8] = b"ASL-PAKE-ANSWER-v1\0";
const CONFIRM_DOMAIN: &[u8] = b"ASL-PAKE-CONFIRM-v1\0";
const RECEIPT_DOMAIN: &[u8] = b"ASL-PAKE-RECEIPT-v1\0";
const PASSWORD_DOMAIN: &[u8] = b"ASL-PAKE-CODE-v1\0";
const IDENTITY_DOMAIN: &[u8] = b"ASL-PAKE-IDENTITY-v1\0";
const MAX_PENDING_SESSIONS: usize = 8;

pub struct PakeJoiner {
    state: Option<Spake2<Ed25519Group>>,
    key: Option<[u8; 32]>,
    answer_share: Option<[u8; PAKE_SHARE_BYTES]>,
    start: PakeStart,
}

pub struct PakeOwner {
    key: [u8; 32],
    answer_share: [u8; PAKE_SHARE_BYTES],
    start: PakeStart,
}

pub struct JoinerAttempt {
    pub connection_id: [u8; 16],
    pub session: PakeJoiner,
}

pub struct OwnerAttempt {
    pub connection_id: [u8; 16],
    pub response_id: [u8; 16],
    pub session: PakeOwner,
}

#[derive(Default)]
pub struct PakeRuntime {
    joiners: HashMap<[u8; 16], JoinerAttempt>,
    owners: HashMap<[u8; 16], OwnerAttempt>,
}

impl PakeRuntime {
    pub fn insert_joiner(
        &mut self,
        request_id: [u8; 16],
        connection_id: [u8; 16],
        session: PakeJoiner,
    ) -> Result<(), AslError> {
        if self.joiners.len() >= MAX_PENDING_SESSIONS || self.joiners.contains_key(&request_id) {
            return Err(AslError::QuotaExceeded);
        }
        self.joiners.insert(
            request_id,
            JoinerAttempt {
                connection_id,
                session,
            },
        );
        Ok(())
    }

    pub fn take_joiner(&mut self, request_id: [u8; 16]) -> Option<JoinerAttempt> {
        self.joiners.remove(&request_id)
    }

    pub fn insert_owner(
        &mut self,
        exchange_id: Id128,
        attempt: OwnerAttempt,
    ) -> Result<(), AslError> {
        if self.owners.len() >= MAX_PENDING_SESSIONS || self.owners.contains_key(&exchange_id.0) {
            return Err(AslError::QuotaExceeded);
        }
        self.owners.insert(exchange_id.0, attempt);
        Ok(())
    }

    pub fn take_owner(&mut self, exchange_id: Id128) -> Option<OwnerAttempt> {
        self.owners.remove(&exchange_id.0)
    }

    pub fn expire(&mut self, now_ms: u64) -> Vec<([u8; 16], Option<Id128>)> {
        let mut expired = Vec::new();
        self.joiners.retain(|_, attempt| {
            if attempt.session.start.expires_at_ms > now_ms {
                true
            } else {
                expired.push((attempt.connection_id, None));
                false
            }
        });
        self.owners.retain(|_, attempt| {
            if attempt.session.start.expires_at_ms > now_ms {
                true
            } else {
                expired.push((
                    attempt.connection_id,
                    Some(attempt.session.start.exchange_id),
                ));
                false
            }
        });
        expired.sort_unstable_by_key(|(connection_id, _)| *connection_id);
        expired
    }

    pub fn clear_connection(&mut self, connection_id: [u8; 16]) {
        self.joiners
            .retain(|_, attempt| attempt.connection_id != connection_id);
        self.owners
            .retain(|_, attempt| attempt.connection_id != connection_id);
    }
}

impl PakeJoiner {
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        identity: &AgentIdentity,
        exchange_id: Id128,
        owner: AgentId,
        joiner: AgentId,
        owner_peer: PeerId,
        joiner_peer: PeerId,
        expires_at_ms: u64,
        code_digits: u8,
        code: &str,
        now_ms: u64,
    ) -> Result<(Self, PakeStart), AslError> {
        validate_binding(
            exchange_id,
            owner,
            joiner,
            expires_at_ms,
            code_digits,
            now_ms,
        )?;
        if identity.agent_id() != joiner {
            return Err(AslError::InvalidIdentity);
        }
        let password = Zeroizing::new(password_bytes(code, code_digits)?);
        let (id_a, id_b) = spake_identities(exchange_id, joiner, owner, &joiner_peer, &owner_peer);
        let (state, share) = Spake2::<Ed25519Group>::start_a(
            &Password::new(password.as_slice()),
            &Identity::new(&id_a),
            &Identity::new(&id_b),
        );
        let mut start = PakeStart {
            exchange_id,
            owner,
            joiner,
            owner_peer,
            joiner_peer,
            expires_at_ms,
            code_digits,
            share: share
                .as_slice()
                .try_into()
                .map_err(|_| AslError::InvalidMessage)?,
            signature: Signature65([0; Signature65::LENGTH]),
        };
        start.signature = identity.sign_domain_message(&start_signing_bytes(&start)?)?;
        Ok((
            Self {
                state: Some(state),
                key: None,
                answer_share: None,
                start: start.clone(),
            },
            start,
        ))
    }

    pub fn finish_answer(
        &mut self,
        identity: &AgentIdentity,
        answer: &PakeAnswer,
        owner_controller: [u8; 20],
        now_ms: u64,
    ) -> Result<PakeConfirm, AslError> {
        if self.start.exchange_id != answer.exchange_id
            || self.start.owner != answer.owner
            || self.start.joiner != answer.joiner
            || self.start.owner_peer != answer.owner_peer
            || self.start.joiner_peer != answer.joiner_peer
            || self.start.expires_at_ms <= now_ms
            || self.key.is_some()
        {
            return Err(AslError::InvalidMessage);
        }
        verify_root_signature(
            &answer_signing_bytes(&self.start, answer)?,
            answer.signature,
            owner_controller,
        )?;
        let key = self
            .state
            .take()
            .ok_or(AslError::InvalidMessage)?
            .finish(&answer.share)
            .map_err(|_| AslError::InvalidIdentity)?;
        let key: [u8; 32] = key.try_into().map_err(|_| AslError::InvalidMessage)?;
        let transcript = transcript_bytes(&self.start, &answer.share)?;
        if confirmation(&key, ANSWER_DOMAIN, &transcript) != answer.confirmation {
            return Err(AslError::InvalidIdentity);
        }
        self.key = Some(key);
        self.answer_share = Some(answer.share);
        let mut confirm = PakeConfirm {
            exchange_id: self.start.exchange_id,
            owner: self.start.owner,
            joiner: self.start.joiner,
            confirmation: confirmation(&key, CONFIRM_DOMAIN, &transcript),
            signature: Signature65([0; Signature65::LENGTH]),
        };
        confirm.signature =
            identity.sign_domain_message(&confirm_signing_bytes(&self.start, &confirm)?)?;
        Ok(confirm)
    }

    pub fn finish_receipt(
        &self,
        receipt: &PakeReceipt,
        owner_controller: [u8; 20],
    ) -> Result<bool, AslError> {
        if self.start.exchange_id != receipt.exchange_id
            || self.start.owner != receipt.owner
            || self.start.joiner != receipt.joiner
        {
            return Err(AslError::InvalidMessage);
        }
        verify_root_signature(
            &receipt_signing_bytes(&self.start, receipt)?,
            receipt.signature,
            owner_controller,
        )?;
        let key = self.key.ok_or(AslError::InvalidMessage)?;
        let answer_share = self.answer_share.ok_or(AslError::InvalidMessage)?;
        let expected = confirmation(
            &key,
            RECEIPT_DOMAIN,
            &receipt_transcript_bytes(&self.start, &answer_share, receipt.accepted)?,
        );
        if expected != receipt.confirmation {
            return Err(AslError::InvalidIdentity);
        }
        Ok(receipt.accepted)
    }

    pub fn binding(&self) -> &PakeStart {
        &self.start
    }
}

impl PakeOwner {
    pub fn start(
        identity: &AgentIdentity,
        start: &PakeStart,
        code: &str,
        joiner_controller: [u8; 20],
        now_ms: u64,
    ) -> Result<(Self, PakeAnswer), AslError> {
        if start.owner != identity.agent_id()
            || start.expires_at_ms <= now_ms
            || start.expires_at_ms.saturating_sub(now_ms) > MAX_PAKE_LIFETIME_MS
        {
            return Err(AslError::InvalidMessage);
        }
        verify_start_signature(start, joiner_controller)?;
        let password = Zeroizing::new(password_bytes(code, start.code_digits)?);
        let (id_a, id_b) = spake_identities(
            start.exchange_id,
            start.joiner,
            start.owner,
            &start.joiner_peer,
            &start.owner_peer,
        );
        let (state, share) = Spake2::<Ed25519Group>::start_b(
            &Password::new(password.as_slice()),
            &Identity::new(&id_a),
            &Identity::new(&id_b),
        );
        let key = state
            .finish(&start.share)
            .map_err(|_| AslError::InvalidIdentity)?;
        let key: [u8; 32] = key.try_into().map_err(|_| AslError::InvalidMessage)?;
        let answer_share: [u8; PAKE_SHARE_BYTES] = share
            .as_slice()
            .try_into()
            .map_err(|_| AslError::InvalidMessage)?;
        let transcript = transcript_bytes(start, &answer_share)?;
        let mut answer = PakeAnswer {
            exchange_id: start.exchange_id,
            owner: start.owner,
            joiner: start.joiner,
            owner_peer: start.owner_peer.clone(),
            joiner_peer: start.joiner_peer.clone(),
            share: answer_share,
            confirmation: confirmation(&key, ANSWER_DOMAIN, &transcript),
            signature: Signature65([0; Signature65::LENGTH]),
        };
        answer.signature = identity.sign_domain_message(&answer_signing_bytes(start, &answer)?)?;
        Ok((
            Self {
                key,
                answer_share,
                start: start.clone(),
            },
            answer,
        ))
    }

    pub fn finish_confirm(
        &self,
        confirm: &PakeConfirm,
        joiner_controller: [u8; 20],
        now_ms: u64,
    ) -> Result<(), AslError> {
        if self.start.exchange_id != confirm.exchange_id
            || self.start.owner != confirm.owner
            || self.start.joiner != confirm.joiner
            || self.start.expires_at_ms <= now_ms
        {
            return Err(AslError::InvalidMessage);
        }
        verify_root_signature(
            &confirm_signing_bytes(&self.start, confirm)?,
            confirm.signature,
            joiner_controller,
        )?;
        let expected = confirmation(
            &self.key,
            CONFIRM_DOMAIN,
            &transcript_bytes(&self.start, &self.answer_share)?,
        );
        if expected != confirm.confirmation {
            return Err(AslError::InvalidIdentity);
        }
        Ok(())
    }

    pub fn receipt(
        &self,
        identity: &AgentIdentity,
        accepted: bool,
    ) -> Result<PakeReceipt, AslError> {
        let mut receipt = PakeReceipt {
            exchange_id: self.start.exchange_id,
            owner: self.start.owner,
            joiner: self.start.joiner,
            accepted,
            confirmation: confirmation(
                &self.key,
                RECEIPT_DOMAIN,
                &receipt_transcript_bytes(&self.start, &self.answer_share, accepted)?,
            ),
            signature: Signature65([0; Signature65::LENGTH]),
        };
        receipt.signature =
            identity.sign_domain_message(&receipt_signing_bytes(&self.start, &receipt)?)?;
        Ok(receipt)
    }

    pub fn binding(&self) -> &PakeStart {
        &self.start
    }
}

fn verify_start_signature(start: &PakeStart, controller: [u8; 20]) -> Result<(), AslError> {
    validate_start(start)?;
    verify_root_signature(&start_signing_bytes(start)?, start.signature, controller)
}

fn validate_binding(
    exchange_id: Id128,
    owner: AgentId,
    joiner: AgentId,
    expires_at_ms: u64,
    code_digits: u8,
    now_ms: u64,
) -> Result<(), AslError> {
    if exchange_id.0 == [0; 16]
        || owner == joiner
        || expires_at_ms <= now_ms
        || expires_at_ms.saturating_sub(now_ms) > MAX_PAKE_LIFETIME_MS
        || !(MIN_PAKE_CODE_DIGITS..=MAX_PAKE_CODE_DIGITS).contains(&code_digits)
    {
        return Err(AslError::InvalidMessage);
    }
    Ok(())
}

fn password_bytes(code: &str, digits: u8) -> Result<Vec<u8>, AslError> {
    let bytes = code.as_bytes();
    if bytes.len() != usize::from(digits) || !bytes.iter().all(|byte| byte.is_ascii_digit()) {
        return Err(AslError::InvalidMessage);
    }
    let mut password = Vec::with_capacity(PASSWORD_DOMAIN.len() + bytes.len());
    password.extend_from_slice(PASSWORD_DOMAIN);
    password.extend_from_slice(bytes);
    Ok(password)
}

fn spake_identities(
    exchange_id: Id128,
    joiner: AgentId,
    owner: AgentId,
    joiner_peer: &PeerId,
    owner_peer: &PeerId,
) -> (Vec<u8>, Vec<u8>) {
    let mut a = Vec::with_capacity(IDENTITY_DOMAIN.len() + 16 + 32 + 32 + 256);
    a.extend_from_slice(IDENTITY_DOMAIN);
    a.extend_from_slice(b"A\0");
    a.extend_from_slice(exchange_id.as_bytes());
    a.extend_from_slice(joiner.as_bytes());
    a.extend_from_slice(owner.as_bytes());
    push_peer_id(&mut a, joiner_peer);
    let mut b = Vec::with_capacity(IDENTITY_DOMAIN.len() + 16 + 32 + 32 + 256);
    b.extend_from_slice(IDENTITY_DOMAIN);
    b.extend_from_slice(b"B\0");
    b.extend_from_slice(exchange_id.as_bytes());
    b.extend_from_slice(joiner.as_bytes());
    b.extend_from_slice(owner.as_bytes());
    push_peer_id(&mut b, owner_peer);
    (a, b)
}

fn start_signing_bytes(start: &PakeStart) -> Result<Vec<u8>, AslError> {
    validate_start(start)?;
    let mut bytes =
        Vec::with_capacity(START_DOMAIN.len() + 16 + 64 + 256 + 8 + 1 + PAKE_SHARE_BYTES);
    bytes.extend_from_slice(START_DOMAIN);
    bytes.extend_from_slice(start.exchange_id.as_bytes());
    bytes.extend_from_slice(start.owner.as_bytes());
    bytes.extend_from_slice(start.joiner.as_bytes());
    push_peer_id(&mut bytes, &start.owner_peer);
    push_peer_id(&mut bytes, &start.joiner_peer);
    bytes.extend_from_slice(&start.expires_at_ms.to_be_bytes());
    bytes.push(start.code_digits);
    bytes.extend_from_slice(&start.share);
    Ok(bytes)
}

fn answer_signing_bytes(start: &PakeStart, answer: &PakeAnswer) -> Result<Vec<u8>, AslError> {
    validate_answer(start, answer)?;
    let mut bytes = Vec::with_capacity(256 + PAKE_SHARE_BYTES * 2 + 32);
    bytes.extend_from_slice(ANSWER_DOMAIN);
    bytes.extend_from_slice(&start_signing_bytes(start)?);
    bytes.extend_from_slice(&answer.share);
    bytes.extend_from_slice(&answer.confirmation.0);
    Ok(bytes)
}

fn confirm_signing_bytes(start: &PakeStart, confirm: &PakeConfirm) -> Result<Vec<u8>, AslError> {
    if start.exchange_id != confirm.exchange_id
        || start.owner != confirm.owner
        || start.joiner != confirm.joiner
        || confirm.confirmation.0 == [0; 32]
    {
        return Err(AslError::InvalidMessage);
    }
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(CONFIRM_DOMAIN);
    bytes.extend_from_slice(&start_signing_bytes(start)?);
    bytes.extend_from_slice(&confirm.confirmation.0);
    Ok(bytes)
}

fn receipt_signing_bytes(start: &PakeStart, receipt: &PakeReceipt) -> Result<Vec<u8>, AslError> {
    if start.exchange_id != receipt.exchange_id
        || start.owner != receipt.owner
        || start.joiner != receipt.joiner
        || receipt.confirmation.0 == [0; 32]
    {
        return Err(AslError::InvalidMessage);
    }
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(RECEIPT_DOMAIN);
    bytes.extend_from_slice(&start_signing_bytes(start)?);
    bytes.push(u8::from(receipt.accepted));
    bytes.extend_from_slice(&receipt.confirmation.0);
    Ok(bytes)
}

fn transcript_bytes(
    start: &PakeStart,
    answer_share: &[u8; PAKE_SHARE_BYTES],
) -> Result<Vec<u8>, AslError> {
    let mut bytes = start_signing_bytes(start)?;
    bytes.extend_from_slice(answer_share);
    Ok(bytes)
}

fn receipt_transcript_bytes(
    start: &PakeStart,
    answer_share: &[u8; PAKE_SHARE_BYTES],
    accepted: bool,
) -> Result<Vec<u8>, AslError> {
    let mut bytes = transcript_bytes(start, answer_share)?;
    bytes.push(u8::from(accepted));
    Ok(bytes)
}

fn confirmation(key: &[u8; 32], label: &[u8], transcript: &[u8]) -> Hash32 {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(label);
    hasher.update(transcript);
    Hash32(*hasher.finalize().as_bytes())
}

fn validate_start(start: &PakeStart) -> Result<(), AslError> {
    if start.exchange_id.0 == [0; 16]
        || start.owner == start.joiner
        || start.expires_at_ms == 0
        || !(MIN_PAKE_CODE_DIGITS..=MAX_PAKE_CODE_DIGITS).contains(&start.code_digits)
        || start.share == [0; PAKE_SHARE_BYTES]
    {
        return Err(AslError::InvalidMessage);
    }
    Ok(())
}

fn validate_answer(start: &PakeStart, answer: &PakeAnswer) -> Result<(), AslError> {
    if start.exchange_id != answer.exchange_id
        || start.owner != answer.owner
        || start.joiner != answer.joiner
        || start.owner_peer != answer.owner_peer
        || start.joiner_peer != answer.joiner_peer
        || answer.confirmation.0 == [0; 32]
        || answer.share == [0; PAKE_SHARE_BYTES]
    {
        return Err(AslError::InvalidMessage);
    }
    Ok(())
}

fn push_peer_id(bytes: &mut Vec<u8>, peer: &PeerId) {
    let length = u16::try_from(peer.as_bytes().len()).unwrap_or(u16::MAX);
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(peer.as_bytes());
}
