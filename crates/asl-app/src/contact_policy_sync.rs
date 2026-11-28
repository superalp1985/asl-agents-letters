use std::io::{Cursor, Read, Write};

use age::{Decryptor, Encryptor, secrecy::SecretString};
use asl_store::{
    Store,
    contact_policy::{ContactRequestMode, ContactRequestPolicy, MAX_RECENT_INTERACTION_TTL_MS},
};
use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32},
    record::{
        ContactPolicyEnvelope, MAX_CONTACT_POLICY_RECORD_LIFETIME_MS, RecordPayload, decode_record,
        record_signing_bytes,
    },
};
use rand::{TryRng, rngs::SysRng};
use serde::{Deserialize, Serialize};

use crate::{
    identity::{AgentIdentity, verify_root_signature},
    profile::sign_record,
};

const PAYLOAD_VERSION: u64 = 1;
const ENCRYPTION_DOMAIN: &str = "ASL-CONTACT-POLICY-ENCRYPTION-v1";
const PUBLICATION_SETTING: &str = "contacts.policy_publication.v1";
const MAX_PAYLOAD_BYTES: usize = 4_096;
const SCRYPT_WORK_FACTOR: u8 = 16;
const RECORD_LIFETIME_MS: u64 = MAX_CONTACT_POLICY_RECORD_LIFETIME_MS;
const REFRESH_BEFORE_EXPIRY_MS: u64 = 5 * 60 * 1_000;
const REFRESH_INTERVAL_MS: u64 = 60 * 60 * 1_000;
const RETRY_BASE_MS: u64 = 5_000;
const RETRY_MAX_MS: u64 = 30 * 60 * 1_000;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContactPolicyPayloadV1 {
    version: u64,
    agent_id: [u8; 32],
    revision: u64,
    mode: ContactRequestMode,
    shared_group_auto_accept: bool,
    recent_interaction_ttl_ms: u64,
    revoked: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicationStateV1 {
    version: u64,
    revision: u64,
    issued_at_ms: u64,
    expires_at_ms: u64,
    record_hex: String,
    next_attempt_ms: u64,
    attempts: u32,
    published_at_ms: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct PreparedPublication {
    pub record: Vec<u8>,
    pub revision: u64,
    pub expires_at_ms: u64,
    pub next_attempt_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImportOutcome {
    Applied(u64),
    KeptLocal(u64),
}

impl ContactPolicyPayloadV1 {
    fn from_policy(agent_id: AgentId, policy: ContactRequestPolicy) -> Self {
        Self {
            version: PAYLOAD_VERSION,
            agent_id: agent_id.0,
            revision: policy.revision,
            mode: policy.mode,
            shared_group_auto_accept: policy.shared_group_auto_accept,
            recent_interaction_ttl_ms: policy.recent_interaction_ttl_ms,
            revoked: policy.revoked,
        }
    }

    fn into_policy(
        self,
        expected_agent: AgentId,
        expected_revision: u64,
    ) -> Result<ContactRequestPolicy, AslError> {
        if self.version != PAYLOAD_VERSION
            || self.agent_id != expected_agent.0
            || self.revision != expected_revision
            || self.revision == 0
            || self.recent_interaction_ttl_ms > MAX_RECENT_INTERACTION_TTL_MS
        {
            return Err(AslError::InvalidMessage);
        }
        Ok(ContactRequestPolicy {
            mode: self.mode,
            shared_group_auto_accept: self.shared_group_auto_accept,
            recent_interaction_ttl_ms: self.recent_interaction_ttl_ms,
            revision: self.revision,
            revoked: self.revoked,
        })
    }
}

/// Returns the exact persisted publication record when it is due. The record
/// bytes are reused across retries and process restarts for one revision.
pub fn due(
    identity: &AgentIdentity,
    store: &Store,
    now_ms: u64,
) -> Result<Option<PreparedPublication>, AslError> {
    let prepared = prepare(identity, store, now_ms)?;
    let state = load_state(store)?.ok_or(AslError::InvalidPolicyState)?;
    let policy = store.contact_request_policy()?;
    if state.revision != policy.revision
        || state.published_at_ms.is_none()
        || now_ms >= state.next_attempt_ms
        || now_ms.saturating_add(REFRESH_BEFORE_EXPIRY_MS) >= state.expires_at_ms
    {
        Ok(Some(prepared))
    } else {
        Ok(None)
    }
}

/// Produces or reloads the stable signed record for the current policy
/// revision. If the old record expired, a new policy revision is materialized
/// so the DHT never has to replace a stale record at the same sequence.
pub fn prepare(
    identity: &AgentIdentity,
    store: &Store,
    now_ms: u64,
) -> Result<PreparedPublication, AslError> {
    let mut policy = store.materialize_contact_request_policy(now_ms)?;
    if let Some(state) = load_state(store)? {
        if state.revision == policy.revision && now_ms < state.expires_at_ms {
            let record = decode_hex_record(&state.record_hex)?;
            validate_local_record(
                identity,
                &record,
                state.revision,
                state.expires_at_ms,
                policy.revoked,
            )?;
            return Ok(PreparedPublication {
                record,
                revision: state.revision,
                expires_at_ms: state.expires_at_ms,
                next_attempt_ms: state.next_attempt_ms,
            });
        }
        if state.revision == policy.revision && now_ms >= state.expires_at_ms {
            policy = store.advance_contact_policy_revision(now_ms)?;
        } else if state.revision > policy.revision {
            return Err(AslError::PolicyVersionConflict);
        }
    }
    let record = build_record(identity, policy, now_ms)?;
    let expires_at_ms = decode_record(&record)?.record.expires_at_ms;
    save_state(
        store,
        PublicationStateV1 {
            version: 1,
            revision: policy.revision,
            issued_at_ms: now_ms,
            expires_at_ms,
            record_hex: alloy_primitives::hex::encode(&record),
            next_attempt_ms: now_ms,
            attempts: 0,
            published_at_ms: None,
        },
        now_ms,
    )?;
    Ok(PreparedPublication {
        record,
        revision: policy.revision,
        expires_at_ms,
        next_attempt_ms: now_ms,
    })
}

pub fn note_attempt(store: &Store, now_ms: u64) -> Result<(), AslError> {
    let mut state = load_state(store)?.ok_or(AslError::InvalidPolicyState)?;
    state.attempts = state.attempts.saturating_add(1);
    state.next_attempt_ms = now_ms.saturating_add(retry_delay(state.attempts));
    save_state(store, state, now_ms)
}

pub fn note_success(store: &Store, now_ms: u64) -> Result<(), AslError> {
    let mut state = load_state(store)?.ok_or(AslError::InvalidPolicyState)?;
    state.attempts = 0;
    state.published_at_ms = Some(now_ms);
    state.next_attempt_ms = now_ms.saturating_add(REFRESH_INTERVAL_MS);
    save_state(store, state, now_ms)
}

pub fn note_success_for_revision(
    store: &Store,
    revision: u64,
    now_ms: u64,
) -> Result<bool, AslError> {
    let Some(state) = load_state(store)? else {
        return Ok(false);
    };
    if state.revision != revision {
        return Ok(false);
    }
    note_success(store, now_ms)?;
    Ok(true)
}

pub fn note_failure(store: &Store, now_ms: u64) -> Result<(), AslError> {
    let mut state = load_state(store)?.ok_or(AslError::InvalidPolicyState)?;
    state.attempts = state.attempts.saturating_add(1);
    state.next_attempt_ms = now_ms.saturating_add(retry_delay(state.attempts));
    save_state(store, state, now_ms)
}

pub fn note_failure_for_revision(
    store: &Store,
    revision: u64,
    now_ms: u64,
) -> Result<bool, AslError> {
    let Some(state) = load_state(store)? else {
        return Ok(false);
    };
    if state.revision != revision {
        return Ok(false);
    }
    note_failure(store, now_ms)?;
    Ok(true)
}

/// Merges an observed local-Agent record. Same-revision conflicts are resolved
/// by the hash of the complete signed record: the lower BLAKE3 hash wins.
pub fn import(
    identity: &AgentIdentity,
    store: &Store,
    bytes: &[u8],
    now_ms: u64,
) -> Result<ImportOutcome, AslError> {
    if !store.contact_policy_sync_authorized()? {
        return Err(AslError::PolicyDenied);
    }
    let remote = validate_record(identity, bytes, now_ms)?;
    let local = prepare(identity, store, now_ms)?;
    let current = store.contact_request_policy()?;
    if remote.policy.revision > current.revision {
        store.apply_contact_policy_snapshot(remote.policy, now_ms)?;
        adopt_publication(store, bytes, &remote, now_ms)?;
        return Ok(ImportOutcome::Applied(remote.policy.revision));
    }
    if remote.policy.revision < current.revision {
        force_republish(store, now_ms)?;
        return Ok(ImportOutcome::KeptLocal(current.revision));
    }
    let remote_hash = blake3::hash(bytes);
    let local_hash = blake3::hash(&local.record);
    if remote_hash.as_bytes() < local_hash.as_bytes() {
        store.replace_contact_policy_snapshot_tiebreak(remote.policy, now_ms)?;
        adopt_publication(store, bytes, &remote, now_ms)?;
        return Ok(ImportOutcome::Applied(remote.policy.revision));
    }
    if remote_hash.as_bytes() > local_hash.as_bytes() {
        force_republish(store, now_ms)?;
        return Ok(ImportOutcome::KeptLocal(current.revision));
    }
    note_success(store, now_ms)?;
    Ok(ImportOutcome::KeptLocal(current.revision))
}

/// Manual export uses the same stable publication bytes as automatic sync.
pub fn export(identity: &AgentIdentity, store: &Store, now_ms: u64) -> Result<Vec<u8>, AslError> {
    Ok(prepare(identity, store, now_ms)?.record)
}

struct ValidatedRemote {
    policy: ContactRequestPolicy,
}

fn validate_record(
    identity: &AgentIdentity,
    bytes: &[u8],
    now_ms: u64,
) -> Result<ValidatedRemote, AslError> {
    let signed = decode_record(bytes)?;
    let RecordPayload::ContactPolicy(envelope) = &signed.record.payload else {
        return Err(AslError::InvalidMessage);
    };
    if envelope.agent_id != identity.agent_id()
        || signed.record.sequence != envelope.revision
        || now_ms < signed.record.issued_at_ms
        || now_ms >= signed.record.expires_at_ms
    {
        return Err(AslError::InvalidMessage);
    }
    verify_root_signature(
        &record_signing_bytes(&signed.record)?,
        signed.signature,
        identity.controller_address(),
    )?;
    let plaintext = decrypt(identity, &envelope.ciphertext)?;
    let payload: ContactPolicyPayloadV1 =
        serde_json::from_slice(&plaintext).map_err(|_| AslError::InvalidMessage)?;
    let policy = payload.into_policy(identity.agent_id(), envelope.revision)?;
    if policy.revoked != envelope.revoked {
        return Err(AslError::InvalidMessage);
    }
    Ok(ValidatedRemote { policy })
}

fn adopt_publication(
    store: &Store,
    bytes: &[u8],
    remote: &ValidatedRemote,
    now_ms: u64,
) -> Result<(), AslError> {
    let signed = decode_record(bytes)?;
    save_state(
        store,
        PublicationStateV1 {
            version: 1,
            revision: remote.policy.revision,
            issued_at_ms: signed.record.issued_at_ms,
            expires_at_ms: signed.record.expires_at_ms,
            record_hex: alloy_primitives::hex::encode(bytes),
            next_attempt_ms: now_ms,
            attempts: 0,
            published_at_ms: None,
        },
        now_ms,
    )
}

fn force_republish(store: &Store, now_ms: u64) -> Result<(), AslError> {
    let mut state = load_state(store)?.ok_or(AslError::InvalidPolicyState)?;
    state.next_attempt_ms = now_ms;
    save_state(store, state, now_ms)
}

fn build_record(
    identity: &AgentIdentity,
    policy: ContactRequestPolicy,
    now_ms: u64,
) -> Result<Vec<u8>, AslError> {
    let payload = ContactPolicyPayloadV1::from_policy(identity.agent_id(), policy);
    let plaintext = serde_json::to_vec(&payload).map_err(|_| AslError::InvalidMessage)?;
    if plaintext.is_empty() || plaintext.len() > MAX_PAYLOAD_BYTES {
        return Err(AslError::QuotaExceeded);
    }
    let mut nonce = [0; 32];
    SysRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| AslError::InvalidIdentity)?;
    if nonce == [0; 32] {
        return Err(AslError::InvalidIdentity);
    }
    let ciphertext = encrypt(identity, &plaintext)?;
    sign_record(
        identity,
        RecordPayload::ContactPolicy(ContactPolicyEnvelope {
            agent_id: identity.agent_id(),
            revision: policy.revision,
            nonce: Hash32(nonce),
            revoked: policy.revoked,
            ciphertext,
        }),
        policy.revision,
        now_ms,
        RECORD_LIFETIME_MS,
    )
}

fn validate_local_record(
    identity: &AgentIdentity,
    bytes: &[u8],
    revision: u64,
    expires_at_ms: u64,
    revoked: bool,
) -> Result<(), AslError> {
    let signed = decode_record(bytes)?;
    let RecordPayload::ContactPolicy(envelope) = &signed.record.payload else {
        return Err(AslError::InvalidDatabase);
    };
    if envelope.agent_id != identity.agent_id()
        || envelope.revision != revision
        || envelope.revoked != revoked
        || signed.record.sequence != revision
        || signed.record.expires_at_ms != expires_at_ms
    {
        return Err(AslError::InvalidDatabase);
    }
    verify_root_signature(
        &record_signing_bytes(&signed.record)?,
        signed.signature,
        identity.controller_address(),
    )
}

fn decode_hex_record(value: &str) -> Result<Vec<u8>, AslError> {
    alloy_primitives::hex::decode(value).map_err(|_| AslError::InvalidDatabase)
}

fn load_state(store: &Store) -> Result<Option<PublicationStateV1>, AslError> {
    let Some(value) = store.get_setting(PUBLICATION_SETTING)? else {
        return Ok(None);
    };
    let state: PublicationStateV1 =
        serde_json::from_str(&value).map_err(|_| AslError::InvalidDatabase)?;
    if state.version != 1 || state.revision == 0 || state.expires_at_ms <= state.issued_at_ms {
        return Err(AslError::InvalidDatabase);
    }
    Ok(Some(state))
}

fn save_state(store: &Store, state: PublicationStateV1, now_ms: u64) -> Result<(), AslError> {
    if now_ms > i64::MAX as u64 {
        return Err(AslError::InvalidMessage);
    }
    let value = serde_json::to_string(&state).map_err(|_| AslError::InvalidMessage)?;
    store.set_setting(PUBLICATION_SETTING, &value, now_ms as i64)
}

fn retry_delay(attempts: u32) -> u64 {
    let shift = attempts.saturating_sub(1).min(12);
    RETRY_BASE_MS
        .saturating_mul(1_u64 << shift)
        .min(RETRY_MAX_MS)
}

fn encryption_passphrase(identity: &AgentIdentity) -> SecretString {
    let seed = identity.migration_seed();
    let key = blake3::derive_key(ENCRYPTION_DOMAIN, &*seed);
    SecretString::from(alloy_primitives::hex::encode(key))
}

fn encrypt(identity: &AgentIdentity, plaintext: &[u8]) -> Result<Vec<u8>, AslError> {
    let mut recipient = age::scrypt::Recipient::new(encryption_passphrase(identity));
    recipient.set_work_factor(SCRYPT_WORK_FACTOR);
    let encryptor = Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
        .map_err(|_| AslError::KeyProtectionFailed)?;
    let mut output = Vec::new();
    {
        let mut writer = encryptor
            .wrap_output(&mut output)
            .map_err(|_| AslError::KeyProtectionFailed)?;
        writer.write_all(plaintext)?;
        writer.finish()?;
    }
    if output.is_empty() || output.len() > asl_types::record::MAX_CONTACT_POLICY_CIPHERTEXT_BYTES {
        return Err(AslError::QuotaExceeded);
    }
    Ok(output)
}

fn decrypt(identity: &AgentIdentity, ciphertext: &[u8]) -> Result<Vec<u8>, AslError> {
    if ciphertext.is_empty()
        || ciphertext.len() > asl_types::record::MAX_CONTACT_POLICY_CIPHERTEXT_BYTES
    {
        return Err(AslError::InvalidMessage);
    }
    let decryptor =
        Decryptor::new(Cursor::new(ciphertext)).map_err(|_| AslError::KeyProtectionFailed)?;
    if !decryptor.is_scrypt() {
        return Err(AslError::InvalidMessage);
    }
    let mut scrypt = age::scrypt::Identity::new(encryption_passphrase(identity));
    scrypt.set_max_work_factor(SCRYPT_WORK_FACTOR);
    let mut reader = decryptor
        .decrypt(std::iter::once(&scrypt as &dyn age::Identity))
        .map_err(|_| AslError::KeyProtectionFailed)?;
    let mut plaintext = Vec::new();
    reader
        .by_ref()
        .take((MAX_PAYLOAD_BYTES + 1) as u64)
        .read_to_end(&mut plaintext)?;
    if plaintext.is_empty() || plaintext.len() > MAX_PAYLOAD_BYTES {
        return Err(AslError::QuotaExceeded);
    }
    Ok(plaintext)
}
