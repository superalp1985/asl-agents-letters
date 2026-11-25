use cbor2::{Value, value::Integer};

use crate::{
    error::AslError,
    ids::{AgentId, Id128, Signature65},
    protocol::{MAX_PAIRING_NOTE_BYTES, cbor::decode_canonical, validate_pairing_note},
};

pub const CONTACT_INVITE_VERSION: u64 = 1;
pub const MAX_CONTACT_INVITE_LIFETIME_MS: u64 = 24 * 60 * 60 * 1_000;
pub const MAX_CONTACT_INVITE_CBOR_BYTES: usize = 1_024;
pub const MAX_CONTACT_INVITE_ENVELOPE_CHARS: usize = 2_048;
pub const CONTACT_INVITE_SIGNING_DOMAIN: &[u8] = b"ASL-CONTACT-INVITE-V1\0";
pub const CONTACT_INVITE_ENVELOPE_SCHEME: &str = "ASL-CONTACT-INVITE:";

const MAX_TIME_MS: u64 = i64::MAX as u64;
const UNSIGNED_FIELDS: [u64; 7] = [0, 1, 2, 3, 4, 5, 6];
const ALL_FIELDS: [u64; 8] = [0, 1, 2, 3, 4, 5, 6, 7];

/// Versioned contact invitation payload. Authentication must verify
/// `signature` over `signing_preimage` before the invitation is accepted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContactInviteV1 {
    pub version: u64,
    pub invite_id: Id128,
    pub token: Id128,
    pub inviter: AgentId,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub note: String,
    pub signature: Signature65,
}

impl ContactInviteV1 {
    pub fn validate(&self, now_ms: u64) -> Result<(), AslError> {
        if self.version != CONTACT_INVITE_VERSION {
            return Err(AslError::IncompatibleVersion);
        }
        if self.invite_id.0 == [0; 16]
            || self.token.0 == [0; 16]
            || self.inviter.0 == [0; 32]
            || self.expires_at_ms > MAX_TIME_MS
            || self.created_at_ms > now_ms
            || self.expires_at_ms <= self.created_at_ms
            || self
                .expires_at_ms
                .checked_sub(self.created_at_ms)
                .is_none_or(|lifetime| lifetime > MAX_CONTACT_INVITE_LIFETIME_MS)
        {
            return Err(AslError::InvalidMessage);
        }
        if now_ms >= self.expires_at_ms {
            return Err(AslError::ExpiredMessage);
        }
        validate_pairing_note(&self.note)
    }

    pub fn to_canonical_cbor(&self, now_ms: u64) -> Result<Vec<u8>, AslError> {
        self.validate(now_ms)?;
        let bytes = cbor2::to_canonical_vec(&self.to_value(ALL_FIELDS))
            .map_err(|_| AslError::InvalidMessage)?;
        if bytes.is_empty() || bytes.len() > MAX_CONTACT_INVITE_CBOR_BYTES {
            return Err(AslError::InvalidMessage);
        }
        Ok(bytes)
    }

    pub fn from_canonical_cbor(bytes: &[u8], now_ms: u64) -> Result<Self, AslError> {
        if bytes.is_empty() || bytes.len() > MAX_CONTACT_INVITE_CBOR_BYTES {
            return Err(AslError::InvalidMessage);
        }
        let mut fields = cbor_fields(decode_canonical(bytes)?)?;
        check_contact_invite_keys(&fields)?;
        let version = cbor_uint(take(&mut fields, 0)?)?;
        if version != CONTACT_INVITE_VERSION {
            return Err(AslError::IncompatibleVersion);
        }
        let invite = Self {
            version,
            invite_id: Id128(cbor_fixed::<16>(take(&mut fields, 1)?)?),
            token: Id128(cbor_fixed::<16>(take(&mut fields, 2)?)?),
            inviter: AgentId(cbor_fixed::<32>(take(&mut fields, 3)?)?),
            created_at_ms: cbor_uint(take(&mut fields, 4)?)?,
            expires_at_ms: cbor_uint(take(&mut fields, 5)?)?,
            note: cbor_note(take(&mut fields, 6)?)?,
            signature: Signature65(cbor_fixed::<65>(take(&mut fields, 7)?)?),
        };
        if !fields.is_empty() {
            return Err(AslError::InvalidMessage);
        }
        invite.validate(now_ms)?;
        Ok(invite)
    }

    /// The signature covers a dedicated domain followed by the canonical CBOR
    /// encoding of every field except `signature`.
    pub fn signing_preimage(&self, now_ms: u64) -> Result<Vec<u8>, AslError> {
        self.validate(now_ms)?;
        let unsigned = cbor2::to_canonical_vec(&self.to_value(UNSIGNED_FIELDS))
            .map_err(|_| AslError::InvalidMessage)?;
        let mut preimage = Vec::with_capacity(CONTACT_INVITE_SIGNING_DOMAIN.len() + unsigned.len());
        preimage.extend_from_slice(CONTACT_INVITE_SIGNING_DOMAIN);
        preimage.extend_from_slice(&unsigned);
        Ok(preimage)
    }

    pub fn to_envelope(&self, now_ms: u64) -> Result<String, AslError> {
        let cbor = self.to_canonical_cbor(now_ms)?;
        Ok(format!(
            "{CONTACT_INVITE_ENVELOPE_SCHEME}{CONTACT_INVITE_VERSION}:{}",
            bs58::encode(cbor).into_string()
        ))
    }

    pub fn from_envelope(envelope: &str, now_ms: u64) -> Result<Self, AslError> {
        if envelope.len() > MAX_CONTACT_INVITE_ENVELOPE_CHARS {
            return Err(AslError::InvalidMessage);
        }
        let payload = envelope
            .strip_prefix(CONTACT_INVITE_ENVELOPE_SCHEME)
            .ok_or(AslError::InvalidMessage)?;
        let (version, encoded) = payload.split_once(':').ok_or(AslError::InvalidMessage)?;
        let version = version
            .parse::<u64>()
            .map_err(|_| AslError::InvalidMessage)?;
        if version != CONTACT_INVITE_VERSION {
            return Err(AslError::IncompatibleVersion);
        }
        let canonical = bs58::decode(encoded)
            .into_vec()
            .map_err(|_| AslError::InvalidMessage)?;
        if bs58::encode(&canonical).into_string() != encoded {
            return Err(AslError::InvalidMessage);
        }
        Self::from_canonical_cbor(&canonical, now_ms)
    }

    fn to_value(&self, fields: impl IntoIterator<Item = u64>) -> Value {
        Value::Map(
            fields
                .into_iter()
                .map(|key| {
                    let value = match key {
                        0 => cbor_uint_value(self.version),
                        1 => Value::Bytes(self.invite_id.0.to_vec()),
                        2 => Value::Bytes(self.token.0.to_vec()),
                        3 => Value::Bytes(self.inviter.0.to_vec()),
                        4 => cbor_uint_value(self.created_at_ms),
                        5 => cbor_uint_value(self.expires_at_ms),
                        6 => Value::Text(self.note.clone()),
                        7 => Value::Bytes(self.signature.0.to_vec()),
                        _ => unreachable!("contact invite field set is fixed"),
                    };
                    (cbor_uint_value(key), value)
                })
                .collect(),
        )
    }
}

fn cbor_uint_value(value: u64) -> Value {
    Value::Integer(Integer::from(value))
}

fn cbor_uint(value: Value) -> Result<u64, AslError> {
    match value {
        Value::Integer(value) => u64::try_from(value).map_err(|_| AslError::InvalidMessage),
        _ => Err(AslError::InvalidMessage),
    }
}

fn cbor_fixed<const N: usize>(value: Value) -> Result<[u8; N], AslError> {
    match value {
        Value::Bytes(bytes) => bytes.try_into().map_err(|_| AslError::InvalidMessage),
        _ => Err(AslError::InvalidMessage),
    }
}

fn cbor_note(value: Value) -> Result<String, AslError> {
    let Value::Text(note) = value else {
        return Err(AslError::InvalidMessage);
    };
    if note.len() > MAX_PAIRING_NOTE_BYTES {
        return Err(AslError::InvalidMessage);
    }
    validate_pairing_note(&note)?;
    Ok(note)
}

fn cbor_fields(value: Value) -> Result<std::collections::BTreeMap<u64, Value>, AslError> {
    let Value::Map(entries) = value else {
        return Err(AslError::InvalidMessage);
    };
    let mut fields = std::collections::BTreeMap::new();
    for (key, value) in entries {
        if fields.insert(cbor_uint(key)?, value).is_some() {
            return Err(AslError::InvalidMessage);
        }
    }
    Ok(fields)
}

fn check_contact_invite_keys(
    fields: &std::collections::BTreeMap<u64, Value>,
) -> Result<(), AslError> {
    if fields.keys().all(|key| ALL_FIELDS.contains(key)) {
        Ok(())
    } else {
        Err(AslError::InvalidMessage)
    }
}

fn take(fields: &mut std::collections::BTreeMap<u64, Value>, key: u64) -> Result<Value, AslError> {
    fields.remove(&key).ok_or(AslError::InvalidMessage)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000_000;

    fn invite() -> ContactInviteV1 {
        ContactInviteV1 {
            version: CONTACT_INVITE_VERSION,
            invite_id: Id128([1; 16]),
            token: Id128([2; 16]),
            inviter: AgentId([3; 32]),
            created_at_ms: NOW - 1_000,
            expires_at_ms: NOW + 60_000,
            note: "Codex, please add me".into(),
            signature: Signature65([4; 65]),
        }
    }

    fn value(invite: &ContactInviteV1) -> Value {
        invite.to_value(ALL_FIELDS)
    }

    fn canonical(value: &Value) -> Vec<u8> {
        cbor2::to_canonical_vec(value).unwrap()
    }

    fn set(value: &mut Value, key: u64, replacement: Value) {
        let Value::Map(entries) = value else {
            panic!("contact invite must be a map");
        };
        let entry = entries
            .iter_mut()
            .find(|(entry, _)| *entry == cbor_uint_value(key))
            .unwrap();
        entry.1 = replacement;
    }

    #[test]
    fn contact_invite_round_trips_canonical_cbor_and_envelope() {
        let original = invite();
        let bytes = original.to_canonical_cbor(NOW).unwrap();
        assert_eq!(
            ContactInviteV1::from_canonical_cbor(&bytes, NOW).unwrap(),
            original
        );
        assert_eq!(bytes, canonical(&value(&original)));

        let envelope = original.to_envelope(NOW).unwrap();
        assert!(envelope.starts_with("ASL-CONTACT-INVITE:1:"));
        assert_eq!(
            ContactInviteV1::from_envelope(&envelope, NOW).unwrap(),
            original
        );
    }

    #[test]
    fn signing_preimage_has_an_independent_domain_and_excludes_signature() {
        let original = invite();
        let preimage = original.signing_preimage(NOW).unwrap();
        assert!(preimage.starts_with(CONTACT_INVITE_SIGNING_DOMAIN));

        let mut re_signed = original.clone();
        re_signed.signature = Signature65([9; 65]);
        assert_eq!(re_signed.signing_preimage(NOW).unwrap(), preimage);

        let mut tampered = original;
        tampered.inviter = AgentId([8; 32]);
        assert_ne!(tampered.signing_preimage(NOW).unwrap(), preimage);
    }

    #[test]
    fn canonical_decoder_rejects_trailing_bytes_noncanonical_and_unknown_versions() {
        let original = invite();
        let bytes = original.to_canonical_cbor(NOW).unwrap();
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(ContactInviteV1::from_canonical_cbor(&trailing, NOW).is_err());

        let mut noncanonical = bytes.clone();
        noncanonical[0] = 0xb8;
        noncanonical.insert(1, 0x08);
        assert!(ContactInviteV1::from_canonical_cbor(&noncanonical, NOW).is_err());

        let mut unknown = value(&original);
        set(&mut unknown, 0, cbor_uint_value(2));
        assert!(matches!(
            ContactInviteV1::from_canonical_cbor(&canonical(&unknown), NOW),
            Err(AslError::IncompatibleVersion)
        ));

        assert!(matches!(
            ContactInviteV1::from_envelope("ASL-CONTACT-INVITE:2:2", NOW),
            Err(AslError::IncompatibleVersion)
        ));
    }

    #[test]
    fn decoder_rejects_zero_ids_oversize_and_invalid_base58_forms() {
        let mut zero_invite = invite();
        zero_invite.invite_id = Id128([0; 16]);
        assert!(zero_invite.to_canonical_cbor(NOW).is_err());

        let mut zero_token = invite();
        zero_token.token = Id128([0; 16]);
        assert!(zero_token.to_canonical_cbor(NOW).is_err());

        let mut zero_inviter = invite();
        zero_inviter.inviter = AgentId([0; 32]);
        assert!(zero_inviter.to_canonical_cbor(NOW).is_err());

        assert!(
            ContactInviteV1::from_canonical_cbor(&vec![0; MAX_CONTACT_INVITE_CBOR_BYTES + 1], NOW)
                .is_err()
        );
        assert!(
            ContactInviteV1::from_envelope(&"A".repeat(MAX_CONTACT_INVITE_ENVELOPE_CHARS + 1), NOW)
                .is_err()
        );

        let envelope = invite().to_envelope(NOW).unwrap();
        let noncanonical = envelope.replacen("ASL-CONTACT-INVITE:1:", "ASL-CONTACT-INVITE:1:1", 1);
        assert!(ContactInviteV1::from_envelope(&noncanonical, NOW).is_err());
    }

    #[test]
    fn validation_rejects_expired_future_rollback_and_excessive_lifetime() {
        let original = invite();
        assert!(matches!(
            original.validate(original.expires_at_ms),
            Err(AslError::ExpiredMessage)
        ));

        let mut future = original.clone();
        future.created_at_ms = NOW + 1;
        future.expires_at_ms = NOW + 60_000;
        assert!(matches!(
            future.validate(NOW),
            Err(AslError::InvalidMessage)
        ));

        let mut rollback = original.clone();
        rollback.expires_at_ms = rollback.created_at_ms;
        assert!(matches!(
            rollback.validate(NOW),
            Err(AslError::InvalidMessage)
        ));

        let mut excessive = original;
        excessive.expires_at_ms = excessive.created_at_ms + MAX_CONTACT_INVITE_LIFETIME_MS + 1;
        assert!(matches!(
            excessive.validate(NOW),
            Err(AslError::InvalidMessage)
        ));
    }

    #[test]
    fn note_uses_the_existing_single_line_bounded_unicode_rules() {
        let mut valid = invite();
        valid.note = "中".repeat(120);
        assert!(valid.validate(NOW).is_ok());

        let mut too_long = invite();
        too_long.note = "中".repeat(121);
        assert!(too_long.validate(NOW).is_err());

        let mut two_sentences = invite();
        two_sentences.note = "First. Second.".into();
        assert!(two_sentences.validate(NOW).is_err());

        let mut multiple_lines = invite();
        multiple_lines.note = "Line one\u{2028}line two".into();
        assert!(multiple_lines.validate(NOW).is_err());
    }
}
