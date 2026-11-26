use asl_types::error::AslError;
use libp2p::kad::RecordKey;

pub const MAX_MAILBOX_RECORD_BYTES: usize = 8 * 1024;
pub const MAX_MAILBOX_RECORD_LIFETIME_MS: u64 = 30 * 24 * 60 * 60 * 1_000;

const MAGIC: &[u8; 8] = b"ASLMBX1\0";
const VERSION: u8 = 1;
const FLAGS: u8 = 0;
const RECORD_HASH_DOMAIN: &[u8] = b"ASL-MAILBOX-RECORD-HASH-v1\0";
const RECORD_KEY_DOMAIN: &[u8] = b"ASL-MAILBOX-RECORD-KEY-v1\0";
const ID_BYTES: usize = 32;
const HASH_BYTES: usize = 32;
const FIXED_BYTES: usize = 226;
const CIPHERTEXT_OFFSET: usize = 194;
const MAX_CIPHERTEXT_BYTES: usize = MAX_MAILBOX_RECORD_BYTES - FIXED_BYTES;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MailboxRecord {
    pub recipient_id: [u8; ID_BYTES],
    pub sender_id: [u8; ID_BYTES],
    pub topic_id: [u8; ID_BYTES],
    pub mailbox_id: [u8; ID_BYTES],
    pub shard_id: [u8; ID_BYTES],
    pub epoch: u64,
    pub shard_index: u16,
    pub shard_count: u16,
    pub expires_at_ms: u64,
    pub ciphertext: Vec<u8>,
}

impl MailboxRecord {
    pub const MAX_CIPHERTEXT_BYTES: usize = MAX_CIPHERTEXT_BYTES;

    pub fn record_key(&self) -> Result<RecordKey, AslError> {
        self.validate_shape()?;
        mailbox_record_key(
            self.recipient_id,
            self.sender_id,
            self.epoch,
            self.shard_index,
        )
    }

    pub fn validate_at(&self, now_ms: u64) -> Result<(), AslError> {
        self.validate_shape()?;
        if self.expires_at_ms <= now_ms
            || self.expires_at_ms - now_ms > MAX_MAILBOX_RECORD_LIFETIME_MS
        {
            return Err(AslError::InvalidMessage);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, AslError> {
        self.validate_shape()?;
        let encoded_len = FIXED_BYTES
            .checked_add(self.ciphertext.len())
            .filter(|len| *len <= MAX_MAILBOX_RECORD_BYTES)
            .ok_or(AslError::InvalidMessage)?;
        let mut bytes = Vec::with_capacity(encoded_len);
        bytes.extend_from_slice(MAGIC);
        bytes.push(VERSION);
        bytes.push(FLAGS);
        bytes.extend_from_slice(&(encoded_len as u16).to_be_bytes());
        bytes.extend_from_slice(&self.recipient_id);
        bytes.extend_from_slice(&self.sender_id);
        bytes.extend_from_slice(&self.topic_id);
        bytes.extend_from_slice(&self.mailbox_id);
        bytes.extend_from_slice(&self.shard_id);
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(&self.shard_index.to_be_bytes());
        bytes.extend_from_slice(&self.shard_count.to_be_bytes());
        bytes.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        bytes.extend_from_slice(&(self.ciphertext.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.ciphertext);
        let hash = record_hash(&bytes);
        bytes.extend_from_slice(&hash);
        debug_assert_eq!(bytes.len(), encoded_len);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, AslError> {
        if !(FIXED_BYTES + 1..=MAX_MAILBOX_RECORD_BYTES).contains(&bytes.len())
            || bytes.get(..MAGIC.len()) != Some(MAGIC)
            || bytes.get(8) != Some(&VERSION)
            || bytes.get(9) != Some(&FLAGS)
        {
            return Err(AslError::InvalidMessage);
        }
        let encoded_len = read_u16(bytes, 10)? as usize;
        if encoded_len != bytes.len() {
            return Err(AslError::InvalidMessage);
        }

        let recipient_id = read_id(bytes, 12)?;
        let sender_id = read_id(bytes, 44)?;
        let topic_id = read_id(bytes, 76)?;
        let mailbox_id = read_id(bytes, 108)?;
        let shard_id = read_id(bytes, 140)?;
        let epoch = read_u64(bytes, 172)?;
        let shard_index = read_u16(bytes, 180)?;
        let shard_count = read_u16(bytes, 182)?;
        let expires_at_ms = read_u64(bytes, 184)?;
        let ciphertext_len = read_u16(bytes, 192)? as usize;
        let ciphertext_end = CIPHERTEXT_OFFSET
            .checked_add(ciphertext_len)
            .filter(|end| *end + HASH_BYTES <= bytes.len())
            .ok_or(AslError::InvalidMessage)?;
        if ciphertext_end + HASH_BYTES != bytes.len() {
            return Err(AslError::InvalidMessage);
        }
        let expected_hash = record_hash(&bytes[..ciphertext_end]);
        if bytes[ciphertext_end..] != expected_hash {
            return Err(AslError::InvalidMessage);
        }

        let record = Self {
            recipient_id,
            sender_id,
            topic_id,
            mailbox_id,
            shard_id,
            epoch,
            shard_index,
            shard_count,
            expires_at_ms,
            ciphertext: bytes[CIPHERTEXT_OFFSET..ciphertext_end].to_vec(),
        };
        record.validate_shape()?;
        Ok(record)
    }

    pub fn hash(&self) -> Result<[u8; HASH_BYTES], AslError> {
        let bytes = self.encode()?;
        Ok(record_hash(&bytes[..bytes.len() - HASH_BYTES]))
    }

    fn validate_shape(&self) -> Result<(), AslError> {
        if is_zero_id(&self.recipient_id)
            || is_zero_id(&self.sender_id)
            || is_zero_id(&self.topic_id)
            || is_zero_id(&self.mailbox_id)
            || is_zero_id(&self.shard_id)
            || self.shard_count == 0
            || self.shard_index >= self.shard_count
            || self.expires_at_ms == 0
            || self.ciphertext.is_empty()
            || self.ciphertext.len() > MAX_CIPHERTEXT_BYTES
        {
            return Err(AslError::InvalidMessage);
        }
        Ok(())
    }
}

pub fn mailbox_record_key(
    recipient_id: [u8; ID_BYTES],
    sender_id: [u8; ID_BYTES],
    epoch: u64,
    shard_index: u16,
) -> Result<RecordKey, AslError> {
    if is_zero_id(&recipient_id) || is_zero_id(&sender_id) {
        return Err(AslError::InvalidMessage);
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(RECORD_KEY_DOMAIN);
    hasher.update(&recipient_id);
    hasher.update(&sender_id);
    hasher.update(&epoch.to_be_bytes());
    hasher.update(&shard_index.to_be_bytes());
    Ok(RecordKey::new(hasher.finalize().as_bytes()))
}

pub fn decode_mailbox_record_for_key(
    key: &RecordKey,
    value: &[u8],
) -> Result<MailboxRecord, AslError> {
    let record = MailboxRecord::decode(value)?;
    if record.record_key()? != *key {
        return Err(AslError::InvalidMessage);
    }
    Ok(record)
}

fn record_hash(bytes_without_hash: &[u8]) -> [u8; HASH_BYTES] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(RECORD_HASH_DOMAIN);
    hasher.update(bytes_without_hash);
    *hasher.finalize().as_bytes()
}

fn read_id(bytes: &[u8], offset: usize) -> Result<[u8; ID_BYTES], AslError> {
    bytes
        .get(offset..offset + ID_BYTES)
        .and_then(|value| value.try_into().ok())
        .ok_or(AslError::InvalidMessage)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, AslError> {
    bytes
        .get(offset..offset + 2)
        .and_then(|value| value.try_into().ok())
        .map(u16::from_be_bytes)
        .ok_or(AslError::InvalidMessage)
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, AslError> {
    bytes
        .get(offset..offset + 8)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_be_bytes)
        .ok_or(AslError::InvalidMessage)
}

fn is_zero_id(id: &[u8; ID_BYTES]) -> bool {
    *id == [0; ID_BYTES]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(ciphertext: Vec<u8>) -> MailboxRecord {
        MailboxRecord {
            recipient_id: [1; ID_BYTES],
            sender_id: [2; ID_BYTES],
            topic_id: [3; ID_BYTES],
            mailbox_id: [4; ID_BYTES],
            shard_id: [5; ID_BYTES],
            epoch: 7,
            shard_index: 0,
            shard_count: 1,
            expires_at_ms: 2_000_000,
            ciphertext,
        }
    }

    #[test]
    fn mailbox_keys_are_domain_separated_and_cover_route_fields() {
        let base = mailbox_record_key([1; 32], [2; 32], 7, 0).unwrap();
        assert_eq!(base, mailbox_record_key([1; 32], [2; 32], 7, 0).unwrap());
        assert_ne!(base, mailbox_record_key([9; 32], [2; 32], 7, 0).unwrap());
        assert_ne!(base, mailbox_record_key([1; 32], [9; 32], 7, 0).unwrap());
        assert_ne!(base, mailbox_record_key([1; 32], [2; 32], 8, 0).unwrap());
        assert_ne!(base, mailbox_record_key([1; 32], [2; 32], 7, 1).unwrap());
        assert!(mailbox_record_key([0; 32], [2; 32], 7, 0).is_err());
    }

    #[test]
    fn mailbox_record_round_trips_and_is_deterministic() {
        let record = record(b"opaque-ciphertext".to_vec());
        let first = record.encode().unwrap();
        let second = record.encode().unwrap();
        assert_eq!(first, second);
        assert_eq!(MailboxRecord::decode(&first).unwrap(), record);
        assert_eq!(
            decode_mailbox_record_for_key(&record.record_key().unwrap(), &first).unwrap(),
            record
        );
        assert_eq!(
            record.hash().unwrap(),
            <[u8; HASH_BYTES]>::try_from(&first[first.len() - HASH_BYTES..]).unwrap()
        );
    }

    #[test]
    fn mailbox_record_rejects_tampering_trailing_bytes_and_text() {
        let record = record(b"opaque-ciphertext".to_vec());
        let encoded = record.encode().unwrap();

        let mut tampered = encoded.clone();
        let ciphertext = CIPHERTEXT_OFFSET;
        tampered[ciphertext] ^= 1;
        assert!(MailboxRecord::decode(&tampered).is_err());

        let mut trailing = encoded;
        trailing.push(0);
        assert!(MailboxRecord::decode(&trailing).is_err());
        assert!(MailboxRecord::decode(b"arbitrary text is not a mailbox record").is_err());
    }

    #[test]
    fn mailbox_record_is_bounded_to_eight_kibibytes() {
        let maximum = record(vec![0x5a; MAX_CIPHERTEXT_BYTES]);
        assert_eq!(maximum.encode().unwrap().len(), MAX_MAILBOX_RECORD_BYTES);
        let oversized = record(vec![0x5a; MAX_CIPHERTEXT_BYTES + 1]);
        assert!(oversized.encode().is_err());
    }

    #[test]
    fn mailbox_record_requires_consistent_shard_metadata() {
        let mut invalid = record(vec![1]);
        invalid.shard_index = 1;
        invalid.shard_count = 1;
        assert!(invalid.encode().is_err());

        invalid.shard_index = 0;
        invalid.shard_count = 0;
        assert!(invalid.encode().is_err());
    }
}
