use std::{borrow::Cow, collections::HashMap, time::Instant};

use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32},
    protocol::ConceptRef,
    record::{RecordKind, RecordPayload, decode_record},
};
pub use libp2p::kad::RecordKey;
use libp2p::{
    PeerId,
    kad::{
        ProviderRecord, Record,
        store::{self, MemoryStore, MemoryStoreConfig, RecordStore},
    },
};

pub const MAX_DHT_VALUE_BYTES: usize = 8 * 1024;
pub const MAX_DHT_RECORDS: usize = 10_000;
pub const MAX_DHT_STORE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_DHT_PROVIDERS_PER_KEY: usize = 20;
pub const MAX_DHT_PROVIDER_ADDRESSES: usize = 8;
const MAX_VALUE_BYTES_FOR_MEMORY_STORE: usize = MAX_DHT_VALUE_BYTES + 1;
const KEY_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DhtAudience {
    Public,
    Contacts,
    Peers,
    Group,
}

impl DhtAudience {
    pub fn allows_public_advertisement(self) -> bool {
        self == Self::Public
    }
}

pub fn concept_key(concept: ConceptRef) -> Result<RecordKey, AslError> {
    if !concept.is_topic() {
        return Err(AslError::InvalidMessage);
    }
    let mut bytes = Vec::with_capacity(6);
    bytes.extend_from_slice(&concept.vocabulary_id.to_be_bytes());
    bytes.extend_from_slice(&concept.concept_id.to_be_bytes());
    Ok(domain_key(b"ASL-CONCEPT-v1\0", &bytes))
}

pub fn content_key(content_id: Hash32) -> RecordKey {
    domain_key(b"ASL-CONTENT-v1\0", content_id.as_bytes())
}

pub fn handle_key(code: u64) -> Result<RecordKey, AslError> {
    if code >= 10_000_000_000_000_000 {
        return Err(AslError::InvalidMessage);
    }
    let digits = format!("{code:016}");
    Ok(domain_key(b"ASL-HANDLE-v1\0", digits.as_bytes()))
}

pub fn identity_record_key(agent: AgentId, kind: RecordKind) -> Result<RecordKey, AslError> {
    let domain = match kind {
        RecordKind::Profile => b"ASL-PROFILE-v1\0".as_slice(),
        RecordKind::DeviceDirectory => b"ASL-DEVICE-DIRECTORY-v1\0".as_slice(),
        RecordKind::ShortCode => b"ASL-SHORT-CODE-CLAIM-v1\0".as_slice(),
    };
    Ok(domain_key(domain, agent.as_bytes()))
}

pub fn record_key_for_payload(payload: &RecordPayload) -> Result<RecordKey, AslError> {
    identity_record_key(payload.agent_id(), payload.kind())
}

fn domain_key(domain: &[u8], value: &[u8]) -> RecordKey {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(value);
    RecordKey::new(hasher.finalize().as_bytes())
}

pub struct BoundedRecordStore {
    inner: MemoryStore,
    record_sizes: HashMap<RecordKey, usize>,
    provider_sizes: HashMap<(RecordKey, PeerId), usize>,
    used_bytes: usize,
}

impl BoundedRecordStore {
    pub fn new(local_peer_id: PeerId) -> Self {
        let config = MemoryStoreConfig {
            max_records: MAX_DHT_RECORDS,
            max_value_bytes: MAX_VALUE_BYTES_FOR_MEMORY_STORE,
            max_providers_per_key: MAX_DHT_PROVIDERS_PER_KEY,
            max_provided_keys: MAX_DHT_RECORDS,
        };
        Self {
            inner: MemoryStore::with_config(local_peer_id, config),
            record_sizes: HashMap::new(),
            provider_sizes: HashMap::new(),
            used_bytes: 0,
        }
    }

    pub fn record_count(&self) -> usize {
        self.record_sizes.len()
    }

    pub fn used_bytes(&self) -> usize {
        self.used_bytes
    }

    fn remove_expired(&mut self) {
        let now = Instant::now();
        let expired_records: Vec<_> = self
            .inner
            .records()
            .filter(|record| record.is_expired(now))
            .map(|record| record.key.clone())
            .collect();
        for key in expired_records {
            self.inner.remove(&key);
            if let Some(size) = self.record_sizes.remove(&key) {
                self.used_bytes = self.used_bytes.saturating_sub(size);
            }
        }

        let expired_providers: Vec<_> = self
            .provider_sizes
            .keys()
            .filter(|(key, peer)| {
                !self
                    .inner
                    .providers(key)
                    .iter()
                    .any(|provider| provider.provider == *peer && !provider.is_expired(now))
            })
            .cloned()
            .collect();
        for (key, peer) in expired_providers {
            self.inner.remove_provider(&key, &peer);
            if let Some(size) = self.provider_sizes.remove(&(key, peer)) {
                self.used_bytes = self.used_bytes.saturating_sub(size);
            }
        }
    }
}

impl RecordStore for BoundedRecordStore {
    type RecordsIter<'a> = <MemoryStore as RecordStore>::RecordsIter<'a>;
    type ProvidedIter<'a> = <MemoryStore as RecordStore>::ProvidedIter<'a>;

    fn get(&self, key: &RecordKey) -> Option<Cow<'_, Record>> {
        self.inner.get(key)
    }

    fn put(&mut self, record: Record) -> store::Result<()> {
        self.remove_expired();
        if record.key.as_ref().len() != KEY_BYTES || record.value.len() > MAX_DHT_VALUE_BYTES {
            return Err(store::Error::ValueTooLarge);
        }
        let signed = decode_record(&record.value).map_err(|_| store::Error::ValueTooLarge)?;
        let payload = &signed.record.payload;
        if !matches!(
            payload,
            RecordPayload::Profile(_)
                | RecordPayload::DeviceDirectory(_)
                | RecordPayload::ShortCode(_)
        ) || record_key_for_payload(payload).map_err(|_| store::Error::ValueTooLarge)?
            != record.key
        {
            return Err(store::Error::ValueTooLarge);
        }

        let existing_size = self.record_sizes.get(&record.key).copied().unwrap_or(0);
        if let Some(existing) = self.inner.get(&record.key) {
            if !existing.is_expired(Instant::now()) {
                let previous =
                    decode_record(&existing.value).map_err(|_| store::Error::ValueTooLarge)?;
                let previous_record = &previous.record;
                let candidate = &signed.record;
                if previous_record.payload.agent_id() != candidate.payload.agent_id()
                    || previous_record.payload.kind() != candidate.payload.kind()
                    || candidate.sequence < previous_record.sequence
                    || (candidate.sequence == previous_record.sequence
                        && existing.value != record.value)
                {
                    return Err(store::Error::ValueTooLarge);
                }
            } else {
                self.inner.remove(&record.key);
                self.record_sizes.remove(&record.key);
                self.used_bytes = self.used_bytes.saturating_sub(existing_size);
            }
        }

        let next_bytes = self
            .used_bytes
            .saturating_sub(existing_size)
            .saturating_add(record.value.len());
        if next_bytes > MAX_DHT_STORE_BYTES
            || (existing_size == 0 && self.record_sizes.len() >= MAX_DHT_RECORDS)
        {
            return Err(store::Error::MaxRecords);
        }

        self.inner.put(record.clone())?;
        self.record_sizes.insert(record.key, record.value.len());
        self.used_bytes = next_bytes;
        Ok(())
    }

    fn remove(&mut self, key: &RecordKey) {
        self.inner.remove(key);
        if let Some(size) = self.record_sizes.remove(key) {
            self.used_bytes = self.used_bytes.saturating_sub(size);
        }
    }

    fn records(&self) -> Self::RecordsIter<'_> {
        self.inner.records()
    }

    fn add_provider(&mut self, mut record: ProviderRecord) -> store::Result<()> {
        self.remove_expired();
        if record.key.as_ref().len() != KEY_BYTES
            || record.addresses.len() > MAX_DHT_PROVIDER_ADDRESSES
        {
            return Err(store::Error::ValueTooLarge);
        }

        let entry = (record.key.clone(), record.provider);
        let existing_size = self.provider_sizes.get(&entry).copied().unwrap_or(0);
        let providers = self.inner.providers(&record.key);
        if existing_size == 0 && providers.len() >= MAX_DHT_PROVIDERS_PER_KEY {
            return Ok(());
        }
        if existing_size == 0 && self.provider_sizes.len() >= MAX_DHT_RECORDS {
            return Err(store::Error::MaxProvidedKeys);
        }

        let size = provider_record_size(&record);
        let next_bytes = self
            .used_bytes
            .saturating_sub(existing_size)
            .saturating_add(size);
        if next_bytes > MAX_DHT_STORE_BYTES {
            return Err(store::Error::MaxProvidedKeys);
        }

        record.expires = record
            .expires
            .or_else(|| Some(Instant::now() + std::time::Duration::from_secs(3_600)));
        self.inner.add_provider(record.clone())?;
        if self
            .inner
            .providers(&record.key)
            .iter()
            .any(|p| p.provider == record.provider)
        {
            self.provider_sizes.insert(entry, size);
            self.used_bytes = next_bytes;
        }
        Ok(())
    }

    fn providers(&self, key: &RecordKey) -> Vec<ProviderRecord> {
        self.inner.providers(key)
    }

    fn provided(&self) -> Self::ProvidedIter<'_> {
        self.inner.provided()
    }

    fn remove_provider(&mut self, key: &RecordKey, peer: &PeerId) {
        self.inner.remove_provider(key, peer);
        if let Some(size) = self.provider_sizes.remove(&(key.clone(), *peer)) {
            self.used_bytes = self.used_bytes.saturating_sub(size);
        }
    }
}

fn provider_record_size(record: &ProviderRecord) -> usize {
    record.key.as_ref().len()
        + record.provider.to_bytes().len()
        + record
            .addresses
            .iter()
            .map(|address| address.to_vec().len())
            .sum::<usize>()
        + 32
}

#[cfg(test)]
mod tests {
    use super::*;
    use asl_types::record::{ShortCodeClaim, encode_record_payload};

    #[test]
    fn public_key_functions_require_supported_concepts_and_fixed_short_codes() {
        assert!(concept_key(ConceptRef::RUST).is_ok());
        assert!(
            concept_key(ConceptRef {
                vocabulary_id: 2,
                concept_id: 101,
            })
            .is_err()
        );
        assert!(handle_key(9_999_999_999_999_999).is_ok());
        assert!(handle_key(10_000_000_000_000_000).is_err());
    }

    #[test]
    fn short_code_declarations_have_agent_scoped_record_keys() {
        let agent = AgentId([7; 32]);
        let payload = RecordPayload::ShortCode(ShortCodeClaim {
            agent_id: agent,
            code: asl_types::record::short_code(agent),
        });
        assert!(encode_record_payload(&payload).is_ok());
        let key = record_key_for_payload(&payload).unwrap();
        assert_ne!(
            key,
            handle_key(asl_types::record::short_code(agent)).unwrap()
        );
    }
}
