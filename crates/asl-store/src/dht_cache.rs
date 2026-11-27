use asl_types::{
    error::AslError,
    ids::{AgentId, PeerId},
    record::RecordKind,
};
use rusqlite::{OptionalExtension, params};

use crate::{Store, database_error};

const MAX_CACHED_RECORD_BYTES: usize = 8 * 1024;
const MAX_CACHED_PROVIDER_ADDRESSES: usize = 8;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachedDhtRecord {
    pub agent_id: AgentId,
    pub kind: RecordKind,
    pub sequence: u64,
    pub registry_sequence: u64,
    pub record: Vec<u8>,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachedDhtProvider {
    pub key: [u8; 32],
    pub provider_id: PeerId,
    pub addresses: Vec<String>,
    pub expires_at_ms: u64,
}

impl Store {
    pub fn cache_dht_record(&self, record: &CachedDhtRecord, now_ms: u64) -> Result<(), AslError> {
        if record.record.is_empty() || record.record.len() > MAX_CACHED_RECORD_BYTES {
            return Err(AslError::InvalidMessage);
        }
        self.connection
            .execute(
                "INSERT INTO dht_record_cache(
                    agent_id,kind,sequence,registry_sequence,record,expires_at_ms,updated_at_ms
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7)
                 ON CONFLICT(agent_id,kind) DO UPDATE SET
                   sequence=excluded.sequence,
                   registry_sequence=excluded.registry_sequence,
                   record=excluded.record,
                   expires_at_ms=excluded.expires_at_ms,
                   updated_at_ms=excluded.updated_at_ms
                 WHERE excluded.sequence >= dht_record_cache.sequence",
                params![
                    crate::chain::agent_text(record.agent_id),
                    kind_code(record.kind),
                    i64::try_from(record.sequence).map_err(|_| AslError::InvalidMessage)?,
                    i64::try_from(record.registry_sequence)
                        .map_err(|_| AslError::InvalidMessage)?,
                    &record.record,
                    i64::try_from(record.expires_at_ms).map_err(|_| AslError::InvalidMessage)?,
                    i64::try_from(now_ms).map_err(|_| AslError::InvalidMessage)?,
                ],
            )
            .map(|_| ())
            .map_err(database_error)
    }

    pub fn cached_dht_record(
        &self,
        agent_id: AgentId,
        kind: RecordKind,
        now_ms: u64,
    ) -> Result<Option<CachedDhtRecord>, AslError> {
        self.connection
            .query_row(
                "SELECT sequence,registry_sequence,record,expires_at_ms
                 FROM dht_record_cache
                 WHERE agent_id=?1 AND kind=?2 AND expires_at_ms>?3",
                params![
                    crate::chain::agent_text(agent_id),
                    kind_code(kind),
                    i64::try_from(now_ms).map_err(|_| AslError::InvalidMessage)?,
                ],
                |row| {
                    let sequence = u64::try_from(row.get::<_, i64>(0)?)
                        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, 0))?;
                    let registry_sequence = u64::try_from(row.get::<_, i64>(1)?)
                        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(1, 0))?;
                    let record = row.get::<_, Vec<u8>>(2)?;
                    let expires_at_ms = u64::try_from(row.get::<_, i64>(3)?)
                        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(3, 0))?;
                    Ok(CachedDhtRecord {
                        agent_id,
                        kind,
                        sequence,
                        registry_sequence,
                        record,
                        expires_at_ms,
                    })
                },
            )
            .optional()
            .map_err(database_error)
    }

    pub fn cached_dht_records(
        &self,
        now_ms: u64,
        limit: u16,
    ) -> Result<Vec<CachedDhtRecord>, AslError> {
        let limit = i64::from(limit.clamp(1, 512));
        let mut statement = self
            .connection
            .prepare(
                "SELECT agent_id,kind,sequence,registry_sequence,record,expires_at_ms
                 FROM dht_record_cache
                 WHERE expires_at_ms>?1
                 ORDER BY updated_at_ms DESC LIMIT ?2",
            )
            .map_err(database_error)?;
        let rows = statement
            .query_map(
                params![
                    i64::try_from(now_ms).map_err(|_| AslError::InvalidMessage)?,
                    limit
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .map_err(database_error)?;
        let mut records = Vec::new();
        for row in rows {
            let (agent, kind, sequence, registry_sequence, record, expires_at_ms) =
                row.map_err(database_error)?;
            let agent_id = AgentId(
                bs58::decode(agent)
                    .into_vec()
                    .map_err(|_| AslError::InvalidDatabase)?
                    .try_into()
                    .map_err(|_| AslError::InvalidDatabase)?,
            );
            let kind = kind_from_code(kind)?;
            records.push(CachedDhtRecord {
                agent_id,
                kind,
                sequence: u64::try_from(sequence).map_err(|_| AslError::InvalidDatabase)?,
                registry_sequence: u64::try_from(registry_sequence)
                    .map_err(|_| AslError::InvalidDatabase)?,
                record,
                expires_at_ms: u64::try_from(expires_at_ms)
                    .map_err(|_| AslError::InvalidDatabase)?,
            });
        }
        Ok(records)
    }

    pub fn cache_dht_provider(
        &self,
        key: [u8; 32],
        provider_id: PeerId,
        addresses: &[String],
        expires_at_ms: u64,
        now_ms: u64,
    ) -> Result<(), AslError> {
        if addresses.len() > MAX_CACHED_PROVIDER_ADDRESSES
            || addresses
                .iter()
                .any(|address| address.is_empty() || address.len() > 512)
        {
            return Err(AslError::InvalidMessage);
        }
        let addresses = serde_json::to_string(addresses).map_err(|_| AslError::InvalidMessage)?;
        self.connection
            .execute(
                "INSERT INTO dht_provider_cache(
                    key,provider_id,addresses_json,expires_at_ms,updated_at_ms
                 ) VALUES (?1,?2,?3,?4,?5)
                 ON CONFLICT(key) DO UPDATE SET
                   provider_id=excluded.provider_id,
                   addresses_json=excluded.addresses_json,
                   expires_at_ms=excluded.expires_at_ms,
                   updated_at_ms=excluded.updated_at_ms",
                params![
                    hex::encode(key),
                    bs58::encode(provider_id.as_bytes()).into_string(),
                    addresses,
                    i64::try_from(expires_at_ms).map_err(|_| AslError::InvalidMessage)?,
                    i64::try_from(now_ms).map_err(|_| AslError::InvalidMessage)?,
                ],
            )
            .map(|_| ())
            .map_err(database_error)
    }

    pub fn cached_dht_providers(
        &self,
        now_ms: u64,
        limit: u16,
    ) -> Result<Vec<CachedDhtProvider>, AslError> {
        let limit = i64::from(limit.clamp(1, 512));
        let mut statement = self
            .connection
            .prepare(
                "SELECT key,provider_id,addresses_json,expires_at_ms
                 FROM dht_provider_cache
                 WHERE expires_at_ms>?1
                 ORDER BY updated_at_ms DESC LIMIT ?2",
            )
            .map_err(database_error)?;
        let rows = statement
            .query_map(
                params![
                    i64::try_from(now_ms).map_err(|_| AslError::InvalidMessage)?,
                    limit
                ],
                |row| {
                    let key = row.get::<_, String>(0)?;
                    let provider = row.get::<_, String>(1)?;
                    let addresses = row.get::<_, String>(2)?;
                    let expires_at_ms = u64::try_from(row.get::<_, i64>(3)?)
                        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(3, 0))?;
                    Ok((key, provider, addresses, expires_at_ms))
                },
            )
            .map_err(database_error)?;
        let mut providers = Vec::new();
        for row in rows {
            let (key, provider, addresses, expires_at_ms) = row.map_err(database_error)?;
            let key = parse_key(&key)?;
            let provider_id = PeerId::from_bytes(
                bs58::decode(provider)
                    .into_vec()
                    .map_err(|_| AslError::InvalidDatabase)?,
            )
            .map_err(|_| AslError::InvalidDatabase)?;
            let addresses =
                serde_json::from_str(&addresses).map_err(|_| AslError::InvalidDatabase)?;
            providers.push(CachedDhtProvider {
                key,
                provider_id,
                addresses,
                expires_at_ms,
            });
        }
        Ok(providers)
    }

    pub fn prune_dht_cache(&self, now_ms: u64) -> Result<(), AslError> {
        let now = i64::try_from(now_ms).map_err(|_| AslError::InvalidMessage)?;
        self.connection
            .execute(
                "DELETE FROM dht_record_cache WHERE expires_at_ms<=?1",
                [now],
            )
            .map_err(database_error)?;
        self.connection
            .execute(
                "DELETE FROM dht_provider_cache WHERE expires_at_ms<=?1",
                [now],
            )
            .map_err(database_error)?;
        Ok(())
    }
}

fn kind_code(kind: RecordKind) -> i64 {
    match kind {
        RecordKind::Profile => 1,
        RecordKind::DeviceDirectory => 2,
        RecordKind::ShortCode => 3,
    }
}

fn kind_from_code(value: i64) -> Result<RecordKind, AslError> {
    match value {
        1 => Ok(RecordKind::Profile),
        2 => Ok(RecordKind::DeviceDirectory),
        3 => Ok(RecordKind::ShortCode),
        _ => Err(AslError::InvalidDatabase),
    }
}

fn parse_key(value: &str) -> Result<[u8; 32], AslError> {
    let mut key = [0; 32];
    hex::decode_to_slice(value, &mut key).map_err(|_| AslError::InvalidDatabase)?;
    Ok(key)
}
