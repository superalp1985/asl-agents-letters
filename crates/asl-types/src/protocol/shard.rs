use cbor2::Value;

use super::cbor::{
    as_u64, byte_string, check_keys, decode_canonical, fields, finish, fixed_bytes, map, take, uint,
};
use crate::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId, Signature65},
};

pub const SHARD_BINDING_SIGNING_DOMAIN: &[u8] = b"ASL-SHARD-BINDING-v1\0";
pub const SHARD_FORWARD_SIGNING_DOMAIN: &[u8] = b"ASL-SHARD-FORWARD-v1\0";
pub const MAX_SHARD_BINDING_BYTES: usize = 768;
pub const MAX_SHARD_FORWARD_BYTES: usize = 60 * 1024;
pub const MAX_SHARD_FORWARD_PAYLOAD_BYTES: usize = 56 * 1024;
pub const MAX_SHARD_BINDING_LIFETIME_MS: u64 = 30 * 24 * 60 * 60 * 1_000;
pub const MAX_SHARD_FORWARD_LIFETIME_MS: u64 = 10 * 60 * 1_000;
pub const MAX_SHARD_FORWARD_HOP: u8 = 1;

const MAGIC: &[u8; 4] = b"ASLS";
const VERSION: u64 = 1;
const BINDING_KIND: u64 = 1;
const FORWARD_KIND: u64 = 2;
const MAX_TIME_MS: u64 = i64::MAX as u64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShardBinding {
    pub message_id: Id128,
    pub logical_root: Hash32,
    pub child: Hash32,
    pub shard_index: u16,
    pub owner_agent: AgentId,
    pub owner_peer: PeerId,
    pub revision: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub signature: Signature65,
}

impl ShardBinding {
    pub fn encode(&self) -> Result<Vec<u8>, AslError> {
        self.validate_shape()?;
        let bytes =
            cbor2::to_canonical_vec(&self.value(true)).map_err(|_| AslError::InvalidMessage)?;
        if bytes.is_empty() || bytes.len() > MAX_SHARD_BINDING_BYTES {
            return Err(AslError::InvalidMessage);
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, AslError> {
        if bytes.is_empty() || bytes.len() > MAX_SHARD_BINDING_BYTES {
            return Err(AslError::InvalidMessage);
        }
        let mut fields = fields(decode_canonical(bytes)?)?;
        check_keys(&fields, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])?;
        if fixed_bytes::<4>(take(&mut fields, 0)?)? != *MAGIC
            || as_u64(take(&mut fields, 1)?)? != VERSION
            || as_u64(take(&mut fields, 2)?)? != BINDING_KIND
        {
            return Err(AslError::InvalidMessage);
        }
        let binding = Self {
            message_id: Id128(fixed_bytes(take(&mut fields, 3)?)?),
            logical_root: Hash32(fixed_bytes(take(&mut fields, 4)?)?),
            child: Hash32(fixed_bytes(take(&mut fields, 5)?)?),
            shard_index: u16::try_from(as_u64(take(&mut fields, 6)?)?)
                .map_err(|_| AslError::InvalidMessage)?,
            owner_agent: AgentId(fixed_bytes(take(&mut fields, 7)?)?),
            owner_peer: PeerId::from_bytes(byte_string(take(&mut fields, 8)?, 1, 128)?)
                .map_err(|_| AslError::InvalidMessage)?,
            revision: as_u64(take(&mut fields, 9)?)?,
            issued_at_ms: as_u64(take(&mut fields, 10)?)?,
            expires_at_ms: as_u64(take(&mut fields, 11)?)?,
            signature: Signature65(fixed_bytes(take(&mut fields, 12)?)?),
        };
        finish(fields)?;
        binding.validate_shape()?;
        Ok(binding)
    }

    pub fn signing_preimage(&self) -> Result<Vec<u8>, AslError> {
        self.validate_shape()?;
        let unsigned =
            cbor2::to_canonical_vec(&self.value(false)).map_err(|_| AslError::InvalidMessage)?;
        let mut preimage = Vec::with_capacity(SHARD_BINDING_SIGNING_DOMAIN.len() + unsigned.len());
        preimage.extend_from_slice(SHARD_BINDING_SIGNING_DOMAIN);
        preimage.extend_from_slice(&unsigned);
        Ok(preimage)
    }

    pub fn validate_at(&self, now_ms: u64) -> Result<(), AslError> {
        self.validate_shape()?;
        if self.issued_at_ms > now_ms {
            return Err(AslError::InvalidMessage);
        }
        if now_ms >= self.expires_at_ms {
            return Err(AslError::ExpiredMessage);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), AslError> {
        if self.message_id.0 == [0; 16]
            || self.logical_root.0 == [0; 32]
            || self.child.0 == [0; 32]
            || self.logical_root == self.child
            || !(1..=19).contains(&self.shard_index)
            || self.owner_agent.0 == [0; 32]
            || self.owner_peer.as_bytes().is_empty()
            || !(1..=i64::MAX as u64).contains(&self.revision)
            || self.expires_at_ms > MAX_TIME_MS
            || self.expires_at_ms <= self.issued_at_ms
            || self
                .expires_at_ms
                .checked_sub(self.issued_at_ms)
                .is_none_or(|lifetime| lifetime > MAX_SHARD_BINDING_LIFETIME_MS)
        {
            return Err(AslError::InvalidMessage);
        }
        Ok(())
    }

    fn value(&self, signed: bool) -> Value {
        let mut entries = vec![
            (0, Value::Bytes(MAGIC.to_vec())),
            (1, uint(VERSION)),
            (2, uint(BINDING_KIND)),
            (3, Value::Bytes(self.message_id.0.to_vec())),
            (4, Value::Bytes(self.logical_root.0.to_vec())),
            (5, Value::Bytes(self.child.0.to_vec())),
            (6, uint(u64::from(self.shard_index))),
            (7, Value::Bytes(self.owner_agent.0.to_vec())),
            (8, Value::Bytes(self.owner_peer.as_bytes().to_vec())),
            (9, uint(self.revision)),
            (10, uint(self.issued_at_ms)),
            (11, uint(self.expires_at_ms)),
        ];
        if signed {
            entries.push((12, Value::Bytes(self.signature.0.to_vec())));
        }
        map(entries)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShardForward {
    pub message_id: Id128,
    pub logical_root: Hash32,
    pub source_child: Hash32,
    pub target_child: Hash32,
    pub source_agent: AgentId,
    pub source_peer: PeerId,
    pub source_mls_epoch: u64,
    pub source_membership_epoch: u64,
    pub source_message_id: Id128,
    pub hop: u8,
    pub observed_at_ms: u64,
    pub expires_at_ms: u64,
    pub payload: Vec<u8>,
    pub target_binding: Option<ShardBinding>,
    pub attestor_agent: AgentId,
    pub attestor_peer: PeerId,
    pub signature: Signature65,
}

impl ShardForward {
    pub fn encode(&self) -> Result<Vec<u8>, AslError> {
        self.validate_shape()?;
        let bytes =
            cbor2::to_canonical_vec(&self.value(true)?).map_err(|_| AslError::InvalidMessage)?;
        if bytes.is_empty() || bytes.len() > MAX_SHARD_FORWARD_BYTES {
            return Err(AslError::InvalidMessage);
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, AslError> {
        if bytes.is_empty() || bytes.len() > MAX_SHARD_FORWARD_BYTES {
            return Err(AslError::InvalidMessage);
        }
        let mut fields = fields(decode_canonical(bytes)?)?;
        check_keys(
            &fields,
            &[
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
            ],
        )?;
        if fixed_bytes::<4>(take(&mut fields, 0)?)? != *MAGIC
            || as_u64(take(&mut fields, 1)?)? != VERSION
            || as_u64(take(&mut fields, 2)?)? != FORWARD_KIND
        {
            return Err(AslError::InvalidMessage);
        }
        let binding = match take(&mut fields, 15)? {
            Value::Null => None,
            value => Some(ShardBinding::decode(&byte_string(
                value,
                1,
                MAX_SHARD_BINDING_BYTES,
            )?)?),
        };
        let forward = Self {
            message_id: Id128(fixed_bytes(take(&mut fields, 3)?)?),
            logical_root: Hash32(fixed_bytes(take(&mut fields, 4)?)?),
            source_child: Hash32(fixed_bytes(take(&mut fields, 5)?)?),
            target_child: Hash32(fixed_bytes(take(&mut fields, 6)?)?),
            source_agent: AgentId(fixed_bytes(take(&mut fields, 7)?)?),
            source_peer: PeerId::from_bytes(byte_string(take(&mut fields, 8)?, 1, 128)?)
                .map_err(|_| AslError::InvalidMessage)?,
            source_mls_epoch: as_u64(take(&mut fields, 9)?)?,
            source_membership_epoch: as_u64(take(&mut fields, 10)?)?,
            source_message_id: Id128(fixed_bytes(take(&mut fields, 11)?)?),
            hop: u8::try_from(as_u64(take(&mut fields, 12)?)?)
                .map_err(|_| AslError::InvalidMessage)?,
            observed_at_ms: as_u64(take(&mut fields, 13)?)?,
            expires_at_ms: as_u64(take(&mut fields, 14)?)?,
            target_binding: binding,
            payload: byte_string(take(&mut fields, 16)?, 1, MAX_SHARD_FORWARD_PAYLOAD_BYTES)?,
            attestor_agent: AgentId(fixed_bytes(take(&mut fields, 17)?)?),
            attestor_peer: PeerId::from_bytes(byte_string(take(&mut fields, 18)?, 1, 128)?)
                .map_err(|_| AslError::InvalidMessage)?,
            signature: Signature65(fixed_bytes(take(&mut fields, 19)?)?),
        };
        finish(fields)?;
        forward.validate_shape()?;
        Ok(forward)
    }

    pub fn signing_preimage(&self) -> Result<Vec<u8>, AslError> {
        self.validate_shape()?;
        let unsigned =
            cbor2::to_canonical_vec(&self.value(false)?).map_err(|_| AslError::InvalidMessage)?;
        let mut preimage = Vec::with_capacity(SHARD_FORWARD_SIGNING_DOMAIN.len() + unsigned.len());
        preimage.extend_from_slice(SHARD_FORWARD_SIGNING_DOMAIN);
        preimage.extend_from_slice(&unsigned);
        Ok(preimage)
    }

    pub fn validate_at(&self, now_ms: u64) -> Result<(), AslError> {
        self.validate_shape()?;
        if let Some(binding) = &self.target_binding {
            binding.validate_at(now_ms)?;
        }
        if self.observed_at_ms > now_ms {
            return Err(AslError::InvalidMessage);
        }
        if now_ms >= self.expires_at_ms {
            return Err(AslError::ExpiredMessage);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), AslError> {
        if let Some(binding) = &self.target_binding {
            binding.validate_shape()?;
        }
        if self.message_id.0 == [0; 16]
            || self.logical_root.0 == [0; 32]
            || self.source_child.0 == [0; 32]
            || self.target_child.0 == [0; 32]
            || self.source_child == self.target_child
            || self.source_agent.0 == [0; 32]
            || self.source_peer.as_bytes().is_empty()
            || self.source_mls_epoch > i64::MAX as u64
            || self.source_membership_epoch == 0
            || self.source_membership_epoch > i64::MAX as u64
            || self.source_message_id.0 == [0; 16]
            || self.hop != MAX_SHARD_FORWARD_HOP
            || self.expires_at_ms > MAX_TIME_MS
            || self.expires_at_ms <= self.observed_at_ms
            || self
                .expires_at_ms
                .checked_sub(self.observed_at_ms)
                .is_none_or(|lifetime| lifetime > MAX_SHARD_FORWARD_LIFETIME_MS)
            || self.payload.is_empty()
            || self.payload.len() > MAX_SHARD_FORWARD_PAYLOAD_BYTES
            || self.attestor_agent.0 == [0; 32]
            || self.attestor_peer.as_bytes().is_empty()
        {
            return Err(AslError::InvalidMessage);
        }
        match &self.target_binding {
            None if self.target_child == self.logical_root => {}
            Some(binding)
                if self.target_child != self.logical_root
                    && binding.logical_root == self.logical_root
                    && binding.child == self.target_child
                    && binding.owner_agent == self.attestor_agent
                    && binding.owner_peer == self.attestor_peer => {}
            _ => return Err(AslError::InvalidMessage),
        }
        Ok(())
    }

    fn value(&self, signed: bool) -> Result<Value, AslError> {
        let mut entries = vec![
            (0, Value::Bytes(MAGIC.to_vec())),
            (1, uint(VERSION)),
            (2, uint(FORWARD_KIND)),
            (3, Value::Bytes(self.message_id.0.to_vec())),
            (4, Value::Bytes(self.logical_root.0.to_vec())),
            (5, Value::Bytes(self.source_child.0.to_vec())),
            (6, Value::Bytes(self.target_child.0.to_vec())),
            (7, Value::Bytes(self.source_agent.0.to_vec())),
            (8, Value::Bytes(self.source_peer.as_bytes().to_vec())),
            (9, uint(self.source_mls_epoch)),
            (10, uint(self.source_membership_epoch)),
            (11, Value::Bytes(self.source_message_id.0.to_vec())),
            (12, uint(u64::from(self.hop))),
            (13, uint(self.observed_at_ms)),
            (14, uint(self.expires_at_ms)),
            (
                15,
                match &self.target_binding {
                    Some(binding) => Value::Bytes(binding.encode()?),
                    None => Value::Null,
                },
            ),
            (16, Value::Bytes(self.payload.clone())),
            (17, Value::Bytes(self.attestor_agent.0.to_vec())),
            (18, Value::Bytes(self.attestor_peer.as_bytes().to_vec())),
        ];
        if signed {
            entries.push((19, Value::Bytes(self.signature.0.to_vec())));
        }
        Ok(map(entries))
    }
}
