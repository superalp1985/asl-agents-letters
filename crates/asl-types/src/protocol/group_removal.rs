use cbor2::Value;

use super::cbor::{array, as_u64, decode_canonical, fixed_bytes, uint};
use crate::{
    error::AslError,
    ids::{Id128, PeerId},
};

pub const GROUP_REMOVAL_REQUEST_TTL_MS: u64 = 300_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupRemovalRequest {
    pub message_id: Id128,
    pub target: PeerId,
    pub expires_at_ms: u64,
}

impl GroupRemovalRequest {
    pub fn encode(&self) -> Result<Vec<u8>, AslError> {
        self.validate()?;
        cbor2::to_canonical_vec(&Value::Array(vec![
            uint(1),
            uint(1),
            Value::Bytes(self.message_id.0.to_vec()),
            Value::Bytes(self.target.as_bytes().to_vec()),
            uint(self.expires_at_ms),
        ]))
        .map_err(|_| AslError::InvalidMessage)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, AslError> {
        if bytes.len() > 160 {
            return Err(AslError::InvalidMessage);
        }
        let [version, operation, id, Value::Bytes(target), expires] =
            <[Value; 5]>::try_from(array(decode_canonical(bytes)?, 5)?)
                .map_err(|_| AslError::InvalidMessage)?
        else {
            return Err(AslError::InvalidMessage);
        };
        if as_u64(version)? != 1 || as_u64(operation)? != 1 {
            return Err(AslError::InvalidMessage);
        }
        let request = Self {
            message_id: Id128(fixed_bytes(id)?),
            target: PeerId::from_bytes(target).map_err(|_| AslError::InvalidMessage)?,
            expires_at_ms: as_u64(expires)?,
        };
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<(), AslError> {
        if self.message_id.0 == [0; 16] || !(1..=i64::MAX as u64).contains(&self.expires_at_ms) {
            return Err(AslError::InvalidMessage);
        }
        Ok(())
    }
}
