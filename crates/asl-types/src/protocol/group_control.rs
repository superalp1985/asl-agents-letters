use cbor2::Value;

use crate::{
    error::AslError,
    ids::{Id128, PeerId},
    protocol::cbor::{
        array, check_keys, decode_canonical, fields, finish, fixed_bytes, map, take, uint,
    },
};

pub const MAX_GROUP_CONTROL_BYTES: usize = 64 * 1024;
pub const MAX_GROUP_CONTROL_PEERS: usize = 512;
pub const GROUP_ALLOW_MEMBER_TEXT: u8 = 1;
pub const GROUP_ALLOW_MEMBER_FILES: u8 = 2;
pub const GROUP_ALLOW_MEMBER_INVITE: u8 = 4;
pub const GROUP_ALLOWED_PERMISSION_BITS: u8 =
    GROUP_ALLOW_MEMBER_TEXT | GROUP_ALLOW_MEMBER_FILES | GROUP_ALLOW_MEMBER_INVITE;

/// Owner-authoritative, deterministic policy carried only inside MLS
/// application plaintext. The creator is the initial owner; key 6 can transfer
/// the effective owner to another active device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupControl {
    pub message_id: Id128,
    pub policy_revision: u64,
    pub permissions: u8,
    pub admins: Vec<PeerId>,
    pub muted: Vec<PeerId>,
    pub owner: Option<PeerId>,
}

impl GroupControl {
    pub fn decode(bytes: &[u8]) -> Result<Self, AslError> {
        if bytes.is_empty() || bytes.len() > MAX_GROUP_CONTROL_BYTES {
            return Err(AslError::InvalidMessage);
        }
        let mut fields = fields(decode_canonical(bytes)?)?;
        check_keys(&fields, &[1, 2, 3, 4, 5, 6])?;
        let message_id = Id128(fixed_bytes::<16>(take(&mut fields, 1)?)?);
        let policy_revision = match take(&mut fields, 2)? {
            Value::Integer(value) => u64::try_from(value).map_err(|_| AslError::InvalidMessage)?,
            _ => return Err(AslError::InvalidMessage),
        };
        let permissions = match take(&mut fields, 3)? {
            Value::Integer(value) => u8::try_from(value).map_err(|_| AslError::InvalidMessage)?,
            _ => return Err(AslError::InvalidMessage),
        };
        let admins = decode_peers(take(&mut fields, 4)?)?;
        let muted = decode_peers(take(&mut fields, 5)?)?;
        let owner = fields
            .remove(&6)
            .map(|value| match value {
                Value::Bytes(bytes) => {
                    PeerId::from_bytes(bytes).map_err(|_| AslError::InvalidMessage)
                }
                _ => Err(AslError::InvalidMessage),
            })
            .transpose()?;
        finish(fields)?;
        if !canonical_peer_order(&admins) || !canonical_peer_order(&muted) {
            return Err(AslError::InvalidMessage);
        }
        let control = Self {
            message_id,
            policy_revision,
            permissions,
            admins,
            muted,
            owner,
        };
        control.validate()?;
        Ok(control)
    }

    pub fn encode(&self) -> Result<Vec<u8>, AslError> {
        self.validate()?;
        let mut admins = self.admins.clone();
        admins.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        let mut muted = self.muted.clone();
        muted.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        let mut entries = vec![
            (1, Value::Bytes(self.message_id.0.to_vec())),
            (2, uint(self.policy_revision)),
            (3, uint(u64::from(self.permissions))),
            (
                4,
                Value::Array(
                    admins
                        .iter()
                        .map(|peer| Value::Bytes(peer.as_bytes().to_vec()))
                        .collect(),
                ),
            ),
            (
                5,
                Value::Array(
                    muted
                        .iter()
                        .map(|peer| Value::Bytes(peer.as_bytes().to_vec()))
                        .collect(),
                ),
            ),
        ];
        if let Some(owner) = &self.owner {
            entries.push((6, Value::Bytes(owner.as_bytes().to_vec())));
        }
        let bytes = cbor2::to_canonical_vec(&map(entries)).map_err(|_| AslError::InvalidMessage)?;
        if bytes.len() > MAX_GROUP_CONTROL_BYTES {
            return Err(AslError::InvalidMessage);
        }
        Self::decode(&bytes)?;
        Ok(bytes)
    }

    fn validate(&self) -> Result<(), AslError> {
        if self.message_id.0 == [0; 16]
            || self.policy_revision == 0
            || self.permissions & !GROUP_ALLOWED_PERMISSION_BITS != 0
            || self.admins.len() > MAX_GROUP_CONTROL_PEERS
            || self.muted.len() > MAX_GROUP_CONTROL_PEERS
            || !unique_peers(&self.admins)
            || !unique_peers(&self.muted)
        {
            return Err(AslError::InvalidMessage);
        }
        Ok(())
    }
}

fn decode_peers(value: Value) -> Result<Vec<PeerId>, AslError> {
    array(value, MAX_GROUP_CONTROL_PEERS)?
        .into_iter()
        .map(|value| {
            let bytes = match value {
                Value::Bytes(bytes) => bytes,
                _ => return Err(AslError::InvalidMessage),
            };
            PeerId::from_bytes(bytes).map_err(|_| AslError::InvalidMessage)
        })
        .collect()
}

fn unique_peers(peers: &[PeerId]) -> bool {
    peers
        .iter()
        .enumerate()
        .all(|(index, peer)| !peers[..index].contains(peer))
}

fn canonical_peer_order(peers: &[PeerId]) -> bool {
    peers
        .windows(2)
        .all(|pair| pair[0].as_bytes() < pair[1].as_bytes())
        && unique_peers(peers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::PeerId;

    fn peer(index: usize) -> PeerId {
        let text = [
            "12D3KooWJ1jPzo4GNd8Zh66dhmDUfPHEjkzurJzMy5ws5bWGV4kS",
            "12D3KooWGHqmBWQ8VMPcaJqq1MBAXinrGaBsD9cMZoZRnbydnv89",
            "12D3KooWAKWr9EpJsNFx7e4TYN57oDJQt6h2Kjvm5QNdUrgzLQph",
        ][index];
        let bytes = bs58::decode(text).into_vec().unwrap();
        PeerId::from_bytes(bytes).unwrap()
    }

    #[test]
    fn policy_round_trips_and_rejects_invalid_permissions() {
        let mut control = GroupControl {
            message_id: Id128([1; 16]),
            policy_revision: 4,
            permissions: GROUP_ALLOW_MEMBER_TEXT | GROUP_ALLOW_MEMBER_FILES,
            admins: vec![peer(0), peer(1)],
            muted: vec![peer(2)],
            owner: None,
        };
        control
            .admins
            .sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        let bytes = control.encode().unwrap();
        assert_eq!(GroupControl::decode(&bytes).unwrap(), control);
        assert!(GroupControl::decode(&[0x82, 0, 0]).is_err());

        let mut invalid = control;
        invalid.permissions = 0x80;
        assert!(invalid.encode().is_err());
    }
}
