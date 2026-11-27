use cbor2::Value;

use crate::{
    error::AslError,
    ids::{Hash32, Id128, PeerId},
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
pub const GROUP_FILE_READ: u8 = 1;
pub const GROUP_FILE_SEND: u8 = 2;
pub const GROUP_FILE_FETCH: u8 = 4;
pub const GROUP_ALLOWED_FILE_PERMISSION_BITS: u8 =
    GROUP_FILE_READ | GROUP_FILE_SEND | GROUP_FILE_FETCH;
pub const GROUP_ADMIN_MANAGE_MEMBERS: u8 = 1;
pub const GROUP_ADMIN_MANAGE_FILES: u8 = 2;
pub const GROUP_ADMIN_MANAGE_INVITES: u8 = 4;
pub const GROUP_ALLOWED_ADMIN_CAPABILITY_BITS: u8 =
    GROUP_ADMIN_MANAGE_MEMBERS | GROUP_ADMIN_MANAGE_FILES | GROUP_ADMIN_MANAGE_INVITES;
pub const MAX_GROUP_CONTROL_FILE_POLICIES: usize = MAX_GROUP_CONTROL_PEERS;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroupFilePolicy {
    pub content_id: Hash32,
    pub permissions: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupAdminCapability {
    pub peer: PeerId,
    pub capabilities: u8,
}

/// Owner-authoritative, deterministic policy carried only inside MLS
/// application plaintext. The creator is the initial owner; key 6 can transfer
/// the effective owner to another active device. Keys 7 and 8 are optional so
/// existing v1 controls remain valid and preserve the prior default behavior.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupControl {
    pub message_id: Id128,
    pub policy_revision: u64,
    pub permissions: u8,
    pub admins: Vec<PeerId>,
    pub muted: Vec<PeerId>,
    pub owner: Option<PeerId>,
    pub file_policies: Vec<GroupFilePolicy>,
    pub admin_capabilities: Vec<GroupAdminCapability>,
}

impl GroupControl {
    pub fn decode(bytes: &[u8]) -> Result<Self, AslError> {
        if bytes.is_empty() || bytes.len() > MAX_GROUP_CONTROL_BYTES {
            return Err(AslError::InvalidMessage);
        }
        let mut fields = fields(decode_canonical(bytes)?)?;
        check_keys(&fields, &[1, 2, 3, 4, 5, 6, 7, 8])?;
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
        let file_policies = fields
            .remove(&7)
            .map(decode_file_policies)
            .transpose()?
            .unwrap_or_default();
        let admin_capabilities = fields
            .remove(&8)
            .map(decode_admin_capabilities)
            .transpose()?
            .unwrap_or_default();
        finish(fields)?;
        if !canonical_peer_order(&admins)
            || !canonical_peer_order(&muted)
            || !canonical_file_policy_order(&file_policies)
            || !canonical_admin_capability_order(&admin_capabilities)
        {
            return Err(AslError::InvalidMessage);
        }
        let control = Self {
            message_id,
            policy_revision,
            permissions,
            admins,
            muted,
            owner,
            file_policies,
            admin_capabilities,
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
        if !self.file_policies.is_empty() {
            let mut policies = self.file_policies.clone();
            policies
                .sort_by(|left, right| left.content_id.as_bytes().cmp(right.content_id.as_bytes()));
            entries.push((
                7,
                Value::Array(
                    policies
                        .into_iter()
                        .map(|policy| {
                            Value::Array(vec![
                                Value::Bytes(policy.content_id.as_bytes().to_vec()),
                                uint(u64::from(policy.permissions)),
                            ])
                        })
                        .collect(),
                ),
            ));
        }
        if !self.admin_capabilities.is_empty() {
            let mut capabilities = self.admin_capabilities.clone();
            capabilities.sort_by(|left, right| left.peer.as_bytes().cmp(right.peer.as_bytes()));
            entries.push((
                8,
                Value::Array(
                    capabilities
                        .into_iter()
                        .map(|capability| {
                            Value::Array(vec![
                                Value::Bytes(capability.peer.as_bytes().to_vec()),
                                uint(u64::from(capability.capabilities)),
                            ])
                        })
                        .collect(),
                ),
            ));
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
            || self.file_policies.len() > MAX_GROUP_CONTROL_FILE_POLICIES
            || self.admin_capabilities.len() > MAX_GROUP_CONTROL_PEERS
            || !unique_peers(&self.admins)
            || !unique_peers(&self.muted)
            || !unique_file_policies(&self.file_policies)
            || !unique_admin_capabilities(&self.admin_capabilities)
            || self
                .file_policies
                .iter()
                .any(|policy| policy.permissions & !GROUP_ALLOWED_FILE_PERMISSION_BITS != 0)
            || self.admin_capabilities.iter().any(|capability| {
                capability.capabilities & !GROUP_ALLOWED_ADMIN_CAPABILITY_BITS != 0
                    || !self.admins.contains(&capability.peer)
            })
        {
            return Err(AslError::InvalidMessage);
        }
        Ok(())
    }
}

fn decode_file_policies(value: Value) -> Result<Vec<GroupFilePolicy>, AslError> {
    array(value, MAX_GROUP_CONTROL_FILE_POLICIES)?
        .into_iter()
        .map(|entry| {
            let mut entry = array(entry, 2)?;
            if entry.len() != 2 {
                return Err(AslError::InvalidMessage);
            }
            let content_id = Hash32(fixed_bytes::<32>(entry.remove(0))?);
            let permissions = match entry.remove(0) {
                Value::Integer(value) => {
                    u8::try_from(value).map_err(|_| AslError::InvalidMessage)?
                }
                _ => return Err(AslError::InvalidMessage),
            };
            Ok(GroupFilePolicy {
                content_id,
                permissions,
            })
        })
        .collect()
}

fn decode_admin_capabilities(value: Value) -> Result<Vec<GroupAdminCapability>, AslError> {
    array(value, MAX_GROUP_CONTROL_PEERS)?
        .into_iter()
        .map(|entry| {
            let mut entry = array(entry, 2)?;
            if entry.len() != 2 {
                return Err(AslError::InvalidMessage);
            }
            let peer = match entry.remove(0) {
                Value::Bytes(bytes) => {
                    PeerId::from_bytes(bytes).map_err(|_| AslError::InvalidMessage)?
                }
                _ => return Err(AslError::InvalidMessage),
            };
            let capabilities = match entry.remove(0) {
                Value::Integer(value) => {
                    u8::try_from(value).map_err(|_| AslError::InvalidMessage)?
                }
                _ => return Err(AslError::InvalidMessage),
            };
            Ok(GroupAdminCapability { peer, capabilities })
        })
        .collect()
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

fn unique_file_policies(policies: &[GroupFilePolicy]) -> bool {
    policies.iter().enumerate().all(|(index, policy)| {
        !policies[..index]
            .iter()
            .any(|candidate| candidate.content_id == policy.content_id)
    })
}

fn unique_admin_capabilities(capabilities: &[GroupAdminCapability]) -> bool {
    capabilities.iter().enumerate().all(|(index, capability)| {
        !capabilities[..index]
            .iter()
            .any(|candidate| candidate.peer == capability.peer)
    })
}

fn canonical_peer_order(peers: &[PeerId]) -> bool {
    peers
        .windows(2)
        .all(|pair| pair[0].as_bytes() < pair[1].as_bytes())
        && unique_peers(peers)
}

fn canonical_file_policy_order(policies: &[GroupFilePolicy]) -> bool {
    policies
        .windows(2)
        .all(|pair| pair[0].content_id.as_bytes() < pair[1].content_id.as_bytes())
        && unique_file_policies(policies)
}

fn canonical_admin_capability_order(capabilities: &[GroupAdminCapability]) -> bool {
    capabilities
        .windows(2)
        .all(|pair| pair[0].peer.as_bytes() < pair[1].peer.as_bytes())
        && unique_admin_capabilities(capabilities)
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
            file_policies: vec![
                GroupFilePolicy {
                    content_id: Hash32([3; 32]),
                    permissions: GROUP_FILE_READ | GROUP_FILE_FETCH,
                },
                GroupFilePolicy {
                    content_id: Hash32([2; 32]),
                    permissions: GROUP_FILE_SEND,
                },
            ],
            admin_capabilities: vec![
                GroupAdminCapability {
                    peer: peer(1),
                    capabilities: GROUP_ADMIN_MANAGE_FILES,
                },
                GroupAdminCapability {
                    peer: peer(0),
                    capabilities: GROUP_ADMIN_MANAGE_MEMBERS | GROUP_ADMIN_MANAGE_INVITES,
                },
            ],
        };
        control
            .admins
            .sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        control
            .file_policies
            .sort_by(|left, right| left.content_id.as_bytes().cmp(right.content_id.as_bytes()));
        let bytes = control.encode().unwrap();
        assert_eq!(GroupControl::decode(&bytes).unwrap(), control);
        assert!(GroupControl::decode(&[0x82, 0, 0]).is_err());

        let mut invalid = control;
        invalid.permissions = 0x80;
        assert!(invalid.encode().is_err());
        invalid.permissions = GROUP_ALLOW_MEMBER_TEXT;
        invalid.file_policies[0].permissions = 0x80;
        assert!(invalid.encode().is_err());
    }

    #[test]
    fn legacy_control_without_keys_seven_or_eight_still_decodes() {
        let legacy = vec![
            0xa5, 0x01, 0x50, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
            0x08, 0x08, 0x08, 0x08, 0x08, 0x02, 0x01, 0x03, 0x03, 0x04, 0x80, 0x05, 0x80,
        ];
        let control = GroupControl::decode(&legacy).unwrap();
        assert!(control.file_policies.is_empty());
        assert!(control.admin_capabilities.is_empty());
        assert_eq!(control.encode().unwrap(), legacy);
    }

    #[test]
    fn extended_control_rejects_unbound_or_unsorted_admin_capabilities() {
        let admin = peer(0);
        let unbound = GroupControl {
            message_id: Id128([4; 16]),
            policy_revision: 2,
            permissions: GROUP_ALLOW_MEMBER_TEXT,
            admins: Vec::new(),
            muted: Vec::new(),
            owner: None,
            file_policies: Vec::new(),
            admin_capabilities: vec![GroupAdminCapability {
                peer: admin,
                capabilities: GROUP_ADMIN_MANAGE_MEMBERS,
            }],
        };
        assert!(unbound.encode().is_err());

        let mut control = GroupControl {
            message_id: Id128([5; 16]),
            policy_revision: 2,
            permissions: GROUP_ALLOW_MEMBER_TEXT,
            admins: vec![peer(1), peer(0)],
            muted: Vec::new(),
            owner: None,
            file_policies: Vec::new(),
            admin_capabilities: Vec::new(),
        };
        control.file_policies = vec![
            GroupFilePolicy {
                content_id: Hash32([2; 32]),
                permissions: GROUP_FILE_READ,
            },
            GroupFilePolicy {
                content_id: Hash32([1; 32]),
                permissions: GROUP_FILE_FETCH,
            },
        ];
        control.admin_capabilities = vec![
            GroupAdminCapability {
                peer: peer(1),
                capabilities: GROUP_ADMIN_MANAGE_MEMBERS,
            },
            GroupAdminCapability {
                peer: peer(0),
                capabilities: GROUP_ADMIN_MANAGE_FILES,
            },
        ];
        let bytes = control.encode().unwrap();
        let decoded = GroupControl::decode(&bytes).unwrap();
        assert!(
            decoded
                .file_policies
                .windows(2)
                .all(|pair| pair[0].content_id.as_bytes() < pair[1].content_id.as_bytes())
        );
        assert!(
            decoded
                .admin_capabilities
                .windows(2)
                .all(|pair| pair[0].peer.as_bytes() < pair[1].peer.as_bytes())
        );
        let mut unsorted = cbor2::from_slice::<Value>(&bytes).unwrap();
        let Value::Map(entries) = &mut unsorted else {
            panic!("group control must be a map");
        };
        for key in [7, 8] {
            let (_, Value::Array(values)) = entries
                .iter_mut()
                .find(|(field, _)| field == &Value::Integer(key.into()))
                .unwrap()
            else {
                panic!("group control must contain key {key}");
            };
            values.reverse();
        }
        let unsorted = cbor2::to_canonical_vec(&unsorted).unwrap();
        assert!(GroupControl::decode(&unsorted).is_err());
        let duplicate = GroupControl {
            file_policies: vec![decoded.file_policies[0], decoded.file_policies[0]],
            ..decoded
        };
        assert!(duplicate.encode().is_err());
    }
}
