use cbor2::Value;

use crate::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId},
};

use super::{
    GroupEnvelope, GroupOperation,
    cbor::{array, as_u64, byte_string, decode_canonical, fixed_bytes, uint},
};

pub const MAX_GROUP_PAYLOAD_BYTES: usize = 65_536;
pub const MAX_GROUP_MLS_OBJECT_BYTES: usize = MAX_GROUP_PAYLOAD_BYTES - 128;
pub const MAX_GROUP_MEMBERS: usize = 512;
const MEMBERSHIP_VERSION: u64 = 1;
const MAX_EPOCH: u64 = i64::MAX as u64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GroupMembership {
    Invite {
        agent: AgentId,
        device: PeerId,
        expires_at_ms: u64,
    },
    KeyPackage {
        invite: Id128,
        message: Vec<u8>,
    },
    Welcome {
        invite: Id128,
        package_ref: Hash32,
        message: Vec<u8>,
    },
    Commit(Vec<u8>),
    SyncRequest {
        epoch_binding: Hash32,
    },
    SyncCommit(Vec<u8>),
    AtHead {
        epoch_binding: Hash32,
    },
    SyncUnavailable,
    Receipt,
}

impl GroupMembership {
    pub fn decode(bytes: &[u8]) -> Result<Self, AslError> {
        if bytes.len() > MAX_GROUP_PAYLOAD_BYTES {
            return Err(AslError::InvalidMessage);
        }
        let mut values = array(decode_canonical(bytes)?, 5)?.into_iter();
        let mut next = || values.next().ok_or(AslError::InvalidMessage);
        if as_u64(next()?)? != MEMBERSHIP_VERSION {
            return Err(AslError::IncompatibleVersion);
        }
        let value = match as_u64(next()?)? {
            0 => Self::Invite {
                agent: AgentId(fixed_bytes(next()?)?),
                device: PeerId::from_bytes(byte_string(next()?, 1, 128)?)
                    .map_err(|_| AslError::InvalidMessage)?,
                expires_at_ms: as_u64(next()?)?,
            },
            1 => Self::KeyPackage {
                invite: Id128(fixed_bytes(next()?)?),
                message: mls(next()?)?,
            },
            2 => Self::Welcome {
                invite: Id128(fixed_bytes(next()?)?),
                package_ref: Hash32(fixed_bytes(next()?)?),
                message: mls(next()?)?,
            },
            3 => Self::Commit(mls(next()?)?),
            4 => Self::SyncRequest {
                epoch_binding: Hash32(fixed_bytes(next()?)?),
            },
            5 => Self::SyncCommit(mls(next()?)?),
            6 => Self::AtHead {
                epoch_binding: Hash32(fixed_bytes(next()?)?),
            },
            7 => Self::SyncUnavailable,
            8 => Self::Receipt,
            _ => return Err(AslError::InvalidMessage),
        };
        if values.next().is_some() {
            return Err(AslError::InvalidMessage);
        }
        value.validate()?;
        Ok(value)
    }

    pub fn encode(self) -> Result<Vec<u8>, AslError> {
        self.validate()?;
        let mut values = vec![uint(MEMBERSHIP_VERSION)];
        match self {
            Self::Invite {
                agent,
                device,
                expires_at_ms,
            } => values.extend([
                uint(0),
                bytes(agent.as_bytes()),
                bytes(device.as_bytes()),
                uint(expires_at_ms),
            ]),
            Self::KeyPackage { invite, message } => {
                values.extend([uint(1), bytes(invite.as_bytes()), Value::Bytes(message)]);
            }
            Self::Welcome {
                invite,
                package_ref,
                message,
            } => values.extend([
                uint(2),
                bytes(invite.as_bytes()),
                bytes(package_ref.as_bytes()),
                Value::Bytes(message),
            ]),
            Self::Commit(message) => values.extend([uint(3), Value::Bytes(message)]),
            Self::SyncRequest { epoch_binding } => {
                values.extend([uint(4), bytes(epoch_binding.as_bytes())]);
            }
            Self::SyncCommit(message) => values.extend([uint(5), Value::Bytes(message)]),
            Self::AtHead { epoch_binding } => {
                values.extend([uint(6), bytes(epoch_binding.as_bytes())]);
            }
            Self::SyncUnavailable => values.push(uint(7)),
            Self::Receipt => values.push(uint(8)),
        }
        cbor2::to_canonical_vec(&Value::Array(values)).map_err(|_| AslError::InvalidMessage)
    }

    fn validate(&self) -> Result<(), AslError> {
        let valid = match self {
            Self::Invite {
                agent,
                expires_at_ms,
                ..
            } => agent.0 != [0; 32] && (1..=i64::MAX as u64).contains(expires_at_ms),
            Self::KeyPackage { invite, message } => invite.0 != [0; 16] && valid_mls(message),
            Self::Welcome {
                invite, message, ..
            } => invite.0 != [0; 16] && valid_mls(message),
            Self::Commit(message) | Self::SyncCommit(message) => valid_mls(message),
            _ => true,
        };
        if valid {
            Ok(())
        } else {
            Err(AslError::InvalidMessage)
        }
    }
}

fn bytes(bytes: &[u8]) -> Value {
    Value::Bytes(bytes.to_vec())
}

fn valid_mls(bytes: &[u8]) -> bool {
    (1..=MAX_GROUP_MLS_OBJECT_BYTES).contains(&bytes.len())
}

fn mls(value: Value) -> Result<Vec<u8>, AslError> {
    byte_string(value, 1, MAX_GROUP_MLS_OBJECT_BYTES)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GroupBody {
    Application(Vec<u8>),
    Membership(GroupMembership),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupPacket {
    pub message_id: Id128,
    pub group_id: Hash32,
    pub epoch: u64,
    pub body: GroupBody,
}

impl GroupPacket {
    /// This checks the frame shape and nothing about its transport or authority.
    pub fn from_envelope(envelope: GroupEnvelope) -> Result<Self, AslError> {
        let packet = Self {
            message_id: envelope.message_id,
            group_id: envelope.group_id,
            epoch: envelope.epoch,
            body: match envelope.operation {
                GroupOperation::Application => GroupBody::Application(envelope.ciphertext),
                GroupOperation::Membership => {
                    GroupBody::Membership(GroupMembership::decode(&envelope.ciphertext)?)
                }
            },
        };
        packet.validate()?;
        Ok(packet)
    }

    pub fn into_envelope(self) -> Result<GroupEnvelope, AslError> {
        self.validate()?;
        let (operation, ciphertext) = match self.body {
            GroupBody::Application(message) => (GroupOperation::Application, message),
            GroupBody::Membership(membership) => (GroupOperation::Membership, membership.encode()?),
        };
        Ok(GroupEnvelope {
            message_id: self.message_id,
            group_id: self.group_id,
            epoch: self.epoch,
            operation,
            ciphertext,
        })
    }

    pub fn validate_request(&self) -> Result<(), AslError> {
        use GroupMembership as Membership;
        self.validate()?;
        match &self.body {
            GroupBody::Application(_)
            | GroupBody::Membership(
                Membership::Invite { .. }
                | Membership::KeyPackage { .. }
                | Membership::Commit(_)
                | Membership::SyncRequest { .. },
            ) => Ok(()),
            _ => Err(AslError::InvalidMessage),
        }
    }

    /// Use only with the original, locally pending request on the same
    /// admitted connection. This is not MLS verification or membership.
    pub fn match_reply(&self, reply: &Self) -> Result<(), AslError> {
        use GroupMembership as Membership;
        self.validate_request()?;
        reply.validate()?;
        if self.message_id != reply.message_id || self.group_id != reply.group_id {
            return Err(AslError::InvalidMessage);
        }
        let GroupBody::Membership(response) = &reply.body else {
            return Err(AslError::InvalidMessage);
        };
        let base = self.epoch;
        let matches = match (&self.body, response) {
            (
                GroupBody::Application(_)
                | GroupBody::Membership(Membership::Invite { .. } | Membership::Commit(_)),
                Membership::Receipt,
            ) => reply.epoch == base,
            (
                GroupBody::Membership(Membership::KeyPackage { invite, .. }),
                Membership::Welcome { invite: echoed, .. },
            ) => echoed == invite && reply.epoch == base + 1,
            (
                GroupBody::Membership(Membership::SyncRequest { .. }),
                Membership::SyncCommit(_) | Membership::SyncUnavailable,
            ) => reply.epoch == base,
            (
                GroupBody::Membership(Membership::SyncRequest { epoch_binding }),
                Membership::AtHead {
                    epoch_binding: confirmed,
                },
            ) => confirmed == epoch_binding && reply.epoch == base,
            _ => false,
        };
        if matches {
            Ok(())
        } else {
            Err(AslError::InvalidMessage)
        }
    }

    fn validate(&self) -> Result<(), AslError> {
        use GroupMembership as Membership;
        if self.message_id.0 == [0; 16] || self.group_id.0 == [0; 32] || self.epoch > MAX_EPOCH {
            return Err(AslError::InvalidMessage);
        }
        match &self.body {
            GroupBody::Application(message) => {
                if !(1..=MAX_GROUP_PAYLOAD_BYTES).contains(&message.len()) {
                    return Err(AslError::InvalidMessage);
                }
                Ok(())
            }
            GroupBody::Membership(membership) => {
                match membership {
                    Membership::Invite { .. }
                    | Membership::KeyPackage { .. }
                    | Membership::Commit(_)
                    | Membership::SyncCommit(_)
                        if self.epoch == MAX_EPOCH =>
                    {
                        return Err(AslError::InvalidMessage);
                    }
                    Membership::Welcome { .. } if self.epoch == 0 => {
                        return Err(AslError::InvalidMessage);
                    }
                    _ => {}
                }
                membership.validate()
            }
        }
    }
}
