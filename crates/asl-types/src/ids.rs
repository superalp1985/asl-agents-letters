use std::{fmt, str::FromStr};

use libp2p_identity::PeerId;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

macro_rules! validated_text {
    ($name:ident, $validate:ident) => {
        #[derive(Clone, Debug, Eq, Hash, PartialEq)]
        pub struct $name(String);

        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = String;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                $validate(&value)?;
                Ok(Self(value))
            }
        }

        impl FromStr for $name {
            type Err = String;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::try_from(value.to_owned())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::try_from(value).map_err(D::Error::custom)
            }
        }
    };
}

fn validate_hex(value: &str, length: usize, label: &str) -> Result<(), String> {
    if value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(format!("invalid {label}"))
    }
}

fn validate_id128(value: &str) -> Result<(), String> {
    validate_hex(value, 32, "128-bit id")
}

fn validate_hash32(value: &str) -> Result<(), String> {
    validate_hex(value, 64, "32-byte hash")
}

fn validate_signature64(value: &str) -> Result<(), String> {
    validate_hex(value, 128, "Ed25519 signature")
}

fn validate_candidate_id(value: &str) -> Result<(), String> {
    let suffix = value
        .strip_prefix("c_")
        .ok_or_else(|| "invalid candidate id".to_owned())?;
    validate_hex(suffix, 16, "candidate id")
}

fn validate_agent_id(value: &str) -> Result<(), String> {
    let encoded = value
        .strip_prefix("did:key:z")
        .ok_or_else(|| "invalid AgentId".to_owned())?;
    let key = bs58::decode(encoded)
        .into_vec()
        .map_err(|_| "invalid AgentId".to_owned())?;
    if key.len() == 34 && key[..2] == [0xed, 0x01] && bs58::encode(&key).into_string() == encoded {
        Ok(())
    } else {
        Err("invalid AgentId".to_owned())
    }
}

fn validate_peer_id(value: &str) -> Result<(), String> {
    let peer_id = PeerId::from_str(value).map_err(|_| "invalid PeerId".to_owned())?;
    if peer_id.to_string() == value {
        Ok(())
    } else {
        Err("non-canonical PeerId".to_owned())
    }
}

validated_text!(Id128, validate_id128);
validated_text!(Hash32, validate_hash32);
validated_text!(Signature64, validate_signature64);
validated_text!(CandidateId, validate_candidate_id);
validated_text!(AgentIdText, validate_agent_id);
validated_text!(PeerIdText, validate_peer_id);
