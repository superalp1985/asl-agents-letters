use serde::{Deserialize, Serialize};

macro_rules! fixed_bytes {
    ($name:ident, $length:expr) => {
        #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
        pub struct $name(pub [u8; $length]);

        impl $name {
            pub const LENGTH: usize = $length;

            pub fn as_bytes(&self) -> &[u8; $length] {
                &self.0
            }
        }

        impl From<[u8; $length]> for $name {
            fn from(value: [u8; $length]) -> Self {
                Self(value)
            }
        }
    };
}

fixed_bytes!(Id128, 16);
fixed_bytes!(Hash32, 32);
fixed_bytes!(AgentId, 32);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Signature65(pub [u8; 65]);

impl Signature65 {
    pub const LENGTH: usize = 65;

    pub fn as_bytes(&self) -> &[u8; 65] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PeerId(Vec<u8>);

impl PeerId {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, &'static str> {
        if !(1..=128).contains(&bytes.len()) {
            return Err("invalid PeerId length");
        }
        let parsed =
            libp2p_identity::PeerId::from_bytes(&bytes).map_err(|_| "invalid PeerId encoding")?;
        if parsed.to_bytes() != bytes {
            return Err("non-canonical PeerId encoding");
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<Vec<u8>> for PeerId {
    type Error = &'static str;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_bytes(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CandidateId(pub [u8; 16]);
