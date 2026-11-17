use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use crate::ids::Id128;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TimeMs(u64);

impl TimeMs {
    pub fn get(self) -> u64 {
        self.0
    }
}

impl TryFrom<u64> for TimeMs {
    type Error = &'static str;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if value <= i64::MAX as u64 {
            Ok(Self(value))
        } else {
            Err("timestamp exceeds i64::MAX")
        }
    }
}

impl<'de> Deserialize<'de> for TimeMs {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Self::try_from(value).map_err(D::Error::custom)
    }
}

impl Serialize for TimeMs {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u64(self.0)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ResourceKey(pub Id128);

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct GrantId(pub Id128);

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct TaskId(pub Id128);

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct TransferId(pub Id128);

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ProviderId(pub String);

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct GroupId(pub Id128);
