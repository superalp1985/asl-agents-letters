use std::env::{self, VarError};

use alloy_primitives::hex;
use asl_agent::QueryScope;
use asl_types::{error::AslError, ids::Id128};
use zeroize::Zeroizing;

const KEY_VAR: &str = "ASL_MCP_KEY";
const SCOPE_VAR: &str = "ASL_MCP_SCOPE";
const INBOX_VAR: &str = "ASL_MCP_INBOX_GRANT";

pub(super) type Key = Zeroizing<[u8; 32]>;

pub(crate) struct HostGrant {
    pub(super) key: Key,
    pub(super) scope: QueryScope,
    pub(super) inbox: Option<Id128>,
}

impl HostGrant {
    pub fn from_environment() -> Result<Option<Self>, AslError> {
        let key = client_key()?;
        let scope = optional_var(SCOPE_VAR)?;
        let inbox = optional_var(INBOX_VAR)?;
        match (key, scope.as_deref(), inbox) {
            (None, None, None) => Ok(None),
            (Some(key), Some(scope), inbox) => Ok(Some(Self {
                key,
                scope: match scope {
                    "contacts_only" => QueryScope::ContactsOnly,
                    "public" => QueryScope::Public,
                    _ => return Err(AslError::InvalidPolicyState),
                },
                inbox: inbox
                    .as_deref()
                    .map(|id| decode(id).map(Id128))
                    .transpose()?,
            })),
            _ => Err(AslError::InvalidPolicyState),
        }
    }
}

pub(super) fn client_key() -> Result<Option<Key>, AslError> {
    let Some(value) = optional_var(KEY_VAR)?.map(Zeroizing::new) else {
        return Ok(None);
    };
    let mut key = Key::new([0; 32]);
    if value.len() != 64
        || hex::decode_to_slice(value.as_bytes(), &mut *key).is_err()
        || *key == [0; 32]
    {
        return Err(AslError::InvalidPolicyState);
    }
    Ok(Some(key))
}

fn optional_var(name: &str) -> Result<Option<String>, AslError> {
    match env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(VarError::NotPresent) => Ok(None),
        Err(VarError::NotUnicode(_)) => Err(AslError::InvalidPolicyState),
    }
}

fn decode<const N: usize>(value: &str) -> Result<[u8; N], AslError> {
    let mut bytes = [0; N];
    if value.len() != 2 * N || hex::decode_to_slice(value, &mut bytes).is_err() {
        return Err(AslError::InvalidPolicyState);
    }
    Ok(bytes)
}
