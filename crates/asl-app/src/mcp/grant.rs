use std::env::{self, VarError};

use alloy_primitives::hex;
use asl_agent::QueryScope;
use asl_types::{error::AslError, ids::Id128};
use zeroize::Zeroizing;

const KEY_VAR: &str = "ASL_MCP_KEY";
const RECOVERY_KEY_VAR: &str = "ASL_MCP_RECOVERY_KEY";
const RECOVERY_RESULTS_VAR: &str = "ASL_MCP_RECOVERY_RESULTS";
const SCOPE_VAR: &str = "ASL_MCP_SCOPE";
const INBOX_VAR: &str = "ASL_MCP_INBOX_GRANT";
const AGENT_PUSH_VAR: &str = "ASL_MCP_AGENT_PUSH";
const EXPRESSIONS_VAR: &str = "ASL_MCP_EXPRESSIONS";
const GROUPS_VAR: &str = "ASL_MCP_GROUPS";

pub(super) type Key = Zeroizing<[u8; 32]>;

pub(crate) struct HostGrant {
    pub(super) key: Key,
    pub(super) recovery_key: Option<Key>,
    pub(super) recovery_results: bool,
    pub(super) scope: QueryScope,
    pub(super) inbox: Option<Id128>,
    pub(super) agent_push: bool,
    pub(super) expressions: bool,
    pub(super) groups_admin: bool,
}

impl HostGrant {
    pub fn from_environment() -> Result<Option<Self>, AslError> {
        let key = client_key()?;
        let recovery_key = read_key(RECOVERY_KEY_VAR)?;
        let recovery_results = match optional_var(RECOVERY_RESULTS_VAR)?.as_deref() {
            None | Some("0") => false,
            Some("1") if recovery_key.is_some() => true,
            _ => return Err(AslError::InvalidPolicyState),
        };
        if let Some(recovery_key) = &recovery_key
            && blake3::hash(recovery_key.as_ref())
                == blake3::hash(key.as_deref().ok_or(AslError::InvalidPolicyState)?)
        {
            return Err(AslError::InvalidPolicyState);
        }
        let scope = optional_var(SCOPE_VAR)?;
        let inbox = optional_var(INBOX_VAR)?;
        let push = optional_var(AGENT_PUSH_VAR)?;
        let expressions = optional_var(EXPRESSIONS_VAR)?;
        let groups = optional_var(GROUPS_VAR)?;
        match (
            key,
            scope.as_deref(),
            inbox,
            push.as_deref(),
            expressions.as_deref(),
            groups.as_deref(),
        ) {
            (None, None, None, None, None, None) => Ok(None),
            (Some(key), Some(scope), inbox, push, expressions, groups) => Ok(Some(Self {
                key,
                recovery_key,
                recovery_results,
                scope: match scope {
                    "contacts_only" => QueryScope::ContactsOnly,
                    "public" => QueryScope::Public,
                    _ => return Err(AslError::InvalidPolicyState),
                },
                inbox: inbox
                    .as_deref()
                    .map(|id| decode(id).map(Id128))
                    .transpose()?,
                agent_push: match push {
                    None | Some("0") => false,
                    Some("1") => true,
                    _ => return Err(AslError::InvalidPolicyState),
                },
                expressions: match expressions {
                    None => false,
                    Some("send") => true,
                    _ => return Err(AslError::InvalidPolicyState),
                },
                groups_admin: match groups {
                    None | Some("none") => false,
                    Some("admin") => true,
                    _ => return Err(AslError::InvalidPolicyState),
                },
            })),
            _ => Err(AslError::InvalidPolicyState),
        }
    }
}

pub(super) fn client_key() -> Result<Option<Key>, AslError> {
    read_key(KEY_VAR)
}

pub(super) fn host_key() -> Result<(Option<Key>, bool), AslError> {
    let recovery = read_key(RECOVERY_KEY_VAR)?;
    let legacy = client_key()?;
    match (recovery, legacy) {
        (Some(_), Some(_)) => Err(AslError::InvalidPolicyState),
        (Some(recovery), None) => Ok((Some(recovery), true)),
        (None, legacy) => Ok((legacy, false)),
    }
}

fn read_key(name: &str) -> Result<Option<Key>, AslError> {
    let Some(value) = optional_var(name)?.map(Zeroizing::new) else {
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
