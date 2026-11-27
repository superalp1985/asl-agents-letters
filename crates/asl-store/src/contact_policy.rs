use asl_types::error::AslError;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::{Store, read_setting};

const REQUEST_POLICY_SETTING: &str = "contacts.request_policy.v1";
const REQUEST_POLICY_VERSION: u64 = 1;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContactRequestMode {
    #[default]
    Review,
    AutoAccept,
    Reject,
}

impl ContactRequestMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Review => "review",
            Self::AutoAccept => "auto_accept",
            Self::Reject => "reject",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ContactRequestPolicyV1 {
    version: u64,
    mode: ContactRequestMode,
    updated_at_ms: i64,
}

impl Store {
    pub fn contact_request_mode(&self) -> Result<ContactRequestMode, AslError> {
        contact_request_mode(&self.connection)
    }

    pub fn set_contact_request_mode(
        &self,
        mode: ContactRequestMode,
        now_ms: u64,
    ) -> Result<(), AslError> {
        if now_ms > i64::MAX as u64 {
            return Err(AslError::InvalidMessage);
        }
        let policy = ContactRequestPolicyV1 {
            version: REQUEST_POLICY_VERSION,
            mode,
            updated_at_ms: now_ms as i64,
        };
        let value = serde_json::to_string(&policy).map_err(|_| AslError::InvalidMessage)?;
        self.set_setting(REQUEST_POLICY_SETTING, &value, now_ms as i64)
    }
}

pub(crate) fn contact_request_mode(
    connection: &Connection,
) -> Result<ContactRequestMode, AslError> {
    let Some(value) = read_setting(connection, REQUEST_POLICY_SETTING)? else {
        return Ok(ContactRequestMode::Review);
    };
    let policy = serde_json::from_str::<ContactRequestPolicyV1>(&value)
        .map_err(|_| AslError::InvalidDatabase)?;
    if policy.version != REQUEST_POLICY_VERSION || policy.updated_at_ms < 0 {
        return Err(AslError::InvalidDatabase);
    }
    Ok(policy.mode)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_policy_defaults_to_review_and_survives_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("asl.sqlite3");
        {
            let store = crate::open_store(&path).unwrap();
            assert_eq!(
                store.contact_request_mode().unwrap(),
                ContactRequestMode::Review
            );
            store
                .set_contact_request_mode(ContactRequestMode::AutoAccept, 42)
                .unwrap();
        }
        let store = crate::open_store(&path).unwrap();
        assert_eq!(
            store.contact_request_mode().unwrap(),
            ContactRequestMode::AutoAccept
        );
    }
}
