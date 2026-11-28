use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32, Id128, PeerId},
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::{Store, chain::agent_text, database_error, read_setting};

const REQUEST_POLICY_SETTING: &str = "contacts.request_policy.v1";
const REQUEST_POLICY_VERSION: u64 = 1;
pub const MAX_RECENT_INTERACTION_TTL_MS: u64 = 7 * 24 * 60 * 60 * 1_000;

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
    #[serde(default)]
    shared_group_auto_accept: bool,
    #[serde(default)]
    recent_interaction_ttl_ms: u64,
    updated_at_ms: i64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ContactRequestPolicy {
    pub mode: ContactRequestMode,
    pub shared_group_auto_accept: bool,
    pub recent_interaction_ttl_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecentContactInteraction {
    pub interaction_id: Id128,
    pub group_id: Option<Hash32>,
    pub group_epoch: Option<u64>,
    pub expires_at_ms: u64,
}

impl Store {
    pub fn contact_request_mode(&self) -> Result<ContactRequestMode, AslError> {
        Ok(self.contact_request_policy()?.mode)
    }

    pub fn contact_request_policy(&self) -> Result<ContactRequestPolicy, AslError> {
        contact_request_policy(&self.connection)
    }

    pub fn set_contact_request_mode(
        &self,
        mode: ContactRequestMode,
        now_ms: u64,
    ) -> Result<(), AslError> {
        let mut policy = self.contact_request_policy()?;
        policy.mode = mode;
        self.set_contact_request_policy(policy, now_ms)
    }

    pub fn set_shared_group_auto_accept(&self, enabled: bool, now_ms: u64) -> Result<(), AslError> {
        let mut policy = self.contact_request_policy()?;
        policy.shared_group_auto_accept = enabled;
        self.set_contact_request_policy(policy, now_ms)
    }

    pub fn set_recent_interaction_ttl(&self, ttl_ms: u64, now_ms: u64) -> Result<(), AslError> {
        let mut policy = self.contact_request_policy()?;
        policy.recent_interaction_ttl_ms = ttl_ms;
        self.set_contact_request_policy(policy, now_ms)
    }

    pub fn set_contact_request_policy(
        &self,
        policy: ContactRequestPolicy,
        now_ms: u64,
    ) -> Result<(), AslError> {
        write_contact_request_policy(&self.connection, policy, now_ms)
    }

    pub fn shared_active_group_evidence(
        &self,
        agent_id: AgentId,
        peer_id: &PeerId,
    ) -> Result<Option<(Hash32, u64)>, AslError> {
        if agent_id.0 == [0; 32] {
            return Err(AslError::InvalidMessage);
        }
        self.connection
            .query_row(
                "SELECT state.wire_group_id,room.membership_epoch
                    FROM group_members mine
                    JOIN local_device_identity local ON local.peer_id=mine.peer_id
                    JOIN group_members other ON other.group_id=mine.group_id
                    JOIN peers peer ON peer.peer_id=other.peer_id
                    JOIN asl_groups room ON room.group_id=mine.group_id
                    JOIN mls_room_states state ON state.local_group_id=room.group_id
                    WHERE peer.agent_id=?1
                      AND peer.peer_id=?2
                      AND mine.state='active'
                      AND other.state='active'
                      AND room.state='active'
                    ORDER BY room.membership_epoch DESC,state.wire_group_id
                    LIMIT 1",
                params![
                    agent_text(agent_id),
                    bs58::encode(peer_id.as_bytes()).into_string()
                ],
                |row| {
                    let group: Vec<u8> = row.get(0)?;
                    Ok((
                        Hash32(
                            group
                                .try_into()
                                .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, 0))?,
                        ),
                        u64::try_from(row.get::<_, i64>(1)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    ))
                },
            )
            .optional()
            .map_err(database_error)
    }

    pub fn record_contact_interaction_evidence(
        &self,
        agent_id: AgentId,
        peer_id: &PeerId,
        interaction_id: Id128,
        group: Option<(Hash32, u64)>,
        now_ms: u64,
    ) -> Result<bool, AslError> {
        if interaction_id.0 == [0; 16] || now_ms > i64::MAX as u64 {
            return Err(AslError::InvalidMessage);
        }
        if agent_id.0 == [0; 32] {
            return Ok(false);
        }
        let ttl_ms = self.contact_request_policy()?.recent_interaction_ttl_ms;
        if ttl_ms == 0 {
            return Ok(false);
        }
        let expires_at_ms = now_ms
            .checked_add(ttl_ms)
            .filter(|expiry| *expiry <= i64::MAX as u64)
            .ok_or(AslError::InvalidMessage)?;
        let now = now_ms as i64;
        let group_id = group.as_ref().map(|(group, _)| group.as_bytes().as_slice());
        let group_epoch = group
            .as_ref()
            .map(|(_, epoch)| i64::try_from(*epoch).map_err(|_| AslError::InvalidMessage))
            .transpose()?;
        self.connection
            .execute(
                "DELETE FROM contact_interaction_evidence WHERE expires_at_ms<=?1",
                [now],
            )
            .map_err(database_error)?;
        self.connection
            .execute(
                "INSERT INTO contact_interaction_evidence(
                    agent_id,peer_id,interaction_id,group_id,group_epoch,
                    observed_at_ms,expires_at_ms
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7)
                 ON CONFLICT(agent_id,peer_id,interaction_id) DO UPDATE SET
                    group_id=excluded.group_id,
                    group_epoch=excluded.group_epoch,
                    observed_at_ms=excluded.observed_at_ms,
                    expires_at_ms=excluded.expires_at_ms",
                params![
                    agent_id.as_bytes().as_slice(),
                    bs58::encode(peer_id.as_bytes()).into_string(),
                    interaction_id.as_bytes().as_slice(),
                    group_id,
                    group_epoch,
                    now,
                    expires_at_ms as i64,
                ],
            )
            .map_err(database_error)?;
        Ok(true)
    }

    pub fn recent_contact_interaction_evidence(
        &self,
        agent_id: AgentId,
        now_ms: u64,
    ) -> Result<Option<RecentContactInteraction>, AslError> {
        if agent_id.0 == [0; 32] || now_ms > i64::MAX as u64 {
            return Err(AslError::InvalidMessage);
        }
        self.connection
            .query_row(
                "SELECT interaction_id,group_id,group_epoch,expires_at_ms
                 FROM contact_interaction_evidence
                 WHERE agent_id=?1 AND expires_at_ms>?2
                 ORDER BY observed_at_ms DESC,interaction_id DESC
                 LIMIT 1",
                params![agent_id.as_bytes().as_slice(), now_ms as i64],
                |row| {
                    let interaction: Vec<u8> = row.get(0)?;
                    let group: Option<Vec<u8>> = row.get(1)?;
                    let group_epoch: Option<i64> = row.get(2)?;
                    let expires: i64 = row.get(3)?;
                    Ok(RecentContactInteraction {
                        interaction_id: Id128(
                            interaction
                                .try_into()
                                .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        ),
                        group_id: group
                            .map(|group| {
                                group
                                    .try_into()
                                    .map(Hash32)
                                    .map_err(|_| rusqlite::Error::InvalidQuery)
                            })
                            .transpose()?,
                        group_epoch: group_epoch
                            .map(|epoch| {
                                u64::try_from(epoch).map_err(|_| rusqlite::Error::InvalidQuery)
                            })
                            .transpose()?,
                        expires_at_ms: u64::try_from(expires)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    })
                },
            )
            .optional()
            .map_err(database_error)
    }
}

pub(crate) fn write_contact_request_policy(
    connection: &Connection,
    policy: ContactRequestPolicy,
    now_ms: u64,
) -> Result<(), AslError> {
    if now_ms > i64::MAX as u64 || policy.recent_interaction_ttl_ms > MAX_RECENT_INTERACTION_TTL_MS
    {
        return Err(AslError::InvalidMessage);
    }
    let stored = ContactRequestPolicyV1 {
        version: REQUEST_POLICY_VERSION,
        mode: policy.mode,
        shared_group_auto_accept: policy.shared_group_auto_accept,
        recent_interaction_ttl_ms: policy.recent_interaction_ttl_ms,
        updated_at_ms: now_ms as i64,
    };
    let value = serde_json::to_string(&stored).map_err(|_| AslError::InvalidMessage)?;
    crate::write_setting(connection, REQUEST_POLICY_SETTING, &value, now_ms as i64)
}

pub(crate) fn contact_request_policy(
    connection: &Connection,
) -> Result<ContactRequestPolicy, AslError> {
    let Some(value) = read_setting(connection, REQUEST_POLICY_SETTING)? else {
        return Ok(ContactRequestPolicy::default());
    };
    let policy = serde_json::from_str::<ContactRequestPolicyV1>(&value)
        .map_err(|_| AslError::InvalidDatabase)?;
    if policy.version != REQUEST_POLICY_VERSION
        || policy.updated_at_ms < 0
        || policy.recent_interaction_ttl_ms > MAX_RECENT_INTERACTION_TTL_MS
    {
        return Err(AslError::InvalidDatabase);
    }
    Ok(ContactRequestPolicy {
        mode: policy.mode,
        shared_group_auto_accept: policy.shared_group_auto_accept,
        recent_interaction_ttl_ms: policy.recent_interaction_ttl_ms,
    })
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
