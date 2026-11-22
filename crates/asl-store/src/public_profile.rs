//! Local signing permission. This setting does not authorize disclosure.

use asl_types::{
    error::AslError,
    ids::AgentId,
    protocol::ConceptRef,
    record::{RecordPayload, decode_record},
};
use rusqlite::{Connection, TransactionBehavior};
use serde::{Deserialize, Serialize};

use crate::{Store, current_time_ms, database_error, read_setting, write_setting};

const KEY: &str = "identity.profile_signing_v1";
const RENEWAL_MS: u64 = 5 * 60 * 1_000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSigningApproval {
    pub agent_id: AgentId,
    pub topics: Vec<u32>,
    revision: u64,
}

pub fn profile_topic(concept_id: u32) -> ConceptRef {
    ConceptRef {
        vocabulary_id: 1,
        concept_id,
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProfileCandidateStatus {
    pub sequence: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Default, Serialize)]
pub struct ProfileSigningStatus {
    pub approval: Option<ProfileSigningApproval>,
    pub last_candidate: Option<ProfileCandidateStatus>,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct State {
    revision: u64,
    approval: Option<ProfileSigningApproval>,
    candidate: Option<ProfileCandidateStatus>,
}

impl Store {
    pub fn set_profile_signing_approval(
        &mut self,
        agent_id: AgentId,
        topics: Vec<u32>,
    ) -> Result<(), AslError> {
        self.update_profile_signing_approval(Some((agent_id, validate_topics(topics)?)))
    }

    pub fn revoke_profile_signing_approval(&mut self) -> Result<(), AslError> {
        self.update_profile_signing_approval(None)
    }

    fn update_profile_signing_approval(
        &mut self,
        selection: Option<(AgentId, Vec<u32>)>,
    ) -> Result<(), AslError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let previous = read(&tx)?;
        let revision = previous
            .revision
            .checked_add(1)
            .ok_or(AslError::PolicyVersionConflict)?;
        let state = State {
            revision,
            approval: selection.map(|(agent_id, topics)| ProfileSigningApproval {
                agent_id,
                topics,
                revision,
            }),
            candidate: None,
        };
        write(&tx, &state)?;
        tx.commit().map_err(database_error)
    }

    pub fn profile_signing_status(&self) -> Result<ProfileSigningStatus, AslError> {
        profile_signing_status(&self.connection)
    }

    pub fn profile_signing_due(
        &self,
        agent_id: AgentId,
        now_ms: u64,
    ) -> Result<Option<ProfileSigningApproval>, AslError> {
        let state = read(&self.connection)?;
        Ok(state.approval.filter(|approval| {
            approval.agent_id == agent_id
                && state
                    .candidate
                    .is_none_or(|record| now_ms.saturating_sub(record.issued_at_ms) >= RENEWAL_MS)
        }))
    }

    /// Commit a local observation of the actual candidate, only while the
    /// exact approval is still current. No candidate bytes are exported.
    pub fn observe_profile_candidate(
        &mut self,
        approval: &ProfileSigningApproval,
        bytes: &[u8],
    ) -> Result<bool, AslError> {
        let signed = decode_record(bytes)?;
        let RecordPayload::Profile(profile) = signed.record.payload else {
            return Err(AslError::InvalidMessage);
        };
        if profile.agent_id != approval.agent_id
            || profile.avatar.is_some()
            || !profile.capabilities.iter().copied().eq(approval
                .topics
                .iter()
                .copied()
                .map(profile_topic))
        {
            return Err(AslError::PolicyDenied);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let mut state = read(&tx)?;
        if state.approval.as_ref() != Some(approval) {
            return Ok(false);
        }
        state.candidate = Some(ProfileCandidateStatus {
            sequence: signed.record.sequence,
            issued_at_ms: signed.record.issued_at_ms,
            expires_at_ms: signed.record.expires_at_ms,
        });
        write(&tx, &state)?;
        tx.commit().map_err(database_error)?;
        Ok(true)
    }
}

pub(crate) fn profile_signing_status(db: &Connection) -> Result<ProfileSigningStatus, AslError> {
    let state = read(db)?;
    Ok(ProfileSigningStatus {
        approval: state.approval,
        last_candidate: state.candidate,
    })
}

fn validate_topics(mut topics: Vec<u32>) -> Result<Vec<u32>, AslError> {
    if topics.is_empty() || topics.iter().any(|id| !profile_topic(*id).is_topic()) {
        return Err(AslError::InvalidMessage);
    }
    topics.sort_unstable();
    if topics.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(AslError::InvalidMessage);
    }
    Ok(topics)
}

fn read(db: &Connection) -> Result<State, AslError> {
    read_setting(db, KEY)?
        .map(|value| serde_json::from_str(&value).map_err(|_| AslError::InvalidDatabase))
        .transpose()
        .map(Option::unwrap_or_default)
}

fn write(db: &Connection, state: &State) -> Result<(), AslError> {
    let value = serde_json::to_string(state).map_err(|_| AslError::InvalidDatabase)?;
    write_setting(db, KEY, &value, current_time_ms())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{dashboard::Dashboard, open_store};

    #[test]
    fn profile_signing_settings_and_cursor_survive_reopen_without_inheriting_identity() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("asl.sqlite3");
        let owner = AgentId([1; 32]);
        let new_owner = AgentId([2; 32]);
        let mut store = open_store(&path).unwrap();
        assert!(store.profile_signing_status().unwrap().approval.is_none());
        for invalid in [vec![], vec![1], vec![101, 101], vec![999]] {
            assert!(store.set_profile_signing_approval(owner, invalid).is_err());
        }
        store
            .set_profile_signing_approval(owner, vec![109, 101])
            .unwrap();
        assert_eq!(store.reserve_profile_sequence(owner).unwrap(), 0);
        assert_eq!(
            store.reserve_device_directory_sequence(owner, 41).unwrap(),
            41
        );
        drop(store);

        let mut store = open_store(&path).unwrap();
        let status = Dashboard::load(&path).unwrap().profile_signing;
        let approval = status.approval.unwrap();
        assert_eq!(approval.agent_id, owner);
        assert_eq!(approval.topics, [101, 109]);
        assert!(store.profile_signing_due(new_owner, 42).unwrap().is_none());
        assert_eq!(store.reserve_profile_sequence(owner).unwrap(), 1);
        store.revoke_profile_signing_approval().unwrap();
        assert!(
            Dashboard::load(&path)
                .unwrap()
                .profile_signing
                .approval
                .is_none()
        );
        assert_eq!(store.reserve_profile_sequence(owner).unwrap(), 2);
    }
}
