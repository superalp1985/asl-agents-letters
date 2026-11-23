//! One short-lived, explicitly requested lookup. Results only come from the verified projection.
use asl_types::{error::AslError, ids::AgentId};
use rusqlite::{Connection, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

use crate::{
    Store, current_time_ms, database_error, network_privacy::network_pause_requested, read_setting,
    remote_profiles::profile_visible, write_setting,
};

const KEY: &str = "profile.lookup_v1";
const WINDOW_MS: i64 = 15_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LookupState {
    Queued,
    Searching,
    Available,
    NoLongerVisible,
    NoVerifiedResult,
    Unavailable,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProfileLookup {
    pub target: AgentId,
    pub operation: [u8; 16],
    pub state: LookupState,
    pub expires_ms: i64,
}

impl ProfileLookup {
    fn save(&self, db: &Connection, now: i64) -> Result<(), AslError> {
        write_setting(
            db,
            KEY,
            &serde_json::to_string(self).map_err(|_| AslError::InvalidDatabase)?,
            now,
        )
    }
    fn expire(&mut self, now: i64) {
        if now >= self.expires_ms
            && matches!(self.state, LookupState::Queued | LookupState::Searching)
        {
            self.state = LookupState::NoVerifiedResult;
        }
    }
}

pub(crate) fn status(db: &Connection, now: i64) -> Result<Option<ProfileLookup>, AslError> {
    let Some(value) = read_setting(db, KEY)? else {
        return Ok(None);
    };
    let mut request: ProfileLookup =
        serde_json::from_str(&value).map_err(|_| AslError::InvalidDatabase)?;
    request.expire(now);
    if request.state == LookupState::Available && !profile_visible(db, request.target, now)? {
        request.state = LookupState::NoLongerVisible;
    }
    Ok(Some(request))
}

fn allowed(db: &Connection, target: AgentId) -> Result<bool, AslError> {
    if network_pause_requested(db)? {
        return Ok(false);
    }
    db.query_row("SELECT NOT EXISTS(SELECT 1 FROM contact_bindings WHERE agent_id=?1 AND state='revoked')
                         AND NOT EXISTS(SELECT 1 FROM local_agent_identity WHERE agent_id=?2)
                         AND NOT EXISTS(SELECT 1 FROM identity_registry_states WHERE agent_id=?2 AND status='revoked')",
        params![target.as_bytes(), bs58::encode(target.as_bytes()).into_string()], |r| r.get(0)).map_err(database_error)
}

impl Store {
    pub fn request_profile_lookup(
        &mut self,
        target: AgentId,
        operation: [u8; 16],
    ) -> Result<ProfileLookup, AslError> {
        if operation == [0; 16] {
            return Err(AslError::InvalidMessage);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let now = current_time_ms();
        if !allowed(&tx, target)? {
            return Err(AslError::PolicyDenied);
        }
        if let Some(existing) = status(&tx, now)?.filter(|r| now < r.expires_ms) {
            return if existing.target == target {
                Ok(existing)
            } else {
                Err(AslError::QuotaExceeded)
            };
        }
        let state = if profile_visible(&tx, target, now)? {
            LookupState::Available
        } else {
            LookupState::Queued
        };
        let request = ProfileLookup {
            target,
            operation,
            state,
            expires_ms: now + WINDOW_MS,
        };
        request.save(&tx, now)?;
        tx.commit().map_err(database_error)?;
        Ok(request)
    }

    pub fn profile_lookup_status(&self) -> Result<Option<ProfileLookup>, AslError> {
        status(&self.connection, current_time_ms())
    }

    pub fn advance_profile_lookup(
        &mut self,
        network_active: bool,
        enqueue: impl FnOnce([u8; 16], AgentId) -> Result<bool, AslError>,
    ) -> Result<(), AslError> {
        let pending =
            |r: &ProfileLookup| matches!(r.state, LookupState::Queued | LookupState::Searching);
        if !self.profile_lookup_status()?.is_some_and(|r| pending(&r)) {
            return Ok(());
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let now = current_time_ms();
        let Some(mut request) = status(&tx, now)?.filter(pending) else {
            return Ok(());
        };
        let next = if !allowed(&tx, request.target)? {
            LookupState::Unavailable
        } else if profile_visible(&tx, request.target, now)? {
            LookupState::Available
        } else if !network_active {
            LookupState::Unavailable
        } else if request.state == LookupState::Searching {
            return Ok(());
        } else if enqueue(request.operation, request.target).unwrap_or(false) {
            LookupState::Searching
        } else {
            LookupState::Unavailable
        };
        request.state = next;
        request.save(&tx, now)?;
        tx.commit().map_err(database_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn profile_lookup_coalesces_one_get_and_reports_timeout_without_retry() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = crate::open_store(&dir.path().join("state.sqlite3")).unwrap();
        let agent = AgentId([7; 32]);
        let request = store.request_profile_lookup(agent, [5; 16]).unwrap();
        assert_eq!(
            store
                .request_profile_lookup(agent, [6; 16])
                .unwrap()
                .operation,
            request.operation
        );
        assert!(matches!(
            store.request_profile_lookup(AgentId([8; 32]), [7; 16]),
            Err(AslError::QuotaExceeded)
        ));
        store
            .advance_profile_lookup(true, |id, target| {
                assert_eq!((id, target), (request.operation, agent));
                Ok(true)
            })
            .unwrap();
        store
            .advance_profile_lookup(true, |_, _| panic!("duplicate GET"))
            .unwrap();
        assert_eq!(
            store.profile_lookup_status().unwrap().unwrap().state,
            LookupState::Searching
        );
        assert_eq!(
            status(&store.connection, request.expires_ms)
                .unwrap()
                .unwrap()
                .state,
            LookupState::NoVerifiedResult
        );
        store.set_network_pause_requested(true).unwrap();
        store
            .advance_profile_lookup(true, |_, _| panic!("network paused"))
            .unwrap();
        assert_eq!(
            store.profile_lookup_status().unwrap().unwrap().state,
            LookupState::Unavailable
        );
        assert!(matches!(
            store.request_profile_lookup(agent, [6; 16]),
            Err(AslError::PolicyDenied)
        ));
    }
}
