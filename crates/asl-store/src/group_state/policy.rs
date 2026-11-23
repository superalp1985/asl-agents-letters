use asl_types::error::AslError;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};

use super::sql_number;
use crate::{Store, database_error};

const POLICY_KEY: &str = "agent.group_inbound_policy_v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupInboundPolicy {
    pub browse_enabled: bool,
    pub answer_enabled: bool,
}

impl Default for GroupInboundPolicy {
    fn default() -> Self {
        Self {
            browse_enabled: true,
            answer_enabled: false,
        }
    }
}

impl GroupInboundPolicy {
    pub fn load(store: &Store) -> Result<Self, AslError> {
        Self::read(&store.connection)
    }

    pub(crate) fn read(db: &Connection) -> Result<Self, AslError> {
        Ok(Self::read_saved(db)?.unwrap_or_default())
    }

    pub(crate) fn read_saved(db: &Connection) -> Result<Option<Self>, AslError> {
        db.query_row(
            "SELECT value_json FROM settings WHERE key=?1",
            [POLICY_KEY],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(database_error)?
        .map(|value| serde_json::from_str(&value).map_err(|_| AslError::InvalidPolicyState))
        .transpose()
    }

    pub fn save(self, store: &Store, now_ms: u64) -> Result<(), AslError> {
        let value = serde_json::to_string(&self).map_err(|_| AslError::InvalidPolicyState)?;
        store.set_setting(POLICY_KEY, &value, sql_number(now_ms)?)
    }

    pub fn set_switch(
        store: &mut Store,
        switch: GroupInboundSwitch,
        enabled: bool,
    ) -> Result<(), AslError> {
        let tx = Transaction::new_unchecked(&store.connection, TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let mut policy = Self::read(&tx)?;
        match switch {
            GroupInboundSwitch::Browse => policy.browse_enabled = enabled,
            GroupInboundSwitch::Answer => policy.answer_enabled = enabled,
        }
        policy.save(store, crate::current_time_ms() as u64)?;
        tx.commit().map_err(database_error)
    }
}

#[derive(Clone, Copy)]
pub enum GroupInboundSwitch {
    Browse,
    Answer,
}
