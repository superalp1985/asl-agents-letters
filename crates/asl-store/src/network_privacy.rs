use asl_types::error::AslError;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::{Store, current_time_ms, read_setting};

const FORCE_RELAY_ONLY: &str = "network.force_relay_only.v1";
const LAST_REPORT: &str = "ui.network_report.v1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkReport {
    pub relay_only: bool,
    pub configured_relays: usize,
    pub reserved_relays: usize,
    pub observed_at_ms: i64,
}

impl Store {
    pub fn force_relay_only(&self) -> Result<bool, AslError> {
        force_relay_only(&self.connection)
    }

    pub fn set_force_relay_only(&self, enabled: bool) -> Result<(), AslError> {
        self.set_setting(
            FORCE_RELAY_ONLY,
            if enabled { "true" } else { "false" },
            current_time_ms(),
        )
    }

    pub fn report_network_state(
        &self,
        relay_only: bool,
        configured_relays: usize,
        reserved_relays: usize,
    ) -> Result<(), AslError> {
        let now = current_time_ms();
        let value = serde_json::to_string(&NetworkReport {
            relay_only,
            configured_relays,
            reserved_relays,
            observed_at_ms: now,
        })
        .map_err(|_| AslError::InvalidDatabase)?;
        self.set_setting(LAST_REPORT, &value, now)
    }
}

pub(crate) fn force_relay_only(db: &Connection) -> Result<bool, AslError> {
    match read_setting(db, FORCE_RELAY_ONLY)?.as_deref() {
        Some("true") => Ok(true),
        Some("false") | None => Ok(false),
        _ => Err(AslError::InvalidDatabase),
    }
}

pub(crate) fn last_network_report(db: &Connection) -> Result<Option<NetworkReport>, AslError> {
    read_setting(db, LAST_REPORT)?
        .map(|value| serde_json::from_str(&value).map_err(|_| AslError::InvalidDatabase))
        .transpose()
}
