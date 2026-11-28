use asl_types::error::AslError;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::{Store, current_time_ms, read_setting};

const FORCE_RELAY_ONLY: &str = "network.force_relay_only.v1";
const PAUSE_REQUESTED: &str = "network.pause_requested.v1";
const LAST_REPORT: &str = "ui.network_report.v1";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkRuntimeState {
    #[default]
    Unknown,
    Running,
    Paused,
    ResumeFailed,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkReachability {
    #[default]
    Unreported,
    Unknown,
    Private,
    Public,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkRouteFailure {
    DirectUnavailable,
    RelayUnavailable,
    HolePunchFailed,
    TimedOut,
    PeerIdentityMismatch,
    Disconnected,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkReport {
    #[serde(default)]
    pub runtime: NetworkRuntimeState,
    pub relay_only: bool,
    pub configured_relays: usize,
    pub reserved_relays: usize,
    pub observed_at_ms: i64,
    #[serde(default)]
    pub reachability: NetworkReachability,
    #[serde(default)]
    pub reachability_confidence: u8,
    #[serde(default)]
    pub public_entry: bool,
    #[serde(default)]
    pub listening_endpoints: usize,
    #[serde(default)]
    pub direct_routes: usize,
    #[serde(default)]
    pub hole_punched_routes: usize,
    #[serde(default)]
    pub relayed_routes: usize,
    #[serde(default)]
    pub negotiating_routes: usize,
    #[serde(default)]
    pub failed_routes: usize,
    #[serde(default)]
    pub last_route_failure: Option<NetworkRouteFailure>,
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

    pub fn network_pause_requested(&self) -> Result<bool, AslError> {
        network_pause_requested(&self.connection)
    }

    pub fn set_network_pause_requested(&self, paused: bool) -> Result<(), AslError> {
        self.set_setting(
            PAUSE_REQUESTED,
            if paused { "true" } else { "false" },
            current_time_ms(),
        )
    }

    pub fn report_network_state(
        &self,
        runtime: NetworkRuntimeState,
        relay_only: bool,
        configured_relays: usize,
        reserved_relays: usize,
    ) -> Result<(), AslError> {
        self.report_network_snapshot(NetworkReport {
            runtime,
            relay_only,
            configured_relays,
            reserved_relays,
            observed_at_ms: 0,
            reachability: NetworkReachability::Unreported,
            reachability_confidence: 0,
            public_entry: false,
            listening_endpoints: 0,
            direct_routes: 0,
            hole_punched_routes: 0,
            relayed_routes: 0,
            negotiating_routes: 0,
            failed_routes: 0,
            last_route_failure: None,
        })
    }

    pub fn report_network_snapshot(&self, mut report: NetworkReport) -> Result<(), AslError> {
        if report.reachability_confidence > 100
            || report.listening_endpoints > 1024
            || report.direct_routes > 100_000
            || report.hole_punched_routes > 100_000
            || report.relayed_routes > 100_000
            || report.negotiating_routes > 100_000
            || report.failed_routes > 100_000
        {
            return Err(AslError::InvalidMessage);
        }
        let now = current_time_ms();
        report.observed_at_ms = now;
        let value = serde_json::to_string(&report).map_err(|_| AslError::InvalidDatabase)?;
        self.set_setting(LAST_REPORT, &value, now)
    }
}

pub(crate) fn force_relay_only(db: &Connection) -> Result<bool, AslError> {
    read_flag(db, FORCE_RELAY_ONLY)
}

pub(crate) fn network_pause_requested(db: &Connection) -> Result<bool, AslError> {
    read_flag(db, PAUSE_REQUESTED)
}

fn read_flag(db: &Connection, key: &str) -> Result<bool, AslError> {
    match read_setting(db, key)?.as_deref() {
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
