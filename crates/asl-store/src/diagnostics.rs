use asl_types::error::AslError;
use serde::Serialize;

use crate::{
    Store, database_error,
    network_privacy::{NetworkReport, last_network_report},
};

#[derive(Serialize)]
pub struct DiagnosticSummary {
    pub last_network_report: Option<NetworkReport>,
    pub counts: DiagnosticCounts,
}

#[derive(Serialize)]
pub struct DiagnosticCounts {
    pub known_agents: i64,
    pub active_share_grants: i64,
    pub active_inbox_grants: i64,
    pub completed_downloads: i64,
    pub failed_downloads: i64,
}

impl Store {
    pub fn diagnostic_summary(&mut self) -> Result<DiagnosticSummary, AslError> {
        let tx = self.connection.transaction().map_err(database_error)?;
        let last_network_report = last_network_report(&tx)?;
        let counts = tx
            .query_row(
                "SELECT (SELECT COUNT(*) FROM agents),
                        (SELECT COUNT(*) FROM grants WHERE status='active'),
                        (SELECT COUNT(*) FROM write_grants WHERE kind='inbox' AND status='active'),
                        (SELECT COUNT(*) FROM transfers WHERE state='complete'),
                        (SELECT COUNT(*) FROM transfers WHERE state='failed')",
                [],
                |row| {
                    Ok(DiagnosticCounts {
                        known_agents: row.get(0)?,
                        active_share_grants: row.get(1)?,
                        active_inbox_grants: row.get(2)?,
                        completed_downloads: row.get(3)?,
                        failed_downloads: row.get(4)?,
                    })
                },
            )
            .map_err(database_error)?;
        tx.commit().map_err(database_error)?;
        Ok(DiagnosticSummary {
            last_network_report,
            counts,
        })
    }
}
