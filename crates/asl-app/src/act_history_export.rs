use std::{io::Write, path::Path};

use alloy_primitives::hex;
use asl_policy::{paths::WriteGrant, snapshot_files::PinnedHome};
use asl_store::{
    act_history::{ActHistoryRow, MAX_ACT_HISTORY_ROWS},
    open_store_read_only,
};
use asl_types::error::AslError;
use serde::Serialize;

use crate::{paths::AppPaths, supervisor::unix_time_ms};

const EXPORT_FORMAT_VERSION: u8 = 1;

#[derive(Serialize)]
struct ExportReport {
    format: &'static str,
    format_version: u8,
    app_version: &'static str,
    exported_at_ms: i64,
    entries: Vec<HistoryEntry>,
}

#[derive(Serialize)]
pub struct HistoryEntry {
    conversation_id: String,
    act_id: String,
    mls_epoch: u64,
    direction: &'static str,
    act_kind: u16,
    causal_root: String,
    reply_to: Option<String>,
    body: Option<String>,
    received_at_ms: i64,
    expires_at_ms: i64,
}

pub fn search(paths: &AppPaths, query: &str, limit: u32) -> Result<Vec<HistoryEntry>, AslError> {
    let store = open_store_read_only(&paths.existing_state_database()?)?;
    store
        .search_act_history(now_ms()?, query, limit)
        .map(|rows| rows.into_iter().map(HistoryEntry::from).collect())
}

/// Export the same bounded, currently decryptable history shown to the local
/// user. The caller explicitly selects a new destination file.
pub fn export(paths: &AppPaths, destination: &Path) -> Result<(), AslError> {
    let directory = destination.parent().ok_or(AslError::InvalidStorageRoot)?;
    let filename = Path::new(
        destination
            .file_name()
            .ok_or(AslError::InvalidStorageRoot)?,
    );
    WriteGrant::filename(filename)?;
    let grant = WriteGrant::open(directory, paths.dos_root())?;
    let _pin = PinnedHome::open(paths.dos_root())?;
    let exported_at_ms = now_ms()?;
    let store = open_store_read_only(&paths.existing_state_database()?)?;
    let report = ExportReport {
        format: "asl-act-history",
        format_version: EXPORT_FORMAT_VERSION,
        app_version: env!("CARGO_PKG_VERSION"),
        exported_at_ms,
        entries: store
            .recent_act_history(exported_at_ms, MAX_ACT_HISTORY_ROWS)?
            .into_iter()
            .map(HistoryEntry::from)
            .collect(),
    };
    let staging = format!(".asl-act-history-{:032x}.tmp", rand::random::<u128>());
    let mut file = grant.create_new(Path::new(&staging))?;
    serde_json::to_writer_pretty(&mut file, &report).map_err(std::io::Error::other)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    grant.rename_new(&mut file, filename)
}

impl From<ActHistoryRow> for HistoryEntry {
    fn from(row: ActHistoryRow) -> Self {
        Self {
            conversation_id: row.conversation_id,
            act_id: hex::encode(row.act_id),
            mls_epoch: row.mls_epoch,
            direction: row.direction.as_str(),
            act_kind: row.act_kind,
            causal_root: hex::encode(row.causal_root),
            reply_to: row.reply_to.map(hex::encode),
            body: row.body,
            received_at_ms: row.created_at_ms,
            expires_at_ms: row.expires_at_ms,
        }
    }
}

fn now_ms() -> Result<i64, AslError> {
    i64::try_from(unix_time_ms()?).map_err(|_| AslError::InvalidPolicyState)
}

#[cfg(test)]
mod tests {
    use asl_store::{
        act_history::{ActDirection, ActHistoryRecord},
        open_store,
    };
    use asl_types::ids::Id128;

    use super::*;

    #[test]
    fn export_writes_only_to_a_new_explicit_file() {
        let fixture = tempfile::tempdir().unwrap();
        let paths = AppPaths::open(&fixture.path().join("profile")).unwrap();
        let now = unix_time_ms().unwrap();
        {
            let mut store = open_store(&paths.state().join("asl.sqlite3")).unwrap();
            store
                .record_act_history(ActHistoryRecord {
                    conversation_id: "00112233445566778899aabbccddeeff",
                    message_id: Id128([1; 16]),
                    mls_epoch: 2,
                    direction: ActDirection::Out,
                    act_kind: 0,
                    reply_to: None,
                    causal_root: Id128([2; 16]),
                    body: Some("exported local memory"),
                    now_ms: now,
                    expires_at_ms: now + 7 * 24 * 60 * 60 * 1_000,
                })
                .unwrap();
        }
        let export_directory = fixture.path().join("exports");
        std::fs::create_dir(&export_directory).unwrap();
        let destination = export_directory.join("act-history.json");
        export(&paths, &destination).unwrap();
        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&destination).unwrap()).unwrap();
        assert_eq!(report["format"], "asl-act-history");
        assert_eq!(report["entries"][0]["body"], "exported local memory");
        assert!(export(&paths, &destination).is_err());
    }
}
