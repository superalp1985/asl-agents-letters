use std::{io::Write, path::Path};

use asl_policy::{paths::WriteGrant, snapshot_files::PinnedHome};
use asl_store::{diagnostics::DiagnosticSummary, open_store_read_only};
use asl_types::error::AslError;
use serde::Serialize;

use crate::paths::AppPaths;

#[derive(Serialize)]
struct Report {
    format_version: u8,
    app_version: &'static str,
    schema_version: u32,
    #[serde(flatten)]
    summary: DiagnosticSummary,
}

/// Export a local, versioned summary to an explicitly selected new file.
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
    let mut store = open_store_read_only(&paths.existing_state_database()?)?;
    let report = Report {
        format_version: 1,
        app_version: env!("CARGO_PKG_VERSION"),
        schema_version: store.schema_version(),
        summary: store.diagnostic_summary()?,
    };
    let staging_name = format!(".asl-diagnostics-{:032x}.tmp", rand::random::<u128>());
    let mut file = grant.create_new(Path::new(&staging_name))?;
    serde_json::to_writer_pretty(&mut file, &report).map_err(std::io::Error::other)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    grant.rename_new(&mut file, filename)
}
