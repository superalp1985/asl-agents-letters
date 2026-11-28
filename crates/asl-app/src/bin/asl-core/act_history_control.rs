use std::{ffi::OsString, path::Path};

use asl_app::{act_history_export, paths::AppPaths};
use asl_types::error::AslError;

const SEARCH_LIMIT: u32 = 100;

pub(super) fn run(args: &[OsString]) -> Result<(), AslError> {
    let root = std::env::var_os("ASL_HOME").ok_or(AslError::InvalidStorageRoot)?;
    let paths = AppPaths::open_existing(Path::new(&root))?;
    match args {
        [command, query] if command == "search" => {
            let query = query.to_str().ok_or(AslError::InvalidMessage)?;
            let entries = act_history_export::search(&paths, query, SEARCH_LIMIT)?;
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "query": query,
                    "limit": SEARCH_LIMIT,
                    "entries": entries,
                }))
                .map_err(std::io::Error::other)?
            );
            Ok(())
        }
        [command, destination] if command == "export" => {
            act_history_export::export(&paths, Path::new(destination))
        }
        _ => Err(AslError::InvalidMessage),
    }
}
