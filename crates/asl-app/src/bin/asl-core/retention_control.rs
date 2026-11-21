use std::{env, ffi::OsStr, path::PathBuf};

use asl_app::paths::AppPaths;
use asl_policy::snapshot_files::PinnedHome;
use asl_store::open_store;
use asl_types::error::AslError;

pub(super) fn set_direct_days(days: &OsStr) -> Result<(), AslError> {
    let days = days
        .to_str()
        .and_then(|value| value.parse::<u8>().ok())
        .ok_or(AslError::InvalidMessage)?;
    let home = PathBuf::from(env::var_os("ASL_HOME").ok_or(AslError::InvalidStorageRoot)?);
    let paths = AppPaths::open_existing(&home)?;
    let _pin = PinnedHome::open(&home)?;
    open_store(&paths.state().join("asl.sqlite3"))?.set_direct_observation_days(days)
}
