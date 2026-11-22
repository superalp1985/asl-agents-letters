use std::{env, ffi::OsStr, path::PathBuf};

use asl_app::paths::AppPaths;
use asl_policy::snapshot_files::PinnedHome;
use asl_store::open_store;
use asl_types::error::AslError;

pub(super) fn set_days(kind: &OsStr, days: &OsStr) -> Result<(), AslError> {
    let apply = match kind.to_str() {
        Some("direct") => asl_store::Store::set_direct_observation_days,
        Some("group") => asl_store::Store::set_group_observation_days,
        _ => return Err(AslError::InvalidMessage),
    };
    let days = days
        .to_str()
        .and_then(|value| value.parse::<u8>().ok())
        .ok_or(AslError::InvalidMessage)?;
    let home = PathBuf::from(env::var_os("ASL_HOME").ok_or(AslError::InvalidStorageRoot)?);
    let paths = AppPaths::open_existing(&home)?;
    let _pin = PinnedHome::open(&home)?;
    apply(&mut open_store(&paths.state().join("asl.sqlite3"))?, days)
}
