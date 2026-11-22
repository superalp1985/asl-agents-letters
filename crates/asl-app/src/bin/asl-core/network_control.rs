use std::{env, ffi::OsStr, path::PathBuf};

use asl_app::{network_settings::NetworkSettingsV1, paths::AppPaths};
use asl_policy::snapshot_files::PinnedHome;
use asl_store::open_store;
use asl_types::error::AslError;

pub(super) fn set_relay_only(mode: &OsStr) -> Result<(), AslError> {
    set_network_flag(mode, |paths, store, enabled| {
        if enabled {
            NetworkSettingsV1::load(&paths.network_settings_configuration())?
                .with_relay_only_override(true)?;
        }
        store.set_force_relay_only(enabled)
    })
}

pub(super) fn set_pause(mode: &OsStr) -> Result<(), AslError> {
    set_network_flag(mode, |_, store, enabled| {
        store.set_network_pause_requested(enabled)
    })
}

fn set_network_flag(
    mode: &OsStr,
    set: impl FnOnce(&AppPaths, asl_store::Store, bool) -> Result<(), AslError>,
) -> Result<(), AslError> {
    let enabled = match mode.to_str() {
        Some("on") => true,
        Some("off") => false,
        _ => return Err(AslError::InvalidMessage),
    };
    let home = PathBuf::from(env::var_os("ASL_HOME").ok_or(AslError::InvalidStorageRoot)?);
    let paths = AppPaths::open_existing(&home)?;
    let _pin = PinnedHome::open(&home)?;
    set(
        &paths,
        open_store(&paths.state().join("asl.sqlite3"))?,
        enabled,
    )
}
