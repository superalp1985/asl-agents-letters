mod audience;
pub mod fetch;
mod labels;
pub mod lease;
pub mod paths;
mod platform;
pub mod reconcile;
pub mod sandbox;
pub mod service;
pub mod snapshot_files;
pub mod types;

pub use fetch::{issue_fetch_grant, validate_fetch_grant};
pub use lease::{
    LEASE_TTL_MS, LeaseAccess, LeaseGrant, LeaseManager, MAX_ACTIVE_LEASES,
    MAX_ACTIVE_LEASES_PER_PEER,
};
pub use paths::{
    AuthorizedFile, AuthorizedWriteFile, FileIdentity, SourceGrant, SourceRules, WriteGrant,
    open_authorized_source,
};
#[cfg(target_os = "linux")]
pub use platform::linux::file_dialog::{
    choose_avatar_file, choose_local_directory, choose_local_file,
};
#[cfg(target_os = "linux")]
pub use platform::linux::local_ipc::{
    LocalPipeClient, LocalPipeConnection, LocalPipeServer, connect_local_pipe,
    connect_recovery_pipe,
};
#[cfg(target_os = "linux")]
pub use platform::linux::notification::{play_notification_sound, send_notification};
#[cfg(target_os = "linux")]
pub use platform::linux::resources::{ResourceSample, local_resource_sample, thread_cpu_time};
#[cfg(target_os = "linux")]
pub use platform::linux::tray::{TrayCommand, TrayHandle, set_tray_language, start_tray};
#[cfg(windows)]
pub use platform::windows::file_dialog::{
    choose_avatar_file, choose_local_directory, choose_local_file,
};
#[cfg(windows)]
pub use platform::windows::local_ipc::{
    LocalPipeConnection, LocalPipeServer, connect_local_pipe, connect_recovery_pipe,
};
#[cfg(windows)]
pub use platform::windows::notification::play_notification_sound;
#[cfg(windows)]
pub use platform::windows::resources::{ResourceSample, local_resource_sample, thread_cpu_time};
#[cfg(windows)]
pub use platform::windows::tray::{TrayCommand, TrayHandle, set_tray_language, start_tray};
pub use platform::{protect_secret, unprotect_secret, validate_storage_root};
pub use service::{Permit, PolicyEngine, PolicyService, ScopedPolicy};
pub use types::*;
