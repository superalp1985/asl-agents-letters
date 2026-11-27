pub(crate) mod appcontainer;
mod dpapi;
mod executable_acl;
pub(crate) mod file_dialog;
pub(crate) mod handles;
mod job;
pub(crate) mod local_ipc;
pub(crate) mod notification;
pub(crate) mod reconcile_watch;
pub(crate) mod resources;
pub(crate) mod tray;
mod volume;

pub use dpapi::{protect_secret, unprotect_secret};
pub use volume::validate_storage_root;
