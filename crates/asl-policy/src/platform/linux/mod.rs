pub(crate) mod file_dialog;
pub(crate) mod filesystem;
pub(crate) mod handles;
pub(crate) mod local_ipc;
pub(crate) mod notification;
pub(crate) mod resources;
pub(crate) mod sandbox;
pub(crate) mod secret;
pub(crate) mod tray;

pub use filesystem::validate_storage_root;
pub use secret::{protect_secret, unprotect_secret};
