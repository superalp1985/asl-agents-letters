mod dpapi;
pub(crate) mod handles;
mod volume;

pub use dpapi::{protect_secret, unprotect_secret};
pub use volume::validate_storage_root;
