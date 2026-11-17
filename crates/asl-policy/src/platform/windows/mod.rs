mod dpapi;
mod volume;

pub use dpapi::{protect_secret, unprotect_secret};
pub use volume::validate_storage_root;
