pub(crate) mod appcontainer;
mod dpapi;
mod executable_acl;
pub(crate) mod handles;
mod job;
mod volume;

pub use dpapi::{protect_secret, unprotect_secret};
pub use volume::validate_storage_root;
