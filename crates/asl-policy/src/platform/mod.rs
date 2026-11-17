#[cfg(windows)]
pub mod windows;

#[cfg(windows)]
pub use windows::validate_storage_root;
#[cfg(windows)]
pub use windows::{protect_secret, unprotect_secret};

#[cfg(not(windows))]
pub fn validate_storage_root(_: &std::path::Path) -> Result<(), asl_types::error::AslError> {
    Err(asl_types::error::AslError::PlatformUnavailable)
}

#[cfg(not(windows))]
pub fn protect_secret(_: &[u8]) -> Result<Vec<u8>, asl_types::error::AslError> {
    Err(asl_types::error::AslError::PlatformUnavailable)
}

#[cfg(not(windows))]
pub fn unprotect_secret(
    _: &[u8],
) -> Result<zeroize::Zeroizing<Vec<u8>>, asl_types::error::AslError> {
    Err(asl_types::error::AslError::PlatformUnavailable)
}
