#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(windows)]
pub mod windows;

#[cfg(any(windows, target_os = "linux"))]
pub use self::platform_impl::{protect_secret, unprotect_secret, validate_storage_root};

#[cfg(windows)]
mod platform_impl {
    pub use super::windows::{protect_secret, unprotect_secret, validate_storage_root};
}

#[cfg(target_os = "linux")]
mod platform_impl {
    pub use super::linux::{protect_secret, unprotect_secret, validate_storage_root};
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn validate_storage_root(_: &std::path::Path) -> Result<(), asl_types::error::AslError> {
    Err(asl_types::error::AslError::PlatformUnavailable)
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn protect_secret(_: &[u8]) -> Result<Vec<u8>, asl_types::error::AslError> {
    Err(asl_types::error::AslError::PlatformUnavailable)
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn unprotect_secret(
    _: &[u8],
) -> Result<zeroize::Zeroizing<Vec<u8>>, asl_types::error::AslError> {
    Err(asl_types::error::AslError::PlatformUnavailable)
}
