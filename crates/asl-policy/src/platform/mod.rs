#[cfg(windows)]
pub mod windows;

#[cfg(windows)]
pub use windows::validate_storage_root;

#[cfg(not(windows))]
pub fn validate_storage_root(_: &std::path::Path) -> Result<(), asl_types::error::AslError> {
    Err(asl_types::error::AslError::PlatformUnavailable)
}
