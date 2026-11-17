use std::path::{Component, Path, Prefix};

use asl_types::error::AslError;
use windows::Win32::Storage::FileSystem::GetVolumeInformationW;
use windows::core::HSTRING;

pub fn validate_storage_root(path: &Path) -> Result<(), AslError> {
    let Some(Component::Prefix(prefix)) = path.components().next() else {
        return Err(AslError::InvalidStorageRoot);
    };
    let Prefix::Disk(drive) = prefix.kind() else {
        return Err(AslError::InvalidStorageRoot);
    };

    let volume_root = HSTRING::from(format!("{}:\\", char::from(drive)));
    let mut filesystem_name = [0u16; 32];
    let result = unsafe {
        GetVolumeInformationW(
            &volume_root,
            None,
            None,
            None,
            None,
            Some(&mut filesystem_name),
        )
    };
    result.map_err(|_| AslError::InvalidStorageRoot)?;

    let filesystem_name = String::from_utf16_lossy(&filesystem_name);
    if filesystem_name
        .trim_end_matches('\0')
        .eq_ignore_ascii_case("NTFS")
    {
        Ok(())
    } else {
        Err(AslError::InvalidStorageRoot)
    }
}
