use std::{
    fs::{self, File},
    io::Read,
    os::windows::fs::MetadataExt,
    path::{Path, PathBuf},
};

use asl_types::error::AslError;

const REPARSE_POINT: u32 = 0x400;
const POINTER: &str = "active-release.txt";
const LAYOUT: &str = "package-layout.txt";
const VERSION: &str = "asl-windows-layout-v2";

pub(super) fn active_agent() -> Result<Option<PathBuf>, AslError> {
    let current = std::env::current_exe()?;
    let root = current.parent().ok_or(AslError::InvalidStorageRoot)?;
    let layout = root.join(LAYOUT);
    match fs::symlink_metadata(&layout) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return match fs::symlink_metadata(root.join(POINTER)) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                _ => Err(AslError::InvalidPolicyState),
            };
        }
        Err(error) => return Err(error.into()),
        Ok(_) => {}
    }
    if read_marker(&layout)? != VERSION {
        return Err(AslError::IncompatibleVersion);
    }
    let pointer = read_marker(&root.join(POINTER))?;
    if pointer == "base" {
        return Ok(None);
    }
    let (name, version) = pointer
        .split_once('\n')
        .ok_or(AslError::InvalidPolicyState)?;
    let id = name
        .strip_prefix("release-")
        .ok_or(AslError::InvalidPolicyState)?;
    if id.len() != 32
        || !id
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        || semver::Version::parse(version).is_err()
    {
        return Err(AslError::InvalidPolicyState);
    }
    let release = root.join(name);
    let metadata = fs::symlink_metadata(&release)?;
    if !metadata.is_dir() || metadata.file_attributes() & REPARSE_POINT != 0 {
        return Err(AslError::InvalidStorageRoot);
    }
    if read_marker(&release.join(LAYOUT))? != VERSION
        || read_marker(&release.join(POINTER))? != "base"
    {
        return Err(AslError::InvalidPolicyState);
    }
    let executable = release.join("asl.exe");
    regular_file(&executable)?;
    Ok(Some(executable))
}

fn regular_file(path: &Path) -> Result<(), AslError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_attributes() & REPARSE_POINT != 0 {
        return Err(AslError::InvalidStorageRoot);
    }
    Ok(())
}

fn read_marker(path: &Path) -> Result<String, AslError> {
    regular_file(path)?;
    let mut bytes = Vec::new();
    File::open(path)?.take(257).read_to_end(&mut bytes)?;
    if bytes.len() > 256 {
        return Err(AslError::InvalidPolicyState);
    }
    String::from_utf8(bytes).map_err(|_| AslError::InvalidPolicyState)
}
