use std::path::PathBuf;

use asl_types::error::AslError;

pub fn choose_avatar_file() -> Result<Option<PathBuf>, AslError> {
    Ok(rfd::FileDialog::new()
        .add_filter("PNG, JPEG, WebP", &["png", "jpg", "jpeg", "webp"])
        .pick_file())
}

pub fn choose_local_directory() -> Result<Option<PathBuf>, AslError> {
    Ok(rfd::FileDialog::new().pick_folder())
}

pub fn choose_local_file() -> Result<Option<PathBuf>, AslError> {
    Ok(rfd::FileDialog::new().pick_file())
}
