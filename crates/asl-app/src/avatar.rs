//! Private preview and separate local consent to sign its content reference.

use std::{io::Cursor, path::Path};

use asl_policy::{paths::read_local_selection, snapshot_files::PinnedHome};
use asl_store::{open_store, open_store_read_only};
use asl_types::error::AslError;
use asl_types::ids::{AgentId, Hash32};
use image::{ImageFormat, ImageReader, Limits, RgbaImage};

use crate::{
    documents::{MAX_AVATAR_BYTES, MAX_AVATAR_INPUT_BYTES},
    identity::AgentIdentity,
    paths::AppPaths,
    supervisor::sanitize_local_avatar,
};

pub mod presets;
mod received;
pub use crate::documents::MAX_AVATAR_EDGE;
pub(crate) use received::sanitize_verified;

pub fn request_download(paths: &AppPaths, owner: AgentId, content: Hash32) -> Result<(), AslError> {
    let _pin = PinnedHome::open(paths.dos_root())?;
    open_store(&paths.existing_state_database()?)?.request_avatar_download(owner, content)?;
    Ok(())
}

pub fn cancel_download(paths: &AppPaths) -> Result<(), AslError> {
    let _pin = PinnedHome::open(paths.dos_root())?;
    open_store(&paths.existing_state_database()?)?.cancel_avatar_download()
}

pub fn received(
    paths: &AppPaths,
    owner: AgentId,
    content: Hash32,
) -> Result<Option<RgbaImage>, AslError> {
    let _pin = PinnedHome::open(paths.dos_root())?;
    open_store_read_only(&paths.existing_state_database()?)?
        .received_avatar(owner, content)?
        .as_deref()
        .map(decode_thumbnail)
        .transpose()
}

pub struct AvatarPreview {
    pub image: RgbaImage,
    pub token: Option<String>,
    pub approved: bool,
}

pub fn load(paths: &AppPaths) -> Result<Option<RgbaImage>, AslError> {
    Ok(preview(paths)?.map(|preview| preview.image))
}

pub fn preview(paths: &AppPaths) -> Result<Option<AvatarPreview>, AslError> {
    let _pin = PinnedHome::open(paths.dos_root())?;
    let mut store = open_store_read_only(&paths.existing_state_database()?)?;
    let Some(review) = store.avatar_review()? else {
        return Ok(None);
    };
    Ok(Some(AvatarPreview {
        image: decode_thumbnail(&review.bytes).map_err(|_| AslError::InvalidDatabase)?,
        token: review.token,
        approved: review.approved,
    }))
}

pub fn set(paths: &AppPaths, source: &Path) -> Result<(), AslError> {
    let extension = source
        .extension()
        .and_then(|ext| ext.to_str())
        .ok_or(AslError::InvalidMessage)?;
    if !["png", "jpg", "jpeg", "webp"]
        .iter()
        .any(|allowed| extension.eq_ignore_ascii_case(allowed))
    {
        return Err(AslError::InvalidMessage);
    }
    let _pin = PinnedHome::open(paths.dos_root())?;
    let database = paths.existing_state_database()?;
    let input = read_local_selection(source, paths.dos_root(), MAX_AVATAR_INPUT_BYTES)?;
    if input.is_empty() {
        return Err(AslError::InvalidMessage);
    }
    let sanitized = sanitize_local_avatar(&input)?;
    decode_thumbnail(&sanitized)?;
    open_store(&database)?.replace_sanitized_avatar(Some(&sanitized))
}

pub fn clear(paths: &AppPaths) -> Result<(), AslError> {
    let _pin = PinnedHome::open(paths.dos_root())?;
    open_store(&paths.existing_state_database()?)?.replace_sanitized_avatar(None)
}

pub fn set_preset(paths: &AppPaths, index: usize) -> Result<(), AslError> {
    let bytes = presets::PNGS.get(index).ok_or(AslError::InvalidMessage)?;
    decode_thumbnail(bytes)?;
    let _pin = PinnedHome::open(paths.dos_root())?;
    open_store(&paths.existing_state_database()?)?.replace_sanitized_avatar(Some(bytes))
}

pub fn approve(paths: &AppPaths, token: &str) -> Result<(), AslError> {
    let _pin = PinnedHome::open(paths.dos_root())?;
    let owner = AgentIdentity::load_protected(&paths.agent_root_key())?.agent_id();
    open_store(&paths.existing_state_database()?)?.approve_avatar_reference(owner, token)
}

pub fn withdraw(paths: &AppPaths) -> Result<(), AslError> {
    let _pin = PinnedHome::open(paths.dos_root())?;
    open_store(&paths.existing_state_database()?)?.withdraw_avatar_reference()
}

fn decode_thumbnail(bytes: &[u8]) -> Result<RgbaImage, AslError> {
    if bytes.is_empty() || bytes.len() > MAX_AVATAR_BYTES {
        return Err(AslError::InvalidMessage);
    }
    let format = image::guess_format(bytes).map_err(|_| AslError::InvalidMessage)?;
    if !matches!(format, ImageFormat::Png | ImageFormat::WebP) {
        return Err(AslError::InvalidMessage);
    }
    let mut reader = ImageReader::with_format(Cursor::new(bytes), format);
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_AVATAR_EDGE);
    limits.max_image_height = Some(MAX_AVATAR_EDGE);
    reader.limits(limits);
    reader
        .decode()
        .map(|decoded| decoded.into_rgba8())
        .map_err(|_| AslError::InvalidMessage)
}
