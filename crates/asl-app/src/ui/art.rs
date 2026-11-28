use eframe::egui::{self, ColorImage, IconData, TextureHandle, TextureOptions};

const ICON_256: &[u8] = include_bytes!("../../assets/icons/asl-icon-256.png");
const MASCOT_IDLE_256: &[u8] = include_bytes!("../../assets/mascot/mascot-idle-256.png");
#[cfg(any(windows, target_os = "linux"))]
const TRAY_PNG: &[u8] = include_bytes!("../../assets/icons/asl-icon-32.png");
#[cfg(any(windows, target_os = "linux"))]
#[repr(align(4))]
struct AlignedTrayPng([u8; TRAY_PNG.len()]);
#[cfg(any(windows, target_os = "linux"))]
static TRAY_ICON: AlignedTrayPng =
    AlignedTrayPng(*include_bytes!("../../assets/icons/asl-icon-32.png"));

#[cfg(any(windows, target_os = "linux"))]
#[cfg_attr(target_os = "linux", allow(dead_code))]
pub(super) fn tray_icon() -> &'static [u8] {
    &TRAY_ICON.0
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub(super) enum Mood {
    Idle,
    Message,
    Transfer,
    Waiting,
    Done,
    Warning,
}

impl Mood {
    fn bytes(self) -> &'static [u8] {
        match self {
            Self::Idle => MASCOT_IDLE_256,
            Self::Message => include_bytes!("../../assets/mascot/mascot-message-128.png"),
            Self::Transfer => include_bytes!("../../assets/mascot/mascot-transfer-128.png"),
            Self::Waiting => include_bytes!("../../assets/mascot/mascot-waiting-128.png"),
            Self::Done => include_bytes!("../../assets/mascot/mascot-done-128.png"),
            Self::Warning => include_bytes!("../../assets/mascot/mascot-warning-128.png"),
        }
    }
}

/// One explainer scene: a distinct character acting out one ASL state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub(super) enum Scene {
    Idle,
    Message,
    Transfer,
    Waiting,
    Done,
    Warning,
    Browse,
    Silent,
    Answer,
}

/// Frames per explainer scene.
pub(super) const SCENE_FRAMES: usize = 4;

macro_rules! scene_frames {
    ($name:literal) => {
        [
            include_bytes!(concat!("../../assets/mascot/anim-", $name, "-0-128.png")),
            include_bytes!(concat!("../../assets/mascot/anim-", $name, "-1-128.png")),
            include_bytes!(concat!("../../assets/mascot/anim-", $name, "-2-128.png")),
            include_bytes!(concat!("../../assets/mascot/anim-", $name, "-3-128.png")),
        ]
    };
}

impl Scene {
    pub(super) const ALL: [Self; 9] = [
        Self::Idle,
        Self::Message,
        Self::Transfer,
        Self::Waiting,
        Self::Done,
        Self::Warning,
        Self::Browse,
        Self::Silent,
        Self::Answer,
    ];

    fn frames(self) -> [&'static [u8]; SCENE_FRAMES] {
        match self {
            Self::Idle => scene_frames!("idle"),
            Self::Message => scene_frames!("message"),
            Self::Transfer => scene_frames!("transfer"),
            Self::Waiting => scene_frames!("waiting"),
            Self::Done => scene_frames!("done"),
            Self::Warning => scene_frames!("warning"),
            Self::Browse => scene_frames!("browse"),
            Self::Silent => scene_frames!("silent"),
            Self::Answer => scene_frames!("answer"),
        }
    }
}

/// Small pixel glyphs for empty, mode and identity states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Glyph {
    EmptyNode,
    EmptyContacts,
    EmptyGroup,
    TransferComplete,
    AwaitingApproval,
    IdentityAnonymous,
    IdentityPublic,
    BrowseOnly,
    NoAnswer,
    NetworkOffline,
}

impl Glyph {
    #[cfg(test)]
    const ALL: [Self; 10] = [
        Self::EmptyNode,
        Self::EmptyContacts,
        Self::EmptyGroup,
        Self::TransferComplete,
        Self::AwaitingApproval,
        Self::IdentityAnonymous,
        Self::IdentityPublic,
        Self::BrowseOnly,
        Self::NoAnswer,
        Self::NetworkOffline,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::EmptyNode => "empty-node",
            Self::EmptyContacts => "empty-contacts",
            Self::EmptyGroup => "empty-group",
            Self::TransferComplete => "transfer-complete",
            Self::AwaitingApproval => "awaiting-approval",
            Self::IdentityAnonymous => "identity-anonymous",
            Self::IdentityPublic => "identity-public",
            Self::BrowseOnly => "mode-browse-only",
            Self::NoAnswer => "mode-no-answer",
            Self::NetworkOffline => "network-offline",
        }
    }

    fn bytes(self) -> &'static [u8] {
        match self {
            Self::EmptyNode => include_bytes!("../../assets/states/empty-node-64.png"),
            Self::EmptyContacts => include_bytes!("../../assets/states/empty-contacts-64.png"),
            Self::EmptyGroup => include_bytes!("../../assets/states/empty-group-64.png"),
            Self::TransferComplete => {
                include_bytes!("../../assets/states/transfer-complete-64.png")
            }
            Self::AwaitingApproval => {
                include_bytes!("../../assets/states/awaiting-approval-64.png")
            }
            Self::IdentityAnonymous => {
                include_bytes!("../../assets/states/identity-anonymous-64.png")
            }
            Self::IdentityPublic => include_bytes!("../../assets/states/identity-public-64.png"),
            Self::BrowseOnly => include_bytes!("../../assets/states/mode-browse-only-64.png"),
            Self::NoAnswer => include_bytes!("../../assets/states/mode-no-answer-64.png"),
            Self::NetworkOffline => include_bytes!("../../assets/states/network-offline-64.png"),
        }
    }
}

fn png(bytes: &[u8]) -> ColorImage {
    let rgba = image::load_from_memory(bytes)
        .expect("compiled art is valid PNG")
        .to_rgba8();
    ColorImage::from_rgba_unmultiplied(
        [rgba.width() as usize, rgba.height() as usize],
        rgba.as_raw(),
    )
}

pub(super) fn icon() -> IconData {
    let rgba = image::load_from_memory(ICON_256)
        .expect("compiled icon is valid PNG")
        .to_rgba8();
    IconData {
        width: rgba.width(),
        height: rgba.height(),
        rgba: rgba.into_raw(),
    }
}

pub(super) fn mascot() -> ColorImage {
    png(MASCOT_IDLE_256)
}

/// Returns a cached NEAREST-filtered texture for a state glyph.
pub(super) fn glyph(ctx: &egui::Context, kind: Glyph) -> TextureHandle {
    texture(ctx, "asl-glyph", kind.name(), kind.bytes())
}

pub(super) fn preset(ctx: &egui::Context, index: usize) -> TextureHandle {
    texture(
        ctx,
        "asl-avatar",
        index,
        asl_app::avatar::presets::PNGS[index],
    )
}

pub(super) fn mascot_state(ctx: &egui::Context, mood: Mood) -> TextureHandle {
    texture(ctx, "asl-mascot-state", mood, mood.bytes())
}

pub(super) fn scene_frame(ctx: &egui::Context, scene: Scene, index: usize) -> TextureHandle {
    let index = index % SCENE_FRAMES;
    texture(
        ctx,
        "asl-explainer-scene",
        (scene, index),
        scene.frames()[index],
    )
}

fn texture(
    ctx: &egui::Context,
    namespace: &'static str,
    key: impl std::hash::Hash + std::fmt::Debug,
    bytes: &[u8],
) -> TextureHandle {
    let id = egui::Id::new((namespace, key));
    if let Some(texture) = ctx.data(|data| data.get_temp::<TextureHandle>(id)) {
        return texture;
    }
    let texture = ctx.load_texture(namespace, png(bytes), TextureOptions::NEAREST);
    ctx.data_mut(|data| data.insert_temp(id, texture.clone()));
    texture
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiled_art_decodes_at_expected_sizes() {
        assert_eq!(icon().width, 256);
        assert_eq!(mascot().size, [256, 256]);
        for kind in Glyph::ALL {
            assert_eq!(png(kind.bytes()).size, [64, 64], "{}", kind.name());
        }
        for mood in [
            Mood::Message,
            Mood::Transfer,
            Mood::Waiting,
            Mood::Done,
            Mood::Warning,
        ] {
            assert_eq!(png(mood.bytes()).size, [128, 128]);
        }
        for scene in Scene::ALL {
            for bytes in scene.frames() {
                assert_eq!(png(bytes).size, [128, 128], "{scene:?}");
            }
        }
        assert_eq!(asl_app::avatar::presets::PNGS.len(), 12);
        for bytes in asl_app::avatar::presets::PNGS {
            assert_eq!(png(bytes).size, [128, 128]);
        }
    }
}
