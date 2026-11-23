//! Shared visual tokens for the desktop interface.
//!
//! Palette: soft teal, deep ink and warm off-white, with a small amount of
//! coral for warnings. Corner radii never exceed 8 px.

use eframe::egui::{Color32, CornerRadius, Stroke};

/// Window and page background.
pub(super) const BG: Color32 = Color32::from_rgb(250, 249, 244);
/// Panels, cards and modal surfaces.
pub(super) const SURFACE: Color32 = Color32::from_rgb(252, 253, 252);
/// Navigation rail background.
pub(super) const NAV_BG: Color32 = Color32::from_rgb(234, 243, 240);
/// Primary text (deep ink).
pub(super) const TEXT: Color32 = Color32::from_rgb(33, 43, 49);
/// Secondary and weak text.
pub(super) const MUTED: Color32 = Color32::from_rgb(84, 100, 104);
/// Accent teal used for selection, links and confirmations.
pub(super) const ACCENT: Color32 = Color32::from_rgb(18, 99, 90);
/// Soft accent fill for selected rows and tabs.
pub(super) const ACCENT_SOFT: Color32 = Color32::from_rgb(205, 234, 226);
/// Errors and destructive actions.
pub(super) const DANGER: Color32 = Color32::from_rgb(160, 58, 40);
pub(super) const DANGER_SOFT: Color32 = Color32::from_rgb(250, 230, 224);
/// Completed and healthy states.
pub(super) const SUCCESS: Color32 = Color32::from_rgb(36, 122, 72);
pub(super) const SUCCESS_SOFT: Color32 = Color32::from_rgb(225, 242, 230);
/// Coral, reserved for pending / waiting states.
pub(super) const WARNING: Color32 = Color32::from_rgb(214, 120, 64);
pub(super) const WARNING_SOFT: Color32 = Color32::from_rgb(253, 236, 220);
/// Outlines and dividers.
pub(super) const BORDER: Color32 = Color32::from_rgb(214, 224, 221);
pub(super) const DIVIDER: Color32 = Color32::from_rgb(230, 236, 234);

/// Button states.
pub(super) const BUTTON: Color32 = Color32::from_rgb(241, 247, 245);
pub(super) const BUTTON_HOVER: Color32 = Color32::from_rgb(222, 239, 233);
pub(super) const BUTTON_PRESSED: Color32 = Color32::from_rgb(197, 231, 222);

/// Avatar container fill.
pub(super) const AVATAR_BG: Color32 = Color32::from_rgb(232, 244, 240);

/// Maximum corner radius for any surface.
pub(super) const RADIUS: u8 = 8;
/// Smaller radius for buttons and inputs.
pub(super) const RADIUS_SMALL: u8 = 6;

pub(super) fn radius() -> CornerRadius {
    CornerRadius::same(RADIUS)
}

pub(super) fn radius_small() -> CornerRadius {
    CornerRadius::same(RADIUS_SMALL)
}

pub(super) fn border() -> Stroke {
    Stroke::new(1.0, BORDER)
}

/// Kind of inline banner shown below a page heading.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Tone {
    Info,
    Success,
    Warning,
    Danger,
}

impl Tone {
    pub(super) fn colors(self) -> (Color32, Color32) {
        match self {
            Self::Info => (ACCENT_SOFT, ACCENT),
            Self::Success => (SUCCESS_SOFT, SUCCESS),
            Self::Warning => (WARNING_SOFT, WARNING),
            Self::Danger => (DANGER_SOFT, DANGER),
        }
    }
}

// Design limit: corner radii never exceed 8 px (checked at compile time).
const _: () = assert!(RADIUS <= 8 && RADIUS_SMALL <= RADIUS);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tones_use_distinct_foregrounds() {
        let tones = [Tone::Info, Tone::Success, Tone::Warning, Tone::Danger];
        for (index, left) in tones.iter().enumerate() {
            for right in &tones[index + 1..] {
                assert_ne!(left.colors().1, right.colors().1);
            }
        }
    }
}
