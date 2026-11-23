//! Speech bubbles drawn for humans.
//!
//! Agent-to-agent traffic stays on the structured protocol; these bubbles only
//! ever appear on the local screen, explaining a state in the active language.
//! The same width, type size and palette are used for both languages, and the
//! width cap is sized for the longer English lines so neither clips.

use eframe::egui::{self, CornerRadius, Rect, Sense, Stroke, Vec2};

use super::{
    locale::Language,
    tokens::{BG, MUTED, RADIUS_SMALL, TEXT},
};

/// Maximum bubble width. English lines are longer than the Chinese ones, so
/// this budget is shared by both languages instead of per-language sizing.
const MAX_WIDTH: f32 = 320.0;
const PADDING: f32 = 10.0;
/// Horizontal room reserved on the left for the pixel tail.
const TAIL: f32 = 12.0;

fn pick<'a>(language: Language, zh: &'a str, en: &'a str) -> &'a str {
    match language {
        Language::Zh => zh,
        Language::En => en,
    }
}

/// Renders a pixel-style speech bubble whose square tail points left, toward
/// the character drawn beside it.
///
/// Display only: nothing shown in a bubble is ever sent on the network.
pub(super) fn bubble(ui: &mut egui::Ui, language: Language, zh: &str, en: &str) {
    let text = pick(language, zh, en);
    let width = (ui.available_width() - TAIL).clamp(2.0 * PADDING + 1.0, MAX_WIDTH);
    let wrap_width = width - 2.0 * PADDING;
    let font = egui::TextStyle::Body.resolve(ui.style());
    let galley = ui.painter().layout(text.to_owned(), font, TEXT, wrap_width);
    let height = (galley.rect.height() + 2.0 * PADDING).max(36.0);
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width + TAIL, height), Sense::hover());
    let body = Rect::from_min_size(rect.min + Vec2::new(TAIL, 0.0), Vec2::new(width, height));
    let painter = ui.painter();
    let stroke = Stroke::new(2.0, TEXT);
    painter.rect_filled(body, CornerRadius::same(RADIUS_SMALL), BG);
    painter.rect_stroke(
        body,
        CornerRadius::same(RADIUS_SMALL),
        stroke,
        egui::StrokeKind::Inside,
    );
    // The tail is three shrinking axis-aligned squares, so it reads as pixels
    // rather than a smooth pointer.
    let anchor_y = body.min.y + 18.0;
    for (offset, side) in [(4.0_f32, 6.0_f32), (8.0, 4.0), (11.0, 2.0)] {
        let square = Rect::from_center_size(
            egui::pos2(body.min.x - offset + side / 2.0, anchor_y),
            Vec2::splat(side),
        );
        painter.rect_filled(square, CornerRadius::ZERO, TEXT);
    }
    painter.galley(body.min + Vec2::splat(PADDING), galley, TEXT);
}

/// Short quiet caption, wrapping instead of clipping so English fits too.
pub(super) fn caption(ui: &mut egui::Ui, language: Language, zh: &str, en: &str) {
    let text = pick(language, zh, en);
    ui.add(egui::Label::new(egui::RichText::new(text).small().color(MUTED)).wrap());
}
