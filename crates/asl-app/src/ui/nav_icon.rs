//! Code-drawn 8x8 pixel icons for the navigation rail.
//!
//! The icons are plain bitmaps rendered with nearest-neighbour sampling, so
//! they stay crisp at 2x and need no extra asset files.

use eframe::egui::{self, ColorImage, TextureHandle, TextureOptions};

use super::views::Page;

const SIZE: usize = 8;

fn pattern(page: Page) -> [&'static str; SIZE] {
    match page {
        Page::Overview => [
            "...##...", "..####..", ".######.", "########", ".#....#.", ".#.##.#.", ".#.##.#.",
            ".######.",
        ],
        Page::Activity => [
            "...##...", "..####..", ".######.", ".######.", ".######.", "########", "........",
            "...##...",
        ],
        Page::Nodes => [
            ".##..##.", ".##..##.", "...##...", "...##...", "..#..#..", ".##..##.", ".##..##.",
            "........",
        ],
        Page::Contacts => [
            "...##...", "..####..", "..####..", "...##...", ".######.", "########", "########",
            "........",
        ],
        Page::Groups => [
            ".##..##.", ".##..##.", "........", "###..###", "########", "########", "........",
            "........",
        ],
        Page::Transfers => [
            "..#.....", ".###....", "#####...", "..#..#..", "..#..#..", "...#####", "....###.",
            ".....#..",
        ],
        Page::Knowledge => [
            "........", ".##..##.", "#..##..#", "#..##..#", "#..##..#", "#..##..#", ".######.",
            "........",
        ],
        Page::Trust => [
            ".######.", "########", "########", "########", ".######.", ".######.", "..####..",
            "...##...",
        ],
        Page::Access => [
            "..####..", ".#....#.", ".#....#.", "########", "########", "###..###", "###..###",
            "########",
        ],
        Page::Migration => [
            "...##...", "..##....", ".######.", "###.##..", "..##.###", ".######.", "....##..",
            "...##...",
        ],
    }
}

fn image(page: Page) -> ColorImage {
    let mut rgba = Vec::with_capacity(SIZE * SIZE * 4);
    for row in pattern(page) {
        for cell in row.bytes() {
            let alpha = if cell == b'#' { 255 } else { 0 };
            rgba.extend_from_slice(&[255, 255, 255, alpha]);
        }
    }
    ColorImage::from_rgba_unmultiplied([SIZE, SIZE], &rgba)
}

/// White pixel icon for `page`; tint it at the call site.
pub(super) fn texture(ctx: &egui::Context, page: Page) -> TextureHandle {
    let id = egui::Id::new(("asl-nav-icon", page));
    if let Some(texture) = ctx.data(|data| data.get_temp::<TextureHandle>(id)) {
        return texture;
    }
    let texture = ctx.load_texture(
        format!("asl-nav-icon-{page:?}"),
        image(page),
        TextureOptions::NEAREST,
    );
    ctx.data_mut(|data| data.insert_temp(id, texture.clone()));
    texture
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_page_has_a_square_non_empty_icon() {
        for page in Page::ALL {
            let rows = pattern(page);
            assert!(rows.iter().all(|row| row.len() == SIZE), "{page:?}");
            assert!(rows.iter().any(|row| row.contains('#')), "{page:?}");
        }
    }
}
