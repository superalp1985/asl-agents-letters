//! Offline QR rendering for desktop-only identity and invitation surfaces.

use std::fmt;

use eframe::egui::{self, Color32, Rect, Sense, Vec2};
use qrcodegen::{QrCode, QrCodeEcc};

const QUIET_ZONE_MODULES: usize = 4;

#[derive(Clone, Debug, PartialEq)]
pub(super) enum Error {
    EmptyPayload,
    PayloadTooLong { bytes: usize },
    InvalidSize { size: f32 },
    TooSmall { size: f32, minimum: f32 },
    InvalidMatrix,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPayload => write!(formatter, "QR payload cannot be empty"),
            Self::PayloadTooLong { bytes } => write!(
                formatter,
                "QR payload is too long ({bytes} bytes); use a shorter identity or invitation URI"
            ),
            Self::InvalidSize { size } => {
                write!(formatter, "QR size must be finite and positive, got {size}")
            }
            Self::TooSmall { size, minimum } => write!(
                formatter,
                "QR size {size} is too small; at least {minimum} points are required"
            ),
            Self::InvalidMatrix => write!(formatter, "QR generator returned an invalid matrix"),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Matrix {
    size: usize,
    modules: Vec<bool>,
}

impl Matrix {
    fn encode(payload: &str) -> Result<Self, Error> {
        if payload.is_empty() {
            return Err(Error::EmptyPayload);
        }
        let code =
            QrCode::encode_text(payload, QrCodeEcc::Medium).map_err(|_| Error::PayloadTooLong {
                bytes: payload.len(),
            })?;
        let size = usize::try_from(code.size()).map_err(|_| Error::InvalidMatrix)?;
        let capacity = size.checked_mul(size).ok_or(Error::InvalidMatrix)?;
        let mut modules = Vec::with_capacity(capacity);
        for y in 0..size {
            let y = i32::try_from(y).map_err(|_| Error::InvalidMatrix)?;
            for x in 0..size {
                let x = i32::try_from(x).map_err(|_| Error::InvalidMatrix)?;
                modules.push(code.get_module(x, y));
            }
        }
        if modules.len() != capacity || !modules.iter().any(|module| *module) {
            return Err(Error::InvalidMatrix);
        }
        Ok(Self { size, modules })
    }

    fn get(&self, x: usize, y: usize) -> bool {
        x < self.size
            && y < self.size
            && self
                .modules
                .get(y * self.size + x)
                .copied()
                .unwrap_or(false)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct Layout {
    module_pixels: f32,
    total_modules: usize,
    symbol_pixels: f32,
    quiet_zone_pixels: f32,
    rendered_pixels: f32,
}

impl Layout {
    fn new(matrix_modules: usize, requested_size: f32) -> Result<Self, Error> {
        if !requested_size.is_finite() || requested_size <= 0.0 {
            return Err(Error::InvalidSize {
                size: requested_size,
            });
        }
        let total_modules = matrix_modules
            .checked_add(QUIET_ZONE_MODULES * 2)
            .ok_or(Error::InvalidMatrix)?;
        let module_pixels = (requested_size / total_modules as f32).floor();
        if module_pixels < 1.0 {
            return Err(Error::TooSmall {
                size: requested_size,
                minimum: total_modules as f32,
            });
        }
        let quiet_zone_pixels = module_pixels * QUIET_ZONE_MODULES as f32;
        let symbol_pixels = module_pixels * matrix_modules as f32;
        Ok(Self {
            module_pixels,
            total_modules,
            symbol_pixels,
            quiet_zone_pixels,
            rendered_pixels: symbol_pixels + quiet_zone_pixels * 2.0,
        })
    }
}

/// Draws a crisp black-and-white QR symbol with the required four-module quiet
/// zone. The requested size includes that quiet zone; unused space remains white.
///
// The component is intentionally independent from contact/invitation state.
#[allow(dead_code)]
pub(super) fn show(ui: &mut egui::Ui, payload: &str, size: f32) -> Result<(), Error> {
    let matrix = Matrix::encode(payload)?;
    let layout = Layout::new(matrix.size, size)?;
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, egui::CornerRadius::ZERO, Color32::WHITE);

    let origin = rect.min
        + Vec2::splat(
            ((rect.width() - layout.rendered_pixels) / 2.0)
                .floor()
                .max(0.0),
        )
        + Vec2::splat(layout.quiet_zone_pixels);
    let mut mesh = egui::Mesh::default();
    for y in 0..matrix.size {
        for x in 0..matrix.size {
            if !matrix.get(x, y) {
                continue;
            }
            let min = origin
                + Vec2::new(
                    x as f32 * layout.module_pixels,
                    y as f32 * layout.module_pixels,
                );
            mesh.add_colored_rect(
                Rect::from_min_size(min, Vec2::splat(layout.module_pixels)),
                Color32::BLACK,
            );
        }
    }
    painter.add(egui::Shape::mesh(mesh));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_payload_produces_a_non_empty_matrix() {
        let matrix =
            Matrix::encode("asl://agent/12D3KooWJ1jPzo4GNd8Zh66dhmDUfPHEjkzurJzMy5ws5bWGV4kS")
                .unwrap();

        assert!(matrix.size >= 21);
        assert_eq!(matrix.modules.len(), matrix.size * matrix.size);
        assert!(matrix.modules.iter().any(|module| *module));
    }

    #[test]
    fn oversized_payload_returns_a_clear_error_without_panicking() {
        let payload = "x".repeat(4096);
        let error = Matrix::encode(&payload).unwrap_err();

        assert_eq!(error, Error::PayloadTooLong { bytes: 4096 });
        assert!(error.to_string().contains("too long"));
        assert!(error.to_string().contains("4096 bytes"));
    }

    #[test]
    fn layout_keeps_an_exact_four_module_quiet_zone() {
        let layout = Layout::new(21, 145.0).unwrap();

        assert_eq!(layout.total_modules, 29);
        assert_eq!(layout.module_pixels, 5.0);
        assert_eq!(layout.symbol_pixels, 105.0);
        assert_eq!(layout.quiet_zone_pixels, 20.0);
        assert_eq!(layout.rendered_pixels, 145.0);
        assert!(layout.rendered_pixels <= 145.0);
    }

    #[test]
    fn undersized_or_non_finite_layouts_are_rejected() {
        assert!(matches!(
            Layout::new(21, 28.9),
            Err(Error::TooSmall {
                size: 28.9,
                minimum: 29.0
            })
        ));
        assert!(matches!(
            Layout::new(21, f32::NAN),
            Err(Error::InvalidSize { size }) if size.is_nan()
        ));
    }
}
