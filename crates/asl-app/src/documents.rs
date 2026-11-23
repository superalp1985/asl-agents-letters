//! In-memory document transforms for the isolated Extractor child.

use std::{
    fmt,
    io::{self, Cursor, Write},
};

use image::{
    DynamicImage, ImageDecoder, ImageEncoder, ImageFormat, Limits,
    codecs::{png::PngEncoder, webp::WebPEncoder},
};
use pdf_extract::{Document, PlainTextOutput};

use crate::ipc::{ExtractorOperation, MAX_IPC_EXTRACTOR_INPUT_BYTES};

pub const MAX_PDF_PAGES: usize = 500;
pub const MAX_PDF_TEXT_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_AVATAR_INPUT_BYTES: usize = MAX_IPC_EXTRACTOR_INPUT_BYTES;
pub const MAX_AVATAR_BYTES: usize = asl_store::avatar_publication::MAX_IMAGE_BYTES;
pub const MAX_AVATAR_EDGE: u32 = 128;
pub const MAX_AVATAR_PIXELS: u64 = 16_777_216;
const MAX_AVATAR_DIMENSION: u32 = 8_192;
const MAX_AVATAR_DECODE_BYTES: u64 = 64 * 1024 * 1024;

pub(crate) fn process(
    operation: ExtractorOperation,
    input: &[u8],
) -> Result<Vec<u8>, asl_types::error::AslError> {
    match operation {
        ExtractorOperation::PdfText => extract_pdf_text(input).map(String::into_bytes),
        ExtractorOperation::Avatar => reencode_avatar(input),
    }
}

pub fn extract_pdf_text(input: &[u8]) -> Result<String, asl_types::error::AslError> {
    use asl_types::error::AslError;

    if input.len() > MAX_IPC_EXTRACTOR_INPUT_BYTES || !input.starts_with(b"%PDF-") {
        return Err(AslError::InvalidMessage);
    }
    let document = Document::load_mem(input).map_err(|_| AslError::InvalidMessage)?;
    let pages = document.get_pages();
    if pages.is_empty() || pages.len() > MAX_PDF_PAGES {
        return Err(AslError::InvalidMessage);
    }

    let mut output = BoundedOutput::new(MAX_PDF_TEXT_BYTES);
    {
        let mut plain_text = PlainTextOutput::new(&mut output as &mut dyn Write);
        for page in pages.keys().copied() {
            pdf_extract::output_doc_page(&document, &mut plain_text, page)
                .map_err(|_| AslError::InvalidMessage)?;
        }
    }
    String::from_utf8(output.into_bytes()).map_err(|_| AslError::InvalidMessage)
}

pub fn reencode_avatar(input: &[u8]) -> Result<Vec<u8>, asl_types::error::AslError> {
    use asl_types::error::AslError;

    if input.is_empty() || input.len() > MAX_AVATAR_INPUT_BYTES {
        return Err(AslError::InvalidMessage);
    }
    let format = image::guess_format(input).map_err(|_| AslError::InvalidMessage)?;
    if !matches!(
        format,
        ImageFormat::Png | ImageFormat::Jpeg | ImageFormat::WebP
    ) {
        return Err(AslError::InvalidMessage);
    }
    if format == ImageFormat::WebP {
        let decoder = image::codecs::webp::WebPDecoder::new(Cursor::new(input))
            .map_err(|_| AslError::InvalidMessage)?;
        if decoder.has_animation() {
            return Err(AslError::InvalidMessage);
        }
    }

    let reader = image::ImageReader::new(Cursor::new(input))
        .with_guessed_format()
        .map_err(|_| AslError::InvalidMessage)?;
    let mut decoder = reader
        .into_decoder()
        .map_err(|_| AslError::InvalidMessage)?;
    let (width, height) = decoder.dimensions();
    let pixels = u64::from(width)
        .checked_mul(u64::from(height))
        .ok_or(AslError::InvalidMessage)?;
    if width == 0
        || height == 0
        || width > MAX_AVATAR_DIMENSION
        || height > MAX_AVATAR_DIMENSION
        || pixels > MAX_AVATAR_PIXELS
    {
        return Err(AslError::InvalidMessage);
    }
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_AVATAR_DIMENSION);
    limits.max_image_height = Some(MAX_AVATAR_DIMENSION);
    limits.max_alloc = Some(MAX_AVATAR_DECODE_BYTES);
    decoder
        .set_limits(limits)
        .map_err(|_| AslError::InvalidMessage)?;
    let decoded = DynamicImage::from_decoder(decoder).map_err(|_| AslError::InvalidMessage)?;
    let thumbnail = decoded
        .thumbnail(MAX_AVATAR_EDGE, MAX_AVATAR_EDGE)
        .to_rgba8();
    let mut png = Vec::new();
    PngEncoder::new(&mut png)
        .write_image(
            thumbnail.as_raw(),
            thumbnail.width(),
            thumbnail.height(),
            image::ExtendedColorType::Rgba8,
        )
        .map_err(|_| AslError::InvalidMessage)?;
    if png.len() <= MAX_AVATAR_BYTES {
        return Ok(png);
    }

    let mut webp = Vec::new();
    WebPEncoder::new_lossless(&mut webp)
        .write_image(
            thumbnail.as_raw(),
            thumbnail.width(),
            thumbnail.height(),
            image::ExtendedColorType::Rgba8,
        )
        .map_err(|_| AslError::InvalidMessage)?;
    if webp.len() > MAX_AVATAR_BYTES {
        return Err(AslError::InvalidMessage);
    }
    Ok(webp)
}

struct BoundedOutput {
    bytes: Vec<u8>,
    maximum: usize,
}

impl BoundedOutput {
    fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::new(),
            maximum,
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let length = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .filter(|length| *length <= self.maximum)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "PDF output limit"))?;
        self.bytes.reserve(length - self.bytes.len());
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl fmt::Debug for BoundedOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedOutput")
            .field("length", &self.bytes.len())
            .field("maximum", &self.maximum)
            .finish()
    }
}

#[cfg(test)]
pub(crate) fn minimal_pdf() -> Vec<u8> {
    let text_stream = b"BT /F1 18 Tf 20 100 Td (ASL PDF text) Tj ET\n";
    let objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>".to_vec(),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_vec(),
        [
            format!("<< /Length {} >>\nstream\n", text_stream.len()).as_bytes(),
            text_stream,
            b"endstream",
        ]
        .concat(),
    ];
    let mut pdf = b"%PDF-1.4\n".to_vec();
    let mut offsets = Vec::with_capacity(objects.len());
    for (index, object) in objects.iter().enumerate() {
        offsets.push(pdf.len());
        pdf.extend_from_slice(format!("{} 0 obj\n", index + 1).as_bytes());
        pdf.extend_from_slice(object);
        pdf.extend_from_slice(b"\nendobj\n");
    }
    let xref_offset = pdf.len();
    pdf.extend_from_slice(format!("xref\n0 {}\n", objects.len() + 1).as_bytes());
    pdf.extend_from_slice(b"0000000000 65535 f \n");
    for offset in offsets {
        pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    pdf.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    pdf
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageEncoder, RgbaImage};

    fn png(width: u32, height: u32) -> Vec<u8> {
        let image = RgbaImage::from_pixel(width, height, image::Rgba([90, 130, 170, 255]));
        let mut bytes = Vec::new();
        PngEncoder::new(&mut bytes)
            .write_image(
                image.as_raw(),
                width,
                height,
                image::ExtendedColorType::Rgba8,
            )
            .unwrap();
        bytes
    }

    fn rgb_image(format: ImageFormat) -> Vec<u8> {
        let mut bytes = Vec::new();
        match format {
            ImageFormat::Jpeg => image::codecs::jpeg::JpegEncoder::new(&mut bytes)
                .write_image(
                    &vec![90; 32 * 24 * 3],
                    32,
                    24,
                    image::ExtendedColorType::Rgb8,
                )
                .unwrap(),
            ImageFormat::WebP => image::codecs::webp::WebPEncoder::new_lossless(&mut bytes)
                .write_image(
                    &vec![90; 32 * 24 * 4],
                    32,
                    24,
                    image::ExtendedColorType::Rgba8,
                )
                .unwrap(),
            _ => unreachable!(),
        }
        bytes
    }

    #[test]
    fn avatar_is_reencoded_without_metadata_and_scaled_to_the_wire_limit() {
        let sanitized = reencode_avatar(&png(256, 192)).unwrap();
        assert!(sanitized.starts_with(b"\x89PNG\r\n\x1a\n"));
        assert!(sanitized.len() <= MAX_AVATAR_BYTES);
        let decoded = image::load_from_memory(&sanitized).unwrap();
        assert!(decoded.width() <= MAX_AVATAR_EDGE);
        assert!(decoded.height() <= MAX_AVATAR_EDGE);
    }

    #[test]
    fn jpeg_and_static_webp_avatars_are_accepted_and_normalized() {
        for input in [rgb_image(ImageFormat::Jpeg), rgb_image(ImageFormat::WebP)] {
            let sanitized = reencode_avatar(&input).unwrap();
            assert!(sanitized.starts_with(b"\x89PNG\r\n\x1a\n"));
            let decoded = image::load_from_memory(&sanitized).unwrap();
            assert!(decoded.width() <= MAX_AVATAR_EDGE);
            assert!(decoded.height() <= MAX_AVATAR_EDGE);
        }
    }

    #[test]
    fn avatar_rejects_svg_animation_oversized_pixels_and_unknown_formats() {
        for input in [
            b"<svg><script>alert(1)</script></svg>".as_slice(),
            b"GIF89a".as_slice(),
            b"not an image".as_slice(),
        ] {
            assert!(reencode_avatar(input).is_err());
        }
        assert!(reencode_avatar(&png(MAX_AVATAR_DIMENSION + 1, 1)).is_err());
        assert!(reencode_avatar(&vec![0; MAX_AVATAR_INPUT_BYTES + 1]).is_err());
    }

    #[test]
    fn pdf_helper_accepts_only_bounded_pdf_input() {
        assert!(extract_pdf_text(b"not a PDF").is_err());
        assert!(extract_pdf_text(&vec![b'x'; MAX_IPC_EXTRACTOR_INPUT_BYTES + 1]).is_err());
    }

    #[test]
    fn pdf_helper_extracts_text_from_a_valid_document() {
        assert!(
            extract_pdf_text(&minimal_pdf())
                .unwrap()
                .contains("ASL PDF text")
        );
    }

    #[test]
    fn output_writer_never_grows_past_its_limit() {
        let mut output = BoundedOutput::new(3);
        output.write_all(b"abc").unwrap();
        assert!(output.write_all(b"d").is_err());
        assert_eq!(output.bytes, b"abc");
    }
}
