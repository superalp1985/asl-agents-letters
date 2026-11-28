use std::{path::Path, str};

use asl_policy::{AuthorizedFile, snapshot_files::StagedSnapshot};
use asl_types::{
    error::AslError,
    protocol::{ConceptRef, MAX_SEMANTIC_CONTEXT_BUNDLE_BYTES},
};

use crate::search::{LocalIndexText, PreparedIndex};

use super::DocumentTextExtractor;

const MAX_TITLE_CHARS: usize = 160;
const MAX_BODY_BYTES: usize = 32768;
const TEXT_EXTENSIONS: &[&str] = &[
    "md", "markdown", "txt", "rs", "toml", "json", "csv", "yaml", "yml", "log",
];

pub(super) fn copy_and_prepare(
    home: &Path,
    source: &mut AuthorizedFile,
    relative: &Path,
    capture_context: bool,
    document_extractor: Option<&dyn DocumentTextExtractor>,
    progress: impl FnMut() -> Result<(), AslError>,
) -> Result<(StagedSnapshot, PreparedIndex, Option<Vec<u8>>), AslError> {
    let basename = relative
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or(AslError::NotFound)?;
    let title: String = basename.chars().take(MAX_TITLE_CHARS).collect();
    let extension = relative.extension().and_then(|s| s.to_str());
    let text = extension.is_some_and(|ext| {
        TEXT_EXTENSIONS
            .iter()
            .any(|allowed| ext.eq_ignore_ascii_case(allowed))
    });
    let mut body = String::new();
    let mut first_chunk = true;
    let extract_document = document_extractor.filter(|extractor| {
        !text
            && source.len() <= extractor.max_input_bytes()
            && extractor.supports(relative, source.len())
    });
    let mut document_bytes = extract_document.map(|_| Vec::new());
    let mut context_bytes = (capture_context
        && (1..=MAX_SEMANTIC_CONTEXT_BUNDLE_BYTES as u64).contains(&source.len()))
    .then(Vec::new);
    let staged = StagedSnapshot::copy_from_observing_chunks(home, source, progress, |chunk| {
        if first_chunk && text {
            body.push_str(text_prefix(chunk));
        }
        first_chunk = false;
        if let Some(bytes) = document_bytes.as_mut() {
            bytes.extend_from_slice(chunk);
        }
        if let Some(bytes) = context_bytes.as_mut() {
            bytes.extend_from_slice(chunk);
        }
    })?;
    if body.is_empty()
        && let (Some(extractor), Some(bytes)) = (extract_document, document_bytes.as_deref())
        && let Some(extracted) = extractor.extract(bytes)?
    {
        body.push_str(utf8_prefix(&extracted));
    }
    let index = PreparedIndex::new(LocalIndexText {
        title: &title,
        summary: "",
        body: &body,
        concepts: if extension.is_some_and(|ext| ext.eq_ignore_ascii_case("rs")) {
            &[ConceptRef::RUST]
        } else {
            &[]
        },
    })?;
    Ok((staged, index, context_bytes))
}

fn utf8_prefix(text: &str) -> &str {
    if text.len() <= MAX_BODY_BYTES {
        return text;
    }
    let mut end = MAX_BODY_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn text_prefix(chunk: &[u8]) -> &str {
    let prefix = &chunk[..chunk.len().min(MAX_BODY_BYTES)];
    if prefix.starts_with(b"%PDF-") {
        return "";
    }
    let text = match str::from_utf8(prefix) {
        Ok(text) => text,
        // Ignore an unfinished character only at our cap, never at EOF.
        Err(e) if chunk.len() > prefix.len() && e.error_len().is_none() => {
            str::from_utf8(&prefix[..e.valid_up_to()]).expect("validated UTF-8 prefix")
        }
        Err(_) => return "",
    };
    if text
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\t' | '\n' | '\r'))
    {
        ""
    } else {
        text
    }
}
