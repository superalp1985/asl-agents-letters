//! Bounded text extraction for OOXML document packages.

use std::{
    collections::BTreeMap,
    io::{Cursor, Read, Seek},
};

use asl_types::error::AslError;
use quick_xml::{
    XmlVersion,
    events::{BytesStart, Event},
    name::{NamespaceResolver, ResolveResult},
    reader::NsReader,
};
use zip::{ZipArchive, result::ZipError};

use super::MAX_DOCUMENT_TEXT_BYTES;

const MAX_PACKAGE_ENTRIES: usize = 4_096;
const MAX_PACKAGE_METADATA_BYTES: usize = 1024 * 1024;
const MAX_PACKAGE_XML_BYTES: usize = 16 * 1024 * 1024;
const MAX_PACKAGE_TOTAL_XML_BYTES: usize = 64 * 1024 * 1024;

const CONTENT_TYPES_NAMESPACE: &[&[u8]] =
    &[b"http://schemas.openxmlformats.org/package/2006/content-types"];
const PACKAGE_RELATIONSHIP_NAMESPACES: &[&[u8]] =
    &[b"http://schemas.openxmlformats.org/package/2006/relationships"];
const OFFICE_RELATIONSHIP_NAMESPACES: &[&[u8]] = &[
    b"http://schemas.openxmlformats.org/officeDocument/2006/relationships",
    b"http://purl.oclc.org/ooxml/officeDocument/relationships",
];
const WORD_NAMESPACES: &[&[u8]] = &[
    b"http://schemas.openxmlformats.org/wordprocessingml/2006/main",
    b"http://purl.oclc.org/ooxml/wordprocessingml/main",
];
const SPREADSHEET_NAMESPACES: &[&[u8]] = &[
    b"http://schemas.openxmlformats.org/spreadsheetml/2006/main",
    b"http://purl.oclc.org/ooxml/spreadsheetml/main",
];
const PRESENTATION_NAMESPACES: &[&[u8]] = &[
    b"http://schemas.openxmlformats.org/presentationml/2006/main",
    b"http://purl.oclc.org/ooxml/presentationml/main",
];
const DRAWING_NAMESPACES: &[&[u8]] = &[
    b"http://schemas.openxmlformats.org/drawingml/2006/main",
    b"http://purl.oclc.org/ooxml/drawingml/main",
];

const DOCX_CONTENT_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml";
const XLSX_CONTENT_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml";
const PPTX_CONTENT_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OfficeFormat {
    Docx,
    Xlsx,
    Pptx,
}

pub(super) fn detect_format(input: &[u8]) -> Result<OfficeFormat, AslError> {
    let mut archive = open_package(input)?;
    detect_archive_format(&mut archive)
}

pub(super) fn extract_text(input: &[u8]) -> Result<String, AslError> {
    let mut archive = open_package(input)?;
    let format = detect_archive_format(&mut archive)?;
    match format {
        OfficeFormat::Docx => extract_docx(&mut archive),
        OfficeFormat::Xlsx => extract_xlsx(&mut archive),
        OfficeFormat::Pptx => extract_pptx(&mut archive),
    }
}

fn open_package(input: &[u8]) -> Result<ZipArchive<Cursor<&[u8]>>, AslError> {
    if input.is_empty() || !input.starts_with(b"PK\x03\x04") {
        return Err(AslError::InvalidMessage);
    }
    ZipArchive::new(Cursor::new(input)).map_err(|_| AslError::InvalidMessage)
}

fn detect_archive_format<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
) -> Result<OfficeFormat, AslError> {
    validate_package(archive)?;
    let content_types = read_part(archive, "[Content_Types].xml", MAX_PACKAGE_METADATA_BYTES)?;
    let mut reader = xml_reader(&content_types);
    let mut buffer = Vec::new();
    let mut selected = None;

    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .map_err(|_| AslError::InvalidMessage)?;
        match event {
            Event::Start(element) | Event::Empty(element) => {
                if !element_is(&reader, &element, CONTENT_TYPES_NAMESPACE, b"Override") {
                    buffer.clear();
                    continue;
                }
                let part = local_attribute(&element, b"PartName")?;
                let content_type = local_attribute(&element, b"ContentType")?;
                if let (Some(part), Some(content_type)) = (part, content_type) {
                    let lowered = content_type.to_ascii_lowercase();
                    if lowered.contains("macroenabled") || lowered.contains("vbaproject") {
                        return Err(AslError::InvalidMessage);
                    }
                    if let Some(format) = content_type_format(&content_type, &part) {
                        if selected
                            .replace(format)
                            .is_some_and(|previous| previous != format)
                        {
                            return Err(AslError::InvalidMessage);
                        }
                    }
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }

    let format = selected.ok_or(AslError::InvalidMessage)?;
    let main_part = match format {
        OfficeFormat::Docx => "word/document.xml",
        OfficeFormat::Xlsx => "xl/workbook.xml",
        OfficeFormat::Pptx => "ppt/presentation.xml",
    };
    let main = archive
        .by_name(main_part)
        .map_err(|_| AslError::InvalidMessage)?;
    if !main.is_file() || main.encrypted() {
        return Err(AslError::InvalidMessage);
    }
    Ok(format)
}

fn content_type_format(content_type: &str, part: &str) -> Option<OfficeFormat> {
    match (content_type, part) {
        (DOCX_CONTENT_TYPE, "/word/document.xml") => Some(OfficeFormat::Docx),
        (XLSX_CONTENT_TYPE, "/xl/workbook.xml") => Some(OfficeFormat::Xlsx),
        (PPTX_CONTENT_TYPE, "/ppt/presentation.xml") => Some(OfficeFormat::Pptx),
        _ => None,
    }
}

fn validate_package<R: Read + Seek>(archive: &mut ZipArchive<R>) -> Result<(), AslError> {
    let length = archive.len();
    if length == 0 || length > MAX_PACKAGE_ENTRIES {
        return Err(AslError::InvalidMessage);
    }
    for index in 0..length {
        let entry = archive
            .by_index(index)
            .map_err(|_| AslError::InvalidMessage)?;
        if entry.encrypted() || entry.is_symlink() {
            return Err(AslError::InvalidMessage);
        }
        let name = entry.name().map_err(|_| AslError::InvalidMessage)?;
        let lowered = name.to_ascii_lowercase();
        if lowered.ends_with("vbaproject.bin") {
            return Err(AslError::InvalidMessage);
        }
    }
    Ok(())
}

fn read_part<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    name: &str,
    maximum: usize,
) -> Result<Vec<u8>, AslError> {
    let mut entry = archive
        .by_name(name)
        .map_err(|_| AslError::InvalidMessage)?;
    if !entry.is_file() || entry.encrypted() {
        return Err(AslError::InvalidMessage);
    }
    let size = entry.size();
    read_bounded_entry(&mut entry, size, maximum)
}

fn read_optional_part<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    name: &str,
    maximum: usize,
) -> Result<Option<Vec<u8>>, AslError> {
    let mut entry = match archive.by_name(name) {
        Ok(entry) => entry,
        Err(ZipError::FileNotFound) => return Ok(None),
        Err(_) => return Err(AslError::InvalidMessage),
    };
    if !entry.is_file() || entry.encrypted() {
        return Err(AslError::InvalidMessage);
    }
    let size = entry.size();
    read_bounded_entry(&mut entry, size, maximum).map(Some)
}

fn read_bounded_entry<R: Read>(
    entry: &mut R,
    declared_size: u64,
    maximum: usize,
) -> Result<Vec<u8>, AslError> {
    let declared_size = usize::try_from(declared_size).map_err(|_| AslError::InvalidMessage)?;
    if declared_size > maximum {
        return Err(AslError::InvalidMessage);
    }
    let mut bytes = Vec::with_capacity(declared_size);
    entry
        .take((maximum as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| AslError::InvalidMessage)?;
    if bytes.len() > maximum {
        return Err(AslError::InvalidMessage);
    }
    Ok(bytes)
}

fn xml_reader(input: &[u8]) -> NsReader<Cursor<&[u8]>> {
    let mut reader = NsReader::from_reader(Cursor::new(input));
    reader.config_mut().trim_text(false);
    reader
}

fn element_is<R>(
    reader: &NsReader<R>,
    element: &BytesStart<'_>,
    namespaces: &[&[u8]],
    local_name: &[u8],
) -> bool {
    let (namespace, local) = reader.resolver().resolve_element(element.name());
    namespace_is(namespace, namespaces) && local.as_ref() == local_name
}

fn end_element_is<R>(
    reader: &NsReader<R>,
    element: &quick_xml::events::BytesEnd<'_>,
    namespaces: &[&[u8]],
    local_name: &[u8],
) -> bool {
    let (namespace, local) = reader.resolver().resolve_element(element.name());
    namespace_is(namespace, namespaces) && local.as_ref() == local_name
}

fn namespace_is(namespace: ResolveResult<'_>, expected: &[&[u8]]) -> bool {
    match namespace {
        ResolveResult::Bound(namespace) => {
            expected.iter().any(|value| namespace.as_ref() == *value)
        }
        _ => false,
    }
}

fn local_attribute(element: &BytesStart<'_>, name: &[u8]) -> Result<Option<String>, AslError> {
    for attribute in element.attributes().with_checks(false) {
        let attribute = attribute.map_err(|_| AslError::InvalidMessage)?;
        if attribute.key.local_name().as_ref() == name {
            return attribute
                .decoded_and_normalized_value(XmlVersion::Implicit1_0, element.decoder())
                .map(|value| Some(value.into_owned()))
                .map_err(|_| AslError::InvalidMessage);
        }
    }
    Ok(None)
}

fn resolved_attribute(
    resolver: &NamespaceResolver,
    element: &BytesStart<'_>,
    namespaces: &[&[u8]],
    local_name: &[u8],
) -> Result<Option<String>, AslError> {
    for attribute in element.attributes().with_checks(false) {
        let attribute = attribute.map_err(|_| AslError::InvalidMessage)?;
        let (namespace, local) = resolver.resolve_attribute(attribute.key);
        if namespace_is(namespace, namespaces) && local.as_ref() == local_name {
            return attribute
                .decoded_and_normalized_value(XmlVersion::Implicit1_0, element.decoder())
                .map(|value| Some(value.into_owned()))
                .map_err(|_| AslError::InvalidMessage);
        }
    }
    Ok(None)
}

fn append_event_text(event: &Event<'_>, output: &mut TextOutput) -> Result<(), AslError> {
    match event {
        Event::Text(text) => output.push(
            text.xml_content(XmlVersion::Implicit1_0)
                .map_err(|_| AslError::InvalidMessage)?
                .as_ref(),
        ),
        Event::CData(text) => output.push(
            text.xml_content(XmlVersion::Implicit1_0)
                .map_err(|_| AslError::InvalidMessage)?
                .as_ref(),
        ),
        Event::GeneralRef(reference) => {
            if let Some(character) = reference
                .resolve_char_ref()
                .map_err(|_| AslError::InvalidMessage)?
            {
                output.push_char(character)
            } else {
                let named = reference.decode().map_err(|_| AslError::InvalidMessage)?;
                let replacement = match named.as_ref() {
                    "amp" => "&",
                    "apos" => "'",
                    "gt" => ">",
                    "lt" => "<",
                    "quot" => "\"",
                    _ => return Err(AslError::InvalidMessage),
                };
                output.push(replacement)
            }
        }
        _ => Ok(()),
    }
}

fn extract_docx<R: Read + Seek>(archive: &mut ZipArchive<R>) -> Result<String, AslError> {
    let mut budget = MAX_PACKAGE_TOTAL_XML_BYTES;
    let document = read_part(
        archive,
        "word/document.xml",
        budget.min(MAX_PACKAGE_XML_BYTES),
    )?;
    budget = budget.saturating_sub(document.len());
    let mut output = TextOutput::new();
    append_word_part(&document, &mut output)?;
    for part in ["word/footnotes.xml", "word/endnotes.xml"] {
        if let Some(bytes) = read_optional_part(archive, part, budget.min(MAX_PACKAGE_XML_BYTES))? {
            budget = budget.saturating_sub(bytes.len());
            append_word_part(&bytes, &mut output)?;
        }
    }
    output.finish()
}

fn append_word_part(bytes: &[u8], output: &mut TextOutput) -> Result<(), AslError> {
    let mut reader = xml_reader(bytes);
    let mut buffer = Vec::new();
    let mut text_depth = 0usize;

    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .map_err(|_| AslError::InvalidMessage)?;
        match event {
            Event::Start(element) => {
                if element_is(&reader, &element, WORD_NAMESPACES, b"t") {
                    text_depth = text_depth.saturating_add(1);
                } else if element_is(&reader, &element, WORD_NAMESPACES, b"tab") {
                    output.push_char('\t')?;
                } else if element_is(&reader, &element, WORD_NAMESPACES, b"br")
                    || element_is(&reader, &element, WORD_NAMESPACES, b"cr")
                {
                    output.push_char('\n')?;
                } else if element_is(&reader, &element, WORD_NAMESPACES, b"noBreakHyphen") {
                    output.push_char('-')?;
                }
            }
            Event::Empty(element) => {
                if element_is(&reader, &element, WORD_NAMESPACES, b"tab") {
                    output.push_char('\t')?;
                } else if element_is(&reader, &element, WORD_NAMESPACES, b"br")
                    || element_is(&reader, &element, WORD_NAMESPACES, b"cr")
                {
                    output.push_char('\n')?;
                } else if element_is(&reader, &element, WORD_NAMESPACES, b"noBreakHyphen") {
                    output.push_char('-')?;
                }
            }
            Event::End(element) => {
                if end_element_is(&reader, &element, WORD_NAMESPACES, b"t") {
                    text_depth = text_depth.saturating_sub(1);
                } else if end_element_is(&reader, &element, WORD_NAMESPACES, b"p") {
                    output.push_char('\n')?;
                } else if end_element_is(&reader, &element, WORD_NAMESPACES, b"tc") {
                    output.push_char('\t')?;
                }
            }
            Event::Text(_) | Event::CData(_) | Event::GeneralRef(_) if text_depth > 0 => {
                append_event_text(&event, output)?;
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }
    Ok(())
}

fn extract_xlsx<R: Read + Seek>(archive: &mut ZipArchive<R>) -> Result<String, AslError> {
    let mut budget = MAX_PACKAGE_TOTAL_XML_BYTES;
    let shared_strings = match read_optional_part(
        archive,
        "xl/sharedStrings.xml",
        budget.min(MAX_PACKAGE_XML_BYTES),
    )? {
        Some(bytes) => {
            budget = budget.saturating_sub(bytes.len());
            parse_shared_strings(&bytes)?
        }
        None => Vec::new(),
    };
    let sheets = workbook_sheets(archive)?;
    let mut output = TextOutput::new();
    for (name, part) in sheets {
        if !output.is_empty() {
            output.push_char('\n')?;
        }
        output.push("Sheet: ")?;
        output.push(&name)?;
        output.push_char('\n')?;
        let worksheet = read_part(archive, &part, budget.min(MAX_PACKAGE_XML_BYTES))?;
        budget = budget.saturating_sub(worksheet.len());
        append_worksheet(&worksheet, &shared_strings, &mut output)?;
    }
    output.finish()
}

fn parse_shared_strings(bytes: &[u8]) -> Result<Vec<String>, AslError> {
    let mut reader = xml_reader(bytes);
    let mut buffer = Vec::new();
    let mut strings = Vec::new();
    let mut current = String::new();
    let mut item_depth = 0usize;
    let mut phonetic_depth = 0usize;
    let mut text_depth = 0usize;

    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .map_err(|_| AslError::InvalidMessage)?;
        match event {
            Event::Start(element) => {
                if element_is(&reader, &element, SPREADSHEET_NAMESPACES, b"si") {
                    item_depth = item_depth.saturating_add(1);
                    if item_depth == 1 {
                        current.clear();
                    }
                } else if item_depth > 0
                    && element_is(&reader, &element, SPREADSHEET_NAMESPACES, b"rPh")
                {
                    phonetic_depth = phonetic_depth.saturating_add(1);
                } else if item_depth > 0
                    && phonetic_depth == 0
                    && element_is(&reader, &element, SPREADSHEET_NAMESPACES, b"t")
                {
                    text_depth = text_depth.saturating_add(1);
                }
            }
            Event::End(element) => {
                if item_depth > 0 && end_element_is(&reader, &element, SPREADSHEET_NAMESPACES, b"t")
                {
                    text_depth = text_depth.saturating_sub(1);
                } else if item_depth > 0
                    && end_element_is(&reader, &element, SPREADSHEET_NAMESPACES, b"rPh")
                {
                    phonetic_depth = phonetic_depth.saturating_sub(1);
                } else if end_element_is(&reader, &element, SPREADSHEET_NAMESPACES, b"si") {
                    item_depth = item_depth.saturating_sub(1);
                    if item_depth == 0 {
                        strings.push(std::mem::take(&mut current));
                    }
                }
            }
            Event::Text(_) | Event::CData(_) | Event::GeneralRef(_) if text_depth > 0 => {
                append_event_text_to_string(&event, &mut current)?;
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }
    Ok(strings)
}

fn workbook_sheets<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
) -> Result<Vec<(String, String)>, AslError> {
    let workbook = read_part(archive, "xl/workbook.xml", MAX_PACKAGE_XML_BYTES)?;
    let relationships = read_relationships(archive, "xl/workbook.xml", "xl")?;
    let mut reader = xml_reader(&workbook);
    let mut buffer = Vec::new();
    let mut sheet_list_depth = 0usize;
    let mut sheets = Vec::new();

    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .map_err(|_| AslError::InvalidMessage)?;
        match event {
            Event::Start(element) => {
                if element_is(&reader, &element, SPREADSHEET_NAMESPACES, b"sheets") {
                    sheet_list_depth = sheet_list_depth.saturating_add(1);
                } else if sheet_list_depth > 0
                    && element_is(&reader, &element, SPREADSHEET_NAMESPACES, b"sheet")
                {
                    push_workbook_sheet(&reader, &element, &relationships, &mut sheets)?;
                }
            }
            Event::Empty(element) => {
                if sheet_list_depth > 0
                    && element_is(&reader, &element, SPREADSHEET_NAMESPACES, b"sheet")
                {
                    push_workbook_sheet(&reader, &element, &relationships, &mut sheets)?;
                }
            }
            Event::End(element) => {
                if end_element_is(&reader, &element, SPREADSHEET_NAMESPACES, b"sheets") {
                    sheet_list_depth = sheet_list_depth.saturating_sub(1);
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }
    if sheets.is_empty() {
        return Err(AslError::InvalidMessage);
    }
    Ok(sheets)
}

fn push_workbook_sheet(
    reader: &NsReader<Cursor<&[u8]>>,
    element: &BytesStart<'_>,
    relationships: &BTreeMap<String, Relationship>,
    sheets: &mut Vec<(String, String)>,
) -> Result<(), AslError> {
    let name = local_attribute(element, b"name")?.ok_or(AslError::InvalidMessage)?;
    let relationship_id = resolved_attribute(
        reader.resolver(),
        element,
        OFFICE_RELATIONSHIP_NAMESPACES,
        b"id",
    )?
    .ok_or(AslError::InvalidMessage)?;
    let relationship = relationships
        .get(&relationship_id)
        .ok_or(AslError::InvalidMessage)?;
    if !relationship.kind.ends_with("/worksheet") {
        return Err(AslError::InvalidMessage);
    }
    sheets.push((name, relationship.target.clone()));
    Ok(())
}

fn append_worksheet(
    bytes: &[u8],
    shared_strings: &[String],
    output: &mut TextOutput,
) -> Result<(), AslError> {
    let mut reader = xml_reader(bytes);
    let mut buffer = Vec::new();
    let mut in_cell = false;
    let mut cell_type = None;
    let mut cell_text = String::new();
    let mut in_value = false;
    let mut inline_string_depth = 0usize;
    let mut phonetic_depth = 0usize;
    let mut text_depth = 0usize;
    let mut cells_in_row = 0usize;

    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .map_err(|_| AslError::InvalidMessage)?;
        match event {
            Event::Start(element) => {
                if element_is(&reader, &element, SPREADSHEET_NAMESPACES, b"row") {
                    cells_in_row = 0;
                } else if element_is(&reader, &element, SPREADSHEET_NAMESPACES, b"c") {
                    in_cell = true;
                    cell_type = local_attribute(&element, b"t")?;
                    cell_text.clear();
                } else if in_cell && element_is(&reader, &element, SPREADSHEET_NAMESPACES, b"is") {
                    inline_string_depth = inline_string_depth.saturating_add(1);
                } else if in_cell
                    && inline_string_depth > 0
                    && element_is(&reader, &element, SPREADSHEET_NAMESPACES, b"rPh")
                {
                    phonetic_depth = phonetic_depth.saturating_add(1);
                } else if in_cell
                    && inline_string_depth > 0
                    && phonetic_depth == 0
                    && element_is(&reader, &element, SPREADSHEET_NAMESPACES, b"t")
                {
                    text_depth = text_depth.saturating_add(1);
                } else if in_cell && element_is(&reader, &element, SPREADSHEET_NAMESPACES, b"v") {
                    in_value = true;
                }
            }
            Event::Empty(element) => {
                if element_is(&reader, &element, SPREADSHEET_NAMESPACES, b"row") {
                    output.push_char('\n')?;
                    cells_in_row = 0;
                } else if element_is(&reader, &element, SPREADSHEET_NAMESPACES, b"c") {
                    push_cell_separator(output, &mut cells_in_row)?;
                }
            }
            Event::End(element) => {
                if in_cell && end_element_is(&reader, &element, SPREADSHEET_NAMESPACES, b"v") {
                    in_value = false;
                } else if inline_string_depth > 0
                    && end_element_is(&reader, &element, SPREADSHEET_NAMESPACES, b"t")
                {
                    text_depth = text_depth.saturating_sub(1);
                } else if inline_string_depth > 0
                    && end_element_is(&reader, &element, SPREADSHEET_NAMESPACES, b"rPh")
                {
                    phonetic_depth = phonetic_depth.saturating_sub(1);
                } else if inline_string_depth > 0
                    && end_element_is(&reader, &element, SPREADSHEET_NAMESPACES, b"is")
                {
                    inline_string_depth = inline_string_depth.saturating_sub(1);
                } else if in_cell && end_element_is(&reader, &element, SPREADSHEET_NAMESPACES, b"c")
                {
                    push_cell_separator(output, &mut cells_in_row)?;
                    let value =
                        resolve_cell_value(&cell_text, cell_type.as_deref(), shared_strings)?;
                    output.push(&value)?;
                    in_cell = false;
                    cell_type = None;
                    cell_text.clear();
                } else if end_element_is(&reader, &element, SPREADSHEET_NAMESPACES, b"row") {
                    output.push_char('\n')?;
                    cells_in_row = 0;
                }
            }
            Event::Text(_) | Event::CData(_) | Event::GeneralRef(_)
                if in_value || text_depth > 0 =>
            {
                append_event_text_to_string(&event, &mut cell_text)?;
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }
    Ok(())
}

fn push_cell_separator(output: &mut TextOutput, cells_in_row: &mut usize) -> Result<(), AslError> {
    if *cells_in_row > 0 {
        output.push_char('\t')?;
    }
    *cells_in_row = cells_in_row.saturating_add(1);
    Ok(())
}

fn resolve_cell_value(
    value: &str,
    cell_type: Option<&str>,
    shared_strings: &[String],
) -> Result<String, AslError> {
    match cell_type {
        Some("s") => {
            let index = value
                .trim()
                .parse::<usize>()
                .map_err(|_| AslError::InvalidMessage)?;
            shared_strings
                .get(index)
                .cloned()
                .ok_or(AslError::InvalidMessage)
        }
        Some("b") => match value.trim() {
            "1" => Ok("TRUE".to_owned()),
            "0" => Ok("FALSE".to_owned()),
            _ => Err(AslError::InvalidMessage),
        },
        Some("inlineStr") | Some("str") | None => Ok(value.to_owned()),
        Some("e") => Ok(value.to_owned()),
        Some("n") => Ok(value.to_owned()),
        Some(_) => Ok(value.to_owned()),
    }
}

fn extract_pptx<R: Read + Seek>(archive: &mut ZipArchive<R>) -> Result<String, AslError> {
    let slides = presentation_slides(archive)?;
    let mut budget = MAX_PACKAGE_TOTAL_XML_BYTES;
    let mut output = TextOutput::new();
    for (index, part) in slides.into_iter().enumerate() {
        if !output.is_empty() {
            output.push_char('\n')?;
        }
        output.push("Slide ")?;
        output.push(&(index + 1).to_string())?;
        output.push_char('\n')?;
        let slide = read_part(archive, &part, budget.min(MAX_PACKAGE_XML_BYTES))?;
        budget = budget.saturating_sub(slide.len());
        append_slide(&slide, &mut output)?;
    }
    output.finish()
}

fn presentation_slides<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
) -> Result<Vec<String>, AslError> {
    let presentation = read_part(archive, "ppt/presentation.xml", MAX_PACKAGE_XML_BYTES)?;
    let relationships = read_relationships(archive, "ppt/presentation.xml", "ppt")?;
    let mut reader = xml_reader(&presentation);
    let mut buffer = Vec::new();
    let mut slide_list_depth = 0usize;
    let mut slides = Vec::new();

    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .map_err(|_| AslError::InvalidMessage)?;
        match event {
            Event::Start(element) => {
                if element_is(&reader, &element, PRESENTATION_NAMESPACES, b"sldIdLst") {
                    slide_list_depth = slide_list_depth.saturating_add(1);
                } else if slide_list_depth > 0
                    && element_is(&reader, &element, PRESENTATION_NAMESPACES, b"sldId")
                {
                    push_presentation_slide(&reader, &element, &relationships, &mut slides)?;
                }
            }
            Event::Empty(element) => {
                if slide_list_depth > 0
                    && element_is(&reader, &element, PRESENTATION_NAMESPACES, b"sldId")
                {
                    push_presentation_slide(&reader, &element, &relationships, &mut slides)?;
                }
            }
            Event::End(element) => {
                if end_element_is(&reader, &element, PRESENTATION_NAMESPACES, b"sldIdLst") {
                    slide_list_depth = slide_list_depth.saturating_sub(1);
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }
    if slides.is_empty() {
        return Err(AslError::InvalidMessage);
    }
    Ok(slides)
}

fn push_presentation_slide(
    reader: &NsReader<Cursor<&[u8]>>,
    element: &BytesStart<'_>,
    relationships: &BTreeMap<String, Relationship>,
    slides: &mut Vec<String>,
) -> Result<(), AslError> {
    let relationship_id = resolved_attribute(
        reader.resolver(),
        element,
        OFFICE_RELATIONSHIP_NAMESPACES,
        b"id",
    )?
    .ok_or(AslError::InvalidMessage)?;
    let relationship = relationships
        .get(&relationship_id)
        .ok_or(AslError::InvalidMessage)?;
    if !relationship.kind.ends_with("/slide") {
        return Err(AslError::InvalidMessage);
    }
    slides.push(relationship.target.clone());
    Ok(())
}

fn append_slide(bytes: &[u8], output: &mut TextOutput) -> Result<(), AslError> {
    let mut reader = xml_reader(bytes);
    let mut buffer = Vec::new();
    let mut text_depth = 0usize;

    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .map_err(|_| AslError::InvalidMessage)?;
        match event {
            Event::Start(element) => {
                if element_is(&reader, &element, DRAWING_NAMESPACES, b"t") {
                    text_depth = text_depth.saturating_add(1);
                } else if element_is(&reader, &element, DRAWING_NAMESPACES, b"br") {
                    output.push_char('\n')?;
                }
            }
            Event::Empty(element) => {
                if element_is(&reader, &element, DRAWING_NAMESPACES, b"br") {
                    output.push_char('\n')?;
                }
            }
            Event::End(element) => {
                if end_element_is(&reader, &element, DRAWING_NAMESPACES, b"t") {
                    text_depth = text_depth.saturating_sub(1);
                } else if end_element_is(&reader, &element, DRAWING_NAMESPACES, b"p") {
                    output.push_char('\n')?;
                }
            }
            Event::Text(_) | Event::CData(_) | Event::GeneralRef(_) if text_depth > 0 => {
                append_event_text(&event, output)?;
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }
    Ok(())
}

fn append_event_text_to_string(event: &Event<'_>, output: &mut String) -> Result<(), AslError> {
    match event {
        Event::Text(text) => push_string(
            output,
            text.xml_content(XmlVersion::Implicit1_0)
                .map_err(|_| AslError::InvalidMessage)?
                .as_ref(),
        )?,
        Event::CData(text) => push_string(
            output,
            text.xml_content(XmlVersion::Implicit1_0)
                .map_err(|_| AslError::InvalidMessage)?
                .as_ref(),
        )?,
        Event::GeneralRef(reference) => {
            if let Some(character) = reference
                .resolve_char_ref()
                .map_err(|_| AslError::InvalidMessage)?
            {
                push_string_char(output, character)?;
            } else {
                let named = reference.decode().map_err(|_| AslError::InvalidMessage)?;
                let replacement = match named.as_ref() {
                    "amp" => "&",
                    "apos" => "'",
                    "gt" => ">",
                    "lt" => "<",
                    "quot" => "\"",
                    _ => return Err(AslError::InvalidMessage),
                };
                push_string(output, replacement)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn push_string(output: &mut String, value: &str) -> Result<(), AslError> {
    output
        .len()
        .checked_add(value.len())
        .filter(|length| *length <= MAX_DOCUMENT_TEXT_BYTES)
        .ok_or(AslError::InvalidMessage)?;
    output.push_str(value);
    Ok(())
}

fn push_string_char(output: &mut String, value: char) -> Result<(), AslError> {
    let mut encoded = [0; 4];
    push_string(output, value.encode_utf8(&mut encoded))
}

struct Relationship {
    target: String,
    kind: String,
}

fn read_relationships<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    part: &str,
    base: &str,
) -> Result<BTreeMap<String, Relationship>, AslError> {
    let relationships_part = relationship_part(part)?;
    let bytes = read_part(archive, &relationships_part, MAX_PACKAGE_METADATA_BYTES)?;
    let mut reader = xml_reader(&bytes);
    let mut buffer = Vec::new();
    let mut relationships = BTreeMap::new();

    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .map_err(|_| AslError::InvalidMessage)?;
        match event {
            Event::Start(element) | Event::Empty(element) => {
                if !element_is(
                    &reader,
                    &element,
                    PACKAGE_RELATIONSHIP_NAMESPACES,
                    b"Relationship",
                ) {
                    buffer.clear();
                    continue;
                }
                let Some(id) = local_attribute(&element, b"Id")? else {
                    buffer.clear();
                    continue;
                };
                let Some(target) = local_attribute(&element, b"Target")? else {
                    buffer.clear();
                    continue;
                };
                let kind = local_attribute(&element, b"Type")?.unwrap_or_default();
                let external = local_attribute(&element, b"TargetMode")?
                    .is_some_and(|mode| mode.eq_ignore_ascii_case("external"));
                if !external {
                    let target = resolve_package_target(base, &target)?;
                    if relationships
                        .insert(id, Relationship { target, kind })
                        .is_some()
                    {
                        return Err(AslError::InvalidMessage);
                    }
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }
    Ok(relationships)
}

fn relationship_part(part: &str) -> Result<String, AslError> {
    let (directory, file) = part.rsplit_once('/').ok_or(AslError::InvalidMessage)?;
    Ok(format!("{directory}/_rels/{file}.rels"))
}

fn resolve_package_target(base: &str, target: &str) -> Result<String, AslError> {
    if target.is_empty() || target.contains('\\') || target.contains("://") {
        return Err(AslError::InvalidMessage);
    }
    let mut components = Vec::new();
    if !target.starts_with('/') {
        for component in base.split('/').filter(|value| !value.is_empty()) {
            components.push(component);
        }
    }
    for component in target.trim_start_matches('/').split('/') {
        match component {
            "" | "." => {}
            ".." => return Err(AslError::InvalidMessage),
            value => components.push(value),
        }
    }
    if components.is_empty() {
        return Err(AslError::InvalidMessage);
    }
    Ok(components.join("/"))
}

struct TextOutput {
    bytes: Vec<u8>,
    maximum: usize,
}

impl TextOutput {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            maximum: MAX_DOCUMENT_TEXT_BYTES,
        }
    }

    fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    fn push(&mut self, value: &str) -> Result<(), AslError> {
        let length = self
            .bytes
            .len()
            .checked_add(value.len())
            .filter(|length| *length <= self.maximum)
            .ok_or(AslError::InvalidMessage)?;
        self.bytes.reserve(length - self.bytes.len());
        self.bytes.extend_from_slice(value.as_bytes());
        Ok(())
    }

    fn push_char(&mut self, value: char) -> Result<(), AslError> {
        let mut encoded = [0; 4];
        self.push(value.encode_utf8(&mut encoded))
    }

    fn finish(self) -> Result<String, AslError> {
        String::from_utf8(self.bytes).map_err(|_| AslError::InvalidMessage)
    }
}
