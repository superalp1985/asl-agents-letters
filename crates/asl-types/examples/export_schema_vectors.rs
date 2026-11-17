use std::{env, fmt::Write, fs, path::Path};

#[path = "../tests/common/corpus.rs"]
mod corpus;

use corpus::{
    ACCEPTED_COUNT, CorpusResult, REJECTED_COUNT, VECTOR_COUNT, check_case_counts, check_vectors,
    parse_hex, vector_cases, vector_index,
};

fn write_vectors(directory: &Path) -> CorpusResult<()> {
    let cases = vector_cases();
    check_case_counts(&cases)?;
    for case in &cases {
        case.check_codec(&case.bytes)?;
    }

    // The preexisting ACK file is immutable, including its whitespace and newlines.
    let ack = cases.iter().find(|case| case.name == "ack-v1").unwrap();
    let ack_path = directory.join("ack-v1.hex");
    if parse_hex(&fs::read_to_string(&ack_path)?)? != ack.bytes {
        return Err("refusing to rewrite the frozen ack-v1.hex; restore its original bytes".into());
    }

    for case in &cases {
        if case.name == "ack-v1" {
            continue;
        }
        let mut hex = String::new();
        for row in case.bytes.chunks(16) {
            for (index, byte) in row.iter().enumerate() {
                if index > 0 {
                    hex.push(' ');
                }
                write!(hex, "{byte:02x}")?;
            }
            hex.push('\n');
        }
        fs::write(directory.join(format!("{}.hex", case.name)), hex)?;
    }
    let mut index = serde_json::to_string_pretty(&vector_index(&cases))?;
    index.push('\n');
    fs::write(directory.join("index.json"), index)?;
    Ok(())
}

fn main() -> CorpusResult<()> {
    let arguments: Vec<_> = env::args_os().skip(1).collect();
    let write = match arguments.as_slice() {
        [] => false,
        [argument] if argument == "--check" => false,
        [argument] if argument == "--write" => true,
        _ => {
            return Err(
                "usage: export_schema_vectors [--check | --write] (default: --check)".into(),
            );
        }
    };
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas/vectors");
    if write {
        write_vectors(&directory)?;
    }
    check_vectors(&directory)?;
    println!(
        "{} and checked {VECTOR_COUNT} schema vectors: {ACCEPTED_COUNT} accepted, {REJECTED_COUNT} rejected; signatures are synthetic fixtures",
        if write { "Exported" } else { "Read" },
    );
    Ok(())
}
