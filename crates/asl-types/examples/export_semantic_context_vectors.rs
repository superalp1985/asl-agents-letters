use std::{
    env,
    error::Error,
    fmt::Write,
    fs,
    io::Write as IoWrite,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use asl_types::{
    ids::{AgentId, Signature65},
    protocol::{
        Expression, SemanticConceptDefinition, SemanticConformanceVector, SemanticContextBundle,
        SignedSemanticContextBundle,
    },
};
use cbor2::{Value, value::Integer};
use serde_json::{Value as Json, json};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn sample_bundle() -> SemanticContextBundle {
    let authority = AgentId([0x11; 32]);
    let expression = Expression::from_json(&json!([
        "meaning_is",
        [
            "concept",
            "1111111111111111111111111111111111111111111111111111111111111111",
            4,
            1,
            7
        ],
        1,
        ["op", "gt", ["var", 0], ["int", "0"]]
    ]))
    .unwrap();
    SemanticContextBundle {
        authority,
        namespace: 4,
        revision: 1,
        kernel_revision: 1,
        dependencies: Vec::new(),
        concepts: vec![SemanticConceptDefinition {
            concept_id: 7,
            arity: 1,
            definition: expression,
        }],
        vectors: vec![SemanticConformanceVector {
            concept_id: 7,
            case_id: 1,
            inputs: vec![Expression::from_json(&json!(["int", "2"])).unwrap()],
            expected: Expression::from_json(&json!(["bool", true])).unwrap(),
        }],
    }
}

fn vector_cases() -> Vec<(&'static str, bool, Vec<u8>)> {
    let signed = SignedSemanticContextBundle {
        bundle: sample_bundle(),
        signature: Signature65([0; 65]),
    };
    let accepted = signed.encode().unwrap();
    let mut cases = vec![("context-file-v1", true, accepted.clone())];

    let mut unknown_version: Value = cbor2::from_slice(&accepted).unwrap();
    set_field(&mut unknown_version, 0, Value::Integer(Integer::from(2)));
    cases.push((
        "context-file-unknown-version",
        false,
        cbor2::to_canonical_vec(&unknown_version).unwrap(),
    ));

    let mut unknown_bundle_version: Value = cbor2::from_slice(&accepted).unwrap();
    let Value::Map(fields) = &mut unknown_bundle_version else {
        panic!("context package root must be a map");
    };
    let bundle_key = Value::Integer(Integer::from(1));
    let bundle = &mut fields
        .iter_mut()
        .find(|(key, _)| *key == bundle_key)
        .unwrap()
        .1;
    set_field(bundle, 0, Value::Integer(Integer::from(2)));
    cases.push((
        "context-bundle-unknown-version",
        false,
        cbor2::to_canonical_vec(&unknown_bundle_version).unwrap(),
    ));

    let mut bad_signature_length: Value = cbor2::from_slice(&accepted).unwrap();
    set_field(&mut bad_signature_length, 2, Value::Bytes(vec![0; 64]));
    cases.push((
        "context-file-bad-signature-length",
        false,
        cbor2::to_canonical_vec(&bad_signature_length).unwrap(),
    ));

    let mut missing_signature: Value = cbor2::from_slice(&accepted).unwrap();
    let Value::Map(fields) = &mut missing_signature else {
        panic!("context package root must be a map");
    };
    let signature_key = Value::Integer(Integer::from(2));
    fields.retain(|(key, _)| *key != signature_key);
    cases.push((
        "context-file-missing-signature",
        false,
        cbor2::to_canonical_vec(&missing_signature).unwrap(),
    ));
    cases
}

fn set_field(root: &mut Value, field: u64, replacement: Value) {
    let Value::Map(fields) = root else {
        panic!("context package root must be a map");
    };
    let target_key = Value::Integer(Integer::from(field));
    let (_, value) = fields
        .iter_mut()
        .find(|(key, _)| *key == target_key)
        .unwrap();
    *value = replacement;
}

fn hex(bytes: &[u8]) -> String {
    let mut text = String::new();
    for row in bytes.chunks(16) {
        for (index, byte) in row.iter().enumerate() {
            if index > 0 {
                text.push(' ');
            }
            write!(text, "{byte:02x}").unwrap();
        }
        text.push('\n');
    }
    text
}

fn parse_hex(text: &str) -> Result<Vec<u8>> {
    let digits = text.chars().filter(|character| !character.is_whitespace());
    let digits: Vec<_> = digits.collect();
    let (pairs, remainder) = digits.as_chunks::<2>();
    if !remainder.is_empty() {
        return Err("hex vector has an odd number of digits".into());
    }
    pairs
        .iter()
        .map(|pair| {
            let pair = pair.iter().collect::<String>();
            Ok(u8::from_str_radix(&pair, 16)?)
        })
        .collect()
}

fn check_vectors(directory: &Path) -> Result<()> {
    let cases = vector_cases();
    let index: Json = serde_json::from_slice(&fs::read(directory.join("index.json"))?)?;
    if index["version"] != 1 || index["vectors"].as_array().map(Vec::len) != Some(cases.len()) {
        return Err("semantic context vector index has an unexpected shape".into());
    }
    for (case, indexed) in cases.iter().zip(index["vectors"].as_array().unwrap()) {
        let (name, accepted, expected) = case;
        if indexed["name"] != *name
            || indexed["root"] != "semantic-context-file"
            || indexed["codec"] != "file"
            || indexed["accepted"] != *accepted
        {
            return Err(format!("semantic context vector index mismatch: {name}").into());
        }
        let actual = parse_hex(&fs::read_to_string(directory.join(format!("{name}.hex")))?)?;
        if &actual != expected {
            return Err(format!("semantic context vector bytes changed: {name}").into());
        }
    }
    Ok(())
}

fn validate_cddl(directory: &Path, schema: &Path, tool: &Path) -> Result<()> {
    let version = Command::new(tool).arg("--version").output()?;
    if !version.status.success() || String::from_utf8_lossy(&version.stdout).trim() != "cddl 0.10.7"
    {
        return Err("expected cddl 0.10.7".into());
    }
    let scratch = directory.join(format!(".cddl-{}", std::process::id()));
    fs::create_dir(&scratch)?;
    let wrapper = scratch.join("vector.cddl");
    let schema_text = fs::read_to_string(schema)?;
    let result = (|| {
        for (name, accepted, bytes) in vector_cases() {
            fs::write(
                &wrapper,
                format!(
                    "semantic-context-root = semantic-context-file\nagent-id = bstr .size 32\nhash32 = bstr .size 32\n{schema_text}"
                ),
            )?;
            let mut child = Command::new(tool)
                .args(["--ci", "validate", "--cddl"])
                .arg(&wrapper)
                .arg("--stdin")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            child.stdin.take().unwrap().write_all(&bytes)?;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
            loop {
                if child.try_wait()?.is_some() {
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    child.kill()?;
                    return Err(format!("independent CDDL validation timed out for {name}").into());
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            let output = child.wait_with_output()?;
            let diagnostic = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let expected_message = if accepted {
                "Validation from stdin is successful"
            } else {
                "Validation from stdin failed: error validating"
            };
            if output.status.success() != accepted || !diagnostic.contains(expected_message) {
                return Err(
                    format!("unexpected independent CDDL result for {name}: {diagnostic}").into(),
                );
            }
        }
        Ok(())
    })();
    if wrapper.exists() {
        fs::remove_file(&wrapper)?;
    }
    fs::remove_dir(&scratch)?;
    result
}

fn main() -> Result<()> {
    let arguments: Vec<_> = env::args_os().skip(1).collect();
    let mut write = false;
    let mut cddl_tool = None::<PathBuf>;
    let mut index = 0;
    while index < arguments.len() {
        if arguments[index] == "--check" {
            index += 1;
        } else if arguments[index] == "--write" {
            write = true;
            index += 1;
        } else if arguments[index] == "--validate-cddl" {
            let Some(path) = arguments.get(index + 1) else {
                return Err("--validate-cddl requires the cddl executable path".into());
            };
            cddl_tool = Some(PathBuf::from(path));
            index += 2;
        } else {
            return Err(
                "usage: export_semantic_context_vectors [--check] [--write] [--validate-cddl <tool>]"
                    .into(),
            );
        }
    }
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas/context-vectors");
    if write {
        fs::create_dir_all(&directory)?;
        let cases = vector_cases();
        for (name, _, bytes) in &cases {
            fs::write(directory.join(format!("{name}.hex")), hex(bytes))?;
        }
        let index = json!({
            "version": 1,
            "vectors": cases.iter().map(|(name, accepted, _)| json!({
                "name": name,
                "root": "semantic-context-file",
                "codec": "file",
                "accepted": accepted,
            })).collect::<Vec<_>>()
        });
        fs::write(
            directory.join("index.json"),
            format!("{}\n", serde_json::to_string_pretty(&index)?),
        )?;
    }
    check_vectors(&directory)?;
    if let Some(tool) = cddl_tool {
        validate_cddl(
            &directory,
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas/asl-context-v1.cddl"),
            &tool,
        )?;
    }
    println!("Checked {} semantic context vectors.", vector_cases().len());
    Ok(())
}
