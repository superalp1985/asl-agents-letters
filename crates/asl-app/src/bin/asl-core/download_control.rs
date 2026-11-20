use std::{env, ffi::OsString, path::PathBuf};

use alloy_primitives::hex;
use asl_app::paths::AppPaths;
use asl_policy::snapshot_files::PinnedHome;
use asl_store::{Store, open_store, resources::SnapshotBroker, transfers::DownloadMode};
use asl_types::{error::AslError, ids::Id128};
use serde_json::{Value, json};

enum Command {
    List,
    Mode,
    SetMode(DownloadMode),
    Decide { id: Id128, approve: bool },
}

impl Command {
    fn parse(args: &[OsString]) -> Result<Self, AslError> {
        let args = args
            .iter()
            .map(|arg| arg.to_str().ok_or(AslError::InvalidMessage))
            .collect::<Result<Vec<_>, _>>()?;
        match args.as_slice() {
            ["list"] => Ok(Self::List),
            ["mode"] => Ok(Self::Mode),
            ["mode", "ask"] => Ok(Self::SetMode(DownloadMode::Ask)),
            ["mode", "automatic"] => Ok(Self::SetMode(DownloadMode::Automatic)),
            [action @ ("approve" | "deny"), id] if id.len() == 32 => Ok(Self::Decide {
                id: parse_id(id)?,
                approve: *action == "approve",
            }),
            _ => Err(AslError::InvalidMessage),
        }
    }

    fn apply(self, store: &mut Store) -> Result<Value, AslError> {
        match self {
            Self::List => {
                let mut rows = Vec::new();
                for entry in store.download_consents()? {
                    let sources = entry
                        .sources
                        .iter()
                        .map(|peer| {
                            libp2p_identity::PeerId::from_bytes(peer.as_bytes())
                                .map(|id| id.to_base58())
                                .map_err(|_| AslError::InvalidDatabase)
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    rows.push(json!({
                        "id": hex::encode(entry.approval_id.0),
                        "content_id": hex::encode(entry.content_id.0),
                        "destination": entry.destination_path,
                        "file_bytes": entry.file_size,
                        "sources": sources,
                        "expires_at_ms": entry.expires_at_ms,
                        "state": if entry.approved { "approved" } else { "pending" },
                    }));
                }
                Ok(Value::Array(rows))
            }
            Self::Mode => Ok(json!({"download_mode": match store.download_mode()? {
                DownloadMode::Ask => "ask", DownloadMode::Automatic => "automatic"
            }})),
            Self::SetMode(mode) => {
                store.set_download_mode(mode)?;
                Self::Mode.apply(store)
            }
            Self::Decide { id, approve } => {
                store.decide_download(id, approve)?;
                Ok(
                    json!({"id": hex::encode(id.0), "state": if approve { "approved" } else { "denied" }}),
                )
            }
        }
    }
}

pub(super) fn run(args: &[OsString]) -> Result<(), AslError> {
    let root = PathBuf::from(env::var_os("ASL_HOME").ok_or(AslError::InvalidStorageRoot)?);
    let data = match args {
        [command, directory, bytes] if command == "authorize-inbox" => {
            let limit = bytes
                .to_str()
                .and_then(|text| text.parse::<u64>().ok())
                .filter(|limit| *limit > 0)
                .ok_or(AslError::InvalidMessage)?;
            let directory = PathBuf::from(directory);
            if !directory.is_absolute() {
                return Err(AslError::InvalidStorageRoot);
            }
            AppPaths::open(&root)?;
            let mut broker = SnapshotBroker::open(&root)?;
            let id = broker.authorize_inbox_directory(&directory, limit)?;
            json!({"inbox_grant_id": hex::encode(id.0)})
        }
        [command, id] if command == "revoke-inbox" => {
            let id = parse_id(id.to_str().ok_or(AslError::InvalidMessage)?)?;
            AppPaths::open(&root)?;
            SnapshotBroker::open(&root)?.revoke_inbox_directory(id)?;
            json!({"inbox_grant_id": hex::encode(id.0), "state": "revoked"})
        }
        _ => apply_local_command(Command::parse(args)?, &root)?,
    };
    println!("{data}");
    Ok(())
}

fn parse_id(text: &str) -> Result<Id128, AslError> {
    let mut bytes = [0; 16];
    if text.len() != 32 || hex::decode_to_slice(text, &mut bytes).is_err() {
        return Err(AslError::InvalidMessage);
    }
    Ok(Id128(bytes))
}

fn apply_local_command(command: Command, root: &std::path::Path) -> Result<Value, AslError> {
    let paths = AppPaths::open(root)?;
    let _pin = PinnedHome::open(root)?;
    let mut store = open_store(&paths.state().join("asl.sqlite3"))?;
    command.apply(&mut store)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Command, AslError> {
        Command::parse(&args.iter().map(OsString::from).collect::<Vec<_>>())
    }

    #[test]
    fn accepts_only_local_modes_and_full_approval_ids() {
        assert!(matches!(
            parse(&["mode", "ask"]),
            Ok(Command::SetMode(DownloadMode::Ask))
        ));
        assert!(matches!(
            parse(&["deny", &"ef".repeat(16)]),
            Ok(Command::Decide { approve: false, .. })
        ));
        for args in [
            &["mode", "remote"][..],
            &["approve", "ef"],
            &["deny", "*"],
            &["list", "all"],
        ] {
            assert!(parse(args).is_err());
        }
    }
}
