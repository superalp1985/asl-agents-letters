use std::{env, ffi::OsString, path::PathBuf};

use alloy_primitives::hex;
use asl_app::paths::AppPaths;
use asl_policy::snapshot_files::PinnedHome;
use asl_store::{Store, open_store, transfers::DownloadMode};
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
            [action @ ("approve" | "deny"), id] if id.len() == 32 => {
                let mut bytes = [0; 16];
                hex::decode_to_slice(id, &mut bytes).map_err(|_| AslError::InvalidMessage)?;
                Ok(Self::Decide {
                    id: Id128(bytes),
                    approve: *action == "approve",
                })
            }
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
    let command = Command::parse(args)?;
    let root = PathBuf::from(env::var_os("ASL_HOME").ok_or(AslError::InvalidStorageRoot)?);
    let paths = AppPaths::open(&root)?;
    let _pin = PinnedHome::open(&root)?;
    let mut store = open_store(&paths.state().join("asl.sqlite3"))?;
    println!("{}", command.apply(&mut store)?);
    Ok(())
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
