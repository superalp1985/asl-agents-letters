use std::{env, ffi::OsString, path::PathBuf};

use alloy_primitives::hex;
use asl_app::paths::AppPaths;
use asl_policy::snapshot_files::PinnedHome;
use asl_store::{Store, open_store, transfers::UploadMode};
use asl_types::{error::AslError, ids::Id128};
use serde_json::{Value, json};

enum Command {
    List,
    Mode,
    SetMode(UploadMode),
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
            ["mode", "ask"] => Ok(Self::SetMode(UploadMode::Ask)),
            ["mode", "automatic"] => Ok(Self::SetMode(UploadMode::Automatic)),
            [action @ ("approve" | "deny"), id] if id.len() == 32 => Ok(Self::Decide {
                id: parse_id(id)?,
                approve: *action == "approve",
            }),
            _ => Err(AslError::InvalidMessage),
        }
    }

    fn apply(self, store: &mut Store) -> Result<Value, AslError> {
        match self {
            Self::List => Ok(Value::Array(
                store
                    .upload_consents()?
                    .into_iter()
                    .map(|entry| {
                        json!({
                            "id": hex::encode(entry.approval_id.0),
                            "content_id": hex::encode(entry.content_id.0),
                            "source_grant_id": hex::encode(entry.source_grant_id.0),
                            "filename": entry.filename,
                            "file_bytes": entry.file_size,
                            "target_agent_id": entry.target_agent_id.map(|id| hex::encode(id.0)),
                            "target_peer_id": libp2p_identity::PeerId::from_bytes(
                                entry.target_peer_id.as_bytes()
                            ).map(|id| id.to_base58()).ok(),
                            "group_id": entry.group.as_ref()
                                .map(|group| hex::encode(group.group_id.0.as_bytes())),
                            "group_epoch": entry.group.as_ref()
                                .map(|group| group.membership_epoch),
                            "expires_at_ms": entry.expires_at_ms,
                            "state": if entry.approved { "approved" } else { "pending" },
                        })
                    })
                    .collect(),
            )),
            Self::Mode => Ok(json!({
                "upload_mode": match store.upload_mode()? {
                    UploadMode::Ask => "ask",
                    UploadMode::Automatic => "automatic",
                }
            })),
            Self::SetMode(mode) => {
                store.set_upload_mode(mode)?;
                Self::Mode.apply(store)
            }
            Self::Decide { id, approve } => {
                store.decide_upload(id, approve)?;
                Ok(json!({
                    "id": hex::encode(id.0),
                    "state": if approve { "approved" } else { "denied" },
                }))
            }
        }
    }
}

pub(super) fn run(args: &[OsString]) -> Result<(), AslError> {
    let root = PathBuf::from(env::var_os("ASL_HOME").ok_or(AslError::InvalidStorageRoot)?);
    let paths = AppPaths::open(&root)?;
    let _pin = PinnedHome::open(&root)?;
    let mut store = open_store(&paths.state().join("asl.sqlite3"))?;
    let result = Command::parse(args)?.apply(&mut store)?;
    println!("{result}");
    Ok(())
}

fn parse_id(text: &str) -> Result<Id128, AslError> {
    let mut bytes = [0; 16];
    if text.len() != 32 || hex::decode_to_slice(text, &mut bytes).is_err() {
        return Err(AslError::InvalidMessage);
    }
    Ok(Id128(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Command, AslError> {
        Command::parse(&args.iter().map(OsString::from).collect::<Vec<_>>())
    }

    #[test]
    fn accepts_only_local_upload_modes_and_full_approval_ids() {
        assert!(matches!(
            parse(&["mode", "ask"]),
            Ok(Command::SetMode(UploadMode::Ask))
        ));
        assert!(matches!(
            parse(&["approve", &"ef".repeat(16)]),
            Ok(Command::Decide { approve: true, .. })
        ));
        for args in [
            &["mode", "remote"][..],
            &["deny", "ef"],
            &["approve", "*"],
            &["list", "all"],
        ] {
            assert!(parse(args).is_err());
        }
    }
}
