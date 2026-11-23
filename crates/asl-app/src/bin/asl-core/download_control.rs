use std::{env, ffi::OsString, path::PathBuf};

use alloy_primitives::hex;
use asl_app::paths::AppPaths;
use asl_policy::snapshot_files::PinnedHome;
use asl_store::{Store, open_store, resources::SnapshotBroker, transfers::DownloadMode};
use asl_types::{error::AslError, ids::Id128, task::TransferId};
use serde_json::{Value, json};

enum Command {
    List,
    Mode,
    SetMode(DownloadMode),
    AuthorizeRecovery(TransferId),
    RevokeRecovery(TransferId),
    AuthorizeRecoveryDecision(Id128),
    RevokeRecoveryDecision(Id128),
    Retention {
        grant: Id128,
        days: Option<u8>,
    },
    Decide {
        id: Id128,
        approve: bool,
    },
    HostInbox {
        request: Id128,
        grant: Option<Id128>,
    },
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
            ["authorize-recovery", id] => Ok(Self::AuthorizeRecovery(TransferId(parse_id(id)?))),
            ["revoke-recovery", id] => Ok(Self::RevokeRecovery(TransferId(parse_id(id)?))),
            ["authorize-recovery-decision", id] => {
                Ok(Self::AuthorizeRecoveryDecision(parse_id(id)?))
            }
            ["revoke-recovery-decision", id] => Ok(Self::RevokeRecoveryDecision(parse_id(id)?)),
            ["retention", grant] => Ok(Self::Retention {
                grant: parse_id(grant)?,
                days: None,
            }),
            ["retention", grant, days] => Ok(Self::Retention {
                grant: parse_id(grant)?,
                days: Some(match *days {
                    "off" => 0,
                    _ => days.parse::<u8>().map_err(|_| AslError::InvalidMessage)?,
                }),
            }),
            ["bind-host-inbox", request, grant] => Ok(Self::HostInbox {
                request: parse_id(request)?,
                grant: Some(parse_id(grant)?),
            }),
            ["deny-host-inbox", request] => Ok(Self::HostInbox {
                request: parse_id(request)?,
                grant: None,
            }),
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
            Self::AuthorizeRecovery(id) => Ok(json!({
                "transfer_id": hex::encode(id.0.0),
                "expires_at_ms": store.authorize_recovery_download(&id)?,
            })),
            Self::RevokeRecovery(id) => {
                store.revoke_recovery_download(&id)?;
                Ok(json!({"transfer_id": hex::encode(id.0.0), "state": "revoked"}))
            }
            Self::AuthorizeRecoveryDecision(id) => {
                let decision = store.authorize_recovery_download_decision(id)?;
                Ok(json!({
                    "approval_id": hex::encode(id.0),
                    "transfer_id": hex::encode(decision.transfer_id.0.0),
                    "state": decision.state,
                    "expires_at_ms": decision.expires_at_ms,
                }))
            }
            Self::RevokeRecoveryDecision(id) => {
                store.revoke_recovery_download_decision(id)?;
                Ok(json!({"approval_id": hex::encode(id.0), "state": "revoked"}))
            }
            Self::Retention { grant, days } => {
                if let Some(days) = days {
                    store.set_inbox_retention_days(grant, days)?;
                }
                Ok(json!({
                    "inbox_grant_id": hex::encode(grant.0),
                    "retention_days": store.inbox_retention_days(grant)?
                }))
            }
            Self::Decide { id, approve } => {
                store.decide_download(id, approve)?;
                Ok(
                    json!({"id": hex::encode(id.0), "state": if approve { "approved" } else { "denied" }}),
                )
            }
            Self::HostInbox { request, grant } => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| AslError::InvalidPolicyState)?
                    .as_millis()
                    .try_into()
                    .map_err(|_| AslError::InvalidPolicyState)?;
                store.decide_host_inbox(request, grant, now)?;
                Ok(
                    json!({"request_id":hex::encode(request.0),"state":if grant.is_some() { "bound" } else { "denied" }}),
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
