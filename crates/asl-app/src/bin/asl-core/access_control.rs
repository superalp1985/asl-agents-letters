use std::{env, ffi::OsString, path::PathBuf};

use alloy_primitives::hex;
use asl_app::paths::AppPaths;
use asl_policy::Audience;
use asl_store::resources::SnapshotBroker;
use asl_types::{
    error::AslError,
    ids::{AgentId, Id128},
    task::{GrantId, GroupId},
};
use serde_json::{Value, json};

enum Command {
    Share {
        root: PathBuf,
        extensions: Vec<String>,
        audience: Audience,
        max_bytes: u64,
        allow_derived_disclosure: bool,
    },
    Derived {
        root: PathBuf,
        max_bytes: u64,
    },
    Revoke {
        kind: String,
        id: Id128,
    },
}

impl Command {
    fn parse(args: &[OsString]) -> Result<Self, AslError> {
        let args = args
            .iter()
            .map(|arg| arg.to_str().ok_or(AslError::InvalidMessage))
            .collect::<Result<Vec<_>, _>>()?;
        match args.as_slice() {
            ["share", root, extensions, scope, target, max_bytes, derived] => {
                let root = PathBuf::from(root);
                if !root.is_absolute() {
                    return Err(AslError::InvalidStorageRoot);
                }
                let extensions = parse_extensions(extensions)?;
                let audience = parse_audience(scope, target)?;
                let max_bytes = max_bytes
                    .parse::<u64>()
                    .ok()
                    .filter(|value| *value > 0)
                    .ok_or(AslError::InvalidMessage)?;
                let allow_derived_disclosure = match *derived {
                    "yes" => true,
                    "no" => false,
                    _ => return Err(AslError::InvalidMessage),
                };
                Ok(Self::Share {
                    root,
                    extensions,
                    audience,
                    max_bytes,
                    allow_derived_disclosure,
                })
            }
            ["derived", root, max_bytes] => {
                let root = PathBuf::from(root);
                if !root.is_absolute() {
                    return Err(AslError::InvalidStorageRoot);
                }
                let max_bytes = max_bytes
                    .parse::<u64>()
                    .ok()
                    .filter(|value| *value > 0)
                    .ok_or(AslError::InvalidMessage)?;
                Ok(Self::Derived { root, max_bytes })
            }
            ["revoke", kind, id] if matches!(*kind, "share" | "inbox" | "derived") => {
                Ok(Self::Revoke {
                    kind: (*kind).to_owned(),
                    id: parse_id(id)?,
                })
            }
            _ => Err(AslError::InvalidMessage),
        }
    }

    fn apply(self, broker: &mut SnapshotBroker) -> Result<Value, AslError> {
        match self {
            Self::Share {
                root,
                extensions,
                audience,
                max_bytes,
                allow_derived_disclosure,
            } => {
                let id = broker.authorize_directory_with_derivation(
                    &root,
                    &extensions,
                    &audience,
                    max_bytes,
                    allow_derived_disclosure,
                )?;
                Ok(json!({"grant_id": hex::encode(id.0.0), "state": "active"}))
            }
            Self::Derived { root, max_bytes } => {
                let id = broker.authorize_derived_directory(&root, max_bytes)?;
                Ok(json!({"grant_id": hex::encode(id.0), "state": "active"}))
            }
            Self::Revoke { kind, id } => {
                match kind.as_str() {
                    "share" => broker.revoke_directory(&GrantId(id))?,
                    "inbox" => broker.revoke_inbox_directory(id)?,
                    "derived" => broker.revoke_derived_directory(id)?,
                    _ => return Err(AslError::InvalidMessage),
                }
                Ok(json!({"grant_id": hex::encode(id.0), "state": "revoked"}))
            }
        }
    }
}

pub(super) fn run(args: &[OsString]) -> Result<(), AslError> {
    let root = PathBuf::from(env::var_os("ASL_HOME").ok_or(AslError::InvalidStorageRoot)?);
    AppPaths::open(&root)?;
    let mut broker = SnapshotBroker::open(&root)?;
    println!("{}", Command::parse(args)?.apply(&mut broker)?);
    Ok(())
}

fn parse_extensions(value: &str) -> Result<Vec<String>, AslError> {
    let extensions = value
        .split(',')
        .map(|extension| extension.trim().trim_start_matches('.').to_owned())
        .collect::<Vec<_>>();
    if extensions.is_empty()
        || extensions.len() > 64
        || extensions
            .iter()
            .any(|extension| extension.is_empty() || extension.len() > 16)
    {
        return Err(AslError::InvalidMessage);
    }
    Ok(extensions)
}

fn parse_audience(scope: &str, target: &str) -> Result<Audience, AslError> {
    match (scope, target) {
        ("public", "-") => Ok(Audience::Public),
        ("contacts", "-") => Ok(Audience::Contacts),
        ("agent", target) => Ok(Audience::Peers(std::collections::HashSet::from([
            parse_agent(target)?,
        ]))),
        ("group", target) => Ok(Audience::Group(GroupId(parse_id(target)?))),
        _ => Err(AslError::InvalidMessage),
    }
}

fn parse_agent(value: &str) -> Result<AgentId, AslError> {
    let bytes = bs58::decode(value)
        .into_vec()
        .map_err(|_| AslError::InvalidMessage)?;
    let agent = AgentId(bytes.try_into().map_err(|_| AslError::InvalidMessage)?);
    if bs58::encode(agent.0).into_string() != value {
        return Err(AslError::InvalidMessage);
    }
    Ok(agent)
}

fn parse_id(value: &str) -> Result<Id128, AslError> {
    let mut bytes = [0; 16];
    if value.len() != 32 || hex::decode_to_slice(value, &mut bytes).is_err() {
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
    fn parses_local_share_scopes_and_revocations() {
        let agent = bs58::encode([7; 32]).into_string();
        assert!(matches!(
            parse(&[
                "share",
                "C:\\shared",
                "md,pdf",
                "public",
                "-",
                "1048576",
                "no"
            ]),
            Ok(Command::Share {
                audience: Audience::Public,
                ..
            })
        ));
        assert!(matches!(
            parse(&["derived", "C:\\experience", "2097152"]),
            Ok(Command::Derived {
                max_bytes: 2_097_152,
                ..
            })
        ));
        assert!(matches!(
            parse(&[
                "share",
                "C:\\shared",
                "md,pdf",
                "contacts",
                "-",
                "1048576",
                "no"
            ]),
            Ok(Command::Share {
                audience: Audience::Contacts,
                ..
            })
        ));
        assert!(matches!(
            parse(&[
                "share",
                "C:\\shared",
                "md,pdf",
                "agent",
                &agent,
                "1048576",
                "no"
            ]),
            Ok(Command::Share {
                audience: Audience::Peers(_),
                ..
            })
        ));
        let group = "ef".repeat(16);
        assert!(matches!(
            parse(&[
                "share",
                "C:\\shared",
                "md",
                "group",
                &group,
                "1048576",
                "yes"
            ]),
            Ok(Command::Share {
                audience: Audience::Group(_),
                allow_derived_disclosure: true,
                ..
            })
        ));
        let grant = "ab".repeat(16);
        assert!(matches!(
            parse(&["revoke", "share", &grant]),
            Ok(Command::Revoke { .. })
        ));
    }

    #[test]
    fn rejects_ambiguous_or_unbounded_local_share_requests() {
        let grant = "ab".repeat(16);
        for args in [
            &["share", "relative", "md", "public", "-", "10", "no"][..],
            &["share", "C:\\shared", "", "public", "-", "10", "no"],
            &["share", "C:\\shared", "md", "public", "target", "10", "no"],
            &["share", "C:\\shared", "md", "agent", "bad-id", "10", "no"],
            &["share", "C:\\shared", "md", "group", "short", "10", "no"],
            &["share", "C:\\shared", "md", "public", "-", "0", "no"],
            &["share", "C:\\shared", "md", "public", "-", "10", "true"],
            &["derived", "relative", "1024"],
            &["derived", "C:\\experience", "0"],
            &["revoke", "unknown", grant.as_str()],
        ] {
            assert!(Command::parse(&args.iter().map(OsString::from).collect::<Vec<_>>()).is_err());
        }
    }
}
