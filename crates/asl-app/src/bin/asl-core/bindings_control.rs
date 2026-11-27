use std::{env, ffi::OsString, path::PathBuf};

use asl_app::paths::AppPaths;
use asl_policy::snapshot_files::PinnedHome;
use asl_store::{
    contact_bindings::ContactBindingActionKind, contact_policy::ContactRequestMode, open_store,
    open_store_read_only,
};
use asl_types::{
    error::AslError,
    ids::{AgentId, PeerId},
    record::short_code,
};
use serde_json::json;

const SHORT_CODE_LIMIT: u64 = 10_000_000_000_000_000;

enum Command {
    Lookup(u64),
    LookupAgent(AgentId),
    Approve(AgentId, PeerId, u64),
    Dismiss(AgentId, PeerId, u64),
    Revoke(AgentId),
    Forget(AgentId),
    Publish(bool),
    SetRequestPolicy(ContactRequestMode),
}

impl Command {
    fn parse(args: &[OsString]) -> Result<Self, AslError> {
        let args = args
            .iter()
            .map(|arg| arg.to_str().ok_or(AslError::InvalidMessage))
            .collect::<Result<Vec<_>, _>>()?;
        match args.as_slice() {
            ["lookup", code] => Ok(Self::Lookup(parse_code(code)?)),
            ["lookup-agent", agent] => Ok(Self::LookupAgent(parse_agent(agent)?)),
            ["approve", agent, peer, code] => Ok(Self::Approve(
                parse_agent(agent)?,
                parse_peer(peer)?,
                parse_code(code)?,
            )),
            ["dismiss", agent, peer, code] => Ok(Self::Dismiss(
                parse_agent(agent)?,
                parse_peer(peer)?,
                parse_code(code)?,
            )),
            ["revoke", agent] => Ok(Self::Revoke(parse_agent(agent)?)),
            ["forget", agent] => Ok(Self::Forget(parse_agent(agent)?)),
            ["publish", "on"] => Ok(Self::Publish(true)),
            ["publish", "off"] => Ok(Self::Publish(false)),
            ["policy", "review"] => Ok(Self::SetRequestPolicy(ContactRequestMode::Review)),
            ["policy", "auto-accept"] => Ok(Self::SetRequestPolicy(ContactRequestMode::AutoAccept)),
            ["policy", "reject"] => Ok(Self::SetRequestPolicy(ContactRequestMode::Reject)),
            _ => Err(AslError::InvalidMessage),
        }
    }

    fn enqueue(self, store: &mut asl_store::Store, now_ms: u64) -> Result<(), AslError> {
        let (kind, code, agent_id, peer_id) = match self {
            Self::Lookup(code) => (ContactBindingActionKind::Lookup, Some(code), None, None),
            Self::LookupAgent(agent) => (
                ContactBindingActionKind::Lookup,
                Some(short_code(agent)),
                Some(agent),
                None,
            ),
            Self::Approve(agent, peer, code) => (
                ContactBindingActionKind::Approve,
                Some(code),
                Some(agent),
                Some(peer),
            ),
            Self::Dismiss(agent, peer, code) => (
                ContactBindingActionKind::Dismiss,
                Some(code),
                Some(agent),
                Some(peer),
            ),
            Self::Revoke(agent) => (ContactBindingActionKind::Revoke, None, Some(agent), None),
            Self::Forget(agent) => (ContactBindingActionKind::Forget, None, Some(agent), None),
            Self::Publish(enabled) => (
                if enabled {
                    ContactBindingActionKind::PublishCode
                } else {
                    ContactBindingActionKind::UnpublishCode
                },
                None,
                None,
                None,
            ),
            Self::SetRequestPolicy(mode) => (
                match mode {
                    ContactRequestMode::Review => ContactBindingActionKind::SetRequestReview,
                    ContactRequestMode::AutoAccept => {
                        ContactBindingActionKind::SetRequestAutoAccept
                    }
                    ContactRequestMode::Reject => ContactBindingActionKind::SetRequestReject,
                },
                None,
                None,
                None,
            ),
        };
        store.enqueue_contact_binding_action(kind, code, agent_id, peer_id.as_ref(), now_ms)
    }
}

pub(super) fn run(args: &[OsString]) -> Result<(), AslError> {
    let root = PathBuf::from(env::var_os("ASL_HOME").ok_or(AslError::InvalidStorageRoot)?);
    let paths = AppPaths::open_existing(&root)?;
    let _pin = PinnedHome::open(&root)?;
    let database = paths.state().join("asl.sqlite3");
    fn text(v: &OsString) -> Result<&str, AslError> {
        v.to_str().ok_or(AslError::InvalidMessage)
    }
    match args {
        [command] if command == "list" => {
            let rows = open_store_read_only(&database)?.recent_contact_bindings()?;
            println!("{}", json!({"bindings": rows}));
        }
        [command] if command == "policy" => {
            let mode = open_store_read_only(&database)?.contact_request_mode()?;
            println!("{}", json!({"request_mode": mode.as_str()}));
        }
        [command, mode, agent, peer, at] if command == "access" && mode == "on" => {
            let agent = parse_agent(text(agent)?)?;
            if asl_app::identity::AgentIdentity::load_protected(&paths.agent_root_key())?.agent_id()
                == agent
            {
                return Err(AslError::PolicyDenied);
            }
            open_store(&database)?.grant_contact_access(
                agent,
                &parse_peer(text(peer)?)?,
                text(at)?.parse().map_err(|_| AslError::InvalidMessage)?,
            )?;
            println!("{}", json!({"authorized": true}));
        }
        [command, mode, agent] if command == "access" && mode == "off" => {
            open_store(&database)?.remove_contact_access(parse_agent(text(agent)?)?)?;
            println!("{}", json!({"authorized": false}));
        }
        _ => {
            Command::parse(args)?.enqueue(&mut open_store(&database)?, unix_time_ms()?)?;
            println!("{}", json!({"queued": true}));
        }
    }
    Ok(())
}

fn parse_code(text: &str) -> Result<u64, AslError> {
    if text.len() != 16 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(AslError::InvalidMessage);
    }
    let code = text.parse::<u64>().map_err(|_| AslError::InvalidMessage)?;
    (code < SHORT_CODE_LIMIT)
        .then_some(code)
        .ok_or(AslError::InvalidMessage)
}

pub(super) fn parse_agent(text: &str) -> Result<AgentId, AslError> {
    let bytes = bs58::decode(text)
        .into_vec()
        .map_err(|_| AslError::InvalidMessage)?;
    Ok(AgentId(
        bytes.try_into().map_err(|_| AslError::InvalidMessage)?,
    ))
}

fn parse_peer(text: &str) -> Result<PeerId, AslError> {
    let peer: libp2p_identity::PeerId = text.parse().map_err(|_| AslError::InvalidMessage)?;
    PeerId::from_bytes(peer.to_bytes()).map_err(|_| AslError::InvalidMessage)
}

fn unix_time_ms() -> Result<u64, AslError> {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .ok_or(AslError::InvalidMessage)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Command, AslError> {
        Command::parse(&args.iter().map(OsString::from).collect::<Vec<_>>())
    }

    #[test]
    fn accepts_only_bounded_local_contact_binding_actions() {
        let agent = bs58::encode([7; 32]).into_string();
        let peer = libp2p_identity::Keypair::ed25519_from_bytes([8; 32])
            .unwrap()
            .public()
            .to_peer_id()
            .to_string();
        assert!(matches!(
            parse(&["lookup", "0000000000000042"]),
            Ok(Command::Lookup(42))
        ));
        assert!(matches!(
            parse(&["lookup-agent", &agent]),
            Ok(Command::LookupAgent(_))
        ));
        assert!(matches!(
            parse(&["approve", &agent, &peer, "0000000000000042"]),
            Ok(Command::Approve(_, _, 42))
        ));
        assert!(matches!(
            parse(&["publish", "off"]),
            Ok(Command::Publish(false))
        ));
        assert!(matches!(
            parse(&["publish", "on"]),
            Ok(Command::Publish(true))
        ));
        assert!(matches!(
            parse(&["policy", "auto-accept"]),
            Ok(Command::SetRequestPolicy(ContactRequestMode::AutoAccept))
        ));
        for args in [
            &["lookup", "42"][..],
            &["lookup", "10000000000000000"],
            &["lookup-agent", "not-an-agent"],
            &["publish", "true"],
            &["policy", "accept-everything"],
            &["revoke", "not-an-agent"],
            &["dismiss", &agent, &peer, "0000000000000042", "extra"],
        ] {
            assert!(parse(args).is_err());
        }
    }
}
