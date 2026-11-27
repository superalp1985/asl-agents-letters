use std::{
    env,
    ffi::{OsStr, OsString},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use asl_app::{
    identity::{AgentIdentity, DeviceIdentity},
    network_settings::NetworkSettingsV1,
    paths::AppPaths,
};
use asl_policy::snapshot_files::PinnedHome;
use asl_store::{
    group_state::{open_mls_runtime_store, operator::AdminRequest},
    open_store_read_only,
};
use asl_types::error::AslError;
use serde_json::json;

pub(super) fn run(args: &[OsString]) -> Result<(), AslError> {
    let request = match args {
        [op] if op == "status" => None,
        [op] if op == "refresh" => Some(AdminRequest::Refresh),
        [op, tag] if op == "create" => Some(AdminRequest::Create {
            tag: text(tag)?.into(),
        }),
        [op, tag, room, connection] if op == "invite" => Some(AdminRequest::Invite {
            tag: text(tag)?.into(),
            room: hex_id(room, 64)?,
            connection: hex_id(connection, 32)?,
        }),
        [op, tag, room, device] if op == "remove" => Some(AdminRequest::Remove {
            tag: text(tag)?.into(),
            room: hex_id(room, 64)?,
            device: device_peer(device)?,
        }),
        [op, tag, room, device] if op == "reject-request" => {
            Some(AdminRequest::RejectJoinRequest {
                tag: text(tag)?.into(),
                room: hex_id(room, 64)?,
                device: device_peer(device)?,
            })
        }
        [op, room, owner] if op == "request-join" => Some(AdminRequest::RequestJoin {
            room: hex_id(room, 64)?,
            owner: agent_id(owner)?,
        }),
        [
            op,
            tag,
            room,
            revision,
            text_flag,
            file_flag,
            invite_flag,
            admins,
            muted,
        ] if op == "access" => Some(AdminRequest::SetAccess {
            tag: text(tag)?.into(),
            room: hex_id(room, 64)?,
            policy_revision: text(revision)?
                .parse()
                .map_err(|_| AslError::InvalidMessage)?,
            allow_member_text: switch(text(text_flag)?)?,
            allow_member_files: switch(text(file_flag)?)?,
            allow_member_invite: switch(text(invite_flag)?)?,
            admins: peer_list(text(admins)?)?,
            muted: peer_list(text(muted)?)?,
        }),
        [op, tag, room, kind, additional, hours] if op == "budget" => {
            Some(AdminRequest::RenewResourceBudget {
                tag: text(tag)?.into(),
                room: hex_id(room, 64)?,
                kind: text(kind)?.into(),
                additional: text(additional)?
                    .parse()
                    .map_err(|_| AslError::InvalidMessage)?,
                window_hours: text(hours)?.parse().map_err(|_| AslError::InvalidMessage)?,
            })
        }
        _ => return Err(AslError::InvalidMessage),
    };
    let home = PathBuf::from(env::var_os("ASL_HOME").ok_or(AslError::InvalidStorageRoot)?);
    let paths = AppPaths::open_existing(&home)?;
    let _pin = PinnedHome::open(&home)?;
    let database = paths.existing_state_database()?;
    let store = open_store_read_only(&database)?;
    let config = NetworkSettingsV1::load(&paths.network_settings_configuration())?;
    if !config.loopback_groups {
        return Err(AslError::PolicyDenied);
    }
    let agent = AgentIdentity::load_protected(&paths.agent_root_key())?.agent_id();
    let device = DeviceIdentity::load_protected(&paths.device_key())?.peer_id();
    let now: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AslError::InvalidMessage)?
        .as_millis()
        .try_into()
        .map_err(|_| AslError::InvalidMessage)?;
    let reply = if let Some(request) = request {
        drop(store);
        open_mls_runtime_store(&database)?.queue_group_admin(agent, &device, request, now)?;
        json!({"state": "queued"})
    } else {
        json!({
            "snapshot": store.local_group_admin_snapshot(agent, &device, now)?,
            "status": store.local_group_admin_status(now)?,
        })
    };
    println!("{reply}");
    Ok(())
}

fn text(value: &OsStr) -> Result<&str, AslError> {
    value
        .to_str()
        .filter(|s| !s.is_empty())
        .ok_or(AslError::InvalidMessage)
}

fn hex_id(value: &OsStr, len: usize) -> Result<String, AslError> {
    let value = text(value)?;
    if value.len() != len || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(AslError::InvalidMessage);
    }
    Ok(value.to_ascii_lowercase())
}

fn device_peer(value: &OsStr) -> Result<String, AslError> {
    let text = text(value)?;
    let peer: libp2p_identity::PeerId = text.parse().map_err(|_| AslError::InvalidMessage)?;
    let canonical = peer.to_base58();
    if canonical != text {
        return Err(AslError::InvalidMessage);
    }
    Ok(canonical)
}

fn agent_id(value: &OsStr) -> Result<String, AslError> {
    let text = text(value)?;
    let bytes = bs58::decode(text)
        .into_vec()
        .map_err(|_| AslError::InvalidMessage)?;
    if bytes.len() != 32 || bs58::encode(&bytes).into_string() != text {
        return Err(AslError::InvalidMessage);
    }
    Ok(text.to_owned())
}

fn switch(value: &str) -> Result<bool, AslError> {
    match value {
        "on" => Ok(true),
        "off" => Ok(false),
        _ => Err(AslError::InvalidMessage),
    }
}

fn peer_list(value: &str) -> Result<Vec<String>, AslError> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    value
        .split(',')
        .map(|peer| device_peer(OsStr::new(peer)))
        .collect::<Result<Vec<_>, _>>()
        .and_then(|peers| {
            if peers.len() <= 512 {
                Ok(peers)
            } else {
                Err(AslError::InvalidMessage)
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removal_requires_a_canonical_libp2p_peer_id() {
        let peer = libp2p_identity::Keypair::ed25519_from_bytes([7; 32])
            .unwrap()
            .public()
            .to_peer_id()
            .to_base58();
        assert_eq!(device_peer(OsStr::new(&peer)).unwrap(), peer);
        for invalid in ["not-a-peer", "", &format!(" {peer}"), &format!("1{peer}")] {
            assert!(device_peer(OsStr::new(invalid)).is_err());
        }
    }

    #[test]
    fn request_join_requires_a_canonical_agent_id() {
        let agent = bs58::encode([9; 32]).into_string();
        assert_eq!(agent_id(OsStr::new(&agent)).unwrap(), agent);
        for invalid in [
            "not-an-agent".to_owned(),
            bs58::encode([9; 31]).into_string(),
            format!(" {agent}"),
        ] {
            assert!(agent_id(OsStr::new(&invalid)).is_err());
        }
    }
}
