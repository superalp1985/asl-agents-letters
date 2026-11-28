use std::{env, ffi::OsString, path::PathBuf};

use asl_app::{
    contact_invite,
    identity::{AgentIdentity, DeviceIdentity},
    paths::AppPaths,
};
use asl_policy::snapshot_files::PinnedHome;
use asl_store::{
    contact_invites::{ContactInviteActionKind, ContactInviteActionPayload},
    open_store,
};
use asl_types::{
    contact_invite::ContactInviteV1,
    error::AslError,
    ids::{Hash32, Id128, Signature65},
    protocol::ContactProvenance,
};
use serde_json::json;

pub(super) fn run(args: &[OsString]) -> Result<(), AslError> {
    let root = PathBuf::from(env::var_os("ASL_HOME").ok_or(AslError::InvalidStorageRoot)?);
    let paths = AppPaths::open_existing(&root)?;
    let _pin = PinnedHome::open(&root)?;
    let database = paths.state().join("asl.sqlite3");
    let now_ms = unix_time_ms()?;
    match args {
        [command, minutes, note] if command == "create" => {
            let minutes = parse_minutes(text(minutes)?)?;
            let identity = AgentIdentity::load_protected(&paths.agent_root_key())?;
            let device = DeviceIdentity::load_protected(&paths.device_key())?;
            let invite = contact_invite::issue(
                &identity,
                text(note)?,
                now_ms,
                minutes.saturating_mul(60_000),
            )?;
            open_store(&database)?.create_contact_invite_with_provenance(
                invite.invite_id,
                invite.token,
                invite.inviter,
                invite.created_at_ms,
                invite.expires_at_ms,
                &invite.note,
                invite.provenance,
                invite.signature.0,
            )?;
            println!(
                "{}",
                json!({
                    "invite_id": hex_id(invite.invite_id),
                    "short_code": contact_invite::short_code(&invite),
                    "short_code_envelope": contact_invite::short_code_envelope(
                        invite.inviter,
                        &device.peer_id(),
                        &invite
                    ),
                    "expires_at_ms": invite.expires_at_ms,
                    "envelope": invite.to_envelope(now_ms)?,
                })
            );
        }
        [command, minutes, note, group, epoch] if command == "create-group" => {
            let minutes = parse_minutes(text(minutes)?)?;
            let identity = AgentIdentity::load_protected(&paths.agent_root_key())?;
            let device = DeviceIdentity::load_protected(&paths.device_key())?;
            let provenance = ContactProvenance::SharedGroup {
                group_id: parse_hash32(text(group)?)?,
                membership_epoch: text(epoch)?.parse().map_err(|_| AslError::InvalidMessage)?,
            };
            let invite = contact_invite::issue_with_provenance(
                &identity,
                text(note)?,
                Some(provenance),
                now_ms,
                minutes.saturating_mul(60_000),
            )?;
            open_store(&database)?.create_contact_invite_with_provenance(
                invite.invite_id,
                invite.token,
                invite.inviter,
                invite.created_at_ms,
                invite.expires_at_ms,
                &invite.note,
                invite.provenance,
                invite.signature.0,
            )?;
            println!(
                "{}",
                json!({
                    "invite_id": hex_id(invite.invite_id),
                    "short_code": contact_invite::short_code(&invite),
                    "short_code_envelope": contact_invite::short_code_envelope(
                        invite.inviter,
                        &device.peer_id(),
                        &invite
                    ),
                    "expires_at_ms": invite.expires_at_ms,
                    "provenance": "shared_group",
                    "envelope": invite.to_envelope(now_ms)?,
                })
            );
        }
        [command, minutes, digits, note] if command == "create-pake" => {
            let minutes = parse_pake_minutes(text(minutes)?)?;
            let digits = parse_pake_digits(text(digits)?)?;
            let identity = AgentIdentity::load_protected(&paths.agent_root_key())?;
            let device = DeviceIdentity::load_protected(&paths.device_key())?;
            let invite = contact_invite::issue_pake(
                &identity,
                text(note)?,
                now_ms,
                minutes.saturating_mul(60_000),
                digits,
            )?;
            open_store(&database)?.create_contact_invite(
                invite.invite_id,
                invite.token,
                invite.inviter,
                invite.created_at_ms,
                invite.expires_at_ms,
                &invite.note,
                invite.signature.0,
            )?;
            println!(
                "{}",
                json!({
                    "invite_id": hex_id(invite.invite_id),
                    "kind": "pake",
                    "code_digits": digits,
                    "pake_code": contact_invite::pake_code(&invite),
                    "pake_envelope": contact_invite::pake_code_envelope(
                        invite.inviter,
                        &device.peer_id(),
                        &invite
                    ),
                    "expires_at_ms": invite.expires_at_ms,
                })
            );
        }
        [command] if command == "list" => {
            let now_ms = unix_time_ms()?;
            let device = DeviceIdentity::load_protected(&paths.device_key())?;
            let rows = open_store(&database)?
                .active_contact_invites(now_ms)?
                .into_iter()
                .map(|row| {
                    let invite = ContactInviteV1 {
                        version: asl_types::contact_invite::CONTACT_INVITE_VERSION,
                        invite_id: row.invite_id,
                        token: row.token,
                        inviter: row.agent_id,
                        created_at_ms: row.created_at_ms,
                        expires_at_ms: row.expires_at_ms,
                        note: row.note.unwrap_or_default(),
                        provenance: row.provenance,
                        signature: Signature65(row.signature),
                    };
                    Ok(json!({
                        "invite_id": hex_id(row.invite_id),
                        "short_code": contact_invite::short_code(&invite),
                        "short_code_envelope": contact_invite::short_code_envelope(
                            invite.inviter,
                            &device.peer_id(),
                            &invite
                        ),
                        "expires_at_ms": row.expires_at_ms,
                        "pake_code": contact_invite::pake_code(&invite),
                        "pake_envelope": contact_invite::pake_code_envelope(
                            invite.inviter,
                            &device.peer_id(),
                            &invite
                        ),
                        "envelope": invite.to_envelope(now_ms)?,
                    }))
                })
                .collect::<Result<Vec<_>, AslError>>()?;
            println!("{}", json!({"invites": rows}));
        }
        [command, envelope] if command == "import" => {
            let mut store = open_store(&database)?;
            let action = store.enqueue_contact_invite_action(
                ContactInviteActionKind::Import,
                ContactInviteActionPayload::Envelope(text(envelope)?.as_bytes().to_vec()),
                now_ms,
            )?;
            println!("{}", json!({"queued": true, "action_id": action}));
        }
        [command] if command == "prompts" => {
            let now_ms = unix_time_ms()?;
            let prompts = open_store(&database)?.list_contact_invite_prompts(now_ms)?;
            println!(
                "{}",
                json!({
                    "prompts": prompts.into_iter().map(|prompt| json!({
                        "prompt_id": hex_id(prompt.prompt_id),
                        "tag": prompt.tag,
                        "remote_agent": bs58::encode(prompt.remote_agent.as_bytes()).into_string(),
                        "note": prompt.note,
                        "expires_at_ms": prompt.expires_at_ms,
                        "provenance": prompt.provenance.map(|provenance| match provenance {
                            ContactProvenance::SharedGroup { group_id, membership_epoch } => json!({
                                "kind": "shared_group",
                                "group_id": alloy_primitives::hex::encode(group_id.0),
                                "membership_epoch": membership_epoch,
                            }),
                            ContactProvenance::RecentInteraction { interaction_id, expires_at_ms } => json!({
                                "kind": "recent_interaction",
                                "interaction_id": alloy_primitives::hex::encode(interaction_id.0),
                                "expires_at_ms": expires_at_ms,
                            }),
                        }),
                    })).collect::<Vec<_>>()
                })
            );
        }
        [command, prompt] if command == "approve" || command == "reject" => {
            let prompt_id = parse_id128(text(prompt)?)?;
            let accepted = command == "approve";
            let mut store = open_store(&database)?;
            if !store.decide_contact_invite_prompt(prompt_id, now_ms, accepted)? {
                return Err(AslError::NotFound);
            }
            store.enqueue_contact_invite_action(
                ContactInviteActionKind::Decide,
                ContactInviteActionPayload::Prompt(prompt_id),
                now_ms,
            )?;
            println!("{}", json!({"decided": accepted}));
        }
        [command, invite] if command == "revoke" => {
            let invite_id = parse_id128(text(invite)?)?;
            if !open_store(&database)?.revoke_contact_invite(invite_id, now_ms)? {
                return Err(AslError::NotFound);
            }
            println!("{}", json!({"revoked": true}));
        }
        _ => return Err(AslError::InvalidMessage),
    }
    Ok(())
}

fn parse_minutes(value: &str) -> Result<u64, AslError> {
    let minutes = value.parse().map_err(|_| AslError::InvalidMessage)?;
    match minutes {
        5 | 15 | 60 | 1_440 => Ok(minutes),
        _ => Err(AslError::InvalidMessage),
    }
}

fn parse_pake_minutes(value: &str) -> Result<u64, AslError> {
    let minutes: u64 = value.parse().map_err(|_| AslError::InvalidMessage)?;
    match minutes {
        5 | 15 => Ok(minutes),
        _ => Err(AslError::InvalidMessage),
    }
}

fn parse_pake_digits(value: &str) -> Result<u8, AslError> {
    let digits: u8 = value.parse().map_err(|_| AslError::InvalidMessage)?;
    match digits {
        6 | 12 => Ok(digits),
        _ => Err(AslError::InvalidMessage),
    }
}

fn parse_id128(value: &str) -> Result<Id128, AslError> {
    let bytes = match alloy_primitives::hex::decode(value) {
        Ok(bytes) if bytes.len() == 16 => bytes,
        _ => bs58::decode(value)
            .into_vec()
            .map_err(|_| AslError::InvalidMessage)?,
    };
    Ok(Id128(
        bytes.try_into().map_err(|_| AslError::InvalidMessage)?,
    ))
}

fn parse_hash32(value: &str) -> Result<Hash32, AslError> {
    let bytes = match alloy_primitives::hex::decode(value) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => bs58::decode(value)
            .into_vec()
            .map_err(|_| AslError::InvalidMessage)?,
    };
    Ok(Hash32(
        bytes.try_into().map_err(|_| AslError::InvalidMessage)?,
    ))
}

fn hex_id(id: Id128) -> String {
    alloy_primitives::hex::encode(id.0)
}

fn text(value: &OsString) -> Result<&str, AslError> {
    value.to_str().ok_or(AslError::InvalidMessage)
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

    #[test]
    fn contact_invite_cli_limits_lifetime_and_ids() {
        for minutes in ["5", "15", "60", "1440"] {
            let expected: u64 = minutes.parse().unwrap();
            assert_eq!(parse_minutes(minutes).unwrap(), expected);
        }
        for minutes in ["0", "4", "30", "1441", "x"] {
            assert!(parse_minutes(minutes).is_err());
        }
        assert!(parse_id128(&"11".repeat(16)).is_ok());
        assert!(parse_id128("short").is_err());
    }
}
