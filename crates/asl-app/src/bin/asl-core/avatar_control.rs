use std::{
    env,
    ffi::OsString,
    path::{Path, PathBuf},
};

use asl_app::{avatar, paths::AppPaths};
use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32},
};

pub(super) fn run(args: &[OsString]) -> Result<(), AslError> {
    let home = PathBuf::from(env::var_os("ASL_HOME").ok_or(AslError::InvalidStorageRoot)?);
    let paths = AppPaths::open_existing(&home)?;
    let result = match args {
        [action] if action == "status" => status_json(avatar::preview(&paths)?.as_ref()),
        [action, source] if action == "set" => {
            let source = std::path::absolute(Path::new(source))?;
            avatar::set(&paths, &source)?;
            serde_json::json!({ "configured": true })
        }
        [action, index] if action == "preset" => {
            let index = index
                .to_str()
                .and_then(|value| value.parse::<usize>().ok())
                .filter(|index| *index > 0)
                .ok_or(AslError::InvalidMessage)?;
            avatar::set_preset(&paths, index - 1)?;
            serde_json::json!({ "configured": true })
        }
        [action] if action == "clear" => {
            avatar::clear(&paths)?;
            serde_json::json!({ "configured": false })
        }
        [action, token] if action == "approve" => {
            let token = token
                .to_str()
                .filter(|token| !token.is_empty())
                .ok_or(AslError::InvalidMessage)?;
            avatar::approve(&paths, token)?;
            serde_json::json!({ "approved": true })
        }
        [action] if action == "withdraw" => {
            avatar::withdraw(&paths)?;
            serde_json::json!({ "approved": false })
        }
        [action, owner, content] if action == "fetch" => {
            let (owner, content) = parse_download_target(
                owner.to_str().ok_or(AslError::InvalidMessage)?,
                content.to_str().ok_or(AslError::InvalidMessage)?,
            )?;
            avatar::request_download(&paths, owner, content)?;
            serde_json::json!({ "requested": true })
        }
        [action] if action == "cancel-fetch" => {
            avatar::cancel_download(&paths)?;
            serde_json::json!({ "cancelled": true })
        }
        _ => {
            eprintln!(
                "Usage: asl-core --avatar status | set <image> | preset <number> | clear | approve <token> | withdraw\n\
                 Usage: asl-core --avatar fetch <agent-base58> <content-hex> | cancel-fetch"
            );
            return Err(AslError::InvalidMessage);
        }
    };
    println!("{result}");
    Ok(())
}

fn parse_download_target(owner: &str, content: &str) -> Result<(AgentId, Hash32), AslError> {
    if owner.len() > 44 || content.len() != 64 {
        return Err(AslError::InvalidMessage);
    }
    let owner = super::bindings_control::parse_agent(owner)?;
    let content =
        alloy_primitives::hex::decode_to_array(content).map_err(|_| AslError::InvalidMessage)?;
    Ok((owner, Hash32(content)))
}

fn status_json(preview: Option<&avatar::AvatarPreview>) -> serde_json::Value {
    match preview {
        Some(preview) => match &preview.token {
            Some(token) => serde_json::json!({
                "configured": true,
                "token": token,
                "approved": preview.approved,
            }),
            None => serde_json::json!({ "configured": true }),
        },
        None => serde_json::json!({ "configured": false }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn avatar_status_preserves_legacy_shape_without_a_token() {
        let mut preview = avatar::AvatarPreview {
            image: image::RgbaImage::new(1, 1),
            token: None,
            approved: false,
        };
        assert_eq!(status_json(None), json!({ "configured": false }));
        assert_eq!(status_json(Some(&preview)), json!({ "configured": true }));
        preview.token = Some("reviewed-image".into());
        for approved in [false, true] {
            preview.approved = approved;
            assert_eq!(
                status_json(Some(&preview)),
                json!({ "configured": true, "token": "reviewed-image", "approved": approved }),
            );
        }
    }

    #[test]
    fn remote_avatar_target_requires_raw_fixed_size_ids() {
        let owner = bs58::encode([7; 32]).into_string();
        let content = "ab".repeat(32);
        assert_eq!(
            parse_download_target(&owner, &content).unwrap(),
            (AgentId([7; 32]), Hash32([0xab; 32]))
        );
        for (owner, content) in [
            ("owner.example", content.as_str()),
            (&"1".repeat(33), &content),
            (&owner, &"ab".repeat(31)),
            (&owner, &format!("0x{content}")),
            (&owner, "https://example.invalid/avatar"),
            (&owner, &"gg".repeat(32)),
        ] {
            assert!(parse_download_target(owner, content).is_err());
        }
    }
}
