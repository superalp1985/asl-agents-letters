use std::{
    ffi::OsString,
    io::{self, IsTerminal},
    path::Path,
};

use age::secrecy::SecretString;
use asl_app::{
    migration::{self, Selection},
    paths::AppPaths,
};
use asl_types::error::AslError;
use zeroize::Zeroizing;

pub(super) fn run(args: &[OsString]) -> Result<(), AslError> {
    match args {
        [command, expected_agent_id] if command == "import-legacy-root" => {
            let expected_agent_id = expected_agent_id
                .to_str()
                .ok_or(AslError::InvalidIdentity)?;
            asl_app::profile_setup::migrate_legacy_core_profile(expected_agent_id, false)
        }
        [command, expected_agent_id, format]
            if command == "import-legacy-root" && format == "--json" =>
        {
            let expected_agent_id = expected_agent_id
                .to_str()
                .ok_or(AslError::InvalidIdentity)?;
            asl_app::profile_setup::migrate_legacy_core_profile(expected_agent_id, true)
        }
        [command, destination, options @ ..] if command == "export" => {
            let mut selection = Selection::default();
            for option in options {
                match option.to_str() {
                    Some("contacts") => selection.contacts = true,
                    Some("trust") => selection.trust = true,
                    Some("history") => selection.history = true,
                    Some("groups") => selection.groups = true,
                    _ => return Err(AslError::InvalidMessage),
                }
            }
            let root = std::env::var_os("ASL_HOME").ok_or(AslError::InvalidStorageRoot)?;
            let paths = AppPaths::open_existing(Path::new(&root))?;
            migration::export(
                &paths,
                Path::new(destination),
                prompt_passphrase(true)?,
                selection,
            )
        }
        [command, bundle, destination] if command == "import-new" => {
            let result = migration::import_new(
                Path::new(bundle),
                Path::new(destination),
                prompt_passphrase(false)?,
            )?;
            println!(
                "{}",
                serde_json::json!({
                    "agent_id": bs58::encode(result.agent_id.as_bytes()).into_string(),
                    "peer_id": bs58::encode(result.peer_id.as_bytes()).into_string(),
                    "state": "pending_device_registration",
                    "next_steps": [
                        "set ASL_HOME to the imported profile",
                        "run asl-core --identity-registration prepare-directory <new registry sequence>",
                        "run asl-core --identity-registration update <sequence> <state commitment> <deadline>",
                        "submit the update with a verified wallet or sponsor transaction"
                    ]
                })
            );
            Ok(())
        }
        _ => Err(AslError::InvalidMessage),
    }
}

fn prompt_passphrase(confirm: bool) -> Result<SecretString, AslError> {
    if !io::stdin().is_terminal() {
        return Err(AslError::PolicyDenied);
    }
    let passphrase = Zeroizing::new(rpassword::prompt_password("Migration passphrase: ")?);
    if passphrase.is_empty() || passphrase.len() > 1024 {
        return Err(AslError::InvalidMessage);
    }
    if confirm {
        let repeated = Zeroizing::new(rpassword::prompt_password("Repeat passphrase: ")?);
        if *repeated != *passphrase {
            return Err(AslError::InvalidMessage);
        }
    }
    Ok(passphrase.as_str().into())
}
