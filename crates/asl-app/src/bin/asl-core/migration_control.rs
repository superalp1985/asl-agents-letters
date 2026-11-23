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
        [command, destination, options @ ..] if command == "export" => {
            let mut selection = Selection::default();
            for option in options {
                match option.to_str() {
                    Some("contacts") => selection.contacts = true,
                    Some("trust") => selection.trust = true,
                    Some("history") => selection.history = true,
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
                    "state": "pending_device_registration"
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
