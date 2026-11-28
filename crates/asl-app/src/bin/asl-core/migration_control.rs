use std::{
    ffi::OsString,
    io::{self, IsTerminal},
    path::Path,
};

use age::secrecy::SecretString;
use asl_app::{
    identity::{AgentIdentity, DeviceIdentity},
    identity_registration::{
        IdentityRegistrationRequest, default_deadline, prepare_device_directory,
    },
    migration::{self, Selection},
    network_identity::NetworkIdentityConfigurationV1,
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
                    "migration": result.migration,
                    "next_steps": [
                        "if migration.source_device is present, authorize that exact old PeerId with --migration authorize-old-device-revoke",
                        "run asl setup with explicit trusted network and onboarding configuration and --onboard",
                        "check completion with asl setup --status"
                    ]
                })
            );
            Ok(())
        }
        [command, destination, peer_id] if command == "authorize-old-device-revoke" => {
            let peer_id = peer_id.to_str().ok_or(AslError::InvalidMessage)?;
            let paths = AppPaths::open_existing(Path::new(destination))?;
            let status = migration::authorize_old_device_revocation(&paths, peer_id)?;
            println!(
                "{}",
                serde_json::to_string(&status).map_err(|_| AslError::InvalidMessage)?
            );
            Ok(())
        }
        [command, destination] if command == "status" => {
            let paths = AppPaths::open_existing(Path::new(destination))?;
            let status = migration::status(&paths)?;
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "schema": "asl-identity-migration-status-v1",
                    "migration": status
                }))
                .map_err(|_| AslError::InvalidMessage)?
            );
            Ok(())
        }
        [command, destination, sequence] if command == "registration-request" => {
            let sequence = sequence
                .to_str()
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|value| *value > 1)
                .ok_or(AslError::InvalidMessage)?;
            prepare_registration_request(Path::new(destination), sequence)
        }
        [command, destination, sequence, deadline] if command == "revoke-request" => {
            let sequence = sequence
                .to_str()
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|value| *value > 1)
                .ok_or(AslError::InvalidMessage)?;
            let deadline = deadline
                .to_str()
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|value| *value > 0)
                .ok_or(AslError::InvalidMessage)?;
            prepare_revoke_request(Path::new(destination), sequence, deadline)
        }
        _ => Err(AslError::InvalidMessage),
    }
}

fn prepare_registration_request(destination: &Path, sequence: u64) -> Result<(), AslError> {
    let paths = AppPaths::open_existing(destination)?;
    let identity = AgentIdentity::load_protected(&paths.agent_root_key())?;
    let device = DeviceIdentity::load_protected(&paths.device_key())?;
    let (bytes, commitment) =
        prepare_device_directory(&identity, &device, sequence, unix_time_ms()?)?;
    if std::fs::symlink_metadata(paths.signed_device_directory()).is_err() {
        std::fs::write(paths.signed_device_directory(), bytes)?;
    }
    let configuration =
        NetworkIdentityConfigurationV1::load(&paths.network_identity_configuration())?
            .ok_or(AslError::InvalidIdentity)?;
    let request = IdentityRegistrationRequest::build_update(
        &identity,
        configuration.resolver.deployment,
        commitment,
        sequence,
        default_deadline()?,
    )?;
    println!(
        "{}",
        serde_json::to_string(&request).map_err(|_| AslError::InvalidMessage)?
    );
    Ok(())
}

fn prepare_revoke_request(
    destination: &Path,
    sequence: u64,
    deadline: u64,
) -> Result<(), AslError> {
    let paths = AppPaths::open_existing(destination)?;
    let identity = AgentIdentity::load_protected(&paths.agent_root_key())?;
    let configuration =
        NetworkIdentityConfigurationV1::load(&paths.network_identity_configuration())?
            .ok_or(AslError::InvalidIdentity)?;
    let request = IdentityRegistrationRequest::build_revoke(
        &identity,
        configuration.resolver.deployment,
        sequence,
        deadline,
    )?;
    println!(
        "{}",
        serde_json::to_string(&request).map_err(|_| AslError::InvalidMessage)?
    );
    Ok(())
}

fn unix_time_ms() -> Result<u64, AslError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| AslError::ExpiredMessage)?
        .as_millis()
        .try_into()
        .map_err(|_| AslError::InvalidMessage)
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
