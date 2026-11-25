use std::{env, ffi::OsString, path::PathBuf, process::Command};

use asl_policy::snapshot_files::ProfileOwner;
use asl_store::open_store;
use asl_types::error::AslError;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::{
    identity::{AgentIdentity, DeviceIdentity},
    paths::{AppPaths, validate_existing_components},
};

#[derive(Serialize)]
struct SetupReport {
    status: &'static str,
    network_status: &'static str,
    data_directory: String,
    agent_id: String,
    peer_id: String,
    schema_version: u32,
}

pub fn run(args: &[OsString]) -> Result<(), AslError> {
    let (data_directory, json) = parse_args(args)?;
    let data_directory = match data_directory {
        Some(path) => path,
        None => default_data_directory()?,
    };
    let core = env::current_exe()?
        .parent()
        .ok_or(AslError::SandboxUnavailable)?
        .join("asl-core.exe");
    let metadata = std::fs::symlink_metadata(&core)?;
    if !metadata.is_file() {
        return Err(AslError::SandboxUnavailable);
    }

    let status = Command::new(core)
        .args(["--initialize-profile"])
        .arg(if json { "--json" } else { "--text" })
        .env("ASL_HOME", data_directory)
        .env_remove("ASL_MCP_KEY")
        .env_remove("ASL_MCP_SCOPE")
        .env_remove("ASL_MCP_INBOX_GRANT")
        .env_remove("ASL_MCP_AGENT_PUSH")
        .env_remove("ASL_MCP_EXPRESSIONS")
        .env_remove("ASL_MCP_SEMANTIC_CONTEXTS")
        .env_remove("ASL_MCP_RECOVERY_KEY")
        .env_remove("ASL_MCP_RECOVERY_RESULTS")
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(AslError::InvalidIdentity)
    }
}

pub fn initialize_core_profile(json: bool) -> Result<(), AslError> {
    let root = env::var_os("ASL_HOME").ok_or(AslError::InvalidStorageRoot)?;
    let root = PathBuf::from(root);
    let root_text = root
        .to_str()
        .ok_or(AslError::InvalidStorageRoot)?
        .to_owned();
    let paths = AppPaths::open(&root)?;
    let _owner = ProfileOwner::core(paths.dos_root())?;
    let store = open_store(&paths.state().join("asl.sqlite3"))?;
    let (agent, device) = ensure_local_identity(&paths)?;
    print_report(
        &root_text,
        &agent,
        &device,
        store.schema_version(),
        "not_evaluated",
        json,
    )?;
    drop(store);
    Ok(())
}

pub fn migrate_legacy_core_profile(expected_agent_id: &str, json: bool) -> Result<(), AslError> {
    let expected_bytes = bs58::decode(expected_agent_id)
        .into_vec()
        .map_err(|_| AslError::InvalidIdentity)?;
    let expected_agent = asl_types::ids::AgentId(
        expected_bytes
            .try_into()
            .map_err(|_| AslError::InvalidIdentity)?,
    );
    if bs58::encode(expected_agent.as_bytes()).into_string() != expected_agent_id {
        return Err(AslError::InvalidIdentity);
    }

    let root = env::var_os("ASL_HOME").ok_or(AslError::InvalidStorageRoot)?;
    let root = PathBuf::from(root);
    let root_text = root
        .to_str()
        .ok_or(AslError::InvalidStorageRoot)?
        .to_owned();
    let paths = AppPaths::open(&root)?;
    let _owner = ProfileOwner::core(paths.dos_root())?;
    let store = open_store(&paths.state().join("asl.sqlite3"))?;

    validate_existing_components(&paths.agent_root_key())?;
    let root_identity = match std::fs::symlink_metadata(paths.agent_root_key()) {
        Ok(metadata) if metadata.file_type().is_file() => {
            let identity = AgentIdentity::load_protected(&paths.agent_root_key())?;
            if identity.agent_id() != expected_agent {
                return Err(AslError::InvalidIdentity);
            }
            Some(identity)
        }
        Ok(_) => return Err(AslError::InvalidIdentity),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };

    let mut legacy = asl_policy::snapshot_files::open_legacy_root_seed(paths.dos_root())?;
    let seed = Zeroizing::new(legacy.read_seed()?);
    let imported = AgentIdentity::from_migration_seed(&seed[..])?;
    if imported.agent_id() != expected_agent {
        return Err(AslError::InvalidIdentity);
    }

    let identity = match root_identity {
        Some(identity) => identity,
        None => {
            imported.save_protected_new(&paths.agent_root_key())?;
            AgentIdentity::load_protected(&paths.agent_root_key())?
        }
    };
    if identity.agent_id() != imported.agent_id() {
        return Err(AslError::InvalidIdentity);
    }
    let device = DeviceIdentity::load_or_create_protected(&paths.device_key())?;
    legacy.retire()?;
    print_report(
        &root_text,
        &identity,
        &device,
        store.schema_version(),
        "local_identity_ready_pending_registration",
        json,
    )?;
    drop(store);
    Ok(())
}

fn print_report(
    root: &str,
    agent: &AgentIdentity,
    device: &DeviceIdentity,
    schema_version: u32,
    network_status: &'static str,
    json: bool,
) -> Result<(), AslError> {
    let report = SetupReport {
        status: "local_identity_ready",
        network_status,
        data_directory: root.to_owned(),
        agent_id: bs58::encode(agent.agent_id().as_bytes()).into_string(),
        peer_id: libp2p_identity::PeerId::from_bytes(device.peer_id().as_bytes())
            .map_err(|_| AslError::InvalidIdentity)?
            .to_string(),
        schema_version,
    };

    if json {
        println!(
            "{}",
            serde_json::to_string(&report).map_err(|_| AslError::InvalidMessage)?
        );
    } else {
        println!(
            "ASL local identity is ready.\nAgentId: {}\nPeerId: {}\nNetwork admission: not evaluated",
            report.agent_id, report.peer_id
        );
    }
    Ok(())
}

pub(crate) fn ensure_local_identity(
    paths: &AppPaths,
) -> Result<(AgentIdentity, DeviceIdentity), AslError> {
    let agent = AgentIdentity::load_or_create_protected(&paths.agent_root_key())?;
    let device = DeviceIdentity::load_or_create_protected(&paths.device_key())?;
    Ok((agent, device))
}

fn parse_args(args: &[OsString]) -> Result<(Option<PathBuf>, bool), AslError> {
    let mut directory = None;
    let mut json = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].to_str() {
            Some("--data-directory") if directory.is_none() && index + 1 < args.len() => {
                index += 1;
                directory = Some(PathBuf::from(&args[index]));
            }
            Some("--json") if !json => json = true,
            _ => return Err(AslError::InvalidMessage),
        }
        index += 1;
    }

    Ok((directory, json))
}

fn default_data_directory() -> Result<PathBuf, AslError> {
    let local_app_data = env::var_os("LOCALAPPDATA").ok_or(AslError::InvalidStorageRoot)?;
    let root = PathBuf::from(local_app_data);
    if !root.is_absolute() {
        return Err(AslError::InvalidStorageRoot);
    }
    Ok(root.join("ASL").join("profile"))
}
