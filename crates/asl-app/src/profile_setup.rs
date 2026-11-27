use std::{
    env,
    ffi::OsString,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
};

use asl_policy::snapshot_files::ProfileOwner;
use asl_store::{open_store, open_store_read_only};
use asl_types::error::AslError;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::{
    identity::{AgentIdentity, DeviceIdentity},
    identity_onboarding::{
        self, GuidedSetupStatusV1, IdentityOnboardingConfigV1, SetupConfigurationStateV1,
        SetupStageV1,
    },
    network_identity::NetworkIdentityConfigurationV1,
    network_settings::NetworkSettingsV1,
    paths::{AppPaths, validate_existing_components, validate_local_absolute_path},
};

const SETUP_CONFIG_MAX_BYTES: u64 = 64 * 1024;

struct SetupOptions {
    data_directory: Option<PathBuf>,
    network_identity_config: Option<PathBuf>,
    onboarding_config: Option<PathBuf>,
    network_settings: Option<PathBuf>,
    network_seeds: Option<PathBuf>,
    onboard: bool,
    status: bool,
    json: bool,
}

#[derive(Serialize)]
struct SetupReport {
    status: &'static str,
    network_status: &'static str,
    data_directory: String,
    agent_id: String,
    peer_id: String,
    schema_version: u32,
    #[serde(flatten)]
    guidance: GuidedSetupStatusV1,
}

pub fn run(args: &[OsString]) -> Result<(), AslError> {
    let options = parse_args(args)?;
    let data_directory = match options.data_directory.as_ref() {
        Some(path) => path.clone(),
        None => default_data_directory()?,
    };
    validate_data_directory(&data_directory)?;
    if options.status
        && (options.onboard
            || options.network_identity_config.is_some()
            || options.onboarding_config.is_some()
            || options.network_settings.is_some()
            || options.network_seeds.is_some())
    {
        return Err(AslError::InvalidMessage);
    }
    if options.status {
        let paths = AppPaths::open_existing(&data_directory)?;
        return print_guided_report(&paths, true);
    }

    validate_setup_config(&options.network_identity_config, &options.onboarding_config)?;
    let network_settings = options
        .network_settings
        .as_deref()
        .map(|path| {
            validate_setup_config_path(path)?;
            NetworkSettingsV1::load(path)
        })
        .transpose()?;
    let explicit_signed_seeds = options
        .network_seeds
        .as_deref()
        .map(read_setup_config)
        .transpose()?;
    if let (Some(settings), Some(bytes)) = (&network_settings, explicit_signed_seeds.as_deref()) {
        if !settings.bootstrap_multiaddrs.is_empty() {
            return Err(AslError::InvalidIdentity);
        }
        let mut verified_settings = settings.clone();
        verified_settings.apply_signed_seeds(bytes, crate::supervisor::unix_time_ms()?)?;
    }

    let executable = env::current_exe()?;
    let install_directory = executable.parent().ok_or(AslError::SandboxUnavailable)?;
    let core = install_directory.join(format!("asl-core{}", env::consts::EXE_SUFFIX));
    let packaged_seeds = install_directory.join("assets").join("network-seeds.json");
    validate_local_absolute_path(&core)?;
    let metadata = std::fs::symlink_metadata(&core)?;
    if !metadata.is_file() {
        return Err(AslError::SandboxUnavailable);
    }

    run_core(
        &core,
        &data_directory,
        &[
            "--initialize-profile",
            if options.json { "--json" } else { "--text" },
        ],
    )?;
    let paths = AppPaths::open_existing(&data_directory)?;

    let mut effective_network_settings = match &network_settings {
        Some(settings) => settings.clone(),
        None => NetworkSettingsV1::load(&paths.network_settings_configuration())?,
    };
    let now_ms = crate::supervisor::unix_time_ms()?;
    let profile_seeds = paths.network_seeds();
    let signed_seeds = if let Some(bytes) = explicit_signed_seeds {
        Some(bytes)
    } else if effective_network_settings.bootstrap_multiaddrs.is_empty()
        && effective_network_settings.network_seed_public_key.is_some()
        && packaged_seeds.try_exists()?
    {
        let bytes = read_setup_config(&packaged_seeds)?;
        let packaged = effective_network_settings.signed_seed_status(&bytes, now_ms)?;
        let current = effective_network_settings
            .signed_seed_file_status(&profile_seeds, now_ms)
            .ok()
            .flatten();
        if current.as_ref().is_none_or(|current| {
            packaged.generated_at_ms > current.generated_at_ms
                || (packaged.generated_at_ms == current.generated_at_ms
                    && packaged.expires_at_ms > current.expires_at_ms)
        }) {
            Some(bytes)
        } else {
            None
        }
    } else {
        None
    };
    if let Some(bytes) = signed_seeds.as_deref() {
        if !effective_network_settings.bootstrap_multiaddrs.is_empty() {
            return Err(AslError::InvalidIdentity);
        }
        effective_network_settings.apply_signed_seeds(bytes, now_ms)?;
    }

    let mut installs = Vec::new();
    if let Some(settings) = &network_settings {
        let bytes = serde_json::to_vec(settings).map_err(|_| AslError::InvalidIdentity)?;
        installs.push((bytes, paths.network_settings_configuration()));
    }
    if let Some(source) = &options.network_identity_config {
        installs.push((
            read_setup_config(source)?,
            paths.network_identity_configuration(),
        ));
    }
    if let Some(source) = &options.onboarding_config {
        installs.push((
            read_setup_config(source)?,
            paths.identity_onboarding_configuration(),
        ));
    }

    for (bytes, destination) in &installs {
        ensure_setup_bytes_compatible(bytes, destination)?;
    }
    for (bytes, destination) in &installs {
        install_setup_bytes(bytes, destination)?;
    }
    if let Some(bytes) = signed_seeds.as_deref() {
        install_refreshable_setup_bytes(bytes, &profile_seeds)?;
    }

    let onboarding_result = if options.onboard {
        let guidance = identity_onboarding::guided_setup_status(&paths)?;
        if guidance.ready_to_start {
            Ok(())
        } else if guidance.can_resume_onboarding {
            run_core(
                &core,
                &data_directory,
                &["--identity-registration", "onboard"],
            )
        } else {
            Err(AslError::InvalidIdentity)
        }
    } else {
        Ok(())
    };

    print_guided_report(&paths, options.json)?;
    onboarding_result
}

fn run_core(core: &Path, data_directory: &Path, args: &[&str]) -> Result<(), AslError> {
    let output = Command::new(core)
        .args(args)
        .env("ASL_HOME", data_directory)
        .env_remove("ASL_MCP_KEY")
        .env_remove("ASL_MCP_SCOPE")
        .env_remove("ASL_MCP_INBOX_GRANT")
        .env_remove("ASL_MCP_AGENT_PUSH")
        .env_remove("ASL_MCP_EXPRESSIONS")
        .env_remove("ASL_MCP_SEMANTIC_CONTEXTS")
        .env_remove("ASL_MCP_RECOVERY_KEY")
        .env_remove("ASL_MCP_RECOVERY_RESULTS")
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        if !output.stderr.is_empty() {
            eprint!("{}", String::from_utf8_lossy(&output.stderr));
        }
        Err(AslError::InvalidIdentity)
    }
}

fn validate_data_directory(path: &Path) -> Result<(), AslError> {
    validate_local_absolute_path(path)?;
    if path.try_exists()? && !fs::symlink_metadata(path)?.file_type().is_dir() {
        return Err(AslError::InvalidStorageRoot);
    }
    Ok(())
}

fn print_guided_report(paths: &AppPaths, json: bool) -> Result<(), AslError> {
    let identity = AgentIdentity::load_protected(&paths.agent_root_key())?;
    let device = DeviceIdentity::load_protected(&paths.device_key())?;
    let store = open_store_read_only(&paths.existing_state_database()?)?;
    let guidance = identity_onboarding::guided_setup_status(paths)?;
    let network_status = if guidance.network_identity == SetupConfigurationStateV1::Missing {
        "not_evaluated"
    } else if guidance.stage == SetupStageV1::ReadyToJoin {
        "network_identity_ready"
    } else if guidance.stage == SetupStageV1::Blocked {
        "blocked"
    } else {
        "identity_onboarding_pending"
    };
    let report = SetupReport {
        status: "local_identity_ready",
        network_status,
        data_directory: paths.root().to_string_lossy().into_owned(),
        agent_id: bs58::encode(identity.agent_id().as_bytes()).into_string(),
        peer_id: libp2p_identity::PeerId::from_bytes(device.peer_id().as_bytes())
            .map_err(|_| AslError::InvalidIdentity)?
            .to_string(),
        schema_version: store.schema_version(),
        guidance,
    };
    drop(store);

    if json {
        println!(
            "{}",
            serde_json::to_string(&report).map_err(|_| AslError::InvalidMessage)?
        );
    } else {
        let value = serde_json::to_value(&report).map_err(|_| AslError::InvalidMessage)?;
        let prerequisites = value["external_prerequisites"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|item| {
                format!(
                    "- {}: {}",
                    item["name"].as_str().unwrap_or("unknown"),
                    item["state"].as_str().unwrap_or("required")
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        println!(
            "ASL setup stage: {}\nAgentId: {}\nPeerId: {}\nNext action: {}\nExternal prerequisites:\n{}",
            value["stage"].as_str().unwrap_or("blocked"),
            report.agent_id,
            report.peer_id,
            value["next_action"]
                .as_str()
                .unwrap_or("repair_configuration"),
            prerequisites
        );
    }
    Ok(())
}

fn validate_setup_config(
    network_identity: &Option<PathBuf>,
    onboarding: &Option<PathBuf>,
) -> Result<(), AslError> {
    if let Some(path) = network_identity {
        validate_setup_config_path(path)?;
        if NetworkIdentityConfigurationV1::load(path)?.is_none() {
            return Err(AslError::InvalidIdentity);
        }
    }
    if let Some(path) = onboarding {
        validate_setup_config_path(path)?;
        IdentityOnboardingConfigV1::load(path)?;
    }
    Ok(())
}

fn validate_setup_config_path(path: &Path) -> Result<(), AslError> {
    validate_local_absolute_path(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > SETUP_CONFIG_MAX_BYTES {
        return Err(AslError::InvalidIdentity);
    }
    Ok(())
}

fn read_setup_config(source: &Path) -> Result<Vec<u8>, AslError> {
    validate_setup_config_path(source)?;
    let metadata = fs::symlink_metadata(source)?;
    let mut input = fs::File::open(source)?.take(SETUP_CONFIG_MAX_BYTES + 1);
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    input.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > SETUP_CONFIG_MAX_BYTES {
        return Err(AslError::QuotaExceeded);
    }
    Ok(bytes)
}

fn ensure_setup_bytes_compatible(bytes: &[u8], destination: &Path) -> Result<(), AslError> {
    validate_existing_components(destination)?;
    if destination.try_exists()? && read_setup_config(destination)? != bytes {
        return Err(AslError::PolicyVersionConflict);
    }
    Ok(())
}

fn install_setup_bytes(bytes: &[u8], destination: &Path) -> Result<(), AslError> {
    ensure_setup_bytes_compatible(bytes, destination)?;
    if destination.try_exists()? {
        return Ok(());
    }
    let mut output = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)?;
    if let Err(error) = output.write_all(bytes).and_then(|()| output.sync_all()) {
        drop(output);
        let _ = fs::remove_file(destination);
        return Err(error.into());
    }
    Ok(())
}

fn install_refreshable_setup_bytes(bytes: &[u8], destination: &Path) -> Result<(), AslError> {
    validate_existing_components(destination)?;
    if destination.try_exists()? && read_setup_config(destination)? == bytes {
        return Ok(());
    }
    let staging = destination.with_extension(format!("{:032x}.tmp", rand::random::<u128>()));
    {
        let mut output = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&staging)?;
        if let Err(error) = output.write_all(bytes).and_then(|()| output.sync_all()) {
            drop(output);
            let _ = fs::remove_file(&staging);
            return Err(error.into());
        }
    }
    if destination.try_exists()? {
        fs::remove_file(destination)?;
    }
    fs::rename(staging, destination)?;
    Ok(())
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
        &paths,
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
        &paths,
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

fn parse_args(args: &[OsString]) -> Result<SetupOptions, AslError> {
    let mut options = SetupOptions {
        data_directory: None,
        network_identity_config: None,
        onboarding_config: None,
        network_settings: None,
        network_seeds: None,
        onboard: false,
        status: false,
        json: false,
    };
    let mut index = 0;
    while index < args.len() {
        let value = args[index].to_str();
        match value {
            Some("--data-directory") if options.data_directory.is_none() => {
                options.data_directory = Some(PathBuf::from(next_arg(args, &mut index)?));
            }
            Some("--network-identity-config") if options.network_identity_config.is_none() => {
                options.network_identity_config = Some(PathBuf::from(next_arg(args, &mut index)?));
            }
            Some("--identity-onboarding-config") if options.onboarding_config.is_none() => {
                options.onboarding_config = Some(PathBuf::from(next_arg(args, &mut index)?));
            }
            Some("--network-settings") if options.network_settings.is_none() => {
                options.network_settings = Some(PathBuf::from(next_arg(args, &mut index)?));
            }
            Some("--network-seeds") if options.network_seeds.is_none() => {
                options.network_seeds = Some(PathBuf::from(next_arg(args, &mut index)?));
            }
            Some("--onboard") if !options.onboard => options.onboard = true,
            Some("--status") if !options.status => options.status = true,
            Some("--json") if !options.json => options.json = true,
            _ => return Err(AslError::InvalidMessage),
        }
        index += 1;
    }
    if options.onboard && options.status {
        return Err(AslError::InvalidMessage);
    }
    Ok(options)
}

fn next_arg<'a>(args: &'a [OsString], index: &mut usize) -> Result<&'a OsString, AslError> {
    *index += 1;
    args.get(*index).ok_or(AslError::InvalidMessage)
}

fn print_report(
    paths: &AppPaths,
    root: &str,
    agent: &AgentIdentity,
    device: &DeviceIdentity,
    schema_version: u32,
    network_status: &'static str,
    json: bool,
) -> Result<(), AslError> {
    let guidance = identity_onboarding::guided_setup_status(paths)?;
    let report = SetupReport {
        status: "local_identity_ready",
        network_status,
        data_directory: root.to_owned(),
        agent_id: bs58::encode(agent.agent_id().as_bytes()).into_string(),
        peer_id: libp2p_identity::PeerId::from_bytes(device.peer_id().as_bytes())
            .map_err(|_| AslError::InvalidIdentity)?
            .to_string(),
        schema_version,
        guidance,
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

fn default_data_directory() -> Result<PathBuf, AslError> {
    let local_app_data = env::var_os("LOCALAPPDATA").ok_or(AslError::InvalidStorageRoot)?;
    let root = PathBuf::from(local_app_data);
    if !root.is_absolute() {
        return Err(AslError::InvalidStorageRoot);
    }
    Ok(root.join("ASL").join("profile"))
}
