#![cfg(windows)]

use std::{fs, path::Path, process::Command};

use k256::ecdsa::SigningKey;
use serde_json::Value;
use sha3::{Digest, Keccak256};
use tempfile::TempDir;

struct PackageFixture {
    _root: TempDir,
    install: std::path::PathBuf,
    local_app_data: std::path::PathBuf,
}

impl PackageFixture {
    fn new() -> Self {
        let root = tempfile::tempdir_in(std::env::temp_dir()).unwrap();
        let install = root.path().join("ASL install with spaces");
        let local_app_data = root.path().join("Local App Data With Spaces");
        fs::create_dir(&install).unwrap();
        fs::create_dir(&local_app_data).unwrap();
        for (source, name) in [
            (env!("CARGO_BIN_EXE_asl"), "asl.exe"),
            (env!("CARGO_BIN_EXE_asl-core"), "asl-core.exe"),
        ] {
            fs::copy(source, install.join(name)).unwrap();
        }
        Self {
            _root: root,
            install,
            local_app_data,
        }
    }

    fn setup(&self, args: &[&str]) -> std::process::Output {
        Command::new(self.install.join("asl.exe"))
            .args(["setup"])
            .args(args)
            .arg("--json")
            .env("LOCALAPPDATA", &self.local_app_data)
            .env_remove("ASL_HOME")
            .env_remove("ASL_MCP_KEY")
            .env_remove("ASL_MCP_SCOPE")
            .env_remove("ASL_MCP_AGENT_PUSH")
            .output()
            .unwrap()
    }

    fn initialize_core(&self, profile: &Path) -> std::process::Output {
        Command::new(self.install.join("asl-core.exe"))
            .args(["--initialize-profile", "--json"])
            .env("ASL_HOME", profile)
            .output()
            .unwrap()
    }

    fn core(&self) -> std::path::PathBuf {
        self.install.join("asl-core.exe")
    }

    fn migrate_legacy_seed(&self, profile: &Path, agent_id: &str) -> std::process::Output {
        Command::new(self.install.join("asl-core.exe"))
            .args(["--migration", "import-legacy-root", agent_id, "--json"])
            .env("ASL_HOME", profile)
            .output()
            .unwrap()
    }
}

fn assert_success(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn agent_id_from_root_seed(seed: &[u8; 32]) -> String {
    let key = SigningKey::from_slice(seed).unwrap();
    let digest = Keccak256::digest(&key.verifying_key().to_sec1_point(false).as_bytes()[1..]);
    let address = &digest[12..];
    let mut preimage = b"ASL-Agent-v1".to_vec();
    preimage.extend_from_slice(address);
    bs58::encode(Keccak256::digest(preimage)).into_string()
}

#[test]
fn core_owns_first_identity_creation_and_setup_only_returns_its_report() {
    let package = PackageFixture::new();
    let profile = package.local_app_data.join("ASL").join("profile");

    let first = package.setup(&[]);
    assert_success(&first);
    let first: Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(first["status"], "local_identity_ready");
    assert_eq!(first["network_status"], "not_evaluated");
    assert_eq!(
        Path::new(first["data_directory"].as_str().unwrap())
            .canonicalize()
            .unwrap(),
        profile.canonicalize().unwrap()
    );
    assert_eq!(
        bs58::decode(first["agent_id"].as_str().unwrap())
            .into_vec()
            .unwrap()
            .len(),
        32
    );
    let peer_id: libp2p_identity::PeerId = first["peer_id"].as_str().unwrap().parse().unwrap();
    assert_eq!(peer_id.to_string(), first["peer_id"].as_str().unwrap());
    assert_eq!(first["schema_version"].as_u64(), Some(50));
    assert!(profile.join("identity/agent-root.dpapi").is_file());
    assert!(profile.join("identity/device-key.dpapi").is_file());
    assert!(profile.join("state/asl.sqlite3").is_file());

    let root_before = fs::read(profile.join("identity/agent-root.dpapi")).unwrap();
    let device_before = fs::read(profile.join("identity/device-key.dpapi")).unwrap();
    let second = package.setup(&[]);
    assert_success(&second);
    let second: Value = serde_json::from_slice(&second.stdout).unwrap();
    assert_eq!(second["agent_id"], first["agent_id"]);
    assert_eq!(second["peer_id"], first["peer_id"]);
    assert_eq!(
        fs::read(profile.join("identity/agent-root.dpapi")).unwrap(),
        root_before
    );
    assert_eq!(
        fs::read(profile.join("identity/device-key.dpapi")).unwrap(),
        device_before
    );
}

#[test]
fn explicit_profile_overrides_os_default_and_relative_path_is_rejected() {
    let package = PackageFixture::new();
    let selected = package.local_app_data.join("Selected Data With Spaces");
    fs::create_dir(&selected).unwrap();

    let result = package.setup(&["--data-directory", selected.to_str().unwrap()]);
    assert_success(&result);
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(
        Path::new(report["data_directory"].as_str().unwrap())
            .canonicalize()
            .unwrap(),
        selected.canonicalize().unwrap()
    );
    assert!(!package.local_app_data.join("ASL/profile").exists());

    let invalid = package.setup(&["--data-directory", "relative-profile"]);
    assert!(!invalid.status.success());
    assert!(!package.local_app_data.join("ASL/profile").exists());
}

#[test]
fn setup_does_not_create_a_profile_when_the_core_initializer_is_missing() {
    let package = PackageFixture::new();
    let profile = package.local_app_data.join("No Core profile");
    fs::remove_file(package.core()).unwrap();

    let result = package.setup(&["--data-directory", profile.to_str().unwrap()]);
    assert!(!result.status.success());
    assert!(!profile.exists());
}

#[test]
fn corrupt_existing_identity_is_not_replaced_by_setup() {
    let package = PackageFixture::new();
    let profile = package.local_app_data.join("Existing profile");
    assert_success(&package.initialize_core(&profile));
    let root_key = profile.join("identity/agent-root.dpapi");
    let mut corrupt = fs::read(&root_key).unwrap();
    corrupt[0] ^= 0x80;
    fs::write(&root_key, &corrupt).unwrap();

    let result = package.setup(&["--data-directory", profile.to_str().unwrap()]);
    assert!(!result.status.success());
    assert_eq!(fs::read(root_key).unwrap(), corrupt);
}

#[test]
fn ordinary_core_initialization_does_not_probe_or_consume_legacy_root_seed() {
    let package = PackageFixture::new();
    let profile = package.local_app_data.join("Legacy profile");
    let legacy_directory = profile.join("agent");
    fs::create_dir_all(&legacy_directory).unwrap();
    let seed_path = legacy_directory.join("root.seed");
    let seed = [0x5a; 32];
    fs::write(&seed_path, seed).unwrap();
    let legacy_agent_id = agent_id_from_root_seed(&seed);

    let result = package.initialize_core(&profile);
    assert_success(&result);
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    let active = asl_app::identity::AgentIdentity::load_protected(
        &profile.join("identity/agent-root.dpapi"),
    )
    .unwrap();
    assert_eq!(
        report["agent_id"],
        bs58::encode(active.agent_id().as_bytes()).into_string()
    );
    assert_ne!(report["agent_id"], legacy_agent_id);
    assert_eq!(fs::read(seed_path).unwrap(), seed);
}

#[test]
fn legacy_seed_migration_requires_expected_agent_id_and_retires_only_that_seed() {
    let package = PackageFixture::new();
    let profile = package.local_app_data.join("Explicit legacy migration");
    let legacy_directory = profile.join("agent");
    fs::create_dir_all(&legacy_directory).unwrap();
    let seed_path = legacy_directory.join("root.seed");
    let seed = [0x24; 32];
    fs::write(&seed_path, seed).unwrap();
    let expected = agent_id_from_root_seed(&seed);

    let mismatch = package.migrate_legacy_seed(&profile, "11111111111111111111111111111111");
    assert!(!mismatch.status.success());
    assert_eq!(fs::read(seed_path).unwrap(), seed);
    assert!(!profile.join("identity/agent-root.dpapi").exists());

    let imported = package.migrate_legacy_seed(&profile, &expected);
    assert_success(&imported);
    let report: Value = serde_json::from_slice(&imported.stdout).unwrap();
    assert_eq!(report["agent_id"], expected);
    assert_eq!(
        report["network_status"],
        "local_identity_ready_pending_registration"
    );
    assert!(!profile.join("agent/root.seed").exists());
    assert!(profile.join("identity/device-key.dpapi").is_file());

    let active_before = fs::read(profile.join("identity/agent-root.dpapi")).unwrap();
    fs::write(profile.join("agent/root.seed"), [0x25; 32]).unwrap();
    let replacement = package.migrate_legacy_seed(&profile, &expected);
    assert!(!replacement.status.success());
    assert_eq!(
        fs::read(profile.join("agent/root.seed")).unwrap(),
        [0x25; 32]
    );
    assert_eq!(
        fs::read(profile.join("identity/agent-root.dpapi")).unwrap(),
        active_before
    );
}

#[test]
fn legacy_seed_retirement_waits_until_device_creation_can_complete() {
    let package = PackageFixture::new();
    let profile = package.local_app_data.join("Interrupted legacy migration");
    let legacy_directory = profile.join("agent");
    fs::create_dir_all(&legacy_directory).unwrap();
    let seed_path = legacy_directory.join("root.seed");
    let seed = [0x2a; 32];
    fs::write(&seed_path, seed).unwrap();
    let expected = agent_id_from_root_seed(&seed);
    fs::create_dir_all(profile.join("identity/device-key.dpapi")).unwrap();

    let interrupted = package.migrate_legacy_seed(&profile, &expected);
    assert!(!interrupted.status.success());
    assert_eq!(fs::read(&seed_path).unwrap(), seed);
    let imported = asl_app::identity::AgentIdentity::load_protected(
        &profile.join("identity/agent-root.dpapi"),
    )
    .unwrap();
    assert_eq!(
        bs58::encode(imported.agent_id().as_bytes()).into_string(),
        expected
    );

    fs::remove_dir(profile.join("identity/device-key.dpapi")).unwrap();
    let resumed = package.migrate_legacy_seed(&profile, &expected);
    assert_success(&resumed);
    assert!(!seed_path.exists());
    assert!(profile.join("identity/device-key.dpapi").is_file());
}

#[test]
fn legacy_seed_migration_resumes_after_atomic_retirement_rename() {
    let package = PackageFixture::new();
    let profile = package.local_app_data.join("Retiring legacy migration");
    let legacy_directory = profile.join("agent");
    fs::create_dir_all(&legacy_directory).unwrap();
    let retiring_path = legacy_directory.join("root.seed.retiring");
    let seed = [0x37; 32];
    fs::write(&retiring_path, seed).unwrap();
    let expected = agent_id_from_root_seed(&seed);

    let resumed = package.migrate_legacy_seed(&profile, &expected);

    assert_success(&resumed);
    assert!(!retiring_path.exists());
    let identity = asl_app::identity::AgentIdentity::load_protected(
        &profile.join("identity/agent-root.dpapi"),
    )
    .unwrap();
    assert_eq!(
        bs58::encode(identity.agent_id().as_bytes()).into_string(),
        expected
    );
}

#[test]
fn legacy_seed_migration_rejects_ambiguous_original_and_retiring_files() {
    let package = PackageFixture::new();
    let profile = package.local_app_data.join("Ambiguous legacy migration");
    let legacy_directory = profile.join("agent");
    fs::create_dir_all(&legacy_directory).unwrap();
    let original_path = legacy_directory.join("root.seed");
    let retiring_path = legacy_directory.join("root.seed.retiring");
    let original = [0x41; 32];
    let retiring = [0x42; 32];
    fs::write(&original_path, original).unwrap();
    fs::write(&retiring_path, retiring).unwrap();
    let expected = agent_id_from_root_seed(&original);

    let result = package.migrate_legacy_seed(&profile, &expected);

    assert!(!result.status.success());
    assert_eq!(fs::read(original_path).unwrap(), original);
    assert_eq!(fs::read(retiring_path).unwrap(), retiring);
    assert!(!profile.join("identity/agent-root.dpapi").exists());
}
