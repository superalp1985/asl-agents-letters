use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use asl_app::identity::{AgentIdentity, DeviceIdentity, verify_device_certificate};
use asl_types::{
    error::AslError,
    ids::{AgentId, PeerId},
};
use sha3::{Digest, Keccak256};

static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../work/test-identity");
        fs::create_dir_all(&base).unwrap();
        let path = base.join(format!(
            "identity-{}-{}",
            std::process::id(),
            NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn root_identity_issues_verifiable_device_certificates() {
    let root = AgentIdentity::generate().unwrap();
    let device = DeviceIdentity::generate().unwrap();
    let mut preimage = b"ASL-Agent-v1".to_vec();
    preimage.extend_from_slice(&root.controller_address());
    let expected_agent_id: [u8; 32] = Keccak256::digest(preimage).into();
    assert_eq!(root.agent_id().0, expected_agent_id);

    let certificate = root
        .issue_device_certificate(device.peer_id(), 1, 100, 10_000)
        .unwrap();

    verify_device_certificate(
        &certificate,
        root.agent_id(),
        &device.peer_id(),
        root.controller_address(),
        1,
        101,
    )
    .unwrap();
}

#[test]
fn device_certificate_rejects_tampering_wrong_identity_expiry_and_rollback() {
    let root = AgentIdentity::generate().unwrap();
    let device = DeviceIdentity::generate().unwrap();
    let other_device = DeviceIdentity::generate().unwrap();
    let certificate = root
        .issue_device_certificate(device.peer_id(), 4, 100, 10_000)
        .unwrap();
    let verify = |certificate: &asl_types::protocol::DeviceCertificate,
                  agent_id,
                  peer_id: &PeerId,
                  minimum_serial,
                  now_ms| {
        verify_device_certificate(
            certificate,
            agent_id,
            peer_id,
            root.controller_address(),
            minimum_serial,
            now_ms,
        )
    };

    assert!(matches!(
        verify(&certificate, root.agent_id(), &device.peer_id(), 5, 101),
        Err(AslError::InvalidDeviceCertificate)
    ));
    assert!(matches!(
        verify(&certificate, AgentId([9; 32]), &device.peer_id(), 1, 101),
        Err(AslError::InvalidDeviceCertificate)
    ));
    assert!(matches!(
        verify(
            &certificate,
            root.agent_id(),
            &other_device.peer_id(),
            1,
            101
        ),
        Err(AslError::InvalidDeviceCertificate)
    ));
    assert!(matches!(
        verify(&certificate, root.agent_id(), &device.peer_id(), 1, 10_000),
        Err(AslError::ExpiredMessage)
    ));

    let mut tampered = certificate.clone();
    tampered.expires_at_ms += 1;
    assert!(matches!(
        verify(&tampered, root.agent_id(), &device.peer_id(), 1, 101),
        Err(AslError::InvalidDeviceCertificate)
    ));

    let mut invalid_recovery_id = certificate;
    invalid_recovery_id.signature.0[64] = 26;
    assert!(matches!(
        verify(
            &invalid_recovery_id,
            root.agent_id(),
            &device.peer_id(),
            1,
            101
        ),
        Err(AslError::InvalidDeviceCertificate)
    ));
}

#[cfg(windows)]
#[test]
fn protected_identity_files_reload_without_changing_identity_or_device() {
    let directory = TestDirectory::new();
    let root_path = directory.0.join("agent-root.dpapi");
    let device_path = directory.0.join("device-key.dpapi");
    let root = AgentIdentity::generate().unwrap();
    let device = DeviceIdentity::generate().unwrap();
    let agent_id = root.agent_id();
    let controller_address = root.controller_address();
    let peer_id = device.peer_id();

    root.save_protected_new(&root_path).unwrap();
    device.save_protected_new(&device_path).unwrap();

    let loaded_root = AgentIdentity::load_protected(&root_path).unwrap();
    let loaded_device = DeviceIdentity::load_protected(&device_path).unwrap();
    assert_eq!(loaded_root.agent_id(), agent_id);
    assert_eq!(loaded_root.controller_address(), controller_address);
    assert_eq!(loaded_device.peer_id(), peer_id);
    assert!(root.save_protected_new(&root_path).is_err());
}

#[cfg(windows)]
#[test]
fn missing_or_corrupt_protected_identity_is_not_replaced() {
    let directory = TestDirectory::new();
    let missing_path = directory.0.join("missing.dpapi");
    assert!(AgentIdentity::load_protected(&missing_path).is_err());

    let path = directory.0.join("agent-root.dpapi");
    let identity = AgentIdentity::generate().unwrap();
    identity.save_protected_new(&path).unwrap();
    let mut ciphertext = fs::read(&path).unwrap();
    *ciphertext.last_mut().unwrap() ^= 1;
    fs::write(&path, ciphertext).unwrap();
    assert!(AgentIdentity::load_protected(&path).is_err());
}

#[cfg(windows)]
#[test]
fn device_identity_is_created_once_and_reloaded() {
    let directory = TestDirectory::new();
    let path = directory.0.join("device-key.dpapi");

    let first = DeviceIdentity::load_or_create_protected(&path).unwrap();
    let peer_id = first.peer_id();
    assert!(path.is_file());

    let second = DeviceIdentity::load_or_create_protected(&path).unwrap();
    assert_eq!(second.peer_id(), peer_id);
}

#[cfg(windows)]
#[test]
fn agent_root_identity_is_created_once_and_reloaded() {
    let directory = TestDirectory::new();
    let path = directory.0.join("agent-root.dpapi");

    let first = AgentIdentity::load_or_create_protected(&path).unwrap();
    let agent_id = first.agent_id();
    let controller = first.controller_address();
    assert!(path.is_file());

    let second = AgentIdentity::load_or_create_protected(&path).unwrap();
    assert_eq!(second.agent_id(), agent_id);
    assert_eq!(second.controller_address(), controller);
}

#[cfg(windows)]
#[test]
fn corrupt_device_identity_is_not_replaced() {
    let directory = TestDirectory::new();
    let path = directory.0.join("device-key.dpapi");
    DeviceIdentity::generate()
        .unwrap()
        .save_protected_new(&path)
        .unwrap();
    let mut ciphertext = fs::read(&path).unwrap();
    *ciphertext.last_mut().unwrap() ^= 1;
    fs::write(&path, &ciphertext).unwrap();

    assert!(DeviceIdentity::load_or_create_protected(&path).is_err());
    assert_eq!(fs::read(&path).unwrap(), ciphertext);
}

#[cfg(windows)]
#[test]
fn corrupt_agent_root_identity_is_not_replaced() {
    let directory = TestDirectory::new();
    let path = directory.0.join("agent-root.dpapi");
    AgentIdentity::generate()
        .unwrap()
        .save_protected_new(&path)
        .unwrap();
    let mut ciphertext = fs::read(&path).unwrap();
    *ciphertext.last_mut().unwrap() ^= 1;
    fs::write(&path, ciphertext).unwrap();
    let damaged = fs::read(&path).unwrap();

    assert!(AgentIdentity::load_or_create_protected(&path).is_err());
    assert_eq!(fs::read(&path).unwrap(), damaged);
}

#[cfg(target_os = "linux")]
#[test]
fn protected_identity_storage_is_available_on_linux() {
    let directory = TestDirectory::new();
    let identity = AgentIdentity::generate().unwrap();
    let path = directory.0.join("identity.protected");
    identity.save_protected_new(&path).unwrap();
    let loaded = AgentIdentity::load_protected(&path).unwrap();
    assert_eq!(loaded.agent_id(), identity.agent_id());
}
