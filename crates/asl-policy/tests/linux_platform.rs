#![cfg(target_os = "linux")]

use std::{
    fs,
    io::{Read, Write},
    path::Path,
    time::Duration,
};

use asl_policy::{
    SourceGrant, SourceRules, WriteGrant, open_authorized_source, protect_secret,
    sandbox::{InheritedPipes, SandboxLauncher, SandboxLimits, SandboxRole},
    snapshot_files::ProfileOwner,
    unprotect_secret, validate_storage_root,
};
use asl_types::error::AslError;

#[test]
fn protected_secrets_round_trip_and_reject_tampering() {
    let plaintext = b"linux protected secret payload";
    let ciphertext = protect_secret(plaintext).unwrap();
    assert_ne!(ciphertext, plaintext);
    assert_eq!(unprotect_secret(&ciphertext).unwrap().as_slice(), plaintext);

    let mut tampered = ciphertext;
    let last = tampered.last_mut().unwrap();
    *last ^= 1;
    assert!(matches!(
        unprotect_secret(&tampered),
        Err(AslError::KeyProtectionFailed)
    ));
}

#[test]
fn storage_root_and_file_grants_reject_symlink_escape() {
    let workspace = tempfile::tempdir().unwrap();
    let home = workspace.path().join("home");
    fs::create_dir(&home).unwrap();
    validate_storage_root(&home).unwrap();

    let linked_home = workspace.path().join("linked-home");
    std::os::unix::fs::symlink(&home, &linked_home).unwrap();
    assert!(validate_storage_root(&linked_home).is_err());

    let source = workspace.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("sample.txt"), b"authorized").unwrap();
    let outside = workspace.path().join("outside.txt");
    fs::write(&outside, b"outside").unwrap();
    std::os::unix::fs::symlink(&outside, source.join("escape.txt")).unwrap();

    let grant = SourceGrant::open(
        &source,
        &home,
        SourceRules::new(["txt".into()], 1024).unwrap(),
    )
    .unwrap();
    let mut file = open_authorized_source(&grant, Path::new("sample.txt")).unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"authorized");
    assert!(open_authorized_source(&grant, Path::new("escape.txt")).is_err());

    let nested_source = home.join("nested");
    fs::create_dir(&nested_source).unwrap();
    assert!(
        SourceGrant::open(
            &nested_source,
            &home,
            SourceRules::new(["txt".into()], 1024).unwrap()
        )
        .is_err()
    );
}

#[test]
fn write_grants_create_and_finalize_only_inside_the_pinned_directory() {
    let workspace = tempfile::tempdir().unwrap();
    let home = workspace.path().join("home");
    let incoming = workspace.path().join("incoming");
    fs::create_dir(&home).unwrap();
    fs::create_dir(&incoming).unwrap();
    let grant = WriteGrant::open(&incoming, &home).unwrap();
    let mut file = grant.create_new(Path::new("part.bin")).unwrap();
    file.write_all(b"complete file").unwrap();
    file.sync_all().unwrap();
    let identity = file.identity().unwrap();
    grant.rename_new(&mut file, Path::new("final.bin")).unwrap();
    file.retain();
    assert_eq!(
        fs::read(incoming.join("final.bin")).unwrap(),
        b"complete file"
    );
    assert!(!incoming.join("part.bin").exists());

    let existing = grant
        .open_existing(Path::new("final.bin"), &identity)
        .unwrap();
    assert_eq!(existing.identity().unwrap(), identity);
    assert!(grant.create_new(Path::new("../escape.bin")).is_err());
}

#[test]
fn profile_owner_is_exclusive_until_dropped() {
    let workspace = tempfile::tempdir().unwrap();
    let home = workspace.path().join("home");
    fs::create_dir(&home).unwrap();
    fs::create_dir(home.join("state")).unwrap();

    let owner = ProfileOwner::core(&home).unwrap();
    assert!(matches!(
        ProfileOwner::core(&home),
        Err(AslError::InvalidPolicyState)
    ));
    drop(owner);
    let _reacquired = ProfileOwner::core(&home).unwrap();
}

#[test]
fn linux_sandbox_clears_environment_and_can_be_terminated() {
    let probe = Path::new(env!("CARGO_BIN_EXE_asl-sandbox-probe")).to_path_buf();
    let launcher =
        SandboxLauncher::new(probe.clone(), probe.clone(), probe).expect("probe launcher");
    let (mut broker, inherited) = InheritedPipes::new().unwrap();
    let limits = SandboxLimits::for_role(SandboxRole::Worker);
    let mut child = launcher
        .spawn_sandbox(SandboxRole::Worker, inherited, limits)
        .expect("real Linux sandbox");
    broker.input.write_all(&[5]).unwrap();
    drop(broker.input);
    let mut response = Vec::new();
    broker.output.read_to_end(&mut response).unwrap();
    assert_eq!(response, [0, 0, 0]);
    let status = child
        .wait_timeout(Duration::from_secs(2))
        .unwrap()
        .expect("probe must exit");
    assert_eq!(status, 0);

    let (mut broker, inherited) = InheritedPipes::new().unwrap();
    let mut child = launcher
        .spawn_sandbox(
            SandboxRole::Worker,
            inherited,
            SandboxLimits::for_role(SandboxRole::Worker),
        )
        .unwrap();
    broker.input.write_all(&[6]).unwrap();
    drop(broker.input);
    let mut marker = [0u8; 1];
    broker.output.read_exact(&mut marker).unwrap();
    assert_eq!(marker, [42]);
    assert!(
        child
            .wait_timeout(Duration::from_millis(100))
            .unwrap()
            .is_none()
    );
    child.terminate().unwrap();
}
