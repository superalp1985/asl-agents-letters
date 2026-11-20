#![cfg(windows)]

use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

use asl_policy::WriteGrant;
use asl_types::error::AslError;
use tempfile::tempdir;

#[test]
fn write_grant_is_pinned_create_new_only_and_cleans_uncommitted_files() {
    let temp = tempdir().unwrap();
    let protected = temp.path().join("home");
    let root = temp.path().join("derived");
    fs::create_dir(&protected).unwrap();
    fs::create_dir(&root).unwrap();
    let grant = WriteGrant::open(&root, &protected).unwrap();

    {
        let mut file = grant.create_new(Path::new("record.json")).unwrap();
        file.write_all(b"record").unwrap();
        file.sync_all().unwrap();
    }
    assert!(!root.join("record.json").exists());

    let mut file = grant.create_new(Path::new("record.json")).unwrap();
    file.write_all(b"record").unwrap();
    file.sync_all().unwrap();
    file.retain();
    drop(file);
    assert_eq!(fs::read(root.join("record.json")).unwrap(), b"record");
    assert!(matches!(
        grant.create_new(Path::new("record.json")),
        Err(AslError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists
    ));
    assert!(grant.create_new(Path::new("../escape.json")).is_err());
    assert!(grant.create_new(Path::new("nested/record.json")).is_err());
}

#[test]
fn write_grant_reopens_only_the_same_file_and_renames_without_replacement() {
    let temp = tempdir().unwrap();
    let protected = temp.path().join("home");
    let root = temp.path().join("inbox");
    fs::create_dir(&protected).unwrap();
    fs::create_dir(&root).unwrap();
    let grant = WriteGrant::open(&root, &protected).unwrap();

    let mut part = grant.create_new(Path::new("transfer.part")).unwrap();
    part.set_len(6).unwrap();
    part.seek(SeekFrom::Start(2)).unwrap();
    part.write_all(b"asl").unwrap();
    part.sync_all().unwrap();
    let identity = part.identity().unwrap();
    part.retain();
    drop(part);

    let mut resumed = grant
        .open_existing(Path::new("transfer.part"), &identity)
        .unwrap();
    let mut bytes = Vec::new();
    resumed.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, [0, 0, b'a', b's', b'l', 0]);

    fs::write(root.join("final.bin"), b"keep").unwrap();
    assert!(
        grant
            .rename_new(&mut resumed, Path::new("final.bin"))
            .is_err()
    );
    grant
        .rename_new(&mut resumed, Path::new("completed.bin"))
        .unwrap();
    assert_eq!(fs::read(root.join("completed.bin")).unwrap(), bytes);
    assert_eq!(fs::read(root.join("final.bin")).unwrap(), b"keep");

    let wrong_identity = asl_policy::FileIdentity {
        volume_serial: identity.volume_serial,
        file_id: [0x7f; 16],
    };
    assert!(
        grant
            .open_existing(Path::new("completed.bin"), &wrong_identity)
            .is_err()
    );
}

#[test]
fn open_write_file_keeps_its_authorized_directory_pinned() {
    let temp = tempdir().unwrap();
    let protected = temp.path().join("home");
    let root = temp.path().join("inbox");
    let moved = temp.path().join("moved-inbox");
    fs::create_dir(&protected).unwrap();
    fs::create_dir(&root).unwrap();

    let mut file = {
        let grant = WriteGrant::open(&root, &protected).unwrap();
        let mut file = grant.create_new(Path::new("transfer.part")).unwrap();
        file.write_all(b"content").unwrap();
        file.retain();
        file
    };
    assert!(fs::rename(&root, &moved).is_err());
    file.remove().unwrap();
    drop(file);
    fs::rename(&root, &moved).unwrap();
}
