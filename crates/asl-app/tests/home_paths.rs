use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use asl_app::paths::AppPaths;

#[test]
fn rejects_relative_storage_root() {
    assert!(AppPaths::open(Path::new("relative")).is_err());
}

#[test]
fn rejects_unc_storage_root() {
    assert!(AppPaths::open(Path::new(r"\\server\share\asl")).is_err());
}

#[test]
fn creates_storage_layout_on_ntfs() {
    let base = PathBuf::from(r"E:\ASL\work\test-fs");
    fs::create_dir_all(&base).unwrap();
    let id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = base.join(format!("home-{}-{id}", std::process::id()));

    let paths = AppPaths::open(&root).unwrap();
    assert!(paths.root().starts_with(base.canonicalize().unwrap()));
    assert_eq!(paths.state(), paths.root().join("state"));
    assert_eq!(paths.snapshots(), paths.root().join("snapshots"));
    assert_eq!(paths.incoming(), paths.root().join("incoming"));
    assert_eq!(paths.logs(), paths.root().join("logs"));

    let created_root = paths.root().to_path_buf();
    drop(paths);
    assert!(created_root.starts_with(base.canonicalize().unwrap()));
    fs::remove_dir_all(created_root).unwrap();
}

#[test]
fn rejects_unavailable_drive() {
    if !Path::new(r"Z:\").exists() {
        assert!(AppPaths::open(Path::new(r"Z:\asl-data")).is_err());
    }
}
