use std::fs::{self, Metadata};
use std::path::{Component, Path, PathBuf, Prefix};

use asl_policy::validate_storage_root;
use asl_types::error::AslError;

pub struct AppPaths {
    root: PathBuf,
    dos_root: PathBuf,
    state: PathBuf,
    identity: PathBuf,
    snapshots: PathBuf,
    incoming: PathBuf,
    logs: PathBuf,
}

impl AppPaths {
    pub fn open(root: &Path) -> Result<Self, AslError> {
        if !root.is_absolute()
            || !is_local_drive(root)
            || root
                .components()
                .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(AslError::InvalidStorageRoot);
        }

        validate_storage_root(root)?;
        validate_existing_components(root)?;
        fs::create_dir_all(root)?;

        // Preserve the checked drive-absolute input for handle-based traversal.
        // canonicalize() returns a verbatim path, a different Windows namespace.
        let dos_root = root.to_path_buf();
        let root = root.canonicalize()?;
        validate_existing_components(&root)?;
        if !fs::metadata(&root)?.is_dir() {
            return Err(AslError::InvalidStorageRoot);
        }

        let state = create_child(&root, "state")?;
        let identity = create_child(&root, "identity")?;
        let snapshots = create_child(&root, "snapshots")?;
        let incoming = create_child(&root, "incoming")?;
        let logs = create_child(&root, "logs")?;

        Ok(Self {
            root,
            dos_root,
            state,
            identity,
            snapshots,
            incoming,
            logs,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn dos_root(&self) -> &Path {
        &self.dos_root
    }

    pub fn state(&self) -> &Path {
        &self.state
    }

    pub fn identity(&self) -> &Path {
        &self.identity
    }

    pub fn device_key(&self) -> PathBuf {
        self.identity.join("device-key.dpapi")
    }

    pub fn agent_root_key(&self) -> PathBuf {
        self.identity.join("agent-root.dpapi")
    }

    pub fn signed_device_directory(&self) -> PathBuf {
        self.identity.join("device-directory.cbor")
    }

    pub fn network_identity_configuration(&self) -> PathBuf {
        self.state.join("network-identity-v1.json")
    }

    pub fn snapshots(&self) -> &Path {
        &self.snapshots
    }

    pub fn incoming(&self) -> &Path {
        &self.incoming
    }

    pub fn logs(&self) -> &Path {
        &self.logs
    }
}

fn is_local_drive(path: &Path) -> bool {
    matches!(
        path.components().next(),
        Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_))
    )
}

fn create_child(root: &Path, name: &str) -> Result<PathBuf, AslError> {
    let path = root.join(name);
    validate_existing_components(&path)?;
    fs::create_dir_all(&path)?;
    validate_existing_components(&path)?;
    if !fs::metadata(&path)?.is_dir() {
        return Err(AslError::InvalidStorageRoot);
    }
    Ok(path)
}

fn validate_existing_components(path: &Path) -> Result<(), AslError> {
    let mut components = path.ancestors().collect::<Vec<_>>();
    components.reverse();

    for component in components {
        match fs::symlink_metadata(component) {
            Ok(metadata) if is_reparse_point(&metadata) => {
                return Err(AslError::InvalidStorageRoot);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn is_reparse_point(metadata: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }

    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}
