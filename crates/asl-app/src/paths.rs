use std::fs::{self, Metadata};
#[cfg(windows)]
use std::path::Prefix;
use std::path::{Component, Path, PathBuf};

use asl_policy::validate_storage_root;
use asl_types::error::AslError;

pub struct AppPaths {
    root: PathBuf,
    dos_root: PathBuf,
    state: PathBuf,
    identity: PathBuf,
    provider_credentials: PathBuf,
    snapshots: PathBuf,
    incoming: PathBuf,
    logs: PathBuf,
}

impl AppPaths {
    pub fn open(root: &Path) -> Result<Self, AslError> {
        Self::open_with(root, true)
    }

    pub fn open_existing(root: &Path) -> Result<Self, AslError> {
        Self::open_with(root, false)
    }

    fn open_with(root: &Path, create: bool) -> Result<Self, AslError> {
        if !root.is_absolute()
            || !is_local_storage_path(root)
            || root
                .components()
                .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(AslError::InvalidStorageRoot);
        }

        validate_storage_root(root)?;
        validate_existing_components(root)?;
        if create {
            fs::create_dir_all(root)?;
        } else if !fs::metadata(root)?.is_dir() {
            return Err(AslError::InvalidStorageRoot);
        }

        // Preserve the checked drive-absolute input for handle-based traversal.
        // canonicalize() returns a verbatim path, a different Windows namespace.
        let dos_root = root.to_path_buf();
        let root = root.canonicalize()?;
        validate_existing_components(&root)?;
        if !fs::metadata(&root)?.is_dir() {
            return Err(AslError::InvalidStorageRoot);
        }

        let child = if create { create_child } else { existing_child };
        let state = child(&root, "state")?;
        let identity = child(&root, "identity")?;
        let provider_credentials = child(&root, "credentials")?;
        let snapshots = child(&root, "snapshots")?;
        let incoming = child(&root, "incoming")?;
        let logs = child(&root, "logs")?;

        Ok(Self {
            root,
            dos_root,
            state,
            identity,
            provider_credentials,
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

    pub fn network_seeds(&self) -> PathBuf {
        self.state.join("network-seeds.json")
    }

    pub fn existing_state_database(&self) -> Result<PathBuf, AslError> {
        let database = self.state.join("asl.sqlite3");
        validate_existing_components(&database)?;
        if !fs::metadata(&database)?.is_file() {
            return Err(AslError::InvalidStorageRoot);
        }
        Ok(database)
    }

    pub fn identity(&self) -> &Path {
        &self.identity
    }

    pub fn device_key(&self) -> PathBuf {
        #[cfg(windows)]
        {
            self.identity.join("device-key.dpapi")
        }
        #[cfg(not(windows))]
        {
            self.identity.join("device-key.protected")
        }
    }

    pub fn agent_root_key(&self) -> PathBuf {
        #[cfg(windows)]
        {
            self.identity.join("agent-root.dpapi")
        }
        #[cfg(not(windows))]
        {
            self.identity.join("agent-root.protected")
        }
    }

    pub fn signed_device_directory(&self) -> PathBuf {
        self.identity.join("device-directory.cbor")
    }

    pub fn network_identity_configuration(&self) -> PathBuf {
        self.state.join("network-identity-v1.json")
    }

    pub fn identity_onboarding_configuration(&self) -> PathBuf {
        self.state.join("identity-onboarding-v1.json")
    }

    pub fn identity_onboarding_status(&self) -> PathBuf {
        self.state.join("identity-onboarding-status-v1.json")
    }

    pub fn network_settings_configuration(&self) -> PathBuf {
        self.state.join("network-settings-v1.json")
    }

    pub fn model_provider_configuration(&self) -> PathBuf {
        self.state.join("model-providers-v1.json")
    }

    pub fn ui_configuration(&self) -> PathBuf {
        self.state.join("ui-settings-v1.json")
    }

    pub fn provider_credentials(&self) -> &Path {
        &self.provider_credentials
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

fn is_local_storage_path(path: &Path) -> bool {
    #[cfg(windows)]
    {
        matches!(
            path.components().next(),
            Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_))
        )
    }
    #[cfg(not(windows))]
    {
        matches!(path.components().next(), Some(Component::RootDir))
    }
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

fn existing_child(root: &Path, name: &str) -> Result<PathBuf, AslError> {
    let path = root.join(name);
    validate_existing_components(&path)?;
    if !fs::metadata(&path)?.is_dir() {
        return Err(AslError::InvalidStorageRoot);
    }
    Ok(path)
}

pub(crate) fn validate_local_absolute_path(path: &Path) -> Result<(), AslError> {
    if !path.is_absolute()
        || !is_local_storage_path(path)
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(AslError::InvalidStorageRoot);
    }
    validate_existing_components(path)
}

pub(crate) fn validate_existing_components(path: &Path) -> Result<(), AslError> {
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
