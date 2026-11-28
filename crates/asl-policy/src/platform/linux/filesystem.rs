use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path};
use std::sync::Arc;

use asl_types::error::AslError;
use rustix::fs::{
    Access, AtFlags, Mode, OFlags, ResolveFlags, fchmod, mkdirat, openat, openat2, statat,
};
use rustix::io::Errno;

use crate::paths::{FileIdentity, validated_relative};

const NFS_SUPER_MAGIC: u64 = 0x6969;
const SMB_SUPER_MAGIC: u64 = 0x517b;
const CIFS_SUPER_MAGIC: u64 = 0xff53_4d42;
const SMB2_SUPER_MAGIC: u64 = 0xfe53_4d42;
const FUSE_SUPER_MAGIC: u64 = 0x6573_5546;
const AFS_SUPER_MAGIC: u64 = 0x5346_414f;
const CEPH_SUPER_MAGIC: u64 = 0x00c3_6400;
const NINE_P_SUPER_MAGIC: u64 = 0x0102_1997;

#[derive(Clone)]
pub(crate) struct PinnedDirectory {
    pins: Vec<Arc<File>>,
    identity: FileIdentity,
}

impl PinnedDirectory {
    pub(crate) fn identity(&self) -> &FileIdentity {
        &self.identity
    }

    pub(crate) fn leaf(&self) -> &File {
        self.pins.last().expect("a pinned directory has a leaf")
    }

    pub(crate) fn child(&self, name: &str, create: bool) -> Result<Self, AslError> {
        validate_name(name).map_err(|_| AslError::InvalidStorageRoot)?;
        let file = open_directory(self.leaf(), name, create)?;
        let identity = file_identity(&file)?;
        if identity.volume_serial != self.identity.volume_serial {
            return Err(AslError::InvalidStorageRoot);
        }
        let mut pins = self.pins.clone();
        pins.push(Arc::new(file));
        Ok(Self { pins, identity })
    }

    pub(crate) fn pins(&self) -> impl Iterator<Item = Arc<File>> + '_ {
        self.pins.iter().cloned()
    }
}

pub(crate) fn pin_directory(path: &Path) -> Result<PinnedDirectory, AslError> {
    if !path.is_absolute() || path == Path::new("/") {
        return Err(AslError::InvalidStorageRoot);
    }
    let mut pins = vec![Arc::new(open_root()?)];
    let mut identity = file_identity(pins[0].as_ref())?;
    for component in components(path)? {
        let file = open_directory(pins.last().expect("root pin").as_ref(), &component, false)?;
        identity = file_identity(&file)?;
        pins.push(Arc::new(file));
    }
    Ok(PinnedDirectory { pins, identity })
}

pub(crate) fn ensure_private_directory(path: &Path) -> Result<File, AslError> {
    if !path.is_absolute() {
        return Err(AslError::InvalidStorageRoot);
    }
    let mut current = open_root()?;
    let components = components(path)?;
    let last = components.len().saturating_sub(1);
    for (index, component) in components.iter().enumerate() {
        let next = open_directory(&current, component, true)?;
        if index == last {
            fchmod(&next, Mode::RUSR | Mode::WUSR | Mode::XUSR).map_err(io_error)?;
            let metadata = next.metadata()?;
            if metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.permissions().mode() & 0o077 != 0
            {
                return Err(AslError::PolicyDenied);
            }
        }
        current = next;
    }
    Ok(current)
}

pub fn validate_storage_root(path: &Path) -> Result<(), AslError> {
    let components = components(path).map_err(|_| AslError::InvalidStorageRoot)?;
    let mut current = open_root().map_err(|_| AslError::InvalidStorageRoot)?;
    for component in components {
        match open_directory(&current, &component, false) {
            Ok(next) => current = next,
            Err(AslError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                validate_writable_local_directory(&current)?;
                return Ok(());
            }
            Err(_) => return Err(AslError::InvalidStorageRoot),
        }
    }
    let metadata = current.metadata().map_err(io_error)?;
    if !metadata.is_dir() {
        return Err(AslError::InvalidStorageRoot);
    }
    validate_writable_local_directory(&current)?;
    Ok(())
}

pub(crate) fn read_file(parent: &File, name: &str, max_bytes: usize) -> Result<Vec<u8>, AslError> {
    use std::io::Read;

    validate_name(name).map_err(|_| AslError::NotFound)?;
    let file = open_regular(parent, name, OFlags::RDONLY | OFlags::CLOEXEC)?;
    let metadata = file.metadata().map_err(io_error)?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(AslError::NotFound);
    }
    let length = usize::try_from(metadata.len()).map_err(|_| AslError::NotFound)?;
    if length > max_bytes {
        return Err(AslError::QuotaExceeded);
    }
    let mut bytes = Vec::with_capacity(length);
    (&file)
        .take(max_bytes.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() != length || bytes.len() > max_bytes {
        return Err(AslError::InvalidMessage);
    }
    Ok(bytes)
}

pub(crate) fn open_regular(parent: &File, name: &str, flags: OFlags) -> Result<File, AslError> {
    validate_name(name).map_err(|_| AslError::NotFound)?;
    let flags = flags | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    let mode = if flags.contains(OFlags::CREATE) {
        Mode::RUSR | Mode::WUSR
    } else {
        Mode::empty()
    };
    let fd = match openat2(parent, name, flags, mode, safe_resolve_flags()) {
        Ok(fd) => fd,
        Err(Errno::NOSYS) => openat(parent, name, flags, mode).map_err(io_error)?,
        Err(error) => return Err(io_error(error)),
    };
    Ok(File::from(fd))
}

pub(crate) fn open_directory(parent: &File, name: &str, create: bool) -> Result<File, AslError> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    match open_directory_once(parent, name, flags) {
        Ok(file) => Ok(file),
        Err(AslError::Io(error)) if error.kind() == io::ErrorKind::NotFound && create => {
            match mkdirat(parent, name, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
                Ok(()) | Err(Errno::EXIST) => {}
                Err(error) => return Err(io_error(error)),
            }
            let file = open_directory_once(parent, name, flags)?;
            fchmod(&file, Mode::RUSR | Mode::WUSR | Mode::XUSR).map_err(io_error)?;
            Ok(file)
        }
        Err(error) => Err(error),
    }
}

fn open_directory_once(parent: &File, name: &str, flags: OFlags) -> Result<File, AslError> {
    validate_name(name).map_err(|_| AslError::NotFound)?;
    let fd = match openat2(parent, name, flags, Mode::empty(), safe_resolve_flags()) {
        Ok(fd) => fd,
        Err(Errno::NOSYS) => openat(parent, name, flags, Mode::empty()).map_err(io_error)?,
        Err(error) => return Err(io_error(error)),
    };
    Ok(File::from(fd))
}

pub(crate) fn file_identity(file: &File) -> Result<FileIdentity, AslError> {
    let metadata = file.metadata().map_err(io_error)?;
    let mut file_id = [0u8; 16];
    file_id[..8].copy_from_slice(&metadata.ino().to_le_bytes());
    Ok(FileIdentity {
        volume_serial: metadata.dev(),
        file_id,
    })
}

pub(crate) fn stat_child(parent: &File, name: &str) -> Result<Option<FileIdentity>, AslError> {
    validate_name(name).map_err(|_| AslError::NotFound)?;
    match statat(
        parent,
        name,
        AtFlags::SYMLINK_NOFOLLOW | AtFlags::NO_AUTOMOUNT,
    ) {
        Ok(stat) => {
            if stat.st_nlink != 1 {
                return Err(AslError::InvalidPolicyState);
            }
            let mut file_id = [0u8; 16];
            file_id[..8].copy_from_slice(&stat.st_ino.to_le_bytes());
            file_id[8..].copy_from_slice(&((stat.st_ino as u128 >> 64) as u64).to_le_bytes());
            Ok(Some(FileIdentity {
                volume_serial: stat.st_dev,
                file_id,
            }))
        }
        Err(Errno::NOENT) => Ok(None),
        Err(error) => Err(io_error(error)),
    }
}

pub(crate) fn shares_component(left: &PinnedDirectory, right: &PinnedDirectory) -> bool {
    fn contains(prefix: &PinnedDirectory, path: &PinnedDirectory) -> bool {
        if prefix.pins.len() > path.pins.len() {
            return false;
        }
        prefix.pins.iter().zip(&path.pins).all(|(prefix, path)| {
            match (file_identity(prefix), file_identity(path)) {
                (Ok(prefix), Ok(path)) => prefix == path,
                _ => true,
            }
        })
    }
    contains(left, right) || contains(right, left)
}

pub(crate) fn io_error(error: impl Into<io::Error>) -> AslError {
    error.into().into()
}

pub(crate) fn safe_resolve_flags() -> ResolveFlags {
    ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS
}

fn open_root() -> Result<File, AslError> {
    let fd = rustix::fs::open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io_error)?;
    Ok(File::from(fd))
}

fn components(path: &Path) -> Result<Vec<String>, AslError> {
    let mut result = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(value) => {
                let value = value.to_str().ok_or(AslError::InvalidStorageRoot)?;
                validate_name(value).map_err(|_| AslError::InvalidStorageRoot)?;
                result.push(value.to_owned());
            }
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(AslError::InvalidStorageRoot);
            }
        }
    }
    if result.is_empty() {
        return Err(AslError::InvalidStorageRoot);
    }
    Ok(result)
}

fn validate_name(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.as_bytes().contains(&b'/')
        || name.as_bytes().contains(&0)
        || OsStr::new(name).to_string_lossy().len() > 255
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut normalized = validated_relative(Path::new(name))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid path component"))?;
    if normalized.len() != 1 || normalized.pop().as_deref() != Some(name) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok(())
}

fn is_remote_filesystem(kind: u64) -> bool {
    matches!(
        kind,
        NFS_SUPER_MAGIC
            | SMB_SUPER_MAGIC
            | CIFS_SUPER_MAGIC
            | SMB2_SUPER_MAGIC
            | FUSE_SUPER_MAGIC
            | AFS_SUPER_MAGIC
            | CEPH_SUPER_MAGIC
            | NINE_P_SUPER_MAGIC
    )
}

fn validate_writable_local_directory(directory: &File) -> Result<(), AslError> {
    let statfs = rustix::fs::fstatfs(directory).map_err(io_error)?;
    if is_remote_filesystem(statfs.f_type as u64) {
        return Err(AslError::InvalidStorageRoot);
    }
    rustix::fs::accessat(directory, ".", Access::WRITE_OK, AtFlags::EACCESS)
        .map_err(|_| AslError::InvalidStorageRoot)?;
    Ok(())
}
