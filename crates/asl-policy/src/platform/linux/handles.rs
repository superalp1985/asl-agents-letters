pub(crate) mod snapshot;

use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;

use asl_types::error::AslError;
use rustix::fs::OFlags;

use super::filesystem::{
    PinnedDirectory, file_identity, io_error, open_regular, pin_directory, read_file,
    shares_component,
};
use crate::paths::FileIdentity;

pub(crate) fn read_local_selection(
    path: &Path,
    protected_root: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>, AslError> {
    let parent = pin_directory(path.parent().ok_or(AslError::NotFound)?)?;
    let protected = pin_directory(protected_root)?;
    if shares_component(&parent, &protected) {
        return Err(AslError::PolicyDenied);
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(AslError::NotFound)?;
    read_file(parent.leaf(), name, max_bytes)
}

pub(crate) struct SourceRoot {
    directory: PinnedDirectory,
    protected: PinnedDirectory,
}

pub(crate) struct SourceFile {
    file: File,
    identity: FileIdentity,
    len: u64,
    stamp: FileStamp,
    _pins: Vec<Arc<File>>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct FileStamp {
    modified_seconds: i64,
    modified_nanos: i64,
    changed_seconds: i64,
    changed_nanos: i64,
}

impl SourceRoot {
    pub(crate) fn open(root: &Path, protected_root: &Path) -> Result<Self, AslError> {
        let protected = pin_directory(protected_root)?;
        let directory = pin_directory(root)?;
        if shares_component(&directory, &protected) {
            return Err(AslError::NotFound);
        }
        Ok(Self {
            directory,
            protected,
        })
    }

    pub(crate) fn identity(&self) -> &FileIdentity {
        self.directory.identity()
    }

    pub(crate) fn create_new_file(&self, name: &str) -> Result<File, AslError> {
        open_regular(
            self.directory.leaf(),
            name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
        )
    }

    pub(crate) fn open_existing_write_file(&self, name: &str) -> Result<File, AslError> {
        open_regular(self.directory.leaf(), name, OFlags::RDWR)
    }

    pub(crate) fn file_identity(&self, file: &File) -> Result<FileIdentity, AslError> {
        let identity = file_identity(file)?;
        if identity.volume_serial != self.directory.identity().volume_serial {
            return Err(AslError::NotFound);
        }
        Ok(identity)
    }

    pub(crate) fn rename_new(
        &self,
        file: &File,
        current: &str,
        target: &str,
    ) -> Result<(), AslError> {
        let before = file_identity(file)?;
        rustix::fs::renameat_with(
            self.directory.leaf(),
            current,
            self.directory.leaf(),
            target,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(io_error)?;
        let after = file_identity(file)?;
        if after != before {
            return Err(AslError::PolicyDenied);
        }
        Ok(())
    }

    pub(crate) fn unlink_if_identity(
        &self,
        name: &str,
        expected: &FileIdentity,
    ) -> Result<(), AslError> {
        let current = open_regular(self.directory.leaf(), name, OFlags::RDONLY)?;
        let metadata = current.metadata()?;
        if metadata.nlink() != 1 || &file_identity(&current)? != expected {
            return Err(AslError::PolicyDenied);
        }
        let quarantine = format!(".asl-remove-{:032x}", rand::random::<u128>());
        rustix::fs::renameat_with(
            self.directory.leaf(),
            name,
            self.directory.leaf(),
            &quarantine,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(io_error)?;
        let moved = open_regular(self.directory.leaf(), &quarantine, OFlags::RDONLY)?;
        if &file_identity(&moved)? != expected {
            return Err(AslError::PolicyDenied);
        }
        rustix::fs::unlinkat(
            self.directory.leaf(),
            &quarantine,
            rustix::fs::AtFlags::empty(),
        )
        .map_err(io_error)?;
        self.directory.leaf().sync_all().map_err(io_error)
    }

    pub(crate) fn open_file(
        &self,
        components: &[String],
        max_file_bytes: u64,
    ) -> Result<SourceFile, AslError> {
        let (last, directories) = components.split_last().ok_or(AslError::NotFound)?;
        let mut pins = self.directory.pins().collect::<Vec<_>>();
        let mut current = self.directory.clone();
        for component in directories {
            current = current.child(component, false)?;
            pins.push(current.leaf().try_clone().map(Arc::new)?);
        }
        let file = open_regular(current.leaf(), last, OFlags::RDONLY)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.len() > max_file_bytes
            || metadata.dev() != self.directory.identity().volume_serial
        {
            return Err(AslError::NotFound);
        }
        pins.extend(self.protected.pins());
        Ok(SourceFile {
            identity: file_identity(&file)?,
            len: metadata.len(),
            stamp: FileStamp::from_metadata(&metadata),
            file,
            _pins: pins,
        })
    }
}

impl SourceFile {
    pub(crate) fn identity(&self) -> &FileIdentity {
        &self.identity
    }

    pub(crate) fn len(&self) -> u64 {
        self.len
    }
}

impl Read for SourceFile {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.check_current()?;
        let mut temporary = vec![0; buffer.len()];
        let count = self.file.read(&mut temporary)?;
        if self.check_current().is_err() {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        buffer[..count].copy_from_slice(&temporary[..count]);
        Ok(count)
    }
}

impl SourceFile {
    fn check_current(&self) -> io::Result<()> {
        let metadata = self.file.metadata()?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.len() != self.len
            || FileStamp::from_metadata(&metadata) != self.stamp
            || file_identity(&self.file).ok().as_ref() != Some(&self.identity)
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(())
    }
}

impl FileStamp {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            modified_seconds: metadata.mtime(),
            modified_nanos: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanos: metadata.ctime_nsec(),
        }
    }
}
