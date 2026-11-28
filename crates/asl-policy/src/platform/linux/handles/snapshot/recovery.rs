use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use asl_types::error::AslError;
use rustix::fs::{FlockOperation, Mode, OFlags, fchmod, flock, unlinkat};
use rustix::io::Errno;

use super::super::super::filesystem::{
    PinnedDirectory, file_identity, io_error, open_regular, pin_directory, stat_child,
};
use super::ObjectNames;

pub(crate) struct Owner {
    _marker: File,
    home: PinnedDirectory,
}

impl Owner {
    pub(crate) fn acquire(home: &Path, id: [u8; 16]) -> Result<Option<Self>, AslError> {
        let home = pin_directory(home)?;
        let state = home.child("state", false)?;
        let dir = state.child("import-owners", true)?;
        let name = format!("{}.lock", hex::encode(id));
        let marker = open_regular(dir.leaf(), &name, OFlags::RDWR | OFlags::CREATE)?;
        let metadata = marker.metadata()?;
        if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() != 0 {
            return Err(AslError::InvalidPolicyState);
        }
        fchmod(&marker, Mode::RUSR | Mode::WUSR).map_err(io_error)?;
        match flock(&marker, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => {}
            Err(Errno::WOULDBLOCK) => return Ok(None),
            Err(error) => return Err(io_error(error)),
        }
        Ok(Some(Self {
            _marker: marker,
            home,
        }))
    }

    fn targets(&self, id: [u8; 32]) -> Result<[Option<Target>; 2], AslError> {
        let names = ObjectNames::new(id);
        Ok([
            Target::open(&self.home, "snapshots", &names.shard, names.blob)?,
            Target::open(&self.home, "manifests", &names.shard, names.manifest)?,
        ])
    }

    pub(crate) fn require_absent(&self, id: [u8; 32]) -> Result<(), AslError> {
        let names = ObjectNames::new(id);
        for (base, name) in [("snapshots", names.blob), ("manifests", names.manifest)] {
            let base = match self.home.child(base, false) {
                Ok(base) => base,
                Err(AslError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                    continue;
                }
                Err(error) => return Err(error),
            };
            let shard = match base.child(&names.shard, false) {
                Ok(shard) => shard,
                Err(AslError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                    continue;
                }
                Err(error) => return Err(error),
            };
            if stat_child(shard.leaf(), &name)?.is_some() {
                return Err(AslError::InvalidPolicyState);
            }
        }
        Ok(())
    }

    pub(crate) fn clean(&self, id: [u8; 32]) -> Result<(), AslError> {
        let targets = self.targets(id)?;
        for target in targets.iter().flatten() {
            let metadata = target.file.metadata()?;
            if !metadata.is_file() || metadata.nlink() != 1 {
                return Err(AslError::InvalidPolicyState);
            }
        }
        for target in targets.into_iter().flatten() {
            target.remove()?;
        }
        Ok(())
    }
}

struct Target {
    file: File,
    parent: PinnedDirectory,
    name: String,
}

impl Target {
    fn open(
        home: &PinnedDirectory,
        base: &str,
        shard: &str,
        name: String,
    ) -> Result<Option<Self>, AslError> {
        let base = match home.child(base, false) {
            Ok(base) => base,
            Err(AslError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let shard = match base.child(shard, false) {
            Ok(shard) => shard,
            Err(AslError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let file = match open_regular(shard.leaf(), &name, OFlags::RDONLY) {
            Ok(file) => file,
            Err(AslError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        Ok(Some(Self {
            file,
            parent: shard,
            name,
        }))
    }

    fn remove(self) -> Result<(), AslError> {
        let identity = file_identity(&self.file)?;
        let quarantine = format!(".asl-remove-{:032x}", rand::random::<u128>());
        rustix::fs::renameat_with(
            self.parent.leaf(),
            &self.name,
            self.parent.leaf(),
            &quarantine,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(io_error)?;
        let moved = open_regular(self.parent.leaf(), &quarantine, OFlags::RDONLY)?;
        if file_identity(&moved)? != identity {
            return Err(AslError::InvalidPolicyState);
        }
        unlinkat(
            self.parent.leaf(),
            &quarantine,
            rustix::fs::AtFlags::empty(),
        )
        .map_err(io_error)?;
        self.parent.leaf().sync_all().map_err(io_error)?;
        drop(self.file);
        if stat_child(self.parent.leaf(), &self.name)?.is_some() {
            return Err(AslError::InvalidPolicyState);
        }
        Ok(())
    }
}
