use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;

use asl_types::error::AslError;
use asl_types::manifest::CHUNK_SIZE;
use rustix::fs::{
    FlockOperation, Mode, OFlags, RenameFlags, fchmod, flock, renameat_with, unlinkat,
};

use super::super::filesystem::{
    PinnedDirectory, file_identity, io_error, open_regular, pin_directory,
};
use crate::paths::FileIdentity;

pub(crate) use recovery::Owner;

mod recovery;

pub(crate) fn pin_state(home: &Path) -> Result<PinnedDirectory, AslError> {
    pin_directory(home)?.child("state", false)
}

pub(crate) fn open_exclusive_marker(state: &PinnedDirectory, name: &str) -> Result<File, AslError> {
    let file = open_regular(state.leaf(), name, OFlags::RDWR | OFlags::CREATE)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() != 0 {
        return Err(AslError::InvalidPolicyState);
    }
    fchmod(&file, Mode::RUSR | Mode::WUSR).map_err(io_error)?;
    flock(&file, FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| AslError::InvalidPolicyState)?;
    Ok(file)
}

struct ObjectNames {
    shard: String,
    blob: String,
    manifest: String,
}

impl ObjectNames {
    fn new(id: [u8; 32]) -> Self {
        let hex = hex::encode(id);
        Self {
            shard: hex[..2].to_owned(),
            blob: format!("{hex}.blob"),
            manifest: format!("{hex}.mnf"),
        }
    }
}

pub(crate) struct ObjectFiles {
    blob: Object,
    manifest: Object,
    _incoming: PinnedDirectory,
    snapshots: PinnedDirectory,
    manifests: PinnedDirectory,
}

pub(crate) struct SnapshotReader {
    blob: File,
    manifest: File,
    blob_identity: FileIdentity,
    manifest_identity: FileIdentity,
    blob_len: u64,
    manifest_len: u64,
    _pins: Vec<Arc<File>>,
}

impl SnapshotReader {
    pub(crate) fn open(home: &Path, id: [u8; 32]) -> Result<Self, AslError> {
        let home = pin_directory(home)?;
        let names = ObjectNames::new(id);
        let snapshots = home.child("snapshots", false)?;
        let snapshot_shard = snapshots.child(&names.shard, false)?;
        let manifests = home.child("manifests", false)?;
        let manifest_shard = manifests.child(&names.shard, false)?;
        let blob = open_regular(snapshot_shard.leaf(), &names.blob, OFlags::RDONLY)?;
        let manifest = open_regular(manifest_shard.leaf(), &names.manifest, OFlags::RDONLY)?;
        let blob_metadata = blob.metadata()?;
        let manifest_metadata = manifest.metadata()?;
        if !blob_metadata.is_file()
            || !manifest_metadata.is_file()
            || blob_metadata.nlink() != 1
            || manifest_metadata.nlink() != 1
            || blob_metadata.dev() != home.identity().volume_serial
            || manifest_metadata.dev() != home.identity().volume_serial
        {
            return Err(AslError::InvalidPolicyState);
        }
        let mut pins = home.pins().collect::<Vec<_>>();
        pins.extend(snapshots.pins());
        pins.extend(snapshot_shard.pins());
        pins.extend(manifests.pins());
        pins.extend(manifest_shard.pins());
        Ok(Self {
            blob_identity: file_identity(&blob)?,
            manifest_identity: file_identity(&manifest)?,
            blob_len: blob_metadata.len(),
            manifest_len: manifest_metadata.len(),
            blob,
            manifest,
            _pins: pins,
        })
    }

    pub(crate) fn read_manifest(&mut self) -> Result<Vec<u8>, AslError> {
        use asl_types::manifest::MAX_MANIFEST_LEN;

        self.check_current(&self.manifest, &self.manifest_identity, self.manifest_len)?;
        self.manifest.rewind()?;
        let mut bytes = Vec::with_capacity(
            usize::try_from(self.manifest_len)
                .unwrap_or(MAX_MANIFEST_LEN)
                .min(MAX_MANIFEST_LEN),
        );
        (&mut self.manifest)
            .take((MAX_MANIFEST_LEN + 1) as u64)
            .read_to_end(&mut bytes)?;
        self.check_current(&self.manifest, &self.manifest_identity, self.manifest_len)?;
        if bytes.len() > MAX_MANIFEST_LEN || bytes.len() as u64 != self.manifest_len {
            return Err(AslError::InvalidPolicyState);
        }
        Ok(bytes)
    }

    pub(crate) fn file_size(&self) -> u64 {
        self.blob_len
    }

    pub(crate) fn read_range(&mut self, offset: u64, length: u32) -> Result<Vec<u8>, AslError> {
        let end = offset
            .checked_add(u64::from(length))
            .ok_or(AslError::NotFound)?;
        if end > self.blob_len {
            return Err(AslError::NotFound);
        }
        self.check_current(&self.blob, &self.blob_identity, self.blob_len)?;
        self.blob.seek(io::SeekFrom::Start(offset))?;
        let mut bytes = vec![0; usize::try_from(length).map_err(|_| AslError::NotFound)?];
        self.blob.read_exact(&mut bytes)?;
        self.check_current(&self.blob, &self.blob_identity, self.blob_len)?;
        Ok(bytes)
    }

    fn check_current(
        &self,
        file: &File,
        identity: &FileIdentity,
        length: u64,
    ) -> Result<(), AslError> {
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.len() != length
            || &file_identity(file)? != identity
        {
            return Err(AslError::InvalidPolicyState);
        }
        Ok(())
    }
}

impl ObjectFiles {
    pub(crate) fn stage(home: &Path) -> Result<Self, AslError> {
        let home = pin_directory(home)?;
        let incoming = home.child("incoming", true)?;
        Ok(Self {
            blob: Object::stage(&incoming)?,
            manifest: Object::stage(&incoming)?,
            _incoming: incoming,
            snapshots: home.child("snapshots", true)?,
            manifests: home.child("manifests", true)?,
        })
    }

    pub(crate) fn writers(&mut self) -> (&mut File, &mut File) {
        (&mut self.blob.file, &mut self.manifest.file)
    }

    pub(crate) fn install(
        &mut self,
        id: [u8; 32],
        mut progress: impl FnMut() -> Result<(), AslError>,
    ) -> Result<(), AslError> {
        progress()?;
        let names = ObjectNames::new(id);
        self.blob.install(
            self.snapshots.child(&names.shard, true)?,
            &names.blob,
            &mut progress,
        )?;
        progress()?;
        self.manifest.install(
            self.manifests.child(&names.shard, true)?,
            &names.manifest,
            &mut progress,
        )?;
        progress()
    }

    pub(crate) fn retain(&mut self) {
        self.blob.owned = false;
        self.manifest.owned = false;
    }
}

struct Object {
    file: File,
    identity: FileIdentity,
    owned: bool,
    parent: PinnedDirectory,
    name: Option<String>,
}

impl Object {
    fn stage(dir: &PinnedDirectory) -> Result<Self, AslError> {
        if let Some(file) = open_anonymous(dir)? {
            let metadata = file.metadata()?;
            if !metadata.is_file() || metadata.nlink() != 0 {
                return Err(AslError::InvalidPolicyState);
            }
            return Ok(Self {
                identity: file_identity(&file)?,
                file,
                owned: false,
                parent: dir.clone(),
                name: None,
            });
        }
        let nonce: [u8; 16] = rand::random();
        Self::create(dir, &format!("{}.part", hex::encode(nonce)))
    }

    fn create(dir: &PinnedDirectory, name: &str) -> Result<Self, AslError> {
        let file = open_regular(
            dir.leaf(),
            name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
        )?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(AslError::InvalidPolicyState);
        }
        Ok(Self {
            identity: file_identity(&file)?,
            file,
            owned: true,
            parent: dir.clone(),
            name: Some(name.to_owned()),
        })
    }

    fn install(
        &mut self,
        dest: PinnedDirectory,
        name: &str,
        progress: &mut dyn FnMut() -> Result<(), AslError>,
    ) -> Result<(), AslError> {
        let len = self.file.metadata()?.len();
        let final_object = match Self::create(&dest, name) {
            Ok(mut new) => {
                read_stage_chunks(&mut self.file, len, progress, |chunk| {
                    Ok(new.file.write_all(chunk)?)
                })?;
                new
            }
            Err(AslError::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists => {
                let mut file = open_regular(dest.leaf(), name, OFlags::RDONLY)?;
                let metadata = file.metadata()?;
                if !metadata.is_file()
                    || metadata.nlink() != 1
                    || metadata.len() != len
                    || metadata.dev() != dest.identity().volume_serial
                {
                    return Err(AslError::InvalidPolicyState);
                }
                file.rewind()?;
                let mut actual = vec![0; len.min(u64::from(CHUNK_SIZE)) as usize];
                read_stage_chunks(&mut self.file, len, progress, |expected| {
                    let actual = &mut actual[..expected.len()];
                    file.read_exact(actual)?;
                    if actual != expected {
                        return Err(AslError::InvalidPolicyState);
                    }
                    Ok(())
                })?;
                Self {
                    identity: file_identity(&file)?,
                    file,
                    owned: false,
                    parent: dest,
                    name: Some(name.to_owned()),
                }
            }
            Err(error) => return Err(error),
        };
        final_object.file.sync_all()?;
        final_object.parent.leaf().sync_all()?;
        let metadata = final_object.file.metadata()?;
        if metadata.len() != len || metadata.nlink() != 1 {
            return Err(AslError::InvalidPolicyState);
        }
        fchmod(&final_object.file, Mode::RUSR).map_err(io_error)?;
        if self.owned {
            let name = self.name.as_deref().ok_or(AslError::InvalidPolicyState)?;
            unlink_identity(&self.parent, name, &self.identity)?;
            self.parent.leaf().sync_all()?;
            self.owned = false;
        }
        *self = final_object;
        Ok(())
    }
}

impl Drop for Object {
    fn drop(&mut self) {
        if self.owned
            && let Some(name) = self.name.as_deref()
        {
            let _ = unlink_identity(&self.parent, name, &self.identity);
        }
    }
}

fn open_anonymous(dir: &PinnedDirectory) -> Result<Option<File>, AslError> {
    let flags = OFlags::RDWR | OFlags::CLOEXEC | OFlags::TMPFILE;
    match rustix::fs::openat2(
        dir.leaf(),
        ".",
        flags,
        Mode::RUSR | Mode::WUSR,
        super::super::filesystem::safe_resolve_flags(),
    ) {
        Ok(fd) => Ok(Some(File::from(fd))),
        Err(rustix::io::Errno::OPNOTSUPP)
        | Err(rustix::io::Errno::ISDIR)
        | Err(rustix::io::Errno::INVAL)
        | Err(rustix::io::Errno::NOSYS) => Ok(None),
        Err(error) => Err(io_error(error)),
    }
}

fn unlink_identity(
    parent: &PinnedDirectory,
    name: &str,
    expected: &FileIdentity,
) -> Result<(), AslError> {
    let file = open_regular(parent.leaf(), name, OFlags::RDONLY)?;
    if file_identity(&file)? != *expected {
        return Err(AslError::PolicyDenied);
    }
    let quarantine = format!(".asl-remove-{:032x}", rand::random::<u128>());
    rustix::fs::renameat_with(
        parent.leaf(),
        name,
        parent.leaf(),
        &quarantine,
        RenameFlags::NOREPLACE,
    )
    .map_err(io_error)?;
    let moved = open_regular(parent.leaf(), &quarantine, OFlags::RDONLY)?;
    if file_identity(&moved)? != *expected {
        return Err(AslError::PolicyDenied);
    }
    unlinkat(parent.leaf(), &quarantine, rustix::fs::AtFlags::empty()).map_err(io_error)?;
    parent.leaf().sync_all().map_err(io_error)
}

fn read_stage_chunks(
    stage: &mut File,
    mut remaining: u64,
    progress: &mut dyn FnMut() -> Result<(), AslError>,
    mut consume: impl FnMut(&[u8]) -> Result<(), AslError>,
) -> Result<(), AslError> {
    stage.rewind()?;
    let mut buffer = vec![0; remaining.min(u64::from(CHUNK_SIZE)) as usize];
    while remaining != 0 {
        let count = remaining.min(buffer.len() as u64) as usize;
        let chunk = &mut buffer[..count];
        stage.read_exact(chunk)?;
        consume(chunk)?;
        remaining -= count as u64;
        progress()?;
    }
    Ok(())
}

mod legacy {
    use super::*;

    pub(crate) struct LegacyRootSeed {
        file: File,
        parent: PinnedDirectory,
        identity: FileIdentity,
        retiring: bool,
    }

    impl LegacyRootSeed {
        pub(super) fn new(
            file: File,
            parent: PinnedDirectory,
            identity: FileIdentity,
            retiring: bool,
        ) -> Self {
            Self {
                file,
                parent,
                identity,
                retiring,
            }
        }

        pub(crate) fn read(&mut self) -> Result<[u8; 32], AslError> {
            let metadata = self.file.metadata()?;
            if !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.len() != 32
                || file_identity(&self.file)? != self.identity
            {
                return Err(AslError::InvalidIdentity);
            }
            let mut seed = [0u8; 32];
            self.file.rewind()?;
            self.file.read_exact(&mut seed)?;
            Ok(seed)
        }

        pub(crate) fn retire(mut self) -> Result<(), AslError> {
            if !self.retiring {
                renameat_with(
                    self.parent.leaf(),
                    "root.seed",
                    self.parent.leaf(),
                    "root.seed.retiring",
                    RenameFlags::NOREPLACE,
                )
                .map_err(io_error)?;
                self.retiring = true;
            }
            drop(self.file);
            let file = open_regular(self.parent.leaf(), "root.seed.retiring", OFlags::RDONLY)?;
            if file_identity(&file)? != self.identity {
                return Err(AslError::InvalidIdentity);
            }
            drop(file);
            unlinkat(
                self.parent.leaf(),
                "root.seed.retiring",
                rustix::fs::AtFlags::empty(),
            )
            .map_err(io_error)
        }
    }
}

pub(crate) use legacy::LegacyRootSeed;

pub(crate) fn open_legacy_root_seed(home: &Path) -> Result<LegacyRootSeed, AslError> {
    let home = pin_directory(home)?;
    let agent = home.child("agent", false)?;
    let seed = open_regular(agent.leaf(), "root.seed", OFlags::RDONLY);
    let retiring = open_regular(agent.leaf(), "root.seed.retiring", OFlags::RDONLY);
    let (file, retiring) = match (seed, retiring) {
        (Ok(_), Ok(_)) => return Err(AslError::InvalidIdentity),
        (Ok(file), Err(AslError::Io(error))) if error.kind() == io::ErrorKind::NotFound => {
            (file, false)
        }
        (Err(AslError::Io(error)), Ok(file)) if error.kind() == io::ErrorKind::NotFound => {
            (file, true)
        }
        (_, _) => return Err(AslError::NotFound),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() != 32 {
        return Err(AslError::InvalidIdentity);
    }
    let identity = file_identity(&file)?;
    Ok(LegacyRootSeed::new(file, agent, identity, retiring))
}
