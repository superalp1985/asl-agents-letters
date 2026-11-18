mod recovery;

pub(crate) use recovery::Owner;

use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::mem::size_of;
use std::path::Path;
use std::sync::Arc;

use asl_types::error::AslError;
use asl_types::manifest::CHUNK_SIZE;
use rand::{TryRng, rngs::SysRng};
use windows::Wdk::Storage::FileSystem::{FILE_CREATE, FILE_OPEN, FILE_OPEN_IF};
use windows::Win32::Storage::FileSystem::{
    DELETE, FILE_DISPOSITION_INFO, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_MODE,
    FILE_SHARE_READ, FILE_TRAVERSE, FILE_WRITE_DATA, FileDispositionInfo, SYNCHRONIZE,
    SetFileInformationByHandle,
};

use super::{
    Entry, PinnedDirectory, check_long_name, inspect, inspect_entry, pin_directory, raw,
    relative_handle,
};

impl PinnedDirectory {
    fn leaf(&self) -> &File {
        self.pins.last().expect("pin_directory pins the volume")
    }

    // Names here are fixed literals or two generated hex digits.
    fn child(&self, name: &str, create: bool) -> Result<Self, AslError> {
        let file = relative_handle(
            self.leaf(),
            name,
            Entry::Directory,
            FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ,
            if create { FILE_OPEN_IF } else { FILE_OPEN },
        )?;
        let identity = inspect(&file, true)?.identity;
        if identity.volume_serial != self.identity.volume_serial {
            return Err(AslError::InvalidStorageRoot);
        }
        let name = check_long_name(&file, &self.name, name)?;
        let mut pins = self.pins.clone();
        pins.push(Arc::new(file));
        Ok(Self {
            pins,
            identity,
            name,
        })
    }

    fn check_file(&self, file: &File, name: &str) -> Result<(), AslError> {
        self.check_entry(file, name, Entry::File)
    }

    fn check_entry(&self, file: &File, name: &str, entry: Entry) -> Result<(), AslError> {
        if inspect_entry(file, entry)?.identity.volume_serial != self.identity.volume_serial {
            return Err(AslError::InvalidStorageRoot);
        }
        check_long_name(file, &self.name, name)?;
        Ok(())
    }
}

pub(crate) fn pin_state(home: &Path) -> Result<PinnedDirectory, AslError> {
    pin_directory(home)?.child("state", false)
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
    owned: bool,
    destination: Option<PinnedDirectory>,
}

impl Object {
    fn stage(dir: &PinnedDirectory) -> Result<Self, AslError> {
        let mut nonce = [0u8; 16];
        SysRng
            .try_fill_bytes(&mut nonce)
            .map_err(io::Error::other)?;
        let name = format!("{}.part", hex::encode(nonce));
        Self::create(dir, &name, Entry::PrivateTemporary)
    }

    fn create(dir: &PinnedDirectory, name: &str, entry: Entry) -> Result<Self, AslError> {
        let file = relative_handle(
            dir.leaf(),
            name,
            entry,
            FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | DELETE | SYNCHRONIZE,
            FILE_SHARE_MODE(0),
            FILE_CREATE,
        )?;
        let object = Self {
            file,
            owned: entry == Entry::File,
            destination: None,
        };
        dir.check_entry(&object.file, name, entry)?;
        Ok(object)
    }

    fn install(
        &mut self,
        dest: PinnedDirectory,
        name: &str,
        progress: &mut dyn FnMut() -> Result<(), AslError>,
    ) -> Result<(), AslError> {
        let len = self.file.metadata()?.len();
        let mut final_object = match Self::create(&dest, name, Entry::File) {
            Ok(mut new) => {
                read_stage_chunks(&mut self.file, len, progress, |chunk| {
                    Ok(new.file.write_all(chunk)?)
                })?;
                new
            }
            Err(AslError::Io(e)) if e.kind() == io::ErrorKind::AlreadyExists => {
                // Never truncate, write to, or request DELETE on a collision.
                // Write access is needed for FlushFileBuffers on adoption.
                let mut file = relative_handle(
                    dest.leaf(),
                    name,
                    Entry::File,
                    FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                    FILE_SHARE_READ,
                    FILE_OPEN,
                )?;
                dest.check_file(&file, name)?;
                if file.metadata()?.len() != len {
                    return Err(AslError::InvalidPolicyState);
                }
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
                    file,
                    owned: false,
                    destination: None,
                }
            }
            Err(e) => return Err(e),
        };
        final_object.file.sync_all()?;
        dest.check_file(&final_object.file, name)?;
        final_object.destination = Some(dest);
        *self = final_object;
        Ok(())
    }
}

impl Drop for Object {
    fn drop(&mut self) {
        if self.owned && inspect(&self.file, false).is_ok() {
            // Never close and reopen by name. If disposal fails, leave an
            // unreferenced object for recovery; there is no path-based retry.
            let _ = mark_delete(&self.file);
        }
    }
}

fn mark_delete(file: &File) -> Result<(), AslError> {
    super::check_single_link(file)?;
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    unsafe {
        SetFileInformationByHandle(
            raw(file),
            FileDispositionInfo,
            (&raw const disposition).cast(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    }
    .map_err(|e| io::Error::other(e).into())
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
