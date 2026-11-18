use std::fs::File;
use std::path::Path;

use asl_types::error::AslError;
use windows::Wdk::Storage::FileSystem::{FILE_OPEN, FILE_OPEN_IF};
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SHARING_VIOLATION};
use windows::Win32::Storage::FileSystem::{
    DELETE, FILE_ACCESS_RIGHTS, FILE_READ_ATTRIBUTES, FILE_SHARE_MODE, SYNCHRONIZE,
};

use super::super::check_single_link;
use super::{
    Entry, Object, ObjectNames, PinnedDirectory, mark_delete, pin_directory, relative_handle,
};

pub(crate) struct Owner {
    _marker: Object,
    home: PinnedDirectory,
}

impl Owner {
    pub(crate) fn acquire(home: &Path, id: [u8; 16]) -> Result<Option<Self>, AslError> {
        let home = pin_directory(home)?;
        let dir = home.child("state", false)?.child("import-owners", true)?;
        let name = format!("{}.lock", hex::encode(id));
        // Existence is not ownership. A crash can leave an empty marker;
        // OPEN_IF reacquires it without truncating or deleting an unchecked entry.
        let file = match relative_handle(
            dir.leaf(),
            &name,
            Entry::File,
            DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_MODE(0),
            FILE_OPEN_IF,
        ) {
            Err(AslError::Io(e)) if e.raw_os_error() == Some(ERROR_SHARING_VIOLATION.0 as i32) => {
                return Ok(None);
            }
            result => result?,
        };
        dir.check_file(&file, &name)?;
        check_single_link(&file)?;
        if file.metadata()?.len() != 0 {
            return Err(AslError::InvalidPolicyState);
        }
        Ok(Some(Self {
            _marker: Object {
                file,
                owned: true,
                destination: Some(dir),
            },
            home,
        }))
    }

    fn targets(
        &self,
        id: [u8; 32],
        access: FILE_ACCESS_RIGHTS,
    ) -> Result<[Option<Target>; 2], AslError> {
        let names = ObjectNames::new(id);
        Ok([
            Target::open(&self.home, "snapshots", &names.shard, names.blob, access)?,
            Target::open(
                &self.home,
                "manifests",
                &names.shard,
                names.manifest,
                access,
            )?,
        ])
    }

    pub(crate) fn require_absent(&self, id: [u8; 32]) -> Result<(), AslError> {
        if self
            .targets(id, FILE_READ_ATTRIBUTES)?
            .iter()
            .any(Option::is_some)
        {
            return Err(AslError::InvalidPolicyState);
        }
        Ok(())
    }

    pub(crate) fn clean(&self, id: [u8; 32]) -> Result<(), AslError> {
        let targets = self.targets(id, FILE_READ_ATTRIBUTES | DELETE)?;
        // Both existing objects are exclusively pinned and validated before
        // either disposition is set. An IO failure later can leave a partial pair.
        for target in targets.iter().flatten() {
            mark_delete(&target.file)?;
        }
        for target in targets.into_iter().flatten() {
            target.confirm_removed()?;
        }
        Ok(())
    }
}

struct Target {
    file: File,
    dir: PinnedDirectory,
    name: String,
}

impl Target {
    fn open(
        home: &PinnedDirectory,
        base: &str,
        shard: &str,
        name: String,
        access: FILE_ACCESS_RIGHTS,
    ) -> Result<Option<Self>, AslError> {
        let Some(dir) = present(home.child(base, false))? else {
            return Ok(None);
        };
        let Some(dir) = present(dir.child(shard, false))? else {
            return Ok(None);
        };
        let Some(file) = present(relative_handle(
            dir.leaf(),
            &name,
            Entry::File,
            access | SYNCHRONIZE,
            FILE_SHARE_MODE(0),
            FILE_OPEN,
        ))?
        else {
            return Ok(None);
        };
        dir.check_file(&file, &name)?;
        check_single_link(&file)?;
        Ok(Some(Self { file, dir, name }))
    }

    fn confirm_removed(self) -> Result<(), AslError> {
        drop(self.file);
        // A metadata-only observer can defer final deletion. Never interpret
        // delete-pending, sharing errors, or a replacement as confirmed absence.
        if present(relative_handle(
            self.dir.leaf(),
            &self.name,
            Entry::File,
            FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_MODE(0),
            FILE_OPEN,
        ))?
        .is_some()
        {
            return Err(AslError::InvalidPolicyState);
        }
        Ok(())
    }
}

fn present<T>(result: Result<T, AslError>) -> Result<Option<T>, AslError> {
    match result {
        Err(AslError::Io(e)) if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND.0 as i32) => Ok(None),
        other => other.map(Some),
    }
}
