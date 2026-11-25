pub(crate) mod snapshot;

use std::fs::File;
use std::io::{self, Read, Seek};
use std::mem::{offset_of, size_of};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Component, Path, Prefix};
use std::ptr;
use std::sync::Arc;

use asl_types::error::AslError;
use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DELETE_ON_CLOSE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
    FILE_OPEN_REPARSE_POINT, FILE_RENAME_INFORMATION, FILE_RENAME_INFORMATION_0,
    FILE_STANDARD_LINK_INFORMATION, FILE_SYNCHRONOUS_IO_NONALERT, FileRenameInformation,
    FileStandardLinkInformation, NTCREATEFILE_CREATE_DISPOSITION, NtCreateFile,
    NtQueryInformationFile, NtSetInformationFile,
};
use windows::Win32::Foundation::{HANDLE, OBJ_DONT_REPARSE, RtlNtStatusToDosError, UNICODE_STRING};
use windows::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, DELETE, FILE_ACCESS_RIGHTS, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
    FILE_DISPOSITION_INFO, FILE_EXECUTE, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_FLAGS_AND_ATTRIBUTES, FILE_ID_INFO, FILE_INFO_BY_HANDLE_CLASS, FILE_NAME_NORMALIZED,
    FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_MODE, FILE_SHARE_READ, FILE_STANDARD_INFO,
    FILE_TRAVERSE, FILE_TYPE_DISK, FILE_WRITE_DATA, FileAttributeTagInfo, FileDispositionInfo,
    FileIdInfo, FileStandardInfo, GETFINALPATHNAMEBYHANDLE_FLAGS, GetDriveTypeW,
    GetFileInformationByHandleEx, GetFileType, GetFinalPathNameByHandleW,
    GetVolumeInformationByHandleW, OPEN_EXISTING, QueryDosDeviceW, READ_CONTROL, SYNCHRONIZE,
    SetFileInformationByHandle, VOLUME_NAME_GUID, WRITE_DAC,
};
use windows::Win32::System::IO::IO_STATUS_BLOCK;
use windows::Win32::System::WindowsProgramming::DRIVE_FIXED;
use windows::core::{HSTRING, PWSTR};

use crate::paths::{FileIdentity, validated_relative};

pub(crate) struct PinnedDirectory {
    pins: Vec<Arc<File>>,
    identity: FileIdentity,
    name: Vec<u16>,
}

impl PinnedDirectory {
    pub(super) fn identity(&self) -> &FileIdentity {
        &self.identity
    }
}

pub(super) struct ExecutablePin {
    pub(super) file: File,
    pub(super) identity: FileIdentity,
    _directory: PinnedDirectory,
}

pub(super) fn pin_executable(path: &Path) -> Result<ExecutablePin, AslError> {
    let directory = pin_directory(path.parent().ok_or(AslError::SandboxUnavailable)?)?;
    let component = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(AslError::SandboxUnavailable)?;
    let names = validated_relative(Path::new(component))?;
    if names.len() != 1 {
        return Err(AslError::SandboxUnavailable);
    }
    let parent = directory.pins.last().ok_or(AslError::SandboxUnavailable)?;
    let file = relative_open_with_access(
        parent,
        component,
        false,
        FILE_READ_ATTRIBUTES
            | FILE_READ_DATA
            | FILE_EXECUTE
            | SYNCHRONIZE
            | READ_CONTROL
            | WRITE_DAC,
    )?;
    let identity = inspect(&file, false)?.identity;
    check_long_name(&file, &directory.name, component)?;
    Ok(ExecutablePin {
        file,
        identity,
        _directory: directory,
    })
}

pub(crate) fn read_local_selection(
    path: &Path,
    protected_root: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>, AslError> {
    let parent = pin_directory(path.parent().ok_or(AslError::NotFound)?)?;
    let protected = pin_directory(protected_root)?;
    if path_contains(&protected.name, &parent.name) {
        return Err(AslError::PolicyDenied);
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(AslError::NotFound)?;
    let components = validated_relative(Path::new(name))?;
    if components.len() != 1 {
        return Err(AslError::NotFound);
    }
    let file = relative_open(parent.pins.last().ok_or(AslError::NotFound)?, name, false)?;
    let information = inspect(&file, false)?;
    check_long_name(&file, &parent.name, name)?;
    if information.identity.volume_serial != parent.identity.volume_serial {
        return Err(AslError::NotFound);
    }
    let len = usize::try_from(information.standard.EndOfFile).map_err(|_| AslError::NotFound)?;
    if len > max_bytes {
        return Err(AslError::QuotaExceeded);
    }
    let mut bytes = Vec::with_capacity(len);
    file.take(len as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() != len {
        return Err(AslError::InvalidMessage);
    }
    Ok(bytes)
}

pub(crate) struct SourceRoot {
    directory: PinnedDirectory,
    protected: PinnedDirectory,
}

pub(crate) struct SourceFile {
    file: File,
    identity: FileIdentity,
    len: u64,
    _pins: Vec<Arc<File>>,
}

struct Information {
    identity: FileIdentity,
    standard: FILE_STANDARD_INFO,
}

impl SourceRoot {
    pub(crate) fn open(root: &Path, protected_root: &Path) -> Result<Self, AslError> {
        let protected = pin_directory(protected_root)?;
        let directory = pin_directory(root)?;
        if path_contains(&directory.name, &protected.name)
            || path_contains(&protected.name, &directory.name)
        {
            return Err(AslError::NotFound);
        }
        Ok(Self {
            directory,
            protected,
        })
    }

    pub(crate) fn identity(&self) -> &FileIdentity {
        &self.directory.identity
    }

    pub(crate) fn write_pins(&self) -> Vec<Arc<File>> {
        self.directory
            .pins
            .iter()
            .chain(self.protected.pins.iter())
            .cloned()
            .collect()
    }

    pub(crate) fn create_new_file(&self, component: &str) -> Result<File, AslError> {
        self.open_write_file(component, FILE_CREATE)
    }

    pub(crate) fn open_existing_write_file(&self, component: &str) -> Result<File, AslError> {
        self.open_write_file(component, FILE_OPEN)
    }

    fn open_write_file(
        &self,
        component: &str,
        disposition: NTCREATEFILE_CREATE_DISPOSITION,
    ) -> Result<File, AslError> {
        let parent = self.directory.pins.last().ok_or(AslError::NotFound)?;
        let file = relative_handle(
            parent,
            component,
            Entry::File,
            DELETE | FILE_READ_ATTRIBUTES | FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE,
            FILE_SHARE_READ,
            disposition,
        )?;
        let information = inspect(&file, false)?;
        if information.identity.volume_serial != self.directory.identity.volume_serial {
            return Err(AslError::NotFound);
        }
        check_long_name(&file, &self.directory.name, component)?;
        Ok(file)
    }

    pub(crate) fn file_identity(&self, file: &File) -> Result<FileIdentity, AslError> {
        let information = inspect(file, false)?;
        if information.identity.volume_serial != self.directory.identity.volume_serial {
            return Err(AslError::NotFound);
        }
        Ok(information.identity)
    }

    pub(crate) fn rename_file(
        &self,
        file: &File,
        expected_root: &FileIdentity,
        component: &str,
    ) -> Result<(), AslError> {
        if expected_root != &self.directory.identity {
            return Err(AslError::PolicyDenied);
        }
        let names = validated_relative(Path::new(component))?;
        if names.len() != 1 || names[0] != component {
            return Err(AslError::InvalidStorageRoot);
        }
        let mut encoded: Vec<u16> = component.encode_utf16().collect();
        let name_bytes = encoded
            .len()
            .checked_mul(size_of::<u16>())
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(AslError::InvalidStorageRoot)?;
        let name_offset = offset_of!(FILE_RENAME_INFORMATION, FileName);
        let file_name_bytes =
            usize::try_from(name_bytes).map_err(|_| AslError::InvalidStorageRoot)?;
        let buffer_bytes = size_of::<FILE_RENAME_INFORMATION>()
            .checked_add(file_name_bytes)
            .ok_or(AslError::InvalidStorageRoot)?;
        let words = buffer_bytes.div_ceil(size_of::<usize>());
        let mut buffer = vec![0usize; words];
        let information = buffer.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
        unsafe {
            ptr::write(
                information,
                FILE_RENAME_INFORMATION {
                    Anonymous: FILE_RENAME_INFORMATION_0 {
                        ReplaceIfExists: false,
                    },
                    RootDirectory: HANDLE::default(),
                    FileNameLength: name_bytes,
                    FileName: [0],
                },
            );
            ptr::copy_nonoverlapping(
                encoded.as_mut_ptr().cast::<u8>(),
                information.cast::<u8>().add(name_offset),
                name_bytes as usize,
            );
        }
        let mut status_block = IO_STATUS_BLOCK::default();
        let status = unsafe {
            NtSetInformationFile(
                raw(file),
                &mut status_block,
                information.cast(),
                u32::try_from(buffer_bytes).map_err(|_| AslError::InvalidStorageRoot)?,
                FileRenameInformation,
            )
        };
        if status.is_err() {
            return Err(io::Error::from_raw_os_error(
                unsafe { RtlNtStatusToDosError(status) } as i32
            )
            .into());
        }
        let information = inspect(file, false)?;
        if information.identity.volume_serial != self.directory.identity.volume_serial {
            return Err(AslError::NotFound);
        }
        check_long_name(file, &self.directory.name, component)?;
        Ok(())
    }

    pub(crate) fn directory_watch(&self) -> io::Result<super::reconcile_watch::DirectoryWatch> {
        super::reconcile_watch::DirectoryWatch::open(&self.directory.name)
    }

    pub(crate) fn open_file(
        &self,
        components: &[String],
        max_file_bytes: u64,
    ) -> Result<SourceFile, AslError> {
        let (last, directories) = components.split_last().ok_or(AslError::NotFound)?;
        let mut pins = self.directory.pins.clone();
        let mut name = self.directory.name.clone();
        for component in directories {
            let parent = pins.last().ok_or(AslError::NotFound)?;
            let child = relative_open(parent, component, true)?;
            let information = inspect(&child, true)?;
            if information.identity.volume_serial != self.directory.identity.volume_serial {
                return Err(AslError::NotFound);
            }
            name = check_long_name(&child, &name, component)?;
            pins.push(Arc::new(child));
        }
        let file = relative_open(pins.last().ok_or(AslError::NotFound)?, last, false)?;
        let information = inspect(&file, false)?;
        check_long_name(&file, &name, last)?;
        let len = u64::try_from(information.standard.EndOfFile).map_err(|_| AslError::NotFound)?;
        if information.identity.volume_serial != self.directory.identity.volume_serial
            || len > max_file_bytes
        {
            return Err(AslError::NotFound);
        }
        pins.extend(self.protected.pins.iter().cloned());
        Ok(SourceFile {
            file,
            identity: information.identity,
            len,
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
        let information = inspect(&self.file, false)
            .map_err(|_| io::Error::from(io::ErrorKind::PermissionDenied))?;
        if information.identity != self.identity
            || u64::try_from(information.standard.EndOfFile).ok() != Some(self.len)
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        self.file.read(buffer)
    }
}

pub(super) fn pin_directory(path: &Path) -> Result<PinnedDirectory, AslError> {
    if !path.is_absolute() {
        return Err(AslError::InvalidStorageRoot);
    }
    let Some(Component::Prefix(prefix)) = path.components().next() else {
        return Err(AslError::InvalidStorageRoot);
    };
    let Prefix::Disk(drive) = prefix.kind() else {
        return Err(AslError::InvalidStorageRoot);
    };
    let drive_path = HSTRING::from(format!("{}:\\", char::from(drive)));
    reject_subst(drive)?;
    // This named constant is from the Windows API, not a user-selected drive.
    if unsafe { GetDriveTypeW(&drive_path) } != DRIVE_FIXED {
        return Err(AslError::InvalidStorageRoot);
    }
    let volume = HSTRING::from(format!("\\\\?\\{}:\\", char::from(drive)));
    // Ownership transfers immediately to File; no inheritable security
    // attributes are supplied and no raw handle leaves this module.
    let handle = unsafe {
        CreateFileW(
            &volume,
            (FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE).0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|_| AslError::NotFound)?;
    let root = unsafe { File::from_raw_handle(handle.0) };
    let information = inspect(&root, true)?;
    validate_ntfs(&root)?;
    let mut name = final_name(&root)?;
    let volume_name = String::from_utf16(&name).map_err(|_| AslError::InvalidStorageRoot)?;
    // A SUBST drive can start inside a directory. Only accept a true volume
    // root so every ancestor is pinned by the traversal below.
    if !volume_name.starts_with(r"\\?\Volume{") || !volume_name.ends_with("}\\") {
        return Err(AslError::InvalidStorageRoot);
    }
    let mut pins = vec![Arc::new(root)];
    let suffix = path
        .to_str()
        .and_then(|value| value.get(3..))
        .ok_or(AslError::InvalidStorageRoot)?;
    let mut identity = information.identity;
    if !suffix.is_empty() {
        for component in validated_relative(Path::new(suffix))? {
            let child = relative_open(pins.last().ok_or(AslError::NotFound)?, &component, true)?;
            let information = inspect(&child, true)?;
            if information.identity.volume_serial != identity.volume_serial {
                return Err(AslError::NotFound);
            }
            name = check_long_name(&child, &name, &component)?;
            identity = information.identity;
            pins.push(Arc::new(child));
        }
    }
    Ok(PinnedDirectory {
        pins,
        identity,
        name,
    })
}

fn relative_open(parent: &File, component: &str, directory: bool) -> Result<File, AslError> {
    let desired = FILE_READ_ATTRIBUTES
        | SYNCHRONIZE
        | if directory {
            FILE_TRAVERSE
        } else {
            FILE_READ_DATA
        };
    relative_open_with_access(parent, component, directory, desired)
}

fn relative_open_with_access(
    parent: &File,
    component: &str,
    directory: bool,
    desired: FILE_ACCESS_RIGHTS,
) -> Result<File, AslError> {
    relative_handle(
        parent,
        component,
        if directory {
            Entry::Directory
        } else {
            Entry::File
        },
        desired,
        FILE_SHARE_READ,
        FILE_OPEN,
    )
    .map_err(|_| AslError::NotFound)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Entry {
    Directory,
    File,
    PrivateTemporary,
}

fn relative_handle(
    parent: &File,
    component: &str,
    entry: Entry,
    desired: FILE_ACCESS_RIGHTS,
    share: FILE_SHARE_MODE,
    disposition: NTCREATEFILE_CREATE_DISPOSITION,
) -> Result<File, AslError> {
    // The caller passes one previously validated component. NT's counted
    // string cannot interpret it as an absolute path or another stream.
    let mut encoded: Vec<u16> = component.encode_utf16().collect();
    let length = u16::try_from(encoded.len() * 2).map_err(|_| AslError::NotFound)?;
    let name = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: PWSTR(encoded.as_mut_ptr()),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: raw(parent),
        ObjectName: &name,
        Attributes: OBJ_DONT_REPARSE,
        ..Default::default()
    };
    let mut handle = HANDLE::default();
    let mut status = IO_STATUS_BLOCK::default();
    let options = FILE_OPEN_REPARSE_POINT
        | FILE_SYNCHRONOUS_IO_NONALERT
        | match entry {
            Entry::Directory => FILE_DIRECTORY_FILE,
            Entry::File => FILE_NON_DIRECTORY_FILE,
            Entry::PrivateTemporary if disposition == FILE_CREATE && share.0 == 0 => {
                FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE
            }
            Entry::PrivateTemporary => return Err(AslError::InvalidPolicyState),
        };
    let result = unsafe {
        NtCreateFile(
            &mut handle,
            desired,
            &attributes,
            &mut status,
            None,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            share,
            disposition,
            options,
            None,
            0,
        )
    };
    if result.is_err() {
        return Err(
            io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(result) } as i32).into(),
        );
    }
    Ok(unsafe { File::from_raw_handle(handle.0) })
}

fn inspect(file: &File, directory: bool) -> Result<Information, AslError> {
    inspect_entry(
        file,
        if directory {
            Entry::Directory
        } else {
            Entry::File
        },
    )
}

pub(crate) fn file_identity(file: &File) -> Result<FileIdentity, AslError> {
    Ok(inspect(file, false)?.identity)
}

pub(crate) struct LegacyRootSeed {
    file: File,
    parent: PinnedDirectory,
    identity: FileIdentity,
    retiring: bool,
}

pub(crate) fn open_legacy_root_seed(home: &Path) -> Result<LegacyRootSeed, AslError> {
    let root = pin_directory(home)?;
    let root_leaf = root.pins.last().ok_or(AslError::InvalidStorageRoot)?;
    let agent_directory = relative_open(root_leaf, "agent", true)?;
    let agent_information = inspect(&agent_directory, true)?;
    if agent_information.identity.volume_serial != root.identity.volume_serial {
        return Err(AslError::InvalidStorageRoot);
    }
    let agent_name = check_long_name(&agent_directory, &root.name, "agent")?;
    let open = |name: &str| {
        relative_handle(
            &agent_directory,
            name,
            Entry::File,
            DELETE | FILE_READ_ATTRIBUTES | FILE_READ_DATA | SYNCHRONIZE,
            FILE_SHARE_READ,
            FILE_OPEN,
        )
    };
    let (seed, seed_name, retiring) = match open("root.seed") {
        Ok(seed) => {
            if open("root.seed.retiring").is_ok() {
                return Err(AslError::InvalidIdentity);
            }
            (seed, "root.seed", false)
        }
        Err(AslError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            (open("root.seed.retiring")?, "root.seed.retiring", true)
        }
        Err(error) => return Err(error),
    };
    let information = inspect(&seed, false)?;
    if information.identity.volume_serial != root.identity.volume_serial
        || information.standard.EndOfFile != 32
    {
        return Err(AslError::InvalidIdentity);
    }
    check_long_name(&seed, &agent_name, seed_name)?;
    let mut pins = root.pins;
    pins.push(Arc::new(agent_directory));
    Ok(LegacyRootSeed {
        file: seed,
        parent: PinnedDirectory {
            pins,
            identity: agent_information.identity,
            name: agent_name,
        },
        identity: information.identity,
        retiring,
    })
}

impl LegacyRootSeed {
    pub(crate) fn read(&mut self) -> Result<[u8; 32], AslError> {
        let information = inspect(&self.file, false)?;
        if information.identity != self.identity || information.standard.EndOfFile != 32 {
            return Err(AslError::InvalidIdentity);
        }
        let mut seed = [0; 32];
        self.file.rewind()?;
        self.file.read_exact(&mut seed)?;
        Ok(seed)
    }

    pub(crate) fn retire(self) -> Result<(), AslError> {
        let information = inspect(&self.file, false)?;
        if information.identity != self.identity || information.standard.EndOfFile != 32 {
            return Err(AslError::InvalidIdentity);
        }
        if !self.retiring {
            rename_file_at(
                &self.file,
                &self.parent.identity,
                &self.parent,
                "root.seed.retiring",
            )?;
        }
        let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
        unsafe {
            SetFileInformationByHandle(
                raw(&self.file),
                FileDispositionInfo,
                (&raw const disposition).cast(),
                size_of::<FILE_DISPOSITION_INFO>() as u32,
            )
        }
        .map_err(|error| io::Error::other(error).into())
    }
}

fn rename_file_at(
    file: &File,
    expected_root: &FileIdentity,
    parent: &PinnedDirectory,
    component: &str,
) -> Result<(), AslError> {
    if expected_root != &parent.identity {
        return Err(AslError::PolicyDenied);
    }
    let names = validated_relative(Path::new(component))?;
    if names.len() != 1 || names[0] != component {
        return Err(AslError::InvalidStorageRoot);
    }
    let mut encoded: Vec<u16> = component.encode_utf16().collect();
    let name_bytes = u32::try_from(encoded.len() * size_of::<u16>())
        .map_err(|_| AslError::InvalidStorageRoot)?;
    let name_offset = offset_of!(FILE_RENAME_INFORMATION, FileName);
    let buffer_bytes = size_of::<FILE_RENAME_INFORMATION>()
        .checked_add(name_bytes as usize)
        .ok_or(AslError::InvalidStorageRoot)?;
    let words = buffer_bytes.div_ceil(size_of::<usize>());
    let mut buffer = vec![0usize; words];
    let information = buffer.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    unsafe {
        ptr::write(
            information,
            FILE_RENAME_INFORMATION {
                Anonymous: FILE_RENAME_INFORMATION_0 {
                    ReplaceIfExists: false,
                },
                RootDirectory: HANDLE::default(),
                FileNameLength: name_bytes,
                FileName: [0],
            },
        );
        ptr::copy_nonoverlapping(
            encoded.as_mut_ptr().cast::<u8>(),
            information.cast::<u8>().add(name_offset),
            name_bytes as usize,
        );
        let mut status_block = IO_STATUS_BLOCK::default();
        let status = NtSetInformationFile(
            raw(file),
            &mut status_block,
            information.cast(),
            u32::try_from(buffer_bytes).map_err(|_| AslError::InvalidStorageRoot)?,
            FileRenameInformation,
        );
        if status.is_err() {
            return Err(io::Error::from_raw_os_error(RtlNtStatusToDosError(status) as i32).into());
        }
    }
    Ok(())
}

fn inspect_entry(file: &File, entry: Entry) -> Result<Information, AslError> {
    if unsafe { GetFileType(raw(file)) } != FILE_TYPE_DISK {
        return Err(AslError::NotFound);
    }
    let attributes: FILE_ATTRIBUTE_TAG_INFO = query(file, FileAttributeTagInfo)?;
    let standard: FILE_STANDARD_INFO = query(file, FileStandardInfo)?;
    if attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
        || attributes.ReparseTag != 0
        || standard.Directory != (entry == Entry::Directory)
        || (standard.DeletePending && entry != Entry::PrivateTemporary)
        || (entry == Entry::File && standard.NumberOfLinks != 1)
    {
        return Err(AslError::NotFound);
    }
    if entry == Entry::PrivateTemporary {
        // A pending deletion can exclude this name from the accessible link
        // count. Require exactly one *total* link on the create-new handle.
        check_single_link(file)?;
    }
    let id: FILE_ID_INFO = query(file, FileIdInfo)?;
    Ok(Information {
        identity: FileIdentity {
            volume_serial: id.VolumeSerialNumber,
            file_id: id.FileId.Identifier,
        },
        standard,
    })
}

fn check_single_link(file: &File) -> Result<(), AslError> {
    // The native query probes the address at 8-byte alignment, even though
    // the generated link-info struct itself has only 4-byte alignment.
    #[repr(C, align(8))]
    struct Aligned(FILE_STANDARD_LINK_INFORMATION);
    let mut result = Aligned(FILE_STANDARD_LINK_INFORMATION::default());
    let links = &mut result.0;
    let status = unsafe {
        NtQueryInformationFile(
            raw(file),
            &mut IO_STATUS_BLOCK::default(),
            (&raw mut *links).cast(),
            size_of::<FILE_STANDARD_LINK_INFORMATION>() as u32,
            FileStandardLinkInformation,
        )
    };
    if status.is_err() {
        return Err(
            io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32).into(),
        );
    }
    if links.Directory || links.TotalNumberOfLinks != 1 {
        return Err(AslError::NotFound);
    }
    Ok(())
}

fn query<T: Default>(file: &File, class: FILE_INFO_BY_HANDLE_CLASS) -> Result<T, AslError> {
    let mut value = T::default();
    // All call sites pair the Windows information class with its fixed repr(C)
    // struct. The buffer remains alive and exclusively borrowed for the call.
    unsafe {
        GetFileInformationByHandleEx(
            raw(file),
            class,
            (&mut value as *mut T).cast(),
            size_of::<T>() as u32,
        )
    }
    .map_err(|_| AslError::NotFound)?;
    Ok(value)
}

fn validate_ntfs(file: &File) -> Result<(), AslError> {
    let mut filesystem = [0u16; 32];
    unsafe {
        GetVolumeInformationByHandleW(raw(file), None, None, None, None, Some(&mut filesystem))
    }
    .map_err(|_| AslError::InvalidStorageRoot)?;
    let end = filesystem
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(filesystem.len());
    if String::from_utf16_lossy(&filesystem[..end]).eq_ignore_ascii_case("NTFS") {
        Ok(())
    } else {
        Err(AslError::InvalidStorageRoot)
    }
}

fn reject_subst(drive: u8) -> Result<(), AslError> {
    let name = HSTRING::from(format!("{}:", char::from(drive)));
    let mut target = vec![0u16; 32_768];
    let length = unsafe { QueryDosDeviceW(&name, Some(&mut target)) } as usize;
    if length == 0 || length > target.len() {
        return Err(AslError::InvalidStorageRoot);
    }
    let end = target[..length]
        .iter()
        .position(|value| *value == 0)
        .ok_or(AslError::InvalidStorageRoot)?;
    let target = String::from_utf16(&target[..end]).map_err(|_| AslError::InvalidStorageRoot)?;
    if target.starts_with(r"\??\") {
        return Err(AslError::InvalidStorageRoot);
    }
    Ok(())
}

fn final_name(file: &File) -> Result<Vec<u16>, AslError> {
    let mut buffer = vec![0u16; 32_768];
    let length = unsafe {
        GetFinalPathNameByHandleW(
            raw(file),
            &mut buffer,
            GETFINALPATHNAMEBYHANDLE_FLAGS(FILE_NAME_NORMALIZED.0 | VOLUME_NAME_GUID.0),
        )
    } as usize;
    if length == 0 || length >= buffer.len() {
        return Err(AslError::NotFound);
    }
    buffer.truncate(length);
    Ok(buffer)
}

fn check_long_name(file: &File, parent: &[u16], component: &str) -> Result<Vec<u16>, AslError> {
    let mut expected = parent.to_vec();
    if expected.last() != Some(&u16::from(b'\\')) {
        expected.push(u16::from(b'\\'));
    }
    expected.extend(component.encode_utf16());
    let actual = final_name(file)?;
    if actual != expected {
        return Err(AslError::NotFound);
    }
    Ok(actual)
}

fn path_contains(parent: &[u16], child: &[u16]) -> bool {
    parent.len() <= child.len()
        && unsafe { CompareStringOrdinal(parent, &child[..parent.len()], true) } == CSTR_EQUAL
        && (parent.len() == child.len()
            || parent.last() == Some(&u16::from(b'\\'))
            || child.get(parent.len()) == Some(&u16::from(b'\\')))
}

fn raw(file: &File) -> HANDLE {
    HANDLE(file.as_raw_handle())
}
