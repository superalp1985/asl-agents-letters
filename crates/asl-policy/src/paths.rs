use std::collections::BTreeSet;
use std::io::{self, Read, Seek, Write};
use std::path::{Component, Path, Prefix};
#[cfg(windows)]
use std::{fs::File, sync::Arc};

use asl_types::error::AslError;

#[cfg(windows)]
use crate::platform::windows::handles;

const MAX_SOURCE_BYTES: u64 = 68_719_476_736;
const MAX_COMPONENTS: usize = 128;

/// Reads one explicitly selected local file without granting directory access.
pub fn read_local_selection(
    path: &Path,
    protected_root: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>, AslError> {
    #[cfg(windows)]
    {
        handles::read_local_selection(path, protected_root, max_bytes)
    }
    #[cfg(not(windows))]
    {
        let _ = (path, protected_root, max_bytes);
        Err(AslError::PlatformUnavailable)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileIdentity {
    pub volume_serial: u64,
    pub file_id: [u8; 16],
}

#[derive(Clone, Debug)]
pub struct SourceRules {
    extensions: BTreeSet<String>,
    max_file_bytes: u64,
}

impl SourceRules {
    pub fn new(
        extensions: impl IntoIterator<Item = String>,
        max_file_bytes: u64,
    ) -> Result<Self, AslError> {
        let mut allowed = BTreeSet::new();
        for extension in extensions {
            if extension.is_empty() || !extension.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
                return Err(AslError::PolicyDenied);
            }
            allowed.insert(extension.to_ascii_lowercase());
        }
        if allowed.is_empty() || max_file_bytes > MAX_SOURCE_BYTES {
            return Err(AslError::PolicyDenied);
        }
        Ok(Self {
            extensions: allowed,
            max_file_bytes,
        })
    }
}

/// A local filesystem capability. The broker must separately authorize the
/// resource and revalidate its policy permit before import or disclosure.
pub struct SourceGrant {
    #[cfg(windows)]
    root: handles::SourceRoot,
    #[cfg(not(windows))]
    unavailable: std::convert::Infallible,
    rules: SourceRules,
}

impl SourceGrant {
    pub fn open(root: &Path, protected_root: &Path, rules: SourceRules) -> Result<Self, AslError> {
        validate_absolute(root)?;
        validate_absolute(protected_root)?;
        #[cfg(windows)]
        {
            Ok(Self {
                root: handles::SourceRoot::open(root, protected_root)?,
                rules,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = rules;
            Err(AslError::PlatformUnavailable)
        }
    }

    pub fn restore(
        root: &Path,
        protected_root: &Path,
        rules: SourceRules,
        expected: &FileIdentity,
    ) -> Result<Self, AslError> {
        let grant = Self::open(root, protected_root, rules)?;
        if grant.identity() != expected {
            return Err(AslError::NotFound);
        }
        Ok(grant)
    }

    #[cfg(windows)]
    pub(crate) fn directory_watch(
        &self,
    ) -> io::Result<crate::platform::windows::reconcile_watch::DirectoryWatch> {
        self.root.directory_watch()
    }

    pub fn identity(&self) -> &FileIdentity {
        #[cfg(windows)]
        {
            self.root.identity()
        }
        #[cfg(not(windows))]
        {
            match self.unavailable {}
        }
    }
}

pub struct AuthorizedFile {
    #[cfg(windows)]
    inner: handles::SourceFile,
    #[cfg(not(windows))]
    unavailable: std::convert::Infallible,
}

/// A pinned local destination that can only create new files beneath its root.
pub struct WriteGrant {
    #[cfg(windows)]
    root: handles::SourceRoot,
    #[cfg(not(windows))]
    unavailable: std::convert::Infallible,
}

pub struct AuthorizedWriteFile {
    #[cfg(windows)]
    inner: File,
    #[cfg(windows)]
    _pins: Vec<Arc<File>>,
    #[cfg(windows)]
    root_identity: FileIdentity,
    #[cfg(windows)]
    retained: bool,
    #[cfg(not(windows))]
    unavailable: std::convert::Infallible,
}

impl WriteGrant {
    pub fn open(root: &Path, protected_root: &Path) -> Result<Self, AslError> {
        validate_absolute(root)?;
        validate_absolute(protected_root)?;
        #[cfg(windows)]
        {
            Ok(Self {
                root: handles::SourceRoot::open(root, protected_root)?,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = (root, protected_root);
            Err(AslError::PlatformUnavailable)
        }
    }

    pub fn restore(
        root: &Path,
        protected_root: &Path,
        expected: &FileIdentity,
    ) -> Result<Self, AslError> {
        let grant = Self::open(root, protected_root)?;
        if grant.identity() != expected {
            return Err(AslError::NotFound);
        }
        Ok(grant)
    }

    pub fn identity(&self) -> &FileIdentity {
        #[cfg(windows)]
        {
            self.root.identity()
        }
        #[cfg(not(windows))]
        {
            match self.unavailable {}
        }
    }

    /// Validate a local inbox filename for the same rules used at creation, without opening it.
    pub fn filename(relative: &Path) -> Result<String, AslError> {
        let mut components = validated_relative(relative)?;
        if components.len() != 1 {
            return Err(AslError::NotFound);
        }
        components.pop().ok_or(AslError::NotFound)
    }

    pub fn create_new(&self, relative: &Path) -> Result<AuthorizedWriteFile, AslError> {
        let name = Self::filename(relative)?;
        #[cfg(windows)]
        {
            let root_identity = self.identity().clone();
            let inner = self.root.create_new_file(&name)?;
            Ok(AuthorizedWriteFile {
                inner,
                _pins: self.root.write_pins(),
                root_identity,
                retained: false,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = name;
            Err(AslError::PlatformUnavailable)
        }
    }

    pub fn open_existing(
        &self,
        relative: &Path,
        expected: &FileIdentity,
    ) -> Result<AuthorizedWriteFile, AslError> {
        let components = validated_relative(relative)?;
        if components.len() != 1 || expected.volume_serial != self.identity().volume_serial {
            return Err(AslError::NotFound);
        }
        #[cfg(windows)]
        {
            let file = self.root.open_existing_write_file(&components[0])?;
            if self.root.file_identity(&file)? != *expected {
                return Err(AslError::PolicyDenied);
            }
            Ok(AuthorizedWriteFile {
                inner: file,
                _pins: self.root.write_pins(),
                root_identity: self.identity().clone(),
                retained: true,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = components;
            Err(AslError::PlatformUnavailable)
        }
    }

    pub fn rename_new(
        &self,
        file: &mut AuthorizedWriteFile,
        relative: &Path,
    ) -> Result<(), AslError> {
        let components = validated_relative(relative)?;
        if components.len() != 1 {
            return Err(AslError::NotFound);
        }
        #[cfg(windows)]
        {
            self.root
                .rename_file(&file.inner, &file.root_identity, &components[0])?;
            file.retained = true;
            Ok(())
        }
        #[cfg(not(windows))]
        {
            let _ = (file, components);
            Err(AslError::PlatformUnavailable)
        }
    }
}

impl AuthorizedWriteFile {
    pub fn identity(&self) -> Result<FileIdentity, AslError> {
        #[cfg(windows)]
        {
            let id = windows_file_identity(&self.inner)?;
            if id.volume_serial != self.root_identity.volume_serial {
                return Err(AslError::PolicyDenied);
            }
            Ok(id)
        }
        #[cfg(not(windows))]
        {
            match self.unavailable {}
        }
    }

    pub fn set_len(&mut self, length: u64) -> io::Result<()> {
        #[cfg(windows)]
        {
            self.inner.set_len(length)
        }
        #[cfg(not(windows))]
        {
            let _ = length;
            match self.unavailable {}
        }
    }

    pub fn len(&self) -> io::Result<u64> {
        #[cfg(windows)]
        {
            self.inner.metadata().map(|metadata| metadata.len())
        }
        #[cfg(not(windows))]
        {
            match self.unavailable {}
        }
    }

    pub fn is_empty(&self) -> io::Result<bool> {
        self.len().map(|length| length == 0)
    }

    pub fn last_write_stamp(&self) -> io::Result<u64> {
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            self.inner
                .metadata()
                .map(|metadata| metadata.last_write_time())
        }
        #[cfg(not(windows))]
        {
            match self.unavailable {}
        }
    }

    pub fn retain(&mut self) {
        #[cfg(windows)]
        {
            self.retained = true;
        }
    }

    pub fn remove(&mut self) -> Result<(), AslError> {
        #[cfg(windows)]
        {
            crate::platform::windows::handles::snapshot::mark_delete(&self.inner)?;
            self.retained = true;
            Ok(())
        }
        #[cfg(not(windows))]
        {
            match self.unavailable {}
        }
    }

    pub fn sync_all(&self) -> io::Result<()> {
        #[cfg(windows)]
        {
            self.inner.sync_all()
        }
        #[cfg(not(windows))]
        {
            match self.unavailable {}
        }
    }
}

#[cfg(windows)]
fn windows_file_identity(file: &File) -> Result<FileIdentity, AslError> {
    crate::platform::windows::handles::file_identity(file)
}

impl Drop for AuthorizedWriteFile {
    fn drop(&mut self) {
        #[cfg(windows)]
        if !self.retained {
            let _ = handles::snapshot::mark_delete(&self.inner);
        }
    }
}

impl Write for AuthorizedWriteFile {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        #[cfg(windows)]
        {
            self.inner.write(buffer)
        }
        #[cfg(not(windows))]
        {
            let _ = buffer;
            match self.unavailable {}
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        #[cfg(windows)]
        {
            self.inner.flush()
        }
        #[cfg(not(windows))]
        {
            match self.unavailable {}
        }
    }
}

impl AuthorizedFile {
    pub fn identity(&self) -> &FileIdentity {
        #[cfg(windows)]
        {
            self.inner.identity()
        }
        #[cfg(not(windows))]
        {
            match self.unavailable {}
        }
    }

    pub fn len(&self) -> u64 {
        #[cfg(windows)]
        {
            self.inner.len()
        }
        #[cfg(not(windows))]
        {
            match self.unavailable {}
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Read for AuthorizedFile {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        #[cfg(windows)]
        {
            self.inner.read(buffer)
        }
        #[cfg(not(windows))]
        {
            let _ = buffer;
            match self.unavailable {}
        }
    }
}

impl Read for AuthorizedWriteFile {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        #[cfg(windows)]
        {
            self.inner.read(buffer)
        }
        #[cfg(not(windows))]
        {
            let _ = buffer;
            match self.unavailable {}
        }
    }
}

impl Seek for AuthorizedWriteFile {
    fn seek(&mut self, position: io::SeekFrom) -> io::Result<u64> {
        #[cfg(windows)]
        {
            self.inner.seek(position)
        }
        #[cfg(not(windows))]
        {
            let _ = position;
            match self.unavailable {}
        }
    }
}

pub fn open_authorized_source(
    grant: &SourceGrant,
    relative: &Path,
) -> Result<AuthorizedFile, AslError> {
    let components = validated_relative(relative)?;
    let extension = relative
        .extension()
        .and_then(|extension| extension.to_str())
        .ok_or(AslError::NotFound)?;
    if !grant
        .rules
        .extensions
        .contains(&extension.to_ascii_lowercase())
    {
        return Err(AslError::NotFound);
    }
    #[cfg(windows)]
    {
        Ok(AuthorizedFile {
            inner: grant
                .root
                .open_file(&components, grant.rules.max_file_bytes)?,
        })
    }
    #[cfg(not(windows))]
    {
        let _ = (components, grant.rules.max_file_bytes);
        Err(AslError::PlatformUnavailable)
    }
}

fn validate_absolute(path: &Path) -> Result<(), AslError> {
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::Prefix(prefix))
        if matches!(prefix.kind(), Prefix::Disk(_)))
        || !matches!(components.next(), Some(Component::RootDir))
    {
        return Err(AslError::InvalidStorageRoot);
    }
    let value = path.to_str().ok_or(AslError::InvalidStorageRoot)?;
    let suffix = value.get(3..).ok_or(AslError::InvalidStorageRoot)?;
    if suffix.is_empty() {
        return Ok(());
    }
    validated_relative(Path::new(suffix)).map_err(|_| AslError::InvalidStorageRoot)?;
    Ok(())
}

pub(crate) fn validated_relative(path: &Path) -> Result<Vec<String>, AslError> {
    let text = path.to_str().ok_or(AslError::NotFound)?;
    let mut result = Vec::new();
    // Validate raw components too: Path::components normalizes "." and repeated
    // separators, which would otherwise hide alternate spellings.
    for part in text.split(['\\', '/']) {
        if part.is_empty()
            || part == "."
            || part == ".."
            || part.ends_with([' ', '.'])
            || part.chars().any(|value| {
                value.is_control() || matches!(value, ':' | '*' | '?' | '"' | '<' | '>' | '|')
            })
            || part.encode_utf16().count() > 255
            || is_device_name(part)
        {
            return Err(AslError::NotFound);
        }
        result.push(part.to_owned());
        if result.len() > MAX_COMPONENTS {
            return Err(AslError::NotFound);
        }
    }
    Ok(result)
}

fn is_device_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or("").trim_end_matches(' ');
    let upper = stem.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$"
    ) || ["COM", "LPT"].iter().any(|prefix| {
        upper.strip_prefix(prefix).is_some_and(|suffix| {
            matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
                || matches!(suffix, "\u{b9}" | "\u{b2}" | "\u{b3}")
        })
    })
}
