use std::collections::BTreeSet;
use std::io::{self, Read};
use std::path::{Component, Path, Prefix};

use asl_types::error::AslError;

#[cfg(windows)]
use crate::platform::windows::handles;

const MAX_SOURCE_BYTES: u64 = 68_719_476_736;
const MAX_COMPONENTS: usize = 128;

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
