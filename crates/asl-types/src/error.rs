use std::fmt;
use std::io;

#[derive(Debug)]
pub enum AslError {
    InvalidStorageRoot,
    PlatformUnavailable,
    Io(io::Error),
}

impl fmt::Display for AslError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidStorageRoot => formatter.write_str("invalid or unsupported storage root"),
            Self::PlatformUnavailable => {
                formatter.write_str("required platform support is unavailable")
            }
            Self::Io(error) => write!(formatter, "storage initialization failed: {error}"),
        }
    }
}

impl std::error::Error for AslError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InvalidStorageRoot | Self::PlatformUnavailable => None,
        }
    }
}

impl From<io::Error> for AslError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
