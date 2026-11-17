use std::fmt;
use std::io;

use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub enum AslError {
    InvalidStorageRoot,
    PlatformUnavailable,
    InvalidMessage,
    IncompatibleVersion,
    ExpiredMessage,
    Io(io::Error),
}

impl fmt::Display for AslError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidStorageRoot => formatter.write_str("invalid or unsupported storage root"),
            Self::PlatformUnavailable => {
                formatter.write_str("required platform support is unavailable")
            }
            Self::InvalidMessage => formatter.write_str("invalid or unsupported message"),
            Self::IncompatibleVersion => formatter.write_str("incompatible protocol version"),
            Self::ExpiredMessage => formatter.write_str("message has expired"),
            Self::Io(error) => write!(formatter, "storage initialization failed: {error}"),
        }
    }
}

impl std::error::Error for AslError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InvalidStorageRoot
            | Self::PlatformUnavailable
            | Self::InvalidMessage
            | Self::IncompatibleVersion
            | Self::ExpiredMessage => None,
        }
    }
}

impl From<io::Error> for AslError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    PolicyDenied,
    GrantRevoked,
    NotFound,
    Offline,
    Timeout,
    Busy,
    QuotaExceeded,
    IntegrityFailed,
    InvalidMessage,
    IncompatibleVersion,
    ModelInvalid,
    ModelUnavailable,
    SandboxUnavailable,
    DiskFull,
    RelayCapacity,
    Cancelled,
    InternalError,
}
