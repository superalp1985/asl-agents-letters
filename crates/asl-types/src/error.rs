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
    InvalidIdentity,
    InvalidDeviceCertificate,
    KeyProtectionFailed,
    UnsupportedSchemaVersion,
    InvalidDatabase,
    PolicyDenied,
    GrantRevoked,
    NotFound,
    InvalidPolicyState,
    PolicyVersionConflict,
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
            Self::InvalidIdentity => formatter.write_str("invalid identity data"),
            Self::InvalidDeviceCertificate => formatter.write_str("invalid device certificate"),
            Self::KeyProtectionFailed => formatter.write_str("identity key protection failed"),
            Self::UnsupportedSchemaVersion => {
                formatter.write_str("database schema version is not supported")
            }
            Self::InvalidDatabase => formatter.write_str("database schema is invalid"),
            Self::PolicyDenied => formatter.write_str("access is denied by policy"),
            Self::GrantRevoked => formatter.write_str("grant has been revoked"),
            Self::NotFound => formatter.write_str("resource not found"),
            Self::InvalidPolicyState => formatter.write_str("policy state is invalid"),
            Self::PolicyVersionConflict => formatter.write_str("policy version conflict"),
            Self::Io(error) => write!(formatter, "storage operation failed: {error}"),
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
            | Self::ExpiredMessage
            | Self::InvalidIdentity
            | Self::InvalidDeviceCertificate
            | Self::KeyProtectionFailed
            | Self::UnsupportedSchemaVersion
            | Self::InvalidDatabase
            | Self::PolicyDenied
            | Self::GrantRevoked
            | Self::NotFound
            | Self::InvalidPolicyState
            | Self::PolicyVersionConflict => None,
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
