//! Trusted local process configuration. No peer or model supplies these values.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::Duration;

use asl_types::error::AslError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxRole {
    Net,
    Worker,
    Extractor,
}

impl SandboxRole {
    #[cfg(windows)]
    pub(crate) fn argument(self) -> &'static str {
        match self {
            Self::Net => "--asl-role=net",
            Self::Worker => "--asl-role=worker",
            Self::Extractor => "--asl-role=extractor",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SandboxLimits {
    pub memory_bytes: u64,
    pub cpu_rate_percent: u8,
    pub cpu_time_ms: Option<u64>,
    pub wall_time_ms: Option<u32>,
}

impl SandboxLimits {
    pub fn for_role(role: SandboxRole) -> Self {
        match role {
            SandboxRole::Net => Self {
                memory_bytes: 256 * 1024 * 1024,
                cpu_rate_percent: 25,
                cpu_time_ms: None,
                wall_time_ms: None,
            },
            SandboxRole::Worker => Self {
                memory_bytes: 256 * 1024 * 1024,
                cpu_rate_percent: 25,
                cpu_time_ms: Some(10_000),
                wall_time_ms: Some(30_000),
            },
            SandboxRole::Extractor => Self {
                memory_bytes: 512 * 1024 * 1024,
                cpu_rate_percent: 25,
                cpu_time_ms: Some(10_000),
                wall_time_ms: Some(10_000),
            },
        }
    }

    pub(crate) fn validate(self, role: SandboxRole) -> Result<(), AslError> {
        if self.memory_bytes == 0
            || usize::try_from(self.memory_bytes).is_err()
            || !(1..=100).contains(&self.cpu_rate_percent)
            || self.cpu_time_ms.is_some_and(|value| {
                value == 0
                    || value
                        .checked_mul(10_000)
                        .is_none_or(|v| v > i64::MAX as u64)
            })
            || self
                .wall_time_ms
                .is_some_and(|value| value == 0 || value == u32::MAX)
            || (role != SandboxRole::Net
                && (self.cpu_time_ms.is_none() || self.wall_time_ms.is_none()))
        {
            return Err(AslError::SandboxUnavailable);
        }
        Ok(())
    }
}

/// Executables chosen by the local broker, never a shell command or remote path.
pub struct SandboxLauncher {
    net: PathBuf,
    worker: PathBuf,
    extractor: PathBuf,
}

impl SandboxLauncher {
    pub fn new(net: PathBuf, worker: PathBuf, extractor: PathBuf) -> Result<Self, AslError> {
        for path in [&net, &worker, &extractor] {
            if !path.is_absolute()
                || path.extension().is_none_or(|value| value != "exe")
                || path
                    .to_str()
                    .is_none_or(|value| value.contains('\0') || value.contains('"'))
            {
                return Err(AslError::SandboxUnavailable);
            }
        }
        Ok(Self {
            net,
            worker,
            extractor,
        })
    }

    fn program(&self, role: SandboxRole) -> &Path {
        match role {
            SandboxRole::Net => &self.net,
            SandboxRole::Worker => &self.worker,
            SandboxRole::Extractor => &self.extractor,
        }
    }

    #[cfg(windows)]
    pub fn spawn_sandbox(
        &self,
        role: SandboxRole,
        inherited_handles: InheritedPipes,
        limits: SandboxLimits,
    ) -> Result<SandboxChild, AslError> {
        limits.validate(role)?;
        crate::platform::windows::appcontainer::spawn(
            self.program(role),
            role,
            inherited_handles,
            limits,
        )
        .map(|inner| SandboxChild { inner })
    }

    #[cfg(not(windows))]
    pub fn spawn_sandbox(
        &self,
        role: SandboxRole,
        _: InheritedPipes,
        limits: SandboxLimits,
    ) -> Result<SandboxChild, AslError> {
        limits.validate(role)?;
        let _ = self.program(role);
        Err(AslError::PlatformUnavailable)
    }
}

/// Broker ends are not inheritable. Child ends can only be made by this module.
pub struct BrokerPipes {
    pub input: File,
    pub output: File,
    pub error: File,
}

#[cfg(windows)]
pub use crate::platform::windows::appcontainer::InheritedPipes;

#[cfg(not(windows))]
pub struct InheritedPipes(());

#[cfg(not(windows))]
impl InheritedPipes {
    pub fn new() -> Result<(BrokerPipes, Self), AslError> {
        Err(AslError::PlatformUnavailable)
    }
}

pub struct SandboxChild {
    #[cfg(windows)]
    inner: crate::platform::windows::appcontainer::Child,
}

#[cfg(not(windows))]
impl SandboxChild {
    pub fn wait_timeout(&mut self, _: Duration) -> Result<Option<u32>, AslError> {
        Err(AslError::PlatformUnavailable)
    }

    pub fn terminate(&mut self) -> Result<(), AslError> {
        Err(AslError::PlatformUnavailable)
    }
}

#[cfg(windows)]
impl SandboxChild {
    pub fn id(&self) -> u32 {
        self.inner.id()
    }

    pub fn wait_timeout(&mut self, timeout: Duration) -> Result<Option<u32>, AslError> {
        self.inner.wait_timeout(timeout)
    }

    pub fn terminate(&mut self) -> Result<(), AslError> {
        self.inner.terminate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_limits_require_bounded_helpers_but_allow_persistent_net() {
        for role in [
            SandboxRole::Net,
            SandboxRole::Worker,
            SandboxRole::Extractor,
        ] {
            assert!(SandboxLimits::for_role(role).validate(role).is_ok());
        }
        let net = SandboxLimits::for_role(SandboxRole::Net);
        assert!(net.validate(SandboxRole::Worker).is_err());
        assert!(net.validate(SandboxRole::Extractor).is_err());
    }

    #[test]
    fn unrepresentable_or_zero_limits_are_rejected() {
        let defaults = SandboxLimits::for_role(SandboxRole::Worker);
        for invalid in [
            SandboxLimits {
                memory_bytes: 0,
                ..defaults
            },
            SandboxLimits {
                cpu_rate_percent: 0,
                ..defaults
            },
            SandboxLimits {
                cpu_rate_percent: 101,
                ..defaults
            },
            SandboxLimits {
                cpu_time_ms: Some(0),
                ..defaults
            },
            SandboxLimits {
                cpu_time_ms: Some(u64::MAX),
                ..defaults
            },
            SandboxLimits {
                wall_time_ms: Some(0),
                ..defaults
            },
            SandboxLimits {
                wall_time_ms: Some(u32::MAX),
                ..defaults
            },
        ] {
            assert!(invalid.validate(SandboxRole::Worker).is_err());
        }
    }

    #[test]
    fn launcher_rejects_relative_programs_and_command_injection() {
        for invalid in [
            "relative.exe",
            "C:\\tools\\program.cmd",
            "C:\\tools\\\"bad.exe",
        ] {
            let path = PathBuf::from(invalid);
            assert!(SandboxLauncher::new(path.clone(), path.clone(), path).is_err());
        }
    }
}
