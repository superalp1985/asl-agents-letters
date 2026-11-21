use std::{
    os::windows::io::AsRawHandle,
    path::PathBuf,
    process::{Child, Command, Stdio},
};

use super::{AslError, HANDLE, Job, system_directory};

pub(super) struct LoopbackFixture {
    utility: PathBuf,
    sid: String,
    listener: Option<(Job, Child)>,
}

impl LoopbackFixture {
    pub(super) fn enable(sid: String) -> Result<Self, AslError> {
        let fixture = Self {
            utility: PathBuf::from(system_directory()?).join("CheckNetIsolation.exe"),
            sid,
            listener: None,
        };
        fixture.change("-a", "loopback_add")?;
        Ok(fixture)
    }

    fn command(&self, operation: &str) -> Command {
        let mut command = Command::new(&self.utility);
        command
            .args(["LoopbackExempt", operation, &format!("-p={}", self.sid)])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        command
    }

    fn change(&self, operation: &str, stage: &'static str) -> Result<(), AslError> {
        let status = self.command(operation).status()?;
        if !status.success() {
            return Err(AslError::SandboxSetupFailed {
                stage,
                code: status.code().unwrap_or(-1),
            });
        }
        Ok(())
    }

    pub(super) fn inbound(&mut self, enable: bool) -> Result<&str, AslError> {
        if enable {
            if self.listener.is_none() {
                self.listener = Some(Self::start_owned(self.command("-is"))?);
            }
            if let Some((_, child)) = &mut self.listener
                && let Some(status) = child.try_wait()?
            {
                return Err(AslError::SandboxSetupFailed {
                    stage: "loopback_listener_exited",
                    code: status.code().unwrap_or(-1),
                });
            }
        } else if let Some((job, mut child)) = self.listener.take() {
            let status = child.try_wait()?;
            drop(job);
            child.wait()?;
            if let Some(status) = status {
                return Err(AslError::SandboxSetupFailed {
                    stage: "loopback_listener_exited",
                    code: status.code().unwrap_or(-1),
                });
            }
        }
        Ok(&self.sid)
    }

    fn start_owned(mut command: Command) -> Result<(Job, Child), AslError> {
        let job = Job::fixture_helper()?;
        let mut child = command.stdin(Stdio::piped()).spawn()?;
        if let Err(error) = job.assign(HANDLE(child.as_raw_handle())) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        if let Some(status) = child.try_wait()? {
            return Err(AslError::SandboxSetupFailed {
                stage: "loopback_listener_exited",
                code: status.code().unwrap_or(-1),
            });
        }
        Ok((job, child))
    }

    pub(super) fn remove(mut self) -> Result<(), AslError> {
        let listener = self.inbound(false).map(|_| ());
        self.change("-d", "loopback_remove")?;
        listener
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::{Foundation::WAIT_OBJECT_0, System::Threading::WaitForSingleObject};

    #[test]
    fn dropping_the_owner_reaps_a_running_fixture_helper() {
        let mut cmd = Command::new(PathBuf::from(system_directory().unwrap()).join("cmd.exe"));
        cmd.args(["/d", "/q"])
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let (job, mut child) = LoopbackFixture::start_owned(cmd).unwrap();
        assert!(child.try_wait().unwrap().is_none());
        drop(job);
        // SAFETY: child retains the process handle for the whole wait.
        let status = unsafe { WaitForSingleObject(HANDLE(child.as_raw_handle()), 5000) };
        if status != WAIT_OBJECT_0 {
            let _ = child.kill();
        }
        child.wait().unwrap();
        assert_eq!(status, WAIT_OBJECT_0);
    }
}
