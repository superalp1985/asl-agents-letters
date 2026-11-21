use std::{
    io::Write,
    os::windows::io::AsRawHandle,
    path::PathBuf,
    process::{Child, Command, Stdio},
};

use super::{AslError, HANDLE, Job, system_directory};

pub(super) struct LoopbackFixture {
    utility: PathBuf,
    sid_argument: String,
    listener: Option<(Job, Child)>,
}

impl LoopbackFixture {
    pub(super) fn enable(sid: String) -> Result<Self, AslError> {
        let mut fixture = Self {
            utility: PathBuf::from(system_directory()?).join("CheckNetIsolation.exe"),
            sid_argument: format!("-p={sid}"),
            listener: None,
        };
        fixture.change("-a", "loopback_add")?;
        if let Err(error) = fixture.start_listener() {
            fixture.remove()?;
            return Err(error);
        }
        Ok(fixture)
    }

    fn command(&self, operation: &str) -> Command {
        let mut command = Command::new(&self.utility);
        command
            .args(["LoopbackExempt", operation, &self.sid_argument])
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

    fn start_listener(&mut self) -> Result<(), AslError> {
        // Windows keeps inbound loopback enabled for the lifetime of this process.
        self.listener = Some(Self::start_owned(self.command("-is"))?);
        Ok(())
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
        let listener = self.listener.take().map(|(job, mut child)| {
            let state = match child.try_wait() {
                Ok(None) => "running".into(),
                Ok(Some(status)) => format!("already exited ({status})"),
                Err(error) => format!("status unavailable ({error})"),
            };
            let _ = writeln!(
                std::io::stderr().lock(),
                "Loopback fixture Core {} {}: -is helper {} {state} before cleanup",
                std::process::id(),
                self.sid_argument,
                child.id()
            );
            drop(job);
            child.wait()
        });
        self.change("-d", "loopback_remove")?;
        listener.transpose()?;
        Ok(())
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
