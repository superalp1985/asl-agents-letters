use std::fs::File;
use std::io;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child as ProcessChild, Command, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use asl_types::error::AslError;
use rustix::pipe::PipeFlags;
use rustix::process::{Resource, Rlimit, Signal, kill_process_group};

use crate::sandbox::{BrokerPipes, SandboxLimits, SandboxRole};

type WatchdogParts = (Option<Sender<()>>, Option<JoinHandle<()>>);

pub struct InheritedPipes {
    input: File,
    output: File,
    error: File,
}

impl InheritedPipes {
    pub fn new() -> Result<(BrokerPipes, Self), AslError> {
        let (input, host_input) = pipe()?;
        let (host_output, output) = pipe()?;
        let (host_error, error) = pipe()?;
        Ok((
            BrokerPipes {
                input: host_input,
                output: host_output,
                error: host_error,
            },
            Self {
                input,
                output,
                error,
            },
        ))
    }
}

pub(crate) struct Child {
    child: ProcessChild,
    stop_watchdog: Option<Sender<()>>,
    watchdog: Option<JoinHandle<()>>,
}

pub(crate) fn spawn(
    program: &Path,
    role: SandboxRole,
    pipes: InheritedPipes,
    limits: SandboxLimits,
) -> Result<Child, AslError> {
    validate_executable(program)?;
    let cpu_seconds = limits
        .cpu_time_ms
        .map(|milliseconds| milliseconds.div_ceil(1000).max(1));
    let memory = limits.memory_bytes;
    let mut command = Command::new(program);
    command
        .arg(role.argument())
        .current_dir("/")
        .env_clear()
        .stdin(Stdio::from(pipes.input))
        .stdout(Stdio::from(pipes.output))
        .stderr(Stdio::from(pipes.error));
    unsafe {
        command.pre_exec(move || configure_child(memory, cpu_seconds));
    }
    let child = command.spawn().map_err(|_| AslError::SandboxUnavailable)?;
    let pid = child.id();
    let (stop_watchdog, watchdog) = if let Some(timeout) = limits.wall_time_ms {
        watchdog(pid, Duration::from_millis(u64::from(timeout)))?
    } else {
        (None, None)
    };
    Ok(Child {
        child,
        stop_watchdog,
        watchdog,
    })
}

impl Child {
    pub(crate) fn id(&self) -> u32 {
        self.child.id()
    }

    pub(crate) fn wait_timeout(&mut self, timeout: Duration) -> Result<Option<u32>, AslError> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait()? {
                self.cleanup()?;
                return Ok(Some(status.code().unwrap_or(1) as u32));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    pub(crate) fn terminate(&mut self) -> Result<(), AslError> {
        if self.child.try_wait()?.is_none() {
            terminate_group(self.child.id())?;
            let _ = self.child.wait()?;
        }
        self.cleanup()
    }

    fn cleanup(&mut self) -> Result<(), AslError> {
        if let Some(stop) = self.stop_watchdog.take() {
            let _ = stop.send(());
        }
        if let Some(watchdog) = self.watchdog.take() {
            watchdog.join().map_err(|_| AslError::SandboxUnavailable)?;
        }
        Ok(())
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

pub(crate) fn confirmed_process_exit(pid: u32) -> bool {
    let Some(pid) = rustix::process::Pid::from_raw(pid as i32) else {
        return false;
    };
    match rustix::process::test_kill_process(pid) {
        Ok(()) => false,
        Err(rustix::io::Errno::SRCH) => true,
        Err(_) => false,
    }
}

fn pipe() -> Result<(File, File), AslError> {
    let (read, write) =
        rustix::pipe::pipe_with(PipeFlags::CLOEXEC).map_err(|_| AslError::SandboxUnavailable)?;
    Ok((File::from(read), File::from(write)))
}

fn configure_child(memory: u64, cpu_seconds: Option<u64>) -> io::Result<()> {
    set_limit(
        Resource::As,
        Rlimit {
            current: Some(memory),
            maximum: Some(memory),
        },
    )?;
    if let Some(seconds) = cpu_seconds {
        set_limit(
            Resource::Cpu,
            Rlimit {
                current: Some(seconds),
                maximum: Some(seconds.saturating_add(1)),
            },
        )?;
    }
    set_limit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )?;
    set_limit(
        Resource::Nofile,
        Rlimit {
            current: Some(64),
            maximum: Some(64),
        },
    )?;
    rustix::thread::set_no_new_privs(true)?;
    if unsafe { libc::setpgid(0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    #[cfg(target_arch = "x86_64")]
    let close_range = libc::SYS_close_range;
    #[cfg(target_arch = "aarch64")]
    let close_range = libc::SYS_close_range;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let close_range = -1;
    if close_range >= 0 {
        let result =
            unsafe { libc::syscall(close_range, 3u32, u32::MAX, libc::CLOSE_RANGE_CLOEXEC) };
        if result != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ENOSYS) {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn set_limit(resource: Resource, limit: Rlimit) -> io::Result<()> {
    rustix::process::setrlimit(resource, limit)
        .map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))
}

fn watchdog(pid: u32, timeout: Duration) -> Result<WatchdogParts, AslError> {
    let (stop, receiver): (Sender<()>, Receiver<()>) = mpsc::channel();
    let watchdog = thread::Builder::new()
        .name("asl-linux-sandbox-deadline".into())
        .spawn(move || {
            if receiver.recv_timeout(timeout).is_err() {
                let _ = terminate_group(pid);
            }
        })
        .map_err(|_| AslError::SandboxUnavailable)?;
    Ok((Some(stop), Some(watchdog)))
}

fn terminate_group(pid: u32) -> Result<(), AslError> {
    let pid = rustix::process::Pid::from_raw(pid as i32).ok_or(AslError::SandboxUnavailable)?;
    match kill_process_group(pid, Signal::KILL) {
        Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
        Err(_) => Err(AslError::SandboxUnavailable),
    }
}

fn validate_executable(path: &Path) -> Result<(), AslError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = path.metadata().map_err(|_| AslError::SandboxUnavailable)?;
    if !path.is_absolute()
        || !metadata.is_file()
        || metadata.permissions().mode() & 0o111 == 0
        || path
            .to_str()
            .is_none_or(|value| value.contains('\0') || value.contains('"'))
    {
        return Err(AslError::SandboxUnavailable);
    }
    Ok(())
}
