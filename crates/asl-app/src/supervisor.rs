use std::env;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use asl_policy::sandbox::{
    BrokerPipes, InheritedPipes, SandboxChild, SandboxLauncher, SandboxLimits, SandboxRole,
};
use asl_types::{error::AslError, ids::PeerId};

use crate::identity::DeviceIdentity;
use crate::ipc::{
    FrameReader, FrameWriter, IpcFrame, IpcMessage, IpcRole, MAX_IPC_TASK_PAYLOAD_BYTES,
    TaskStatus, WorkerOperation, write_device_identity_prelude,
};
use crate::libraries::LocalLibraries;
use crate::paths::AppPaths;

const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const NET_PING_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Supervisor {
    libraries: LocalLibraries,
    launcher: SandboxLauncher,
    net: NetRuntime,
}

impl Supervisor {
    pub fn start(paths: AppPaths) -> Result<Self, AslError> {
        let directory = sibling_binary_directory()?;
        let launcher = SandboxLauncher::new(
            directory.join("asl-net.exe"),
            directory.join("asl-worker.exe"),
            directory.join("asl-worker.exe"),
        )?;
        Self::start_with_launcher(paths, launcher)
    }

    fn start_with_launcher(paths: AppPaths, launcher: SandboxLauncher) -> Result<Self, AslError> {
        let device_identity = DeviceIdentity::load_or_create_protected(&paths.device_key())?;
        let libraries = LocalLibraries::open(&paths)?;
        let net = NetRuntime::start(&launcher, &device_identity)?;
        Ok(Self {
            libraries,
            launcher,
            net,
        })
    }

    /// Trusted in-process entry point only; not dispatched from Net or Worker IPC.
    pub fn local_libraries(&mut self) -> &mut LocalLibraries {
        &mut self.libraries
    }

    pub fn ping_net(&mut self) -> Result<(), AslError> {
        let nonce = self.net.next_nonce;
        self.net.next_nonce = nonce.checked_add(1).ok_or(AslError::InvalidMessage)?;
        self.net
            .writer
            .as_mut()
            .ok_or(AslError::SandboxUnavailable)?
            .send(&IpcMessage::Ping { nonce })?;
        let frame = self.net.receive(NET_PING_TIMEOUT)?;
        if frame.message == (IpcMessage::Pong { nonce }) {
            Ok(())
        } else {
            Err(AslError::InvalidMessage)
        }
    }

    /// Runs strict control-frame validation in a fresh, networkless worker.
    /// The worker is scoped to one task; a crash cannot replace the net process
    /// or take down the core supervisor.
    pub fn validate_control_frame(
        &self,
        task_id: [u8; 16],
        payload: &[u8],
    ) -> Result<TaskStatus, AslError> {
        run_worker_validation(&self.launcher, task_id, payload)
    }

    pub fn run(mut self) -> Result<(), AslError> {
        loop {
            self.libraries.check_health()?;
            self.ping_net()?;
            thread::sleep(Duration::from_secs(5));
        }
    }
}

struct NetRuntime {
    child: Option<SandboxChild>,
    writer: Option<FrameWriter<File>>,
    events: Option<Receiver<Result<IpcFrame, AslError>>>,
    reader_thread: Option<JoinHandle<()>>,
    next_nonce: u64,
}

impl NetRuntime {
    fn start(
        launcher: &SandboxLauncher,
        device_identity: &DeviceIdentity,
    ) -> Result<Self, AslError> {
        let (mut pipes, inherited) = InheritedPipes::new()?;
        let child = launcher.spawn_sandbox(
            SandboxRole::Net,
            inherited,
            SandboxLimits::for_role(SandboxRole::Net),
        )?;
        write_device_identity_prelude(&mut pipes.input, device_identity)?;
        Self::from_child(pipes, child, &device_identity.peer_id())
    }

    fn from_child(
        pipes: BrokerPipes,
        child: SandboxChild,
        expected_peer_id: &PeerId,
    ) -> Result<Self, AslError> {
        drop(pipes.error);
        let (sender, receiver) = mpsc::sync_channel(8);
        let reader_thread = thread::Builder::new()
            .name("asl-net-ipc".into())
            .spawn(move || {
                forward_net_events(
                    FrameReader::new(pipes.output, IpcRole::Net, IpcRole::Core),
                    sender,
                )
            })
            .map_err(|_| AslError::SandboxUnavailable)?;
        let mut runtime = Self {
            child: Some(child),
            writer: Some(FrameWriter::new(pipes.input, IpcRole::Core, IpcRole::Net)),
            events: Some(receiver),
            reader_thread: Some(reader_thread),
            next_nonce: 1,
        };
        match runtime.receive(STARTUP_TIMEOUT) {
            Ok(frame) => match validate_net_ready(frame.message, expected_peer_id) {
                Ok(()) => Ok(runtime),
                Err(error) => {
                    runtime.stop();
                    Err(error)
                }
            },
            Err(error) => {
                runtime.stop();
                Err(error)
            }
        }
    }

    fn receive(&self, timeout: Duration) -> Result<IpcFrame, AslError> {
        match self
            .events
            .as_ref()
            .ok_or(AslError::SandboxUnavailable)?
            .recv_timeout(timeout)
        {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {
                Err(AslError::SandboxUnavailable)
            }
        }
    }

    fn stop(&mut self) {
        self.writer.take();
        if let Some(child) = self.child.as_mut() {
            let _ = child.terminate();
        }
        self.child.take();
        self.events.take();
        if let Some(reader_thread) = self.reader_thread.take() {
            let _ = reader_thread.join();
        }
    }
}

fn validate_net_ready(message: IpcMessage, expected_peer_id: &PeerId) -> Result<(), AslError> {
    match message {
        IpcMessage::NetReady { peer_id } if &peer_id == expected_peer_id => Ok(()),
        IpcMessage::NetReady { .. } => Err(AslError::InvalidIdentity),
        _ => Err(AslError::InvalidMessage),
    }
}

fn forward_net_events<R: Read>(
    mut reader: FrameReader<R>,
    sender: SyncSender<Result<IpcFrame, AslError>>,
) {
    loop {
        let frame = reader.receive();
        let terminal = frame.is_err()
            || matches!(
                &frame,
                Ok(IpcFrame {
                    message: IpcMessage::Stopped,
                    ..
                })
            );
        if sender.send(frame).is_err() || terminal {
            break;
        }
    }
}

impl Drop for NetRuntime {
    fn drop(&mut self) {
        self.stop();
    }
}

fn run_worker_validation(
    launcher: &SandboxLauncher,
    task_id: [u8; 16],
    payload: &[u8],
) -> Result<TaskStatus, AslError> {
    run_worker_validation_with(launcher, task_id, payload, |_| Ok(()))
}

fn run_worker_validation_with(
    launcher: &SandboxLauncher,
    task_id: [u8; 16],
    payload: &[u8],
    after_task_started: impl FnOnce(&mut SandboxChild) -> Result<(), AslError>,
) -> Result<TaskStatus, AslError> {
    if payload.len() > MAX_IPC_TASK_PAYLOAD_BYTES {
        return Err(AslError::InvalidMessage);
    }
    let (pipes, inherited) = InheritedPipes::new()?;
    let mut child = launcher.spawn_sandbox(
        SandboxRole::Worker,
        inherited,
        SandboxLimits::for_role(SandboxRole::Worker),
    )?;
    drop(pipes.error);

    let mut reader = FrameReader::new(pipes.output, IpcRole::Worker, IpcRole::Core);
    let mut writer = FrameWriter::new(pipes.input, IpcRole::Core, IpcRole::Worker);
    if reader.receive()?.message != IpcMessage::Ready {
        return Err(AslError::InvalidMessage);
    }
    writer.send(&IpcMessage::RunTask {
        task_id,
        operation: WorkerOperation::ValidateControlFrame,
        payload: payload.to_vec(),
    })?;
    if reader.receive()?.message != (IpcMessage::TaskStarted { task_id }) {
        return Err(AslError::InvalidMessage);
    }
    after_task_started(&mut child)?;
    writer.send(&IpcMessage::TaskContinue { task_id })?;
    let result = reader.receive()?;
    let status = match result.message {
        IpcMessage::TaskResult {
            task_id: received,
            status,
        } if received == task_id => status,
        _ => return Err(AslError::InvalidMessage),
    };
    writer.send(&IpcMessage::Shutdown)?;
    if reader.receive()?.message != IpcMessage::Stopped {
        return Err(AslError::InvalidMessage);
    }
    if child.wait_timeout(SHUTDOWN_TIMEOUT)? != Some(0) {
        return Err(AslError::SandboxUnavailable);
    }
    Ok(status)
}

fn sibling_binary_directory() -> Result<PathBuf, AslError> {
    let executable = env::current_exe()?;
    let mut directory = executable
        .parent()
        .ok_or(AslError::SandboxUnavailable)?
        .to_path_buf();
    loop {
        if directory.join("asl-net.exe").is_file() && directory.join("asl-worker.exe").is_file() {
            return Ok(directory);
        }
        if !directory.pop() {
            return Err(AslError::SandboxUnavailable);
        }
    }
}

pub fn run_from_environment() -> Result<(), AslError> {
    let root = configured_root(env::var_os("ASL_HOME"))?;
    let paths = AppPaths::open(&root)?;
    Supervisor::start(paths)?.run()
}

fn configured_root(value: Option<std::ffi::OsString>) -> Result<PathBuf, AslError> {
    value.map(PathBuf::from).ok_or(AslError::InvalidStorageRoot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::DeviceIdentity;
    use std::io::Cursor;

    #[test]
    fn net_ready_must_match_the_local_device_identity() {
        let expected = DeviceIdentity::generate().unwrap().peer_id();
        let other = DeviceIdentity::generate().unwrap().peer_id();

        assert!(
            validate_net_ready(
                IpcMessage::NetReady {
                    peer_id: expected.clone(),
                },
                &expected,
            )
            .is_ok()
        );
        assert!(validate_net_ready(IpcMessage::NetReady { peer_id: other }, &expected).is_err());
        assert!(validate_net_ready(IpcMessage::Ready, &expected).is_err());
    }

    #[test]
    fn cargo_test_binary_directory_resolves_to_target_directory() {
        let path = sibling_binary_directory().unwrap();
        assert!(path.is_absolute());
        assert!(path.join("asl-net.exe").is_file());
        assert!(path.join("asl-worker.exe").is_file());
    }

    #[test]
    fn missing_home_does_not_select_a_default_directory() {
        assert!(configured_root(None).is_err());
    }

    #[test]
    fn net_reader_stops_after_ipc_eof() {
        let (sender, receiver) = mpsc::sync_channel(1);
        let reader = FrameReader::new(Cursor::new(Vec::new()), IpcRole::Net, IpcRole::Core);
        let reader_thread = thread::spawn(move || forward_net_events(reader, sender));

        assert!(receiver.recv().unwrap().is_err());
        reader_thread.join().unwrap();
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::TryRecvError::Disconnected)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn sandboxed_worker_failure_does_not_stop_net_or_core() {
        use std::fs;
        use std::path::PathBuf;
        use std::time::{SystemTime, UNIX_EPOCH};

        struct Fixture {
            base: PathBuf,
            root: PathBuf,
        }

        impl Drop for Fixture {
            fn drop(&mut self) {
                let Some(name) = self.root.file_name().and_then(|name| name.to_str()) else {
                    return;
                };
                if !name.starts_with("t10-supervisor-") {
                    return;
                }
                let (Ok(base), Ok(root)) = (self.base.canonicalize(), self.root.canonicalize())
                else {
                    return;
                };
                if root.parent() == Some(base.as_path()) && root.starts_with(&base) {
                    let _ = fs::remove_dir_all(root);
                }
            }
        }

        let input_base = match env::var_os("ASL_T10_FIXTURE_BASE") {
            Some(base) => PathBuf::from(base),
            None => {
                let base = env::temp_dir().join("asl-test-fs");
                fs::create_dir_all(&base).unwrap();
                base
            }
        };
        assert!(input_base.is_absolute() && input_base.is_dir());
        let base = input_base.canonicalize().unwrap();
        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = input_base.join(format!("t10-supervisor-{}-{id}", std::process::id()));
        let fixture = Fixture {
            base,
            root: root.clone(),
        };
        let bin = root.join("bin");
        let home = root.join("home");
        fs::create_dir_all(&bin).unwrap();
        let source = sibling_binary_directory().unwrap();
        let net = bin.join("asl-net.exe");
        let worker = bin.join("asl-worker.exe");
        fs::copy(source.join("asl-net.exe"), &net).unwrap();
        fs::copy(source.join("asl-worker.exe"), &worker).unwrap();

        let mut supervisor = Supervisor::start_with_launcher(
            AppPaths::open(&home).unwrap(),
            SandboxLauncher::new(net.clone(), worker, net.clone()).unwrap(),
        )
        .expect("real Net and Worker AppContainers must start");
        supervisor.ping_net().unwrap();
        assert_eq!(
            supervisor.validate_control_frame([9; 16], &[0xff]).unwrap(),
            TaskStatus::Invalid
        );
        assert!(
            run_worker_validation_with(
                &supervisor.launcher,
                [11; 16],
                &[0xff],
                SandboxChild::terminate,
            )
            .is_err(),
            "terminating a Worker during its task must fail that task"
        );
        assert_eq!(
            supervisor
                .validate_control_frame([12; 16], &[0xff])
                .unwrap(),
            TaskStatus::Invalid,
            "a fresh Worker must complete the next task"
        );
        supervisor.ping_net().unwrap();
        drop(supervisor);

        let broken_worker = Supervisor::start_with_launcher(
            AppPaths::open(&home).unwrap(),
            SandboxLauncher::new(net.clone(), net.clone(), net).unwrap(),
        )
        .expect("Net must start independently of the worker executable");
        assert!(
            broken_worker
                .validate_control_frame([10; 16], &[0xff])
                .is_err()
        );
        let mut broken_worker = broken_worker;
        broken_worker.ping_net().unwrap();
        drop(broken_worker);
        drop(fixture);
    }
}
