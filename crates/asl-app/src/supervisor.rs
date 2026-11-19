use std::collections::VecDeque;
use std::env;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use asl_net::transport::TransportKind;
use asl_policy::sandbox::{
    BrokerPipes, InheritedPipes, SandboxChild, SandboxLauncher, SandboxLimits, SandboxRole,
};
use asl_types::{
    error::AslError,
    ids::{AgentId, PeerId},
};
use rand::{TryRng, rngs::SysRng};

use crate::chain::DurableIdentityResolver;
use crate::chain_refresh::{ChainRefreshEvent, ChainRefreshWorker};
use crate::identity::{AgentIdentity, DeviceIdentity};
use crate::ipc::{
    FrameReader, FrameWriter, IpcFrame, IpcMessage, IpcRole, MAX_IPC_TASK_PAYLOAD_BYTES,
    NetworkErrorCode, TaskStatus, WorkerOperation, write_device_identity_prelude,
};
use crate::libraries::LocalLibraries;
use crate::network::{LocalNetworkObservation, NetworkCommand, NetworkEvent};
use crate::network_identity::{NetworkAdmissionStatus, load_network_admission};
use crate::network_settings::NetworkSettingsV1;
use crate::paths::AppPaths;
use crate::profile::{AdmissionBatch, AdmittedNetworkEvent, CoreAdmission};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const NET_PING_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PENDING_NETWORK_EVENTS: usize = 64;
const NETWORK_EVENT_POLL_INTERVAL: Duration = Duration::from_millis(250);
const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(5);

pub struct Supervisor {
    agent_identity: AgentIdentity,
    device_peer_id: PeerId,
    libraries: LocalLibraries,
    launcher: SandboxLauncher,
    net: NetRuntime,
    pub(crate) admission: Option<CoreAdmission>,
    network_admission_status: NetworkAdmissionStatus,
    chain_refresh: Option<ChainRefreshWorker>,
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
        let network_settings = NetworkSettingsV1::load(&paths.network_settings_configuration())?;
        let agent_identity = AgentIdentity::load_or_create_protected(&paths.agent_root_key())?;
        let device_identity = DeviceIdentity::load_or_create_protected(&paths.device_key())?;
        let device_peer_id = device_identity.peer_id();
        let libraries = LocalLibraries::open(&paths)?;
        let network_admission =
            load_network_admission(&paths, &agent_identity, device_peer_id.clone())?;
        let net = NetRuntime::start(&launcher, &device_identity)?;
        let mut supervisor = Self {
            agent_identity,
            device_peer_id,
            libraries,
            launcher,
            net,
            admission: network_admission.admission,
            network_admission_status: network_admission.status,
            chain_refresh: network_admission.refresh_worker,
        };
        supervisor.apply_network_settings(&network_settings)?;
        Ok(supervisor)
    }

    fn apply_network_settings(&mut self, settings: &NetworkSettingsV1) -> Result<(), AslError> {
        settings.validate()?;
        self.send_startup_network_operation(|operation_id| NetworkCommand::SetAddressPolicy {
            operation_id,
            policy: settings.address_policy(),
        })?;

        for address in &settings.relay_addresses {
            let address = asl_net::relay::relay_endpoint_config(address)?;
            self.send_startup_network_operation(|operation_id| NetworkCommand::ReserveRelay {
                operation_id,
                address,
            })?;
        }

        if !settings.listen_on_interfaces {
            return Ok(());
        }

        for (kind, port) in [
            (TransportKind::Tcp, settings.tcp_port),
            (TransportKind::Quic, settings.quic_port),
        ] {
            self.send_startup_network_operation(|operation_id| NetworkCommand::Listen {
                operation_id,
                kind,
                address: settings.listener_address(port),
            })?;
        }
        Ok(())
    }

    fn send_startup_network_operation(
        &mut self,
        command: impl FnOnce([u8; 16]) -> NetworkCommand,
    ) -> Result<(), AslError> {
        let mut operation_id = [0; 16];
        for _ in 0..8 {
            SysRng
                .try_fill_bytes(&mut operation_id)
                .map_err(|_| AslError::InvalidIdentity)?;
            if operation_id != [0; 16] {
                self.send_network_command(command(operation_id))?;
                return self.net.wait_for_operation(operation_id, STARTUP_TIMEOUT);
            }
        }
        Err(AslError::InvalidIdentity)
    }

    pub fn agent_id(&self) -> AgentId {
        self.agent_identity.agent_id()
    }

    pub fn network_admission_status(&self) -> NetworkAdmissionStatus {
        self.network_admission_status
    }

    pub fn activate_network_admission(
        &mut self,
        signed_directory: Vec<u8>,
        resolver: DurableIdentityResolver,
        now_ms: u64,
    ) -> Result<(), AslError> {
        if self.admission.is_some() {
            return Err(AslError::PolicyDenied);
        }
        let admission = CoreAdmission::for_local_identity(
            &self.agent_identity,
            self.device_peer_id.clone(),
            signed_directory,
            resolver,
            now_ms,
        )?;
        self.admission = Some(admission);
        self.network_admission_status = NetworkAdmissionStatus::Active;
        Ok(())
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
        self.net.wait_for_pong(nonce, NET_PING_TIMEOUT)
    }

    pub(crate) fn send_network_ipc(&mut self, message: IpcMessage) -> Result<(), AslError> {
        self.net.send(&message)
    }

    pub(crate) fn receive_network_ipc(
        &mut self,
        timeout: Duration,
    ) -> Result<IpcMessage, AslError> {
        self.net.receive_network_event(timeout)
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

    pub fn run(self) -> Result<(), AslError> {
        self.run_with_network_handler(|_| Vec::new())
    }

    /// Runs the authenticated network event pump. The handler sees only
    /// identity-admitted peer events; returned application commands are
    /// independently checked against the current connection admission.
    pub fn run_with_network_handler(
        self,
        handler: impl FnMut(AdmittedNetworkEvent) -> Vec<NetworkCommand>,
    ) -> Result<(), AslError> {
        self.run_with_network_observers(handler, |_| {})
    }

    /// Passes local discovery observations to a read-only callback, separate from
    /// the identity-admitted Agent event handler.
    pub fn run_with_network_observers(
        mut self,
        mut handler: impl FnMut(AdmittedNetworkEvent) -> Vec<NetworkCommand>,
        mut observer: impl FnMut(LocalNetworkObservation),
    ) -> Result<(), AslError> {
        let mut next_health_check = Instant::now();
        let mut next_ping = Instant::now();
        loop {
            self.process_chain_refresh()?;
            if self.network_admission_status == NetworkAdmissionStatus::Active {
                let now_ms = unix_time_ms()?;
                let batch = self
                    .admission
                    .as_mut()
                    .map(|admission| admission.poll(now_ms))
                    .unwrap_or_default();
                self.dispatch_admission_batch(batch, now_ms, &mut handler)?;
            }
            let now = Instant::now();
            if now >= next_health_check {
                self.libraries.check_health()?;
                next_health_check = now + HEALTH_CHECK_INTERVAL;
            }
            if self
                .net
                .pending_pong
                .is_some_and(|(_, deadline)| now >= deadline)
            {
                return Err(AslError::SandboxUnavailable);
            }
            if now >= next_ping {
                self.net.start_ping(now)?;
                next_ping = now + HEALTH_CHECK_INTERVAL;
            }

            let Some(message) = self
                .net
                .receive_runtime_message_optional(NETWORK_EVENT_POLL_INTERVAL)?
            else {
                continue;
            };
            let event = match message {
                IpcMessage::Pong { nonce } => {
                    self.net.acknowledge_pong(nonce)?;
                    continue;
                }
                message if is_network_event(&message) => NetworkEvent::try_from(message)?,
                _ => return Err(AslError::InvalidMessage),
            };
            if let Some(observation) = event.as_local_observation() {
                observer(observation);
                continue;
            }
            let now_ms = unix_time_ms()?;
            let batch = if self.network_admission_status != NetworkAdmissionStatus::Active {
                reject_unadmitted_event(event)
            } else {
                match self.admission.as_mut() {
                    Some(admission) => admission.handle_event(event, now_ms),
                    None => reject_unadmitted_event(event),
                }
            };
            self.dispatch_admission_batch(batch, now_ms, &mut handler)?;
        }
    }

    fn dispatch_admission_batch(
        &mut self,
        batch: AdmissionBatch,
        now_ms: u64,
        handler: &mut impl FnMut(AdmittedNetworkEvent) -> Vec<NetworkCommand>,
    ) -> Result<(), AslError> {
        for command in batch.commands {
            self.send_network_command(command)?;
        }
        for event in batch.events {
            for command in handler(event) {
                self.send_admitted_network_command(command, now_ms)?;
            }
        }
        Ok(())
    }

    fn process_chain_refresh(&mut self) -> Result<(), AslError> {
        let Some(event) = self
            .chain_refresh
            .as_ref()
            .and_then(ChainRefreshWorker::try_recv)
        else {
            return Ok(());
        };
        match event {
            ChainRefreshEvent::Updated(candidate) => {
                let now_ms = unix_time_ms()?;
                let result = self.admission.as_mut().map(|admission| {
                    admission.refresh_local_identity(
                        candidate.light_client,
                        &candidate.proof,
                        now_ms,
                    )
                });
                match result {
                    Some(Ok(true)) => {
                        self.network_admission_status = NetworkAdmissionStatus::Active;
                    }
                    Some(Ok(false)) => {
                        self.suspend_network_admission(
                            NetworkAdmissionStatus::RegistryAnchorMissing,
                        )?;
                    }
                    Some(Err(_)) | None => {
                        self.suspend_network_admission(NetworkAdmissionStatus::ChainUnavailable)?;
                    }
                }
            }
            ChainRefreshEvent::Unavailable => {
                self.suspend_network_admission(NetworkAdmissionStatus::ChainUnavailable)?;
            }
        }
        Ok(())
    }

    fn suspend_network_admission(
        &mut self,
        status: NetworkAdmissionStatus,
    ) -> Result<(), AslError> {
        self.network_admission_status = status;
        if let Some(admission) = self.admission.as_mut() {
            for command in admission.close_all().commands {
                self.send_network_command(command)?;
            }
        }
        Ok(())
    }
}

struct NetRuntime {
    child: Option<SandboxChild>,
    writer: Option<FrameWriter<File>>,
    events: Option<Receiver<Result<IpcFrame, AslError>>>,
    reader_thread: Option<JoinHandle<()>>,
    next_nonce: u64,
    pending_pong: Option<(u64, Instant)>,
    pending_network_events: VecDeque<IpcMessage>,
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
            pending_pong: None,
            pending_network_events: VecDeque::new(),
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
        self.receive_optional(timeout)?
            .ok_or(AslError::SandboxUnavailable)
    }

    fn wait_for_operation(
        &mut self,
        operation_id: [u8; 16],
        timeout: Duration,
    ) -> Result<(), AslError> {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(AslError::SandboxUnavailable);
            }
            let Some(frame) = self.receive_optional(remaining)? else {
                return Err(AslError::SandboxUnavailable);
            };
            match frame.message {
                IpcMessage::OperationAccepted {
                    operation_id: received,
                } if received == operation_id => return Ok(()),
                IpcMessage::OperationFailed {
                    operation_id: received,
                    code,
                } if received == operation_id => {
                    return Err(match code {
                        NetworkErrorCode::InvalidCommand => AslError::PolicyDenied,
                        _ => AslError::SandboxUnavailable,
                    });
                }
                message if is_network_event(&message) => {
                    if self.pending_network_events.len() >= MAX_PENDING_NETWORK_EVENTS {
                        return Err(AslError::SandboxUnavailable);
                    }
                    self.pending_network_events.push_back(message);
                }
                _ => return Err(AslError::InvalidMessage),
            }
        }
    }

    fn receive_optional(&self, timeout: Duration) -> Result<Option<IpcFrame>, AslError> {
        match self
            .events
            .as_ref()
            .ok_or(AslError::SandboxUnavailable)?
            .recv_timeout(timeout)
        {
            Ok(result) => result.map(Some),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => Err(AslError::SandboxUnavailable),
        }
    }

    fn send(&mut self, message: &IpcMessage) -> Result<(), AslError> {
        self.writer
            .as_mut()
            .ok_or(AslError::SandboxUnavailable)?
            .send(message)
    }

    fn start_ping(&mut self, now: Instant) -> Result<(), AslError> {
        if self.pending_pong.is_some() {
            return Err(AslError::InvalidPolicyState);
        }
        let nonce = self.next_nonce;
        self.next_nonce = nonce.checked_add(1).ok_or(AslError::InvalidMessage)?;
        self.send(&IpcMessage::Ping { nonce })?;
        self.pending_pong = Some((nonce, now + NET_PING_TIMEOUT));
        Ok(())
    }

    fn acknowledge_pong(&mut self, nonce: u64) -> Result<(), AslError> {
        match self.pending_pong {
            Some((expected, _)) if expected == nonce => {
                self.pending_pong = None;
                Ok(())
            }
            _ => Err(AslError::InvalidMessage),
        }
    }

    fn wait_for_pong(&mut self, nonce: u64, timeout: Duration) -> Result<(), AslError> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(AslError::SandboxUnavailable);
            }
            let message = self.receive(remaining)?.message;
            match message {
                IpcMessage::Pong { nonce: received } if received == nonce => return Ok(()),
                message if is_network_event(&message) => {
                    if self.pending_network_events.len() >= MAX_PENDING_NETWORK_EVENTS {
                        return Err(AslError::SandboxUnavailable);
                    }
                    self.pending_network_events.push_back(message);
                }
                _ => return Err(AslError::InvalidMessage),
            }
        }
    }

    fn receive_network_event(&mut self, timeout: Duration) -> Result<IpcMessage, AslError> {
        self.receive_network_event_optional(timeout)?
            .ok_or(AslError::SandboxUnavailable)
    }

    fn receive_network_event_optional(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<IpcMessage>, AslError> {
        match self.receive_runtime_message_optional(timeout)? {
            Some(message) if is_network_event(&message) => Ok(Some(message)),
            Some(_) => Err(AslError::InvalidMessage),
            None => Ok(None),
        }
    }

    fn receive_runtime_message_optional(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<IpcMessage>, AslError> {
        if let Some(event) = self.pending_network_events.pop_front() {
            return Ok(Some(event));
        }
        match self.receive_optional(timeout)? {
            Some(frame) => Ok(Some(frame.message)),
            None => Ok(None),
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

fn is_network_event(message: &IpcMessage) -> bool {
    matches!(
        message,
        IpcMessage::OperationAccepted { .. }
            | IpcMessage::OperationFailed { .. }
            | IpcMessage::Listening { .. }
            | IpcMessage::RelayReserved { .. }
            | IpcMessage::RelayUnavailable { .. }
            | IpcMessage::DiscoveryCandidate { .. }
            | IpcMessage::PeerAuthenticated { .. }
            | IpcMessage::PeerDisconnected { .. }
            | IpcMessage::IdentityProofRequested { .. }
            | IpcMessage::IdentityProofReceived { .. }
            | IpcMessage::ControlRequested { .. }
            | IpcMessage::ControlReceived { .. }
            | IpcMessage::BulkRequested { .. }
            | IpcMessage::BulkReceived { .. }
            | IpcMessage::RequestFailed { .. }
            | IpcMessage::NetworkError { .. }
    )
}

fn reject_unadmitted_event(event: NetworkEvent) -> AdmissionBatch {
    let mut batch = AdmissionBatch::default();
    match event {
        NetworkEvent::OperationAccepted { operation_id } => batch
            .events
            .push(AdmittedNetworkEvent::OperationAccepted { operation_id }),
        NetworkEvent::OperationFailed { operation_id, code } => batch
            .events
            .push(AdmittedNetworkEvent::OperationFailed { operation_id, code }),
        NetworkEvent::Listening { kind, address } => {
            batch
                .events
                .push(AdmittedNetworkEvent::Listening { kind, address });
        }
        NetworkEvent::RelayReserved {
            relay_peer_id,
            address,
        } => batch.events.push(AdmittedNetworkEvent::RelayReserved {
            relay_peer_id,
            address,
        }),
        NetworkEvent::RelayUnavailable { relay_peer_id } => {
            batch
                .events
                .push(AdmittedNetworkEvent::RelayUnavailable { relay_peer_id });
        }
        NetworkEvent::DiscoveryCandidate { .. } => {}
        NetworkEvent::PeerDisconnected { connection_id } => {
            batch.events.push(AdmittedNetworkEvent::PeerDisconnected {
                connection_id,
                agent_id: None,
            });
        }
        NetworkEvent::NetworkError { code } => {
            batch
                .events
                .push(AdmittedNetworkEvent::NetworkError { code });
        }
        event => {
            if let Some(connection_id) = event_connection_id(&event) {
                batch
                    .commands
                    .push(NetworkCommand::CloseConnection { connection_id });
            }
        }
    }
    batch
}

fn event_connection_id(event: &NetworkEvent) -> Option<[u8; 16]> {
    match event {
        NetworkEvent::TransportConnected { connection_id, .. }
        | NetworkEvent::IdentityProofRequested { connection_id, .. }
        | NetworkEvent::IdentityProofReceived { connection_id, .. }
        | NetworkEvent::UnverifiedControlRequest { connection_id, .. }
        | NetworkEvent::UnverifiedControlResponse { connection_id, .. }
        | NetworkEvent::UnverifiedBulkRequest { connection_id, .. }
        | NetworkEvent::UnverifiedBulkResponse { connection_id, .. }
        | NetworkEvent::RequestFailed { connection_id, .. } => Some(*connection_id),
        NetworkEvent::OperationAccepted { .. }
        | NetworkEvent::OperationFailed { .. }
        | NetworkEvent::Listening { .. }
        | NetworkEvent::RelayReserved { .. }
        | NetworkEvent::RelayUnavailable { .. }
        | NetworkEvent::DiscoveryCandidate { .. }
        | NetworkEvent::PeerDisconnected { .. }
        | NetworkEvent::NetworkError { .. } => None,
    }
}

fn unix_time_ms() -> Result<u64, AslError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .ok_or(AslError::ExpiredMessage)
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
    use crate::ipc::NetworkErrorCode;
    use crate::network::LocalNetworkObservation;
    use asl_net::transport::DiscoveryCandidateState;
    use asl_types::{error::ErrorCode, ids::Id128, protocol::ProtocolError};
    use std::io::Cursor;

    #[test]
    fn discovery_candidate_is_exposed_only_as_a_local_observation() {
        let event = NetworkEvent::DiscoveryCandidate {
            peer_id: DeviceIdentity::generate().unwrap().peer_id(),
            kind: TransportKind::Tcp,
            address: "192.168.1.10:4001".parse().unwrap(),
            state: DiscoveryCandidateState::Discovered,
        };

        assert!(matches!(
            event.as_local_observation(),
            Some(LocalNetworkObservation::DiscoveryCandidate {
                state: DiscoveryCandidateState::Discovered,
                ..
            })
        ));
        assert!(reject_unadmitted_event(event).events.is_empty());
    }

    #[test]
    fn unadmitted_connections_are_closed_before_control_events_are_exposed() {
        let connection_id = [23; 16];
        let event = NetworkEvent::UnverifiedControlRequest {
            connection_id,
            response_id: [24; 16],
            request: asl_types::protocol::WireFrame::Error(ProtocolError {
                message_id: Id128([25; 16]),
                code: ErrorCode::PolicyDenied,
            }),
        };

        let batch = reject_unadmitted_event(event);

        assert!(batch.events.is_empty());
        assert_eq!(
            batch.commands,
            vec![NetworkCommand::CloseConnection { connection_id }]
        );
    }

    #[test]
    fn unadmitted_transport_status_remains_observable() {
        let operation_id = [26; 16];

        let batch = reject_unadmitted_event(NetworkEvent::OperationAccepted { operation_id });

        assert!(batch.commands.is_empty());
        assert_eq!(
            batch.events,
            vec![AdmittedNetworkEvent::OperationAccepted { operation_id }]
        );
    }

    #[test]
    fn network_event_poll_timeout_is_distinct_from_net_shutdown() {
        let (sender, receiver) = mpsc::sync_channel(1);
        let mut runtime = NetRuntime {
            child: None,
            writer: None,
            events: Some(receiver),
            reader_thread: None,
            next_nonce: 1,
            pending_pong: None,
            pending_network_events: VecDeque::new(),
        };

        assert_eq!(
            runtime
                .receive_network_event_optional(Duration::ZERO)
                .unwrap(),
            None
        );
        sender
            .send(Ok(IpcFrame {
                role: IpcRole::Net,
                sequence: 1,
                message: IpcMessage::NetworkError {
                    code: NetworkErrorCode::Transport,
                },
            }))
            .unwrap();
        assert_eq!(
            runtime
                .receive_network_event_optional(Duration::from_secs(1))
                .unwrap(),
            Some(IpcMessage::NetworkError {
                code: NetworkErrorCode::Transport
            })
        );
    }

    #[test]
    fn startup_operation_wait_preserves_unrelated_network_events() {
        let (sender, receiver) = mpsc::sync_channel(2);
        let operation_id = [43; 16];
        sender
            .send(Ok(IpcFrame {
                role: IpcRole::Net,
                sequence: 1,
                message: IpcMessage::NetworkError {
                    code: NetworkErrorCode::Transport,
                },
            }))
            .unwrap();
        sender
            .send(Ok(IpcFrame {
                role: IpcRole::Net,
                sequence: 2,
                message: IpcMessage::OperationAccepted { operation_id },
            }))
            .unwrap();
        let mut runtime = NetRuntime {
            child: None,
            writer: None,
            events: Some(receiver),
            reader_thread: None,
            next_nonce: 1,
            pending_pong: None,
            pending_network_events: VecDeque::new(),
        };

        runtime
            .wait_for_operation(operation_id, Duration::from_secs(1))
            .unwrap();
        assert_eq!(
            runtime
                .receive_runtime_message_optional(Duration::ZERO)
                .unwrap(),
            Some(IpcMessage::NetworkError {
                code: NetworkErrorCode::Transport
            })
        );
    }

    #[test]
    fn net_heartbeat_only_accepts_the_current_nonce() {
        let (_sender, receiver) = mpsc::sync_channel(1);
        let mut runtime = NetRuntime {
            child: None,
            writer: None,
            events: Some(receiver),
            reader_thread: None,
            next_nonce: 2,
            pending_pong: Some((41, Instant::now() + NET_PING_TIMEOUT)),
            pending_network_events: VecDeque::new(),
        };

        assert!(runtime.acknowledge_pong(40).is_err());
        assert!(runtime.pending_pong.is_some());
        runtime.acknowledge_pong(41).unwrap();
        assert!(runtime.pending_pong.is_none());
    }

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
        use crate::ipc::NetworkErrorCode;
        use crate::network::{NetworkCommand, NetworkEvent};
        use asl_net::transport::TransportKind;
        use std::fs;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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

        let listen_operation = [13; 16];
        supervisor
            .send_network_command(NetworkCommand::Listen {
                operation_id: listen_operation,
                kind: TransportKind::Tcp,
                address: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            })
            .unwrap();
        assert_eq!(
            supervisor
                .receive_network_event(Duration::from_secs(5))
                .unwrap(),
            NetworkEvent::OperationFailed {
                operation_id: listen_operation,
                code: NetworkErrorCode::Transport,
            },
            "Net IPC must report the operation ID when address policy rejects a listener"
        );

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
