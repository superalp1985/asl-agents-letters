use std::collections::{HashMap, VecDeque};
use std::env;
use std::io::Read;
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
    mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use asl_agent::gateway::{
    AuthorizedPrompt, HttpModelGateway, ModelGateway, ModelGatewayError, ModelText,
};
#[cfg(any(windows, test))]
use asl_net::transport::TransportKind;
use asl_policy::{
    PolicyService,
    sandbox::{
        BrokerPipes, InheritedPipes, SandboxChild, SandboxLauncher, SandboxLimits, SandboxRole,
    },
    snapshot_files::ProfileOwner,
};
use asl_types::{
    error::AslError,
    ids::{AgentId, PeerId},
    protocol::{PairingExchange, PairingInvite, WireFrame},
    record::short_code,
    task::ProviderId,
};

use crate::chain::DurableIdentityResolver;
use crate::chain_refresh::{ChainRefreshEvent, ChainRefreshWorker};
use crate::direct_inbound::{self, DirectInbound};
use crate::direct_outbound::DirectOutbound;
use crate::documents::{MAX_AVATAR_BYTES, MAX_DOCUMENT_TEXT_BYTES};
use crate::downloads::{
    DownloadBridge, DownloadDriverEvent, DownloadEnqueue, DownloadRuntime, WorkerRequest,
    download_channel,
};
use crate::identity::{AgentIdentity, DeviceIdentity};
use crate::ipc::{
    ExtractorOperation, ExtractorStatus, FrameReader, FrameWriter, IpcFrame, IpcMessage, IpcRole,
    MAX_IPC_EXTRACTOR_INPUT_BYTES, MAX_IPC_TASK_PAYLOAD_BYTES, NetworkErrorCode, NetworkProtocol,
    TaskStatus, WorkerOperation, encode_frame, write_net_startup_prelude,
};
use crate::libraries::LocalLibraries;
use crate::model_endpoint_access::configured_model_gateway;
use crate::network::{LocalNetworkObservation, NetworkCommand, NetworkEvent};
use crate::network_identity::{NetworkAdmissionStatus, load_network_admission};
use crate::network_settings::NetworkSettingsV1;
use crate::pairing::{self, PairingAuthorization};
use crate::paths::AppPaths;
use crate::profile::{
    AdmissionBatch, AdmittedNetworkEvent, CoreAdmission, MAX_ADMISSION_CONNECTIONS, fresh_id,
};
use crate::transfer::{ReceivedBulk, TransferService};
use crate::{OutgoingQueryRuntime, outgoing_query_channel};
use asl_store::network_privacy::NetworkRuntimeState;
use asl_store::{
    dashboard::LocalIdentityProjection, open_store, search::direct::open_direct_store,
};

mod auto_reply;
mod auto_reply_evidence;
mod avatar_download;
mod bindings;
mod contact_invites;
mod dht_cache;
mod directory;
#[cfg(windows)]
mod group_routing;
#[cfg(windows)]
mod groups;
#[cfg(windows)]
mod mail;
#[cfg(windows)]
mod mailbox_wire;
mod network_pause;
mod network_report;
mod onboarding_publication;
mod profile_signing;
mod resource_providers;
#[cfg(windows)]
pub use groups::{LocalGroupAction, LocalGroupCommand, run_with_local_groups_from_environment};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const NET_PING_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PENDING_NETWORK_EVENTS: usize = 64;
const MAX_PENDING_NET_WRITES: usize = 8;
const NET_ADMISSION_WRITE_HEADROOM: usize = 2;
const NETWORK_EVENT_POLL_INTERVAL: Duration = Duration::from_millis(250);
const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(5);
const ACTIVITY_PRUNE_INTERVAL: Duration = Duration::from_secs(60);
const DIRECTORY_RENEWAL_RETRY_INTERVAL: Duration = Duration::from_secs(10);

pub struct Supervisor {
    #[cfg(windows)]
    auto_reply: auto_reply::AutoReplyRuntime,
    #[cfg(windows)]
    mailbox: crate::agent_mail::Mailbox,
    #[cfg(windows)]
    mailbox_wire: mailbox_wire::MailboxWireRuntime,
    agent_identity: AgentIdentity,
    device_peer_id: PeerId,
    libraries: LocalLibraries,
    launcher: SandboxLauncher,
    model_gateway: HttpModelGateway,
    net: NetRuntime,
    network_settings: NetworkSettingsV1,
    device_key_path: PathBuf,
    transport_connections: HashMap<[u8; 16], PeerId>,
    network_report: network_report::NetworkStatus,
    onboarding_publication: onboarding_publication::OnboardingPublicationRuntime,
    profile_signing: profile_signing::ProfileSigningRuntime,
    pub(crate) admission: Option<CoreAdmission>,
    network_admission_status: NetworkAdmissionStatus,
    #[cfg(windows)]
    mcp_readiness: tokio::sync::watch::Sender<NetworkAdmissionStatus>,
    chain_refresh: Option<ChainRefreshWorker>,
    home: PathBuf,
    state_database: PathBuf,
    directory_reader: Option<directory::DirectoryReader>,
    directory_removed: bool,
    directory_renewal_retry_at: Instant,
    contact_bindings: bindings::ContactBindingRuntime,
    contact_invites: contact_invites::ContactInviteRuntime,
    resource_providers: resource_providers::ResourceProviderRuntime,
    dht_restore: dht_cache::DhtRestoreRuntime,
    pending_disconnects: PendingDisconnects,
    #[cfg(windows)]
    groups: Option<groups::LoopbackGroups>,
    #[cfg(windows)]
    group_controls: Option<Receiver<LocalGroupCommand>>,
    pub(crate) pending_pairing_prompts: pairing::PendingPairingPrompts,
    _owner: ProfileOwner,
}

impl Supervisor {
    pub fn start(paths: AppPaths) -> Result<Self, AslError> {
        let directory = sibling_binary_directory()?;
        let launcher = SandboxLauncher::new(
            directory.join("asl-net.exe"),
            directory.join("asl-worker.exe"),
            directory.join("asl-extractor.exe"),
        )?;
        Self::start_with_launcher(paths, launcher)
    }

    fn start_with_launcher(paths: AppPaths, launcher: SandboxLauncher) -> Result<Self, AslError> {
        Self::start_with_net(paths, launcher, NetRuntime::start)
    }

    fn start_with_net(
        paths: AppPaths,
        launcher: SandboxLauncher,
        start_net: impl FnOnce(
            &SandboxLauncher,
            &DeviceIdentity,
            bool,
            asl_net::transport::TraversalConfig,
        ) -> Result<NetRuntime, AslError>,
    ) -> Result<Self, AslError> {
        let owner = ProfileOwner::core(paths.dos_root())?;
        let state_database = paths.state().join("asl.sqlite3");
        let mut settings = NetworkSettingsV1::load(&paths.network_settings_configuration())?;
        let packaged_seeds = sibling_binary_directory()?
            .join("assets")
            .join("network-seeds.json");
        let profile_seeds = paths.network_seeds();
        let seeds = if profile_seeds.try_exists()? {
            crate::paths::validate_existing_components(&profile_seeds)?;
            &profile_seeds
        } else {
            &packaged_seeds
        };
        settings.apply_packaged_bootstrap(seeds, unix_time_ms()?)?;
        let network_store = open_store(&state_database)?;
        let _ = network_store.prune_dht_cache(unix_time_ms()?);
        let network_settings =
            settings.with_relay_only_override(network_store.force_relay_only()?)?;
        let model_gateway =
            configured_model_gateway(&paths).map_err(|_| AslError::InvalidPolicyState)?;
        let (agent_identity, device_identity) =
            crate::profile_setup::ensure_local_identity(&paths)?;
        let device_key_path = paths.device_key();
        let device_peer_id = device_identity.peer_id();
        let libraries = LocalLibraries::open(&paths)?;
        let network_admission =
            load_network_admission(&paths, &agent_identity, device_peer_id.clone())?;
        let directory_reader = network_admission
            .refresh_worker
            .as_ref()
            .map(|_| directory::DirectoryReader::spawn(paths.signed_device_directory()))
            .transpose()?;
        #[cfg(windows)]
        let groups = network_settings
            .loopback_groups
            .then(|| groups::LoopbackGroups::open(&state_database, unix_time_ms()?))
            .transpose()?;
        #[cfg(not(windows))]
        if network_settings.loopback_groups {
            return Err(AslError::PlatformUnavailable);
        }
        let paused = network_store.network_pause_requested()?;
        let net = if paused {
            NetRuntime::default()
        } else {
            start_net(
                &launcher,
                &device_identity,
                network_settings.loopback_groups,
                network_settings.traversal.transport_config()?,
            )?
        };
        #[cfg(windows)]
        let auto_reply = auto_reply::AutoReplyRuntime::spawn(&paths)?;
        let mut supervisor = Self {
            #[cfg(windows)]
            auto_reply,
            #[cfg(windows)]
            mailbox: Default::default(),
            #[cfg(windows)]
            mailbox_wire: Default::default(),
            agent_identity,
            device_peer_id,
            libraries,
            launcher,
            model_gateway,
            net,
            profile_signing: profile_signing::ProfileSigningRuntime::open(&state_database)?,
            onboarding_publication: onboarding_publication::OnboardingPublicationRuntime::new(),
            network_report: network_report::NetworkStatus::new(network_store, &network_settings),
            network_settings,
            device_key_path,
            transport_connections: HashMap::new(),
            admission: network_admission.admission,
            network_admission_status: network_admission.status,
            #[cfg(windows)]
            mcp_readiness: tokio::sync::watch::Sender::new(network_admission.status),
            chain_refresh: network_admission.refresh_worker,
            home: paths.dos_root().to_owned(),
            state_database,
            directory_reader,
            directory_removed: false,
            directory_renewal_retry_at: Instant::now(),
            contact_bindings: bindings::ContactBindingRuntime::default(),
            contact_invites: contact_invites::ContactInviteRuntime::default(),
            resource_providers: resource_providers::ResourceProviderRuntime::default(),
            dht_restore: dht_cache::DhtRestoreRuntime::default(),
            pending_disconnects: PendingDisconnects::default(),
            #[cfg(windows)]
            groups,
            #[cfg(windows)]
            group_controls: None,
            pending_pairing_prompts: pairing::PendingPairingPrompts::default(),
            _owner: owner,
        };
        supervisor.persist_local_identity_projection();
        #[cfg(windows)]
        supervisor.configure_group_admission();
        if paused {
            supervisor
                .network_report
                .set_runtime(NetworkRuntimeState::Paused);
        } else {
            supervisor
                .net
                .apply_settings(&supervisor.network_settings)?;
            supervisor.reload_dht_restore()?;
            supervisor.pump_dht_restore()?;
            supervisor
                .network_report
                .set_runtime(NetworkRuntimeState::Running);
        }
        Ok(supervisor)
    }

    #[cfg(all(test, windows))]
    fn send_startup_network_operation(
        &mut self,
        command: impl FnOnce([u8; 16]) -> NetworkCommand,
    ) -> Result<(), AslError> {
        self.net.send_startup_operation(command)
    }

    pub fn agent_id(&self) -> AgentId {
        self.agent_identity.agent_id()
    }
    pub async fn complete_model(
        &self,
        provider_id: &ProviderId,
        prompt: AuthorizedPrompt,
        policy: &(dyn PolicyService + Sync),
        now_ms: u64,
    ) -> Result<ModelText, ModelGatewayError> {
        self.model_gateway
            .complete(provider_id, prompt, policy, now_ms)
            .await
    }

    pub fn network_admission_status(&self) -> NetworkAdmissionStatus {
        self.network_admission_status
    }

    pub fn issue_pairing_invite(
        &mut self,
        connection_id: [u8; 16],
        target: AgentId,
        note: &str,
        now_ms: u64,
    ) -> Result<PairingInvite, AslError> {
        let invite = pairing::issue_signed_invite(&self.agent_identity, target, note, now_ms)?;
        let request_id = fresh_id()?;
        self.send_network_command(NetworkCommand::RequestPairing {
            connection_id,
            request_id,
            invite: invite.clone(),
        })?;
        Ok(invite)
    }

    pub(crate) fn answer_pairing_invite(
        &mut self,
        connection_id: [u8; 16],
        response_id: [u8; 16],
        invite: PairingInvite,
        authorization: PairingAuthorization,
        now_ms: u64,
    ) -> Result<PairingExchange, AslError> {
        let admission = self.admission.as_mut().ok_or(AslError::InvalidIdentity)?;
        let (remote_agent, exchange) = pairing::prepare_answer(
            &self.agent_identity,
            admission,
            &self.device_peer_id,
            connection_id,
            &invite,
            authorization,
            now_ms,
        )?;
        self.send_network_command(NetworkCommand::ReplyPairing {
            connection_id,
            response_id,
            exchange: exchange.clone(),
        })?;
        let mut store = open_store(&self.state_database)?;
        if !pairing::commit_answer(&mut store, remote_agent, &invite, &exchange, now_ms)? {
            return Err(AslError::InvalidMessage);
        }
        Ok(exchange)
    }

    pub(crate) fn verify_pairing_response(
        &mut self,
        event: AdmittedNetworkEvent,
        _now_ms: u64,
    ) -> Result<Option<AdmittedNetworkEvent>, AslError> {
        if !matches!(event, AdmittedNetworkEvent::PairingExchangeReceived { .. }) {
            return Ok(Some(event));
        }
        Ok(Some(event))
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
        #[cfg(windows)]
        self.configure_group_admission();
        self.set_network_admission_status(NetworkAdmissionStatus::Active);
        Ok(())
    }

    fn set_network_admission_status(&mut self, status: NetworkAdmissionStatus) {
        if self.network_admission_status == status {
            return;
        }
        self.network_admission_status = status;
        #[cfg(windows)]
        self.mcp_readiness.send_replace(status);
        self.persist_local_identity_projection();
    }

    fn persist_local_identity_projection(&self) {
        let Ok(store) = open_store(&self.state_database) else {
            return;
        };
        let projection = LocalIdentityProjection {
            agent_id: bs58::encode(self.agent_identity.agent_id().as_bytes()).into_string(),
            peer_id: bs58::encode(self.device_peer_id.as_bytes()).into_string(),
            network_state: self.network_admission_status.dashboard_state().to_owned(),
            binding_code: format!("{:016}", short_code(self.agent_identity.agent_id())),
        };
        let _ = store.set_local_identity_projection(&projection);
    }

    /// Trusted in-process entry point only; not dispatched from Net or Worker IPC.
    pub fn local_libraries(&mut self) -> &mut LocalLibraries {
        &mut self.libraries
    }

    pub fn ping_net(&mut self) -> Result<(), AslError> {
        let nonce = self.net.next_nonce;
        self.net.next_nonce = nonce.checked_add(1).ok_or(AslError::InvalidMessage)?;
        self.net.send(&IpcMessage::Ping { nonce })?;
        self.net.wait_for_pong(nonce, NET_PING_TIMEOUT)
    }

    /// One-shot typed DHT publication used by the onboarding command. The
    /// signed record is checked against the finalized directory commitment
    /// before it enters the Net process.
    pub fn publish_signed_directory_once(
        paths: &AppPaths,
        expected_agent: AgentId,
        expected_sequence: u64,
        expected_commitment: [u8; 32],
        timeout: Duration,
    ) -> Result<(), AslError> {
        let bytes = std::fs::read(paths.signed_device_directory())?;
        crate::identity_onboarding::verify_signed_directory(
            &bytes,
            expected_agent,
            expected_sequence,
            expected_commitment,
        )?;

        let reopened = AppPaths::open_existing(paths.root())?;
        let mut supervisor = Self::start(reopened)?;
        if !supervisor.net.is_running()
            || supervisor.network_admission_status != NetworkAdmissionStatus::Active
        {
            return Err(AslError::InvalidIdentity);
        }
        let operation_id = fresh_id()?;
        supervisor.send_network_command(NetworkCommand::PrepareDirectory {
            operation_id,
            agent: expected_agent,
        })?;
        let deadline = Instant::now() + timeout;
        let mut publishing = false;
        loop {
            if Instant::now() >= deadline {
                let _ = supervisor.net.send(&IpcMessage::CancelDirectory {
                    operation_id,
                    receipt_id: fresh_id()?,
                });
                return Err(AslError::ExpiredMessage);
            }
            let Some(message) = supervisor.net.receive_runtime_message_optional(
                NETWORK_EVENT_POLL_INTERVAL.min(Duration::from_secs(1)),
            )?
            else {
                continue;
            };
            match message {
                IpcMessage::Pong { nonce } => {
                    supervisor.net.acknowledge_pong(nonce)?;
                }
                IpcMessage::OperationAccepted {
                    operation_id: accepted,
                } if accepted == operation_id && !publishing => {
                    supervisor.send_network_command(NetworkCommand::PublishDirectory {
                        operation_id,
                        value: bytes.clone(),
                    })?;
                    publishing = true;
                }
                IpcMessage::OperationAccepted {
                    operation_id: accepted,
                } if accepted == operation_id && publishing => {
                    return Ok(());
                }
                IpcMessage::OperationFailed {
                    operation_id: failed,
                    ..
                } if failed == operation_id => {
                    let _ = supervisor.net.send(&IpcMessage::CancelDirectory {
                        operation_id,
                        receipt_id: fresh_id()?,
                    });
                    return Err(AslError::InvalidIdentity);
                }
                message if is_network_event(&message) => {
                    let event = NetworkEvent::try_from(message)?;
                    let batch = supervisor.handle_admitted_event(event, unix_time_ms()?)?;
                    for command in batch.commands {
                        supervisor.send_network_command(command)?;
                    }
                }
                _ => {}
            }
        }
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

    /// Extracts text in a fresh, networkless PDF helper process.
    pub fn extract_pdf_text(&self, task_id: [u8; 16], pdf: &[u8]) -> Result<String, AslError> {
        let output = run_extractor_task(&self.launcher, task_id, ExtractorOperation::PdfText, pdf)?;
        String::from_utf8(output).map_err(|_| AslError::InvalidMessage)
    }

    /// Detects PDF/OOXML in the extractor and returns bounded plain text.
    pub fn extract_document_text(
        &self,
        task_id: [u8; 16],
        document: &[u8],
    ) -> Result<String, AslError> {
        let output = run_extractor_task(
            &self.launcher,
            task_id,
            ExtractorOperation::DocumentText,
            document,
        )?;
        String::from_utf8(output).map_err(|_| AslError::InvalidMessage)
    }

    /// Sanitizes an avatar in a fresh, networkless image helper process.
    pub fn sanitize_avatar(&self, task_id: [u8; 16], image: &[u8]) -> Result<Vec<u8>, AslError> {
        run_extractor_task(&self.launcher, task_id, ExtractorOperation::Avatar, image)
    }

    pub fn run(self) -> Result<(), AslError> {
        let (port, runtime) = outgoing_query_channel();
        #[cfg(windows)]
        let (grant, recovery) = {
            let grant = crate::mcp::HostGrant::from_environment()?;
            let recovery = crate::mcp::Recovery::configure(&self.state_database, grant.as_ref())?;
            (grant, recovery)
        };
        #[cfg(windows)]
        if let Some(grant) = grant {
            let (download_port, downloads) = download_channel();
            let _mcp = crate::mcp::McpWorker::spawn_with_mail_and_readiness(
                self.home.clone(),
                grant,
                port,
                download_port,
                self.mailbox.port.clone(),
                recovery,
                self.mcp_readiness.subscribe(),
            )?;
            return self.run_with_local_downloads(runtime, downloads);
        }
        drop(port);
        self.run_with_outgoing_queries(runtime)
    }

    pub fn run_with_outgoing_queries(self, runtime: OutgoingQueryRuntime) -> Result<(), AslError> {
        let (_, downloads) = download_channel();
        self.run_with_local_downloads(runtime, downloads)
    }

    pub fn run_with_local_downloads(
        self,
        queries: OutgoingQueryRuntime,
        downloads: DownloadRuntime,
    ) -> Result<(), AslError> {
        let mut bridge = DownloadBridge::spawn(self.home.clone(), downloads)?;
        self.run_with_transfer_handler(queries, move |supervisor, transfer, event| {
            match event {
                DownloadDriverEvent::Network(event) => bridge.forward(event),
                DownloadDriverEvent::Tick => {
                    bridge.poll(unix_time_ms()?, |request| {
                        supervisor.send_download_request(transfer, request)
                    });
                }
            }
            Ok(())
        })
    }

    /// Core-local download integration point. The driver chooses what to fetch
    /// and when to poll; each emitted command still passes identity admission.
    /// Keep the callbacks short, moving slow disk work off the event pump.
    pub fn run_with_download_driver(
        self,
        runtime: OutgoingQueryRuntime,
        mut driver: impl FnMut(
            DownloadDriverEvent<'_>,
            &mut DownloadEnqueue<'_>,
        ) -> Result<(), AslError>,
    ) -> Result<(), AslError> {
        self.run_with_transfer_handler(runtime, |supervisor, transfer, event| {
            driver(event, &mut |command| {
                supervisor.try_send_admitted_network_command_with_transfer(
                    transfer,
                    command,
                    unix_time_ms()?,
                )
            })
        })
    }

    fn run_with_transfer_handler(
        self,
        runtime: OutgoingQueryRuntime,
        driver: impl FnMut(
            &mut Self,
            &mut TransferService,
            DownloadDriverEvent<'_>,
        ) -> Result<(), AslError>,
    ) -> Result<(), AslError> {
        let mut inbound = DirectInbound::open(&self.state_database)?;
        let transfer = std::cell::RefCell::new(TransferService::open(&self.state_database)?);
        let avatars =
            std::cell::RefCell::new(avatar_download::Receiver::open(&self.state_database)?);
        let driver = std::cell::RefCell::new(driver);
        let outbound =
            std::cell::RefCell::new(DirectOutbound::open(&self.state_database, runtime)?);
        self.run_loop(
            |supervisor, event| {
                #[cfg(windows)]
                supervisor.observe_mailbox_operation(&event);
                match event {
                    #[cfg(windows)]
                    AdmittedNetworkEvent::MailboxRecordAvailable(record) => {
                        supervisor.deliver_mailbox_record(&record, unix_time_ms()?)
                    }
                    event @ AdmittedNetworkEvent::ControlRequest {
                        request: WireFrame::FetchRequest(_),
                        ..
                    } => supervisor.handle_fetch_request(&mut transfer.borrow_mut(), event),
                    #[cfg(windows)]
                    event @ AdmittedNetworkEvent::ControlRequest {
                        request: WireFrame::ContextRequest(_),
                        ..
                    } => supervisor.handle_context_request(&mut transfer.borrow_mut(), event),
                    event @ AdmittedNetworkEvent::BulkRequest { .. } => {
                        supervisor.handle_bulk_request(&mut transfer.borrow_mut(), event)
                    }
                    event @ AdmittedNetworkEvent::ControlRequest { .. } => {
                        supervisor.handle_direct_inbound(&mut inbound, event)
                    }
                    event => {
                        let mut transfer = transfer.borrow_mut();
                        let now_ms = unix_time_ms()?;
                        let Some(event) =
                            avatars
                                .borrow_mut()
                                .route(supervisor, &mut transfer, event, now_ms)?
                        else {
                            return Ok(());
                        };
                        let Some(event) =
                            supervisor.route_transfer_event(&mut transfer, event, now_ms)?
                        else {
                            return Ok(());
                        };
                        #[cfg(windows)]
                        if matches!(
                            &event,
                            AdmittedNetworkEvent::ControlResponse {
                                response: WireFrame::ContextOffer(_)
                                    | WireFrame::ContextAgreement(_),
                                ..
                            }
                        ) {
                            supervisor.observe_context_response(&event)?;
                        }
                        if supervisor.net.is_running() {
                            outbound.borrow_mut().handle_event(&event, now_ms)?;
                        }
                        driver.borrow_mut()(
                            supervisor,
                            &mut transfer,
                            DownloadDriverEvent::Network(&event),
                        )
                    }
                }
            },
            |supervisor, observation| {
                supervisor.observe_dht_provider_observation(&observation)?;
                supervisor.observe_contact_binding_network(observation.clone())?;
                supervisor.observe_contact_invite_network(observation.clone())?;
                match observation {
                    LocalNetworkObservation::DhtProviders { .. } => {
                        outbound
                            .borrow_mut()
                            .handle_local_observation(observation, unix_time_ms()?);
                        Ok(())
                    }
                    _ => Ok(()),
                }
            },
            |supervisor| {
                #[cfg(windows)]
                supervisor.poll_mail();
                supervisor.poll_direct_outbound(&mut outbound.borrow_mut())?;
                let mut transfer = transfer.borrow_mut();
                avatars
                    .borrow_mut()
                    .poll(supervisor, &mut transfer, unix_time_ms()?)?;
                #[cfg(windows)]
                supervisor.poll_group_transfers(&mut transfer, |supervisor, transfer, event| {
                    driver.borrow_mut()(supervisor, transfer, DownloadDriverEvent::Network(&event))
                })?;
                driver.borrow_mut()(supervisor, &mut transfer, DownloadDriverEvent::Tick)
            },
        )
    }

    fn send_download_request(
        &mut self,
        transfer: &mut TransferService,
        request: WorkerRequest,
    ) -> Result<Option<[u8; 16]>, AslError> {
        if !self.net.is_running() {
            return Ok(None);
        }
        let now = unix_time_ms()?;
        let (connection_id, command) = match request {
            WorkerRequest::Fetch {
                source,
                group: Some(group),
                request,
            } => {
                #[cfg(windows)]
                {
                    return self.send_group_fetch(transfer, &source, &group, &request);
                }
                #[cfg(not(windows))]
                {
                    let _ = (source, group, request);
                    return Ok(None);
                }
            }
            WorkerRequest::Fetch {
                source,
                group: None,
                request,
            } => {
                let (_, connection_id, _) = self
                    .admission
                    .as_ref()
                    .filter(|_| self.network_admission_status == NetworkAdmissionStatus::Active)
                    .ok_or(AslError::NotFound)?
                    .admitted_connections(now)
                    .into_iter()
                    .find(|(agent, _, peer)| *agent == source.agent_id && *peer == source.peer_id)
                    .ok_or(AslError::NotFound)?;
                (
                    connection_id,
                    NetworkCommand::SendControl {
                        connection_id,
                        request_id: request.message_id.0,
                        request: WireFrame::FetchRequest(request),
                    },
                )
            }
            WorkerRequest::Bulk {
                source,
                connection_id,
                request,
            } => {
                let (agent, peer) = self
                    .admission
                    .as_mut()
                    .filter(|_| self.network_admission_status == NetworkAdmissionStatus::Active)
                    .ok_or(AslError::InvalidIdentity)?
                    .admitted_peer_identity(connection_id, now)?;
                if (agent, peer) != (source.agent_id, source.peer_id) {
                    return Err(AslError::InvalidIdentity);
                }
                (
                    connection_id,
                    NetworkCommand::SendBulk {
                        connection_id,
                        request,
                    },
                )
            }
        };
        self.try_send_admitted_network_command_with_transfer(transfer, command, now)
            .map(|sent| sent.then_some(connection_id))
    }

    fn handle_fetch_request(
        &mut self,
        transfers: &mut TransferService,
        event: AdmittedNetworkEvent,
    ) -> Result<(), AslError> {
        let AdmittedNetworkEvent::ControlRequest {
            connection_id,
            agent_id,
            response_id,
            request: WireFrame::FetchRequest(request),
        } = event
        else {
            return Ok(());
        };
        let now_ms = unix_time_ms()?;
        let Some(admission) = self.admission.as_mut() else {
            return Ok(());
        };
        let Some(requester) = admission.direct_requester(connection_id, agent_id) else {
            return Ok(());
        };
        let Ok(prepared) =
            transfers.prepare_fetch(requester, &request, now_ms, |store, recipient| {
                admission.register_connected_transfer_peer(
                    store,
                    connection_id,
                    recipient.agent,
                    &recipient.peer,
                    now_ms,
                )
            })
        else {
            return Ok(());
        };
        let net = &self.net;
        match transfers.finish_fetch(prepared, unix_time_ms()?, |response, _| {
            let now_ms = unix_time_ms()?;
            let Ok(command) =
                admission.authorize_control_reply(connection_id, response_id, response, now_ms)
            else {
                return Ok(());
            };
            if net.try_send(&command.into_ipc()?)? {
                Ok(())
            } else {
                Err(AslError::SandboxUnavailable)
            }
        }) {
            Ok(()) | Err(AslError::NotFound | AslError::PolicyVersionConflict) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn handle_bulk_request(
        &mut self,
        transfers: &mut TransferService,
        event: AdmittedNetworkEvent,
    ) -> Result<(), AslError> {
        let AdmittedNetworkEvent::BulkRequest {
            connection_id,
            agent_id,
            response_id,
            request,
        } = event
        else {
            return Ok(());
        };
        let now_ms = unix_time_ms()?;
        let Some(requester) = self
            .admission
            .as_ref()
            .and_then(|admission| admission.direct_requester(connection_id, agent_id))
        else {
            return Ok(());
        };
        if let Some(group_requester) =
            transfers.group_requester_for_lease(request.lease_id, &requester, now_ms)
        {
            let prepared =
                transfers.prepare_group_bulk(&self.libraries, group_requester, request, now_ms);
            let Some(admission) = self.admission.as_mut() else {
                return Ok(());
            };
            let net = &self.net;
            return match transfers.finish_group_bulk(prepared, unix_time_ms()?, |response| {
                let now_ms = unix_time_ms()?;
                let Ok(command) =
                    admission.authorize_bulk_reply(connection_id, response_id, response, now_ms)
                else {
                    return Ok(());
                };
                if net.try_send(&command.into_ipc()?)? {
                    Ok(())
                } else {
                    Err(AslError::SandboxUnavailable)
                }
            }) {
                Ok(()) | Err(AslError::NotFound | AslError::PolicyVersionConflict) => Ok(()),
                Err(error) => Err(error),
            };
        }
        let prepared = transfers.prepare_bulk(&self.libraries, requester, request, now_ms);
        let Some(admission) = self.admission.as_mut() else {
            return Ok(());
        };
        let net = &self.net;
        match transfers.finish_bulk(prepared, unix_time_ms()?, |response| {
            let now_ms = unix_time_ms()?;
            let Ok(command) =
                admission.authorize_bulk_reply(connection_id, response_id, response, now_ms)
            else {
                return Ok(());
            };
            if net.try_send(&command.into_ipc()?)? {
                Ok(())
            } else {
                Err(AslError::SandboxUnavailable)
            }
        }) {
            Ok(()) | Err(AslError::NotFound | AslError::PolicyVersionConflict) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn handle_direct_inbound(
        &mut self,
        inbound: &mut DirectInbound,
        event: AdmittedNetworkEvent,
    ) -> Result<(), AslError> {
        #[cfg(windows)]
        self.observe_direct_mail(&event)?;
        let AdmittedNetworkEvent::ControlRequest {
            connection_id,
            agent_id,
            response_id,
            request: request @ WireFrame::Query(_),
        } = event
        else {
            return Ok(());
        };
        let now_ms = unix_time_ms()?;
        let Some(requester) = self
            .admission
            .as_ref()
            .and_then(|admission| admission.direct_requester(connection_id, agent_id))
        else {
            return Ok(());
        };
        let Ok(Some(reply)) = inbound.prepare(requester, request, now_ms) else {
            return Ok(());
        };
        inbound.enqueue(reply, |response, expires_at_ms| {
            let now_ms = unix_time_ms()?;
            let Some(admission) = self.admission.as_mut() else {
                return Ok(());
            };
            // This rechecks chain admission before the original Net response handle is used.
            let Ok(NetworkCommand::ReplyControl { response, .. }) =
                admission.authorize_control_reply(connection_id, response_id, response, now_ms)
            else {
                return Ok(());
            };
            // This is the nonblocking authorization handoff. A full queue
            // drops the reply instead of stalling revocation or the event pump.
            self.net
                .try_send(&IpcMessage::ReplyDirect {
                    connection_id,
                    response_id,
                    expires_at_ms,
                    response,
                })
                .map(|_| ())
        })
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
        self,
        mut handler: impl FnMut(AdmittedNetworkEvent) -> Vec<NetworkCommand>,
        mut observer: impl FnMut(LocalNetworkObservation),
    ) -> Result<(), AslError> {
        let mut transfers = TransferService::open(&self.state_database)?;
        self.run_loop(
            |supervisor, event| {
                let Some(event) =
                    supervisor.route_transfer_event(&mut transfers, event, unix_time_ms()?)?
                else {
                    return Ok(());
                };
                let commands = handler(event);
                if !supervisor.net.is_running() {
                    return Ok(());
                }
                for command in commands {
                    let sent = supervisor.try_send_admitted_network_command_with_transfer(
                        &mut transfers,
                        command,
                        unix_time_ms()?,
                    )?;
                    if !sent {
                        return Err(AslError::SandboxUnavailable);
                    }
                }
                Ok(())
            },
            |supervisor, observation| {
                supervisor.observe_contact_binding_network(observation.clone())?;
                supervisor.observe_contact_invite_network(observation.clone())?;
                observer(observation);
                Ok(())
            },
            |_| Ok(()),
        )
    }

    fn try_send_admitted_network_command_with_transfer(
        &mut self,
        transfers: &mut TransferService,
        command: NetworkCommand,
        now_ms: u64,
    ) -> Result<bool, AslError> {
        if !self.net.is_running() {
            return Ok(false);
        }
        match command {
            NetworkCommand::SendControl {
                request: WireFrame::FetchRequest(_),
                ..
            }
            | NetworkCommand::SendBulk { .. } => {
                self.send_tracked_with(transfers, command, now_ms, NetRuntime::try_send)
            }
            command => self
                .send_admitted_network_command(command, now_ms)
                .map(|()| true),
        }
    }

    fn send_tracked_with(
        &mut self,
        transfers: &mut TransferService,
        command: NetworkCommand,
        now_ms: u64,
        enqueue: impl FnOnce(&NetRuntime, &IpcMessage) -> Result<bool, AslError>,
    ) -> Result<bool, AslError> {
        if !self.net.is_running() {
            return Ok(false);
        }
        match command {
            NetworkCommand::SendControl {
                connection_id,
                request_id,
                request: WireFrame::FetchRequest(fetch),
            } => {
                let admission = self.admission.as_mut().ok_or(AslError::InvalidIdentity)?;
                let (agent_id, _) = admission.admitted_peer_identity(connection_id, now_ms)?;
                let requester = admission
                    .direct_requester(connection_id, agent_id)
                    .ok_or(AslError::InvalidIdentity)?;
                let frame = WireFrame::FetchRequest(fetch.clone());
                let command = admission.authorize_control_command(
                    connection_id,
                    request_id,
                    frame,
                    now_ms,
                )?;
                match transfers.expect_fetch_response(
                    connection_id,
                    &requester,
                    request_id,
                    &fetch,
                    now_ms,
                ) {
                    Ok(()) => {}
                    Err(AslError::QuotaExceeded) => return Ok(false),
                    Err(error) => return Err(error),
                }
                let sent = command
                    .into_ipc()
                    .and_then(|message| enqueue(&self.net, &message));
                if !matches!(sent, Ok(true)) {
                    transfers.fail_control_request(
                        connection_id,
                        requester.agent,
                        &requester.peer,
                        request_id,
                    );
                }
                sent
            }
            NetworkCommand::SendBulk {
                connection_id,
                request,
            } => {
                let request_id = request.request_id.0;
                let admission = self.admission.as_mut().ok_or(AslError::InvalidIdentity)?;
                let authorized = match transfers.authorize_bulk_request(
                    admission,
                    connection_id,
                    request,
                    now_ms,
                ) {
                    Ok(command) => command,
                    Err(AslError::QuotaExceeded) => return Ok(false),
                    Err(error) => return Err(error),
                };
                let sent = authorized
                    .into_ipc()
                    .and_then(|message| enqueue(&self.net, &message));
                if !matches!(sent, Ok(true)) {
                    transfers.cancel_bulk_request(request_id);
                }
                sent
            }
            _ => Err(AslError::InvalidMessage),
        }
    }

    fn route_transfer_event(
        &mut self,
        transfers: &mut TransferService,
        event: AdmittedNetworkEvent,
        now_ms: u64,
    ) -> Result<Option<AdmittedNetworkEvent>, AslError> {
        Self::route_transfer_with(
            self.admission.as_mut(),
            transfers,
            event,
            now_ms,
            |command| self.net.try_send(&command.into_ipc()?),
        )
    }

    pub(crate) fn route_transfer_with(
        admission: Option<&mut CoreAdmission>,
        transfers: &mut TransferService,
        event: AdmittedNetworkEvent,
        now_ms: u64,
        enqueue: impl FnOnce(NetworkCommand) -> Result<bool, AslError>,
    ) -> Result<Option<AdmittedNetworkEvent>, AslError> {
        if let AdmittedNetworkEvent::ControlResponse { request_id, .. } = &event
            && transfers.pending_fetch_group(*request_id).is_some()
        {
            return Ok(None);
        }
        Self::route_matched_transfer(admission, transfers, event, now_ms, enqueue)
    }

    fn route_matched_transfer(
        admission: Option<&mut CoreAdmission>,
        transfers: &mut TransferService,
        event: AdmittedNetworkEvent,
        now_ms: u64,
        enqueue: impl FnOnce(NetworkCommand) -> Result<bool, AslError>,
    ) -> Result<Option<AdmittedNetworkEvent>, AslError> {
        transfers.expire_pending(now_ms);
        match event {
            AdmittedNetworkEvent::ControlResponse {
                connection_id,
                agent_id,
                request_id,
                response: WireFrame::FetchGrant(grant),
            } => {
                let Some(admission) = admission else {
                    return Ok(None);
                };
                let Some(requester) = admission.direct_requester(connection_id, agent_id) else {
                    return Ok(None);
                };
                let (bulk_id, command) = match transfers.prepare_manifest_request(
                    admission,
                    connection_id,
                    &requester,
                    request_id,
                    &grant,
                    now_ms,
                ) {
                    Ok(Some(request)) => request,
                    Err(AslError::QuotaExceeded) => {
                        return Ok(Some(fetch_failure(
                            connection_id,
                            requester.peer,
                            agent_id,
                            request_id,
                            NetworkErrorCode::Capacity,
                        )));
                    }
                    _ => return Ok(None),
                };
                if !enqueue(command)? {
                    transfers.cancel_bulk_request(bulk_id.0);
                    return Ok(Some(fetch_failure(
                        connection_id,
                        requester.peer,
                        agent_id,
                        request_id,
                        NetworkErrorCode::Capacity,
                    )));
                }
                Ok(None)
            }
            event @ AdmittedNetworkEvent::ControlResponse {
                connection_id,
                agent_id,
                request_id,
                ..
            } => {
                if let Some(requester) = admission
                    .and_then(|admission| admission.direct_requester(connection_id, agent_id))
                {
                    transfers.fail_control_request(
                        connection_id,
                        agent_id,
                        &requester.peer,
                        request_id,
                    );
                }
                Ok(Some(event))
            }
            AdmittedNetworkEvent::BulkResponse {
                connection_id,
                agent_id,
                peer_id,
                request_id,
                response,
            } => {
                match transfers.accept_bulk_response(
                    connection_id,
                    agent_id,
                    &peer_id,
                    request_id,
                    response,
                    now_ms,
                ) {
                    Some(ReceivedBulk::Manifest(manifest)) => {
                        let Some(admission) = admission else {
                            return Ok(None);
                        };
                        match transfers.register_manifest_source(admission, &manifest, now_ms) {
                            Ok(()) => {
                                Ok(Some(AdmittedNetworkEvent::FetchManifestReceived(manifest)))
                            }
                            Err(
                                AslError::InvalidIdentity
                                | AslError::InvalidDeviceCertificate
                                | AslError::ExpiredMessage
                                | AslError::InvalidMessage,
                            ) => Ok(None),
                            Err(AslError::Io(error))
                                if error.kind() == std::io::ErrorKind::WouldBlock =>
                            {
                                Ok(Some(fetch_failure(
                                    connection_id,
                                    peer_id,
                                    agent_id,
                                    manifest.fetch_request_id.0,
                                    NetworkErrorCode::Capacity,
                                )))
                            }
                            Err(error) => Err(error),
                        }
                    }
                    Some(ReceivedBulk::Raw(matched)) => {
                        Ok(Some(AdmittedNetworkEvent::BulkTransferResponse(matched)))
                    }
                    Some(ReceivedBulk::CorruptManifest(manifest)) => {
                        Ok(Some(AdmittedNetworkEvent::FetchManifestCorrupt(manifest)))
                    }
                    None => Ok(None),
                }
            }
            AdmittedNetworkEvent::RequestFailed {
                connection_id,
                agent_id,
                peer_id,
                request_id,
                protocol: NetworkProtocol::Bulk,
                code,
            } => {
                if let Some(fetch_id) = transfers.fail_bulk_request(
                    connection_id,
                    agent_id,
                    &peer_id,
                    request_id,
                    now_ms,
                ) {
                    return Ok(Some(fetch_failure(
                        connection_id,
                        peer_id,
                        agent_id,
                        fetch_id.0,
                        code,
                    )));
                }
                Ok(Some(AdmittedNetworkEvent::RequestFailed {
                    connection_id,
                    agent_id,
                    peer_id,
                    request_id,
                    protocol: NetworkProtocol::Bulk,
                    code,
                }))
            }
            AdmittedNetworkEvent::RequestFailed {
                connection_id,
                agent_id,
                peer_id,
                request_id,
                protocol: NetworkProtocol::Control,
                code,
            } => {
                transfers.fail_control_request(connection_id, agent_id, &peer_id, request_id);
                Ok(Some(AdmittedNetworkEvent::RequestFailed {
                    connection_id,
                    agent_id,
                    peer_id,
                    request_id,
                    protocol: NetworkProtocol::Control,
                    code,
                }))
            }
            AdmittedNetworkEvent::PeerDisconnected {
                connection_id,
                peer_id,
                agent_id,
            } => {
                transfers.connection_disconnected(connection_id, peer_id.as_ref());
                Ok(Some(AdmittedNetworkEvent::PeerDisconnected {
                    connection_id,
                    peer_id,
                    agent_id,
                }))
            }
            event => Ok(Some(event)),
        }
    }

    fn run_loop(
        mut self,
        mut handler: impl FnMut(&mut Self, AdmittedNetworkEvent) -> Result<(), AslError>,
        mut observer: impl FnMut(&mut Self, LocalNetworkObservation) -> Result<(), AslError>,
        mut tick: impl FnMut(&mut Self) -> Result<(), AslError>,
    ) -> Result<(), AslError> {
        let mut activity_store = open_direct_store(&self.state_database)?;
        let mut next_activity_prune = Instant::now();
        let mut next_health_check = Instant::now();
        let mut next_ping = Instant::now();
        let mut next_agent_tick = Instant::now();
        loop {
            if Instant::now() >= next_agent_tick
                && self.sync_network_pause(NetRuntime::start, &mut handler)?
            {
                next_ping = Instant::now();
            }
            self.renew_local_directory_if_due(unix_time_ms()?);
            self.check_network_admission_deadline(unix_time_ms()?)?;
            self.process_chain_refresh()?;
            let now = Instant::now();
            if let Some(update) = self
                .directory_reader
                .as_mut()
                .and_then(|reader| reader.poll(now))
            {
                self.apply_network_directory(update, unix_time_ms()?)?;
            }
            self.check_network_admission_deadline(unix_time_ms()?)?;
            if self
                .net
                .pending_pong
                .is_some_and(|(_, deadline)| now >= deadline)
            {
                return Err(AslError::SandboxUnavailable);
            }
            if self.net.is_running() && now >= next_ping && self.net.pending_pong.is_none() {
                if self.net.try_start_ping(now)? {
                    next_ping = now + HEALTH_CHECK_INTERVAL;
                } else if now >= next_ping + NET_PING_TIMEOUT {
                    return Err(AslError::SandboxUnavailable);
                }
            }
            if now < next_ping || self.net.pending_pong.is_some() {
                self.flush_disconnects()?;
            }
            if self.net.is_running()
                && self.network_admission_status == NetworkAdmissionStatus::Active
            {
                let now_ms = unix_time_ms()?;
                let batch = self
                    .admission
                    .as_mut()
                    .map(|admission| admission.poll(now_ms))
                    .unwrap_or_default();
                self.dispatch_admission_batch(batch, &mut handler)?;
            }
            let now = Instant::now();
            if now >= next_agent_tick {
                #[cfg(windows)]
                self.poll_local_groups()?;
                #[cfg(windows)]
                self.poll_auto_act_replies()?;
                #[cfg(windows)]
                self.poll_mailbox_wire()?;
                self.poll_contact_bindings()?;
                self.poll_contact_invites()?;
                self.poll_resource_providers()?;
                self.poll_profile_signing(now, unix_time_ms()?);
                self.poll_onboarding_directory_publication(now);
                self.pump_dht_restore()?;
                tick(&mut self)?;
                next_agent_tick = now + NETWORK_EVENT_POLL_INTERVAL;
            }
            if now >= next_health_check {
                self.libraries.check_health()?;
                next_health_check = now + HEALTH_CHECK_INTERVAL;
            }
            if now >= next_activity_prune {
                next_activity_prune = now + ACTIVITY_PRUNE_INTERVAL;
                let now_ms =
                    i64::try_from(unix_time_ms()?).map_err(|_| AslError::InvalidMessage)?;
                if activity_store.prune_expired_activity(now_ms).is_err() {
                    eprintln!("ASL activity retention failed");
                }
            }
            if !self.net.is_running() {
                thread::sleep(NETWORK_EVENT_POLL_INTERVAL);
                continue;
            }
            let Some(message) = self
                .net
                .receive_runtime_message_optional(NETWORK_EVENT_POLL_INTERVAL)?
            else {
                continue;
            };
            if let IpcMessage::OperationAccepted { operation_id } = &message {
                match self.advance_onboarding_publication(*operation_id, Instant::now()) {
                    Ok(true) => continue,
                    Ok(false) => {}
                    Err(_) => {
                        let _ = self.note_onboarding_publication_failure(*operation_id);
                        continue;
                    }
                }
            }
            if let IpcMessage::OperationFailed { operation_id, .. } = &message {
                match self.note_onboarding_publication_failure(*operation_id) {
                    Ok(true) => continue,
                    Ok(false) => {}
                    Err(_) => continue,
                }
            }
            let event = match message {
                IpcMessage::Pong { nonce } => {
                    self.net.acknowledge_pong(nonce)?;
                    continue;
                }
                IpcMessage::OperationAccepted { operation_id }
                    if self
                        .profile_signing
                        .handle_response(operation_id, true, Instant::now()) =>
                {
                    continue;
                }
                IpcMessage::OperationFailed { operation_id, .. }
                    if self.profile_signing.handle_response(
                        operation_id,
                        false,
                        Instant::now(),
                    ) =>
                {
                    continue;
                }
                message if is_network_event(&message) => NetworkEvent::try_from(message)?,
                _ => return Err(AslError::InvalidMessage),
            };
            if let Some(observation) = event.as_local_observation() {
                observer(&mut self, observation)?;
                continue;
            }
            let now_ms = unix_time_ms()?;
            let batch = self.handle_admitted_event(event, now_ms)?;
            self.dispatch_admission_batch(batch, &mut handler)?;
        }
    }

    pub(crate) fn handle_admitted_event(
        &mut self,
        event: NetworkEvent,
        now_ms: u64,
    ) -> Result<AdmissionBatch, AslError> {
        self.network_report.observe(&event);
        self.check_network_admission_deadline(now_ms)?;
        if let NetworkEvent::PeerDisconnected { connection_id } = &event {
            self.transport_connections.remove(connection_id);
            self.pending_disconnects.remove(*connection_id);
        } else if event_connection_id(&event)
            .is_some_and(|id| self.pending_disconnects.contains(id))
        {
            return Ok(AdmissionBatch::default());
        }
        if let NetworkEvent::TransportConnected {
            connection_id,
            peer_id,
        } = &event
        {
            if self.transport_connections.len() >= MAX_ADMISSION_CONNECTIONS {
                return Err(AslError::SandboxUnavailable);
            }
            self.transport_connections
                .insert(*connection_id, peer_id.clone());
        }
        if self.admission.is_none()
            || self.network_admission_status != NetworkAdmissionStatus::Active
        {
            return Ok(reject_unadmitted_event(event));
        }
        #[cfg(windows)]
        if matches!(
            event,
            NetworkEvent::UnverifiedGroupRequest { .. }
                | NetworkEvent::UnverifiedGroupResponse { .. }
                | NetworkEvent::GossipReceived { .. }
        ) {
            self.route_group_event(event, now_ms);
            return Ok(AdmissionBatch::default());
        }
        Ok(self
            .admission
            .as_mut()
            .ok_or(AslError::InvalidIdentity)?
            .handle_event(event, now_ms))
    }

    fn poll_direct_outbound(&mut self, outbound: &mut DirectOutbound) -> Result<(), AslError> {
        let now_ms = unix_time_ms()?;
        if !self.net.is_running() {
            outbound.poll_paused(now_ms);
            return Ok(());
        }
        if self.network_admission_status != NetworkAdmissionStatus::Active {
            outbound.poll_offline(now_ms);
            return Ok(());
        }
        let admission = self.admission.as_mut().ok_or(AslError::InvalidIdentity)?;
        let connections = admission.admitted_connections(now_ms);
        let connecting_peers = admission.connecting_peers();
        let net = &self.net;
        outbound.poll(
            &connections,
            &connecting_peers,
            now_ms,
            |connection_id, request_id, request| {
                let command = admission.authorize_control_command(
                    connection_id,
                    request_id,
                    request,
                    now_ms,
                )?;
                if net.try_send(&command.into_ipc()?)? {
                    Ok(())
                } else {
                    Err(AslError::SandboxUnavailable)
                }
            },
            |lookup_id, key| {
                let command = NetworkCommand::FindProviders { lookup_id, key }.into_ipc()?;
                if net.try_send(&command)? {
                    Ok(())
                } else {
                    Err(AslError::SandboxUnavailable)
                }
            },
            |operation_id, peer_id, endpoint, relay_route_available| {
                let command = match endpoint {
                    Some((kind, address)) => NetworkCommand::Dial {
                        operation_id,
                        kind,
                        address,
                        peer_id,
                    },
                    None if relay_route_available => NetworkCommand::DialViaRelays {
                        operation_id,
                        peer_id,
                    },
                    None => return Err(AslError::PolicyDenied),
                };
                if net.try_send(&command.into_ipc()?)? {
                    Ok(())
                } else {
                    Err(AslError::SandboxUnavailable)
                }
            },
        )
    }

    fn dispatch_admission_batch(
        &mut self,
        batch: AdmissionBatch,
        handler: &mut impl FnMut(&mut Self, AdmittedNetworkEvent) -> Result<(), AslError>,
    ) -> Result<(), AslError> {
        self.pending_pairing_prompts.expire(unix_time_ms()?);
        for command in batch.commands {
            self.send_network_command(command)?;
        }
        for event in batch.events {
            if let Some((key, true)) = self
                .resource_providers
                .observe_resource_provider_event(&event)
                && let Ok(store) = open_store(&self.state_database)
            {
                let now = unix_time_ms()?;
                let _ = store.cache_dht_provider(
                    key,
                    self.device_peer_id.clone(),
                    &[],
                    now.saturating_add(60 * 60 * 1_000),
                    now,
                );
            }
            if let AdmittedNetworkEvent::DhtRecordAvailable {
                agent_id,
                kind,
                sequence,
                registry_sequence,
                record,
            } = &event
                && let Ok(store) = open_store(&self.state_database)
                && let Ok(signed) = asl_types::record::decode_record(record)
            {
                let now = unix_time_ms()?;
                let _ = store.cache_dht_record(
                    &asl_store::dht_cache::CachedDhtRecord {
                        agent_id: *agent_id,
                        kind: *kind,
                        sequence: *sequence,
                        registry_sequence: *registry_sequence,
                        record: record.clone(),
                        expires_at_ms: signed.record.expires_at_ms,
                    },
                    now,
                );
            }
            self.observe_contact_binding_event(&event)?;
            self.observe_contact_invite_operation(&event);
            self.profile_signing
                .observe_remote_record(self.agent_identity.agent_id(), &event);
            match self.handle_contact_invite_event(&event, unix_time_ms()?) {
                Ok(Some(command)) => self.send_network_command(command)?,
                Ok(None) => {}
                Err(error)
                    if matches!(
                        event,
                        AdmittedNetworkEvent::PairingInviteReceived { .. }
                            | AdmittedNetworkEvent::PairingExchangeReceived { .. }
                            | AdmittedNetworkEvent::PeerAdmitted { .. }
                    ) =>
                {
                    if let Some(connection_id) = admitted_event_connection(&event) {
                        self.send_network_command(NetworkCommand::CloseConnection {
                            connection_id,
                        })?;
                    }
                    if !matches!(
                        error,
                        AslError::InvalidIdentity
                            | AslError::InvalidMessage
                            | AslError::ExpiredMessage
                            | AslError::PolicyDenied
                    ) {
                        return Err(error);
                    }
                }
                Err(error) => return Err(error),
            }
            match &event {
                AdmittedNetworkEvent::PairingInviteReceived { .. } => continue,
                AdmittedNetworkEvent::PairingExchangeReceived { .. } => continue,
                AdmittedNetworkEvent::PairingAccepted { .. }
                | AdmittedNetworkEvent::PairingDeclined { .. } => continue,
                AdmittedNetworkEvent::PeerDisconnected { connection_id, .. } => {
                    self.pending_pairing_prompts
                        .remove_connection(*connection_id);
                }
                _ => {}
            }
            if let Some(event) = self.verify_pairing_response(event, unix_time_ms()?)? {
                handler(self, event)?;
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
                    admission.refresh_local_chain(candidate.light_client, &candidate.proof, now_ms)
                });
                match result {
                    Some(Ok(true)) => {
                        if let Some(reader) = &mut self.directory_reader {
                            reader.request_refresh();
                        }
                        if self.directory_removed {
                            self.suspend_network_admission(
                                NetworkAdmissionStatus::DeviceDirectoryMissing,
                            )?;
                        } else if self
                            .admission
                            .as_mut()
                            .is_some_and(|a| a.check_local_directory(now_ms).is_ok())
                        {
                            self.set_network_admission_status(NetworkAdmissionStatus::Active);
                        } else {
                            self.suspend_network_admission(
                                NetworkAdmissionStatus::DeviceDirectoryUnavailable,
                            )?;
                        }
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

    fn apply_network_directory(
        &mut self,
        update: directory::DirectoryRead,
        now_ms: u64,
    ) -> Result<(), AslError> {
        self.check_network_admission_deadline(now_ms)?;
        if matches!(update, Ok(None)) {
            self.directory_removed = true;
        }
        if !matches!(
            self.network_admission_status,
            NetworkAdmissionStatus::Active
                | NetworkAdmissionStatus::DeviceDirectoryUnavailable
                | NetworkAdmissionStatus::DeviceDirectoryMissing
        ) {
            return Ok(());
        }
        match update {
            Ok(Some(bytes)) => {
                let Ok(mut store) = open_store(&self.state_database) else {
                    return Ok(());
                };
                let admission = self.admission.as_mut().ok_or(AslError::InvalidIdentity)?;
                let changed = admission.update_local_device_directory_source(
                    bytes,
                    &self.agent_identity,
                    &mut store,
                    now_ms,
                );
                if matches!(changed, Ok(true))
                    || (matches!(changed, Ok(false))
                        && self.network_admission_status != NetworkAdmissionStatus::Active
                        && admission.check_local_directory(now_ms).is_ok())
                {
                    self.directory_removed = false;
                    self.set_network_admission_status(NetworkAdmissionStatus::Active);
                }
            }
            Ok(None) => {
                self.suspend_network_admission(NetworkAdmissionStatus::DeviceDirectoryMissing)?;
            }
            Err(_) => {}
        }
        Ok(())
    }

    fn renew_local_directory_if_due(&mut self, now_ms: u64) {
        if Instant::now() < self.directory_renewal_retry_at
            || self.directory_removed
            || !matches!(
                self.network_admission_status,
                NetworkAdmissionStatus::Active
                    | NetworkAdmissionStatus::DeviceDirectoryUnavailable
                    | NetworkAdmissionStatus::DeviceDirectoryMissing
            )
            || !self
                .admission
                .as_ref()
                .is_some_and(|admission| admission.local_directory_renewal_due(now_ms))
        {
            return;
        }
        self.directory_renewal_retry_at = Instant::now() + DIRECTORY_RENEWAL_RETRY_INTERVAL;
        let Ok(mut store) = open_store(&self.state_database) else {
            return;
        };
        let Some(admission) = &mut self.admission else {
            return;
        };
        if matches!(
            admission
                .renew_local_device_directory_if_due(&self.agent_identity, &mut store, now_ms,),
            Ok(true)
        ) {
            self.directory_removed = false;
            self.set_network_admission_status(NetworkAdmissionStatus::Active);
        }
    }

    fn check_network_admission_deadline(&mut self, now_ms: u64) -> Result<(), AslError> {
        if matches!(
            self.network_admission_status,
            NetworkAdmissionStatus::Active
                | NetworkAdmissionStatus::DeviceDirectoryUnavailable
                | NetworkAdmissionStatus::DeviceDirectoryMissing
        ) && self
            .admission
            .as_ref()
            .is_some_and(|admission| !admission.local_chain_is_current(now_ms))
        {
            self.suspend_network_admission(NetworkAdmissionStatus::ChainUnavailable)?;
        } else if self.network_admission_status == NetworkAdmissionStatus::Active
            && self
                .admission
                .as_ref()
                .is_some_and(|admission| !admission.local_directory_is_current(now_ms))
        {
            self.suspend_network_admission(NetworkAdmissionStatus::DeviceDirectoryUnavailable)?;
        }
        Ok(())
    }

    fn suspend_network_admission(
        &mut self,
        status: NetworkAdmissionStatus,
    ) -> Result<(), AslError> {
        self.set_network_admission_status(status);
        if let Some(admission) = self.admission.as_mut() {
            if matches!(
                status,
                NetworkAdmissionStatus::ChainUnavailable
                    | NetworkAdmissionStatus::RegistryAnchorMissing
            ) {
                admission.clear_local_chain();
            }
            for command in admission.close_all().commands {
                if let NetworkCommand::CloseConnection { connection_id } = command {
                    self.pending_disconnects.insert(connection_id)?;
                }
            }
        }
        Ok(())
    }

    pub(crate) fn queue_disconnect(&mut self, connection_id: [u8; 16]) -> Result<(), AslError> {
        if let Some(admission) = &mut self.admission {
            admission.invalidate_connection(connection_id);
        }
        self.pending_pairing_prompts
            .remove_connection(connection_id);
        self.pending_disconnects.insert(connection_id)
    }

    pub(crate) fn flush_disconnects(&mut self) -> Result<(), AslError> {
        self.pending_disconnects.flush(&self.net)
    }
}

#[derive(Default)]
struct PendingDisconnects(VecDeque<[u8; 16]>);

impl PendingDisconnects {
    fn contains(&self, id: [u8; 16]) -> bool {
        self.0.contains(&id)
    }

    fn insert(&mut self, id: [u8; 16]) -> Result<(), AslError> {
        if !self.contains(id) {
            // An old connection can still have its disconnection in the event queue.
            if self.0.len() >= MAX_ADMISSION_CONNECTIONS + MAX_PENDING_NETWORK_EVENTS {
                return Err(AslError::SandboxUnavailable);
            }
            self.0.push_back(id);
        }
        Ok(())
    }

    fn remove(&mut self, id: [u8; 16]) {
        self.0.retain(|pending| *pending != id);
    }

    fn flush(&mut self, net: &NetRuntime) -> Result<(), AslError> {
        while let Some(connection_id) = self.0.front().copied() {
            if !net.try_send_close(connection_id)? {
                break;
            }
            self.0.pop_front();
        }
        Ok(())
    }
}

fn fetch_failure(
    connection_id: [u8; 16],
    peer_id: PeerId,
    agent_id: AgentId,
    request_id: [u8; 16],
    code: NetworkErrorCode,
) -> AdmittedNetworkEvent {
    AdmittedNetworkEvent::RequestFailed {
        connection_id,
        peer_id,
        agent_id,
        request_id,
        protocol: NetworkProtocol::Control,
        code,
    }
}

#[derive(Default)]
struct NetRuntime {
    child: Option<SandboxChild>,
    writer: Option<NetWriter>,
    writer_thread: Option<JoinHandle<()>>,
    events: Option<Receiver<Result<IpcFrame, AslError>>>,
    reader_thread: Option<JoinHandle<()>>,
    next_nonce: u64,
    pending_pong: Option<(u64, Instant)>,
    pending_network_events: VecDeque<IpcMessage>,
}

struct NetWriter {
    sender: SyncSender<Vec<u8>>,
    queued: Arc<AtomicUsize>,
}

impl NetWriter {
    fn channel() -> (Self, Receiver<Vec<u8>>) {
        let (sender, receiver) = mpsc::sync_channel(MAX_PENDING_NET_WRITES);
        let queued = Arc::new(AtomicUsize::new(0));
        (Self { sender, queued }, receiver)
    }

    fn try_send(&self, bytes: Vec<u8>) -> Result<bool, AslError> {
        self.queued.fetch_add(1, Ordering::Relaxed);
        match self.sender.try_send(bytes) {
            Ok(()) => Ok(true),
            Err(error) => {
                self.queued.fetch_sub(1, Ordering::Relaxed);
                match error {
                    TrySendError::Full(_) => Ok(false),
                    TrySendError::Disconnected(_) => Err(AslError::SandboxUnavailable),
                }
            }
        }
    }
}

impl NetRuntime {
    fn start(
        launcher: &SandboxLauncher,
        device_identity: &DeviceIdentity,
        loopback_groups: bool,
        traversal: asl_net::transport::TraversalConfig,
    ) -> Result<Self, AslError> {
        let (mut pipes, inherited) = InheritedPipes::new()?;
        let child = launcher.spawn_sandbox(
            SandboxRole::Net,
            inherited,
            SandboxLimits::for_role(SandboxRole::Net),
        )?;
        write_net_startup_prelude(
            &mut pipes.input,
            device_identity,
            loopback_groups,
            traversal,
        )?;
        Self::from_child(pipes, child, &device_identity.peer_id())
    }

    fn from_child(
        pipes: BrokerPipes,
        child: SandboxChild,
        expected_peer_id: &PeerId,
    ) -> Result<Self, AslError> {
        drop(pipes.error);
        Self::from_pipes(pipes.input, pipes.output, Some(child), expected_peer_id)
    }

    fn from_pipes(
        input: impl std::io::Write + Send + 'static,
        output: impl Read + Send + 'static,
        child: Option<SandboxChild>,
        expected_peer_id: &PeerId,
    ) -> Result<Self, AslError> {
        let (sender, receiver) = mpsc::sync_channel(8);
        let reader_thread = thread::Builder::new()
            .name("asl-net-ipc".into())
            .spawn(move || {
                forward_net_events(
                    FrameReader::new(output, IpcRole::Net, IpcRole::Core),
                    sender,
                )
            })
            .map_err(|_| AslError::SandboxUnavailable)?;
        let (writer, outgoing) = NetWriter::channel();
        let queued = Arc::clone(&writer.queued);
        let writer_thread = thread::Builder::new()
            .name("asl-net-ipc-writer".into())
            .spawn(move || {
                let mut pipe = FrameWriter::new(input, IpcRole::Core, IpcRole::Net);
                while let Ok(frame) = outgoing.recv() {
                    queued.fetch_sub(1, Ordering::Relaxed);
                    if pipe.send_prepared(frame).is_err() {
                        break;
                    }
                }
            })
            .map_err(|_| AslError::SandboxUnavailable)?;
        let mut runtime = Self {
            child,
            writer: Some(writer),
            writer_thread: Some(writer_thread),
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
        self.try_send(message)?
            .then_some(())
            .ok_or(AslError::SandboxUnavailable)
    }

    fn try_send(&self, message: &IpcMessage) -> Result<bool, AslError> {
        let writer = self.writer.as_ref().ok_or(AslError::SandboxUnavailable)?;
        writer.try_send(encode_frame(IpcRole::Core, IpcRole::Net, 1, message)?)
    }

    fn try_send_close(&self, connection_id: [u8; 16]) -> Result<bool, AslError> {
        let writer = self.writer.as_ref().ok_or(AslError::SandboxUnavailable)?;
        // A Hello can enqueue a reply and a proof request in one turn.
        if writer.queued.load(Ordering::Relaxed)
            >= MAX_PENDING_NET_WRITES - NET_ADMISSION_WRITE_HEADROOM
        {
            return Ok(false);
        }
        self.try_send(&IpcMessage::CloseConnection { connection_id })
    }

    fn try_start_ping(&mut self, now: Instant) -> Result<bool, AslError> {
        if self.pending_pong.is_some() {
            return Err(AslError::InvalidPolicyState);
        }
        let nonce = self.next_nonce;
        let next_nonce = nonce.checked_add(1).ok_or(AslError::InvalidMessage)?;
        if !self.try_send(&IpcMessage::Ping { nonce })? {
            return Ok(false);
        }
        self.next_nonce = next_nonce;
        self.pending_pong = Some((nonce, now + NET_PING_TIMEOUT));
        Ok(true)
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
        if let Some(writer_thread) = self.writer_thread.take() {
            let _ = writer_thread.join();
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
            | IpcMessage::ReachabilityChanged { .. }
            | IpcMessage::RouteChanged { .. }
            | IpcMessage::DiscoveryCandidate { .. }
            | IpcMessage::DhtRecordCandidate { .. }
            | IpcMessage::DhtProviders { .. }
            | IpcMessage::DhtProviderObserved { .. }
            | IpcMessage::PeerAuthenticated { .. }
            | IpcMessage::PeerDisconnected { .. }
            | IpcMessage::IdentityProofRequested { .. }
            | IpcMessage::IdentityProofReceived { .. }
            | IpcMessage::PairingInviteRequested { .. }
            | IpcMessage::PairingExchangeReceived { .. }
            | IpcMessage::ControlRequested { .. }
            | IpcMessage::ControlReceived { .. }
            | IpcMessage::BulkRequested { .. }
            | IpcMessage::BulkReceived { .. }
            | IpcMessage::GroupRequested { .. }
            | IpcMessage::GroupReceived { .. }
            | IpcMessage::RequestFailed { .. }
            | IpcMessage::NetworkError { .. }
    )
}

pub(crate) fn reject_unadmitted_event(event: NetworkEvent) -> AdmissionBatch {
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
        NetworkEvent::DhtProviders { .. } => {}
        NetworkEvent::DhtProviderObserved { .. } => {}
        NetworkEvent::DhtRecordCandidate { candidate_id, .. } => {
            batch.commands.push(NetworkCommand::DecideDhtRecord {
                candidate_id,
                accept: false,
            })
        }
        NetworkEvent::PeerDisconnected { connection_id } => {
            batch.events.push(AdmittedNetworkEvent::PeerDisconnected {
                connection_id,
                peer_id: None,
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
        | NetworkEvent::UnverifiedPairingInvite { connection_id, .. }
        | NetworkEvent::UnverifiedPairingExchangeResponse { connection_id, .. }
        | NetworkEvent::UnverifiedControlRequest { connection_id, .. }
        | NetworkEvent::UnverifiedControlResponse { connection_id, .. }
        | NetworkEvent::UnverifiedBulkRequest { connection_id, .. }
        | NetworkEvent::UnverifiedBulkResponse { connection_id, .. }
        | NetworkEvent::UnverifiedGroupRequest { connection_id, .. }
        | NetworkEvent::UnverifiedGroupResponse { connection_id, .. }
        | NetworkEvent::RequestFailed { connection_id, .. } => Some(*connection_id),
        NetworkEvent::OperationAccepted { .. }
        | NetworkEvent::OperationFailed { .. }
        | NetworkEvent::Listening { .. }
        | NetworkEvent::RelayReserved { .. }
        | NetworkEvent::RelayUnavailable { .. }
        | NetworkEvent::ReachabilityChanged { .. }
        | NetworkEvent::RouteChanged { .. }
        | NetworkEvent::DiscoveryCandidate { .. }
        | NetworkEvent::DhtRecordCandidate { .. }
        | NetworkEvent::DhtProviders { .. }
        | NetworkEvent::DhtProviderObserved { .. }
        | NetworkEvent::GossipReceived { .. }
        | NetworkEvent::PeerDisconnected { .. }
        | NetworkEvent::NetworkError { .. } => None,
    }
}

fn admitted_event_connection(event: &AdmittedNetworkEvent) -> Option<[u8; 16]> {
    match event {
        AdmittedNetworkEvent::PeerAdmitted { connection_id, .. }
        | AdmittedNetworkEvent::PairingInviteReceived { connection_id, .. }
        | AdmittedNetworkEvent::PairingExchangeReceived { connection_id, .. }
        | AdmittedNetworkEvent::PeerDisconnected { connection_id, .. } => Some(*connection_id),
        _ => None,
    }
}

pub(crate) fn unix_time_ms() -> Result<u64, AslError> {
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

pub(crate) fn sanitize_local_avatar(input: &[u8]) -> Result<Vec<u8>, AslError> {
    let executable = env::current_exe()?;
    let launcher = SandboxLauncher::new(
        executable.with_file_name("asl-net.exe"),
        executable.with_file_name("asl-worker.exe"),
        executable.with_file_name("asl-extractor.exe"),
    )?;
    sanitize_avatar_with(&launcher, input)
}

pub(crate) fn sanitize_avatar_with(
    launcher: &SandboxLauncher,
    input: &[u8],
) -> Result<Vec<u8>, AslError> {
    run_extractor_task(launcher, rand::random(), ExtractorOperation::Avatar, input)
}

pub(crate) fn extract_document_text_once(document: &[u8]) -> Result<String, AslError> {
    let directory = sibling_binary_directory()?;
    let launcher = SandboxLauncher::new(
        directory.join("asl-net.exe"),
        directory.join("asl-worker.exe"),
        directory.join("asl-extractor.exe"),
    )?;
    let output = run_extractor_task(
        &launcher,
        rand::random(),
        ExtractorOperation::DocumentText,
        document,
    )?;
    String::from_utf8(output).map_err(|_| AslError::InvalidMessage)
}

pub(crate) fn run_extractor_task(
    launcher: &SandboxLauncher,
    task_id: [u8; 16],
    operation: ExtractorOperation,
    payload: &[u8],
) -> Result<Vec<u8>, AslError> {
    if payload.len() > MAX_IPC_EXTRACTOR_INPUT_BYTES {
        return Err(AslError::InvalidMessage);
    }
    let (pipes, inherited) = InheritedPipes::new()?;
    let mut child = launcher.spawn_sandbox(
        SandboxRole::Extractor,
        inherited,
        SandboxLimits::for_role(SandboxRole::Extractor),
    )?;
    drop(pipes.error);

    let mut reader = FrameReader::new(pipes.output, IpcRole::Extractor, IpcRole::Core);
    let mut writer = FrameWriter::new(pipes.input, IpcRole::Core, IpcRole::Extractor);
    if reader.receive()?.message != IpcMessage::Ready {
        return Err(AslError::InvalidMessage);
    }
    writer.send(&IpcMessage::RunExtractorTask {
        task_id,
        operation,
        payload: payload.to_vec(),
    })?;
    let (status, output) = match reader.receive()?.message {
        IpcMessage::ExtractorResult {
            task_id: received,
            status,
            payload,
        } if received == task_id
            && (status == ExtractorStatus::Completed || payload.is_empty()) =>
        {
            (status, payload)
        }
        _ => return Err(AslError::InvalidMessage),
    };
    let maximum_output_bytes = match operation {
        ExtractorOperation::PdfText | ExtractorOperation::DocumentText => {
            MAX_DOCUMENT_TEXT_BYTES
        }
        ExtractorOperation::Avatar => MAX_AVATAR_BYTES,
    };
    let invalid_output = output.len() > maximum_output_bytes
        || (operation == ExtractorOperation::Avatar && output.is_empty());
    writer.send(&IpcMessage::Shutdown)?;
    if reader.receive()?.message != IpcMessage::Stopped {
        return Err(AslError::InvalidMessage);
    }
    if child.wait_timeout(SHUTDOWN_TIMEOUT)? != Some(0) {
        return Err(AslError::SandboxUnavailable);
    }
    if status == ExtractorStatus::Rejected || invalid_output {
        return Err(AslError::InvalidMessage);
    }
    Ok(output)
}

fn sibling_binary_directory() -> Result<PathBuf, AslError> {
    let executable = env::current_exe()?;
    let mut directory = executable
        .parent()
        .ok_or(AslError::SandboxUnavailable)?
        .to_path_buf();
    loop {
        if directory.join("asl-net.exe").is_file()
            && directory.join("asl-worker.exe").is_file()
            && directory.join("asl-extractor.exe").is_file()
        {
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

pub fn set_direct_inbound_from_environment(mode: &str) -> Result<(), AslError> {
    let root = configured_root(env::var_os("ASL_HOME"))?;
    let paths = AppPaths::open(&root)?;
    direct_inbound::configure(&paths.state().join("asl.sqlite3"), mode)
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
    fn dht_record_candidates_are_rejected_when_core_identity_is_unavailable() {
        let batch = reject_unadmitted_event(NetworkEvent::DhtRecordCandidate {
            candidate_id: [27; 16],
            key: [28; 32],
            value: vec![0x01],
        });

        assert!(batch.events.is_empty());
        assert_eq!(
            batch.commands,
            vec![NetworkCommand::DecideDhtRecord {
                candidate_id: [27; 16],
                accept: false,
            }]
        );
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
            writer_thread: None,
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
            writer_thread: None,
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
            writer_thread: None,
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
    fn disconnects_wait_for_writer_capacity_and_heartbeat_keeps_its_nonce() {
        let (writer, receiver) = NetWriter::channel();
        let queued = Arc::clone(&writer.queued);
        let read = || {
            let bytes = receiver.try_recv().unwrap();
            queued.fetch_sub(1, Ordering::Relaxed);
            bytes
        };
        let mut runtime = NetRuntime {
            child: None,
            writer: Some(writer),
            writer_thread: None,
            events: None,
            reader_thread: None,
            next_nonce: 1,
            pending_pong: None,
            pending_network_events: VecDeque::new(),
        };
        for _ in 0..MAX_PENDING_NET_WRITES {
            assert!(runtime.try_send(&IpcMessage::Ping { nonce: 9 }).unwrap());
        }
        let mut pending = PendingDisconnects::default();
        for value in 1..=MAX_ADMISSION_CONNECTIONS as u8 {
            pending.insert([value; 16]).unwrap();
            pending.insert([value; 16]).unwrap();
        }
        assert_eq!(pending.0.len(), MAX_ADMISSION_CONNECTIONS);
        assert!(!runtime.try_start_ping(Instant::now()).unwrap());
        pending.flush(&runtime).unwrap();
        assert_eq!(pending.0.len(), MAX_ADMISSION_CONNECTIONS);
        assert!(runtime.pending_pong.is_none());
        for _ in 0..MAX_PENDING_NET_WRITES {
            read();
        }
        let now = Instant::now();
        assert!(runtime.try_start_ping(now).unwrap());
        assert_eq!(runtime.pending_pong, Some((1, now + NET_PING_TIMEOUT)));
        assert_eq!(
            read(),
            encode_frame(
                IpcRole::Core,
                IpcRole::Net,
                1,
                &IpcMessage::Ping { nonce: 1 }
            )
            .unwrap()
        );
        pending.remove([1; 16]);
        for chunk in (2..=MAX_ADMISSION_CONNECTIONS as u8)
            .collect::<Vec<_>>()
            .chunks(MAX_PENDING_NET_WRITES - NET_ADMISSION_WRITE_HEADROOM)
        {
            pending.flush(&runtime).unwrap();
            for nonce in 10..(10 + NET_ADMISSION_WRITE_HEADROOM as u64) {
                assert!(runtime.try_send(&IpcMessage::Ping { nonce }).unwrap());
            }
            for &value in chunk {
                let command = IpcMessage::CloseConnection {
                    connection_id: [value; 16],
                };
                assert_eq!(
                    read(),
                    encode_frame(IpcRole::Core, IpcRole::Net, 1, &command).unwrap()
                );
            }
            for nonce in 10..(10 + NET_ADMISSION_WRITE_HEADROOM as u64) {
                assert_eq!(
                    read(),
                    encode_frame(IpcRole::Core, IpcRole::Net, 1, &IpcMessage::Ping { nonce })
                        .unwrap()
                );
            }
        }
        assert!(pending.0.is_empty());
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
        use image::ImageEncoder;
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
        let extractor = bin.join("asl-extractor.exe");
        fs::copy(source.join("asl-net.exe"), &net).unwrap();
        fs::copy(source.join("asl-worker.exe"), &worker).unwrap();
        fs::copy(source.join("asl-extractor.exe"), &extractor).unwrap();

        let mut supervisor = Supervisor::start_with_launcher(
            AppPaths::open(&home).unwrap(),
            SandboxLauncher::new(net.clone(), worker, extractor).unwrap(),
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
        let mut avatar = Vec::new();
        image::codecs::png::PngEncoder::new(&mut avatar)
            .write_image(
                &vec![120; 256 * 192 * 4],
                256,
                192,
                image::ExtendedColorType::Rgba8,
            )
            .unwrap();
        let sanitized = supervisor.sanitize_avatar([14; 16], &avatar).unwrap();
        assert!(sanitized.starts_with(b"\x89PNG\r\n\x1a\n"));
        assert!(sanitized.len() <= crate::documents::MAX_AVATAR_BYTES);
        let dimensions = image::load_from_memory(&sanitized).unwrap();
        assert!(dimensions.width() <= crate::documents::MAX_AVATAR_EDGE);
        assert!(dimensions.height() <= crate::documents::MAX_AVATAR_EDGE);
        assert!(
            supervisor
                .extract_pdf_text([15; 16], &crate::documents::minimal_pdf())
                .unwrap()
                .contains("ASL PDF text")
        );
        assert!(
            supervisor
                .extract_pdf_text([16; 16], b"%PDF-invalid")
                .is_err()
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

        let paths = AppPaths::open(&home).unwrap();
        assert!(
            NetworkSettingsV1::load(&paths.network_settings_configuration())
                .is_ok_and(|settings| !settings.loopback_groups)
        );
        fs::write(
            paths.network_settings_configuration(),
            serde_json::to_vec(&NetworkSettingsV1 {
                loopback_groups: true,
                ..NetworkSettingsV1::default()
            })
            .unwrap(),
        )
        .unwrap();
        let broken_worker = Supervisor::start_with_launcher(
            paths,
            SandboxLauncher::new(net.clone(), net.clone(), net).unwrap(),
        )
        .expect("opt-in Net must start independently of the worker executable");
        assert!(broken_worker.groups.is_some());
        assert!(
            broken_worker
                .validate_control_frame([10; 16], &[0xff])
                .is_err()
        );
        let mut broken_worker = broken_worker;
        assert!(
            broken_worker
                .send_startup_network_operation(|operation_id| NetworkCommand::SetAddressPolicy {
                    operation_id,
                    policy: asl_net::address_policy::AddressPolicy::LanOnly,
                })
                .is_err(),
            "Net must enforce loopback after receiving the private startup opt-in"
        );
        broken_worker.ping_net().unwrap();
        drop(broken_worker);
        drop(fixture);
    }
}
