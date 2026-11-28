use asl_net::transport::TransportKind;
use asl_store::network_privacy::NetworkRuntimeState;
use asl_types::error::AslError;

use super::{
    AdmittedNetworkEvent, DeviceIdentity, NetRuntime, NetworkCommand, NetworkEvent,
    NetworkSettingsV1, PendingDisconnects, STARTUP_TIMEOUT, SandboxLauncher, Supervisor, pairing,
    unix_time_ms,
};

impl Supervisor {
    pub(super) fn sync_network_pause(
        &mut self,
        start_net: impl FnOnce(
            &SandboxLauncher,
            &DeviceIdentity,
            bool,
            asl_net::transport::TraversalConfig,
        ) -> Result<NetRuntime, AslError>,
        handler: &mut impl FnMut(&mut Self, AdmittedNetworkEvent) -> Result<(), AslError>,
    ) -> Result<bool, AslError> {
        let paused = self.network_report.pause_requested()?;
        match (paused, self.network_report.runtime()) {
            (true, NetworkRuntimeState::Running) => {
                self.net.stop_for_pause()?;
                self.resource_providers.reset_resource_providers();
                self.profile_signing.reset_transport();
                let now = unix_time_ms()?;
                for (connection_id, peer_id) in std::mem::take(&mut self.transport_connections) {
                    let mut batch = self.handle_admitted_event(
                        NetworkEvent::PeerDisconnected { connection_id },
                        now,
                    )?;
                    for event in &mut batch.events {
                        if let AdmittedNetworkEvent::PeerDisconnected { peer_id: peer, .. } = event
                        {
                            *peer = Some(peer_id.clone());
                        }
                    }
                    self.dispatch_admission_batch(batch, handler)?;
                }
                if let Some(admission) = &mut self.admission {
                    admission.close_all();
                }
                self.pending_disconnects = PendingDisconnects::default();
                self.pending_pairing_prompts = pairing::PendingPairingPrompts::default();
                self.clear_group_transport();
                self.network_report.set_runtime(NetworkRuntimeState::Paused);
                self.reset_binding_transport()?;
                self.reset_contact_invite_transport()?;
                self.reset_contact_policy_sync_transport();
            }
            (true, NetworkRuntimeState::ResumeFailed) => {
                self.network_report.set_runtime(NetworkRuntimeState::Paused);
            }
            (false, NetworkRuntimeState::Paused) => match self.restart_net(start_net) {
                Ok(net) => {
                    self.net = net;
                    self.reload_dht_restore()?;
                    self.pump_dht_restore()?;
                    self.resource_providers.reset_resource_providers();
                    self.network_report
                        .set_runtime(NetworkRuntimeState::Running);
                    return Ok(true);
                }
                Err(error) => {
                    eprintln!("ASL peer network resume failed: {error}");
                    self.network_report
                        .set_runtime(NetworkRuntimeState::ResumeFailed);
                }
            },
            _ => {}
        }
        Ok(false)
    }

    fn restart_net(
        &self,
        start_net: impl FnOnce(
            &SandboxLauncher,
            &DeviceIdentity,
            bool,
            asl_net::transport::TraversalConfig,
        ) -> Result<NetRuntime, AslError>,
    ) -> Result<NetRuntime, AslError> {
        let device = DeviceIdentity::load_protected(&self.device_key_path)?;
        if device.peer_id() != self.device_peer_id {
            return Err(AslError::InvalidIdentity);
        }
        let mut net = start_net(
            &self.launcher,
            &device,
            self.network_settings.loopback_groups,
            self.network_settings.traversal.transport_config()?,
        )?;
        net.apply_settings(&self.network_settings)?;
        Ok(net)
    }
}

impl NetRuntime {
    pub(super) fn is_running(&self) -> bool {
        self.writer.is_some()
    }

    fn stop_for_pause(&mut self) -> Result<(), AslError> {
        if let Some(child) = &mut self.child {
            child.terminate()?;
            self.child.take();
        }
        self.stop();
        *self = Self::default();
        Ok(())
    }

    pub(super) fn apply_settings(&mut self, settings: &NetworkSettingsV1) -> Result<(), AslError> {
        settings.validate()?;
        self.send_startup_operation(|operation_id| NetworkCommand::SetAddressPolicy {
            operation_id,
            policy: settings.address_policy(),
        })?;

        for address in &settings.bootstrap_multiaddrs {
            let (peer_id, kind, socket) =
                asl_net::transport::parse_bootstrap_multiaddr(address, settings.address_policy())
                    .map_err(|_| AslError::InvalidIdentity)?;
            self.send_startup_operation(|operation_id| NetworkCommand::Dial {
                operation_id,
                kind,
                address: socket,
                peer_id,
            })?;
        }

        for address in &settings.relay_addresses {
            let address = asl_net::relay::relay_endpoint_config(address)?;
            self.send_startup_operation(|operation_id| NetworkCommand::ReserveRelay {
                operation_id,
                address,
            })?;
        }

        if settings.listen_on_interfaces {
            for (kind, port) in [
                (TransportKind::Tcp, settings.tcp_port),
                (TransportKind::Quic, settings.quic_port),
            ] {
                self.send_startup_operation(|operation_id| NetworkCommand::Listen {
                    operation_id,
                    kind,
                    address: settings.listener_address(port),
                })?;
            }
        }
        Ok(())
    }

    pub(super) fn send_startup_operation(
        &mut self,
        command: impl FnOnce([u8; 16]) -> NetworkCommand,
    ) -> Result<(), AslError> {
        let operation_id = crate::profile::fresh_id()?;
        self.send(&command(operation_id).into_ipc()?)?;
        self.wait_for_operation(operation_id, STARTUP_TIMEOUT)
    }
}

#[cfg(all(test, windows))]
mod tests {
    use std::{
        env, fs, io,
        net::{SocketAddr, TcpStream},
        thread,
        time::Duration,
    };

    use asl_store::{dashboard::Dashboard, open_store};

    use super::*;
    use crate::{
        ipc::{run_net_pipe_fixture, write_net_startup_prelude},
        paths::AppPaths,
        transfer::tests::Fixture,
    };

    fn socket_fixture(
        _: &SandboxLauncher,
        device: &DeviceIdentity,
        groups: bool,
        traversal: asl_net::transport::TraversalConfig,
    ) -> Result<NetRuntime, AslError> {
        let (net_input, mut core_output) = io::pipe()?;
        let (core_input, net_output) = io::pipe()?;
        write_net_startup_prelude(&mut core_output, device, groups, traversal)?;
        thread::spawn(move || {
            let _ = run_net_pipe_fixture(net_input, net_output);
        });
        NetRuntime::from_pipes(core_output, core_input, None, &device.peer_id())
    }

    fn listen_address(supervisor: &mut Supervisor) -> SocketAddr {
        loop {
            let event = supervisor
                .net
                .receive_network_event(STARTUP_TIMEOUT)
                .unwrap();
            if let NetworkEvent::Listening {
                kind: TransportKind::Tcp,
                address,
            } = NetworkEvent::try_from(event).unwrap()
            {
                return address;
            }
        }
    }

    #[test]
    fn p2p_pause_closes_tcp_listener_and_resumes_with_original_scope_and_identity() {
        let fixture = Fixture::new();
        let paths = AppPaths::open(fixture.path()).unwrap();
        let config = paths.network_settings_configuration();
        let settings = NetworkSettingsV1 {
            listen_on_interfaces: true,
            ..NetworkSettingsV1::default()
        };
        fs::write(&config, serde_json::to_vec(&settings).unwrap()).unwrap();
        let db = paths.state().join("asl.sqlite3");
        let store = open_store(&db).unwrap();
        let exe = env::current_exe().unwrap();
        let launcher = SandboxLauncher::new(exe.clone(), exe.clone(), exe).unwrap();

        store.set_network_pause_requested(true).unwrap();
        let mut supervisor = Supervisor::start_with_net(paths, launcher, |_, _, _, _| {
            panic!("saved pause started Net")
        })
        .unwrap();
        let second_paths = AppPaths::open_existing(fixture.path()).unwrap();
        let exe = env::current_exe().unwrap();
        let second_launcher = SandboxLauncher::new(exe.clone(), exe.clone(), exe).unwrap();
        assert!(matches!(
            Supervisor::start_with_net(second_paths, second_launcher, |_, _, _, _| {
                panic!("duplicate Core reached Net startup")
            }),
            Err(AslError::InvalidPolicyState)
        ));
        let local_peer = supervisor.device_peer_id.clone();
        let report = || Dashboard::load(&db).unwrap().network_report.unwrap();
        let mut handler = |_: &mut Supervisor, _| Ok(());
        assert!(report().runtime == NetworkRuntimeState::Paused);
        assert!(supervisor.ping_net().is_err());

        store.set_network_pause_requested(false).unwrap();
        assert!(
            !supervisor
                .sync_network_pause(|_, _, _, _| Err(AslError::SandboxUnavailable), &mut handler)
                .unwrap()
        );
        assert!(report().runtime == NetworkRuntimeState::ResumeFailed);
        assert!(
            !supervisor
                .sync_network_pause(
                    |_, _, _, _| panic!("resume must not retry itself"),
                    &mut handler
                )
                .unwrap()
        );
        store.set_network_pause_requested(true).unwrap();
        supervisor
            .sync_network_pause(socket_fixture, &mut handler)
            .unwrap();

        store.set_network_pause_requested(false).unwrap();
        assert!(
            supervisor
                .sync_network_pause(socket_fixture, &mut handler)
                .unwrap()
        );
        let first = listen_address(&mut supervisor);
        assert!(first.ip().is_loopback());
        assert!(TcpStream::connect_timeout(&first, Duration::from_secs(1)).is_ok());

        // A separately staged configuration must not widen the active Core's scope.
        let staged = NetworkSettingsV1 {
            address_scope: crate::network_settings::NetworkAddressScopeV1::Hybrid,
            ..settings
        };
        fs::write(&config, serde_json::to_vec(&staged).unwrap()).unwrap();
        store.set_network_pause_requested(true).unwrap();
        supervisor
            .sync_network_pause(socket_fixture, &mut handler)
            .unwrap();
        assert!(report().runtime == NetworkRuntimeState::Paused);
        assert_eq!(report().reserved_relays, 0);
        assert!(TcpStream::connect_timeout(&first, Duration::from_millis(500)).is_err());

        store.set_network_pause_requested(false).unwrap();
        assert!(
            supervisor
                .sync_network_pause(socket_fixture, &mut handler)
                .unwrap()
        );
        assert!(report().runtime == NetworkRuntimeState::Running);
        assert!(listen_address(&mut supervisor).ip().is_loopback());
        assert_eq!(supervisor.device_peer_id, local_peer);
        supervisor.ping_net().unwrap();
    }
}
