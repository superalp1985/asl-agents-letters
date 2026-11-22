use std::collections::HashSet;

use asl_store::{Store, network_privacy::NetworkRuntimeState};
use asl_types::error::AslError;
use asl_types::ids::PeerId;

use crate::{
    network::NetworkEvent,
    network_settings::{NetworkAddressScopeV1, NetworkSettingsV1},
};

pub(super) struct NetworkStatus {
    store: Store,
    runtime: NetworkRuntimeState,
    relay_only: bool,
    configured_relays: usize,
    reserved_relays: HashSet<PeerId>,
}

impl NetworkStatus {
    pub(super) fn new(store: Store, settings: &NetworkSettingsV1) -> Self {
        Self {
            store,
            runtime: NetworkRuntimeState::Unknown,
            relay_only: settings.address_scope == NetworkAddressScopeV1::RelayOnly,
            configured_relays: settings.relay_addresses.len(),
            reserved_relays: HashSet::new(),
        }
    }

    pub(super) fn pause_requested(&self) -> Result<bool, AslError> {
        self.store.network_pause_requested()
    }

    pub(super) fn runtime(&self) -> NetworkRuntimeState {
        self.runtime
    }

    pub(super) fn set_runtime(&mut self, runtime: NetworkRuntimeState) {
        self.runtime = runtime;
        self.reserved_relays.clear();
        self.report();
    }

    pub(super) fn observe(&mut self, event: &NetworkEvent) {
        let changed = match event {
            NetworkEvent::RelayReserved { relay_peer_id, .. } => {
                self.reserved_relays.insert(relay_peer_id.clone())
            }
            NetworkEvent::RelayUnavailable { relay_peer_id } => {
                self.reserved_relays.remove(relay_peer_id)
            }
            _ => false,
        };
        if changed {
            self.report();
        }
    }

    pub(super) fn report(&self) {
        let _ = self.store.report_network_state(
            self.runtime,
            self.relay_only,
            self.configured_relays,
            self.reserved_relays.len(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{paths::AppPaths, transfer::tests::Fixture};
    use asl_store::{dashboard::Dashboard, open_store};

    #[test]
    fn relay_reports_track_confirmed_reservations_separately_from_saved_mode() {
        let fixture = Fixture::new();
        let paths = AppPaths::open(&fixture.path().join("receiver")).unwrap();
        let db = paths.state().join("asl.sqlite3");
        let store = open_store(&db).unwrap();
        let relay = libp2p_identity::PeerId::random();
        let settings = NetworkSettingsV1 {
            relay_addresses: vec![format!("/ip4/127.0.0.1/tcp/41000/p2p/{relay}")],
            ..NetworkSettingsV1::default()
        }
        .with_relay_only_override(true)
        .unwrap();
        let mut status = NetworkStatus::new(store, &settings);
        let view = || Dashboard::load(&db).unwrap().network_report.unwrap();
        status.report();
        assert!(view().relay_only);
        assert_eq!(view().configured_relays, 1);
        assert_eq!(view().reserved_relays, 0);

        let relay_peer_id = PeerId::from_bytes(relay.to_bytes()).unwrap();
        let reserved = NetworkEvent::RelayReserved {
            relay_peer_id: relay_peer_id.clone(),
            address: vec![],
        };
        status.observe(&reserved);
        status.observe(&reserved);
        assert_eq!(view().reserved_relays, 1);
        open_store(&db)
            .unwrap()
            .set_force_relay_only(false)
            .unwrap();
        assert!(view().relay_only);

        status.observe(&NetworkEvent::RelayUnavailable { relay_peer_id });
        assert_eq!(view().reserved_relays, 0);
    }
}
