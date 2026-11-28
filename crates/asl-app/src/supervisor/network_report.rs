use std::collections::{HashMap, HashSet};

use asl_net::transport::{ReachabilityState, RouteFailure, RouteState};
use asl_store::{
    Store,
    network_privacy::{
        NetworkReachability, NetworkReport, NetworkRouteFailure, NetworkRuntimeState,
    },
};
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
    listeners: HashSet<String>,
    routes: HashMap<PeerId, RouteState>,
    reachability: NetworkReachability,
    reachability_confidence: u8,
    public_entry: bool,
    last_route_failure: Option<NetworkRouteFailure>,
}

impl NetworkStatus {
    #[cfg(windows)]
    pub(super) fn store(&self) -> &Store {
        &self.store
    }

    pub(super) fn new(store: Store, settings: &NetworkSettingsV1) -> Self {
        Self {
            store,
            runtime: NetworkRuntimeState::Unknown,
            relay_only: settings.address_scope == NetworkAddressScopeV1::RelayOnly,
            configured_relays: settings.relay_addresses.len(),
            reserved_relays: HashSet::new(),
            listeners: HashSet::new(),
            routes: HashMap::new(),
            reachability: NetworkReachability::Unreported,
            reachability_confidence: 0,
            public_entry: false,
            last_route_failure: None,
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
        self.listeners.clear();
        self.routes.clear();
        self.reachability = NetworkReachability::Unreported;
        self.reachability_confidence = 0;
        self.public_entry = false;
        self.last_route_failure = None;
        self.report();
    }

    pub(super) fn observe(&mut self, event: &NetworkEvent) {
        let changed = match event {
            NetworkEvent::Listening { kind, address } => {
                self.listeners.insert(format!("{kind:?}:{address}"))
            }
            NetworkEvent::RelayReserved { relay_peer_id, .. } => {
                self.reserved_relays.insert(relay_peer_id.clone())
            }
            NetworkEvent::RelayUnavailable { relay_peer_id } => {
                self.reserved_relays.remove(relay_peer_id)
            }
            NetworkEvent::ReachabilityChanged { status } => {
                let reachability = match status.state {
                    ReachabilityState::Unknown => NetworkReachability::Unknown,
                    ReachabilityState::Private => NetworkReachability::Private,
                    ReachabilityState::Public => NetworkReachability::Public,
                };
                let public_entry = reachability == NetworkReachability::Public
                    && status
                        .public_address
                        .as_ref()
                        .is_some_and(|value| !value.is_empty());
                let changed = self.reachability != reachability
                    || self.reachability_confidence != status.confidence
                    || self.public_entry != public_entry;
                self.reachability = reachability;
                self.reachability_confidence = status.confidence.min(100);
                self.public_entry = public_entry;
                changed
            }
            NetworkEvent::RouteChanged { status } => {
                if !self.routes.contains_key(&status.peer_id)
                    && self.routes.len() >= 256
                    && let Some(peer) = self.routes.keys().next().cloned()
                {
                    self.routes.remove(&peer);
                }
                let failure = status.failure.map(route_failure);
                let changed = self.routes.insert(status.peer_id.clone(), status.state)
                    != Some(status.state)
                    || self.last_route_failure != failure;
                self.last_route_failure = failure;
                changed
            }
            _ => false,
        };
        if changed {
            self.report();
        }
    }

    pub(super) fn report(&self) {
        let mut direct_routes = 0;
        let mut hole_punched_routes = 0;
        let mut relayed_routes = 0;
        let mut negotiating_routes = 0;
        let mut failed_routes = 0;
        for state in self.routes.values() {
            match state {
                RouteState::DirectDialing | RouteState::RelayDialing | RouteState::HolePunching => {
                    negotiating_routes += 1;
                }
                RouteState::Direct => direct_routes += 1,
                RouteState::HolePunched => hole_punched_routes += 1,
                RouteState::Relayed => relayed_routes += 1,
                RouteState::Failed => failed_routes += 1,
            }
        }
        let _ = self.store.report_network_snapshot(NetworkReport {
            runtime: self.runtime,
            relay_only: self.relay_only,
            configured_relays: self.configured_relays,
            reserved_relays: self.reserved_relays.len(),
            observed_at_ms: 0,
            reachability: self.reachability,
            reachability_confidence: self.reachability_confidence,
            public_entry: self.public_entry,
            listening_endpoints: self.listeners.len(),
            direct_routes,
            hole_punched_routes,
            relayed_routes,
            negotiating_routes,
            failed_routes,
            last_route_failure: self.last_route_failure,
        });
    }
}

fn route_failure(value: RouteFailure) -> NetworkRouteFailure {
    match value {
        RouteFailure::DirectUnavailable => NetworkRouteFailure::DirectUnavailable,
        RouteFailure::RelayUnavailable => NetworkRouteFailure::RelayUnavailable,
        RouteFailure::HolePunchFailed => NetworkRouteFailure::HolePunchFailed,
        RouteFailure::TimedOut => NetworkRouteFailure::TimedOut,
        RouteFailure::PeerIdentityMismatch => NetworkRouteFailure::PeerIdentityMismatch,
        RouteFailure::Disconnected => NetworkRouteFailure::Disconnected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{paths::AppPaths, transfer::tests::Fixture};
    use asl_net::transport::{
        ReachabilityState, ReachabilityStatus, RouteState, RouteStatus, TransportKind,
    };
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

    #[test]
    fn network_events_persist_entry_and_route_snapshot_fields() {
        let fixture = Fixture::new();
        let paths = AppPaths::open(&fixture.path().join("snapshot")).unwrap();
        let db = paths.state().join("asl.sqlite3");
        let store = open_store(&db).unwrap();
        let relay = libp2p_identity::PeerId::random();
        let settings = NetworkSettingsV1 {
            relay_addresses: vec![format!("/ip4/127.0.0.1/tcp/41000/p2p/{relay}")],
            ..NetworkSettingsV1::default()
        };
        let mut status = NetworkStatus::new(store, &settings);
        status.set_runtime(NetworkRuntimeState::Running);
        let view = || Dashboard::load(&db).unwrap().network_report.unwrap();
        let peer = || PeerId::from_bytes(libp2p_identity::PeerId::random().to_bytes()).unwrap();
        let relay_peer_id =
            PeerId::from_bytes(libp2p_identity::PeerId::random().to_bytes()).unwrap();

        status.observe(&NetworkEvent::Listening {
            kind: TransportKind::Tcp,
            address: "127.0.0.1:4001".parse().unwrap(),
        });
        status.observe(&NetworkEvent::RelayReserved {
            relay_peer_id: relay_peer_id.clone(),
            address: vec![1, 2, 3],
        });
        status.observe(&NetworkEvent::ReachabilityChanged {
            status: ReachabilityStatus {
                state: ReachabilityState::Public,
                confidence: 87,
                public_address: Some(vec![4, 127, 0, 0, 1]),
            },
        });
        for (state, failure) in [
            (RouteState::Direct, None),
            (RouteState::HolePunched, None),
            (RouteState::Relayed, None),
            (RouteState::HolePunching, None),
            (RouteState::Failed, Some(RouteFailure::DirectUnavailable)),
        ] {
            status.observe(&NetworkEvent::RouteChanged {
                status: RouteStatus {
                    peer_id: peer(),
                    state,
                    relay_peer_id: None,
                    direct_attempts: 1,
                    relay_attempts: 1,
                    failure,
                },
            });
        }

        let report = view();
        assert_eq!(report.runtime, NetworkRuntimeState::Running);
        assert_eq!(report.listening_endpoints, 1);
        assert_eq!(report.configured_relays, 1);
        assert_eq!(report.reserved_relays, 1);
        assert_eq!(report.reachability, NetworkReachability::Public);
        assert_eq!(report.reachability_confidence, 87);
        assert!(report.public_entry);
        assert_eq!(report.direct_routes, 1);
        assert_eq!(report.hole_punched_routes, 1);
        assert_eq!(report.relayed_routes, 1);
        assert_eq!(report.negotiating_routes, 1);
        assert_eq!(report.failed_routes, 1);
        assert_eq!(
            report.last_route_failure,
            Some(NetworkRouteFailure::DirectUnavailable)
        );
        assert!(report.observed_at_ms > 0);

        status.observe(&NetworkEvent::RelayUnavailable { relay_peer_id });
        let report = view();
        assert_eq!(report.reserved_relays, 0);
        assert_eq!(report.reachability, NetworkReachability::Public);
        assert_eq!(report.direct_routes, 1);
    }
}
