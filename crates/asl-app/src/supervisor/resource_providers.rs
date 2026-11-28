use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

use asl_store::{open_store, resources::public_resource_provider_keys};
use asl_types::error::AslError;

use super::{NetworkCommand, Supervisor, fresh_id};

const PROVIDER_SYNC_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Default)]
pub(super) struct ResourceProviderRuntime {
    published: HashSet<[u8; 32]>,
    pending: HashMap<[u8; 16], ([u8; 32], bool)>,
    next_sync: Option<Instant>,
}

impl Supervisor {
    pub(super) fn poll_resource_providers(&mut self) -> Result<(), AslError> {
        let now = Instant::now();
        if self
            .resource_providers
            .next_sync
            .is_some_and(|next| now < next)
        {
            return Ok(());
        }
        self.resource_providers.next_sync = Some(now + PROVIDER_SYNC_INTERVAL);
        if !self.net.is_running()
            || self.network_admission_status
                != crate::network_identity::NetworkAdmissionStatus::Active
        {
            return Ok(());
        }

        let store = open_store(&self.state_database)?;
        let desired = public_resource_provider_keys(&store)?
            .into_iter()
            .collect::<HashSet<_>>();

        for key in desired
            .difference(&self.resource_providers.published)
            .copied()
            .collect::<Vec<_>>()
        {
            if self
                .resource_providers
                .pending
                .values()
                .any(|(pending, _)| pending == &key)
            {
                continue;
            }
            let operation_id = fresh_id()?;
            if self
                .send_network_command(NetworkCommand::StartProviding { operation_id, key })
                .is_ok()
            {
                self.resource_providers
                    .pending
                    .insert(operation_id, (key, true));
            }
        }

        for key in self
            .resource_providers
            .published
            .difference(&desired)
            .copied()
            .collect::<Vec<_>>()
        {
            if self
                .resource_providers
                .pending
                .values()
                .any(|(pending, _)| pending == &key)
            {
                continue;
            }
            let operation_id = fresh_id()?;
            if self
                .send_network_command(NetworkCommand::StopProviding { operation_id, key })
                .is_ok()
            {
                self.resource_providers
                    .pending
                    .insert(operation_id, (key, false));
            }
        }
        Ok(())
    }
}

impl ResourceProviderRuntime {
    pub(super) fn observe_resource_provider_event(
        &mut self,
        event: &crate::profile::AdmittedNetworkEvent,
    ) -> Option<([u8; 32], bool)> {
        match event {
            crate::profile::AdmittedNetworkEvent::OperationAccepted { operation_id } => {
                if let Some((key, start)) = self.pending.remove(operation_id) {
                    if start {
                        self.published.insert(key);
                    } else {
                        self.published.remove(&key);
                    }
                    return Some((key, start));
                }
            }
            crate::profile::AdmittedNetworkEvent::OperationFailed { operation_id, .. } => {
                self.pending.remove(operation_id);
            }
            _ => {}
        }
        None
    }

    pub(super) fn reset_resource_providers(&mut self) {
        self.published.clear();
        self.pending.clear();
        self.next_sync = None;
    }
}
