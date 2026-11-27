use std::{
    collections::HashSet,
    time::{Duration, Instant},
};

use asl_store::{open_store, resources::public_resource_provider_keys};
use asl_types::error::AslError;

use super::{NetworkCommand, Supervisor, fresh_id};

const PROVIDER_SYNC_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Default)]
pub(super) struct ResourceProviderRuntime {
    published: HashSet<[u8; 32]>,
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
            let operation_id = fresh_id()?;
            if self
                .send_network_command(NetworkCommand::StartProviding { operation_id, key })
                .is_ok()
            {
                self.resource_providers.published.insert(key);
            }
        }

        for key in self
            .resource_providers
            .published
            .difference(&desired)
            .copied()
            .collect::<Vec<_>>()
        {
            let operation_id = fresh_id()?;
            if self
                .send_network_command(NetworkCommand::StopProviding { operation_id, key })
                .is_ok()
            {
                self.resource_providers.published.remove(&key);
            }
        }
        Ok(())
    }
}
