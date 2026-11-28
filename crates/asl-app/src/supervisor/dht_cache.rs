use std::{collections::VecDeque, env};

use asl_store::{Store, open_store};
use asl_types::error::AslError;

use super::{NetRuntime, Supervisor, unix_time_ms};
use crate::{ipc::IpcMessage, network::LocalNetworkObservation};

const ENV_RESTORE_RECORDS: &str = "ASL_DHT_RESTORE_RECORDS";
const ENV_RESTORE_PROVIDERS: &str = "ASL_DHT_RESTORE_PROVIDERS";
const ENV_RESTORE_BATCH: &str = "ASL_DHT_RESTORE_BATCH";
const DEFAULT_RESTORE_RECORDS: u16 = 256;
const DEFAULT_RESTORE_PROVIDERS: u16 = 256;
const DEFAULT_RESTORE_BATCH: usize = 4;
const MAX_RESTORE_RECORDS: u16 = 512;
const MAX_RESTORE_PROVIDERS: u16 = 512;
const MAX_RESTORE_BATCH: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct DhtRestoreConfig {
    pub records: u16,
    pub providers: u16,
    pub batch: usize,
}

impl DhtRestoreConfig {
    fn from_env() -> Self {
        Self::bounded(
            env_u16(ENV_RESTORE_RECORDS).unwrap_or(DEFAULT_RESTORE_RECORDS),
            env_u16(ENV_RESTORE_PROVIDERS).unwrap_or(DEFAULT_RESTORE_PROVIDERS),
            env_usize(ENV_RESTORE_BATCH).unwrap_or(DEFAULT_RESTORE_BATCH),
        )
    }

    fn bounded(records: u16, providers: u16, batch: usize) -> Self {
        Self {
            records: records.min(MAX_RESTORE_RECORDS),
            providers: providers.min(MAX_RESTORE_PROVIDERS),
            batch: batch.clamp(1, MAX_RESTORE_BATCH),
        }
    }
}

impl Default for DhtRestoreConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

pub(super) struct DhtRestoreRuntime {
    config: DhtRestoreConfig,
    pending: VecDeque<IpcMessage>,
}

impl Default for DhtRestoreRuntime {
    fn default() -> Self {
        Self::new(DhtRestoreConfig::default())
    }
}

impl DhtRestoreRuntime {
    fn new(config: DhtRestoreConfig) -> Self {
        Self {
            config,
            pending: VecDeque::new(),
        }
    }

    fn reload(&mut self, store: &Store, now_ms: u64) -> Result<(), AslError> {
        self.pending.clear();
        if self.config.records != 0 {
            for record in store.cached_dht_records(now_ms, self.config.records)? {
                self.pending.push_back(IpcMessage::RestoreDhtRecord {
                    expires_at_ms: record.expires_at_ms,
                    value: record.record,
                });
            }
        }
        if self.config.providers != 0 {
            for provider in store.cached_dht_providers(now_ms, self.config.providers)? {
                self.pending.push_back(IpcMessage::RestoreDhtProvider {
                    key: provider.key,
                    peer_id: provider.provider_id,
                    addresses: provider.addresses,
                    expires_at_ms: provider.expires_at_ms,
                });
            }
        }
        Ok(())
    }

    fn pump(&mut self, net: &NetRuntime) -> Result<(), AslError> {
        if !net.is_running() {
            return Ok(());
        }
        for _ in 0..self.config.batch {
            let Some(message) = self.pending.front() else {
                break;
            };
            if !net.try_send(message)? {
                break;
            }
            self.pending.pop_front();
        }
        Ok(())
    }
}

impl Supervisor {
    pub(super) fn reload_dht_restore(&mut self) -> Result<(), AslError> {
        let store = open_store(&self.state_database)?;
        self.dht_restore.reload(&store, unix_time_ms()?)
    }

    pub(super) fn pump_dht_restore(&mut self) -> Result<(), AslError> {
        self.dht_restore.pump(&self.net)
    }

    pub(crate) fn observe_dht_provider_observation(
        &self,
        observation: &LocalNetworkObservation,
    ) -> Result<(), AslError> {
        let LocalNetworkObservation::DhtProviderObserved {
            key,
            peer_id,
            addresses,
            expires_at_ms,
        } = observation
        else {
            return Ok(());
        };
        let store = open_store(&self.state_database)?;
        store.cache_dht_provider(
            *key,
            peer_id.clone(),
            addresses,
            *expires_at_ms,
            unix_time_ms()?,
        )
    }
}

fn env_u16(name: &str) -> Option<u16> {
    env::var(name).ok()?.parse().ok()
}

fn env_usize(name: &str) -> Option<usize> {
    env::var(name).ok()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_configuration_clamps_environment_style_limits() {
        let config = DhtRestoreConfig::bounded(u16::MAX, u16::MAX, usize::MAX);
        assert_eq!(config.records, MAX_RESTORE_RECORDS);
        assert_eq!(config.providers, MAX_RESTORE_PROVIDERS);
        assert_eq!(config.batch, MAX_RESTORE_BATCH);
    }
}
