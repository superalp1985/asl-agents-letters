use std::{
    sync::mpsc::{self, Receiver},
    thread,
    time::Duration,
};

use asl_types::{error::AslError, ids::AgentId};

use crate::chain::{
    ChainHttpClient, ChainHttpConfigV1, EthereumLightClient, IdentityProofV1, RegistryDeploymentV1,
};
use tokio::sync::watch;

pub(crate) enum ChainRefreshEvent {
    Updated(Box<ChainRefreshCandidate>),
    Unavailable,
}

pub(crate) struct ChainRefreshCandidate {
    pub light_client: EthereumLightClient,
    pub proof: IdentityProofV1,
}

pub(crate) struct ChainRefreshWorker {
    events: Receiver<ChainRefreshEvent>,
    stop: watch::Sender<bool>,
}

impl ChainRefreshWorker {
    pub(crate) fn start(
        http_config: ChainHttpConfigV1,
        mut light_client: EthereumLightClient,
        agent_id: AgentId,
        deployment: RegistryDeploymentV1,
        max_cache_age_secs: u64,
    ) -> Result<Self, AslError> {
        let interval = Duration::from_secs((max_cache_age_secs / 2).max(1));
        let retry_interval = interval.min(Duration::from_millis(http_config.request_timeout_ms));
        let client = ChainHttpClient::new(http_config).map_err(|_| AslError::InvalidIdentity)?;
        let (event_sender, events) = mpsc::sync_channel(1);
        let (stop, mut stop_receiver) = watch::channel(false);
        thread::Builder::new()
            .name("asl-chain-refresh".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(_) => {
                        let _ = event_sender.send(ChainRefreshEvent::Unavailable);
                        return;
                    }
                };
                runtime.block_on(async move {
                    loop {
                        let mut candidate = light_client.clone();
                        let synchronized = tokio::select! {
                            changed = stop_receiver.changed() => {
                                let _ = changed;
                                return;
                            }
                            result = async {
                                let now_secs = unix_time_secs()?;
                                client
                                    .synchronize_light_client(&mut candidate, now_secs)
                                    .await
                                    .map_err(|_| AslError::InvalidIdentity)
                            } => result,
                        };
                        let (event, wait) = if synchronized.is_ok() {
                            light_client = candidate.clone();
                            let proof = tokio::select! {
                                changed = stop_receiver.changed() => {
                                    let _ = changed;
                                    return;
                                }
                                result = async {
                                    let now_secs = unix_time_secs()?;
                                    client
                                        .fetch_identity_proof(
                                            &candidate,
                                            agent_id,
                                            deployment,
                                            now_secs,
                                        )
                                        .await
                                        .map_err(|_| AslError::InvalidIdentity)
                                } => result,
                            };
                            match proof {
                                Ok(proof) => (
                                    ChainRefreshEvent::Updated(Box::new(ChainRefreshCandidate {
                                        light_client: candidate,
                                        proof,
                                    })),
                                    interval,
                                ),
                                Err(_) => (ChainRefreshEvent::Unavailable, retry_interval),
                            }
                        } else {
                            (ChainRefreshEvent::Unavailable, retry_interval)
                        };
                        match event_sender.try_send(event) {
                            Ok(()) | Err(mpsc::TrySendError::Full(_)) => {}
                            Err(mpsc::TrySendError::Disconnected(_)) => return,
                        }
                        tokio::select! {
                            _ = tokio::time::sleep(wait) => {}
                            changed = stop_receiver.changed() => {
                                let _ = changed;
                                return;
                            }
                        }
                    }
                });
            })
            .map_err(AslError::Io)?;
        Ok(Self { events, stop })
    }

    pub(crate) fn try_recv(&self) -> Option<ChainRefreshEvent> {
        self.events.try_recv().ok()
    }
}

impl Drop for ChainRefreshWorker {
    fn drop(&mut self) {
        self.stop.send_replace(true);
    }
}

fn unix_time_secs() -> Result<u64, AslError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| AslError::ExpiredMessage)
}
