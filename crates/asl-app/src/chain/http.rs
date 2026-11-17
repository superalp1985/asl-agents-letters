use std::{
    net::IpAddr,
    time::{Duration, Instant},
};

use alloy_primitives::{Address, B256};
use alloy_rpc_types_eth::{EIP1186AccountProofResponse, Header};
use asl_types::ids::AgentId;
use helios_consensus_core::consensus_spec::{ConsensusSpec, MainnetConsensusSpec};
use reqwest::{Client, RequestBuilder, Url};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json, value::RawValue};

use super::{
    AccountProofV1, ChainError, ConsensusConfigV1, DurableIdentityResolver, EthereumLightClient,
    FinalizedExecution, IdentityProofV1, RegistryDeploymentV1, StorageProofV1, registry_slots,
};

const MAX_BEACON_BYTES: usize = 256 * 1024;
const MAX_RPC_BYTES: usize = 768 * 1024;

#[derive(Clone, Serialize, Deserialize)]
pub struct ChainEndpointV1 {
    pub url: String,
    pub allow_loopback_http: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ChainHttpConfigV1 {
    pub version: u16,
    pub beacon_endpoints: Vec<ChainEndpointV1>,
    pub execution_endpoints: Vec<ChainEndpointV1>,
    pub request_timeout_ms: u64,
    pub max_committee_updates: u8,
    pub max_sync_requests: u8,
}

pub struct ChainHttpClient {
    client: Client,
    beacon: Vec<Url>,
    execution: Vec<Url>,
    max_updates: u8,
    max_requests: u8,
}

#[derive(Debug)]
pub struct ChainSyncReport {
    pub committee_updates: u8,
    pub requests_used: u8,
    pub finalized: FinalizedExecution,
}

struct Budget {
    remaining: u8,
}

struct RequestClock {
    started: Instant,
    now_secs: u64,
}

impl RequestClock {
    fn new(now_secs: u64) -> Self {
        Self {
            started: Instant::now(),
            now_secs,
        }
    }

    fn now(&self) -> Result<u64, ChainError> {
        self.now_secs
            .checked_add(self.started.elapsed().as_secs())
            .ok_or(ChainError::ClockBeforeState)
    }
}

impl Budget {
    fn charge(&mut self) -> Result<(), ChainError> {
        self.remaining = self
            .remaining
            .checked_sub(1)
            .ok_or(ChainError::TransportUnavailable)?;
        Ok(())
    }
}

// Typed operations are the only callers of the HTTP layer. Neither peer input
// nor response fields can select a URL, method, checkpoint, slot or retry count.
impl ChainHttpClient {
    pub fn new(config: ChainHttpConfigV1) -> Result<Self, ChainError> {
        if config.version != 1
            || !(100..=30_000).contains(&config.request_timeout_ms)
            || !(1..=16).contains(&config.max_committee_updates)
            || !(2..=32).contains(&config.max_sync_requests)
        {
            return Err(ChainError::InvalidConfiguration);
        }
        let timeout = Duration::from_millis(config.request_timeout_ms);
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .referer(false)
            .connect_timeout(timeout)
            .read_timeout(timeout)
            .timeout(timeout)
            .pool_max_idle_per_host(1)
            .build()
            .map_err(|_| ChainError::InvalidConfiguration)?;
        Ok(Self {
            client,
            beacon: endpoints(&config.beacon_endpoints)?,
            execution: endpoints(&config.execution_endpoints)?,
            max_updates: config.max_committee_updates,
            max_requests: config.max_sync_requests,
        })
    }

    pub async fn bootstrap(
        &self,
        config: ConsensusConfigV1,
        now_secs: u64,
    ) -> Result<EthereumLightClient, ChainError> {
        config.validate()?;
        let clock = RequestClock::new(now_secs);
        let mut budget = Budget {
            remaining: self.max_requests,
        };
        let root = B256::from(config.checkpoint.beacon_root).to_string();
        let mut last_error = ChainError::TransportUnavailable;
        for base in &self.beacon {
            let url = beacon_url(base, &["bootstrap", &root])?;
            let result = async {
                let bytes = self
                    .read(self.client.get(url), MAX_BEACON_BYTES, &mut budget)
                    .await?;
                EthereumLightClient::bootstrap(config.clone(), &bytes, clock.now()?)
            }
            .await;
            match result {
                Ok(mut client) => {
                    if client.observed_execution().is_none() {
                        self.complete_bootstrap_execution(&mut client, &clock, &mut budget)
                            .await?;
                    }
                    return Ok(client);
                }
                Err(error) if local_failure(error) => return Err(error),
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }

    pub async fn synchronize(
        &self,
        resolver: &mut DurableIdentityResolver,
        now_secs: u64,
    ) -> Result<ChainSyncReport, ChainError> {
        let clock = RequestClock::new(now_secs);
        let mut budget = Budget {
            remaining: self.max_requests,
        };
        let updates = self.sync_target(resolver, &clock, &mut budget).await?;
        Ok(ChainSyncReport {
            committee_updates: updates,
            requests_used: self.max_requests - budget.remaining,
            finalized: resolver.light_client().finalized(clock.now()?)?,
        })
    }

    pub async fn fetch_identity(
        &self,
        resolver: &mut DurableIdentityResolver,
        agent: AgentId,
        now_secs: u64,
    ) -> Result<(), ChainError> {
        let clock = RequestClock::new(now_secs);
        let finalized = resolver.light_client().finalized(now_secs)?;
        let deployment = resolver.deployment();
        let params = json!([
            Address::from(deployment.address),
            registry_slots(agent).map(B256::from),
            {"blockHash": B256::from(finalized.block_hash()), "requireCanonical": true}
        ]);
        let mut budget = Budget {
            remaining: self.execution.len() as u8,
        };
        let mut last_error = ChainError::TransportUnavailable;
        for endpoint in &self.execution {
            let result = async {
                let response: EIP1186AccountProofResponse = self
                    .rpc(endpoint, "eth_getProof", &params, &mut budget)
                    .await?;
                let proof = identity_proof(response, agent, deployment, &finalized)?;
                resolver.accept_proof(agent, &proof, clock.now()?)
            }
            .await;
            match result {
                Ok(()) => return Ok(()),
                Err(error) if local_failure(error) => return Err(error),
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }

    async fn complete_bootstrap_execution(
        &self,
        client: &mut EthereumLightClient,
        clock: &RequestClock,
        budget: &mut Budget,
    ) -> Result<(), ChainError> {
        let params = json!([B256::from(client.execution_block_hash()?), false]);
        let mut last_error = ChainError::TransportUnavailable;
        for endpoint in &self.execution {
            let result = async {
                let header: Header = self
                    .rpc(endpoint, "eth_getBlockByHash", &params, budget)
                    .await?;
                client.supply_execution_header(
                    &alloy_rlp::encode(header.into_consensus()),
                    clock.now()?,
                )
            }
            .await;
            match result {
                Ok(()) => return Ok(()),
                Err(error) if local_failure(error) => return Err(error),
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }

    async fn sync_target(
        &self,
        target: &mut DurableIdentityResolver,
        clock: &RequestClock,
        budget: &mut Budget,
    ) -> Result<u8, ChainError> {
        let mut updates = 0;
        for _ in 0..self.max_updates {
            let now_secs = clock.now()?;
            let period = target.light_client().update_period();
            let config = target.light_client().config();
            if period
                > config.current_slot(now_secs)?
                    / MainnetConsensusSpec::slots_per_sync_committee_period()
            {
                break;
            }
            let mut accepted = false;
            for base in &self.beacon {
                let mut url = beacon_url(base, &["updates"])?;
                url.query_pairs_mut()
                    .append_pair("start_period", &period.to_string())
                    .append_pair("count", "1");
                let result = async {
                    let bytes = self
                        .read(self.client.get(url), MAX_BEACON_BYTES, budget)
                        .await?;
                    let entries: Vec<Box<RawValue>> = serde_json::from_slice(&bytes)
                        .map_err(|_| ChainError::InvalidRpcResponse)?;
                    if entries.len() != 1 {
                        return Err(ChainError::InvalidRpcResponse);
                    }
                    target.apply_update_json(entries[0].get().as_bytes(), clock.now()?)
                }
                .await;
                match result {
                    Ok(()) => {
                        accepted = true;
                        updates += 1;
                        break;
                    }
                    Err(error) if local_failure(error) => return Err(error),
                    Err(_) => {}
                }
            }
            if !accepted || target.light_client().update_period() == period {
                break;
            }
        }
        let mut last_error = ChainError::TransportUnavailable;
        let mut accepted = false;
        for base in &self.beacon {
            let url = beacon_url(base, &["finality_update"])?;
            let result = async {
                let bytes = self
                    .read(self.client.get(url), MAX_BEACON_BYTES, budget)
                    .await?;
                target.apply_finality_json(&bytes, clock.now()?)
            }
            .await;
            match result {
                Ok(()) => {
                    accepted = true;
                    break;
                }
                Err(error) if local_failure(error) => return Err(error),
                Err(error) => last_error = error,
            }
        }
        if !accepted {
            return Err(last_error);
        }
        if target.light_client().finalized(clock.now()?) == Err(ChainError::ExecutionHeaderRequired)
        {
            let hash = target.light_client().execution_block_hash()?;
            let params = json!([B256::from(hash), false]);
            for endpoint in &self.execution {
                let result = async {
                    let header: Header = self
                        .rpc(endpoint, "eth_getBlockByHash", &params, budget)
                        .await?;
                    let rlp = alloy_rlp::encode(header.into_consensus());
                    target.supply_execution_header(&rlp, clock.now()?)
                }
                .await;
                match result {
                    Ok(()) => {
                        target.light_client().finalized(clock.now()?)?;
                        return Ok(updates);
                    }
                    Err(error) if local_failure(error) => return Err(error),
                    Err(error) => last_error = error,
                }
            }
            return Err(last_error);
        }
        target.light_client().finalized(clock.now()?)?;
        Ok(updates)
    }

    async fn rpc<T: DeserializeOwned>(
        &self,
        endpoint: &Url,
        method: &str,
        params: &Value,
        budget: &mut Budget,
    ) -> Result<T, ChainError> {
        #[derive(Deserialize)]
        struct Response<T> {
            jsonrpc: String,
            id: u64,
            result: Option<T>,
            error: Option<Value>,
        }
        let bytes = self
            .read(
                self.client.post(endpoint.clone()).json(&json!({
                    "jsonrpc": "2.0", "id": 1, "method": method, "params": params
                })),
                MAX_RPC_BYTES,
                budget,
            )
            .await?;
        let response: Response<T> =
            serde_json::from_slice(&bytes).map_err(|_| ChainError::InvalidRpcResponse)?;
        if response.jsonrpc != "2.0" || response.id != 1 || response.error.is_some() {
            return Err(ChainError::InvalidRpcResponse);
        }
        response.result.ok_or(ChainError::InvalidRpcResponse)
    }

    async fn read(
        &self,
        request: RequestBuilder,
        max_bytes: usize,
        budget: &mut Budget,
    ) -> Result<Vec<u8>, ChainError> {
        budget.charge()?;
        let mut response = request
            .send()
            .await
            .map_err(|_| ChainError::TransportUnavailable)?;
        if !response.status().is_success() {
            return Err(ChainError::TransportUnavailable);
        }
        if response
            .content_length()
            .is_some_and(|length| length > max_bytes as u64)
        {
            return Err(ChainError::ResponseTooLarge);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| ChainError::TransportUnavailable)?
        {
            if chunk.len() > max_bytes - bytes.len() {
                return Err(ChainError::ResponseTooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
}

fn endpoints(config: &[ChainEndpointV1]) -> Result<Vec<Url>, ChainError> {
    if !(1..=4).contains(&config.len()) {
        return Err(ChainError::InvalidConfiguration);
    }
    config
        .iter()
        .map(|endpoint| {
            let url = Url::parse(&endpoint.url).map_err(|_| ChainError::InvalidConfiguration)?;
            let loopback = url
                .host_str()
                .and_then(|host| host.trim_matches(['[', ']']).parse::<IpAddr>().ok())
                .is_some_and(|address| address.is_loopback());
            if url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
                || (url.scheme() != "https"
                    && !(url.scheme() == "http" && loopback && endpoint.allow_loopback_http))
            {
                return Err(ChainError::InvalidConfiguration);
            }
            Ok(url)
        })
        .collect()
}

fn beacon_url(base: &Url, suffix: &[&str]) -> Result<Url, ChainError> {
    let mut url = base.clone();
    url.path_segments_mut()
        .map_err(|_| ChainError::InvalidConfiguration)?
        .pop_if_empty()
        .extend(["eth", "v1", "beacon", "light_client"])
        .extend(suffix.iter().copied());
    Ok(url)
}

fn identity_proof(
    response: EIP1186AccountProofResponse,
    agent: AgentId,
    deployment: RegistryDeploymentV1,
    finalized: &FinalizedExecution,
) -> Result<IdentityProofV1, ChainError> {
    if response.address != Address::from(deployment.address) {
        return Err(ChainError::WrongContext);
    }
    Ok(IdentityProofV1 {
        version: 1,
        agent_id: agent,
        chain_id: deployment.chain_id,
        registry_address: deployment.address,
        block_number: finalized.block_number(),
        block_hash: finalized.block_hash(),
        state_root: finalized.state_root(),
        account: AccountProofV1 {
            nonce: response.nonce,
            balance: response.balance.to_be_bytes(),
            storage_root: response.storage_hash.0,
            code_hash: response.code_hash.0,
            nodes: response
                .account_proof
                .into_iter()
                .map(|node| node.to_vec())
                .collect(),
        },
        storage: response
            .storage_proof
            .into_iter()
            .map(|path| StorageProofV1 {
                slot: path.key.as_b256().0,
                value: path.value.to_be_bytes(),
                nodes: path.proof.into_iter().map(|node| node.to_vec()).collect(),
            })
            .collect(),
    })
}

fn local_failure(error: ChainError) -> bool {
    matches!(
        error,
        ChainError::ExpiredCheckpoint
            | ChainError::ClockBeforeState
            | ChainError::ConflictingFinality
            | ChainError::StorageUnavailable
            | ChainError::InvalidConfiguration
            | ChainError::InvalidLocalState
            | ChainError::ObservationLimit
    )
}

#[cfg(test)]
#[path = "http_tests.rs"]
mod tests;
