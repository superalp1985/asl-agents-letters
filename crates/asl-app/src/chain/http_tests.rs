use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Instant,
};

use super::*;
use crate::chain::{
    DurableResolverConfigV1, IdentityProofVerifier, IdentityResolution, IdentityResolver,
    test_support::{
        BOOTSTRAP, BOOTSTRAP_TIME, FINALITY, FINALITY_NOW, TestChainDatabase, UPDATES,
        bootstrapped, consensus_config, proof_fixture, registry_values, synced,
    },
};

struct Reply {
    status: &'static str,
    headers: String,
    body: Vec<u8>,
    delay_ms: u64,
    close_delimited: bool,
}

impl Reply {
    fn json(body: impl Into<Vec<u8>>) -> Self {
        Self {
            status: "200 OK",
            headers: String::new(),
            body: body.into(),
            delay_ms: 0,
            close_delimited: false,
        }
    }
}

type RequestLog = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

struct Server {
    url: String,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    requests: RequestLog,
}

impl Server {
    fn start(handler: impl Fn(&str, &[u8]) -> Reply + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let requests: RequestLog = Arc::default();
        let thread_requests = requests.clone();
        let handle = thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                let Ok((mut stream, _)) = listener.accept() else {
                    thread::sleep(Duration::from_millis(2));
                    continue;
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = Vec::new();
                let header_end = loop {
                    let mut buffer = [0; 4096];
                    match stream.read(&mut buffer) {
                        Ok(0) | Err(_) => break None,
                        Ok(count) => request.extend_from_slice(&buffer[..count]),
                    }
                    if let Some(index) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                        break Some(index + 4);
                    }
                };
                let Some(header_end) = header_end else {
                    continue;
                };
                let headers = String::from_utf8(request[..header_end].to_vec()).unwrap();
                let length: usize = headers
                    .lines()
                    .filter_map(|line| line.split_once(':'))
                    .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                    .map(|(_, value)| value.trim().parse().unwrap())
                    .unwrap_or(0);
                while request.len() - header_end < length {
                    let mut buffer = [0; 4096];
                    let count = stream.read(&mut buffer).unwrap();
                    if count == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..count]);
                }
                let body = request[header_end..].to_vec();
                thread_requests
                    .lock()
                    .unwrap()
                    .push((headers.clone(), body.clone()));
                let reply = handler(&headers, &body);
                thread::sleep(Duration::from_millis(reply.delay_ms));
                let length = if reply.close_delimited {
                    String::new()
                } else {
                    format!("Content-Length: {}\r\n", reply.body.len())
                };
                let headers = format!(
                    "HTTP/1.1 {}\r\n{}{}Connection: close\r\nContent-Type: application/json\r\n\r\n",
                    reply.status, length, reply.headers,
                );
                let _ = stream
                    .write_all(headers.as_bytes())
                    .and_then(|()| stream.write_all(&reply.body));
            }
        });
        Self {
            url,
            stop,
            handle: Some(handle),
            requests,
        }
    }

    fn endpoint(&self) -> ChainEndpointV1 {
        ChainEndpointV1 {
            url: self.url.clone(),
            allow_loopback_http: true,
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.handle.take().unwrap().join().unwrap();
    }
}

fn client_config(
    beacon: Vec<ChainEndpointV1>,
    execution: Vec<ChainEndpointV1>,
) -> ChainHttpConfigV1 {
    ChainHttpConfigV1 {
        version: 1,
        beacon_endpoints: beacon,
        execution_endpoints: execution,
        request_timeout_ms: 5000,
        max_committee_updates: 16,
        max_sync_requests: 32,
    }
}

fn durable_config() -> DurableResolverConfigV1 {
    let (deployment, _, _) = proof_fixture(registry_values(9, 1, 1), 8);
    DurableResolverConfigV1 {
        consensus: consensus_config(),
        deployment,
        max_cache_age_secs: 120,
        cache_capacity: 2,
    }
}

fn historical_server() -> Server {
    let updates: Vec<Value> = serde_json::from_slice(UPDATES).unwrap();
    Server::start(move |headers, _| {
        let target = headers
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap();
        let url = Url::parse(&format!("http://127.0.0.1{target}")).unwrap();
        if url.path().contains("/bootstrap/") {
            Reply::json(BOOTSTRAP)
        } else if url.path().ends_with("/updates") {
            let period: u64 = url
                .query_pairs()
                .find(|(key, _)| key == "start_period")
                .unwrap()
                .1
                .parse()
                .unwrap();
            let result: Vec<_> = updates
                .iter()
                .filter(|update| {
                    update["data"]["attested_header"]["beacon"]["slot"]
                        .as_str()
                        .unwrap()
                        .parse::<u64>()
                        .unwrap()
                        / (32 * 256)
                        == period
                })
                .take(1)
                .collect();
            Reply::json(serde_json::to_vec(&result).unwrap())
        } else if url.path().ends_with("/finality_update") {
            Reply::json(FINALITY)
        } else {
            let mut reply = Reply::json(b"{}".to_vec());
            reply.status = "404 Not Found";
            reply
        }
    })
}

#[test]
fn endpoint_validation_rejects_implicit_http_credentials_and_fragments() {
    let endpoint = |url: &str, allow_loopback_http| ChainEndpointV1 {
        url: url.to_owned(),
        allow_loopback_http,
    };
    for invalid in [
        endpoint("http://example.com", true),
        endpoint("http://127.0.0.1", false),
        endpoint("http://localhost", true),
        endpoint("https://name:secret@example.com", false),
        endpoint("https://example.com/#fragment", false),
        endpoint("file:///E:/config", false),
    ] {
        assert!(endpoints(&[invalid]).is_err());
    }
    let urls = endpoints(&[
        endpoint("https://example.com/base?token=local-config", false),
        endpoint("http://[::1]:10001/base", true),
    ])
    .unwrap();
    let url = beacon_url(&urls[0], &["bootstrap", "0x1234"]).unwrap();
    assert_eq!(
        url.path(),
        "/base/eth/v1/beacon/light_client/bootstrap/0x1234"
    );
    assert_eq!(url.query(), Some("token=local-config"));
}

#[tokio::test]
async fn bootstrap_fails_over_after_invalid_response_and_preserves_base_path() {
    let bad = Server::start(|_, _| Reply::json(b"{}".to_vec()));
    let good = historical_server();
    let mut endpoint = good.endpoint();
    endpoint.url.push_str("/replaceable-prefix?access=local");
    let client = ChainHttpClient::new(client_config(
        vec![bad.endpoint(), endpoint],
        vec![good.endpoint()],
    ))
    .unwrap();
    let light_client = client
        .bootstrap(consensus_config(), BOOTSTRAP_TIME)
        .await
        .unwrap();
    assert_eq!(
        light_client.finalized(BOOTSTRAP_TIME).unwrap(),
        bootstrapped().finalized(BOOTSTRAP_TIME).unwrap()
    );
    let requests = good.requests.lock().unwrap();
    assert!(
        requests[0]
            .0
            .contains("/replaceable-prefix/eth/v1/beacon/light_client/bootstrap/")
    );
    assert!(requests[0].0.contains("?access=local "));
    assert_eq!(bad.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn redirects_are_not_followed_and_oversized_bodies_are_bounded_without_length() {
    let destination = Server::start(|_, _| Reply::json(BOOTSTRAP));
    let location = destination.url.clone();
    let redirect = Server::start(move |_, _| {
        let mut reply = Reply::json(Vec::new());
        reply.status = "302 Found";
        reply.headers = format!("Location: {location}\r\n");
        reply
    });
    let client = ChainHttpClient::new(client_config(
        vec![redirect.endpoint()],
        vec![destination.endpoint()],
    ))
    .unwrap();
    assert!(
        client
            .bootstrap(consensus_config(), BOOTSTRAP_TIME)
            .await
            .is_err()
    );
    assert!(destination.requests.lock().unwrap().is_empty());
    for close_delimited in [false, true] {
        let oversized = Server::start(move |_, _| {
            let mut reply = Reply::json(vec![b' '; MAX_BEACON_BYTES + 1]);
            reply.close_delimited = close_delimited;
            reply
        });
        let client = ChainHttpClient::new(client_config(
            vec![oversized.endpoint()],
            vec![destination.endpoint()],
        ))
        .unwrap();
        assert!(matches!(
            client.bootstrap(consensus_config(), BOOTSTRAP_TIME).await,
            Err(ChainError::ResponseTooLarge)
        ));
    }
}

#[tokio::test]
async fn timeout_is_bounded_and_switches_to_next_authorized_endpoint() {
    let slow = Server::start(|_, _| {
        let mut reply = Reply::json(BOOTSTRAP);
        reply.delay_ms = 250;
        reply
    });
    let good = historical_server();
    let mut config = client_config(
        vec![slow.endpoint(), good.endpoint()],
        vec![good.endpoint()],
    );
    config.request_timeout_ms = 100;
    let client = ChainHttpClient::new(config).unwrap();
    let started = Instant::now();
    assert!(
        client
            .bootstrap(consensus_config(), BOOTSTRAP_TIME)
            .await
            .is_ok()
    );
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(slow.requests.lock().unwrap().len(), 1);
}

#[cfg(windows)]
#[tokio::test]
async fn http_historical_sync_persists_every_verified_step_and_restores_offline() {
    let server = historical_server();
    let client = ChainHttpClient::new(client_config(
        vec![server.endpoint()],
        vec![server.endpoint()],
    ))
    .unwrap();
    let light_client = client
        .bootstrap(consensus_config(), FINALITY_NOW)
        .await
        .unwrap();
    let database = TestChainDatabase::new();
    let mut durable = DurableIdentityResolver::create(
        database.open(),
        durable_config(),
        light_client,
        FINALITY_NOW,
    )
    .unwrap();
    let report = client
        .synchronize(&mut durable, FINALITY_NOW)
        .await
        .unwrap();
    let targets: Vec<_> = server
        .requests
        .lock()
        .unwrap()
        .iter()
        .map(|(headers, _)| headers.lines().next().unwrap().to_owned())
        .collect();
    assert_eq!(report.committee_updates, 6, "{targets:?}");
    assert_eq!(report.requests_used, 7, "{targets:?}");
    assert_eq!(report.finalized, synced().finalized(FINALITY_NOW).unwrap());
    drop(durable);
    drop(client);
    drop(server);
    let restored =
        DurableIdentityResolver::restore(database.open(), durable_config(), FINALITY_NOW).unwrap();
    assert_eq!(
        restored.light_client().finalized(FINALITY_NOW).unwrap(),
        report.finalized
    );
}

#[cfg(windows)]
#[tokio::test]
async fn light_client_sync_updates_only_the_supplied_candidate() {
    let server = historical_server();
    let client = ChainHttpClient::new(client_config(
        vec![server.endpoint()],
        vec![server.endpoint()],
    ))
    .unwrap();
    let mut candidate = client
        .bootstrap(consensus_config(), FINALITY_NOW)
        .await
        .unwrap();
    let before_period = candidate.update_period();

    let report = client
        .synchronize_light_client(&mut candidate, FINALITY_NOW)
        .await
        .unwrap();

    assert_eq!(report.committee_updates, 6);
    assert_eq!(report.finalized, synced().finalized(FINALITY_NOW).unwrap());
    assert_ne!(candidate.update_period(), before_period);
    assert_eq!(candidate.finalized(FINALITY_NOW).unwrap(), report.finalized);
}

#[cfg(windows)]
#[tokio::test]
async fn total_sync_request_budget_stops_retries_and_keeps_verified_checkpoint() {
    let server = Server::start(|_, _| {
        let mut reply = Reply::json(b"{}".to_vec());
        reply.status = "503 Service Unavailable";
        reply
    });
    let mut config = client_config(vec![server.endpoint(); 4], vec![server.endpoint()]);
    config.max_sync_requests = 2;
    let client = ChainHttpClient::new(config).unwrap();
    let database = TestChainDatabase::new();
    let mut durable = DurableIdentityResolver::create(
        database.open(),
        durable_config(),
        bootstrapped(),
        BOOTSTRAP_TIME,
    )
    .unwrap();
    let before = durable.light_client().finalized(BOOTSTRAP_TIME).unwrap();
    assert!(
        client
            .synchronize(&mut durable, BOOTSTRAP_TIME)
            .await
            .is_err()
    );
    assert_eq!(server.requests.lock().unwrap().len(), 2);
    assert_eq!(
        durable.light_client().finalized(BOOTSTRAP_TIME).unwrap(),
        before
    );
}

fn rpc_proof(proof: &IdentityProofV1) -> Value {
    json!({
        "address": Address::from(proof.registry_address),
        "balance": "0x0", "nonce": "0x1",
        "storageHash": B256::from(proof.account.storage_root),
        "codeHash": B256::from(proof.account.code_hash),
        "accountProof": proof.account.nodes.iter().map(alloy_primitives::hex::encode_prefixed).collect::<Vec<_>>(),
        "storageProof": proof.storage.iter().map(|path| json!({
            "key": B256::from(path.slot),
            "value": alloy_primitives::U256::from_be_bytes(path.value),
            "proof": path.nodes.iter().map(alloy_primitives::hex::encode_prefixed).collect::<Vec<_>>()
        })).collect::<Vec<_>>()
    })
}

#[cfg(windows)]
#[tokio::test]
async fn eip1186_failover_checks_mpt_and_requests_only_the_local_finalized_hash() {
    let (_, finalized, proof) = proof_fixture(registry_values(9, 1, 1), 8);
    let good_response = json!({"jsonrpc":"2.0","id":1,"result":rpc_proof(&proof)});
    let mut bad_response = good_response.clone();
    bad_response["result"]["storageProof"][0]["value"] = json!("0x1");
    let bad = Server::start(move |_, _| Reply::json(serde_json::to_vec(&bad_response).unwrap()));
    let good = Server::start(move |_, _| Reply::json(serde_json::to_vec(&good_response).unwrap()));
    let client = ChainHttpClient::new(client_config(
        vec![good.endpoint()],
        vec![bad.endpoint(), good.endpoint()],
    ))
    .unwrap();
    let database = TestChainDatabase::new();
    let mut durable = DurableIdentityResolver::create(
        database.open(),
        durable_config(),
        bootstrapped().with_test_execution(finalized.clone()),
        BOOTSTRAP_TIME,
    )
    .unwrap();
    client
        .fetch_identity(&mut durable, proof.agent_id, BOOTSTRAP_TIME)
        .await
        .unwrap();
    assert!(matches!(
        durable.resolve(proof.agent_id, BOOTSTRAP_TIME),
        IdentityResolution::Verified(_)
    ));
    assert_eq!(bad.requests.lock().unwrap().len(), 1);
    let requests = good.requests.lock().unwrap();
    let request: Value = serde_json::from_slice(&requests[0].1).unwrap();
    assert_eq!(request["method"], "eth_getProof");
    assert_eq!(
        request["params"][2],
        json!({"blockHash": B256::from(finalized.block_hash()),"requireCanonical":true})
    );
    assert_eq!(
        request["params"][1],
        json!(registry_slots(proof.agent_id).map(B256::from))
    );
}

#[tokio::test]
async fn jsonrpc_error_wrong_id_and_null_result_are_not_successful_responses() {
    for value in [
        json!({"jsonrpc":"2.0","id":2,"result":7}),
        json!({"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"unsupported"}}),
        json!({"jsonrpc":"2.0","id":1,"result":null}),
    ] {
        let server = Server::start(move |_, _| Reply::json(serde_json::to_vec(&value).unwrap()));
        let client = ChainHttpClient::new(client_config(
            vec![server.endpoint()],
            vec![server.endpoint()],
        ))
        .unwrap();
        let mut budget = Budget { remaining: 1 };
        assert_eq!(
            client
                .rpc::<u64>(
                    &client.execution[0],
                    "eth_getProof",
                    &json!([]),
                    &mut budget
                )
                .await,
            Err(ChainError::InvalidRpcResponse)
        );
    }
}

#[test]
fn alloy_accepts_full_width_and_quantity_storage_keys_before_mpt_verification() {
    let (deployment, finalized, proof) = proof_fixture(registry_values(9, 1, 1), 8);
    let mut value = rpc_proof(&proof);
    value["storageProof"][0]["key"] = json!("0x1");
    let response: EIP1186AccountProofResponse = serde_json::from_value(value).unwrap();
    let converted = identity_proof(response, proof.agent_id, deployment, &finalized).unwrap();
    assert_eq!(converted.storage[0].slot, B256::with_last_byte(1).0);
    assert_eq!(
        super::super::EthereumProofVerifier::new(deployment)
            .unwrap()
            .verify(&finalized, proof.agent_id, &converted,),
        Err(ChainError::WrongContext)
    );
}

#[tokio::test]
async fn gloas_rpc_header_is_hashed_before_exposing_the_execution_root() {
    let execution = alloy_consensus::Header {
        number: 17_883_334,
        timestamp: BOOTSTRAP_TIME + 12,
        state_root: B256::repeat_byte(4),
        ..Default::default()
    };
    let mut light_client = bootstrapped().with_test_gloas_execution(&execution);
    let incorrect = Header::new(alloy_consensus::Header::default());
    let bad_reply = json!({"jsonrpc":"2.0","id":1,"result":incorrect});
    let correct = Header::new(execution);
    let good_reply = json!({"jsonrpc":"2.0","id":1,"result":correct});
    let bad = Server::start(move |_, _| Reply::json(serde_json::to_vec(&bad_reply).unwrap()));
    let good = Server::start(move |_, _| Reply::json(serde_json::to_vec(&good_reply).unwrap()));
    let client = ChainHttpClient::new(client_config(
        vec![good.endpoint()],
        vec![bad.endpoint(), good.endpoint()],
    ))
    .unwrap();
    client
        .complete_bootstrap_execution(
            &mut light_client,
            &RequestClock::new(BOOTSTRAP_TIME + 12),
            &mut Budget { remaining: 2 },
        )
        .await
        .unwrap();
    assert_eq!(
        light_client
            .finalized(BOOTSTRAP_TIME + 12)
            .unwrap()
            .state_root(),
        [4; 32]
    );
    assert_eq!(bad.requests.lock().unwrap().len(), 1);
}
