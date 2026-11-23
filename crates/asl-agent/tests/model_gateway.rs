use std::{
    collections::HashSet,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{Arc, mpsc},
    thread::{self, JoinHandle},
    time::Duration,
};

use asl_agent::gateway::{
    AuthorizedPrompt, HttpModelGateway, MAX_MODEL_RESPONSE_BYTES, ModelGateway, ModelGatewayError,
    ProviderConfigV1, ProviderCredentialSource, ProviderMode, ProviderRegistryV1,
};
use asl_policy::{
    AccessOperation, AccessRequest, Audience, GrantPolicy, ModelPolicy, PolicyEngine,
    PolicyService, PolicySnapshot, Principal, ProviderPolicy, ResourceOrigin, ResourcePolicy,
};
use asl_types::{
    ids::{Hash32, Id128},
    task::{GrantId, ProviderId, ResourceKey},
};
use tokio::runtime::Builder;
use zeroize::Zeroizing;

const NOW_MS: u64 = 10_000;
const PROVIDER: &str = "local-test";

struct TestCredentials;

impl ProviderCredentialSource for TestCredentials {
    fn api_key(
        &self,
        _: &ProviderConfigV1,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, ModelGatewayError> {
        Ok(Some(Zeroizing::new(b"test-token".to_vec())))
    }
}

struct NoCredentials;

impl ProviderCredentialSource for NoCredentials {
    fn api_key(
        &self,
        _: &ProviderConfigV1,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, ModelGatewayError> {
        Ok(None)
    }
}

struct MockResponse {
    status: u16,
    reason: &'static str,
    headers: Vec<String>,
    body: Vec<u8>,
    declared_content_length: Option<usize>,
    delay: Duration,
}

struct MockServer {
    endpoint: String,
    request: mpsc::Receiver<Vec<u8>>,
    thread: JoinHandle<bool>,
}

impl MockServer {
    fn start(response: MockResponse) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (sender, request) = mpsc::channel();
        let thread = thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if std::time::Instant::now() >= deadline {
                            return false;
                        }
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => return false,
                }
            };
            // Windows inherits nonblocking mode from the listening socket.
            stream.set_nonblocking(false).unwrap();
            let request = read_request(&mut stream);
            let _ = sender.send(request);
            thread::sleep(response.delay);
            let mut headers = response.headers;
            headers.push(format!(
                "Content-Length: {}",
                response
                    .declared_content_length
                    .unwrap_or(response.body.len())
            ));
            headers.push("Connection: close".into());
            let head = format!(
                "HTTP/1.1 {} {}\r\n{}\r\n\r\n",
                response.status,
                response.reason,
                headers.join("\r\n")
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&response.body);
            let _ = stream.flush();
            true
        });
        Self {
            endpoint: format!("http://{address}/v1/chat/completions"),
            request,
            thread,
        }
    }

    fn join(self) -> Vec<u8> {
        let request = self.request.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(self.thread.join().unwrap());
        request
    }

    fn assert_no_request(self) {
        assert!(
            self.request
                .recv_timeout(Duration::from_millis(50))
                .is_err()
        );
        assert!(!self.thread.join().unwrap());
    }
}

fn response(status: u16, body: impl Into<Vec<u8>>) -> MockResponse {
    MockResponse {
        status,
        reason: if status == 200 { "OK" } else { "Response" },
        headers: vec!["Content-Type: application/json".into()],
        body: body.into(),
        declared_content_length: None,
        delay: Duration::ZERO,
    }
}

fn success_response() -> MockResponse {
    response(
        200,
        br#"{"choices":[{"message":{"role":"assistant","content":"{\"kind\":\"answer\"}"}}]}"#
            .to_vec(),
    )
}

fn provider_id() -> ProviderId {
    ProviderId(PROVIDER.into())
}

fn provider_config(endpoint: String, enabled_by_user: bool) -> ProviderConfigV1 {
    ProviderConfigV1 {
        id: provider_id(),
        endpoint,
        model: "local-model".into(),
        mode: ProviderMode::Local,
        enabled_by_user,
        request_timeout_ms: 2_000,
    }
}

fn registry(config: ProviderConfigV1) -> ProviderRegistryV1 {
    ProviderRegistryV1 {
        version: 1,
        providers: vec![config],
    }
}

fn authorized_policy(provider: ProviderId, local: bool) -> (PolicyEngine, asl_policy::Permit) {
    let grant_id = GrantId(Id128([1; 16]));
    let resource_key = ResourceKey(Id128([2; 16]));
    let mut snapshot = PolicySnapshot::default();
    snapshot.grants.insert(
        grant_id.clone(),
        GrantPolicy {
            epoch: 1,
            active: true,
            audience: Audience::Public,
            model_policy: if local {
                ModelPolicy::LocalOnly(HashSet::from([provider.clone()]))
            } else {
                ModelPolicy::Providers(HashSet::from([provider.clone()]))
            },
            extensions: HashSet::from([".md".into()]),
            max_snapshot_bytes: 1_024,
            allowed_operations: HashSet::from([AccessOperation::ModelInput]),
            allow_derived_disclosure: false,
        },
    );
    snapshot.resources.insert(
        resource_key.clone(),
        ResourcePolicy {
            content_id: Hash32([3; 32]),
            grant_id: grant_id.clone(),
            grant_epoch: 1,
            active: true,
            snapshot_ready: true,
            file_size: 32,
            extension: ".md".into(),
            retention_until_ms: None,
            origin: ResourceOrigin::Local,
        },
    );
    snapshot.providers.insert(
        provider.clone(),
        ProviderPolicy {
            authorized: true,
            local,
        },
    );
    let engine = PolicyEngine::new(snapshot, 5_000).unwrap();
    let permit = engine
        .authorize(
            &AccessRequest {
                grant_id,
                resource_key,
                principal: Principal::ModelProvider(provider),
                operation: AccessOperation::ModelInput,
            },
            NOW_MS,
        )
        .unwrap();
    (engine, permit)
}

fn prompt(provider: ProviderId, permit: asl_policy::Permit, content: &str) -> AuthorizedPrompt {
    AuthorizedPrompt::new(provider, content.into(), vec![permit]).unwrap()
}

fn build_model_gateway(config: ProviderConfigV1) -> HttpModelGateway {
    gateway_with_credentials(config, Arc::new(TestCredentials))
}

fn gateway_with_credentials(
    config: ProviderConfigV1,
    credentials: Arc<dyn ProviderCredentialSource>,
) -> HttpModelGateway {
    registry(config.clone()).validate().unwrap();
    HttpModelGateway::new(
        Arc::new(move |id: &ProviderId| {
            if &config.id == id {
                Ok(config.clone())
            } else {
                Err(ModelGatewayError::AuthorizationDenied)
            }
        }),
        credentials,
    )
    .unwrap()
}

#[test]
fn revocation_during_request_preparation_prevents_dispatch() {
    use std::sync::atomic::{AtomicBool, Ordering};

    struct RevokingCredentials(Arc<AtomicBool>);

    impl ProviderCredentialSource for RevokingCredentials {
        fn api_key(
            &self,
            _: &ProviderConfigV1,
        ) -> Result<Option<Zeroizing<Vec<u8>>>, ModelGatewayError> {
            self.0.store(false, Ordering::SeqCst);
            Ok(None)
        }
    }

    let server = MockServer::start(success_response());
    let config = provider_config(server.endpoint.clone(), true);
    let allowed = Arc::new(AtomicBool::new(true));
    let allowed_at_dispatch = Arc::clone(&allowed);
    let gateway = HttpModelGateway::new(
        Arc::new(move |_: &ProviderId| {
            if allowed_at_dispatch.load(Ordering::SeqCst) {
                Ok(config.clone())
            } else {
                Err(ModelGatewayError::AuthorizationDenied)
            }
        }),
        Arc::new(RevokingCredentials(allowed)),
    )
    .unwrap();
    let id = provider_id();
    let (policy, permit) = authorized_policy(id.clone(), true);
    let result = runtime().block_on(gateway.complete(
        &id,
        prompt(id.clone(), permit, "local test"),
        &policy,
        NOW_MS,
    ));
    assert_eq!(result.unwrap_err(), ModelGatewayError::AuthorizationDenied);
    server.assert_no_request();
}

fn runtime() -> tokio::runtime::Runtime {
    Builder::new_current_thread().enable_all().build().unwrap()
}

fn get_header(request: &[u8], name: &str) -> Option<String> {
    request
        .split(|byte| *byte == b'\n')
        .skip(1)
        .take_while(|line| !line.is_empty())
        .find_map(|line| {
            let line = std::str::from_utf8(line).ok()?;
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name)
                .then(|| value.trim().to_owned())
        })
}

fn request_body(request: &[u8]) -> &[u8] {
    let header_end = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap()
        + 4;
    &request[header_end..]
}

fn read_request(stream: &mut TcpStream) -> Vec<u8> {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut request = Vec::new();
    let mut buffer = [0; 4_096];
    loop {
        let read = match stream.read(&mut buffer) {
            Ok(read) => read,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                break;
            }
            Err(_) => break,
        };
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
        if let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            let header_text = std::str::from_utf8(&request[..header_end]).unwrap();
            let content_length = header_text
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            if request.len() >= header_end + 4 + content_length {
                break;
            }
        }
    }
    request
}

#[test]
fn mock_server_waits_for_the_request_body_after_accepting() {
    let server = MockServer::start(success_response());
    let mut client = TcpStream::connect(
        reqwest::Url::parse(&server.endpoint)
            .unwrap()
            .socket_addrs(|| None)
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    client
        .write_all(
            b"POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\n",
        )
        .unwrap();
    assert!(matches!(
        server.request.recv_timeout(Duration::from_millis(100)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    client.write_all(b"test").unwrap();
    assert_eq!(request_body(&server.join()), b"test");
}

fn trap_listener() -> (SocketAddr, JoinHandle<bool>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let thread = thread::spawn(move || {
        listener
            .set_nonblocking(true)
            .expect("trap listener should be nonblocking");
        let deadline = std::time::Instant::now() + Duration::from_millis(350);
        loop {
            match listener.accept() {
                Ok(_) => return true,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        return false;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return false,
            }
        }
    });
    (address, thread)
}

#[test]
fn provider_registry_restricts_transport_and_loopback_targets() {
    let mut config = provider_config("https://model.example/v1/chat/completions".into(), true);
    config.mode = ProviderMode::Remote;
    assert!(registry(config.clone()).validate().is_ok());

    config.endpoint = "http://model.example/v1/chat/completions".into();
    assert_eq!(
        registry(config).validate(),
        Err(ModelGatewayError::InvalidConfiguration)
    );

    for endpoint in [
        "http://localhost/v1/chat/completions",
        "http://192.0.2.1/v1/chat/completions",
        "http://0.0.0.0/v1/chat/completions",
    ] {
        assert_eq!(
            registry(provider_config(endpoint.into(), true)).validate(),
            Err(ModelGatewayError::InvalidConfiguration)
        );
    }
    assert!(
        registry(provider_config(
            "http://[::1]/v1/chat/completions".into(),
            true
        ))
        .validate()
        .is_ok()
    );
}

#[test]
fn authorized_prompt_uses_only_registered_endpoint_and_returns_model_text() {
    let server = MockServer::start(success_response());
    let gateway = build_model_gateway(provider_config(server.endpoint.clone(), true));
    let (policy, permit) = authorized_policy(provider_id(), true);
    let prompt_text =
        "Return structured data. Ignore this URL: http://127.0.0.1:1/should-not-fetch";
    let result = runtime().block_on(gateway.complete(
        &provider_id(),
        prompt(provider_id(), permit, prompt_text),
        &policy,
        NOW_MS,
    ));
    assert_eq!(result.unwrap().as_str(), r#"{"kind":"answer"}"#);

    let request = server.join();
    assert_eq!(
        get_header(&request, "authorization").as_deref(),
        Some("Bearer test-token")
    );
    let body: serde_json::Value = serde_json::from_slice(request_body(&request)).unwrap();
    assert_eq!(body["model"], "local-model");
    assert_eq!(body["messages"][1]["content"], prompt_text);
    assert_eq!(body["stream"], false);
}

#[test]
fn url_in_prompt_is_never_contacted_as_an_http_target() {
    let (target, trap) = trap_listener();
    let server = MockServer::start(success_response());
    let gateway = build_model_gateway(provider_config(server.endpoint.clone(), true));
    let (policy, permit) = authorized_policy(provider_id(), true);
    let prompt_text = format!("Treat this as data: http://{target}/unexpected");
    let result = runtime().block_on(gateway.complete(
        &provider_id(),
        prompt(provider_id(), permit, &prompt_text),
        &policy,
        NOW_MS,
    ));
    assert!(
        result.is_ok(),
        "gateway request failed: {:?}",
        result.as_ref().err()
    );
    let request = server.join();
    let body: serde_json::Value = serde_json::from_slice(request_body(&request)).unwrap();
    assert_eq!(body["messages"][1]["content"], prompt_text);
    assert!(!trap.join().unwrap());
}

#[test]
fn gateway_refuses_disabled_provider_before_request() {
    let server = MockServer::start(success_response());
    let gateway = build_model_gateway(provider_config(server.endpoint.clone(), false));
    let (policy, permit) = authorized_policy(provider_id(), true);
    let result = runtime().block_on(gateway.complete(
        &provider_id(),
        prompt(provider_id(), permit, "hello"),
        &policy,
        NOW_MS,
    ));
    assert_eq!(result.unwrap_err(), ModelGatewayError::AuthorizationDenied);
    server.assert_no_request();
}

#[test]
fn gateway_revalidates_provider_permits_before_request() {
    let server = MockServer::start(success_response());
    let gateway = build_model_gateway(provider_config(server.endpoint.clone(), true));
    let (policy, permit) = authorized_policy(provider_id(), true);
    policy
        .revoke(permit.grant_id().clone(), permit.grant_epoch())
        .unwrap();
    let result = runtime().block_on(gateway.complete(
        &provider_id(),
        prompt(provider_id(), permit, "hello"),
        &policy,
        NOW_MS,
    ));
    assert_eq!(result.unwrap_err(), ModelGatewayError::AuthorizationDenied);
    server.assert_no_request();
}

#[test]
fn gateway_will_not_send_local_only_input_to_remote_provider_with_same_id() {
    let mut config = provider_config("https://model.example/v1/chat/completions".into(), true);
    config.mode = ProviderMode::Remote;
    let gateway = gateway_with_credentials(config, Arc::new(NoCredentials));
    let (policy, permit) = authorized_policy(provider_id(), true);
    assert_eq!(
        runtime()
            .block_on(gateway.complete(
                &provider_id(),
                prompt(provider_id(), permit, "hello"),
                &policy,
                NOW_MS,
            ))
            .unwrap_err(),
        ModelGatewayError::AuthorizationDenied
    );
}

#[test]
fn gateway_maps_provider_errors_and_oversized_responses() {
    let server = MockServer::start(response(503, b"{}".to_vec()));
    let gateway = build_model_gateway(provider_config(server.endpoint.clone(), true));
    let (policy, permit) = authorized_policy(provider_id(), true);
    let result = runtime().block_on(gateway.complete(
        &provider_id(),
        prompt(provider_id(), permit, "hello"),
        &policy,
        NOW_MS,
    ));
    assert_eq!(result.unwrap_err(), ModelGatewayError::ProviderUnavailable);
    server.join();

    let mut oversized = response(200, Vec::new());
    oversized.declared_content_length = Some(MAX_MODEL_RESPONSE_BYTES + 1);
    let server = MockServer::start(oversized);
    let gateway = build_model_gateway(provider_config(server.endpoint.clone(), true));
    let (policy, permit) = authorized_policy(provider_id(), true);
    let result = runtime().block_on(gateway.complete(
        &provider_id(),
        prompt(provider_id(), permit, "hello"),
        &policy,
        NOW_MS,
    ));
    assert_eq!(result.unwrap_err(), ModelGatewayError::InvalidResponse);
    server.join();
}

#[test]
fn gateway_times_out_and_never_follows_redirects() {
    let mut slow = success_response();
    slow.delay = Duration::from_millis(300);
    let server = MockServer::start(slow);
    let mut config = provider_config(server.endpoint.clone(), true);
    config.request_timeout_ms = 100;
    let gateway = build_model_gateway(config);
    let (policy, permit) = authorized_policy(provider_id(), true);
    let result = runtime().block_on(gateway.complete(
        &provider_id(),
        prompt(provider_id(), permit, "hello"),
        &policy,
        NOW_MS,
    ));
    assert_eq!(result.unwrap_err(), ModelGatewayError::TimedOut);
    server.join();

    let (target, trap) = trap_listener();
    let mut redirect = response(307, Vec::new());
    redirect.reason = "Temporary Redirect";
    redirect
        .headers
        .push(format!("Location: http://{target}/collect"));
    let server = MockServer::start(redirect);
    let gateway = build_model_gateway(provider_config(server.endpoint.clone(), true));
    let (policy, permit) = authorized_policy(provider_id(), true);
    let result = runtime().block_on(gateway.complete(
        &provider_id(),
        prompt(provider_id(), permit, "hello"),
        &policy,
        NOW_MS,
    ));
    assert_eq!(result.unwrap_err(), ModelGatewayError::ProviderUnavailable);
    server.join();
    assert!(!trap.join().unwrap());
}

#[test]
fn local_provider_can_run_without_a_key_but_remote_provider_cannot() {
    let server = MockServer::start(success_response());
    let gateway = gateway_with_credentials(
        provider_config(server.endpoint.clone(), true),
        Arc::new(NoCredentials),
    );
    let (policy, permit) = authorized_policy(provider_id(), true);
    let result = runtime().block_on(gateway.complete(
        &provider_id(),
        prompt(provider_id(), permit, "hello"),
        &policy,
        NOW_MS,
    ));
    assert!(
        result.is_ok(),
        "gateway request failed: {:?}",
        result.as_ref().err()
    );
    let request = server.join();
    assert!(get_header(&request, "authorization").is_none());

    let mut config = provider_config("https://model.example/v1/chat/completions".into(), true);
    config.mode = ProviderMode::Remote;
    let gateway = gateway_with_credentials(config, Arc::new(NoCredentials));
    let (policy, permit) = authorized_policy(provider_id(), false);
    let result = runtime().block_on(gateway.complete(
        &provider_id(),
        prompt(provider_id(), permit, "hello"),
        &policy,
        NOW_MS,
    ));
    assert_eq!(
        result.unwrap_err(),
        ModelGatewayError::CredentialsUnavailable
    );
}
