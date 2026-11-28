#![cfg(windows)]

use std::{
    collections::HashSet,
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    process::Command,
    time::{Duration, Instant},
};

use asl_agent::gateway::{
    AuthorizedPrompt, ModelGateway, ModelGatewayError, ProviderConfigV1, ProviderMode,
    ProviderRegistryV1,
};
use asl_app::{
    model_endpoint_access::{ModelEndpointAccess, configured_model_gateway},
    paths::AppPaths,
};
use asl_policy::{
    AccessOperation, AccessRequest, Audience, GrantPolicy, ModelPolicy, Permit, PolicyEngine,
    PolicyService, PolicySnapshot, Principal, ProviderPolicy, ResourceOrigin, ResourcePolicy,
};
use asl_types::{
    ids::{Hash32, Id128},
    task::{GrantId, ProviderId, ResourceKey},
};

#[test]
fn cli_approval_controls_an_existing_gateway_without_restarting() {
    let home = std::env::temp_dir().join(format!(
        "asl provider settings {}",
        libp2p_identity::PeerId::random()
    ));
    let paths = AppPaths::open(&home).unwrap();
    drop(asl_store::open_store(&paths.state().join("asl.sqlite3")).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut config = ProviderConfigV1 {
        id: ProviderId("sample".into()),
        endpoint: format!("http://{}/chat", listener.local_addr().unwrap()),
        model: "sample-model".into(),
        mode: ProviderMode::Local,
        enabled_by_user: true,
        request_timeout_ms: 2_000,
    };
    let save = |config: &ProviderConfigV1| {
        std::fs::write(
            paths.model_provider_configuration(),
            serde_json::to_vec(&ProviderRegistryV1 {
                version: 1,
                providers: vec![config.clone()],
            })
            .unwrap(),
        )
        .unwrap();
    };
    save(&config);
    let cli = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_asl-core"))
            .arg("--providers")
            .args(args)
            .env("ASL_HOME", &home)
            .output()
            .unwrap()
    };
    let (policy, permit) = authorized_policy(&config.id);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let gateway = configured_model_gateway(&paths).unwrap();
    let id = config.id.clone();
    let invoke = |now| {
        let prompt = AuthorizedPrompt::new(
            id.clone(),
            "authorized test content".into(),
            vec![permit.clone()],
        )
        .unwrap();
        runtime.block_on(gateway.complete(&id, prompt, &policy, now))
    };
    let status = || ModelEndpointAccess::new(&paths).list().unwrap().remove(0);
    let no_connection = || {
        assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
    };

    assert!(!status().authorized);
    assert_eq!(
        invoke(1).unwrap_err(),
        ModelGatewayError::AuthorizationDenied
    );
    no_connection();
    let list = cli(&["list"]);
    assert!(list.status.success());
    let value: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    let reviewed = value[0]["fingerprint"].as_str().unwrap();
    assert!(!cli(&["allow", &id.0, "stale"]).status.success());
    assert!(cli(&["allow", &id.0, reviewed]).status.success());
    assert!(status().authorized);
    assert_eq!(
        ModelEndpointAccess::new(&paths).first_authorized().unwrap(),
        Some(id.clone())
    );

    assert!(AuthorizedPrompt::new(id.clone(), "unapproved".into(), vec![]).is_err());
    assert_eq!(
        invoke(9_000).unwrap_err(),
        ModelGatewayError::AuthorizationDenied
    );
    no_connection();

    std::thread::scope(|scope| {
        let reply = scope.spawn(|| {
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("fixture did not accept request: {error}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut reader = BufReader::new(&mut stream);
            let mut content_len = None;
            loop {
                let mut line = String::new();
                assert_ne!(reader.read_line(&mut line).unwrap(), 0);
                if line == "\r\n" {
                    break;
                }
                if let Some((name, value)) = line.split_once(':')
                    && name.eq_ignore_ascii_case("content-length")
                {
                    content_len = Some(value.trim().parse::<usize>().unwrap());
                }
            }
            let mut body = vec![0; content_len.unwrap()];
            reader.read_exact(&mut body).unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["model"], "sample-model");
            assert_eq!(body["messages"][1]["content"], "authorized test content");
            let response = r#"{"choices":[{"message":{"role":"assistant","content":"accepted"}}]}"#;
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}", response.len()).unwrap();
        });
        assert_eq!(invoke(1).unwrap().as_str(), "accepted");
        reply.join().unwrap();
    });

    let original = config.clone();
    config.model = "different-model".into();
    save(&config);
    assert!(!status().authorized);
    assert!(!cli(&["allow", &id.0, reviewed]).status.success());
    assert_eq!(
        invoke(1).unwrap_err(),
        ModelGatewayError::AuthorizationDenied
    );
    no_connection();

    config = original.clone();
    config.endpoint.push_str("/different");
    save(&config);
    assert_eq!(
        invoke(1).unwrap_err(),
        ModelGatewayError::AuthorizationDenied
    );
    no_connection();
    config.mode = ProviderMode::Remote;
    config.endpoint = "https://provider.example/chat".into();
    save(&config);
    assert!(!status().authorized);
    assert_eq!(
        invoke(1).unwrap_err(),
        ModelGatewayError::AuthorizationDenied
    );

    assert!(cli(&["revoke", &id.0]).status.success());
    save(&original);
    assert!(!status().authorized);
    assert_eq!(
        ModelEndpointAccess::new(&paths).first_authorized().unwrap(),
        None
    );
    assert_eq!(
        invoke(1).unwrap_err(),
        ModelGatewayError::AuthorizationDenied
    );
    no_connection();
    std::fs::remove_dir_all(home).unwrap();
}

fn authorized_policy(id: &ProviderId) -> (PolicyEngine, Permit) {
    let grant_id = GrantId(Id128([1; 16]));
    let resource_key = ResourceKey(Id128([2; 16]));
    let mut policy = PolicySnapshot::default();
    policy.grants.insert(
        grant_id.clone(),
        GrantPolicy {
            epoch: 1,
            active: true,
            audience: Audience::Public,
            model_policy: ModelPolicy::LocalOnly(HashSet::from([id.clone()])),
            extensions: HashSet::from([".md".into()]),
            max_snapshot_bytes: 100,
            allowed_operations: HashSet::from([AccessOperation::ModelInput]),
            allow_derived_disclosure: false,
        },
    );
    policy.resources.insert(
        resource_key.clone(),
        ResourcePolicy {
            content_id: Hash32([3; 32]),
            grant_id: grant_id.clone(),
            grant_epoch: 1,
            active: true,
            snapshot_ready: true,
            file_size: 5,
            extension: ".md".into(),
            retention_until_ms: None,
            origin: ResourceOrigin::Local,
        },
    );
    policy.providers.insert(
        id.clone(),
        ProviderPolicy {
            authorized: true,
            local: true,
        },
    );
    let policy = PolicyEngine::new(policy, 5_000).unwrap();
    let permit = policy
        .authorize(
            &AccessRequest {
                grant_id,
                resource_key,
                principal: Principal::ModelProvider(id.clone()),
                operation: AccessOperation::ModelInput,
            },
            1,
        )
        .unwrap();
    (policy, permit)
}
