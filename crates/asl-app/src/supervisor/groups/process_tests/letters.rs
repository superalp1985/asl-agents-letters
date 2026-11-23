use super::*;
use crate::{
    direct_inbound,
    downloads::download_channel,
    mcp::{HostGrant, McpWorker, test_host::Host},
    outgoing_query_channel,
    supervisor::DownloadDriverEvent,
};
use alloy_primitives::hex;

pub(super) fn run(
    core: Supervisor,
    tick: impl Fn(&mut Supervisor) -> Result<(), AslError>,
) -> Result<(), AslError> {
    let (port, queries) = outgoing_query_channel();
    let (downloads, runtime) = download_channel();
    let mut bridge = crate::downloads::DownloadBridge::spawn(core.home.clone(), runtime)?;
    let _worker = McpWorker::spawn_with_mail(
        core.home.clone(),
        HostGrant::from_environment()?.unwrap(),
        port,
        downloads,
        core.mailbox.port.clone(),
        None,
    )?;
    core.run_with_transfer_handler(queries, |core, transfer, event| {
        match event {
            DownloadDriverEvent::Network(event) => bridge.forward(event),
            DownloadDriverEvent::Tick => {
                tick(core)?;
                bridge.poll(unix_time_ms()?, |request| {
                    core.send_download_request(transfer, request)
                });
            }
        }
        Ok(())
    })
}

pub(super) fn verify(registry: &Path, nodes: &[(PeerId, PathBuf, RegistryClaim); 3]) {
    let [
        (a_peer, a_home, (a_id, _)),
        (b_peer, b_home, (b_id, _)),
        (_, _, (offline, _)),
    ] = nodes;
    let a_db = a_home.join("state/asl.sqlite3");
    let b_db = b_home.join("state/asl.sqlite3");
    let [a_key, b_key] = rand::random::<[[u8; 32]; 2]>();
    let (mut a, ready_a) = CoreProcess::start_with_grant(a_home, registry, false, Some(a_key));
    let (mut b, ready_b) = CoreProcess::start_with_grant(b_home, registry, false, Some(b_key));
    b.dial(&ready_a, a_peer);
    b.connection(&ready_a["peer"]);
    a.connection(&ready_b["peer"]);
    direct_inbound::configure(&a_db, "answer").unwrap();
    direct_inbound::configure(&b_db, "browse").unwrap();
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        tokio::time::timeout(WAIT * 2, async {
            let mut alice = Host::connect_to_core(a_home.clone(), a_key).await;
            let mut bob = Host::connect_to_core(b_home.clone(), b_key).await;
            let address = |agent: AgentId| format!("agent:{}", hex::encode(agent.0));
            let concept = json!(["concept", hex::encode(b_id.0), 9, 1, 903]);
            let question = json!(["meaning", concept]);
            for peer in [*b_id, *offline] {
                let result = alice.call("asl_send_expression", json!({"target":address(peer), "expression":question})).await;
                assert_eq!(result["error_code"], "policy_denied", "{result}");
            }
            for (db, contact, peer) in [(&a_db, *b_id, b_peer), (&b_db, *a_id, a_peer)] {
                let mut store = asl_store::open_store(db).unwrap();
                let code = asl_types::record::short_code(contact);
                let at = unix_time_ms().unwrap();
                assert!(store.record_contact_binding_candidate(contact, peer, code, at).unwrap());
                store.approve_contact_binding(contact, peer, code, at).unwrap();
                assert!(store.authorized_contacts().unwrap().is_empty());
                store.grant_contact_access(contact, peer, at as i64).unwrap();
            }
            let queued = alice.call("asl_send_expression", json!({"target":address(*b_id),"expression":question})).await;
            let id = &queued["message_id"];
            assert!(id.is_string(), "{queued}");
            let incoming = bob.notified("expression", "message_id", id).await;
            assert_eq!(incoming["expression"], question);
            assert_eq!(incoming["agent"], address(*a_id));
            assert_eq!(&incoming["root_task_id"], id);
            let definition = json!(["meaning_is",concept,1,["op","gt",["var",0],["int","8"]]]);
            let reply = json!({"target":incoming["agent"],"root":incoming["root_task_id"],"expression":definition});
            let denied = bob.call("asl_send_expression", reply.clone()).await;
            assert_eq!(denied["error_code"], "policy_denied", "{denied}");
            direct_inbound::configure(&b_db, "answer").unwrap();
            let sent = bob.call("asl_send_expression", reply).await;
            assert!(sent["message_id"].is_string(), "{sent}");
            assert_ne!(&sent["message_id"], id);
            let answer = alice.notified("expression", "message_id", &sent["message_id"]).await;
            assert_eq!(&answer["root_task_id"], id);
            assert_eq!(answer["agent"], address(*b_id));
            assert_eq!(answer["expression"], definition);
            verify_inbox_request(&mut alice, b_home, a_home, &a_db).await;
            bob.close().await;
            alice.close().await;
        }).await.expect("host-to-host expression exchange timed out");
    });
    b.close();
    a.close();
}

async fn verify_inbox_request(
    host: &mut Host,
    provider: &Path,
    receiver: &Path,
    receiver_db: &Path,
) {
    use asl_store::{dashboard::Dashboard, resources::SnapshotBroker};
    let library = provider.with_extension("library");
    fs::create_dir(&library).unwrap();
    fs::write(library.join("sample.rs"), b"const N: u8 = 8;\n").unwrap();
    let mut broker = SnapshotBroker::open(provider).unwrap();
    let grant = broker
        .authorize_directory(&library, &["rs".into()], &asl_policy::Audience::Public, 256)
        .unwrap();
    broker
        .import_source(&grant, Path::new("sample.rs"))
        .unwrap();
    let rust = ConceptRef::RUST;
    let task = host.call("asl_query", json!({
        "query":{"intent":"locate_resource","result_shape":"resources"},
        "terms":[[rust.vocabulary_id, rust.concept_id]], "audience":"contacts_only", "deadline_ms":10000
    })).await;
    assert!(task["task_id"].is_string(), "{task}");
    let offer = host
        .notified("task_file_offer", "task_id", &task["task_id"])
        .await;
    assert_eq!(offer["inbox_permission_required"], true);
    assert!(
        Dashboard::load(receiver_db)
            .unwrap()
            .host_inbox_request
            .is_none()
    );
    let selection = json!({"task_id":task["task_id"],"offer_id":offer["offer_id"]});
    let result = host.call("asl_fetch", selection.clone()).await;
    assert_eq!(result, json!({"status":"inbox_permission_required"}));
    let view = Dashboard::load(receiver_db).unwrap();
    let request = view.host_inbox_request.unwrap();
    assert!(view.access.is_empty() && view.download_approvals.is_empty());
    let state = host
        .call("asl_task_status", json!({"task_id": task["task_id"]}))
        .await;
    assert_eq!(state["downloads"], json!([]), "{state}");

    let directory = receiver.with_extension("inbox");
    fs::create_dir(&directory).unwrap();
    let grant = SnapshotBroker::open(receiver)
        .unwrap()
        .authorize_inbox_directory(&directory, 4096)
        .unwrap();
    let mut store = asl_store::open_store(receiver_db).unwrap();
    store
        .set_download_mode(asl_store::transfers::DownloadMode::Ask)
        .unwrap();
    store
        .decide_host_inbox(request, Some(grant), unix_time_ms().unwrap())
        .unwrap();
    tokio::time::timeout(
        Duration::from_secs(5),
        host.notified("inbox_permission", "status", &json!("granted")),
    )
    .await
    .expect("Core did not push the local directory decision");
    let deadline = Instant::now() + Duration::from_secs(7);
    let pending = loop {
        let result = host.call("asl_fetch", selection.clone()).await;
        if result["status"] == "awaiting_approval" {
            break result;
        }
        assert_eq!(result["error_code"], "timeout", "{result}");
        if Instant::now() >= deadline {
            let state = host
                .call("asl_task_status", json!({"task_id":task["task_id"]}))
                .await;
            let peer = Dashboard::load(&provider.join("state/asl.sqlite3")).unwrap();
            panic!(
                "after directory binding: {state}, sender upload mode {}, pending uploads {}",
                peer.upload_mode,
                peer.upload_approvals.len()
            );
        }
    };
    let transfer = pending["transfer_id"].as_str().unwrap();
    host.wait_transfer_notice("file_approval_required", transfer)
        .await;
    assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);
    let choices = store.download_consents().unwrap();
    assert_eq!(choices.len(), 1);
    store.decide_download(choices[0].approval_id, true).unwrap();
    host.wait_transfer_notice("file_received", transfer).await;
    assert_eq!(
        fs::read(choices[0].destination_path.clone()).unwrap(),
        b"const N: u8 = 8;\n"
    );
}
