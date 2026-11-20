use std::{cell::Cell, collections::HashMap, fs, path::Path};

use alloy_primitives::hex;
use asl_net::{
    codec::{BulkOperation, BulkStatus},
    transport::{LocalTransport, TransportEvent, TransportKind},
};
use asl_policy::Audience;
use asl_store::{
    Store,
    resources::SnapshotBroker,
    search::{LocalIndexText, direct::DirectRequester},
    transfers::{DownloadBroker, DownloadMode},
};
use asl_types::{
    manifest::{CHUNK_SIZE, Manifest, content_id, decode_manifest, encode_manifest},
    protocol::{ConceptRef, WireFrame},
};
use rusqlite::params;
use serde_json::json;
use tokio::time::{interval, sleep, timeout};

use super::*;
use crate::{
    FetchManifestDetails, MatchedBulkResponse, VerifiedFetchManifest,
    direct_inbound::{self, DirectInbound},
    direct_outbound::{DirectOutbound, outgoing_query_channel},
    identity::{AgentIdentity, DeviceIdentity},
    libraries::LocalLibraries,
    mcp::test_host::Host,
    transfer::{TransferService, tests::Fixture},
};

#[tokio::test]
async fn mcp_offer_and_approved_tcp_chunks_publish_to_authorized_inbox() {
    let fixture = Fixture::new();
    let home = fixture.path().join("receiver");
    let inbox = fixture.path().join("inbox");
    let library = fixture.path().join("library");
    fs::create_dir(&inbox).unwrap();
    fs::create_dir(&library).unwrap();
    AppPaths::open(&home).unwrap();
    let inbox_grant = SnapshotBroker::open(&home)
        .unwrap()
        .authorize_inbox_directory(&inbox, 8 << 20)
        .unwrap();
    let chunk_size = CHUNK_SIZE as usize;
    let mut bytes = vec![b'a'; chunk_size];
    bytes.extend_from_slice(b"\nTCP download tail\n");
    let size = bytes.len() as u64;
    let expected = Manifest {
        file_size: size,
        file_hash: *blake3::hash(&bytes).as_bytes(),
        chunk_hashes: bytes
            .chunks(chunk_size)
            .map(|b| *blake3::hash(b).as_bytes())
            .collect(),
    };
    let content = Hash32(content_id(&encode_manifest(&expected).unwrap()));
    fs::write(library.join("source.md"), &bytes).unwrap();
    let paths = AppPaths::open(&fixture.path().join("provider")).unwrap();
    let mut libraries = LocalLibraries::open(&paths).unwrap();
    let grant = libraries
        .authorize_directory(&library, &["md".into()], &Audience::Public, size)
        .unwrap();
    let resource = libraries
        .import_source(&grant, Path::new("source.md"))
        .unwrap();
    let provider_db = paths.state().join("asl.sqlite3");
    direct_inbound::configure(&provider_db, "answer").unwrap();
    asl_store::open_store(&provider_db)
        .unwrap()
        .index_local_text(
            &resource,
            content,
            LocalIndexText {
                title: "Loopback",
                summary: "",
                body: "Rust",
                concepts: &[ConceptRef::RUST],
            },
        )
        .unwrap();
    let mut inbound = DirectInbound::open(&provider_db).unwrap();
    let mut provider = TransferService::open(&provider_db).unwrap();

    let receiver_device = DeviceIdentity::generate().unwrap();
    let provider_device = DeviceIdentity::generate().unwrap();
    let receiver_peer = receiver_device.peer_id();
    let provider_peer = provider_device.peer_id();
    let provider_key = provider_device.into_keypair();
    let device_key = provider_key.public().try_into_ed25519().unwrap().to_bytes();
    let mut listener = LocalTransport::new(provider_key).unwrap();
    let mut dialer = LocalTransport::new(receiver_device.into_keypair()).unwrap();
    listener
        .listen(TransportKind::Tcp, "127.0.0.1:0".parse().unwrap())
        .unwrap();
    let handshake = Duration::from_secs(5);
    let TransportEvent::Listening(TransportKind::Tcp, endpoint) =
        timeout(handshake, listener.next_event())
            .await
            .unwrap()
            .unwrap()
    else {
        panic!("expected TCP listener");
    };
    dialer
        .dial(TransportKind::Tcp, endpoint, &provider_peer)
        .unwrap();
    let (left, right) = timeout(handshake, async {
        tokio::join!(dialer.next_event(), listener.next_event())
    })
    .await
    .unwrap();
    let (
        TransportEvent::Connected { connection: client },
        TransportEvent::Connected { connection: server },
    ) = (left.unwrap(), right.unwrap())
    else {
        panic!("expected two authenticated TCP connections");
    };
    assert_eq!(client.peer_id(), &provider_peer);
    assert_eq!(server.peer_id(), &receiver_peer);

    // Synthetic Core admission: bind fixture registry state to the authenticated
    // peers. The provider's grant, lease and snapshot reads are production code.
    let now = unix_time_ms().unwrap();
    let requester = admit_fixture(
        &provider_db,
        &AgentIdentity::generate().unwrap(),
        receiver_peer,
        now,
    );
    let receiver_db = home.join("state/asl.sqlite3");
    let root = AgentIdentity::generate().unwrap();
    let admitted = admit_fixture(&receiver_db, &root, provider_peer, now);
    let certificate = root
        .issue_device_certificate(
            admitted.peer.clone(),
            1,
            now,
            admitted.session_expires_at_ms,
        )
        .unwrap();
    asl_store::open_store(&receiver_db)
        .unwrap()
        .register_transfer_peer(&admitted, 1, &certificate, device_key, now)
        .unwrap();
    let source = DownloadSource {
        agent_id: admitted.agent,
        peer_id: admitted.peer,
    };
    rusqlite::Connection::open(&receiver_db)
        .unwrap()
        .execute(
            "INSERT INTO authorized_contacts(agent_id,authorized_at_ms,authorization_revision)
             VALUES (?1,1,1)",
            [bs58::encode(source.agent_id.0).into_string()],
        )
        .unwrap();
    let mut decisions = asl_store::open_store(&receiver_db).unwrap();
    decisions.set_download_mode(DownloadMode::Ask).unwrap();
    let connection_id = [1; 16]; // Core's handle for `client` in this fixture.
    let (port, runtime) = download_channel();
    let mut bridge = DownloadBridge::spawn(home.clone(), runtime).unwrap();
    let (queries, query_runtime) = outgoing_query_channel();
    let mut outbound = DirectOutbound::open(&receiver_db, query_runtime).unwrap();
    let mut host = timeout(
        handshake,
        Host::connect(home.clone(), inbox_grant, queries, port),
    )
    .await
    .unwrap();
    let filename = format!("asl-{}.bin", hex::encode(content.0));
    let destination = inbox.join(&filename);
    let approved = Cell::new(false);

    let mut tick = interval(Duration::from_millis(5));
    let mut query = None;
    let mut fetch = None;
    let mut granted = None;
    let mut bulk = HashMap::new();
    let drive_network = async {
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    let now = unix_time_ms().unwrap();
                    outbound.poll(
                        &[(source.agent_id, connection_id, source.peer_id.clone())],
                        &[],
                        now,
                        |connection, request_id, frame| {
                            assert_eq!(connection, connection_id);
                            let token = dialer.send_control_request(&client, frame)?;
                            assert!(query.replace((token, request_id)).is_none());
                            Ok(())
                        },
                        |_, _| panic!("contacts-only query must not use the DHT"),
                        |_, _, _, _| panic!("the admitted contact is already connected"),
                    ).unwrap();
                    bridge.poll(now, |request| {
                        match request {
                            WorkerRequest::Fetch { source: selected, request } => {
                                assert_eq!(selected, source);
                                let token = dialer.send_control_request(&client, WireFrame::FetchRequest(request.clone()))?;
                                assert!(fetch.replace((token, request)).is_none());
                            }
                            WorkerRequest::Bulk { connection_id: selected, source: device, request } => {
                                assert!(approved.get(), "chunk requested before local approval");
                                assert_eq!(selected, connection_id);
                                assert_eq!(device, source);
                                assert_eq!(request.operation, BulkOperation::Chunk);
                                let token = dialer.send_bulk_request(&client, request.clone())?;
                                assert!(bulk.insert(request.request_id, (token, request)).is_none());
                            }
                        }
                        Ok(Some(connection_id))
                    });
                }
                event = listener.next_event() => {
                    let now = unix_time_ms().unwrap();
                    match event.unwrap() {
                        TransportEvent::ControlRequest { connection, request: frame @ WireFrame::Query(_), response } => {
                            assert_eq!(connection, server);
                            let prepared = inbound.prepare(requester.clone(), frame, now).unwrap().unwrap();
                            inbound.enqueue(prepared, |frame, _| {
                                assert!(matches!(frame, WireFrame::Offer(_)));
                                Ok(listener.send_control_response(&server, &response, frame)?)
                            }).unwrap();
                        }
                        TransportEvent::ControlRequest { connection, request: WireFrame::FetchRequest(request), response } => {
                            assert_eq!(connection, server);
                            assert_eq!(request.content_id, content);
                            let prepared = provider.prepare_fetch(requester.clone(), &request, now).unwrap();
                            provider.finish_fetch(prepared, now, |grant, _| {
                                Ok(listener.send_control_response(&server, &response, grant)?)
                            }).unwrap();
                        }
                        TransportEvent::BulkRequest { connection, request, response } => {
                            assert_eq!(connection, server);
                            let prepared = provider.prepare_bulk(&libraries, requester.clone(), request, now);
                            provider.finish_bulk(prepared, now, |data| {
                                Ok(listener.send_bulk_response(&server, &response, data)?)
                            }).unwrap();
                        }
                        other => panic!("unexpected provider event: {other:?}"),
                    }
                }
                event = dialer.next_event() => match event.unwrap() {
                    TransportEvent::ControlResponse { connection, request, response: response @ WireFrame::Offer(_) } => {
                        assert_eq!(connection, client);
                        let (token, request_id) = query.take().unwrap();
                        assert_eq!(request, token);
                        outbound.handle_event(&AdmittedNetworkEvent::ControlResponse {
                            connection_id, agent_id: source.agent_id, request_id, response,
                        }, unix_time_ms().unwrap()).unwrap();
                    }
                    TransportEvent::ControlResponse { connection, request, response: WireFrame::FetchGrant(grant) } => {
                        assert_eq!(connection, client);
                        let (token, original) = fetch.take().unwrap();
                        assert_eq!(request, token);
                        assert_ne!(grant.message_id, original.message_id);
                        assert_eq!(grant.content_id, content);
                        assert_eq!(grant.file_size, size);
                        let manifest = BulkRequest {
                            operation: BulkOperation::Manifest, request_id: Id128([2; 16]),
                            content_id: grant.content_id, lease_id: grant.lease_id, chunk_index: 0,
                        };
                        let token = dialer.send_bulk_request(&client, manifest.clone()).unwrap();
                        assert!(bulk.insert(manifest.request_id, (token, manifest)).is_none());
                        assert!(granted.replace((original, grant)).is_none());
                    }
                    TransportEvent::BulkResponse { connection, request, response } => {
                        assert_eq!(connection, client);
                        let (token, original) = bulk.remove(&response.request_id).unwrap();
                        assert_eq!(request, token);
                        assert_eq!(response.status, BulkStatus::Success);
                        let (fetch, grant) = granted.as_ref().unwrap();
                        assert_eq!(original.content_id, grant.content_id);
                        assert_eq!(original.lease_id, grant.lease_id);
                        let event = if original.operation == BulkOperation::Manifest {
                            let manifest = decode_manifest(&response.payload, grant.content_id.0).unwrap();
                            assert_eq!(manifest, expected);
                            AdmittedNetworkEvent::FetchManifestReceived(VerifiedFetchManifest(
                                FetchManifestDetails {
                                    fetch_generation: 1,
                                    fetch_request_id: fetch.message_id,
                                    root_task_id: fetch.root_task_id,
                                    connection_id,
                                    agent_id: source.agent_id,
                                    peer_id: source.peer_id.clone(),
                                    content_id: grant.content_id,
                                    lease_id: grant.lease_id,
                                    expires_at_ms: grant.expires_at_ms,
                                    manifest,
                                },
                            ))
                        } else {
                            let offset = original.chunk_index as usize * chunk_size;
                            let end = bytes.len().min(offset + chunk_size);
                            assert_eq!(response.payload.as_slice(), &bytes[offset..end]);
                            AdmittedNetworkEvent::BulkTransferResponse(MatchedBulkResponse {
                                connection_id, agent_id: source.agent_id, peer_id: source.peer_id.clone(),
                                request: original, response,
                            })
                        };
                        bridge.forward(&event);
                    }
                    other => panic!("unexpected receiver event: {other:?}"),
                }
            }
        }
    };
    let transfer_id = timeout(Duration::from_secs(20), async {
        tokio::select! {
            biased;
            id = approve_and_download(&mut host, &mut decisions, &destination, content, size, &approved) => id,
            () = drive_network => unreachable!(),
        }
    })
    .await
    .expect("MCP/TCP download timed out");
    timeout(handshake, host.close()).await.unwrap();
    drop(bridge);
    let info = DownloadBroker::open(&home)
        .unwrap()
        .info(&transfer_id)
        .unwrap();
    assert_eq!(info.content_id, content);
    assert_eq!(
        (info.file_size, info.durable_bytes, info.chunk_count),
        (size, size, 2)
    );
    assert_eq!(info.state, "complete");
    assert_eq!(
        info.destination_path.canonicalize().unwrap(),
        destination.canonicalize().unwrap()
    );
    assert_eq!(fs::read(destination).unwrap(), bytes);
    assert!(!info.part_path.exists());
}

async fn approve_and_download(
    host: &mut Host,
    decisions: &mut Store,
    destination: &Path,
    content: Hash32,
    size: u64,
    approved: &Cell<bool>,
) -> TransferId {
    let topic = ConceptRef::RUST;
    let query = host
        .call(
            "asl_query",
            json!({
                "query": {"intent":"locate_resource","result_shape":"resources"},
                "terms": [[topic.vocabulary_id, topic.concept_id]],
                "audience": "contacts_only",
                "deadline_ms": 10000
            }),
        )
        .await;
    let task = query["task_id"].as_str().expect("query ID");
    let result = loop {
        let result = host.call("asl_result", json!({"task_id":task})).await;
        if result["status"] == "complete" {
            break result;
        }
        assert_eq!(result["error_code"], "busy", "{result}");
        sleep(Duration::from_millis(20)).await;
    };
    let offers = result["offers"].as_array().unwrap();
    assert_eq!(offers.len(), 1);
    let offer = &offers[0];
    assert_eq!(offer["content_id"], hex::encode(content.0));
    assert_eq!(offer["file_size"], size);
    let selection = json!({"task_id": task, "offer_id": offer["offer_id"]});
    let pending = loop {
        let pending = host.call("asl_fetch", selection.clone()).await;
        if pending["status"] == "awaiting_approval" {
            break pending;
        }
        assert_eq!(pending["error_code"], "timeout", "{pending}");
    };
    let id = pending["transfer_id"]
        .as_str()
        .expect("reserved transfer ID");
    assert_eq!(host.call("asl_fetch", selection).await, pending);
    let prompts = decisions.download_consents().unwrap();
    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0].content_id, content);
    assert_eq!(prompts[0].file_size, size);
    assert_eq!(prompts[0].destination_path, destination);
    assert!(!prompts[0].approved);
    assert_eq!(
        fs::read_dir(destination.parent().unwrap()).unwrap().count(),
        0
    );
    decisions
        .decide_download(prompts[0].approval_id, true)
        .unwrap();
    approved.set(true);
    loop {
        let status = host.call("asl_result", json!({"task_id":task})).await;
        let download = &status["downloads"][0];
        assert_eq!(download["transfer_id"], id, "{status}");
        match download["status"].as_str() {
            Some("completed") => break,
            Some("awaiting_approval" | "started") => sleep(Duration::from_millis(25)).await,
            _ => panic!("unexpected transfer status: {status}"),
        }
    }
    TransferId(Id128(hex::decode(id).unwrap().try_into().unwrap()))
}

fn admit_fixture(db: &Path, root: &AgentIdentity, peer: PeerId, now: u64) -> DirectRequester {
    let requester = DirectRequester {
        agent: root.agent_id(),
        peer,
        session_expires_at_ms: now + 60_000,
        registry_sequence: 1,
        directory_commitment: [3; 32],
        controller: root.controller_address(),
    };
    let db = rusqlite::Connection::open(db).unwrap();
    let agent = bs58::encode(requester.agent.0).into_string();
    db.execute_batch(
        "INSERT INTO chain_state_cache VALUES
        (1,zeroblob(20),zeroblob(32),0,zeroblob(32),zeroblob(32),zeroblob(32),x'',0);",
    )
    .unwrap();
    db.execute(
        "INSERT INTO agents(agent_id,identity_state) VALUES (?1,'verified')",
        [&agent],
    )
    .unwrap();
    db.execute(
        "INSERT INTO identity_registry_states
        (agent_id,chain_id,controller_address,state_commitment,sequence,status,
         finalized_height,storage_proof_hash,verified_at_ms)
        VALUES (?1,1,?2,?3,1,'active',0,zeroblob(32),0)",
        params![
            agent,
            requester.controller.as_slice(),
            requester.directory_commitment.as_slice()
        ],
    )
    .unwrap();
    requester
}
