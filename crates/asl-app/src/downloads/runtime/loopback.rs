use std::{
    cell::Cell,
    collections::{HashMap, HashSet},
    fs,
    path::Path,
};

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

mod provider;
use provider::{Provider, ReceiverIdentity};

#[tokio::test]
async fn mcp_offer_and_approved_tcp_chunks_publish_to_authorized_inbox() {
    verify_download(Scenario::Single).await;
}

#[tokio::test]
async fn mcp_selects_two_offers_and_both_tcp_sources_supply_chunks() {
    verify_download(Scenario::TwoSources).await;
}

#[tokio::test]
async fn mcp_surviving_tcp_source_replaces_chunk_lost_to_disconnect() {
    verify_download(Scenario::LoseSource).await;
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scenario {
    Single,
    TwoSources,
    LoseSource,
}

async fn verify_download(scenario: Scenario) {
    let provider_count = if scenario == Scenario::Single { 1 } else { 2 };
    let fixture = Fixture::new();
    let home = fixture.path().join("receiver");
    let inbox = fixture.path().join("inbox");
    fs::create_dir(&inbox).unwrap();
    AppPaths::open(&home).unwrap();
    let inbox_grant = SnapshotBroker::open(&home)
        .unwrap()
        .authorize_inbox_directory(&inbox, 8 << 20)
        .unwrap();
    let chunk_size = CHUNK_SIZE as usize;
    let mut bytes = vec![b'a'; chunk_size];
    if provider_count == 2 {
        bytes.extend(std::iter::repeat_n(b'b', chunk_size));
        bytes.extend(std::iter::repeat_n(b'c', chunk_size));
    }
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
    let receiver_device = DeviceIdentity::generate().unwrap();
    let receiver_peer = receiver_device.peer_id();
    let receiver_key = receiver_device.into_keypair();
    let receiver = ReceiverIdentity {
        root: AgentIdentity::generate().unwrap(),
        peer: receiver_peer,
        device_key: receiver_key.public().try_into_ed25519().unwrap().to_bytes(),
    };
    let mut dialer = LocalTransport::new(receiver_key).unwrap();
    let handshake = Duration::from_secs(5);
    let receiver_db = home.join("state/asl.sqlite3");
    let mut providers = Vec::new();
    let mut clients = HashMap::new();
    let mut peers = HashMap::new();
    let mut contacts = Vec::new();
    for index in 0..provider_count {
        let (provider, client, source) = Provider::connect(
            &fixture.path().join(format!("provider-{index}")),
            &receiver_db,
            &receiver,
            &mut dialer,
            &bytes,
            content,
        )
        .await;
        let id = rand::random::<[u8; 16]>();
        contacts.push((source.agent_id, id, source.peer_id.clone()));
        peers.insert(source.peer_id.clone(), (id, source));
        clients.insert(id, client);
        providers.push(provider);
    }
    let mut decisions = asl_store::open_store(&receiver_db).unwrap();
    decisions.set_download_mode(DownloadMode::Ask).unwrap();
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
    let mut query = HashMap::new();
    let mut fetch = HashMap::new();
    let mut granted = HashMap::new();
    let mut bulk = HashMap::new();
    let mut delivered = HashSet::new();
    let interrupted = Cell::new(None);
    let mut disconnected = None;
    let drive_network = async {
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    let now = unix_time_ms().unwrap();
                    outbound.poll(
                        &contacts,
                        &[],
                        now,
                        |connection, request_id, frame| {
                            let token = dialer.send_control_request(&clients[&connection], frame)?;
                            assert!(query.insert(connection, (token, request_id)).is_none());
                            Ok(())
                        },
                        |_, _| panic!("contacts-only query must not use the DHT"),
                        |_, _, _, _| panic!("the admitted contact is already connected"),
                    ).unwrap();
                    bridge.poll(now, |request| {
                        let device = match &request {
                            WorkerRequest::Fetch {source, ..} | WorkerRequest::Bulk {source, ..} => source,
                        };
                        let (connection_id, source) = &peers[&device.peer_id];
                        assert_eq!(device, source);
                        if disconnected.as_ref() == Some(&device.peer_id) {
                            // Match Core before the asynchronous worker consumes the disconnect.
                            return Err(match request {
                                WorkerRequest::Fetch { .. } => AslError::NotFound,
                                WorkerRequest::Bulk { .. } => AslError::InvalidIdentity,
                            });
                        }
                        let client = &clients[connection_id];
                        match request {
                            WorkerRequest::Fetch { group, request, .. } => {
                                assert!(group.is_none());
                                let token = dialer.send_control_request(client, WireFrame::FetchRequest(request.clone()))?;
                                assert!(fetch.insert(*connection_id, (token, request)).is_none());
                            }
                            WorkerRequest::Bulk { connection_id: selected, request, .. } => {
                                assert!(approved.get(), "chunk requested before local approval");
                                assert_eq!(selected, *connection_id);
                                assert_eq!(request.operation, BulkOperation::Chunk);
                                let token = dialer.send_bulk_request(client, request.clone())?;
                                assert!(bulk.insert(request.request_id, (token, request)).is_none());
                            }
                        }
                        Ok(Some(*connection_id))
                    });
                }
                event = dialer.next_event() => match event.unwrap() {
                    TransportEvent::ControlResponse { connection, request, response: response @ WireFrame::Offer(_) } => {
                        let (connection_id, source) = &peers[connection.peer_id()];
                        assert_eq!(connection, clients[connection_id]);
                        let (token, request_id) = query.remove(connection_id).unwrap();
                        assert_eq!(request, token);
                        outbound.handle_event(&AdmittedNetworkEvent::ControlResponse {
                            connection_id: *connection_id, agent_id: source.agent_id, request_id, response,
                        }, unix_time_ms().unwrap()).unwrap();
                    }
                    TransportEvent::ControlResponse { connection, request, response: WireFrame::FetchGrant(grant) } => {
                        let (connection_id, _) = &peers[connection.peer_id()];
                        assert_eq!(connection, clients[connection_id]);
                        let (token, original) = fetch.remove(connection_id).unwrap();
                        assert_eq!(request, token);
                        assert_ne!(grant.message_id, original.message_id);
                        assert_eq!(grant.content_id, content);
                        assert_eq!(grant.file_size, size);
                        let manifest = BulkRequest {
                            operation: BulkOperation::Manifest, request_id: Id128(rand::random()),
                            content_id: grant.content_id, lease_id: grant.lease_id, chunk_index: 0,
                        };
                        let token = dialer.send_bulk_request(&connection, manifest.clone()).unwrap();
                        assert!(bulk.insert(manifest.request_id, (token, manifest)).is_none());
                        assert!(granted.insert(*connection_id, (original, grant)).is_none());
                    }
                    TransportEvent::BulkResponse { connection, request, response } => {
                        let (connection_id, source) = &peers[connection.peer_id()];
                        assert_eq!(connection, clients[connection_id]);
                        let (token, original) = bulk.remove(&response.request_id).unwrap();
                        assert_eq!(request, token);
                        assert_eq!(response.status, BulkStatus::Success);
                        let (fetch, grant) = &granted[connection_id];
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
                                    connection_id: *connection_id,
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
                            delivered.insert(source.peer_id.clone());
                            AdmittedNetworkEvent::BulkTransferResponse(MatchedBulkResponse {
                                connection_id: *connection_id, agent_id: source.agent_id, peer_id: source.peer_id.clone(),
                                request: original, response,
                            })
                        };
                        bridge.forward(&event);
                    }
                    TransportEvent::Disconnected { connection_id, peer } if scenario == Scenario::LoseSource => {
                        let (id, source) = &peers[&peer];
                        assert_eq!(clients[id].connection_id(), connection_id);
                        assert!(interrupted.get().is_some());
                        assert!(disconnected.replace(peer.clone()).is_none());
                        bridge.forward(&AdmittedNetworkEvent::PeerDisconnected {
                            connection_id: *id, agent_id: Some(source.agent_id), peer_id: Some(peer),
                        });
                    }
                    TransportEvent::RequestFailed { connection_id, request } if scenario == Scenario::LoseSource => {
                        let (id, client) = clients.iter().find(|(_, c)| c.connection_id() == connection_id).unwrap();
                        let (_, source) = &peers[client.peer_id()];
                        let request_id = *bulk.iter().find(|(_, (token, _))| token == &request).unwrap().0;
                        bulk.remove(&request_id);
                        // The disconnect has already released every ticket for this connection.
                        if disconnected.as_ref() == Some(client.peer_id()) {
                            continue;
                        }
                        bridge.forward(&AdmittedNetworkEvent::RequestFailed {
                            connection_id: *id, agent_id: source.agent_id, peer_id: source.peer_id.clone(),
                            request_id: request_id.0, protocol: NetworkProtocol::Bulk,
                            code: crate::ipc::NetworkErrorCode::TimedOut,
                        });
                    }
                    other => panic!("unexpected receiver event: {other:?}"),
                }
            }
        }
    };
    let expected_peers: HashSet<_> = peers.keys().cloned().collect();
    let loss = (scenario == Scenario::LoseSource).then_some(&interrupted);
    let mut providers = providers.into_iter();
    let first = providers.next().unwrap();
    let drive_providers = async {
        tokio::join!(first.serve(loss), async {
            if let Some(second) = providers.next() {
                second.serve(loss).await;
            }
        });
    };
    let transfer_id = timeout(Duration::from_secs(20), async {
        tokio::select! {
            biased;
            id = approve_and_download(&mut host, &mut decisions, &destination, content, size, &approved, &expected_peers) => id,
            () = drive_network => unreachable!(),
            () = drive_providers => unreachable!(),
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
    if scenario == Scenario::LoseSource {
        let lost = disconnected.expect("expected a TCP disconnect");
        let survivor = expected_peers.iter().find(|peer| **peer != lost).unwrap();
        assert_eq!(delivered, HashSet::from([survivor.clone()]));
        let durable_source: String = rusqlite::Connection::open(&receiver_db).unwrap()
            .query_row(
                "SELECT source_peer FROM transfer_chunks WHERE transfer_id=?1 AND chunk_index=?2 AND state='durable'",
                params![hex::encode(transfer_id.0.as_bytes()), interrupted.get().unwrap()],
                |row| row.get(0),
            ).unwrap();
        assert_eq!(
            durable_source,
            bs58::encode(survivor.as_bytes()).into_string()
        );
    } else {
        assert_eq!(delivered, expected_peers);
    }
    assert_eq!(
        (info.file_size, info.durable_bytes, info.chunk_count),
        (size, size, expected.chunk_hashes.len() as u32)
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
    peers: &HashSet<PeerId>,
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
    assert_eq!(offers.len(), peers.len());
    let offer = &offers[0];
    assert_eq!(offer["content_id"], hex::encode(content.0));
    assert_eq!(offer["file_size"], size);
    let mut selection = json!({"task_id": task, "offer_id": offer["offer_id"]});
    if offers.len() > 1 {
        selection["additional_offer_ids"] = json!([offers[1]["offer_id"]]);
    }
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
    host.wait_transfer_notice("file_approval_required", id)
        .await;
    if offers.len() == 2 {
        let reordered = json!({"task_id":task,"offer_id":offers[1]["offer_id"],"additional_offer_ids":[offer["offer_id"]]});
        assert_eq!(host.call("asl_fetch", reordered).await, pending);
        assert_eq!(
            pending["additional_offer_ids"],
            json!([offers[1]["offer_id"]])
        );
    }
    let prompts = decisions.download_consents().unwrap();
    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0].content_id, content);
    assert_eq!(prompts[0].file_size, size);
    assert_eq!(
        &prompts[0].sources.iter().cloned().collect::<HashSet<_>>(),
        peers
    );
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
            Some("completed") => {
                host.wait_transfer_notice("file_received", id).await;
                break;
            }
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
        "INSERT OR IGNORE INTO chain_state_cache VALUES
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
