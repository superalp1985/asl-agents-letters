use std::{
    fs,
    sync::mpsc::Receiver,
    thread,
    time::{Duration, Instant},
};

use asl_net::codec::{BulkOperation, BulkResponse, BulkStatus};
use asl_types::manifest::CHUNK_SIZE;

use super::*;
use crate::{
    MatchedBulkResponse, VerifiedFetchManifest,
    downloads::{DownloadMode, test_inbox::Inbox},
};

struct Harness {
    bridge: DownloadBridge,
    port: DownloadPort,
    output: Receiver<WorkerRequest>,
    route: SyncSender<WorkerRequest>,
    source: VerifiedFetchManifest,
    connection: Option<[u8; 16]>,
}

impl Harness {
    fn new(home: &Path, manifest: &VerifiedFetchManifest) -> Self {
        let (port, runtime) = download_channel();
        let bridge = DownloadBridge::spawn(home.to_owned(), runtime).unwrap();
        let (route, output) = sync_channel(TRACKED_REQUESTS);
        Self {
            bridge,
            port,
            route,
            output,
            source: manifest.clone(),
            connection: Some(manifest.connection_id),
        }
    }

    fn fetch(&self, grant: Id128, standby: Option<&VerifiedFetchManifest>) -> DownloadTicket {
        let sources = std::iter::once(&self.source)
            .chain(standby)
            .map(|source| DownloadSource {
                agent_id: source.agent_id,
                peer_id: source.peer_id.clone(),
            })
            .collect();
        self.port
            .submit(DownloadJob::Fetch(DownloadSelection {
                content_id: self.source.content_id,
                inbox_grant: grant,
                filename: "received.bin".into(),
                sources,
            }))
            .unwrap()
    }

    fn poll(&mut self) {
        self.bridge.poll(unix_time_ms().unwrap(), |request| {
            let connection = match &request {
                WorkerRequest::Fetch { source, .. } => {
                    if source.agent_id != self.source.agent_id
                        || source.peer_id != self.source.peer_id
                    {
                        return Err(AslError::NotFound);
                    }
                    self.connection.ok_or(AslError::NotFound)?
                }
                WorkerRequest::Bulk { connection_id, .. } => {
                    assert_eq!(Some(*connection_id), self.connection);
                    *connection_id
                }
            };
            self.route.try_send(request).unwrap();
            Ok(Some(connection))
        });
    }

    fn until<T>(&mut self, mut ready: impl FnMut(&Self) -> Option<T>) -> T {
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            self.poll();
            if let Some(value) = ready(self) {
                return value;
            }
            assert!(
                Instant::now() < deadline,
                "download worker did not progress"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn request(&mut self) -> WorkerRequest {
        self.until(|h| recv(&h.output).unwrap())
    }

    fn event(&mut self, ticket: &DownloadTicket) -> DownloadEvent {
        self.until(|_| ticket.try_recv().unwrap())
    }

    fn manifest(&mut self, request: FetchRequest) {
        let mut verified = self.source.clone();
        verified.0.fetch_generation += 1;
        self.source.0.fetch_generation = verified.fetch_generation;
        verified.0.lease_id = Hash32(rand::random());
        verified.0.fetch_request_id = request.message_id;
        verified.0.root_task_id = request.root_task_id;
        verified.0.expires_at_ms = unix_time_ms().unwrap() + 60_000;
        verified.0.connection_id = self.connection.unwrap();
        self.bridge
            .forward(&AdmittedNetworkEvent::FetchManifestReceived(verified));
    }

    fn respond(&mut self, request: BulkRequest, payload: Vec<u8>) {
        let response = BulkResponse {
            request_id: request.request_id,
            status: BulkStatus::Success,
            payload,
        };
        self.bridge
            .forward(&AdmittedNetworkEvent::BulkTransferResponse(
                MatchedBulkResponse {
                    connection_id: self.connection.unwrap(),
                    agent_id: self.source.agent_id,
                    peer_id: self.source.peer_id.clone(),
                    request,
                    response,
                },
            ));
    }

    fn reconnect(&mut self) {
        let previous = self.connection.replace(rand::random()).unwrap();
        self.bridge
            .forward(&AdmittedNetworkEvent::PeerDisconnected {
                connection_id: previous,
                peer_id: Some(self.source.peer_id.clone()),
                agent_id: Some(self.source.agent_id),
            });
    }
}

#[test]
fn inline_requires_local_selection_and_can_refresh_after_approval() {
    let bytes = b"ASL inline";
    let mut inbox = Inbox::new(bytes);
    inbox.local.set_download_mode(DownloadMode::Ask).unwrap();
    let standby = inbox.new_source();
    drop(inbox.local);
    let mut decisions = asl_store::open_store(&inbox.home.join("state/asl.sqlite3")).unwrap();
    let mut h = Harness::new(&inbox.home, &inbox.event);
    let selection = h.fetch(inbox.grant, Some(&standby));
    let WorkerRequest::Fetch { request, .. } = h.request() else {
        panic!("expected Fetch");
    };
    h.manifest(request.clone());
    let DownloadEvent::AwaitingApproval(approval) = h.event(&selection) else {
        panic!("expected approval");
    };
    assert_eq!(fs::read_dir(&inbox.folder).unwrap().count(), 0);
    let decisions_record = decisions.download_consents().unwrap();
    assert_eq!(decisions_record[0].sources.len(), 2);
    assert!(decisions_record[0].sources.contains(&standby.peer_id));
    h.reconnect();
    decisions.decide_download(approval, true).unwrap();
    let WorkerRequest::Fetch {
        request: renewed, ..
    } = h.request()
    else {
        panic!("expected fresh Fetch");
    };
    assert_ne!(request.message_id, renewed.message_id);
    assert_eq!(request.root_task_id, renewed.root_task_id);
    h.manifest(renewed);
    assert!(matches!(h.event(&selection), DownloadEvent::Started(_)));
    let WorkerRequest::Bulk { request, .. } = h.request() else {
        panic!("expected Inline");
    };
    assert_eq!(request.operation, BulkOperation::Inline);
    h.respond(request, bytes.to_vec());
    let DownloadEvent::Completed(info) = h.event(&selection) else {
        panic!("expected publish");
    };
    assert_eq!(fs::read(info.destination_path).unwrap(), bytes);
    assert!(!info.part_path.exists());
}

#[test]
fn chunk_worker_reconnects_without_requesting_already_durable_blocks() {
    let bytes = vec![3; CHUNK_SIZE as usize + 17];
    let inbox = Inbox::new(&bytes);
    drop(inbox.local);
    let mut h = Harness::new(&inbox.home, &inbox.event);
    let ticket = h.fetch(inbox.grant, None);
    let WorkerRequest::Fetch { request, .. } = h.request() else {
        panic!("expected Fetch");
    };
    h.manifest(request);
    assert!(matches!(h.event(&ticket), DownloadEvent::Started(_)));
    let WorkerRequest::Bulk { request: first, .. } = h.request() else {
        panic!("expected chunk");
    };
    let WorkerRequest::Bulk {
        request: second, ..
    } = h.request()
    else {
        panic!("expected second chunk");
    };
    assert_eq!((first.chunk_index, second.chunk_index), (0, 1));
    h.respond(first, bytes[..CHUNK_SIZE as usize].to_vec());
    h.reconnect();
    let WorkerRequest::Fetch { request, .. } = h.request() else {
        panic!("expected renewed Fetch");
    };
    h.manifest(request);
    let WorkerRequest::Bulk {
        request: retried, ..
    } = h.request()
    else {
        panic!("expected retried chunk");
    };
    assert_eq!(retried.chunk_index, 1);
    assert_ne!(retried.lease_id, second.lease_id);
    h.respond(retried, bytes[CHUNK_SIZE as usize..].to_vec());
    let DownloadEvent::Completed(info) = h.event(&ticket) else {
        panic!("expected publish");
    };
    assert_eq!(fs::read(info.destination_path).unwrap(), bytes);
}

#[test]
fn download_port_is_bounded_and_rejects_non_filename_destinations() {
    let (port, _runtime) = download_channel();
    let make = |filename: &str| {
        DownloadJob::Fetch(DownloadSelection {
            content_id: Hash32([1; 32]),
            inbox_grant: Id128([2; 16]),
            filename: filename.into(),
            sources: vec![DownloadSource {
                agent_id: AgentId([3; 32]),
                peer_id: crate::identity::DeviceIdentity::generate()
                    .unwrap()
                    .peer_id(),
            }],
        })
    };
    assert!(port.submit(make("outside/item.bin")).is_err());
    for _ in 0..LOCAL_QUEUE {
        assert!(port.submit(make("item.bin")).is_ok());
    }
    assert!(matches!(
        port.submit(make("item.bin")),
        Err(AslError::QuotaExceeded)
    ));
}

#[test]
fn restarted_worker_can_resume_only_with_previously_authorized_sources() {
    let bytes = vec![4; CHUNK_SIZE as usize + 23];
    let inbox = Inbox::new(&bytes);
    let outsider = inbox.new_source();
    drop(inbox.local);
    let mut h = Harness::new(&inbox.home, &inbox.event);
    let ticket = h.fetch(inbox.grant, None);
    let WorkerRequest::Fetch { request, .. } = h.request() else {
        panic!("expected Fetch");
    };
    h.manifest(request);
    let DownloadEvent::Started(info) = h.event(&ticket) else {
        panic!("expected start");
    };
    let WorkerRequest::Bulk { request: first, .. } = h.request() else {
        panic!("expected chunk");
    };
    assert_eq!(first.chunk_index, 0);
    let old_lease = first.lease_id;
    h.respond(first, bytes[..CHUNK_SIZE as usize].to_vec());
    let db = Inbox::database(&inbox.home);
    h.until(|_| {
        let durable: i64 = db
            .query_row(
                "SELECT count(*) FROM transfer_chunks WHERE state='durable'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        (durable == 1).then_some(())
    });
    drop(h);

    let mut h = Harness::new(&inbox.home, &inbox.event);
    let denied = h
        .port
        .submit(DownloadJob::Resume {
            transfer_id: info.transfer_id.clone(),
            sources: vec![DownloadSource {
                agent_id: outsider.agent_id,
                peer_id: outsider.peer_id.clone(),
            }],
        })
        .unwrap();
    assert!(matches!(
        h.event(&denied),
        DownloadEvent::Failed(AslError::PolicyDenied)
    ));
    assert!(recv(&h.output).unwrap().is_none());

    let resumed = h
        .port
        .submit(DownloadJob::Resume {
            transfer_id: info.transfer_id,
            sources: vec![DownloadSource {
                agent_id: h.source.agent_id,
                peer_id: h.source.peer_id.clone(),
            }],
        })
        .unwrap();
    let DownloadEvent::Started(info) = h.event(&resumed) else {
        panic!("expected resumable task");
    };
    assert_eq!(info.durable_bytes, CHUNK_SIZE as u64);
    let WorkerRequest::Fetch { request, .. } = h.request() else {
        panic!("expected fresh Fetch");
    };
    h.manifest(request);
    let WorkerRequest::Bulk { request, .. } = h.request() else {
        panic!("expected remaining chunk");
    };
    assert_eq!(request.chunk_index, 1);
    assert_ne!(request.lease_id, old_lease);
    h.respond(request, bytes[CHUNK_SIZE as usize..].to_vec());
    let DownloadEvent::Completed(info) = h.event(&resumed) else {
        panic!("expected complete");
    };
    assert_eq!(fs::read(info.destination_path).unwrap(), bytes);
}
