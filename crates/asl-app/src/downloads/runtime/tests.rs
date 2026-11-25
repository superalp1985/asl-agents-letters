use std::{
    fs,
    sync::mpsc::Receiver,
    thread,
    time::{Duration, Instant},
};

use asl_net::codec::{BulkOperation, BulkResponse, BulkStatus};
use asl_types::{manifest::CHUNK_SIZE, task::GroupId};

use super::*;
use crate::{
    CorruptFetchManifest, MatchedBulkResponse, VerifiedFetchManifest,
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
        self.fetch_with_group(grant, standby, None)
    }

    fn fetch_with_group(
        &self,
        grant: Id128,
        standby: Option<&VerifiedFetchManifest>,
        group: Option<GroupTransferBinding>,
    ) -> DownloadTicket {
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
                group,
                context_ref: None,
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

fn seed_group(inbox: &Inbox) -> GroupTransferBinding {
    let group_id = GroupId(Id128(rand::random()));
    let group_text = alloy_primitives::hex::encode(group_id.0.as_bytes());
    let peer_text = bs58::encode(inbox.event.peer_id.as_bytes()).into_string();
    let db = Inbox::database(&inbox.home);
    db.execute(
        "INSERT INTO asl_groups(
             group_id,creator_peer_id,local_name,mls_epoch,membership_epoch,state,
             created_at_ms,updated_at_ms)
         VALUES (?1,?2,'runtime',1,1,'active',0,0)",
        rusqlite::params![group_text, peer_text],
    )
    .unwrap();
    db.execute(
        "INSERT INTO group_members(group_id,peer_id,role,state,joined_at_ms)
         VALUES (?1,?2,'creator','active',0)",
        rusqlite::params![group_text, peer_text],
    )
    .unwrap();
    GroupTransferBinding {
        group_id,
        membership_epoch: 1,
    }
}

#[test]
fn correlated_corrupt_manifest_blocks_refetch_after_worker_restart() {
    let mut inbox = Inbox::new(b"local fixture");
    let content = Hash32(asl_types::manifest::content_id(b"not an ASL manifest"));
    inbox.event.0.content_id = content;
    drop(inbox.local);
    let mut h = Harness::new(&inbox.home, &inbox.event);
    let ticket = h.fetch(inbox.grant, None);
    let WorkerRequest::Fetch { request, .. } = h.request() else {
        panic!("expected Fetch");
    };
    let connection_id = h.connection.unwrap();
    let report = CorruptFetchManifest {
        fetch_request_id: request.message_id,
        root_task_id: request.root_task_id,
        agent_id: h.source.agent_id,
        peer_id: h.source.peer_id.clone(),
        connection_id,
        content_id: request.content_id,
        expires_at_ms: unix_time_ms().unwrap(),
    };
    // Keep the simulated Fetch tracked while injecting an expired receipt.
    // A subsequent capacity reply makes the worker retry only if it ignored it.
    h.bridge
        .deliver(&AdmittedNetworkEvent::FetchManifestCorrupt(report.clone()));
    h.bridge.forward(&AdmittedNetworkEvent::RequestFailed {
        connection_id,
        agent_id: report.agent_id,
        peer_id: report.peer_id.clone(),
        request_id: report.fetch_request_id.0,
        protocol: NetworkProtocol::Control,
        code: crate::ipc::NetworkErrorCode::Capacity,
    });
    let WorkerRequest::Fetch { request, .. } = h.request() else {
        panic!("expected retry after the expired report");
    };
    let database = Inbox::database(&inbox.home);
    let count: i64 = database
        .query_row(
            "SELECT count(*) FROM transfer_cooldowns WHERE content_id=lower(hex(?1))",
            [content.0.as_slice()],
            |row| row.get::<_, i64>(0),
        )
        .unwrap();
    assert_eq!(count, 0);
    let before = unix_time_ms().unwrap() as i64;
    h.bridge
        .forward(&AdmittedNetworkEvent::FetchManifestCorrupt(
            CorruptFetchManifest {
                fetch_request_id: request.message_id,
                expires_at_ms: before as u64 + 5_000,
                ..report
            },
        ));
    assert!(matches!(
        h.event(&ticket),
        DownloadEvent::Failed(AslError::InvalidMessage)
    ));
    drop(h);

    let (deadline, reason): (i64, String) = database
        .query_row(
            "SELECT retry_after_ms,reason FROM transfer_cooldowns WHERE content_id=lower(hex(?1))",
            [content.0.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let cooldown = asl_store::transfers::DOWNLOAD_COOLDOWN_MS;
    assert!((before + cooldown..=unix_time_ms().unwrap() as i64 + cooldown).contains(&deadline));
    assert_eq!(reason, "invalid_manifest");
    assert_eq!(fs::read_dir(&inbox.folder).unwrap().count(), 0);

    let mut h = Harness::new(&inbox.home, &inbox.event);
    let ticket = h.fetch(inbox.grant, None);
    assert!(matches!(
        h.event(&ticket),
        DownloadEvent::Failed(AslError::PolicyDenied)
    ));
    assert!(recv(&h.output).unwrap().is_none());
    drop(h);
    let broker = asl_store::transfers::DownloadBroker::open(&inbox.home).unwrap();
    assert!(broker.ensure_retry_allowed(content, deadline - 1).is_err());
    assert!(broker.ensure_retry_allowed(content, deadline).is_ok());
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
    let DownloadEvent::AwaitingApproval {
        approval_id,
        transfer_id,
    } = h.event(&selection)
    else {
        panic!("expected approval");
    };
    assert_eq!(fs::read_dir(&inbox.folder).unwrap().count(), 0);
    let decisions_record = decisions.download_consents().unwrap();
    assert_eq!(decisions_record[0].sources.len(), 2);
    assert!(decisions_record[0].sources.contains(&standby.peer_id));
    h.reconnect();
    decisions.decide_download(approval_id, true).unwrap();
    let WorkerRequest::Fetch {
        request: renewed, ..
    } = h.request()
    else {
        panic!("expected fresh Fetch");
    };
    assert_ne!(request.message_id, renewed.message_id);
    assert_eq!(request.root_task_id, renewed.root_task_id);
    h.manifest(renewed);
    let DownloadEvent::Started(info) = h.event(&selection) else {
        panic!("expected approved download to start");
    };
    assert_eq!(info.transfer_id, transfer_id);
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
fn revoked_inbox_never_sends_initial_fetch() {
    let inbox = Inbox::new(b"local fixture");
    drop(inbox.local);
    asl_store::resources::SnapshotBroker::open(&inbox.home)
        .unwrap()
        .revoke_inbox_directory(inbox.grant)
        .unwrap();
    let mut h = Harness::new(&inbox.home, &inbox.event);
    let ticket = h.fetch(inbox.grant, None);
    assert!(matches!(
        h.event(&ticket),
        DownloadEvent::Failed(AslError::PolicyDenied)
    ));
    assert!(recv(&h.output).unwrap().is_none());
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
            group: None,
            context_ref: None,
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
    check_worker_resume(false);
}

#[test]
fn recovery_host_resumes_only_the_approved_existing_transfer() {
    check_recovery_host_resume(false);
}

#[test]
fn recovery_host_resumes_group_download_in_its_original_membership_epoch() {
    check_recovery_host_resume(true);
}

fn check_recovery_host_resume(group_download: bool) {
    let bytes = vec![4; CHUNK_SIZE as usize + 23];
    let inbox = Inbox::new(&bytes);
    let binding = group_download.then(|| seed_group(&inbox));
    drop(inbox.local);
    let (info, old_lease) = interrupt_after_first_chunk(
        &inbox.home,
        &inbox.event,
        inbox.grant,
        binding.as_ref(),
        &bytes,
    );
    let store = asl_store::open_store(&inbox.home.join("state/asl.sqlite3")).unwrap();
    let subject = [17; 32];
    store
        .configure_mcp_recovery(Some(&subject), unix_time_ms().unwrap() as i64)
        .unwrap();
    let mut h = Harness::new(&inbox.home, &inbox.event);
    let resume = |subject| DownloadJob::ResumeForHost {
        transfer_id: info.transfer_id.clone(),
        subject,
    };
    let denied = h.port.submit(resume(subject)).unwrap();
    assert!(matches!(
        h.event(&denied),
        DownloadEvent::Failed(AslError::NotFound)
    ));
    store
        .authorize_recovery_download(&info.transfer_id)
        .unwrap();
    let denied = h.port.submit(resume([18; 32])).unwrap();
    assert!(matches!(
        h.event(&denied),
        DownloadEvent::Failed(AslError::PolicyDenied)
    ));
    assert!(recv(&h.output).unwrap().is_none());

    let resumed = h.port.submit(resume(subject)).unwrap();
    let DownloadEvent::Started(started) = h.event(&resumed) else {
        panic!("expected start")
    };
    assert_eq!(started.transfer_id, info.transfer_id);
    assert_eq!(started.durable_bytes, CHUNK_SIZE as u64);
    let WorkerRequest::Fetch { request, group, .. } = h.request() else {
        panic!("expected Fetch")
    };
    assert_eq!(group, binding);
    h.manifest(request);
    let WorkerRequest::Bulk { request, .. } = h.request() else {
        panic!("expected missing chunk")
    };
    assert_eq!(request.chunk_index, 1);
    assert_ne!(request.lease_id, old_lease);
    h.respond(request, bytes[CHUNK_SIZE as usize..].to_vec());
    let DownloadEvent::Completed(done) = h.event(&resumed) else {
        panic!("expected completion")
    };
    assert_eq!(fs::read(done.destination_path).unwrap(), bytes);
    let repeated = h.port.submit(resume(subject)).unwrap();
    assert!(matches!(h.event(&repeated), DownloadEvent::Completed(_)));
    assert!(recv(&h.output).unwrap().is_none());
}

#[test]
fn recovery_host_cannot_resume_group_download_after_membership_changes() {
    check_group_recovery_loses_authority(true);
}

#[test]
fn recovery_host_stops_when_the_group_source_device_is_revoked() {
    check_group_recovery_loses_authority(false);
}

fn check_group_recovery_loses_authority(change_epoch: bool) {
    let bytes = vec![5; CHUNK_SIZE as usize + 7];
    let inbox = Inbox::new(&bytes);
    let binding = seed_group(&inbox);
    drop(inbox.local);
    let (info, _) = interrupt_after_first_chunk(
        &inbox.home,
        &inbox.event,
        inbox.grant,
        Some(&binding),
        &bytes,
    );
    let store = asl_store::open_store(&inbox.home.join("state/asl.sqlite3")).unwrap();
    let subject = [17; 32];
    store
        .configure_mcp_recovery(Some(&subject), unix_time_ms().unwrap() as i64)
        .unwrap();
    store
        .authorize_recovery_download(&info.transfer_id)
        .unwrap();
    let mut h = Harness::new(&inbox.home, &inbox.event);
    let ticket = h
        .port
        .submit(DownloadJob::ResumeForHost {
            transfer_id: info.transfer_id.clone(),
            subject,
        })
        .unwrap();
    assert!(matches!(h.event(&ticket), DownloadEvent::Started(_)));
    let WorkerRequest::Fetch { request, group, .. } = h.request() else {
        panic!("expected Fetch in original epoch");
    };
    assert_eq!(group.as_ref(), Some(&binding));
    let db = Inbox::database(&inbox.home);
    if change_epoch {
        assert_eq!(db.execute(
            "UPDATE asl_groups SET membership_epoch=membership_epoch+1 WHERE group_id=lower(hex(?1))",
            [binding.group_id.0.as_bytes().as_slice()],
        ).unwrap(), 1);
    } else {
        assert_eq!(
            db.execute(
                "UPDATE device_identities SET revoked_at_ms=?1 WHERE peer_id=?2",
                rusqlite::params![
                    unix_time_ms().unwrap() as i64,
                    bs58::encode(inbox.event.peer_id.as_bytes()).into_string(),
                ],
            )
            .unwrap(),
            1
        );
    }
    h.manifest(request);
    assert!(matches!(
        h.event(&ticket),
        DownloadEvent::Failed(AslError::PolicyDenied)
    ));
    assert!(recv(&h.output).unwrap().is_none());
    assert!(!info.destination_path.exists());
    if change_epoch {
        assert!(matches!(
            store.authorize_recovery_download(&info.transfer_id),
            Err(AslError::PolicyDenied)
        ));
    }
}

#[test]
fn recovery_host_does_not_fetch_after_inbox_revocation() {
    let bytes = vec![4; CHUNK_SIZE as usize + 23];
    let inbox = Inbox::new(&bytes);
    drop(inbox.local);
    let (info, _) =
        interrupt_after_first_chunk(&inbox.home, &inbox.event, inbox.grant, None, &bytes);
    let store = asl_store::open_store(&inbox.home.join("state/asl.sqlite3")).unwrap();
    let subject = [17; 32];
    store
        .configure_mcp_recovery(Some(&subject), unix_time_ms().unwrap() as i64)
        .unwrap();
    store
        .authorize_recovery_download(&info.transfer_id)
        .unwrap();
    asl_store::resources::SnapshotBroker::open(&inbox.home)
        .unwrap()
        .revoke_inbox_directory(inbox.grant)
        .unwrap();

    let mut h = Harness::new(&inbox.home, &inbox.event);
    let ticket = h
        .port
        .submit(DownloadJob::ResumeForHost {
            transfer_id: info.transfer_id,
            subject,
        })
        .unwrap();
    assert!(matches!(
        h.event(&ticket),
        DownloadEvent::Failed(AslError::NotFound)
    ));
    assert!(recv(&h.output).unwrap().is_none());
    assert!(!info.destination_path.exists());
}

#[test]
fn restarted_group_download_keeps_its_binding_and_requests_only_the_missing_chunk() {
    check_worker_resume(true);
}

fn check_worker_resume(group_download: bool) {
    let bytes = vec![4; CHUNK_SIZE as usize + 23];
    let inbox = Inbox::new(&bytes);
    let binding = group_download.then(|| seed_group(&inbox));
    let outsider = inbox.new_source();
    drop(inbox.local);
    let (info, old_lease) = interrupt_after_first_chunk(
        &inbox.home,
        &inbox.event,
        inbox.grant,
        binding.as_ref(),
        &bytes,
    );

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
    let WorkerRequest::Fetch { request, group, .. } = h.request() else {
        panic!("expected fresh Fetch");
    };
    assert_eq!(group, binding);
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
    assert!(!info.part_path.exists());
    assert!(recv(&h.output).unwrap().is_none());
}

fn interrupt_after_first_chunk(
    home: &Path,
    source: &VerifiedFetchManifest,
    grant: Id128,
    binding: Option<&GroupTransferBinding>,
    bytes: &[u8],
) -> (DownloadInfo, Hash32) {
    let mut h = Harness::new(home, source);
    let ticket = h.fetch_with_group(grant, None, binding.cloned());
    let WorkerRequest::Fetch { request, group, .. } = h.request() else {
        panic!("expected Fetch");
    };
    assert_eq!(group.as_ref(), binding);
    h.manifest(request);
    let DownloadEvent::Started(info) = h.event(&ticket) else {
        panic!("expected start");
    };
    let WorkerRequest::Bulk { request: first, .. } = h.request() else {
        panic!("expected chunk");
    };
    let WorkerRequest::Bulk {
        request: second, ..
    } = h.request()
    else {
        panic!("expected outstanding second chunk");
    };
    assert_eq!((first.chunk_index, second.chunk_index), (0, 1));
    let old_lease = first.lease_id;
    h.respond(first, bytes[..CHUNK_SIZE as usize].to_vec());
    let db = Inbox::database(home);
    h.until(|_| {
        let durable: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM transfer_chunks
             WHERE transfer_id=lower(hex(?1)) AND chunk_index=0 AND state='durable')",
                [info.transfer_id.0.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        durable.then_some(())
    });
    assert!(!info.destination_path.exists());
    (info, old_lease)
}

#[test]
fn restarted_group_download_with_obsolete_membership_never_fetches_or_publishes() {
    let bytes = vec![5; CHUNK_SIZE as usize + 7];
    let inbox = Inbox::new(&bytes);
    let binding = seed_group(&inbox);
    drop(inbox.local);
    let (info, _) = interrupt_after_first_chunk(
        &inbox.home,
        &inbox.event,
        inbox.grant,
        Some(&binding),
        &bytes,
    );
    // Model a reconciled, active room where the source is still a member.
    // The old transfer must not inherit the new membership epoch.
    assert_eq!(Inbox::database(&inbox.home).execute(
        "UPDATE asl_groups SET membership_epoch=membership_epoch+1 WHERE group_id=lower(hex(?1))",
        [binding.group_id.0.as_bytes().as_slice()],
    ).unwrap(), 1);
    let mut h = Harness::new(&inbox.home, &inbox.event);
    let ticket = h
        .port
        .submit(DownloadJob::Resume {
            transfer_id: info.transfer_id,
            sources: vec![DownloadSource {
                agent_id: h.source.agent_id,
                peer_id: h.source.peer_id.clone(),
            }],
        })
        .unwrap();
    assert!(matches!(
        h.event(&ticket),
        DownloadEvent::Failed(AslError::PolicyDenied)
    ));
    assert!(recv(&h.output).unwrap().is_none());
    assert!(!info.destination_path.exists());
    assert!(!info.part_path.exists());
}
