use super::*;
use crate::{
    direct_outbound::outgoing_query_channel,
    downloads::{
        DownloadBridge, DownloadDriverEvent, DownloadEvent, DownloadJob, DownloadPort,
        DownloadSelection, DownloadSource, DownloadTicket, download_channel,
    },
};
use asl_net::codec::{BulkOperation, BulkStatus};
use asl_store::transfers::{DownloadMode, GroupTransferBinding, UploadMode};
use asl_types::manifest::{CHUNK_SIZE, Manifest, content_id, encode_manifest};
use std::collections::BTreeSet;

const SOURCE: &str = "group.md";
const DEST: &str = "approved.bin";
const LIMIT: u64 = 4 * CHUNK_SIZE as u64;

#[derive(Serialize, Deserialize)]
pub(super) enum FileAction {
    Share(Hash32),
    Fetch {
        room: Hash32,
        content: Hash32,
        peers: Vec<Vec<u8>>,
    },
    Status,
    WaitingForUpload,
}

type Command = (FileAction, mpsc::SyncSender<Result<Value, AslError>>);

pub(super) fn run(
    supervisor: Supervisor,
    commands: Receiver<Command>,
    tick: impl Fn(&mut Supervisor) -> Result<(), AslError>,
    scenario: Scenario,
) -> Result<(), AslError> {
    let (port, downloads) = download_channel();
    let (_, queries) = outgoing_query_channel();
    let mut bridge = DownloadBridge::spawn(supervisor.home.clone(), downloads)?;
    let mut ticket = None;
    let mut saw_pending = false;
    let mut await_two_sources = scenario == Scenario::TwoSources;
    let mut held = Vec::<crate::MatchedBulkResponse>::new();
    supervisor.run_with_transfer_handler(queries, |core, transfers, event| {
        match event {
            DownloadDriverEvent::Network(event) => {
                // Delay delivery to the disk worker, not the TCP exchange, until
                // two providers have answered distinct outstanding assignments.
                if await_two_sources
                    && let AdmittedNetworkEvent::BulkTransferResponse(reply) = event
                    && reply.request.operation == BulkOperation::Chunk
                    && reply.response.status == BulkStatus::Success
                {
                    if held.iter().all(|p| p.peer_id == reply.peer_id) {
                        assert!(held.len() < 2, "one source exceeded its chunk window");
                        held.push(reply.clone());
                        return Ok(());
                    }
                    assert!(
                        held.iter()
                            .all(|p| p.request.chunk_index != reply.request.chunk_index)
                    );
                    for previous in held.drain(..) {
                        bridge.forward(&AdmittedNetworkEvent::BulkTransferResponse(previous));
                    }
                    await_two_sources = false;
                }
                saw_pending |= matches!(
                    event,
                    AdmittedNetworkEvent::ControlResponse {
                        response: asl_types::protocol::WireFrame::FetchPending(_),
                        ..
                    }
                );
                bridge.forward(event);
            }
            DownloadDriverEvent::Tick => {
                tick(core)?;
                if let Ok((action, reply)) = commands.try_recv() {
                    let _ = reply.send(handle(core, &port, &mut ticket, action, saw_pending));
                }
                bridge.poll(unix_time_ms()?, |request| {
                    core.send_download_request(transfers, request)
                });
            }
        }
        Ok(())
    })
}

fn handle(
    core: &mut Supervisor,
    port: &DownloadPort,
    ticket: &mut Option<DownloadTicket>,
    action: FileAction,
    saw_pending: bool,
) -> Result<Value, AslError> {
    let room = match action {
        FileAction::WaitingForUpload => return Ok(json!(saw_pending)),
        FileAction::Share(room) | FileAction::Fetch { room, .. } => room,
        FileAction::Status => {
            return Ok(
                match ticket.as_ref().ok_or(AslError::NotFound)?.try_recv()? {
                    Some(DownloadEvent::Completed(_)) => json!("complete"),
                    Some(DownloadEvent::Failed(error)) => return Err(error),
                    _ => json!("waiting"),
                },
            );
        }
    };
    let store = &core.groups.as_ref().ok_or(AslError::NotFound)?.store;
    let snapshot = store.mls_room_snapshot(room)?.ok_or(AslError::NotFound)?;
    let parent = core.home.parent().unwrap();
    match action {
        FileAction::Share(_) => {
            let grant = core.libraries.authorize_directory(
                &core.home.with_extension("library"),
                &["md".into()],
                &asl_policy::Audience::Group(snapshot.local_id),
                LIMIT,
            )?;
            core.libraries.import_source(&grant, Path::new(SOURCE))?;
        }
        FileAction::Fetch { content, peers, .. } => {
            let sources = peers
                .into_iter()
                .map(|peer| {
                    let peer_id =
                        PeerId::from_bytes(peer).map_err(|_| AslError::InvalidIdentity)?;
                    let agent_id = store
                        .mls_peer_agent(&peer_id)?
                        .ok_or(AslError::InvalidIdentity)?;
                    Ok(DownloadSource { agent_id, peer_id })
                })
                .collect::<Result<_, AslError>>()?;
            let inbox_grant = core
                .libraries
                .authorize_inbox_directory(&parent.join("inbox"), LIMIT)?;
            *ticket = Some(port.submit(DownloadJob::Fetch(DownloadSelection {
                content_id: content,
                inbox_grant,
                filename: DEST.into(),
                sources,
                group: Some(GroupTransferBinding {
                    group_id: snapshot.local_id,
                    membership_epoch: snapshot.version.membership_epoch,
                }),
                context_ref: None,
            }))?);
        }
        FileAction::Status | FileAction::WaitingForUpload => unreachable!(),
    }
    Ok(json!(true))
}

fn file(core: &mut CoreProcess, action: FileAction) -> Value {
    let reply = core.fixture_request(FixtureRequest::File(action), "group file");
    assert!(reply.get("error").is_none(), "{}: {reply}", core.node);
    reply
}

pub(super) fn verify(
    provider: &mut CoreProcess,
    receiver: &mut CoreProcess,
    provider_home: &Path,
    receiver_home: &Path,
    room: Hash32,
    source: &PeerId,
) {
    let root = provider_home.parent().unwrap();
    let inbox = root.join("inbox");
    fs::create_dir(&inbox).unwrap();
    let mut bytes = vec![b'X'; CHUNK_SIZE as usize];
    bytes.extend_from_slice(b"\nsecond chunk\n");
    let content = share(provider, provider_home, room, &bytes);
    let mut send = local(provider_home);
    let mut receive = local(receiver_home);
    send.set_upload_mode(UploadMode::Ask).unwrap();
    receive.set_download_mode(DownloadMode::Ask).unwrap();
    file(
        receiver,
        FileAction::Fetch {
            room,
            content,
            peers: vec![source.as_bytes().to_vec()],
        },
    );
    wait("upload consent", || {
        !send.upload_consents().unwrap().is_empty()
    });
    wait("group FetchPending at download driver", || {
        file(receiver, FileAction::WaitingForUpload) == true
    });
    let [upload] = send.upload_consents().unwrap().try_into().unwrap();
    assert_eq!(upload.content_id, content);
    assert_eq!(
        upload.group.unwrap().group_id,
        send.mls_room_snapshot(room).unwrap().unwrap().local_id
    );
    assert!(receive.download_consents().unwrap().is_empty());
    assert_eq!(fs::read_dir(&inbox).unwrap().count(), 0);
    send.decide_upload(upload.approval_id, true).unwrap();
    approve_and_verify(
        receiver,
        &mut receive,
        room,
        content,
        &[source],
        &inbox,
        &bytes,
    );
}

fn share(core: &mut CoreProcess, home: &Path, room: Hash32, bytes: &[u8]) -> Hash32 {
    let library = home.with_extension("library");
    fs::create_dir(&library).unwrap();
    fs::write(library.join(SOURCE), bytes).unwrap();
    file(core, FileAction::Share(room));
    let manifest = Manifest {
        file_size: bytes.len() as u64,
        file_hash: *blake3::hash(bytes).as_bytes(),
        chunk_hashes: bytes
            .chunks(CHUNK_SIZE as usize)
            .map(|c| *blake3::hash(c).as_bytes())
            .collect(),
    };
    Hash32(content_id(&encode_manifest(&manifest).unwrap()))
}

fn local(home: &Path) -> asl_store::Store {
    asl_store::open_store(
        &AppPaths::open_existing(home)
            .unwrap()
            .state()
            .join("asl.sqlite3"),
    )
    .unwrap()
}

fn wait(stage: &str, mut ready: impl FnMut() -> bool) {
    let start = Instant::now();
    while !ready() {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "timed out: {stage}"
        );
        thread::sleep(Duration::from_millis(100));
    }
}

fn approve_and_verify(
    receiver: &mut CoreProcess,
    receive: &mut asl_store::Store,
    room: Hash32,
    content: Hash32,
    sources: &[&PeerId],
    inbox: &Path,
    bytes: &[u8],
) {
    wait("download consent", || {
        !receive.download_consents().unwrap().is_empty()
    });
    let [download] = receive.download_consents().unwrap().try_into().unwrap();
    assert_eq!(download.content_id, content);
    assert_eq!(
        download.group.unwrap().group_id,
        receive.mls_room_snapshot(room).unwrap().unwrap().local_id
    );
    assert_eq!(download.sources.len(), sources.len());
    assert!(sources.iter().all(|p| download.sources.contains(p)));
    assert_eq!(fs::read_dir(inbox).unwrap().count(), 0);
    receive.decide_download(download.approval_id, true).unwrap();
    wait("file publication", || {
        file(receiver, FileAction::Status) == "complete"
    });
    assert_eq!(fs::read(inbox.join(DEST)).unwrap(), bytes);
}

pub(super) fn verify_two_sources(
    receiver: &mut CoreProcess,
    home: &Path,
    room: Hash32,
    providers: [(&mut CoreProcess, &Path, &PeerId); 2],
) {
    let inbox = home.parent().unwrap().join("inbox");
    fs::create_dir(&inbox).unwrap();
    let mut bytes = Vec::new();
    for &value in b"ABC" {
        bytes.extend(std::iter::repeat_n(value, CHUNK_SIZE as usize));
    }
    bytes.extend_from_slice(b"tail");
    let mut receive = local(home);
    receive.set_download_mode(DownloadMode::Ask).unwrap();
    let [a, b] = providers;
    let sources = [a.2, b.2];
    let [left, right] = [a, b].map(|(core, path, _)| {
        local(path).set_upload_mode(UploadMode::Automatic).unwrap();
        share(core, path, room, &bytes)
    });
    assert_eq!(left, right);
    file(
        receiver,
        FileAction::Fetch {
            room,
            content: left,
            peers: sources.map(|p| p.as_bytes().to_vec()).to_vec(),
        },
    );
    approve_and_verify(receiver, &mut receive, room, left, &sources, &inbox, &bytes);

    let db = rusqlite::Connection::open(
        AppPaths::open_existing(home)
            .unwrap()
            .state()
            .join("asl.sqlite3"),
    )
    .unwrap();
    let mut query = db.prepare(
        "SELECT c.chunk_index,c.source_peer FROM transfer_chunks c JOIN transfers t USING(transfer_id)
         WHERE t.content_id=?1 AND t.state='complete' AND c.state='durable' ORDER BY c.chunk_index"
    ).unwrap();
    let rows = query
        .query_map([alloy_primitives::hex::encode(left.0)], |r| {
            Ok((r.get::<_, u32>(0)?, r.get::<_, String>(1)?))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(rows.iter().map(|r| r.0).collect::<Vec<_>>(), [0, 1, 2, 3]);
    assert_eq!(
        rows.into_iter().map(|r| r.1).collect::<BTreeSet<_>>(),
        sources
            .iter()
            .map(|p| bs58::encode(p.as_bytes()).into_string())
            .collect()
    );
}
