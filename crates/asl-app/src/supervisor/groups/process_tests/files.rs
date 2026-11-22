use super::*;
use crate::{
    direct_outbound::outgoing_query_channel,
    downloads::{
        DownloadBridge, DownloadDriverEvent, DownloadEvent, DownloadJob, DownloadPort,
        DownloadSelection, DownloadSource, DownloadTicket, download_channel,
    },
};
use asl_store::transfers::{DownloadMode, GroupTransferBinding, UploadMode};
use asl_types::manifest::{CHUNK_SIZE, Manifest, content_id, encode_manifest};

const SOURCE: &str = "group.md";
const DEST: &str = "approved.bin";
const LIMIT: u64 = 4 * CHUNK_SIZE as u64;

#[derive(Serialize, Deserialize)]
pub(super) enum FileAction {
    Share(Hash32),
    Fetch {
        room: Hash32,
        content: Hash32,
        peer: Vec<u8>,
    },
    Status,
    WaitingForUpload,
}

type Command = (FileAction, mpsc::SyncSender<Result<Value, AslError>>);

pub(super) fn run(
    supervisor: Supervisor,
    commands: Receiver<Command>,
    tick: impl Fn(&mut Supervisor) -> Result<(), AslError>,
) -> Result<(), AslError> {
    let (port, downloads) = download_channel();
    let (_, queries) = outgoing_query_channel();
    let mut bridge = DownloadBridge::spawn(supervisor.home.clone(), downloads)?;
    let mut ticket = None;
    let mut saw_pending = false;
    supervisor.run_with_transfer_handler(queries, |core, transfers, event| {
        match event {
            DownloadDriverEvent::Network(event) => {
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
                &parent.join("library"),
                &["md".into()],
                &asl_policy::Audience::Group(snapshot.local_id),
                LIMIT,
            )?;
            core.libraries.import_source(&grant, Path::new(SOURCE))?;
        }
        FileAction::Fetch { content, peer, .. } => {
            let peer_id = PeerId::from_bytes(peer).map_err(|_| AslError::InvalidIdentity)?;
            let agent_id = store
                .mls_peer_agent(&peer_id)?
                .ok_or(AslError::InvalidIdentity)?;
            let inbox_grant = core
                .libraries
                .authorize_inbox_directory(&parent.join("inbox"), LIMIT)?;
            *ticket = Some(port.submit(DownloadJob::Fetch(DownloadSelection {
                content_id: content,
                inbox_grant,
                filename: DEST.into(),
                sources: vec![DownloadSource { agent_id, peer_id }],
                group: Some(GroupTransferBinding {
                    group_id: snapshot.local_id,
                    membership_epoch: snapshot.version.membership_epoch,
                }),
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
    let library = root.join("library");
    fs::create_dir(&inbox).unwrap();
    fs::create_dir(&library).unwrap();
    let mut bytes = vec![b'X'; CHUNK_SIZE as usize];
    bytes.extend_from_slice(b"\nsecond chunk\n");
    fs::write(library.join(SOURCE), &bytes).unwrap();
    let manifest = Manifest {
        file_size: bytes.len() as u64,
        file_hash: *blake3::hash(&bytes).as_bytes(),
        chunk_hashes: bytes
            .chunks(CHUNK_SIZE as usize)
            .map(|c| *blake3::hash(c).as_bytes())
            .collect(),
    };
    let content = Hash32(content_id(&encode_manifest(&manifest).unwrap()));
    let local = |home: &Path| {
        asl_store::open_store(
            &AppPaths::open_existing(home)
                .unwrap()
                .state()
                .join("asl.sqlite3"),
        )
        .unwrap()
    };
    let mut send = local(provider_home);
    let mut receive = local(receiver_home);
    send.set_upload_mode(UploadMode::Ask).unwrap();
    receive.set_download_mode(DownloadMode::Ask).unwrap();
    file(provider, FileAction::Share(room));
    file(
        receiver,
        FileAction::Fetch {
            room,
            content,
            peer: source.as_bytes().to_vec(),
        },
    );
    let wait = |stage, ready: &mut dyn FnMut() -> bool| {
        let start = Instant::now();
        while !ready() {
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "timed out: {stage}"
            );
            thread::sleep(Duration::from_millis(100));
        }
    };
    wait("upload consent", &mut || {
        !send.upload_consents().unwrap().is_empty()
    });
    wait("group FetchPending at download driver", &mut || {
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
    wait("download consent", &mut || {
        !receive.download_consents().unwrap().is_empty()
    });
    let [download] = receive.download_consents().unwrap().try_into().unwrap();
    assert_eq!(download.content_id, content);
    assert_eq!(
        download.group.unwrap().group_id,
        receive.mls_room_snapshot(room).unwrap().unwrap().local_id
    );
    assert_eq!(download.sources.as_slice(), std::slice::from_ref(source));
    assert_eq!(fs::read_dir(&inbox).unwrap().count(), 0);
    receive.decide_download(download.approval_id, true).unwrap();
    wait("file publication", &mut || {
        file(receiver, FileAction::Status) == "complete"
    });
    assert_eq!(fs::read(inbox.join(DEST)).unwrap(), bytes);
}
