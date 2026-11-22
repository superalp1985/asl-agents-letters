use super::*;
use asl_net::transport::AuthenticatedPeer;

pub(super) struct Provider {
    listener: LocalTransport,
    server: AuthenticatedPeer,
    requester: DirectRequester,
    inbound: DirectInbound,
    transfer: TransferService,
    libraries: LocalLibraries,
    content: Hash32,
}

pub(super) struct ReceiverIdentity {
    pub root: AgentIdentity,
    pub peer: PeerId,
    pub device_key: [u8; 32],
}

impl Provider {
    pub async fn connect(
        root: &Path,
        receiver_db: &Path,
        receiver: &ReceiverIdentity,
        dialer: &mut LocalTransport,
        bytes: &[u8],
        content: Hash32,
    ) -> (Self, AuthenticatedPeer, DownloadSource) {
        let library = root.join("library");
        fs::create_dir_all(&library).unwrap();
        fs::write(library.join("source.md"), bytes).unwrap();
        let paths = AppPaths::open(&root.join("home")).unwrap();
        let mut libraries = LocalLibraries::open(&paths).unwrap();
        let grant = libraries
            .authorize_directory(
                &library,
                &["md".into()],
                &Audience::Public,
                bytes.len() as u64,
            )
            .unwrap();
        let resource = libraries
            .import_source(&grant, Path::new("source.md"))
            .unwrap();
        let db = paths.state().join("asl.sqlite3");
        direct_inbound::configure(&db, "answer").unwrap();
        asl_store::open_store(&db)
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
        let device = DeviceIdentity::generate().unwrap();
        let peer = device.peer_id();
        let key = device.into_keypair();
        let device_key = key.public().try_into_ed25519().unwrap().to_bytes();
        let mut listener = LocalTransport::new(key).unwrap();
        listener
            .listen(
                TransportKind::Tcp,
                (std::net::Ipv4Addr::LOCALHOST, 0).into(),
            )
            .unwrap();
        let (client, server) = timeout(Duration::from_secs(5), async {
            let TransportEvent::Listening(TransportKind::Tcp, endpoint) =
                listener.next_event().await.unwrap()
            else {
                panic!("expected TCP listener")
            };
            dialer.dial(TransportKind::Tcp, endpoint, &peer).unwrap();
            let (left, right) = tokio::join!(dialer.next_event(), listener.next_event());
            let (
                TransportEvent::Connected { connection: client },
                TransportEvent::Connected { connection: server },
            ) = (left.unwrap(), right.unwrap())
            else {
                panic!("expected authenticated connections")
            };
            (client, server)
        })
        .await
        .unwrap();
        assert_eq!(client.peer_id(), &peer);
        assert_eq!(server.peer_id(), &receiver.peer);
        let requester = register(
            &db,
            &receiver.root,
            receiver.peer.clone(),
            receiver.device_key,
        );
        let admitted = register(
            receiver_db,
            &AgentIdentity::generate().unwrap(),
            peer,
            device_key,
        );
        rusqlite::Connection::open(receiver_db).unwrap().execute(
            "INSERT INTO authorized_contacts(agent_id,authorized_at_ms,authorization_revision) VALUES (?1,1,1)",
            [bs58::encode(admitted.agent.0).into_string()],
        ).unwrap();
        let source = DownloadSource {
            agent_id: admitted.agent,
            peer_id: admitted.peer,
        };
        (
            Self {
                listener,
                server,
                requester,
                libraries,
                content,
                inbound: DirectInbound::open(&db).unwrap(),
                transfer: TransferService::open(&db).unwrap(),
            },
            client,
            source,
        )
    }

    pub async fn serve(&mut self) {
        loop {
            let event = self.listener.next_event().await.unwrap();
            let now = unix_time_ms().unwrap();
            match event {
                TransportEvent::ControlRequest {
                    connection,
                    request: frame @ WireFrame::Query(_),
                    response,
                } => {
                    assert_eq!(connection, self.server);
                    let prepared = self
                        .inbound
                        .prepare(self.requester.clone(), frame, now)
                        .unwrap()
                        .unwrap();
                    self.inbound
                        .enqueue(prepared, |frame, _| {
                            assert!(matches!(frame, WireFrame::Offer(_)));
                            Ok(self.listener.send_control_response(
                                &self.server,
                                &response,
                                frame,
                            )?)
                        })
                        .unwrap();
                }
                TransportEvent::ControlRequest {
                    connection,
                    request: WireFrame::FetchRequest(request),
                    response,
                } => {
                    assert_eq!(connection, self.server);
                    assert_eq!(request.content_id, self.content);
                    let prepared = self
                        .transfer
                        .prepare_fetch(self.requester.clone(), &request, now)
                        .unwrap();
                    self.transfer
                        .finish_fetch(prepared, now, |grant, _| {
                            Ok(self.listener.send_control_response(
                                &self.server,
                                &response,
                                grant,
                            )?)
                        })
                        .unwrap();
                }
                TransportEvent::BulkRequest {
                    connection,
                    request,
                    response,
                } => {
                    assert_eq!(connection, self.server);
                    let prepared = self.transfer.prepare_bulk(
                        &self.libraries,
                        self.requester.clone(),
                        request,
                        now,
                    );
                    self.transfer
                        .finish_bulk(prepared, now, |data| {
                            Ok(self
                                .listener
                                .send_bulk_response(&self.server, &response, data)?)
                        })
                        .unwrap();
                }
                other => panic!("unexpected provider event: {other:?}"),
            }
        }
    }
}

fn register(db: &Path, root: &AgentIdentity, peer: PeerId, key: [u8; 32]) -> DirectRequester {
    let now = unix_time_ms().unwrap();
    let admitted = admit_fixture(db, root, peer, now);
    let cert = root
        .issue_device_certificate(
            admitted.peer.clone(),
            1,
            now,
            admitted.session_expires_at_ms,
        )
        .unwrap();
    asl_store::open_store(db)
        .unwrap()
        .register_transfer_peer(&admitted, 1, &cert, key, now)
        .unwrap();
    admitted
}
