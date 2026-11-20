use asl_net::transport::{LocalTransport, TransportEvent, TransportKind};
use asl_types::ids::PeerId;
use libp2p::identity::Keypair;
use std::{
    env, io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    process::{Child, Command, ExitStatus, Stdio},
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream},
    time::{Instant, sleep, timeout_at},
};

const TEST_TIMEOUT: Duration = Duration::from_secs(30);

const HELLO: u8 = 1;
const LISTENER_READY: u8 = 2;
const OBSERVED_PEER: u8 = 3;
const WRONG_PEER_REJECTED: u8 = 4;
const EXPECTED_PEER: u8 = 10;
const DIAL: u8 = 11;
const DIAL_WRONG_PEER: u8 = 12;
const RELEASE: u8 = 13;

#[tokio::test]
async fn tcp_noise_yamux_two_processes() {
    run_two_process_transport(TransportKind::Tcp, false)
        .await
        .expect("TCP Noise/Yamux two-process test failed");
}

#[tokio::test]
async fn tcp_noise_yamux_loopback() {
    let dialer_identity = Keypair::generate_ed25519();
    let dialer_peer = peer_id(&dialer_identity);
    let mut dialer = LocalTransport::new(dialer_identity).unwrap();
    let listener_identity = Keypair::generate_ed25519();
    let listener_peer = peer_id(&listener_identity);
    let mut listener = LocalTransport::new(listener_identity).unwrap();
    listener
        .listen(
            TransportKind::Tcp,
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into(),
        )
        .unwrap();
    let endpoint = match listener.next_event().await.unwrap() {
        TransportEvent::Listening(TransportKind::Tcp, endpoint) => endpoint,
        event => panic!("unexpected listener event: {event:?}"),
    };
    dialer
        .dial(TransportKind::Tcp, endpoint, &listener_peer)
        .unwrap();
    let (left, right) = tokio::join!(dialer.next_event(), listener.next_event());
    assert!(matches!(
        left.unwrap(),
        TransportEvent::Connected { connection } if connection.peer_id() == &listener_peer
    ));
    assert!(matches!(
        right.unwrap(),
        TransportEvent::Connected { connection } if connection.peer_id() == &dialer_peer
    ));
}

#[tokio::test]
async fn closing_an_authenticated_connection_emits_disconnects_on_both_sides() {
    let dialer_identity = Keypair::generate_ed25519();
    let dialer_peer = peer_id(&dialer_identity);
    let mut dialer = LocalTransport::new(dialer_identity).unwrap();
    let listener_identity = Keypair::generate_ed25519();
    let listener_peer = peer_id(&listener_identity);
    let mut listener = LocalTransport::new(listener_identity).unwrap();
    listener
        .listen(
            TransportKind::Tcp,
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into(),
        )
        .unwrap();
    let endpoint = match listener.next_event().await.unwrap() {
        TransportEvent::Listening(TransportKind::Tcp, endpoint) => endpoint,
        event => panic!("unexpected listener event: {event:?}"),
    };
    dialer
        .dial(TransportKind::Tcp, endpoint, &listener_peer)
        .unwrap();
    let (dialer_event, listener_event) = tokio::join!(dialer.next_event(), listener.next_event());
    let TransportEvent::Connected {
        connection: dialer_connection,
    } = dialer_event.unwrap()
    else {
        panic!("dialer did not authenticate the listener");
    };
    let TransportEvent::Connected {
        connection: listener_connection,
    } = listener_event.unwrap()
    else {
        panic!("listener did not authenticate the dialer");
    };
    assert_eq!(dialer_connection.peer_id(), &listener_peer);
    assert_eq!(listener_connection.peer_id(), &dialer_peer);

    dialer.close_connection(&dialer_connection).unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), dialer.next_event())
            .await
            .unwrap()
            .unwrap(),
        TransportEvent::Disconnected { peer, .. } if peer == listener_peer
    ));
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), listener.next_event())
            .await
            .unwrap()
            .unwrap(),
        TransportEvent::Disconnected { peer, .. } if peer == dialer_peer
    ));
}

#[tokio::test]
async fn quic_two_processes() {
    run_two_process_transport(TransportKind::Quic, false)
        .await
        .expect("QUIC two-process test failed");
}

#[tokio::test]
async fn tcp_wrong_expected_peer_is_rejected() {
    run_two_process_transport(TransportKind::Tcp, true)
        .await
        .expect("TCP wrong-peer test failed");
}

#[tokio::test]
async fn quic_wrong_expected_peer_is_rejected() {
    run_two_process_transport(TransportKind::Quic, true)
        .await
        .expect("QUIC wrong-peer test failed");
}

#[tokio::test]
#[ignore]
async fn child_process_entry() {
    run_child_process()
        .await
        .expect("transport child process failed");
}

async fn run_two_process_transport(kind: TransportKind, wrong_probe: bool) -> io::Result<()> {
    let deadline = Instant::now() + TEST_TIMEOUT;
    let control_listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).await?;
    let control_addr = control_listener.local_addr()?.to_string();

    let mut dialer = ChildGuard::spawn(&control_addr, kind, "dialer")?;
    let mut dialer_control = accept_control(&control_listener, deadline).await?;
    let dialer_peer = read_peer(&mut dialer_control, HELLO, deadline).await?;

    let mut listener = ChildGuard::spawn(&control_addr, kind, "listener")?;
    let mut listener_control = accept_control(&control_listener, deadline).await?;
    let (listener_peer, endpoint) = read_listener_ready(&mut listener_control, deadline).await?;
    write_peer(&mut listener_control, EXPECTED_PEER, &dialer_peer, deadline).await?;

    if wrong_probe {
        let mut wrong_dialer = ChildGuard::spawn(&control_addr, kind, "wrong-dialer")?;
        let mut wrong_control = accept_control(&control_listener, deadline).await?;
        let wrong_dialer_peer = read_peer(&mut wrong_control, HELLO, deadline).await?;
        let wrong_expected_peer = random_peer_id();
        if wrong_expected_peer == listener_peer || wrong_expected_peer == wrong_dialer_peer {
            return Err(io::Error::other("unexpected generated PeerId collision"));
        }
        write_dial_command(
            &mut wrong_control,
            DIAL_WRONG_PEER,
            endpoint,
            &wrong_expected_peer,
            deadline,
        )
        .await?;
        read_tag(&mut wrong_control, WRONG_PEER_REJECTED, deadline).await?;
        ensure_success(wrong_dialer.wait(deadline).await?, "wrong-peer dialer")?;
    }

    write_dial_command(
        &mut dialer_control,
        DIAL,
        endpoint,
        &listener_peer,
        deadline,
    )
    .await?;
    let listener_observed = read_peer(&mut listener_control, OBSERVED_PEER, deadline).await?;
    let dialer_observed = read_peer(&mut dialer_control, OBSERVED_PEER, deadline).await?;
    if listener_observed != dialer_peer || dialer_observed != listener_peer {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "a process observed an unexpected authenticated PeerId",
        ));
    }
    write_tag(&mut listener_control, RELEASE, deadline).await?;
    write_tag(&mut dialer_control, RELEASE, deadline).await?;

    ensure_success(listener.wait(deadline).await?, "listener")?;
    ensure_success(dialer.wait(deadline).await?, "dialer")?;
    Ok(())
}

async fn run_child_process() -> io::Result<()> {
    let deadline = Instant::now() + TEST_TIMEOUT;
    let kind = match env::var("ASL_TEST_TRANSPORT_KIND").as_deref() {
        Ok("tcp") => TransportKind::Tcp,
        Ok("quic") => TransportKind::Quic,
        _ => return Err(io::Error::other("invalid child transport kind")),
    };
    let role =
        env::var("ASL_TEST_TRANSPORT_ROLE").map_err(|_| io::Error::other("missing child role"))?;
    let control_addr: SocketAddr = env::var("ASL_TEST_TRANSPORT_CONTROL")
        .map_err(|_| io::Error::other("missing control address"))?
        .parse()
        .map_err(|_| io::Error::other("invalid control address"))?;
    let mut control = timeout_at(deadline, TcpStream::connect(control_addr))
        .await
        .map_err(|_| timeout_error())??;

    match role.as_str() {
        "listener" => run_listener_child(&mut control, kind, deadline).await,
        "dialer" => run_dialer_child(&mut control, kind, false, deadline).await,
        "wrong-dialer" => run_dialer_child(&mut control, kind, true, deadline).await,
        _ => Err(io::Error::other("invalid child role")),
    }
}

async fn run_listener_child(
    control: &mut TcpStream,
    kind: TransportKind,
    deadline: Instant,
) -> io::Result<()> {
    let identity = Keypair::generate_ed25519();
    let local_peer = peer_id(&identity);
    let mut transport = LocalTransport::new(identity)?;
    transport.listen(kind, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into())?;
    loop {
        match next_event(&mut transport, deadline).await? {
            TransportEvent::Listening(event_kind, addr) if event_kind == kind => {
                if !addr.ip().is_loopback() || addr.port() == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "listener reported a non-loopback or zero-port address",
                    ));
                }
                write_listener_ready(control, &local_peer, addr, deadline).await?;
                break;
            }
            TransportEvent::Listening(_, _) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "listener reported the wrong transport",
                ));
            }
            _ => continue,
        }
    }

    let expected_dialer = read_peer(control, EXPECTED_PEER, deadline).await?;
    loop {
        match timeout_at(deadline, transport.next_event())
            .await
            .map_err(|_| timeout_error())?
        {
            Ok(TransportEvent::Connected { connection }) => {
                if connection.peer_id() != &expected_dialer {
                    continue;
                }
                write_peer(control, OBSERVED_PEER, connection.peer_id(), deadline).await?;
                return read_tag(control, RELEASE, deadline).await;
            }
            Ok(TransportEvent::Disconnected { .. }) => {
                continue;
            }
            Ok(TransportEvent::InboundRejected) => continue,
            Ok(TransportEvent::Listening(_, _)) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "listener reported an unexpected extra endpoint",
                ));
            }
            Ok(_) => continue,
            Err(error) => return Err(error),
        }
    }
}

async fn run_dialer_child(
    control: &mut TcpStream,
    kind: TransportKind,
    wrong_expected_peer: bool,
    deadline: Instant,
) -> io::Result<()> {
    let identity = Keypair::generate_ed25519();
    let local_peer = peer_id(&identity);
    write_peer(control, HELLO, &local_peer, deadline).await?;
    let (tag, endpoint, expected_peer) = read_dial_command(control, deadline).await?;
    let required_tag = if wrong_expected_peer {
        DIAL_WRONG_PEER
    } else {
        DIAL
    };
    if tag != required_tag || expected_peer == local_peer {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid dial command",
        ));
    }

    let mut transport = LocalTransport::new(identity)?;
    transport.dial(kind, endpoint, &expected_peer)?;
    let event = timeout_at(deadline, transport.next_event())
        .await
        .map_err(|_| timeout_error())?;

    if wrong_expected_peer {
        match event {
            Ok(TransportEvent::DialFailed {
                failure: asl_net::transport::DialFailure::PeerIdentityMismatch,
                ..
            }) => write_tag(control, WRONG_PEER_REJECTED, deadline).await,
            Err(error) => Err(io::Error::new(
                error.kind(),
                "wrong expected PeerId was not rejected as an identity mismatch",
            )),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "dial unexpectedly connected with a wrong expected PeerId",
            )),
        }
    } else {
        match event? {
            TransportEvent::Connected { connection } if connection.peer_id() == &expected_peer => {
                write_peer(control, OBSERVED_PEER, connection.peer_id(), deadline).await?;
                read_tag(control, RELEASE, deadline).await
            }
            TransportEvent::Connected { .. } => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "dialer observed an unexpected authenticated PeerId",
            )),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "dialer received an unexpected transport event",
            )),
        }
    }
}

async fn next_event(
    transport: &mut LocalTransport,
    deadline: Instant,
) -> io::Result<TransportEvent> {
    timeout_at(deadline, transport.next_event())
        .await
        .map_err(|_| timeout_error())?
}

async fn accept_control(listener: &TcpListener, deadline: Instant) -> io::Result<TcpStream> {
    let (stream, _) = timeout_at(deadline, listener.accept())
        .await
        .map_err(|_| timeout_error())??;
    Ok(stream)
}

async fn read_listener_ready(
    stream: &mut TcpStream,
    deadline: Instant,
) -> io::Result<(PeerId, SocketAddr)> {
    let (tag, peer) = read_peer_header(stream, deadline).await?;
    if tag != LISTENER_READY {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected listener-ready message",
        ));
    }
    let mut endpoint = [0; 6];
    read_exact_until(stream, &mut endpoint, deadline).await?;
    let ip = Ipv4Addr::new(endpoint[0], endpoint[1], endpoint[2], endpoint[3]);
    let port = u16::from_be_bytes([endpoint[4], endpoint[5]]);
    let addr = SocketAddrV4::new(ip, port);
    if !ip.is_loopback() || port == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "listener sent an invalid loopback endpoint",
        ));
    }
    Ok((peer, SocketAddr::V4(addr)))
}

async fn read_peer(
    stream: &mut TcpStream,
    expected_tag: u8,
    deadline: Instant,
) -> io::Result<PeerId> {
    let (tag, peer) = read_peer_header(stream, deadline).await?;
    if tag != expected_tag {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected test-control message",
        ));
    }
    Ok(peer)
}

async fn read_peer_header(stream: &mut TcpStream, deadline: Instant) -> io::Result<(u8, PeerId)> {
    let mut header = [0; 2];
    read_exact_until(stream, &mut header, deadline).await?;
    let length = usize::from(header[1]);
    if !(1..=128).contains(&length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid PeerId length in test-control message",
        ));
    }
    let mut bytes = vec![0; length];
    read_exact_until(stream, &mut bytes, deadline).await?;
    let peer = PeerId::from_bytes(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid test PeerId"))?;
    Ok((header[0], peer))
}

async fn read_dial_command(
    stream: &mut TcpStream,
    deadline: Instant,
) -> io::Result<(u8, SocketAddr, PeerId)> {
    let mut header = [0; 8];
    read_exact_until(stream, &mut header, deadline).await?;
    let ip = Ipv4Addr::new(header[1], header[2], header[3], header[4]);
    let port = u16::from_be_bytes([header[5], header[6]]);
    let length = usize::from(header[7]);
    if !ip.is_loopback() || port == 0 || !(1..=128).contains(&length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid dial command endpoint or PeerId length",
        ));
    }
    let mut bytes = vec![0; length];
    read_exact_until(stream, &mut bytes, deadline).await?;
    let expected_peer = PeerId::from_bytes(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid expected PeerId"))?;
    Ok((
        header[0],
        SocketAddr::V4(SocketAddrV4::new(ip, port)),
        expected_peer,
    ))
}

async fn write_listener_ready(
    stream: &mut TcpStream,
    peer: &PeerId,
    addr: SocketAddr,
    deadline: Instant,
) -> io::Result<()> {
    let SocketAddr::V4(addr) = addr else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected an IPv4 loopback listener",
        ));
    };
    let mut message = Vec::with_capacity(2 + peer.as_bytes().len() + 6);
    message.push(LISTENER_READY);
    message.push(peer.as_bytes().len() as u8);
    message.extend_from_slice(peer.as_bytes());
    message.extend_from_slice(&addr.ip().octets());
    message.extend_from_slice(&addr.port().to_be_bytes());
    write_all_until(stream, &message, deadline).await
}

async fn write_peer(
    stream: &mut TcpStream,
    tag: u8,
    peer: &PeerId,
    deadline: Instant,
) -> io::Result<()> {
    let bytes = peer.as_bytes();
    if !(1..=128).contains(&bytes.len()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "PeerId cannot be represented in test-control protocol",
        ));
    }
    let mut message = Vec::with_capacity(2 + bytes.len());
    message.push(tag);
    message.push(bytes.len() as u8);
    message.extend_from_slice(bytes);
    write_all_until(stream, &message, deadline).await
}

async fn write_dial_command(
    stream: &mut TcpStream,
    tag: u8,
    endpoint: SocketAddr,
    expected_peer: &PeerId,
    deadline: Instant,
) -> io::Result<()> {
    let SocketAddr::V4(endpoint) = endpoint else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "test control only supports IPv4 loopback endpoints",
        ));
    };
    let peer_bytes = expected_peer.as_bytes();
    if !(1..=128).contains(&peer_bytes.len()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected PeerId cannot be represented in test-control protocol",
        ));
    }
    let mut message = Vec::with_capacity(8 + peer_bytes.len());
    message.push(tag);
    message.extend_from_slice(&endpoint.ip().octets());
    message.extend_from_slice(&endpoint.port().to_be_bytes());
    message.push(peer_bytes.len() as u8);
    message.extend_from_slice(peer_bytes);
    write_all_until(stream, &message, deadline).await
}

async fn write_tag(stream: &mut TcpStream, tag: u8, deadline: Instant) -> io::Result<()> {
    write_all_until(stream, &[tag], deadline).await
}

async fn read_tag(stream: &mut TcpStream, expected: u8, deadline: Instant) -> io::Result<()> {
    let mut tag = [0];
    read_exact_until(stream, &mut tag, deadline).await?;
    if tag[0] != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected test-control acknowledgement",
        ));
    }
    Ok(())
}

async fn read_exact_until(
    stream: &TcpStream,
    buffer: &mut [u8],
    deadline: Instant,
) -> io::Result<()> {
    let mut read = 0;
    while read < buffer.len() {
        timeout_at(deadline, stream.readable())
            .await
            .map_err(|_| timeout_error())??;
        match stream.try_read(&mut buffer[read..]) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(count) => read += count,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

async fn write_all_until(stream: &TcpStream, buffer: &[u8], deadline: Instant) -> io::Result<()> {
    let mut written = 0;
    while written < buffer.len() {
        timeout_at(deadline, stream.writable())
            .await
            .map_err(|_| timeout_error())??;
        match stream.try_write(&buffer[written..]) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(count) => written += count,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn random_peer_id() -> PeerId {
    peer_id(&Keypair::generate_ed25519())
}

fn peer_id(identity: &Keypair) -> PeerId {
    PeerId::from_bytes(identity.public().to_peer_id().to_bytes())
        .expect("generated ed25519 identity has a valid PeerId")
}

fn transport_name(kind: TransportKind) -> &'static str {
    match kind {
        TransportKind::Tcp => "tcp",
        TransportKind::Quic => "quic",
    }
}

fn timeout_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "two-process test deadline exceeded",
    )
}

fn ensure_success(status: ExitStatus, process: &str) -> io::Result<()> {
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{process} exited with status {status}"
        )))
    }
}

struct ChildGuard {
    child: Child,
    reaped: bool,
}

impl ChildGuard {
    fn spawn(control_addr: &str, kind: TransportKind, role: &str) -> io::Result<Self> {
        let child = Command::new(env::current_exe()?)
            .args(["--exact", "child_process_entry", "--ignored", "--nocapture"])
            .env("ASL_TEST_TRANSPORT_CONTROL", control_addr)
            .env("ASL_TEST_TRANSPORT_KIND", transport_name(kind))
            .env("ASL_TEST_TRANSPORT_ROLE", role)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;
        Ok(Self {
            child,
            reaped: false,
        })
    }

    async fn wait(&mut self, deadline: Instant) -> io::Result<ExitStatus> {
        loop {
            if let Some(status) = self.child.try_wait()? {
                self.reaped = true;
                return Ok(status);
            }
            timeout_at(deadline, sleep(Duration::from_millis(10)))
                .await
                .map_err(|_| timeout_error())?;
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
            self.reaped = true;
        }
    }
}
