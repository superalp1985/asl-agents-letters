#![cfg(windows)]

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use asl_policy::{LocalPipeServer, connect_local_pipe};
use asl_types::error::AslError;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{sleep, timeout};
use windows::Win32::Foundation::{ERROR_NO_DATA, ERROR_PIPE_BUSY};

const CHILD_ROOT: &str = "ASL_TEST_LOCAL_PIPE_CHILD_ROOT";
const TEST_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::test]
async fn local_pipe_round_trips_across_processes_and_reaccepts() {
    let root = tempfile::tempdir().unwrap();
    let mut listener = LocalPipeServer::bind(root.path()).unwrap();

    for _ in 0..2 {
        let mut child = TestChild(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "local_pipe_client_child"])
                .env(CHILD_ROOT, root.path())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .spawn()
                .unwrap(),
        );

        timeout(TEST_TIMEOUT, async {
            let mut connection = listener.accept().await.unwrap();
            let stream = connection.stream();
            let mut request = [0; 4];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").await.unwrap();
            loop {
                if let Some(status) = child.0.try_wait().unwrap() {
                    assert!(status.success(), "{status}");
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("cross-process pipe exchange timed out");
    }
}

#[tokio::test]
async fn local_pipe_client_child() {
    let Some(root) = std::env::var_os(CHILD_ROOT) else {
        return;
    };
    let mut client = connect_local_pipe(Path::new(&root)).unwrap();
    timeout(TEST_TIMEOUT, async {
        client.write_all(b"ping").await.unwrap();
        let mut reply = [0; 4];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"pong");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn local_pipe_rejects_duplicate_bind_and_scopes_by_directory_identity() {
    let workspace = tempfile::tempdir().unwrap();
    let first = workspace.path().join("first");
    let second = workspace.path().join("second");
    for root in [&first, &second] {
        std::fs::create_dir(root).unwrap();
    }

    let mut listener = LocalPipeServer::bind(&first).unwrap();
    assert!(LocalPipeServer::bind(&first).is_err());
    assert!(connect_local_pipe(&second).is_err());
    let other = LocalPipeServer::bind(&second).unwrap();

    let client = connect_local_pipe(&first).unwrap();
    let connection = timeout(TEST_TIMEOUT, listener.accept())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        connect_local_pipe(&first),
        Err(AslError::Io(error)) if error.raw_os_error() == Some(ERROR_PIPE_BUSY.0 as i32)
    ));
    drop((connection, client, other));
}

#[tokio::test]
async fn local_pipe_can_accept_after_client_exits_before_accept() {
    let root = tempfile::tempdir().unwrap();
    let mut listener = LocalPipeServer::bind(root.path()).unwrap();
    drop(connect_local_pipe(root.path()).unwrap());
    // Windows can report a departed client as a disconnected instance, or
    // complete the connection and deliver EOF if I/O already owns a handle.
    match timeout(TEST_TIMEOUT, listener.accept()).await.unwrap() {
        Ok(connection) => drop(connection),
        Err(AslError::Io(error)) => assert_eq!(error.raw_os_error(), Some(ERROR_NO_DATA.0 as i32)),
        Err(error) => panic!("{error}"),
    }
    // On a recycled instance, poll accept to make it listen before opening.
    let (connection, _client) = timeout(TEST_TIMEOUT, async {
        tokio::join!(biased; listener.accept(), async {
            connect_local_pipe(root.path()).unwrap()
        })
    })
    .await
    .unwrap();
    connection.unwrap();
}

#[tokio::test]
async fn local_pipe_does_not_create_a_missing_home() {
    let workspace = tempfile::tempdir().unwrap();
    let absent = workspace.path().join("absent");
    assert!(connect_local_pipe(&absent).is_err());
    assert!(!absent.exists());
}

struct TestChild(Child);

impl Drop for TestChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
