use std::{
    io,
    path::PathBuf,
    sync::mpsc,
    thread::{self, JoinHandle},
    time::Duration,
};

use asl_policy::LocalPipeServer;
use asl_types::error::AslError;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::oneshot,
    time::{sleep, timeout},
};

use crate::{OutgoingQueryPort, downloads::DownloadPort};

use super::{contract::Request, grant::HostGrant, secure::SecurePipe, session::Session};

const IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const FIRST_REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct McpWorker {
    stop: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl McpWorker {
    pub fn spawn(
        root: PathBuf,
        grant: HostGrant,
        queries: OutgoingQueryPort,
        downloads: DownloadPort,
    ) -> Result<Self, AslError> {
        let (ready, started) = mpsc::channel();
        let (stop, stopped) = oneshot::channel();
        let thread = thread::Builder::new()
            .name("asl-mcp-bridge".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = ready.send(Err(error.into()));
                        return;
                    }
                };
                runtime.block_on(async {
                    let mut listener = match LocalPipeServer::bind(&root) {
                        Ok(listener) => listener,
                        Err(error) => {
                            let _ = ready.send(Err(error));
                            return;
                        }
                    };
                    if ready.send(Ok(())).is_ok() {
                        tokio::select! {
                            _ = stopped => {}
                            _ = listen(&mut listener, &grant, &queries, &downloads) => {}
                        }
                    }
                });
            })?;
        let worker = Self {
            stop: Some(stop),
            thread: Some(thread),
        };
        started.recv().map_err(|_| AslError::SandboxUnavailable)??;
        Ok(worker)
    }
}

impl Drop for McpWorker {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

async fn listen(
    listener: &mut LocalPipeServer,
    grant: &HostGrant,
    queries: &OutgoingQueryPort,
    downloads: &DownloadPort,
) {
    loop {
        match listener.accept().await {
            Ok(mut connection) => {
                let _ = serve(connection.stream(), grant, queries, downloads).await;
            }
            Err(AslError::Io(error)) if error.kind() == io::ErrorKind::NotConnected => return,
            Err(_) => sleep(Duration::from_millis(50)).await,
        }
    }
}

async fn serve(
    stream: impl AsyncRead + AsyncWrite + Unpin,
    grant: &HostGrant,
    queries: &OutgoingQueryPort,
    downloads: &DownloadPort,
) -> Result<(), AslError> {
    let mut pipe = SecurePipe::respond(stream, &grant.key).await?;
    let mut session = Session::new(queries, downloads, grant.scope, grant.inbox);
    let mut read_deadline = FIRST_REQUEST_TIMEOUT;
    loop {
        let request = timeout(read_deadline, pipe.receive::<Request>())
            .await
            .map_err(|_| AslError::ExpiredMessage)??;
        read_deadline = IDLE_TIMEOUT;
        let reply = session.call(request).await;
        timeout(RESPONSE_TIMEOUT, pipe.send(&reply))
            .await
            .map_err(|_| AslError::ExpiredMessage)??;
    }
}
