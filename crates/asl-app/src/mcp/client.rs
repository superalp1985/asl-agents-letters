use std::{io, path::PathBuf, sync::Arc, time::Duration};

use asl_policy::{connect_local_pipe, connect_recovery_pipe};
use asl_types::error::{AslError, ErrorCode};
use serde_json::Value;
use tokio::{
    net::windows::named_pipe::NamedPipeClient,
    sync::{Mutex, Semaphore, mpsc, oneshot, watch},
    task::JoinHandle,
    time::timeout,
};

use super::{
    contract::{Request, ServerFrame},
    grant::Key,
    inbox::Inbox,
    secure::SecurePipe,
};

const CALL_TIMEOUT: Duration = Duration::from_secs(20);
const OPEN_TIMEOUT: Duration = Duration::from_secs(3);

pub(super) struct Client {
    root: PathBuf,
    key: Option<Key>,
    recovery: bool,
    connection: Mutex<Option<Connection>>,
    opening: Arc<Semaphore>,
    events: watch::Sender<Inbox>,
}

impl Client {
    pub(super) fn new(root: PathBuf, key: Option<Key>, recovery: bool) -> Self {
        Self {
            root,
            key,
            recovery,
            connection: Mutex::new(None),
            opening: Arc::new(Semaphore::new(1)),
            events: watch::Sender::new(Inbox::default()),
        }
    }

    pub(super) fn has_key(&self) -> bool {
        self.key.is_some()
    }

    pub(super) fn is_recovery(&self) -> bool {
        self.recovery
    }

    pub(super) fn events(&self) -> watch::Receiver<Inbox> {
        self.events.subscribe()
    }

    pub(super) async fn call(&self, request: Request) -> Result<Value, ErrorCode> {
        let key = self.key.as_ref().ok_or(ErrorCode::PolicyDenied)?;
        let mut slot = self.connection.try_lock().map_err(|_| ErrorCode::Busy)?;
        // Keep the existing one-call contract. A cancelled or failed call
        // drops the attachment rather than reusing a pipe with a pending reply.
        let connection = match slot.take() {
            Some(connection) if !connection.calls.is_closed() => connection,
            _ => {
                self.events.send_replace(Inbox::default());
                let mut connection = self.attach(key).await?;
                match connection.request(Request::LocalCapabilities).await {
                    Ok(Ok(caps)) => connection.capabilities = caps,
                    Ok(Err(_)) => {}
                    // Older Core releases close on an unknown operation. It is
                    // safe to reconnect here, before submitting any host work.
                    Err(_) if !self.recovery => {
                        drop(connection);
                        connection = self.attach(key).await?;
                    }
                    Err(code) => return Err(code),
                }
                connection
            }
        };
        let reply = match &request {
            Request::LocalCapabilities => Ok(connection.capabilities.clone()),
            Request::SendExpression(_) if connection.capabilities["send_expression"] != true => {
                Err(ErrorCode::PolicyDenied)
            }
            Request::ReceiveOffer(_) if connection.capabilities["receive_offer"] != true => {
                Err(ErrorCode::PolicyDenied)
            }
            Request::RecoveryTask(_) | Request::RecoveryEvents(_)
                if connection.capabilities["task_recovery"] != true =>
            {
                Err(ErrorCode::PolicyDenied)
            }
            Request::RecoveryQuery(_) if connection.capabilities["recovery_query"] != true => {
                Err(ErrorCode::PolicyDenied)
            }
            Request::RecoveryResult(_) if connection.capabilities["recovery_results"] != true => {
                Err(ErrorCode::PolicyDenied)
            }
            Request::RecoveryDownload(_)
                if connection.capabilities["recovery_download"] != true =>
            {
                Err(ErrorCode::PolicyDenied)
            }
            Request::RecoveryDownloadDecision(_)
                if connection.capabilities["recovery_download_decision"] != true =>
            {
                Err(ErrorCode::PolicyDenied)
            }
            Request::AgentEventsAvailable
            | Request::SubscribeAgentEvents
            | Request::UnsubscribeAgentEvents
                if !connection.capabilities.is_object() =>
            {
                Err(ErrorCode::IncompatibleVersion)
            }
            _ => connection.request(request).await?,
        };
        *slot = Some(connection);
        reply
    }

    async fn attach(&self, key: &[u8; 32]) -> Result<Connection, ErrorCode> {
        let stream = self.open().await?;
        let pipe = SecurePipe::initiate(stream, key)
            .await
            .map_err(|_| ErrorCode::PolicyDenied)?;
        Ok(Connection::new(pipe, self.events.clone()))
    }

    async fn open(&self) -> Result<NamedPipeClient, ErrorCode> {
        let permit = Arc::clone(&self.opening)
            .try_acquire_owned()
            .map_err(|_| ErrorCode::Busy)?;
        let root = self.root.clone();
        let recovery = self.recovery;
        let runtime = tokio::runtime::Handle::current();
        // NTFS traversal and pipe ownership checks are synchronous. Keep the
        // slot occupied until the OS call returns, even if its caller cancels.
        let attempt = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _context = runtime.enter();
            if recovery {
                connect_recovery_pipe(&root)
            } else {
                connect_local_pipe(&root)
            }
        });
        timeout(OPEN_TIMEOUT, attempt)
            .await
            .map_err(|_| ErrorCode::Timeout)?
            .map_err(|_| ErrorCode::InternalError)?
            .map_err(|error| match error {
                AslError::PolicyDenied => ErrorCode::PolicyDenied,
                AslError::Io(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                    ErrorCode::PolicyDenied
                }
                _ => ErrorCode::Offline,
            })
    }
}

type Reply = Result<Value, ErrorCode>;

struct Call {
    request: Request,
    reply: oneshot::Sender<Result<Reply, AslError>>,
}

struct Connection {
    calls: mpsc::Sender<Call>,
    driver: JoinHandle<()>,
    capabilities: Value,
}

impl Connection {
    fn new(pipe: SecurePipe<NamedPipeClient>, events: watch::Sender<Inbox>) -> Self {
        let (calls, pending) = mpsc::channel(1);
        Self {
            calls,
            capabilities: Value::Null,
            driver: tokio::spawn(async move {
                let _ = Self::drive(pipe, pending, events).await;
            }),
        }
    }

    async fn request(&self, request: Request) -> Result<Reply, ErrorCode> {
        let (reply, answer) = oneshot::channel();
        self.calls
            .try_send(Call { request, reply })
            .map_err(|_| ErrorCode::Offline)?;
        timeout(CALL_TIMEOUT, answer)
            .await
            .map_err(|_| ErrorCode::Timeout)?
            .map_err(|_| ErrorCode::Offline)?
            .map_err(pipe_error)
    }

    async fn drive(
        mut pipe: SecurePipe<NamedPipeClient>,
        mut calls: mpsc::Receiver<Call>,
        events: watch::Sender<Inbox>,
    ) -> Result<(), AslError> {
        let mut subscribed = false;
        loop {
            tokio::select! {
                biased;
                call = calls.recv() => {
                    let Some(Call { request, reply }) = call else {
                        return Ok(());
                    };
                    let result = async {
                        pipe.send(&request).await?;
                        loop {
                            match pipe.receive::<ServerFrame>().await? {
                                ServerFrame::Reply(result) => return Ok(result),
                                frame => publish(frame, subscribed, &events)?,
                            }
                        }
                    }.await;
                    let stop = result.is_err();
                    if result.as_ref().is_ok_and(Result::is_ok) {
                        match request {
                            Request::SubscribeAgentEvents => subscribed = true,
                            Request::UnsubscribeAgentEvents => {
                                subscribed = false;
                                events.send_replace(Inbox::default());
                            }
                            _ => {}
                        }
                    }
                    if reply.send(result).is_err() || stop {
                        return Ok(());
                    }
                }
                frame = pipe.receive::<ServerFrame>() => publish(frame?, subscribed, &events)?,
            }
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

fn publish(
    frame: ServerFrame,
    subscribed: bool,
    events: &watch::Sender<Inbox>,
) -> Result<(), AslError> {
    match frame {
        ServerFrame::AgentEvent { event } if subscribed => {
            events.send_modify(|inbox| inbox.push(event));
            Ok(())
        }
        ServerFrame::AgentEventLoss { dropped } if subscribed && dropped != 0 => {
            events.send_modify(|inbox| inbox.lose(dropped));
            Ok(())
        }
        _ => Err(AslError::InvalidMessage),
    }
}

fn pipe_error(error: AslError) -> ErrorCode {
    match error {
        AslError::PolicyDenied => ErrorCode::PolicyDenied,
        AslError::QuotaExceeded => ErrorCode::QuotaExceeded,
        _ => ErrorCode::Offline,
    }
}
