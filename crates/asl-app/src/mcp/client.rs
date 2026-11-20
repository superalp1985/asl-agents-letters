use std::{io, path::PathBuf, sync::Arc, time::Duration};

use asl_policy::connect_local_pipe;
use asl_types::error::{AslError, ErrorCode};
use serde_json::Value;
use tokio::{
    net::windows::named_pipe::NamedPipeClient,
    sync::{Mutex, Semaphore},
    time::timeout,
};

use super::{contract::Request, grant::Key, secure::SecurePipe};

const CALL_TIMEOUT: Duration = Duration::from_secs(20);
const OPEN_TIMEOUT: Duration = Duration::from_secs(3);

pub(super) struct Client {
    root: PathBuf,
    key: Option<Key>,
    connection: Mutex<Option<SecurePipe<NamedPipeClient>>>,
    opening: Arc<Semaphore>,
}

impl Client {
    pub(super) fn new(root: PathBuf, key: Option<Key>) -> Self {
        Self {
            root,
            key,
            connection: Mutex::new(None),
            opening: Arc::new(Semaphore::new(1)),
        }
    }

    pub(super) async fn call(&self, request: Request) -> Result<Value, ErrorCode> {
        let key = self.key.as_ref().ok_or(ErrorCode::PolicyDenied)?;
        let mut connection = self.connection.try_lock().map_err(|_| ErrorCode::Busy)?;
        if connection.is_none() {
            let stream = self.open().await?;
            *connection = Some(
                SecurePipe::initiate(stream, key)
                    .await
                    .map_err(|_| ErrorCode::PolicyDenied)?,
            );
        }

        // A cancelled or failed caller must not reuse a half-read response.
        let mut pipe = connection.take().ok_or(ErrorCode::InternalError)?;
        let reply = timeout(CALL_TIMEOUT, async {
            pipe.send(&request).await?;
            pipe.receive::<Result<Value, ErrorCode>>().await
        })
        .await
        .map_err(|_| ErrorCode::Timeout)?
        .map_err(|error| match error {
            AslError::PolicyDenied => ErrorCode::PolicyDenied,
            AslError::QuotaExceeded => ErrorCode::QuotaExceeded,
            _ => ErrorCode::Offline,
        })?;
        *connection = Some(pipe);
        reply
    }

    async fn open(&self) -> Result<NamedPipeClient, ErrorCode> {
        let permit = Arc::clone(&self.opening)
            .try_acquire_owned()
            .map_err(|_| ErrorCode::Busy)?;
        let root = self.root.clone();
        let runtime = tokio::runtime::Handle::current();
        // NTFS traversal and pipe ownership checks are synchronous. Keep the
        // slot occupied until the OS call returns, even if its caller cancels.
        let attempt = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _context = runtime.enter();
            connect_local_pipe(&root)
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
