use std::{
    path::PathBuf,
    sync::mpsc::{self, Receiver, SyncSender, TryRecvError},
    thread,
    time::{Duration, Instant},
};

use asl_types::error::AslError;

use crate::network_identity::read_signed_device_directory;

const POLL_INTERVAL: Duration = Duration::from_secs(10);
pub(super) type DirectoryRead = Result<Option<Vec<u8>>, AslError>;

pub(super) struct DirectoryReader {
    request: SyncSender<()>,
    result: Receiver<DirectoryRead>,
    next_read: Instant,
    reading: bool,
}

impl DirectoryReader {
    pub(super) fn spawn(path: PathBuf) -> Result<Self, AslError> {
        let (request, wake) = mpsc::sync_channel(1);
        let (finished, result) = mpsc::sync_channel(1);
        thread::Builder::new()
            .name("asl-directory-reader".into())
            .spawn(move || {
                while wake.recv().is_ok() {
                    if finished.send(read_signed_device_directory(&path)).is_err() {
                        break;
                    }
                }
            })?;
        Ok(Self {
            request,
            result,
            next_read: Instant::now() + POLL_INTERVAL,
            reading: false,
        })
    }

    pub(super) fn request_refresh(&mut self) {
        self.next_read = Instant::now();
    }

    pub(super) fn poll(&mut self, now: Instant) -> Option<DirectoryRead> {
        if self.reading {
            match self.result.try_recv() {
                Ok(result) => {
                    self.reading = false;
                    return Some(result);
                }
                Err(TryRecvError::Empty) => return None,
                Err(TryRecvError::Disconnected) => {
                    self.reading = false;
                    return Some(Err(AslError::InvalidPolicyState));
                }
            }
        }
        if now >= self.next_read {
            self.next_read = now + POLL_INTERVAL;
            self.reading = self.request.try_send(()).is_ok();
        }
        None
    }
}
