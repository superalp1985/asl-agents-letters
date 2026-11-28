//! Core-local library operations. The caller supplies explicit user choices;
//! there is no IPC dispatch, discovery, lease, or disclosure authority here.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use asl_policy::{
    Audience,
    reconcile::{RECONCILE_INTERVAL, ReconcileDriver, ReconcileHints},
};
use asl_store::resources::{DocumentTextExtractor, SnapshotBroker, StoredSnapshotReader};
use asl_types::{
    error::AslError,
    ids::{Hash32, Id128},
    task::{GrantId, ResourceKey},
};

use crate::paths::AppPaths;

// Even a continuously changing directory cannot cause an unpaced polling loop.
const MIN_POLL_GAP: Duration = Duration::from_millis(100);

pub struct LocalLibraries {
    worker: ReconcileWorker,
    broker: SnapshotBroker,
}

impl LocalLibraries {
    pub fn open(paths: &AppPaths) -> Result<Self, AslError> {
        let extractor = Arc::new(SandboxedDocumentExtractor);
        let mut broker = SnapshotBroker::open(paths.dos_root())?;
        broker.set_document_text_extractor(extractor.clone());
        let worker = ReconcileWorker::start(paths.dos_root(), extractor)?;
        Ok(Self { worker, broker })
    }

    /// Register a directory selected by the local user, never by a peer or model.
    pub fn authorize_directory(
        &mut self,
        root: &Path,
        extensions: &[String],
        audience: &Audience,
        max_snapshot_bytes: u64,
    ) -> Result<GrantId, AslError> {
        self.authorize_directory_with_derivation(
            root,
            extensions,
            audience,
            max_snapshot_bytes,
            false,
        )
    }

    pub fn authorize_directory_with_derivation(
        &mut self,
        root: &Path,
        extensions: &[String],
        audience: &Audience,
        max_snapshot_bytes: u64,
        allow_derived_disclosure: bool,
    ) -> Result<GrantId, AslError> {
        self.check_health()?;
        let grant = self.broker.authorize_directory_with_derivation(
            root,
            extensions,
            audience,
            max_snapshot_bytes,
            allow_derived_disclosure,
        )?;
        self.worker.grants_changed();
        Ok(grant)
    }

    pub fn authorize_inbox_directory(
        &mut self,
        root: &Path,
        max_bytes: u64,
    ) -> Result<Id128, AslError> {
        self.check_health()?;
        self.broker.authorize_inbox_directory(root, max_bytes)
    }

    pub fn authorize_derived_directory(
        &mut self,
        root: &Path,
        max_bytes: u64,
    ) -> Result<Id128, AslError> {
        self.check_health()?;
        self.broker.authorize_derived_directory(root, max_bytes)
    }

    pub fn revoke_inbox_directory(&mut self, grant: Id128) -> Result<(), AslError> {
        self.check_health()?;
        self.broker.revoke_inbox_directory(grant)
    }

    pub fn revoke_derived_directory(&mut self, grant: Id128) -> Result<(), AslError> {
        self.check_health()?;
        self.broker.revoke_derived_directory(grant)
    }

    /// Import only through a stored grant. A resource key is not a read permit.
    pub fn import_source(
        &mut self,
        grant: &GrantId,
        relative: &Path,
    ) -> Result<ResourceKey, AslError> {
        self.check_health()?;
        let key = self
            .broker
            .import_with_progress(grant, relative, || self.worker.check_health())?;
        // An empty grant only becomes watchable after its first committed import.
        self.worker.watches_dirty.store(true, Ordering::Release);
        self.worker.hints.changed(key.clone());
        Ok(key)
    }

    pub fn open_snapshot(&self, content_id: Hash32) -> Result<StoredSnapshotReader, AslError> {
        self.broker.open_snapshot(content_id)
    }

    pub fn revoke_directory(&mut self, grant: &GrantId) -> Result<(), AslError> {
        // Revocation remains possible even when reconciliation has failed.
        self.broker.revoke_directory(grant)?;
        self.worker.grants_changed();
        Ok(())
    }

    /// A background error is terminal for this runtime. Never infer a valid
    /// source or a lease from a successful health check.
    pub fn check_health(&mut self) -> Result<(), AslError> {
        self.worker.check_health()
    }
}

struct ReconcileWorker {
    stop: SyncSender<()>,
    cancel: Arc<AtomicBool>,
    hints: ReconcileHints,
    watches_dirty: Arc<AtomicBool>,
    handle: Option<JoinHandle<Result<(), AslError>>>,
}

impl ReconcileWorker {
    fn start(
        home: &Path,
        document_text_extractor: Arc<dyn DocumentTextExtractor>,
    ) -> Result<Self, AslError> {
        let mut broker = SnapshotBroker::open(home)?;
        broker.set_document_text_extractor(document_text_extractor);
        let cancel = Arc::new(AtomicBool::new(false));
        broker.set_reconcile_stop(Arc::clone(&cancel));
        let mut last_periodic = Instant::now();
        let mut driver = ReconcileDriver::new(last_periodic);
        broker.sync_watches(&mut driver)?;
        let hints = driver.hints();
        let cancelled = Arc::clone(&cancel);
        let watches_dirty = Arc::new(AtomicBool::new(false));
        let dirty = Arc::clone(&watches_dirty);
        let (stop, stopping) = mpsc::sync_channel(1);
        let handle = thread::Builder::new()
            .name("asl-source-reconcile".into())
            .spawn(move || {
                loop {
                    driver.wait_for_work();
                    if cancelled.load(Ordering::Acquire) {
                        return Ok(());
                    }
                    let now = Instant::now();
                    let periodic = now.duration_since(last_periodic) >= RECONCILE_INTERVAL;
                    if periodic {
                        last_periodic = now;
                    }
                    if dirty.swap(false, Ordering::AcqRel) || periodic {
                        broker.sync_watches(&mut driver)?;
                    }
                    driver.poll(now, &mut broker)?;
                    if stopping.recv_timeout(MIN_POLL_GAP) != Err(RecvTimeoutError::Timeout) {
                        return Ok(());
                    }
                }
            })?;
        Ok(Self {
            stop,
            cancel,
            hints,
            watches_dirty,
            handle: Some(handle),
        })
    }

    fn grants_changed(&self) {
        self.watches_dirty.store(true, Ordering::Release);
        self.hints.rescan();
    }

    fn check_health(&mut self) -> Result<(), AslError> {
        let handle = self.handle.as_ref().ok_or(AslError::InvalidPolicyState)?;
        if handle.is_finished() {
            self.join()?;
            return Err(AslError::InvalidPolicyState);
        }
        Ok(())
    }

    fn join(&mut self) -> Result<(), AslError> {
        self.handle
            .take()
            .ok_or(AslError::InvalidPolicyState)?
            .join()
            .map_err(|_| AslError::InvalidPolicyState)?
    }
}

struct SandboxedDocumentExtractor;

impl DocumentTextExtractor for SandboxedDocumentExtractor {
    fn max_input_bytes(&self) -> u64 {
        crate::ipc::MAX_IPC_EXTRACTOR_INPUT_BYTES as u64
    }

    fn supports(&self, relative: &Path, length: u64) -> bool {
        length <= self.max_input_bytes()
            && relative
                .extension()
                .and_then(|value| value.to_str())
                .is_some_and(|extension| {
                    matches!(
                        extension.to_ascii_lowercase().as_str(),
                        "pdf" | "docx" | "xlsx" | "pptx"
                    )
                })
    }

    fn extract(&self, bytes: &[u8]) -> Result<Option<String>, AslError> {
        match crate::supervisor::extract_document_text_once(bytes) {
            Ok(text) if !text.is_empty() => Ok(Some(text)),
            Ok(_) | Err(_) => Ok(None),
        }
    }
}

impl Drop for ReconcileWorker {
    fn drop(&mut self) {
        if self.handle.is_some() {
            self.cancel.store(true, Ordering::Release);
            let _ = self.stop.try_send(());
            self.hints.rescan();
            let _ = self.join();
        }
    }
}
