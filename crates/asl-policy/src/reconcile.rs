//! Broker-local reconciliation of existing imports, never discovery or authorization.
//! A watcher adapter may post hints; even without one, `wait_for_work` and `poll`
//! on a broker worker run a startup sweep and schedule a fresh sweep every 30s.
//! This interval schedules work; it is not a deadline for hashing all sources.

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use asl_types::error::AslError;
use asl_types::ids::Hash32;
use asl_types::manifest::CHUNK_SIZE;
use asl_types::task::ResourceKey;

#[cfg(windows)]
use crate::platform::windows::reconcile_watch::DirectoryWatch;
use crate::{AuthorizedFile, FileIdentity, SourceGrant};

pub const RECONCILE_INTERVAL: Duration = Duration::from_secs(30);
pub const HINT_CAPACITY: usize = 64;
pub const PAGE_SIZE: usize = 16;
pub const MAX_WATCHED_ROOTS: usize = 64;
#[cfg(windows)]
const WATCH_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub enum SourceCheck {
    /// Leave the existing reference alone. Never activate a ref or grant a lease.
    Unchanged,
    /// Conditionally deactivate this import, not every ref to the same snapshot.
    Deactivate,
}

/// Pass the result of restoring the stored local grant and opening a **fresh**
/// authorized file. Compare snapshots.file_hash (BLAKE3 of bytes), not content_id
/// (BLAKE3 of the manifest). An operational error is not evidence of a match.
pub fn check_source(
    opened: Result<AuthorizedFile, AslError>,
    expected_identity: &FileIdentity,
    expected_len: u64,
    expected_file_hash: &Hash32,
) -> Result<SourceCheck, AslError> {
    check_source_with_progress(
        opened,
        expected_identity,
        expected_len,
        expected_file_hash,
        || Ok(()),
    )
}

/// Like [`check_source`], but calls `progress` before every read, including the
/// EOF check. Each read is at most 1 MiB. A hook error is returned directly.
pub fn check_source_with_progress(
    opened: Result<AuthorizedFile, AslError>,
    expected_identity: &FileIdentity,
    expected_len: u64,
    expected_file_hash: &Hash32,
    progress: impl FnMut() -> Result<(), AslError>,
) -> Result<SourceCheck, AslError> {
    let mut file = match opened {
        Ok(file) => file,
        Err(
            AslError::NotFound
            | AslError::GrantRevoked
            | AslError::PolicyDenied
            | AslError::InvalidStorageRoot,
        ) => {
            return Ok(SourceCheck::Deactivate);
        }
        Err(error) => return Err(error),
    };
    if file.identity() != expected_identity || file.len() != expected_len {
        return Ok(SourceCheck::Deactivate);
    }
    check_contents(&mut file, expected_len, expected_file_hash, progress)
}

fn check_contents(
    file: &mut impl io::Read,
    expected_len: u64,
    expected_file_hash: &Hash32,
    mut progress: impl FnMut() -> Result<(), AslError>,
) -> Result<SourceCheck, AslError> {
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0; expected_len.clamp(1, u64::from(CHUNK_SIZE)) as usize];
    let mut remaining = expected_len;
    loop {
        progress()?;
        let limit = remaining.clamp(1, buffer.len() as u64) as usize;
        let n = match file.read(&mut buffer[..limit]) {
            Ok(0) => break,
            Ok(n) => n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };
        if n as u64 > remaining {
            return Ok(SourceCheck::Deactivate);
        }
        hasher.update(&buffer[..n]);
        remaining -= n as u64;
    }
    Ok(
        if remaining == 0 && hasher.finalize().as_bytes() == expected_file_hash.as_bytes() {
            SourceCheck::Unchanged
        } else {
            SourceCheck::Deactivate
        },
    )
}

/// Keyset page for active local imports. Its bounds are set by the driver.
pub struct ActivePage {
    rows: Vec<(i64, ResourceKey)>,
    after: Option<i64>,
    through: i64,
}

impl ActivePage {
    /// A malformed or oversized DB page is an error, not end-of-scan.
    pub fn push(&mut self, row: i64, key: ResourceKey) -> Result<(), AslError> {
        let previous = self.rows.last().map(|r| r.0).or(self.after);
        if self.rows.len() >= PAGE_SIZE || row > self.through || previous.is_some_and(|p| row <= p)
        {
            return Err(AslError::InvalidDatabase);
        }
        self.rows.push((row, key));
        Ok(())
    }
}

pub trait ReconcileBackend {
    /// MAX(row_id) for active local imports only. None means empty.
    fn last_active_row(&mut self) -> Result<Option<i64>, AslError>;

    /// Same filter, `after < row_id <= through`, ORDER BY row_id LIMIT PAGE_SIZE.
    /// None omits the lower bound. Push rows directly, propagating push errors.
    /// An empty page means exhausted. Release the read transaction before hashing.
    fn active_page(
        &mut self,
        after: Option<i64>,
        through: i64,
        page: &mut ActivePage,
    ) -> Result<(), AslError>;

    /// Re-read the active local import by key; ignore unknown/remote/inactive
    /// rows. Restore its grant and reopen the locally recorded relative source.
    /// On `Deactivate`, atomically invalidate only the still-matching binding
    /// (key, grant/epoch, identity, snapshot); a reimport must not lose a race.
    /// On operational errors fail closed for new leases and surface the error.
    fn reconcile_one(&mut self, key: &ResourceKey) -> Result<(), AslError>;
}

#[derive(Default)]
struct Pending {
    keys: VecDeque<ResourceKey>,
    rescan: bool,
}

impl Pending {
    fn request_scan(&mut self) {
        self.keys.clear();
        self.rescan = true;
    }
}

#[derive(Default)]
struct Mailbox {
    state: Mutex<Pending>,
    wake: Condvar,
}

/// Clone into local watcher callbacks. No paths, filesystem reads, or DB work
/// cross this boundary. The lock is never held across broker operations.
#[derive(Clone)]
pub struct ReconcileHints(Arc<Mailbox>);

impl ReconcileHints {
    /// Use only for a resource key already mapped locally by the broker.
    pub fn changed(&self, key: ResourceKey) {
        let mut pending = self.0.state.lock().unwrap();
        if pending.rescan || pending.keys.contains(&key) {
            return;
        }
        if pending.keys.len() == HINT_CAPACITY {
            pending.request_scan();
        } else {
            pending.keys.push_back(key);
        }
        self.0.wake.notify_one();
    }

    /// Use for lost, ambiguous, unmapped or overflowed filesystem notifications.
    pub fn rescan(&self) {
        let mut pending = self.0.state.lock().unwrap();
        if !pending.rescan {
            pending.request_scan();
            self.0.wake.notify_one();
        }
    }
}

#[derive(Clone, Copy)]
struct Sweep {
    after: Option<i64>,
    through: i64,
}

/// Single consumer; the caller owns worker lifetime and error handling.
pub struct ReconcileDriver {
    hints: ReconcileHints,
    last_tick: Instant,
    sweep: Option<Sweep>,
    #[cfg(windows)]
    watches: Vec<(FileIdentity, DirectoryWatch)>,
    #[cfg(windows)]
    last_sample: Instant,
    watch_failure: Option<(FileIdentity, io::Error)>,
}

impl ReconcileDriver {
    pub fn new(now: Instant) -> Self {
        let hints = ReconcileHints(Arc::new(Mailbox::default()));
        hints.rescan();
        Self {
            hints,
            last_tick: now,
            sweep: None,
            #[cfg(windows)]
            watches: Vec::new(),
            #[cfg(windows)]
            last_sample: now,
            watch_failure: None,
        }
    }

    /// Attach to a locally validated root, not a path supplied by an event.
    /// Idempotent by directory identity (shared by grants for the same root).
    /// Registration failure does not disable the independent periodic sweep.
    pub fn watch_grant(&mut self, grant: &SourceGrant) -> Result<(), AslError> {
        #[cfg(windows)]
        {
            if self.watches.iter().any(|(id, _)| id == grant.identity()) {
                return Ok(());
            }
            if self.watches.len() == MAX_WATCHED_ROOTS {
                return Err(AslError::QuotaExceeded);
            }
            self.watches
                .push((grant.identity().clone(), grant.directory_watch()?));
            Ok(())
        }
        #[cfg(not(windows))]
        {
            let _ = grant;
            Err(AslError::PlatformUnavailable)
        }
    }

    /// Detach when no active local grant still needs this root.
    pub fn unwatch_grant(&mut self, identity: &FileIdentity) -> bool {
        #[cfg(windows)]
        if let Some(index) = self.watches.iter().position(|(id, _)| id == identity) {
            self.watches.swap_remove(index);
            return true;
        }
        let _ = identity;
        false
    }

    /// Close watches outside the broker's active root set; never open new ones.
    pub fn retain_watches(&mut self, identities: &[FileIdentity]) {
        #[cfg(windows)]
        self.watches.retain(|(id, _)| identities.contains(id));
        #[cfg(not(windows))]
        let _ = identities;
    }

    /// A failed native watch is dropped and requests a fallback sweep. At most
    /// one diagnostic is retained; the broker can reattach its active roots.
    pub fn take_watch_failure(&mut self) -> Option<(FileIdentity, io::Error)> {
        self.watch_failure.take()
    }

    #[cfg(windows)]
    fn sample_watches(&mut self, now: Instant) {
        if self.watches.is_empty()
            || now.saturating_duration_since(self.last_sample) < WATCH_INTERVAL
        {
            return;
        }
        self.last_sample = now;
        let mut dirty = false;
        self.watches
            .retain_mut(|(id, watch)| match watch.take_change() {
                Ok(changed) => {
                    dirty |= changed;
                    true
                }
                Err(error) => {
                    dirty = true;
                    self.watch_failure
                        .get_or_insert_with(|| (id.clone(), error));
                    false
                }
            });
        if dirty {
            self.hints.rescan();
        }
    }

    pub fn hints(&self) -> ReconcileHints {
        self.hints.clone()
    }

    /// Optional blocking wait before `poll(Instant::now(), backend)`. Wakes for
    /// pending pages, hints, or the deadline, even if no watcher ever fires.
    pub fn wait_for_work(&self) {
        if self.sweep.is_some() {
            return;
        }
        let mailbox = &self.hints.0;
        let pending = mailbox.state.lock().unwrap();
        let timeout = RECONCILE_INTERVAL.saturating_sub(self.last_tick.elapsed());
        #[cfg(windows)]
        let timeout = if self.watches.is_empty() {
            timeout
        } else {
            timeout.min(WATCH_INTERVAL.saturating_sub(self.last_sample.elapsed()))
        };
        drop(
            mailbox
                .wake
                .wait_timeout_while(pending, timeout, |p| !p.rescan && p.keys.is_empty())
                .unwrap(),
        );
    }

    /// Run at most one targeted check and one bounded DB page. Use monotonic
    /// time from the same clock as `new`. A tick never rewinds an ongoing sweep.
    /// Handle errors before polling again (stop or back off on DB failure).
    pub fn poll(
        &mut self,
        now: Instant,
        backend: &mut impl ReconcileBackend,
    ) -> Result<(), AslError> {
        #[cfg(windows)]
        self.sample_watches(now);
        let (start, key) = {
            let mut pending = self.hints.0.state.lock().unwrap();
            if now.saturating_duration_since(self.last_tick) >= RECONCILE_INTERVAL {
                self.last_tick = now;
                pending.request_scan();
            }
            let start = self.sweep.is_none() && std::mem::take(&mut pending.rescan);
            (start, pending.keys.pop_front())
        };
        if start {
            match backend.last_active_row() {
                Ok(tail) => {
                    self.sweep = tail.map(|through| Sweep {
                        after: None,
                        through,
                    })
                }
                Err(error) => {
                    self.hints.rescan();
                    return Err(error);
                }
            }
        }
        let mut result = key
            .as_ref()
            .map_or(Ok(()), |key| backend.reconcile_one(key));
        if let Some(sweep) = self.sweep {
            let mut page = ActivePage {
                rows: Vec::with_capacity(PAGE_SIZE),
                after: sweep.after,
                through: sweep.through,
            };
            backend.active_page(sweep.after, sweep.through, &mut page)?;
            let last = page.rows.last().map(|r| r.0);
            for (_, row_key) in page.rows {
                if key.as_ref() != Some(&row_key) {
                    // One failed source must not starve later rows. Return the
                    // first failure; the next periodic sweep revisits this key.
                    result = result.and(backend.reconcile_one(&row_key));
                }
            }
            self.sweep = last.filter(|&id| id < sweep.through).map(|id| Sweep {
                after: Some(id),
                ..sweep
            });
        }
        result
    }
}

#[cfg(test)]
mod progress_tests {
    use super::*;

    #[test]
    fn hash_progress_cancels_before_reading_or_at_a_mib_boundary() {
        const MIB: usize = 1 << 20;
        let bytes = vec![0xa5; 2 * MIB + 7];
        let digest = Hash32(*blake3::hash(&bytes).as_bytes());
        for (cancel_at, consumed) in [(1, 0), (2, MIB), (3, 2 * MIB)] {
            let mut reader = bytes.as_slice();
            let mut calls = 0;
            let result = check_contents(&mut reader, bytes.len() as u64, &digest, || {
                calls += 1;
                if calls == cancel_at {
                    Err(AslError::PolicyDenied)
                } else {
                    Ok(())
                }
            });
            assert!(matches!(result, Err(AslError::PolicyDenied)));
            assert_eq!(bytes.len() - reader.len(), consumed);
        }
        for (n, expected) in [
            (bytes.len(), SourceCheck::Unchanged),
            (bytes.len() - 1, SourceCheck::Deactivate),
        ] {
            assert_eq!(
                check_contents(&mut &bytes[..n], bytes.len() as u64, &digest, || Ok(())).unwrap(),
                expected
            );
        }
    }
}
