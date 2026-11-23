//! Local physical objects only. A database reference, not a filename, makes
//! an object available. The broker owns the grant, quota and transaction.

use std::path::Path;

use asl_types::error::AslError;
use asl_types::manifest::Manifest;

use crate::AuthorizedFile;
#[cfg(windows)]
use crate::platform::windows::handles::{PinnedDirectory, snapshot};

/// Pins the existing private home and its `state` directory (not the DB file).
/// Acquire before opening SQLite; keep alive until the connection is closed.
#[must_use = "keep the directory pins for the lifetime of the database connection"]
pub struct PinnedHome {
    #[cfg(windows)]
    state: PinnedDirectory,
    #[cfg(not(windows))]
    _unavailable: std::convert::Infallible,
}

impl PinnedHome {
    pub fn open(home: &Path) -> Result<Self, AslError> {
        #[cfg(windows)]
        {
            Ok(Self {
                state: snapshot::pin_state(home)?,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = home;
            Err(AslError::PlatformUnavailable)
        }
    }
}

/// Exclusive, cross-process ownership of a service for one home.
#[must_use = "hold the owner for the lifetime of the service"]
pub struct ProfileOwner {
    #[cfg(windows)]
    _marker: std::fs::File,
    _home: PinnedHome,
}

impl ProfileOwner {
    pub fn core(home: &Path) -> Result<Self, AslError> {
        Self::acquire(home, "core-owner.lock")
    }

    pub fn downloads(home: &Path) -> Result<Self, AslError> {
        Self::acquire(home, "download-worker.lock")
    }

    /// A sharing conflict returns `InvalidPolicyState`; dropping this guard
    /// releases ownership without removing the marker.
    fn acquire(home: &Path, marker: &str) -> Result<Self, AslError> {
        #[cfg(windows)]
        {
            let home = PinnedHome::open(home)?;
            let marker = snapshot::open_exclusive_marker(&home.state, marker)?;
            Ok(Self {
                _marker: marker,
                _home: home,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = (home, marker);
            Err(AslError::PlatformUnavailable)
        }
    }
}

/// Opens one content-addressed snapshot without resolving its names through a
/// caller-controlled path.
pub struct SnapshotReader {
    #[cfg(windows)]
    reader: snapshot::SnapshotReader,
    #[cfg(not(windows))]
    _unavailable: std::convert::Infallible,
}

impl SnapshotReader {
    pub fn open(home: &Path, content_id: [u8; 32]) -> Result<Self, AslError> {
        #[cfg(windows)]
        {
            Ok(Self {
                reader: snapshot::SnapshotReader::open(home, content_id)?,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = (home, content_id);
            Err(AslError::PlatformUnavailable)
        }
    }

    pub fn read_manifest(&mut self) -> Result<Vec<u8>, AslError> {
        #[cfg(windows)]
        {
            self.reader.read_manifest()
        }
        #[cfg(not(windows))]
        {
            Err(AslError::PlatformUnavailable)
        }
    }

    pub fn file_size(&self) -> Result<u64, AslError> {
        #[cfg(windows)]
        {
            Ok(self.reader.file_size())
        }
        #[cfg(not(windows))]
        {
            Err(AslError::PlatformUnavailable)
        }
    }

    pub fn read_range(&mut self, offset: u64, length: u32) -> Result<Vec<u8>, AslError> {
        #[cfg(windows)]
        {
            self.reader.read_range(offset, length)
        }
        #[cfg(not(windows))]
        {
            let _ = (offset, length);
            Err(AslError::PlatformUnavailable)
        }
    }
}

/// A non-blocking cross-process fence for a single import ID under one home.
#[must_use = "hold the owner throughout the import or recovery transaction"]
pub struct ImportOwner {
    #[cfg(windows)]
    owner: snapshot::Owner,
    #[cfg(not(windows))]
    _unavailable: std::convert::Infallible,
}

impl ImportOwner {
    /// A sharing conflict returns `Ok(None)`. A crashed process may leave an
    /// empty marker; the exclusive handle, not marker existence, is the fence.
    pub fn try_acquire(home: &Path, id: [u8; 16]) -> Result<Option<Self>, AslError> {
        #[cfg(windows)]
        {
            Ok(snapshot::Owner::acquire(home, id)?.map(|owner| Self { owner }))
        }
        #[cfg(not(windows))]
        {
            let _ = (home, id);
            Err(AslError::PlatformUnavailable)
        }
    }

    /// Under BEGIN IMMEDIATE the caller must verify that this fenced intent
    /// names `content` and no durable snapshot references it. Release the DB
    /// hold only on success. A partial cleanup is retryable with the same checks.
    pub fn clean_unreferenced(&self, content: [u8; 32]) -> Result<(), AslError> {
        #[cfg(windows)]
        {
            self.owner.clean(content)
        }
        #[cfg(not(windows))]
        {
            let _ = content;
            Err(AslError::PlatformUnavailable)
        }
    }

    /// Metadata-only preclaim check: neither generated final name may exist.
    /// This does not reserve an absent name; serialize the check and claim in
    /// the caller's IMMEDIATE transaction.
    pub fn require_absent(&self, content: [u8; 32]) -> Result<(), AslError> {
        #[cfg(windows)]
        {
            self.owner.require_absent(content)
        }
        #[cfg(not(windows))]
        {
            let _ = content;
            Err(AslError::PlatformUnavailable)
        }
    }
}

#[must_use = "dropping a snapshot before retain_installed rolls back new files"]
pub struct StagedSnapshot {
    manifest: Manifest,
    id: [u8; 32],
    #[cfg(windows)]
    files: Option<snapshot::ObjectFiles>,
    #[cfg(windows)]
    installed: bool,
}

impl StagedSnapshot {
    /// Stage trusted broker-generated bytes using the same immutable object layout as imports.
    pub fn from_bytes(home: &Path, bytes: &[u8]) -> Result<Self, AslError> {
        #[cfg(windows)]
        {
            use asl_types::manifest::{content_id, encode_manifest};
            use std::io::Write;

            let manifest = Manifest::from_bytes(bytes).map_err(|_| AslError::QuotaExceeded)?;
            let encoded = encode_manifest(&manifest).map_err(|_| AslError::InvalidPolicyState)?;
            let mut files = snapshot::ObjectFiles::stage(home)?;
            let (blob, mnf) = files.writers();
            blob.write_all(bytes)?;
            mnf.write_all(&encoded)?;
            blob.sync_all()?;
            mnf.sync_all()?;
            Ok(Self {
                manifest,
                id: content_id(&encoded),
                files: Some(files),
                installed: false,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = (home, bytes);
            Err(AslError::PlatformUnavailable)
        }
    }

    /// Copy from a freshly opened source. The callback can stop the copy
    /// before the first read, after each protocol chunk, or before handoff.
    pub fn copy_from(
        home: &Path,
        source: &mut AuthorizedFile,
        progress: impl FnMut() -> Result<(), AslError>,
    ) -> Result<Self, AslError> {
        Self::copy_from_observing_first_chunk(home, source, progress, |_| {})
    }

    /// `observe` borrows the first nonempty chunk copied and hashed from the
    /// pinned source. It is never called for an empty file.
    pub fn copy_from_observing_first_chunk(
        home: &Path,
        source: &mut AuthorizedFile,
        progress: impl FnMut() -> Result<(), AslError>,
        observe: impl FnOnce(&[u8]),
    ) -> Result<Self, AslError> {
        #[cfg(windows)]
        {
            use asl_types::manifest::{CHUNK_SIZE, content_id, encode_manifest};
            use std::io::{Read, Write};
            let mut progress = progress;
            progress()?;
            let mut files = snapshot::ObjectFiles::stage(home)?;
            let (blob, mnf) = files.writers();
            let file_size = source.len();
            let mut remaining = file_size;
            let mut whole = blake3::Hasher::new();
            let mut chunk_hashes = Vec::new();
            let mut buffer = vec![0; remaining.min(u64::from(CHUNK_SIZE)) as usize];
            let mut first_chunk = Some(observe);
            while remaining != 0 {
                let len = remaining.min(u64::from(CHUNK_SIZE)) as usize;
                let chunk = &mut buffer[..len];
                source.read_exact(chunk)?;
                blob.write_all(chunk)?;
                whole.update(chunk);
                chunk_hashes.push(*blake3::hash(chunk).as_bytes());
                if let Some(observe) = first_chunk.take() {
                    observe(chunk);
                }
                remaining -= len as u64;
                progress()?;
            }
            if source.read(&mut [0])? != 0 {
                return Err(AslError::InvalidPolicyState);
            }
            let manifest = Manifest {
                file_size,
                file_hash: *whole.finalize().as_bytes(),
                chunk_hashes,
            };
            let encoded = encode_manifest(&manifest).map_err(|_| AslError::InvalidPolicyState)?;
            mnf.write_all(&encoded)?;
            blob.sync_all()?;
            mnf.sync_all()?;
            progress()?;
            Ok(Self {
                manifest,
                id: content_id(&encoded),
                files: Some(files),
                installed: false,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = (home, source, progress, observe);
            Err(AslError::PlatformUnavailable)
        }
    }

    pub fn content_id(&self) -> [u8; 32] {
        self.id
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Equivalent to `install_with_progress(|| Ok(()))`.
    pub fn install(&mut self) -> Result<(), AslError> {
        self.install_with_progress(|| Ok(()))
    }

    /// Install and sync once, before taking the SQLite writer lock. Checks
    /// progress before starting, after each block of at most 1 MiB copied or
    /// compared, and after the final sync. A callback error consumes staging
    /// and rolls back only newly created objects, by their still-open handles.
    ///
    /// New objects stay exclusive; adopted objects deny writers and deletion.
    /// Hold this guard while revalidating authorization and quota inside the
    /// transaction, through commit. A new file needs space for both copies.
    pub fn install_with_progress(
        &mut self,
        progress: impl FnMut() -> Result<(), AslError>,
    ) -> Result<(), AslError> {
        #[cfg(windows)]
        {
            if self.installed {
                return Err(AslError::InvalidPolicyState);
            }
            let mut files = self.files.take().ok_or(AslError::InvalidPolicyState)?;
            files.install(self.id, progress)?;
            self.files = Some(files);
            self.installed = true;
            Ok(())
        }
        #[cfg(not(windows))]
        {
            let _ = progress;
            Err(AslError::PlatformUnavailable)
        }
    }

    /// After successful COMMIT, disarm cleanup in memory and release pins.
    /// Drop instead on cancellation or known rollback, even if no transaction
    /// was opened. On indeterminate commit retain rather than risk a dangling row.
    pub fn retain_installed(&mut self) {
        #[cfg(windows)]
        if self.installed
            && let Some(mut files) = self.files.take()
        {
            files.retain();
        }
    }
}

#[cfg(all(windows, test))]
mod tests {
    use super::{ImportOwner, PinnedHome, ProfileOwner, SnapshotReader, StagedSnapshot};
    use crate::{AuthorizedFile, SourceGrant, SourceRules, open_authorized_source};
    use asl_types::error::AslError;
    use asl_types::manifest::{Manifest, content_id, encode_manifest};
    use std::fs;
    use std::path::{Path, PathBuf};

    struct Fixture {
        base: PathBuf,
        root: PathBuf,
        home: PathBuf,
    }

    impl Fixture {
        fn new(bytes: &[u8]) -> Self {
            let base = std::env::temp_dir();
            let root = base.join(format!("t11-disk-{:032x}", rand::random::<u128>()));
            fs::create_dir(&root).unwrap();
            let home = root.join("home");
            fs::create_dir(&home).unwrap();
            fs::create_dir(home.join("state")).unwrap();
            fs::create_dir(root.join("source")).unwrap();
            fs::write(root.join("source/item.txt"), bytes).unwrap();
            Self { base, root, home }
        }

        fn source(&self) -> AuthorizedFile {
            let rules = SourceRules::new(["txt".into()], 4 << 20).unwrap();
            let grant = SourceGrant::open(&self.root.join("source"), &self.home, rules).unwrap();
            open_authorized_source(&grant, Path::new("item.txt")).unwrap()
        }

        fn stage(&self) -> StagedSnapshot {
            StagedSnapshot::copy_from(&self.home, &mut self.source(), || Ok(())).unwrap()
        }

        fn objects(&self, id: [u8; 32]) -> [PathBuf; 2] {
            let id = hex::encode(id);
            let shard = &id[..2];
            [
                self.home.join(format!("snapshots/{shard}/{id}.blob")),
                self.home.join(format!("manifests/{shard}/{id}.mnf")),
            ]
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let resolved = self.root.canonicalize().unwrap();
            let base = self.base.canonicalize().unwrap();
            assert_eq!(resolved.parent(), Some(base.as_path()));
            assert_eq!(resolved.file_name(), self.root.file_name());
            fs::remove_dir_all(resolved).unwrap();
        }
    }

    #[test]
    fn home_pins_state_and_requires_an_existing_absolute_home() {
        let f = Fixture::new(b"");
        let state = f.home.join("state");
        let pin = PinnedHome::open(&f.home).unwrap();
        assert!(fs::rename(&state, f.home.join("old")).is_err());
        assert!(fs::rename(&f.home, f.root.join("old-home")).is_err());
        drop(pin);
        fs::rename(&state, f.home.join("old")).unwrap();
        assert!(PinnedHome::open(&f.home).is_err());
        assert!(PinnedHome::open(Path::new("E:work")).is_err());
    }

    #[test]
    fn core_owner_is_exclusive_and_does_not_lock_the_download_worker() {
        let f = Fixture::new(b"");
        let core = ProfileOwner::core(&f.home).unwrap();
        assert!(matches!(
            ProfileOwner::core(&f.home),
            Err(AslError::InvalidPolicyState)
        ));
        let downloads = ProfileOwner::downloads(&f.home).unwrap();
        drop(core);
        let _restarted = ProfileOwner::core(&f.home).unwrap();
        assert!(matches!(
            ProfileOwner::downloads(&f.home),
            Err(AslError::InvalidPolicyState)
        ));
        drop(downloads);
    }

    #[test]
    fn chunk_boundaries_manifest_and_dedup_rollback() {
        let mut bytes = vec![7; 1 << 20];
        bytes.push(31);
        let f = Fixture::new(&bytes);
        let mut s = f.stage();
        let expected = Manifest {
            file_size: bytes.len() as u64,
            file_hash: *blake3::hash(&bytes).as_bytes(),
            chunk_hashes: vec![
                *blake3::hash(&bytes[..1 << 20]).as_bytes(),
                *blake3::hash(&[31]).as_bytes(),
            ],
        };
        let encoded = encode_manifest(&expected).unwrap();
        assert_eq!(s.manifest(), &expected);
        assert_eq!(s.content_id(), content_id(&encoded));
        let [blob, mnf] = f.objects(s.content_id());
        s.install().unwrap();
        assert!(fs::File::open(&blob).is_err());
        assert!(fs::File::open(&mnf).is_err());
        assert!(f.stage().install().is_err());
        s.retain_installed();
        assert_eq!(fs::read(&blob).unwrap(), bytes);
        assert_eq!(fs::read(&mnf).unwrap(), encoded);
        f.stage().install().unwrap(); // Drop an all-deduplicated install.
        assert_eq!(fs::read(&blob).unwrap(), bytes);
        assert_eq!(fs::read(&mnf).unwrap(), encoded);
    }

    #[test]
    fn content_addressed_reader_checks_manifest_and_reads_exact_ranges() {
        let bytes = b"authorized immutable snapshot";
        let f = Fixture::new(bytes);
        let mut staged = f.stage();
        let content_id = staged.content_id();
        staged.install().unwrap();
        staged.retain_installed();

        let mut reader = SnapshotReader::open(&f.home, content_id).unwrap();
        let manifest_bytes = reader.read_manifest().unwrap();
        let manifest = asl_types::manifest::decode_manifest(&manifest_bytes, content_id).unwrap();

        assert_eq!(manifest.file_size, bytes.len() as u64);
        assert_eq!(reader.file_size().unwrap(), bytes.len() as u64);
        assert_eq!(reader.read_range(0, bytes.len() as u32).unwrap(), bytes);
        assert!(reader.read_range(bytes.len() as u64, 1).is_err());
    }

    #[test]
    fn rollback_removes_only_new_objects_including_partial_install() {
        let f = Fixture::new(b"");
        let mut s = f.stage();
        assert!(s.manifest().chunk_hashes.is_empty());
        let [blob, mnf] = f.objects(s.content_id());
        s.install().unwrap();
        drop(s);
        assert!(!blob.try_exists().unwrap() && !mnf.try_exists().unwrap());
        fs::write(&mnf, [0; 58]).unwrap();
        assert!(f.stage().install().is_err());
        assert!(!blob.try_exists().unwrap());
        assert_eq!(fs::read(&mnf).unwrap(), [0; 58]);
        fs::remove_file(&mnf).unwrap();
        fs::write(&blob, []).unwrap();
        f.stage().install().unwrap();
        assert!(blob.try_exists().unwrap() && !mnf.try_exists().unwrap());
    }

    #[test]
    fn mismatched_blob_and_multiply_linked_blob_are_not_adopted() {
        let f = Fixture::new(b"first");
        let s = f.stage();
        let [blob, mnf] = f.objects(s.content_id());
        drop(s);
        fs::create_dir_all(blob.parent().unwrap()).unwrap();
        fs::write(&blob, b"other").unwrap();
        assert!(f.stage().install().is_err());
        assert_eq!(fs::read(&blob).unwrap(), b"other");
        fs::remove_file(&blob).unwrap();
        fs::write(f.root.join("original"), b"first").unwrap();
        fs::hard_link(f.root.join("original"), &blob).unwrap();
        assert!(f.stage().install().is_err());
        assert!(!mnf.try_exists().unwrap());
        assert_eq!(fs::read(f.root.join("original")).unwrap(), b"first");
    }

    #[test]
    fn state_staging_and_output_reject_directory_junctions() {
        use std::process::Command;
        let f = Fixture::new(b"junction");
        let target = f.root.join("unused");
        fs::create_dir(&target).unwrap();
        let junction = |path: &Path| {
            let status = Command::new("powershell.exe")
                .args(["-NoProfile", "-NonInteractive", "-Command",
                    "$ErrorActionPreference='Stop'; New-Item -ItemType Junction -Path $env:ASL_LINK -Target $env:ASL_TARGET | Out-Null"])
                .env("ASL_LINK", path)
                .env("ASL_TARGET", &target)
                .status().unwrap();
            assert!(status.success());
        };
        let state = f.home.join("state");
        fs::remove_dir(&state).unwrap();
        junction(&state);
        assert!(PinnedHome::open(&f.home).is_err());
        fs::remove_dir(&state).unwrap();
        fs::create_dir(&state).unwrap();
        let incoming = f.home.join("incoming");
        junction(&incoming);
        assert!(StagedSnapshot::copy_from(&f.home, &mut f.source(), || Ok(())).is_err());
        fs::remove_dir(&incoming).unwrap();
        let mut s = f.stage();
        let [blob, mnf] = f.objects(s.content_id());
        let shard = mnf.parent().unwrap();
        junction(shard);
        assert!(s.install().is_err());
        assert!(!blob.try_exists().unwrap());
        let owner = ImportOwner::try_acquire(&f.home, [1; 16]).unwrap().unwrap();
        assert!(owner.require_absent(s.content_id()).is_err());
        assert!(owner.clean_unreferenced(s.content_id()).is_err());
        assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
        fs::remove_dir(shard).unwrap();
    }

    #[test]
    fn uninstalled_stage_is_private_and_drop_cleans_parts() {
        let f = Fixture::new(b"private");
        let mut s = f.stage();
        let incoming = f.home.join("incoming");
        let parts = fs::read_dir(&incoming)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(parts.len(), 2);
        for part in parts {
            assert!(fs::File::open(part.path()).is_err());
        }
        let [blob, mnf] = f.objects(s.content_id());
        assert!(!blob.try_exists().unwrap() && !mnf.try_exists().unwrap());
        assert!(fs::rename(&incoming, f.home.join("old-incoming")).is_err());
        s.retain_installed(); // An early retain must not abandon private staging.
        drop(s);
        assert_eq!(fs::read_dir(incoming).unwrap().count(), 0);
    }

    #[test]
    fn abrupt_process_exit_removes_both_stage_files() {
        const CHILD: &str = "ASL_T11_STAGE_CRASH_FIXTURE";
        if let Some(root) = std::env::var_os(CHILD) {
            let root = PathBuf::from(root);
            let home = root.join("home");
            let grant = SourceGrant::open(
                &root.join("source"),
                &home,
                SourceRules::new(["txt".into()], 1024).unwrap(),
            )
            .unwrap();
            let mut source = open_authorized_source(&grant, Path::new("item.txt")).unwrap();
            let _stage = StagedSnapshot::copy_from(&home, &mut source, || Ok(())).unwrap();
            assert_eq!(fs::read_dir(home.join("incoming")).unwrap().count(), 2);
            std::process::exit(61); // No Rust destructors.
        }
        let f = Fixture::new(b"crash");
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "snapshot_files::tests::abrupt_process_exit_removes_both_stage_files",
            ])
            .env(CHILD, &f.root)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(61));
        assert_eq!(fs::read_dir(f.home.join("incoming")).unwrap().count(), 0);
    }

    #[test]
    fn owner_is_exclusive_across_processes_and_reacquirable_after_exit() {
        const CHILD: &str = "ASL_T11_OWNER_CRASH_HOME";
        if let Some(home) = std::env::var_os(CHILD) {
            let home = Path::new(&home);
            assert!(ImportOwner::try_acquire(home, [1; 16]).unwrap().is_none());
            let _live = ImportOwner::try_acquire(home, [2; 16]).unwrap().unwrap();
            std::process::exit(62);
        }
        let f = Fixture::new(b"");
        let live = ImportOwner::try_acquire(&f.home, [1; 16]).unwrap().unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "snapshot_files::tests::owner_is_exclusive_across_processes_and_reacquirable_after_exit"])
            .env(CHILD, &f.home)
            .status().unwrap();
        assert_eq!(status.code(), Some(62));
        assert!(
            ImportOwner::try_acquire(&f.home, [2; 16])
                .unwrap()
                .is_some()
        );
        assert!(
            ImportOwner::try_acquire(&f.home, [1; 16])
                .unwrap()
                .is_none()
        );
        let other = Fixture::new(b"");
        assert!(
            ImportOwner::try_acquire(&other.home, [1; 16])
                .unwrap()
                .is_some()
        );
        drop(live);
        assert!(
            ImportOwner::try_acquire(&f.home, [1; 16])
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn cleanup_preflights_both_entries_and_never_removes_other_names() {
        let f = Fixture::new(b"orphan");
        let owner = ImportOwner::try_acquire(&f.home, [3; 16]).unwrap().unwrap();
        let id = [17; 32];
        let [blob, mnf] = f.objects(id);
        owner.clean_unreferenced(id).unwrap(); // Missing base directories.
        for name in [&blob, &mnf] {
            fs::create_dir_all(name.parent().unwrap()).unwrap();
        }
        let unrelated = blob.with_extension("untouched");
        let outside = f.root.join("outside");
        fs::write(&unrelated, b"unrelated").unwrap();
        fs::write(&outside, b"outside").unwrap();
        fs::write(&blob, b"partial blob").unwrap();
        fs::hard_link(&outside, &mnf).unwrap();
        assert!(owner.require_absent(id).is_err());
        assert!(owner.clean_unreferenced(id).is_err());
        assert_eq!(fs::read(&blob).unwrap(), b"partial blob");
        assert_eq!(fs::read(&mnf).unwrap(), b"outside");
        fs::remove_file(&mnf).unwrap();
        fs::write(&mnf, b"partial manifest").unwrap();
        let busy = fs::File::open(&mnf).unwrap();
        assert!(owner.clean_unreferenced(id).is_err());
        assert!(blob.try_exists().unwrap() && mnf.try_exists().unwrap());
        drop(busy);
        owner.clean_unreferenced(id).unwrap();
        assert!(!blob.try_exists().unwrap() && !mnf.try_exists().unwrap());
        fs::write(&mnf, b"only manifest remains").unwrap();
        owner.clean_unreferenced(id).unwrap();
        owner.clean_unreferenced(id).unwrap();
        assert!(!mnf.try_exists().unwrap());
        assert_eq!(fs::read(outside).unwrap(), b"outside");
        assert_eq!(fs::read(unrelated).unwrap(), b"unrelated");
    }

    #[test]
    fn require_absent_never_claims_or_changes_either_preexisting_name() {
        let f = Fixture::new(b"");
        let owner = ImportOwner::try_acquire(&f.home, [4; 16]).unwrap().unwrap();
        let id = [42; 32];
        let [blob, mnf] = f.objects(id);
        owner.require_absent(id).unwrap();
        assert!(!f.home.join("snapshots").try_exists().unwrap());
        assert!(!f.home.join("manifests").try_exists().unwrap());
        for path in [&blob, &mnf] {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"predates this intent").unwrap();
            assert!(owner.require_absent(id).is_err());
            assert_eq!(fs::read(path).unwrap(), b"predates this intent");
            fs::remove_file(path).unwrap();
        }
        let upper = blob.with_extension("BLOB");
        fs::write(&upper, b"alternate spelling").unwrap();
        if blob.try_exists().unwrap() {
            assert!(owner.require_absent(id).is_err());
            assert!(owner.clean_unreferenced(id).is_err());
        }
        assert_eq!(fs::read(&upper).unwrap(), b"alternate spelling");
        fs::remove_file(upper).unwrap();
        owner.require_absent(id).unwrap();
    }

    #[test]
    fn cleanup_requires_confirmed_disappearance_before_releasing_hold() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES;

        let f = Fixture::new(b"");
        let owner = ImportOwner::try_acquire(&f.home, [5; 16]).unwrap().unwrap();
        let id = [33; 32];
        let [blob, _] = f.objects(id);
        fs::create_dir_all(blob.parent().unwrap()).unwrap();
        fs::write(&blob, b"partial").unwrap();
        let observer = fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES.0)
            .open(&blob)
            .unwrap();
        assert!(owner.clean_unreferenced(id).is_err());
        assert!(owner.require_absent(id).is_err());
        drop(observer);
        owner.clean_unreferenced(id).unwrap();
        owner.require_absent(id).unwrap();
    }

    #[test]
    fn progress_error_mid_copy_cleans_staging() {
        let f = Fixture::new(&vec![1; (1 << 20) + 1]);
        let mut calls = 0;
        let result = StagedSnapshot::copy_from(&f.home, &mut f.source(), || {
            calls += 1;
            if calls == 2 {
                Err(AslError::GrantRevoked)
            } else {
                Ok(())
            }
        });
        assert!(matches!(result, Err(AslError::GrantRevoked)));
        assert_eq!(fs::read_dir(f.home.join("incoming")).unwrap().count(), 0);
    }

    #[test]
    fn cancel_halfway_through_new_final_removes_partial_and_allows_retry() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES;

        let half = 1 << 20;
        let bytes = vec![13; 2 * half];
        let f = Fixture::new(&bytes);
        let mut s = f.stage();
        let [blob, mnf] = f.objects(s.content_id());
        let mut cancelled_at = None;
        let result = s.install_with_progress(|| {
            let attributes = fs::OpenOptions::new()
                .access_mode(FILE_READ_ATTRIBUTES.0)
                .open(&blob);
            let file = match attributes {
                Ok(file) => file,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(e.into()),
            };
            let len = file.metadata()?.len();
            if len >= half as u64 {
                cancelled_at = Some(len);
                assert!(fs::File::open(&blob).is_err());
                return Err(AslError::GrantRevoked);
            }
            Ok(())
        });
        assert!(matches!(result, Err(AslError::GrantRevoked)));
        assert_eq!(cancelled_at, Some(half as u64));
        assert!(!blob.try_exists().unwrap() && !mnf.try_exists().unwrap());
        assert_eq!(fs::read_dir(f.home.join("incoming")).unwrap().count(), 0);
        let mut retry = f.stage();
        retry.install().unwrap();
        retry.retain_installed();
        assert_eq!(fs::read(blob).unwrap(), bytes);
    }

    #[test]
    fn cancel_during_dedup_verification_preserves_shared_objects() {
        let bytes = vec![23; 3 << 20];
        let f = Fixture::new(&bytes);
        let mut original = f.stage();
        let [blob, mnf] = f.objects(original.content_id());
        let expected_manifest = encode_manifest(original.manifest()).unwrap();
        original.install().unwrap();
        original.retain_installed();

        let writer = |path: &Path| fs::OpenOptions::new().write(true).open(path);
        let mut s = f.stage();
        let mut checks_during_blob = 0;
        let result = s.install_with_progress(|| {
            if writer(&blob).is_err() && writer(&mnf).is_ok() {
                checks_during_blob += 1;
                if checks_during_blob == 2 {
                    return Err(AslError::GrantRevoked);
                }
            }
            Ok(())
        });
        assert!(matches!(result, Err(AslError::GrantRevoked)));
        assert_eq!(fs::read(&blob).unwrap(), bytes);
        assert_eq!(fs::read(&mnf).unwrap(), expected_manifest);
        let mut adopted = f.stage();
        adopted.install_with_progress(|| Ok(())).unwrap();
        for path in [&blob, &mnf] {
            assert!(writer(path).is_err());
            assert!(fs::remove_file(path).is_err());
        }
        drop(adopted);
        assert_eq!(fs::read(&blob).unwrap(), bytes);
        assert_eq!(fs::read(&mnf).unwrap(), expected_manifest);
    }
}
