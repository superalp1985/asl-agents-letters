use std::env;
use std::fs::{self, File};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use asl_types::error::AslError;
use rustix::fs::{Mode, chmod};
use tokio::net::{UnixListener, UnixStream};

use super::filesystem::{ensure_private_directory, pin_directory};
use crate::FileIdentity;

pub type LocalPipeClient = UnixStream;

pub struct LocalPipeServer {
    listener: Option<UnixListener>,
    path: PathBuf,
    socket_identity: FileIdentity,
    bind_failed: bool,
    _runtime: File,
    _root: super::filesystem::PinnedDirectory,
}

impl LocalPipeServer {
    pub fn bind(root: &Path) -> Result<Self, AslError> {
        Self::bind_endpoint(root, false)
    }

    pub fn bind_recovery(root: &Path) -> Result<Self, AslError> {
        Self::bind_endpoint(root, true)
    }

    fn bind_endpoint(root: &Path, recovery: bool) -> Result<Self, AslError> {
        let root = pin_directory(root)?;
        let runtime_path = runtime_directory()?;
        let runtime = ensure_private_directory(&runtime_path)?;
        let path = socket_path(&runtime_path, root.identity(), recovery)?;
        if recovery && path.exists() {
            clear_stale_socket(&path)?;
        }
        let listener = UnixListener::bind(&path)?;
        chmod(&path, Mode::RUSR | Mode::WUSR).map_err(|error| {
            let _ = fs::remove_file(&path);
            io::Error::from_raw_os_error(error.raw_os_error())
        })?;
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            let _ = fs::remove_file(&path);
            return Err(AslError::PolicyDenied);
        }
        let socket_identity = identity_from_metadata(&metadata);
        Ok(Self {
            listener: Some(listener),
            path,
            socket_identity,
            bind_failed: false,
            _runtime: runtime,
            _root: root,
        })
    }

    pub async fn accept(&mut self) -> Result<LocalPipeConnection<'_>, AslError> {
        if self.bind_failed {
            return Err(io::Error::from(io::ErrorKind::NotConnected).into());
        }
        let listener = self
            .listener
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?;
        let (stream, _) = listener.accept().await?;
        self.listener = None;
        verify_peer_uid(&stream)?;
        Ok(LocalPipeConnection {
            stream,
            _server: self,
        })
    }

    fn restore_listener(&mut self) {
        let current = fs::symlink_metadata(&self.path)
            .ok()
            .map(|metadata| identity_from_metadata(&metadata));
        if current.as_ref() == Some(&self.socket_identity) {
            let _ = fs::remove_file(&self.path);
        }
        let result = (|| {
            let listener = UnixListener::bind(&self.path)?;
            chmod(&self.path, Mode::RUSR | Mode::WUSR)
                .map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))?;
            let metadata = fs::symlink_metadata(&self.path)?;
            if !metadata.file_type().is_socket()
                || metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.permissions().mode() & 0o077 != 0
            {
                return Err(io::Error::from(io::ErrorKind::PermissionDenied));
            }
            self.socket_identity = identity_from_metadata(&metadata);
            self.listener = Some(listener);
            Ok(())
        })();
        self.bind_failed = result.is_err();
    }
}

pub struct LocalPipeConnection<'a> {
    stream: UnixStream,
    _server: &'a mut LocalPipeServer,
}

impl LocalPipeConnection<'_> {
    pub fn stream(&mut self) -> &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin) {
        &mut self.stream
    }
}

impl Drop for LocalPipeConnection<'_> {
    fn drop(&mut self) {
        self._server.restore_listener();
    }
}

impl Drop for LocalPipeServer {
    fn drop(&mut self) {
        let current = fs::symlink_metadata(&self.path)
            .ok()
            .map(|metadata| identity_from_metadata(&metadata));
        if current.as_ref() == Some(&self.socket_identity) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub fn connect_local_pipe(root: &Path) -> Result<LocalPipeClient, AslError> {
    connect_endpoint(root, false)
}

pub fn connect_recovery_pipe(root: &Path) -> Result<LocalPipeClient, AslError> {
    connect_endpoint(root, true)
}

fn connect_endpoint(root: &Path, recovery: bool) -> Result<LocalPipeClient, AslError> {
    let root = pin_directory(root)?;
    let runtime_path = runtime_directory()?;
    let runtime = pin_directory(&runtime_path)?;
    let metadata = runtime.leaf().metadata()?;
    if metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(AslError::PolicyDenied);
    }
    let path = socket_path(&runtime_path, root.identity(), recovery)?;
    let stream = std::os::unix::net::UnixStream::connect(&path)?;
    verify_peer_uid(&stream)?;
    stream.set_nonblocking(true)?;
    UnixStream::from_std(stream).map_err(AslError::from)
}

fn socket_path(
    runtime: &Path,
    root_identity: &FileIdentity,
    recovery: bool,
) -> Result<PathBuf, AslError> {
    let mut digest = blake3::Hasher::new_derive_key("ASL Linux local IPC endpoint v1");
    digest.update(&root_identity.volume_serial.to_le_bytes());
    digest.update(&root_identity.file_id);
    digest.update(&rustix::process::geteuid().as_raw().to_le_bytes());
    let prefix = if recovery { "r" } else { "l" };
    let path = runtime.join(format!(
        "{prefix}-{}.sock",
        &digest.finalize().to_hex()[..32]
    ));
    if path.as_os_str().as_encoded_bytes().len() >= 108 {
        return Err(AslError::InvalidStorageRoot);
    }
    Ok(path)
}

fn runtime_directory() -> Result<PathBuf, AslError> {
    if let Some(runtime) = env::var_os("XDG_RUNTIME_DIR") {
        let runtime = PathBuf::from(runtime);
        if !runtime.is_absolute() {
            return Err(AslError::InvalidStorageRoot);
        }
        return Ok(runtime.join("asl"));
    }
    Ok(PathBuf::from(format!(
        "/tmp/asl-{}",
        rustix::process::geteuid().as_raw()
    )))
}

fn clear_stale_socket(path: &Path) -> Result<(), AslError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(AslError::PolicyDenied);
    }
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_) => return Err(AslError::InvalidPolicyState),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
            ) => {}
        Err(error) => return Err(error.into()),
    }
    fs::remove_file(path)?;
    Ok(())
}

fn verify_peer_uid(socket: &impl AsRawFd) -> Result<(), AslError> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: u32::MAX,
        gid: u32::MAX,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut credentials).cast(),
            &mut length,
        )
    };
    if result != 0 || length as usize != std::mem::size_of::<libc::ucred>() {
        return Err(io::Error::last_os_error().into());
    }
    if credentials.uid != rustix::process::geteuid().as_raw() {
        return Err(AslError::PolicyDenied);
    }
    Ok(())
}

fn identity_from_metadata(metadata: &fs::Metadata) -> FileIdentity {
    let mut file_id = [0u8; 16];
    file_id[..8].copy_from_slice(&metadata.ino().to_le_bytes());
    FileIdentity {
        volume_serial: metadata.dev(),
        file_id,
    }
}
