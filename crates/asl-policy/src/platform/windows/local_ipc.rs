use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr;

use asl_types::error::AslError;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::windows::named_pipe::{NamedPipeClient, NamedPipeServer, ServerOptions};
use windows::Win32::Foundation::{ERROR_NO_DATA, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    GetTokenInformation, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES, SECURITY_MAX_SID_SIZE, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_OVERLAPPED, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_MODE,
    FILE_TYPE_PIPE, FILE_WRITE_DATA, GetFileType, OPEN_EXISTING, READ_CONTROL, SECURITY_ANONYMOUS,
    SECURITY_SQOS_PRESENT, SYNCHRONIZE,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::{HRESULT, HSTRING, PWSTR};

use super::handles::{PinnedDirectory, pin_directory};
use crate::FileIdentity;

// FILE_APPEND_DATA also grants FILE_CREATE_PIPE_INSTANCE. Do not ask for
// GENERIC_WRITE or include it in the client ACE.
const CLIENT_ACCESS: u32 =
    FILE_READ_DATA.0 | FILE_WRITE_DATA.0 | FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0 | SYNCHRONIZE.0;

/// One local, same-user attachment at a time. This is a transport boundary,
/// not evidence that the connected program has an application grant.
pub struct LocalPipeServer {
    pipe: NamedPipeServer,
    disconnect_failed: bool,
    _root: PinnedDirectory,
}

impl LocalPipeServer {
    /// Bind within a Tokio runtime with I/O enabled. Never join an existing
    /// listener; callers must report a conflicting endpoint instead.
    pub fn bind(root: &Path) -> Result<Self, AslError> {
        Self::bind_endpoint(root, false)
    }

    pub fn bind_recovery(root: &Path) -> Result<Self, AslError> {
        Self::bind_endpoint(root, true)
    }

    fn bind_endpoint(root: &Path, recovery: bool) -> Result<Self, AslError> {
        let root = pin_directory(root)?;
        let sid = process_user_sid()?;
        let descriptor = private_descriptor(&sid)?;
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: false.into(),
        };
        // The non-inheritable attributes and self-relative descriptor live
        // through CreateNamedPipeW; Tokio owns the resulting overlapped handle.
        let pipe = unsafe {
            ServerOptions::new()
                .first_pipe_instance(true)
                .max_instances(1)
                .reject_remote_clients(true)
                .create_with_security_attributes_raw(
                    endpoint_name(root.identity(), &sid, recovery),
                    (&raw mut attributes).cast(),
                )
        }?;
        Ok(Self {
            pipe,
            disconnect_failed: false,
            _root: root,
        })
    }

    pub async fn accept(&mut self) -> Result<LocalPipeConnection<'_>, AslError> {
        if self.disconnect_failed {
            return Err(io::Error::from(io::ErrorKind::NotConnected).into());
        }
        if let Err(error) = self.pipe.connect().await {
            // A client can open and close before accept observes it. Windows
            // requires a disconnect before this instance may listen again.
            if error.raw_os_error() == Some(ERROR_NO_DATA.0 as i32) {
                self.reset_attachment();
            }
            return Err(error.into());
        }
        Ok(LocalPipeConnection(self))
    }

    fn reset_attachment(&mut self) {
        self.disconnect_failed = self.pipe.disconnect().is_err();
    }
}

pub struct LocalPipeConnection<'a>(&'a mut LocalPipeServer);

impl LocalPipeConnection<'_> {
    pub fn stream(&mut self) -> &mut (impl AsyncRead + AsyncWrite + Unpin) {
        &mut self.0.pipe
    }
}

impl Drop for LocalPipeConnection<'_> {
    fn drop(&mut self) {
        // Keep the same instance registered even between connections; do not
        // drop/rebind the name and create an ownership gap.
        self.0.reset_attachment();
    }
}

/// Open only the local endpoint for this data root, within a Tokio runtime.
/// A matching Windows owner SID does not identify a particular executable.
pub fn connect_local_pipe(root: &Path) -> Result<NamedPipeClient, AslError> {
    connect_endpoint(root, false)
}

pub fn connect_recovery_pipe(root: &Path) -> Result<NamedPipeClient, AslError> {
    connect_endpoint(root, true)
}

fn connect_endpoint(root: &Path, recovery: bool) -> Result<NamedPipeClient, AslError> {
    let root = pin_directory(root)?;
    let sid = process_user_sid()?;
    let name = HSTRING::from(endpoint_name(root.identity(), &sid, recovery));
    let handle = unsafe {
        CreateFileW(
            &name,
            CLIENT_ACCESS,
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS,
            None,
        )
    }
    .map_err(win_io)?;
    let handle = unsafe { OwnedHandle::from_raw_handle(handle.0) };
    verify_pipe_owner(&handle, &sid)?;
    // The handle is non-inheritable, overlapped and verified as a pipe.
    // Ownership transfers exactly once, even if runtime registration fails.
    Ok(unsafe { NamedPipeClient::from_raw_handle(handle.into_raw_handle()) }?)
}

fn endpoint_name(identity: &FileIdentity, sid: &str, recovery: bool) -> String {
    let mut digest = blake3::Hasher::new_derive_key("ASL local IPC endpoint v1");
    digest.update(&identity.volume_serial.to_le_bytes());
    digest.update(&identity.file_id);
    digest.update(sid.as_bytes());
    let prefix = if recovery {
        "asl-recovery-v1"
    } else {
        "asl-local-v1"
    };
    format!(r"\\.\pipe\{prefix}-{}", digest.finalize().to_hex())
}

fn private_descriptor(sid: &str) -> Result<LocalAllocation, AslError> {
    let sddl = HSTRING::from(format!("O:{sid}D:P(A;;0x{CLIENT_ACCESS:08x};;;{sid})"));
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &sddl,
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }
    .map_err(win_io)?;
    Ok(LocalAllocation(descriptor.0))
}

fn process_user_sid() -> Result<String, AslError> {
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.map_err(win_io)?;
    let token = unsafe { OwnedHandle::from_raw_handle(token.0) };
    // TokenUser stores its SID after the aligned TOKEN_USER header and
    // returns a pointer into this buffer. Convert it before the buffer drops.
    #[repr(C)]
    struct UserBuffer {
        user: TOKEN_USER,
        sid: [u8; SECURITY_MAX_SID_SIZE as usize],
    }
    let mut buffer = UserBuffer {
        user: TOKEN_USER::default(),
        sid: [0; SECURITY_MAX_SID_SIZE as usize],
    };
    let mut size = 0;
    unsafe {
        GetTokenInformation(
            HANDLE(token.as_raw_handle()),
            TokenUser,
            Some((&raw mut buffer).cast()),
            size_of::<UserBuffer>() as u32,
            &mut size,
        )
    }
    .map_err(win_io)?;
    sid_string(buffer.user.User.Sid)
}

fn verify_pipe_owner(handle: &OwnedHandle, expected: &str) -> Result<(), AslError> {
    let handle = HANDLE(handle.as_raw_handle());
    if unsafe { GetFileType(handle) } != FILE_TYPE_PIPE {
        return Err(AslError::PolicyDenied);
    }
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let mut owner = PSID(ptr::null_mut());
    unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            Some(&mut descriptor),
        )
    }
    .ok()
    .map_err(win_io)?;
    let _descriptor = LocalAllocation(descriptor.0);
    if owner.is_invalid() || sid_string(owner)? != expected {
        return Err(AslError::PolicyDenied);
    }
    Ok(())
}

fn sid_string(sid: PSID) -> Result<String, AslError> {
    let mut text = PWSTR::null();
    unsafe { ConvertSidToStringSidW(sid, &mut text) }.map_err(win_io)?;
    let _text = LocalAllocation(text.0.cast());
    unsafe { text.to_string() }.map_err(|_| AslError::PolicyDenied)
}

fn win_io(error: windows::core::Error) -> io::Error {
    let code = error.code();
    let win32_code = (code.0 as u32) & u32::from(u16::MAX);
    if win32_code != 0 && HRESULT::from_win32(win32_code) == code {
        io::Error::from_raw_os_error(win32_code as i32)
    } else {
        error.into()
    }
}

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        unsafe { LocalFree(Some(HLOCAL(self.0))) };
    }
}
