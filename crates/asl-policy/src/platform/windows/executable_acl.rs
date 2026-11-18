use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::sync::Mutex;

use asl_types::error::AslError;
use windows::Win32::Foundation::{
    HANDLE, HLOCAL, LocalFree, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, GRANT_ACCESS, GetSecurityInfo, NO_MULTIPLE_TRUSTEE, REVOKE_ACCESS,
    SE_FILE_OBJECT, SetEntriesInAclW, SetSecurityInfo, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN,
    TRUSTEE_W,
};
use windows::Win32::Security::{
    ACL, CopySid, DACL_SECURITY_INFORMATION, GetLengthSid, NO_INHERITANCE, PSECURITY_DESCRIPTOR,
    PSID,
};
use windows::Win32::Storage::FileSystem::{FILE_GENERIC_EXECUTE, FILE_GENERIC_READ};
use windows::Win32::System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject};
use windows::core::{HSTRING, PWSTR};

use super::appcontainer::setup_error;
use super::handles::ExecutablePin;
use crate::paths::FileIdentity;

// Serializes threads in this process; the named mutex also covers other ASL processes.
static ACL_LOCK: Mutex<()> = Mutex::new(());
const ACL_MUTEX_TIMEOUT_MS: u32 = 30_000;

struct AclMutex(OwnedHandle);

impl AclMutex {
    fn acquire(identity: &FileIdentity) -> Result<Self, AslError> {
        Self::acquire_named(&mutex_name(identity))
    }

    fn acquire_named(name: &str) -> Result<Self, AslError> {
        let name = HSTRING::from(name);
        let handle = unsafe { CreateMutexW(None, false, &name) }
            .map_err(|error| setup_error("create_executable_acl_mutex", error))?;
        let handle = unsafe { OwnedHandle::from_raw_handle(handle.0) };
        match unsafe { WaitForSingleObject(HANDLE(handle.as_raw_handle()), ACL_MUTEX_TIMEOUT_MS) } {
            WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(Self(handle)),
            WAIT_TIMEOUT => Err(AslError::SandboxUnavailable),
            _ => Err(setup_error(
                "wait_executable_acl_mutex",
                windows::core::Error::from_thread(),
            )),
        }
    }
}

fn mutex_name(identity: &FileIdentity) -> String {
    format!(
        "Global\\ASL.ExecutableAcl.{:016x}.{:032x}",
        identity.volume_serial,
        u128::from_le_bytes(identity.file_id)
    )
}

impl Drop for AclMutex {
    fn drop(&mut self) {
        let _ = unsafe { ReleaseMutex(HANDLE(self.0.as_raw_handle())) };
    }
}

struct LocalAllocation(*mut std::ffi::c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(Some(HLOCAL(self.0))) };
        }
    }
}

pub(super) struct ExecutableGrant {
    _pin: ExecutablePin,
    sid: Vec<u64>,
    granted: bool,
}

impl ExecutableGrant {
    pub(super) fn new(pin: ExecutablePin, sid: PSID) -> Result<Self, AslError> {
        let length = unsafe { GetLengthSid(sid) };
        if length == 0 || length > 68 {
            return Err(AslError::SandboxUnavailable);
        }
        let mut copied = vec![0u64; (length as usize).div_ceil(size_of::<u64>())];
        unsafe { CopySid(length, PSID(copied.as_mut_ptr().cast()), sid) }
            .map_err(|_| AslError::SandboxUnavailable)?;
        let mut grant = Self {
            _pin: pin,
            sid: copied,
            granted: false,
        };
        grant.update(GRANT_ACCESS)?;
        grant.granted = true;
        Ok(grant)
    }

    pub(super) fn revoke(&mut self) -> Result<(), AslError> {
        if self.granted {
            self.update(REVOKE_ACCESS)?;
            self.granted = false;
        }
        Ok(())
    }

    fn update(
        &self,
        mode: windows::Win32::Security::Authorization::ACCESS_MODE,
    ) -> Result<(), AslError> {
        let _lock = ACL_LOCK.lock().map_err(|_| AslError::SandboxUnavailable)?;
        let _process_lock = AclMutex::acquire(&self._pin.identity)?;
        let handle = HANDLE(self._pin.file.as_raw_handle());
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let mut old_acl: *mut ACL = std::ptr::null_mut();
        unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut old_acl),
                None,
                Some(&mut descriptor),
            )
        }
        .ok()
        .map_err(|error| setup_error("get_executable_acl", error))?;
        let _descriptor = LocalAllocation(descriptor.0);
        if old_acl.is_null() {
            return Err(AslError::SandboxUnavailable);
        }
        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE).0,
            grfAccessMode: mode,
            grfInheritance: NO_INHERITANCE,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_UNKNOWN,
                ptstrName: PWSTR(self.sid.as_ptr().cast_mut().cast()),
            },
        };
        let mut new_acl: *mut ACL = std::ptr::null_mut();
        unsafe { SetEntriesInAclW(Some(&[entry]), Some(old_acl), &mut new_acl) }
            .ok()
            .map_err(|error| setup_error("build_executable_acl", error))?;
        let _new_acl = LocalAllocation(new_acl.cast());
        unsafe {
            SetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(new_acl),
                None,
            )
        }
        .ok()
        .map_err(|error| setup_error("set_executable_acl", error))
    }
}

impl Drop for ExecutableGrant {
    fn drop(&mut self) {
        // A never-reused per-launch SID makes a failed cleanup inert for later launches.
        let _ = self.revoke();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Child, Command, Stdio};
    use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
    use std::thread;
    use std::time::Duration;

    struct LockProcess {
        child: Child,
        output: Receiver<String>,
    }

    impl LockProcess {
        fn spawn(volume_serial: u64) -> Self {
            let mut child = Command::new(std::env::current_exe().unwrap())
                .arg("cross_process_mutex_child")
                .arg("--nocapture")
                .env("ASL_TEST_ACL_MUTEX_VOLUME", volume_serial.to_string())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let stdout = child.stdout.take().unwrap();
            let (sender, output) = mpsc::channel();
            thread::spawn(move || forward_lines(stdout, sender));
            Self { child, output }
        }

        fn message(&self) -> String {
            self.output.recv_timeout(Duration::from_secs(5)).unwrap()
        }

        fn message_timeout(&self, timeout: Duration) -> Result<String, RecvTimeoutError> {
            self.output.recv_timeout(timeout)
        }

        fn release(&mut self) {
            self.child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(b"release\n")
                .unwrap();
            self.child.stdin.as_mut().unwrap().flush().unwrap();
        }
    }

    impl Drop for LockProcess {
        fn drop(&mut self) {
            if self.child.try_wait().ok().flatten().is_none() {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }
    }

    fn forward_lines(stdout: impl std::io::Read, sender: Sender<String>) {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else {
                break;
            };
            if matches!(line.as_str(), "started" | "acquired") && sender.send(line).is_err() {
                break;
            }
        }
    }

    #[test]
    fn named_acl_mutex_serializes_other_processes() {
        let volume_serial = u64::from(std::process::id());
        let mut first = LockProcess::spawn(volume_serial);
        assert_eq!(first.message(), "started");
        assert_eq!(first.message(), "acquired");

        let mut second = LockProcess::spawn(volume_serial);
        assert_eq!(second.message(), "started");
        let acquired_while_held = matches!(
            second.message_timeout(Duration::from_millis(250)),
            Ok(message) if message == "acquired"
        );

        first.release();
        assert!(first.child.wait().unwrap().success());
        if !acquired_while_held {
            assert_eq!(second.message(), "acquired");
        }
        second.release();
        assert!(second.child.wait().unwrap().success());
        assert!(
            !acquired_while_held,
            "second process acquired the ACL mutex before the first released it"
        );
    }

    #[test]
    fn cross_process_mutex_child() {
        let Ok(volume_serial) = std::env::var("ASL_TEST_ACL_MUTEX_VOLUME") else {
            return;
        };
        let identity = FileIdentity {
            volume_serial: volume_serial.parse().unwrap(),
            file_id: [0x5a; 16],
        };
        println!("started");
        std::io::stdout().flush().unwrap();
        let _lock = AclMutex::acquire(&identity).unwrap();
        println!("acquired");
        std::io::stdout().flush().unwrap();
        let mut input = String::new();
        std::io::stdin().lock().read_line(&mut input).unwrap();
    }
}
