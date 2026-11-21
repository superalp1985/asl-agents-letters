use std::ffi::c_void;
use std::fs::File;
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use asl_types::error::AslError;
use windows::Win32::Foundation::{
    DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE, HANDLE_FLAG_INHERIT, HANDLE_FLAGS,
    SetHandleInformation, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
#[cfg(feature = "appcontainer-loopback-fixture")]
use windows::Win32::Foundation::{HLOCAL, LocalFree};
#[cfg(feature = "appcontainer-loopback-fixture")]
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::Isolation::{CreateAppContainerProfile, DeleteAppContainerProfile};
use windows::Win32::Security::{
    CreateWellKnownSid, EqualSid, FreeSid, GetTokenInformation, PSID, SECURITY_CAPABILITIES,
    SID_AND_ATTRIBUTES, TOKEN_APPCONTAINER_INFORMATION, TOKEN_GROUPS, TOKEN_QUERY,
    TokenAppContainerSid, TokenCapabilities, TokenIsAppContainer, WELL_KNOWN_SID_TYPE,
    WinCapabilityInternetClientServerSid, WinCapabilityPrivateNetworkClientServerSid,
};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::Pipes::CreatePipe;
use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows::Win32::System::SystemServices::SE_GROUP_ENABLED;
use windows::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, GetExitCodeProcess,
    InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcessToken,
    PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION, ResumeThread,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject,
};
use windows::Win32::UI::Shell::{FOLDERID_LocalAppData, KF_FLAG_DEFAULT, SHGetKnownFolderPath};
use windows::core::{HSTRING, PWSTR};

use super::executable_acl::ExecutableGrant;
use super::handles::pin_executable;
use super::job::Job;
use crate::sandbox::{BrokerPipes, SandboxLimits, SandboxRole};

// Every ASL child is launched through this path; the explicit handle list
// narrows which inherited handles enter each child while this lock prevents
// concurrent ASL launches from observing temporary inheritable duplicates.
static PROCESS_CREATION_LOCK: Mutex<()> = Mutex::new(());

pub(super) fn setup_error(stage: &'static str, error: windows::core::Error) -> AslError {
    AslError::SandboxSetupFailed {
        stage,
        code: error.code().0,
    }
}

/// Only private anonymous pipes created here can enter the child handle list.
pub struct InheritedPipes {
    input: OwnedHandle,
    output: OwnedHandle,
    error: OwnedHandle,
}

impl InheritedPipes {
    pub fn new() -> Result<(BrokerPipes, Self), AslError> {
        let (input, host_input) = pipe()?;
        let (host_output, output) = pipe()?;
        let (host_error, error) = pipe()?;
        Ok((
            BrokerPipes {
                input: File::from(host_input),
                output: File::from(host_output),
                error: File::from(host_error),
            },
            Self {
                input,
                output,
                error,
            },
        ))
    }
}

fn pipe() -> Result<(OwnedHandle, OwnedHandle), AslError> {
    let mut read = HANDLE::default();
    let mut write = HANDLE::default();
    unsafe { CreatePipe(&mut read, &mut write, None, 0) }
        .map_err(|_| AslError::SandboxUnavailable)?;
    let read = owned(read);
    let write = owned(write);
    Ok((read, write))
}

fn duplicate_inheritable(handle: &OwnedHandle) -> Result<OwnedHandle, AslError> {
    let mut output = HANDLE::default();
    unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            raw(handle),
            GetCurrentProcess(),
            &mut output,
            0,
            true,
            DUPLICATE_SAME_ACCESS,
        )
    }
    .map_err(|_| AslError::SandboxUnavailable)?;
    Ok(owned(output))
}

struct Profile {
    name: HSTRING,
    sid: PSID,
    present: bool,
    #[cfg(feature = "appcontainer-loopback-fixture")]
    loopback_fixture: Option<LoopbackFixture>,
}

impl Profile {
    fn create(_role: SandboxRole) -> Result<Self, AslError> {
        let name_text = format!("asl.{}", rand::random::<u128>());
        let name = HSTRING::from(&name_text);
        let sid = unsafe { CreateAppContainerProfile(&name, &name, &name, None) }
            .map_err(|error| setup_error("create_appcontainer", error))?;
        let profile = Self {
            name,
            sid,
            present: true,
            #[cfg(feature = "appcontainer-loopback-fixture")]
            loopback_fixture: None,
        };
        #[cfg(feature = "appcontainer-loopback-fixture")]
        if _role == SandboxRole::Net
            && std::env::var_os("ASL_APPCONTAINER_LOOPBACK_FIXTURE").as_deref()
                == Some(std::ffi::OsStr::new("1"))
        {
            let mut profile = profile;
            profile.loopback_fixture = Some(LoopbackFixture::enable(sid_text(sid)?)?);
            return Ok(profile);
        }
        Ok(profile)
    }

    fn remove(&mut self) -> Result<(), AslError> {
        #[cfg(feature = "appcontainer-loopback-fixture")]
        let loopback_result = self
            .loopback_fixture
            .take()
            .map(LoopbackFixture::remove)
            .transpose();
        if self.present {
            let result = unsafe { DeleteAppContainerProfile(&self.name) }
                .map_err(|_| AslError::SandboxUnavailable);
            self.present = false;
            result?;
        }
        #[cfg(feature = "appcontainer-loopback-fixture")]
        loopback_result?;
        Ok(())
    }
}

impl Drop for Profile {
    fn drop(&mut self) {
        let _ = self.remove();
        unsafe { FreeSid(self.sid) };
    }
}

#[cfg(feature = "appcontainer-loopback-fixture")]
#[path = "loopback_fixture.rs"]
mod loopback_fixture;
#[cfg(feature = "appcontainer-loopback-fixture")]
use loopback_fixture::LoopbackFixture;

#[cfg(feature = "appcontainer-loopback-fixture")]
fn sid_text(sid: PSID) -> Result<String, AslError> {
    let mut text = PWSTR::null();
    unsafe { ConvertSidToStringSidW(sid, &mut text) }
        .map_err(|error| setup_error("convert_appcontainer_sid", error))?;
    let value = unsafe { text.to_string() }.map_err(|_| AslError::SandboxUnavailable);
    unsafe {
        LocalFree(Some(HLOCAL(text.as_ptr().cast())));
    }
    value
}

struct Attributes {
    storage: Vec<usize>,
    list: LPPROC_THREAD_ATTRIBUTE_LIST,
}

impl Attributes {
    fn new(count: u32) -> Result<Self, AslError> {
        let mut bytes = 0;
        let _ = unsafe { InitializeProcThreadAttributeList(None, count, None, &mut bytes) };
        if bytes == 0 || bytes > 64 * 1024 {
            return Err(AslError::SandboxUnavailable);
        }
        let mut storage = vec![0usize; bytes.div_ceil(size_of::<usize>())];
        let list = LPPROC_THREAD_ATTRIBUTE_LIST(storage.as_mut_ptr().cast());
        unsafe { InitializeProcThreadAttributeList(Some(list), count, None, &mut bytes) }
            .map_err(|error| setup_error("initialize_attributes", error))?;
        Ok(Self { storage, list })
    }

    fn set<T>(&mut self, attribute: u32, value: &T) -> Result<(), AslError> {
        unsafe {
            UpdateProcThreadAttribute(
                self.list,
                0,
                attribute as usize,
                Some((value as *const T).cast()),
                size_of::<T>(),
                None,
                None,
            )
        }
        .map_err(|error| setup_error("update_attribute", error))
    }
}

impl Drop for Attributes {
    fn drop(&mut self) {
        unsafe { DeleteProcThreadAttributeList(self.list) };
        // The backing allocation must outlive DeleteProcThreadAttributeList.
        let _ = self.storage.len();
    }
}

/// A suspended process is always killed on an unsuccessful launch.
struct SuspendedProcess {
    process: OwnedHandle,
    thread: OwnedHandle,
    id: u32,
    resumed: bool,
}

impl Drop for SuspendedProcess {
    fn drop(&mut self) {
        if !self.resumed {
            unsafe { TerminateProcess(raw(&self.process), 1) }.ok();
            unsafe { WaitForSingleObject(raw(&self.process), 5_000) };
        }
    }
}

pub(crate) struct Child {
    process: OwnedHandle,
    job: Arc<Job>,
    watchdog: Option<JoinHandle<()>>,
    grant: Option<ExecutableGrant>,
    profile: Option<Profile>,
    id: u32,
}

pub(crate) fn spawn(
    program: &Path,
    role: SandboxRole,
    pipes: InheritedPipes,
    limits: SandboxLimits,
) -> Result<Child, AslError> {
    let pin = pin_executable(program).map_err(|_| AslError::SandboxUnavailable)?;
    let profile = Profile::create(role)?;
    let grant = ExecutableGrant::new(pin, profile.sid)?;
    let job = Arc::new(Job::create(
        usize::try_from(limits.memory_bytes).map_err(|_| AslError::SandboxUnavailable)?,
        limits.cpu_time_ms.map(|value| (value * 10_000) as i64),
        limits.cpu_rate_percent,
    )?);
    let mut capability_sids = Vec::new();
    if role == SandboxRole::Net {
        for kind in [
            WinCapabilityInternetClientServerSid,
            WinCapabilityPrivateNetworkClientServerSid,
        ] {
            capability_sids.push(well_known_sid(kind)?);
        }
    }
    let mut capabilities: Vec<_> = capability_sids
        .iter_mut()
        .map(|sid| SID_AND_ATTRIBUTES {
            Sid: PSID(sid.as_mut_ptr().cast()),
            Attributes: SE_GROUP_ENABLED as u32,
        })
        .collect();
    let security = SECURITY_CAPABILITIES {
        AppContainerSid: profile.sid,
        Capabilities: if capabilities.is_empty() {
            std::ptr::null_mut()
        } else {
            capabilities.as_mut_ptr()
        },
        CapabilityCount: capabilities.len() as u32,
        Reserved: 0,
    };
    let _creation_guard = PROCESS_CREATION_LOCK
        .lock()
        .map_err(|_| AslError::SandboxUnavailable)?;
    let inheritable = [
        duplicate_inheritable(&pipes.input)?,
        duplicate_inheritable(&pipes.output)?,
        duplicate_inheritable(&pipes.error)?,
    ];
    let handles = [
        raw(&inheritable[0]),
        raw(&inheritable[1]),
        raw(&inheritable[2]),
    ];
    // Windows' documented PROCESS_CREATION_CHILD_PROCESS_RESTRICTED value.
    let child_policy = 1u32;
    let mut attributes = Attributes::new(3)?;
    attributes.set(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &security)?;
    attributes.set(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &handles)?;
    attributes.set(PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY, &child_policy)?;
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = handles[0];
    startup.StartupInfo.hStdOutput = handles[1];
    startup.StartupInfo.hStdError = handles[2];
    startup.lpAttributeList = attributes.list;
    let system = system_directory()?;
    let windows = Path::new(&system)
        .parent()
        .and_then(Path::to_str)
        .ok_or(AslError::SandboxUnavailable)?;
    // Windows' AppContainer setup requires LOCALAPPDATA. Resolve the OS known
    // folder rather than inheriting arbitrary parent environment variables.
    let local_app_data = local_app_data()?;
    let environment: Vec<u16> = format!(
        "LOCALAPPDATA={local_app_data}\0PATH={system}\0SystemRoot={windows}\0WINDIR={windows}\0\0"
    )
    .encode_utf16()
    .collect();
    let program_text = program.to_str().ok_or(AslError::SandboxUnavailable)?;
    let executable = HSTRING::from(program_text);
    let mut command: Vec<u16> = format!("\"{program_text}\" {}\0", role.argument())
        .encode_utf16()
        .collect();
    let mut information = PROCESS_INFORMATION::default();
    let created = unsafe {
        CreateProcessW(
            &executable,
            Some(PWSTR(command.as_mut_ptr())),
            None,
            None,
            true,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
            Some(environment.as_ptr().cast::<c_void>()),
            &HSTRING::from(&system),
            &startup.StartupInfo,
            &mut information,
        )
    };
    match created {
        Ok(()) => {}
        Err(error) => {
            for handle in &inheritable {
                let _ = unsafe {
                    SetHandleInformation(raw(handle), HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0))
                };
            }
            return Err(setup_error("create_process", error));
        }
    }
    let mut inheritance_cleanup_failed = false;
    for handle in &inheritable {
        inheritance_cleanup_failed |= unsafe {
            SetHandleInformation(raw(handle), HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0)).is_err()
        };
    }
    if inheritance_cleanup_failed {
        let process = owned(information.hProcess);
        let thread = owned(information.hThread);
        unsafe { TerminateProcess(raw(&process), 1) }.ok();
        unsafe { WaitForSingleObject(raw(&process), 5_000) };
        drop(thread);
        return Err(AslError::SandboxUnavailable);
    }
    drop(inheritable);
    drop(_creation_guard);
    let mut pending = SuspendedProcess {
        process: owned(information.hProcess),
        thread: owned(information.hThread),
        id: information.dwProcessId,
        resumed: false,
    };
    job.assign(raw(&pending.process))?;
    verify_container(raw(&pending.process), profile.sid, &capabilities)?;
    let process = duplicate(&pending.process)?;
    let watchdog = if let Some(timeout) = limits.wall_time_ms {
        let process = duplicate(&pending.process)?;
        let deadline_job = Arc::clone(&job);
        Some(
            thread::Builder::new()
                .name("asl-sandbox-deadline".into())
                .spawn(move || {
                    if unsafe { WaitForSingleObject(raw(&process), timeout) } != WAIT_OBJECT_0 {
                        let _ = deadline_job.terminate();
                    }
                })
                .map_err(|_| AslError::SandboxUnavailable)?,
        )
    } else {
        None
    };
    if unsafe { ResumeThread(raw(&pending.thread)) } != 1 {
        job.terminate()?;
        if let Some(watchdog) = watchdog {
            let _ = watchdog.join();
        }
        return Err(AslError::SandboxUnavailable);
    }
    pending.resumed = true;
    Ok(Child {
        process,
        job,
        watchdog,
        grant: Some(grant),
        profile: Some(profile),
        id: pending.id,
    })
}

impl Child {
    pub(crate) fn id(&self) -> u32 {
        self.id
    }

    pub(crate) fn wait_timeout(&mut self, timeout: Duration) -> Result<Option<u32>, AslError> {
        let milliseconds = u32::try_from(timeout.as_millis())
            .map_err(|_| AslError::SandboxUnavailable)?
            .min(u32::MAX - 1);
        match unsafe { WaitForSingleObject(raw(&self.process), milliseconds) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => {
                let mut code = 0;
                unsafe { GetExitCodeProcess(raw(&self.process), &mut code) }
                    .map_err(|_| AslError::SandboxUnavailable)?;
                self.cleanup()?;
                Ok(Some(code))
            }
            _ => Err(AslError::SandboxUnavailable),
        }
    }

    pub(crate) fn terminate(&mut self) -> Result<(), AslError> {
        self.job.terminate()?;
        if unsafe { WaitForSingleObject(raw(&self.process), 5_000) } != WAIT_OBJECT_0 {
            return Err(AslError::SandboxUnavailable);
        }
        self.cleanup()
    }

    fn cleanup(&mut self) -> Result<(), AslError> {
        if let Some(watchdog) = self.watchdog.take() {
            watchdog.join().map_err(|_| AslError::SandboxUnavailable)?;
        }
        if let Some(grant) = self.grant.as_mut() {
            grant.revoke()?;
        }
        self.grant = None;
        if let Some(profile) = self.profile.as_mut() {
            profile.remove()?;
        }
        self.profile = None;
        Ok(())
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

fn system_directory() -> Result<String, AslError> {
    let mut path = vec![0u16; 32_768];
    let count = unsafe { GetSystemDirectoryW(Some(&mut path)) } as usize;
    if count == 0 || count >= path.len() {
        return Err(AslError::SandboxUnavailable);
    }
    String::from_utf16(&path[..count]).map_err(|_| AslError::SandboxUnavailable)
}

fn local_app_data() -> Result<String, AslError> {
    let path = unsafe { SHGetKnownFolderPath(&FOLDERID_LocalAppData, KF_FLAG_DEFAULT, None) }
        .map_err(|error| setup_error("local_app_data", error))?;
    let result = unsafe { path.to_string() }.map_err(|_| AslError::SandboxUnavailable);
    unsafe { CoTaskMemFree(Some(path.0.cast())) };
    result
}

fn well_known_sid(kind: WELL_KNOWN_SID_TYPE) -> Result<Vec<u64>, AslError> {
    let mut sid = vec![0u64; 9];
    let mut bytes = (sid.len() * size_of::<u64>()) as u32;
    unsafe { CreateWellKnownSid(kind, None, Some(PSID(sid.as_mut_ptr().cast())), &mut bytes) }
        .map_err(|_| AslError::SandboxUnavailable)?;
    Ok(sid)
}

fn verify_container(
    process: HANDLE,
    expected_sid: PSID,
    expected_capabilities: &[SID_AND_ATTRIBUTES],
) -> Result<(), AslError> {
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }
        .map_err(|error| setup_error("open_child_token", error))?;
    let token = owned(token);
    let mut flag = 0u32;
    let mut length = 0;
    unsafe {
        GetTokenInformation(
            raw(&token),
            TokenIsAppContainer,
            Some((&mut flag as *mut u32).cast()),
            size_of::<u32>() as u32,
            &mut length,
        )
    }
    .map_err(|_| AslError::SandboxUnavailable)?;
    if flag != 1 {
        return Err(AslError::SandboxUnavailable);
    }
    let mut buffer = [0u64; 32];
    unsafe {
        GetTokenInformation(
            raw(&token),
            TokenAppContainerSid,
            Some(buffer.as_mut_ptr().cast()),
            size_of_val(&buffer) as u32,
            &mut length,
        )
    }
    .map_err(|_| AslError::SandboxUnavailable)?;
    let info = unsafe { &*buffer.as_ptr().cast::<TOKEN_APPCONTAINER_INFORMATION>() };
    unsafe { EqualSid(info.TokenAppContainer, expected_sid) }
        .map_err(|_| AslError::SandboxUnavailable)?;
    let mut capability_buffer = [0u64; 512];
    unsafe {
        GetTokenInformation(
            raw(&token),
            TokenCapabilities,
            Some(capability_buffer.as_mut_ptr().cast()),
            size_of_val(&capability_buffer) as u32,
            &mut length,
        )
    }
    .map_err(|error| setup_error("query_child_capabilities", error))?;
    let groups = unsafe { &*capability_buffer.as_ptr().cast::<TOKEN_GROUPS>() };
    let count = groups.GroupCount as usize;
    let required = std::mem::offset_of!(TOKEN_GROUPS, Groups)
        + count
            .checked_mul(size_of::<SID_AND_ATTRIBUTES>())
            .ok_or(AslError::SandboxUnavailable)?;
    if count != expected_capabilities.len()
        || required > length as usize
        || length as usize > size_of_val(&capability_buffer)
    {
        return Err(AslError::SandboxUnavailable);
    }
    // The kernel-provided buffer was bounded above; SID pointers remain valid in it.
    let actual = unsafe { std::slice::from_raw_parts(groups.Groups.as_ptr(), count) };
    for expected in expected_capabilities {
        if !actual
            .iter()
            .any(|group| unsafe { EqualSid(group.Sid, expected.Sid) }.is_ok())
        {
            return Err(AslError::SandboxUnavailable);
        }
    }
    Ok(())
}

fn raw(handle: &OwnedHandle) -> HANDLE {
    HANDLE(handle.as_raw_handle())
}

fn owned(handle: HANDLE) -> OwnedHandle {
    // Called only with a successfully created, non-pseudo Win32 handle.
    unsafe { OwnedHandle::from_raw_handle(handle.0) }
}

fn duplicate(handle: &OwnedHandle) -> Result<OwnedHandle, AslError> {
    let mut output = HANDLE::default();
    unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            raw(handle),
            GetCurrentProcess(),
            &mut output,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )
    }
    .map_err(|_| AslError::SandboxUnavailable)?;
    Ok(owned(output))
}
