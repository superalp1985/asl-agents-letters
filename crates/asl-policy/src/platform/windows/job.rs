use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use asl_types::error::AslError;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob, JOB_OBJECT_CPU_RATE_CONTROL_ENABLE,
    JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_JOB_MEMORY,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    JOB_OBJECT_LIMIT_PROCESS_TIME, JOB_OBJECT_UILIMIT_DESKTOP, JOB_OBJECT_UILIMIT_DISPLAYSETTINGS,
    JOB_OBJECT_UILIMIT_EXITWINDOWS, JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES,
    JOB_OBJECT_UILIMIT_READCLIPBOARD, JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS,
    JOB_OBJECT_UILIMIT_WRITECLIPBOARD, JOBOBJECT_BASIC_LIMIT_INFORMATION,
    JOBOBJECT_BASIC_UI_RESTRICTIONS, JOBOBJECT_CPU_RATE_CONTROL_INFORMATION,
    JOBOBJECT_CPU_RATE_CONTROL_INFORMATION_0, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectBasicUIRestrictions, JobObjectCpuRateControlInformation,
    JobObjectExtendedLimitInformation, SetInformationJobObject, TerminateJobObject,
};
use windows::core::{BOOL, PCWSTR};

pub(super) struct Job {
    handle: OwnedHandle,
}

impl Job {
    pub(super) fn create(
        memory_bytes: usize,
        cpu_time_100ns: Option<i64>,
        cpu_rate_percent: u8,
    ) -> Result<Self, AslError> {
        if memory_bytes == 0
            || cpu_time_100ns.is_some_and(|limit| limit <= 0)
            || !(1..=100).contains(&cpu_rate_percent)
        {
            return Err(AslError::SandboxUnavailable);
        }

        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: false.into(),
        };
        // SAFETY: The attributes remain valid for the call; a null name creates
        // a fresh, unnamed job with an explicitly noninheritable handle.
        let handle = unsafe { CreateJobObjectW(Some(&attributes), PCWSTR::null()) }
            .map_err(|_| AslError::SandboxUnavailable)?;
        // SAFETY: CreateJobObjectW returned a valid, uniquely owned handle.
        // Transfer it immediately so every later failure closes the job.
        let job = Self {
            handle: unsafe { OwnedHandle::from_raw_handle(handle.0) },
        };

        let mut limit_flags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_PROCESS_MEMORY
            | JOB_OBJECT_LIMIT_JOB_MEMORY
            | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        if cpu_time_100ns.is_some() {
            limit_flags |= JOB_OBJECT_LIMIT_PROCESS_TIME;
        }
        let limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
            BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION {
                PerProcessUserTimeLimit: cpu_time_100ns.unwrap_or(0),
                LimitFlags: limit_flags,
                ActiveProcessLimit: 1,
                ..Default::default()
            },
            ProcessMemoryLimit: memory_bytes,
            JobMemoryLimit: memory_bytes,
            ..Default::default()
        };
        // SAFETY: The live job handle and repr(C) buffer match the information
        // class and size; Windows reads the buffer only during this call.
        unsafe {
            SetInformationJobObject(
                job.raw(),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        }
        .map_err(|_| AslError::SandboxUnavailable)?;

        let cpu_rate = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION {
            ControlFlags: JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
            Anonymous: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION_0 {
                CpuRate: u32::from(cpu_rate_percent) * 100,
            },
        };
        // SAFETY: The buffer matches this information class and size, with
        // CpuRate selected by the hard-cap flags, and lives through the call.
        unsafe {
            SetInformationJobObject(
                job.raw(),
                JobObjectCpuRateControlInformation,
                (&cpu_rate as *const JOBOBJECT_CPU_RATE_CONTROL_INFORMATION).cast(),
                size_of::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>() as u32,
            )
        }
        .map_err(|_| AslError::SandboxUnavailable)?;

        let ui_limits = JOBOBJECT_BASIC_UI_RESTRICTIONS {
            UIRestrictionsClass: JOB_OBJECT_UILIMIT_DESKTOP
                | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
                | JOB_OBJECT_UILIMIT_EXITWINDOWS
                | JOB_OBJECT_UILIMIT_GLOBALATOMS
                | JOB_OBJECT_UILIMIT_HANDLES
                | JOB_OBJECT_UILIMIT_READCLIPBOARD
                | JOB_OBJECT_UILIMIT_WRITECLIPBOARD
                | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS,
        };
        // SAFETY: This buffer matches the UI information class and size and
        // remains alive for the call; job still owns the handle.
        unsafe {
            SetInformationJobObject(
                job.raw(),
                JobObjectBasicUIRestrictions,
                (&ui_limits as *const JOBOBJECT_BASIC_UI_RESTRICTIONS).cast(),
                size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
            )
        }
        .map_err(|_| AslError::SandboxUnavailable)?;

        Ok(job)
    }

    pub(super) fn assign(&self, process: HANDLE) -> Result<(), AslError> {
        // SAFETY: The job remains owned for the call. Windows validates the
        // supplied process handle; ownership of it is not transferred.
        unsafe { AssignProcessToJobObject(self.raw(), process) }
            .map_err(|_| AslError::SandboxUnavailable)?;
        let mut assigned = BOOL::default();
        // SAFETY: Windows validates both handles, and assigned is a live,
        // exclusively borrowed BOOL output buffer for the duration of the call.
        unsafe { IsProcessInJob(process, Some(self.raw()), &mut assigned) }
            .map_err(|_| AslError::SandboxUnavailable)?;
        if !assigned.as_bool() {
            return Err(AslError::SandboxUnavailable);
        }
        Ok(())
    }

    pub(super) fn terminate(&self) -> Result<(), AslError> {
        // SAFETY: The job handle remains valid and owned for the call.
        unsafe { TerminateJobObject(self.raw(), 1) }.map_err(|_| AslError::SandboxUnavailable)
    }

    fn raw(&self) -> HANDLE {
        HANDLE(self.handle.as_raw_handle())
    }
}
