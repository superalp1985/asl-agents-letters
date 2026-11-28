use std::{io, os::windows::ffi::OsStrExt, path::Path, time::Duration};

use windows::{
    Win32::{
        Foundation::FILETIME,
        Storage::FileSystem::GetDiskFreeSpaceExW,
        System::{
            ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS},
            SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX},
            Threading::{GetCurrentProcess, GetCurrentThread, GetThreadTimes},
        },
    },
    core::PCWSTR,
};

#[derive(Clone, Copy, Debug)]
pub struct ResourceSample {
    pub working_set_bytes: u64,
    pub available_memory_bytes: u64,
    pub available_disk_bytes: u64,
}

pub fn local_resource_sample(data_dir: &Path) -> io::Result<ResourceSample> {
    let mut path: Vec<u16> = data_dir.as_os_str().encode_wide().collect();
    if !data_dir.is_absolute() || path.contains(&0) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    path.push(0);
    let mut disk_free = 0;
    let mut process = PROCESS_MEMORY_COUNTERS {
        cb: size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        ..Default::default()
    };
    let mut memory = MEMORYSTATUSEX {
        dwLength: size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    let process_size = process.cb;
    // Each pointer refers to a live, correctly sized output. The process
    // pseudo-handle does not need closing.
    unsafe {
        GetDiskFreeSpaceExW(PCWSTR(path.as_ptr()), Some(&mut disk_free), None, None)
            .map_err(io::Error::other)?;
        GlobalMemoryStatusEx(&mut memory).map_err(io::Error::other)?;
        GetProcessMemoryInfo(GetCurrentProcess(), &mut process, process_size)
            .map_err(io::Error::other)?;
    }
    Ok(ResourceSample {
        working_set_bytes: process.WorkingSetSize as u64,
        available_memory_bytes: memory.ullAvailPhys,
        available_disk_bytes: disk_free,
    })
}

pub fn thread_cpu_time() -> io::Result<Duration> {
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // The outputs are independent and live, and the thread pseudo-handle is valid here.
    unsafe {
        GetThreadTimes(
            GetCurrentThread(),
            &mut created,
            &mut exited,
            &mut kernel,
            &mut user,
        )
        .map_err(io::Error::other)?;
    }
    let ticks =
        |time: FILETIME| (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime);
    Ok(Duration::from_nanos(
        ticks(kernel)
            .saturating_add(ticks(user))
            .saturating_mul(100),
    ))
}
