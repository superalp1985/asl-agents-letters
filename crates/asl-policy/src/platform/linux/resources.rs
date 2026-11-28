use std::fs;
use std::io;
use std::path::Path;
use std::time::Duration;

#[derive(Clone, Copy, Debug)]
pub struct ResourceSample {
    pub working_set_bytes: u64,
    pub available_memory_bytes: u64,
    pub available_disk_bytes: u64,
}

pub fn local_resource_sample(data_dir: &Path) -> io::Result<ResourceSample> {
    if !data_dir.is_absolute() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let statm = fs::read_to_string("/proc/self/statm")?;
    let resident_pages = statm
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| io::Error::other("invalid /proc/self/statm"))?
        .parse::<u64>()
        .map_err(io::Error::other)?;
    let working_set_bytes = resident_pages
        .checked_mul(rustix::param::page_size() as u64)
        .ok_or_else(|| io::Error::other("process memory overflow"))?;
    let meminfo = fs::read_to_string("/proc/meminfo")?;
    let available_memory_bytes = meminfo
        .lines()
        .find_map(|line| {
            let value = line.strip_prefix("MemAvailable:")?;
            let kib = value.split_whitespace().next()?.parse::<u64>().ok()?;
            kib.checked_mul(1024)
        })
        .ok_or_else(|| io::Error::other("missing MemAvailable"))?;
    let vfs = rustix::fs::statvfs(data_dir)
        .map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))?;
    let available_disk_bytes = vfs
        .f_bavail
        .checked_mul(vfs.f_frsize)
        .ok_or_else(|| io::Error::other("disk capacity overflow"))?;
    Ok(ResourceSample {
        working_set_bytes,
        available_memory_bytes,
        available_disk_bytes,
    })
}

pub fn thread_cpu_time() -> io::Result<Duration> {
    let tid = rustix::thread::gettid();
    let stat = fs::read_to_string(format!("/proc/self/task/{}/stat", tid.as_raw_pid()))?;
    let fields = stat
        .rsplit_once(')')
        .map(|(_, fields)| fields)
        .ok_or_else(|| io::Error::other("invalid thread stat"))?;
    let fields: Vec<_> = fields.split_whitespace().collect();
    let user = fields
        .get(11)
        .ok_or_else(|| io::Error::other("missing utime"))?
        .parse::<u64>()
        .map_err(io::Error::other)?;
    let system = fields
        .get(12)
        .ok_or_else(|| io::Error::other("missing stime"))?
        .parse::<u64>()
        .map_err(io::Error::other)?;
    let ticks = rustix::param::clock_ticks_per_second();
    let nanoseconds = user
        .checked_add(system)
        .and_then(|value| value.checked_mul(1_000_000_000))
        .ok_or_else(|| io::Error::other("thread CPU overflow"))?
        / ticks;
    Ok(Duration::from_nanos(nanoseconds))
}
