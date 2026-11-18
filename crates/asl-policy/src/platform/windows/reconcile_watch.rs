use std::io;

use windows::Win32::Foundation::{HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::Storage::FileSystem::{
    FILE_NOTIFY_CHANGE_ATTRIBUTES, FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_FILE_NAME,
    FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SECURITY, FILE_NOTIFY_CHANGE_SIZE,
    FindCloseChangeNotification, FindFirstChangeNotificationW, FindNextChangeNotification,
};
use windows::Win32::System::Threading::WaitForSingleObject;
use windows::core::HSTRING;

/// The handle is a coalescing kernel signal, not a buffer of directory entries.
pub(crate) struct DirectoryWatch(HANDLE);

// Change-notification handles have no thread affinity. Only one owner can
// rearm or close this handle; there is no outstanding asynchronous buffer.
unsafe impl Send for DirectoryWatch {}

impl DirectoryWatch {
    pub(super) fn open(pinned_volume_name: &[u16]) -> io::Result<Self> {
        let name = HSTRING::from_wide(pinned_volume_name);
        let filter = FILE_NOTIFY_CHANGE_FILE_NAME
            | FILE_NOTIFY_CHANGE_DIR_NAME
            | FILE_NOTIFY_CHANGE_SIZE
            | FILE_NOTIFY_CHANGE_LAST_WRITE
            | FILE_NOTIFY_CHANGE_ATTRIBUTES
            | FILE_NOTIFY_CHANGE_SECURITY;
        // The caller holds the grant's directory and all ancestor pins while
        // Windows opens this absolute, volume-qualified name. No path is retained.
        let handle = unsafe { FindFirstChangeNotificationW(&name, true, filter) }?;
        Ok(Self(handle))
    }

    pub(crate) fn take_change(&mut self) -> io::Result<bool> {
        // A zero timeout samples the owned handle without blocking the broker.
        match unsafe { WaitForSingleObject(self.0, 0) } {
            WAIT_TIMEOUT => Ok(false),
            WAIT_OBJECT_0 => {
                unsafe { FindNextChangeNotification(self.0) }?;
                Ok(true)
            }
            WAIT_FAILED => Err(io::Error::last_os_error()),
            _ => Err(io::Error::other("unexpected directory notification state")),
        }
    }
}

impl Drop for DirectoryWatch {
    fn drop(&mut self) {
        // These handles require FindCloseChangeNotification, not CloseHandle.
        let _ = unsafe { FindCloseChangeNotification(self.0) };
    }
}
