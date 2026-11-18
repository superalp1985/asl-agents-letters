//! OS operations used only by the real sandbox probe executable and its tests.
use std::fs::File;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::time::Duration;

use windows::Win32::Foundation::{
    GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, HLOCAL, LocalFree, SetHandleInformation,
    WAIT_OBJECT_0,
};
use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows::Win32::Security::{ACL, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};
use windows::Win32::Storage::FileSystem::ReadFile;
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, WaitForSingleObject,
};

pub fn make_inheritable(file: &File) {
    unsafe {
        SetHandleInformation(
            HANDLE(file.as_raw_handle()),
            HANDLE_FLAG_INHERIT.0,
            HANDLE_FLAG_INHERIT,
        )
    }
    .expect("mark test sentinel handle inheritable");
}

pub fn is_inheritable(file: &File) -> bool {
    let mut flags = 0;
    unsafe { GetHandleInformation(HANDLE(file.as_raw_handle()), &mut flags) }
        .expect("query test pipe handle flags");
    flags & HANDLE_FLAG_INHERIT.0 != 0
}

pub fn read_handle(value: usize) -> Vec<u8> {
    let mut flags = 0;
    if unsafe { GetHandleInformation(HANDLE(value as *mut _), &mut flags) }.is_err() {
        return Vec::new();
    }
    let mut bytes = [0u8; 128];
    let mut count = 0;
    if unsafe {
        ReadFile(
            HANDLE(value as *mut _),
            Some(&mut bytes),
            Some(&mut count),
            None,
        )
    }
    .is_ok()
    {
        bytes[..count as usize].to_vec()
    } else {
        Vec::new()
    }
}

pub fn wait_process(id: u32, timeout: Duration) -> bool {
    let Ok(handle) = (unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            false,
            id,
        )
    }) else {
        return true;
    };
    let handle = unsafe { OwnedHandle::from_raw_handle(handle.0) };
    (unsafe { WaitForSingleObject(HANDLE(handle.as_raw_handle()), timeout.as_millis() as u32) })
        == WAIT_OBJECT_0
}

pub fn dacl(file: &File) -> Vec<u8> {
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let mut acl: *mut ACL = std::ptr::null_mut();
    unsafe {
        GetSecurityInfo(
            HANDLE(file.as_raw_handle()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut acl),
            None,
            Some(&mut descriptor),
        )
    }
    .ok()
    .expect("read test fixture DACL");
    let result = if acl.is_null() {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(acl.cast::<u8>(), (*acl).AclSize as usize) }.to_vec()
    };
    unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
    result
}
