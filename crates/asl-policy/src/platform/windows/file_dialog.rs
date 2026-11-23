use std::{ffi::OsString, io, os::windows::ffi::OsStringExt, path::PathBuf};

use asl_types::error::AslError;
use windows::{
    Win32::{
        Foundation::ERROR_CANCELLED,
        System::Com::{
            CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE,
            CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize,
        },
        UI::{
            Input::KeyboardAndMouse::GetActiveWindow,
            Shell::{
                Common::COMDLG_FILTERSPEC, FOS_DONTADDTORECENT, FOS_FILEMUSTEXIST,
                FOS_FORCEFILESYSTEM, FOS_NOCHANGEDIR, FOS_NODEREFERENCELINKS, FOS_PATHMUSTEXIST,
                FOS_PICKFOLDERS, FileOpenDialog, IFileOpenDialog, SIGDN_FILESYSPATH,
            },
        },
    },
    core::{HRESULT, w},
};

/// Opens a modal file picker on the desktop UI thread. No file is opened here.
pub fn choose_avatar_file() -> Result<Option<PathBuf>, AslError> {
    choose(Selection::Avatar).map_err(|error| io::Error::other(error).into())
}

pub fn choose_local_directory() -> Result<Option<PathBuf>, AslError> {
    choose(Selection::Directory).map_err(|error| io::Error::other(error).into())
}

pub fn choose_local_file() -> Result<Option<PathBuf>, AslError> {
    choose(Selection::File).map_err(|error| io::Error::other(error).into())
}

enum Selection {
    Avatar,
    File,
    Directory,
}

fn choose(kind: Selection) -> windows::core::Result<Option<PathBuf>> {
    struct Apartment;
    impl Drop for Apartment {
        fn drop(&mut self) {
            // Balances this thread's successful CoInitializeEx, including S_FALSE.
            unsafe { CoUninitialize() };
        }
    }

    unsafe {
        CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE).ok()?;
        let _apartment = Apartment;
        let dialog: IFileOpenDialog =
            CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER)?;
        dialog.SetOptions(
            FOS_FORCEFILESYSTEM
                | match kind {
                    Selection::Directory => FOS_PICKFOLDERS,
                    _ => FOS_FILEMUSTEXIST,
                }
                | FOS_PATHMUSTEXIST
                | FOS_NODEREFERENCELINKS
                | FOS_DONTADDTORECENT
                | FOS_NOCHANGEDIR,
        )?;
        if matches!(kind, Selection::Avatar) {
            dialog.SetFileTypes(&[COMDLG_FILTERSPEC {
                pszName: w!("PNG, JPEG, WebP"),
                pszSpec: w!("*.png;*.jpg;*.jpeg;*.webp"),
            }])?;
        }
        match dialog.Show(Some(GetActiveWindow())) {
            Err(error) if error.code() == HRESULT::from_win32(ERROR_CANCELLED.0) => {
                return Ok(None);
            }
            result => result?,
        }
        let name = dialog.GetResult()?.GetDisplayName(SIGDN_FILESYSPATH)?;
        // GetDisplayName transfers the NUL-terminated string to the caller.
        let path = PathBuf::from(OsString::from_wide(name.as_wide()));
        CoTaskMemFree(Some(name.0.cast()));
        Ok(Some(path))
    }
}
